use super::*;
use crate::base64_decode;
use crate::xchacha_decrypt;

/// Roundtrip the `make_file_id_json` output through the same
/// decryption the `/fs` handler does. This is the contract that
/// keeps chat images loading — if this test fails, the server is
/// either encrypting the wrong thing or the token doesn't match
/// the one the web side will derive from `app.urlToken`.
#[test]
fn make_file_id_json_roundtrips_through_fs_decrypt() {
    let token_raw = [42u8; 32];
    let token_b64 = crate::base64_encode(&token_raw);

    let fid = make_file_id_json("fid:abc123def456.jpg", "cat.jpg", &token_b64);
    assert!(!fid.is_empty(), "encrypted id should not be empty");

    // `/fs` handler: base64-decode the query param, then
    // xchacha_decrypt with the local URL token.
    let encrypted = base64_decode(&fid);
    let plaintext = xchacha_decrypt(&token_b64, &encrypted)
        .expect("server-side encrypted id must decrypt with local token");

    // The decrypted plaintext is the JSON we built in
    // `make_file_id_json` — must round-trip to the original
    // `{path, name}` pair.
    let v: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(v["path"], "fid:abc123def456.jpg");
    assert_eq!(v["name"], "cat.jpg");
}

/// `make_file_id` (the `&str` variant) is used for text-message
/// link-preview paths. Decryption should give back the bare
/// `imageLocalPath` (not JSON-wrapped).
#[test]
fn make_file_id_roundtrips_through_fs_decrypt() {
    let token_raw = [7u8; 32];
    let token_b64 = crate::base64_encode(&token_raw);

    let path = "app://Pictures/foo.png";
    let fid = make_file_id(path, &token_b64);

    let plaintext = xchacha_decrypt(&token_b64, &base64_decode(&fid))
        .expect("decrypt must succeed for text link-preview path");
    assert_eq!(std::str::from_utf8(&plaintext).unwrap(), path);
}

/// The full `chat_item_data_from_content` flow: build a chat
/// `content` JSON, compute its `data` with the token, decrypt
/// each id back, and confirm we recover the original `{path,
/// name}`.
#[test]
fn chat_item_data_from_content_roundtrips() {
    let token_b64 = crate::base64_encode(&[99u8; 32]);

    let content = serde_json::json!({
        "type": "IMAGES",
        "value": {
            "items": [
                { "uri": "fid:00112233.jpg", "fileName": "first.jpg" },
                { "uri": "fid:ffeeddcc.png", "fileName": "second.png" },
            ]
        }
    })
    .to_string();

    let data = chat_item_data_from_content(&content, &token_b64).expect("should parse content");
    let ids = match data {
        ChatItemData::Images { ids } => ids,
        _ => panic!("expected Images"),
    };
    assert_eq!(ids.len(), 2);

    for (i, expected) in ["fid:00112233.jpg", "fid:ffeeddcc.png"].iter().enumerate() {
        let expected_name = if i == 0 { "first.jpg" } else { "second.png" };
        let plaintext = xchacha_decrypt(&token_b64, &base64_decode(&ids[i])).expect("must decrypt");
        let v: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(v["path"], *expected);
        assert_eq!(v["name"], expected_name);
    }
}

/// TEXT messages map linkPreviews[].imageLocalPath through the bare-path
/// encryption; empty paths are skipped.
#[test]
fn chat_item_data_from_content_text_link_previews() {
    let token_b64 = crate::base64_encode(&[3u8; 32]);

    let content = serde_json::json!({
        "type": "TEXT",
        "value": {
            "text": "see this",
            "linkPreviews": [
                { "url": "https://example.com/a", "imageLocalPath": "app://cache/p1.png" },
                { "url": "https://example.com/b", "imageLocalPath": "" }
            ]
        }
    })
    .to_string();

    let data = chat_item_data_from_content(&content, &token_b64).expect("should parse");
    match data {
        ChatItemData::Text {
            link_preview_image_ids,
        } => {
            assert_eq!(link_preview_image_ids.len(), 1);
            let plaintext =
                xchacha_decrypt(&token_b64, &base64_decode(&link_preview_image_ids[0])).unwrap();
            assert_eq!(
                std::str::from_utf8(&plaintext).unwrap(),
                "app://cache/p1.png"
            );
        }
        _ => panic!("expected Text"),
    }
}

/// Unknown envelope types and malformed JSON yield `None`, never a panic.
#[test]
fn chat_item_data_from_content_rejects_unknown_and_malformed() {
    let token = crate::base64_encode(&[1u8; 32]);
    assert!(chat_item_data_from_content(r#"{"type":"SHARE","value":{}}"#, &token).is_none());
    assert!(chat_item_data_from_content("not json", &token).is_none());
    assert!(chat_item_data_from_content("{}", &token).is_none());
    // Missing items array.
    assert!(chat_item_data_from_content(r#"{"type":"IMAGES","value":{}}"#, &token).is_none());
}

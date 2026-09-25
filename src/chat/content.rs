//! Chat message `content` envelope: `{type: TEXT|IMAGES|FILES|SHARE,
//! value: {...}}` parsing plus the URL-token file-id encryption the
//! `/fs` endpoint decrypts. Mirrors plain-app `ChatItem.getContentData()`
//! and `FileHelper.getFileId`.

use serde_json::Value;

use crate::base64_encode;
use crate::xchacha_encrypt;

/// The typed `ChatItem.data` payload derived from the content envelope.
/// Apps map this onto their GraphQL `ChatItemContent` union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatItemData {
    /// IMAGES messages: URL-token-encrypted `{path, name}` per image.
    Images { ids: Vec<String> },
    /// FILES messages: URL-token-encrypted `{path, name}` per file.
    Files { ids: Vec<String> },
    /// TEXT messages: URL-token-encrypted bare `imageLocalPath` per
    /// link-preview image.
    Text { link_preview_image_ids: Vec<String> },
}

/// Encrypt `JSON.stringify({path, name})` with the local URL token and
/// base64-encode the result. Mirrors `plain-app`'s
/// `FileHelper.getFileId(JSONObject().apply { put("path", …); put("name", …) })`
/// for chat image/file payloads.
pub fn make_file_id_json(path: &str, name: &str, token: &str) -> String {
    let json = serde_json::json!({ "path": path, "name": name }).to_string();
    make_file_id(&json, token)
}

/// Encrypt `path` with the local URL token and base64-encode the
/// result. Mirrors `plain-app`'s `FileHelper.getFileId(path)` for the
/// text-message link-preview path (no JSON wrapping).
pub fn make_file_id(path: &str, token: &str) -> String {
    let Some(encrypted) = xchacha_encrypt(token, path.as_bytes()) else {
        return String::new();
    };
    base64_encode(&encrypted)
}

/// Parse a chat `content` envelope into its typed data payload. `token`
/// is the base64 URL token the local `/fs` endpoint decrypts with — the
/// produced `ids` are only meaningful to that endpoint. Returns `None`
/// for unknown types or malformed envelopes.
pub fn chat_item_data_from_content(content: &str, token: &str) -> Option<ChatItemData> {
    let v: Value = serde_json::from_str(content).ok()?;
    let msg_type = v.get("type")?.as_str()?;
    let value = v.get("value")?;
    match msg_type {
        "IMAGES" => {
            let ids = value
                .get("items")?
                .as_array()?
                .iter()
                .filter_map(|i| {
                    let uri = i.get("uri").and_then(|u| u.as_str())?;
                    let name = i.get("fileName").and_then(|u| u.as_str()).unwrap_or("");
                    Some(make_file_id_json(uri, name, token))
                })
                .collect();
            Some(ChatItemData::Images { ids })
        }
        "FILES" => {
            let ids = value
                .get("items")?
                .as_array()?
                .iter()
                .filter_map(|i| {
                    let uri = i.get("uri").and_then(|u| u.as_str())?;
                    let name = i.get("fileName").and_then(|u| u.as_str()).unwrap_or("");
                    Some(make_file_id_json(uri, name, token))
                })
                .collect();
            Some(ChatItemData::Files { ids })
        }
        "TEXT" => {
            // For text messages, the encryption input is the bare
            // `imageLocalPath` (not wrapped in JSON) — matches plain-app
            // `ChatItem.getContentData()`'s `ChatText` branch.
            let ids = value
                .get("linkPreviews")?
                .as_array()?
                .iter()
                .filter_map(|p| p.get("imageLocalPath").and_then(|s| s.as_str()))
                .filter(|s| !s.is_empty())
                .map(|p| make_file_id(p, token))
                .collect();
            Some(ChatItemData::Text {
                link_preview_image_ids: ids,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/chat/content.rs"]
mod tests;

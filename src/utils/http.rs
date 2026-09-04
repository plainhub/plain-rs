/// CORS preflight headers. Same on the local server and the upstream
/// HTTP proxy — both surfaces serve the web UI, so the policy is
/// identical.
pub const CORS: &[u8] = b"access-control-allow-origin: *\r\n\
                       access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS\r\n\
                       access-control-allow-headers: *\r\n";

/// Parse an HTTP `Range` header (RFC 7233 §2.1) against a file size.
/// Returns the inclusive `(start, end)` byte range to serve, or `None`
/// when the header is absent, unsupported, or out of bounds.
///
/// Supported forms:
///   * `bytes=0-499`   → first 500 bytes
///   * `bytes=500-`    → from byte 500 to end
///   * `bytes=-500`    → last 500 bytes
///
/// Multi-range requests (`bytes=0-10,20-30`) are not supported — the
/// first range is served and the rest ignored, which keeps downloads
/// working without the multipart/byteranges dance. Callers should serve
/// a full 200 response when this returns `None`.
pub fn parse_range_header(range: &str, file_size: u64) -> Option<(u64, u64)> {
    let spec = range.strip_prefix("bytes=")?;
    let spec = spec.split(',').next()?.trim();
    let (start_s, end_s) = spec.split_once('-')?;
    let start_s = start_s.trim();
    let end_s = end_s.trim();
    if file_size == 0 {
        return None;
    }
    let (start, end) = match (start_s.is_empty(), end_s.is_empty()) {
        (false, false) => {
            let start: u64 = start_s.parse().ok()?;
            let end: u64 = end_s.parse().ok()?;
            if start > end || start >= file_size {
                return None;
            }
            (start, end.min(file_size - 1))
        }
        (false, true) => {
            let start: u64 = start_s.parse().ok()?;
            if start >= file_size {
                return None;
            }
            (start, file_size - 1)
        }
        (true, false) => {
            let n: u64 = end_s.parse().ok()?;
            if n == 0 {
                return None;
            }
            let start = file_size.saturating_sub(n);
            (start, file_size - 1)
        }
        (true, true) => return None,
    };
    Some((start, end))
}

/// Build a `Content-Disposition` header value (RFC 6266 / RFC 5987).
/// `kind` is `"inline"` or `"attachment"`; the filename is URL-encoded for
/// both the legacy `filename="…"` and the `filename*=utf-8''…` forms —
/// matching plain-app exactly so non-ASCII names round-trip correctly.
pub fn content_disposition(kind: &str, filename: &str) -> String {
    let encoded = super::query::url_encode(filename);
    format!("{kind}; filename=\"{encoded}\"; filename*=utf-8''{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_range_start_end() {
        assert_eq!(parse_range_header("bytes=0-499", 1000), Some((0, 499)));
        assert_eq!(parse_range_header("bytes=100-199", 1000), Some((100, 199)));
    }

    #[test]
    fn parse_range_open_end() {
        assert_eq!(parse_range_header("bytes=500-", 1000), Some((500, 999)));
    }

    #[test]
    fn parse_range_suffix() {
        assert_eq!(parse_range_header("bytes=-500", 1000), Some((500, 999)));
        assert_eq!(parse_range_header("bytes=-2000", 1000), Some((0, 999)));
    }

    #[test]
    fn parse_range_clamps_end_to_file_size() {
        assert_eq!(parse_range_header("bytes=900-2000", 1000), Some((900, 999)));
    }

    #[test]
    fn parse_range_rejects_out_of_bounds_start() {
        assert_eq!(parse_range_header("bytes=1000-", 1000), None);
        assert_eq!(parse_range_header("bytes=2000-3000", 1000), None);
    }

    #[test]
    fn parse_range_rejects_invalid_input() {
        assert_eq!(parse_range_header("", 1000), None);
        assert_eq!(parse_range_header("items=0-10", 1000), None);
        assert_eq!(parse_range_header("bytes=abc-def", 1000), None);
        assert_eq!(parse_range_header("bytes=-", 1000), None);
        assert_eq!(parse_range_header("bytes=-0", 1000), None);
        assert_eq!(parse_range_header("bytes=5-2", 1000), None);
        assert_eq!(parse_range_header("bytes=0-10", 0), None);
    }

    #[test]
    fn parse_range_multi_range_serves_first() {
        assert_eq!(parse_range_header("bytes=0-10,20-30", 1000), Some((0, 10)));
    }

    #[test]
    fn content_disposition_inline_and_attachment() {
        assert_eq!(
            content_disposition("inline", "cat.jpg"),
            "inline; filename=\"cat.jpg\"; filename*=utf-8''cat.jpg"
        );
        assert_eq!(
            content_disposition("attachment", "r port.pdf"),
            "attachment; filename=\"r%20port.pdf\"; filename*=utf-8''r%20port.pdf"
        );
    }

    #[test]
    fn content_disposition_encodes_non_ascii() {
        assert_eq!(
            content_disposition("inline", "中文.pdf"),
            "inline; filename=\"%E4%B8%AD%E6%96%87.pdf\"; filename*=utf-8''%E4%B8%AD%E6%96%87.pdf"
        );
    }
}

//! Public Notion URL discipline.
//!
//! The lane reads public pages only: HTTPS, on Notion's own
//! hosts, with no credential slot anywhere in the design. The
//! page id is never taken from the URL — Notion serves it in
//! the page's own bootstrap data, and the URL slug is decorative.

use fathom_core::error::{ErrorCode, FathomError};

/// The API host every chunk request goes to, whatever host the
/// page itself was served from.
pub const API_HOST: &str = "www.notion.so";

/// The chunk endpoint path on [`API_HOST`].
pub const CHUNK_PATH: &str = "/api/v3/loadCachedPageChunkV2";

/// Whether `host` may serve a public Notion page: `notion.so`,
/// `www.notion.so`, `notion.site`, or any `*.notion.site`
/// workspace domain. Suffix lookalikes (`notion.site.evil.com`,
/// `evil-notion.site`) are refused — the match is on whole
/// labels, never substrings.
pub fn page_host_allowed(host: &str) -> bool {
    host == "notion.so"
        || host == "www.notion.so"
        || host == "notion.site"
        || host.ends_with(".notion.site")
}

/// Validate a caller-supplied page URL and return it unchanged
/// for the fetch. Refuses non-HTTPS URLs and non-Notion hosts
/// before any network byte moves.
pub fn validate_page_url(url: &str) -> Result<String, FathomError> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        FathomError::new(
            ErrorCode::InvalidRequest,
            format!(
                "web_notion_tree reads public pages over HTTPS only; {url:?} is not an HTTPS URL"
            ),
        )
    })?;
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::InvalidRequest,
                format!("page URL {url:?} has no host"),
            )
        })?;
    // A userinfo or port component is never part of a public
    // page URL this lane will fetch.
    if host.contains('@') || host.contains(':') {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!("page URL {url:?} carries a userinfo or port component; refused"),
        ));
    }
    if !page_host_allowed(host) {
        return Err(FathomError::new(
            ErrorCode::InvalidRequest,
            format!(
                "page host {host:?} is not a Notion host (notion.so, notion.site, or a *.notion.site workspace)"
            ),
        ));
    }
    Ok(url.to_string())
}

/// Whether `text` has the canonical UUID shape Notion page ids
/// carry: 36 chars, hex digits and dashes at 8/13/18/23. The id
/// is interpolated into a JSON request body the lane builds, so
/// its shape is proven before it is used.
pub fn is_page_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    bytes.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            *byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    })
}

/// Extract the root page id from a public page's HTML: the
/// bootstrap data embeds `"pageId":"<uuid>"`. Absence is a
/// typed refusal — the page is not a public Notion page this
/// lane can read (it may be private, or not Notion at all).
pub fn page_id_from_html(html: &str) -> Result<String, FathomError> {
    let marker = "\"pageId\":\"";
    let start = html.find(marker).map(|index| index + marker.len()).ok_or_else(|| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            "the fetched page carries no pageId in its bootstrap data; it is not a public Notion page this lane can read",
        )
    })?;
    let candidate: String = html[start..].chars().take(36).collect();
    if !is_page_id(&candidate) {
        return Err(FathomError::new(
            ErrorCode::UnreadableOutput,
            "the pageId in the fetched page's bootstrap data is not a well-formed page id",
        ));
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_http_url_is_refused() {
        let err =
            validate_page_url("http://noggi3d.notion.site/guilty-gear-style-summary").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_lookalike_hosts_are_refused() {
        for url in [
            "https://notion.site.evil.com/page",
            "https://evil-notion.site/page",
            "https://notion.so.evil.com/page",
            "https://example.com/page",
        ] {
            let err = validate_page_url(url).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidRequest, "{url}");
        }
    }

    #[test]
    fn adversarial_malformed_page_ids_are_refused() {
        assert!(!is_page_id("36a2ccea-40b1-809c-b319-cbf3a879250")); // short
        assert!(!is_page_id("36a2ccea_40b1_809c_b319_cbf3a8792508")); // wrong separators
        assert!(!is_page_id("36a2ccea-40b1-809c-b319-cbf3a879250g")); // non-hex
        assert!(!is_page_id(""));
    }

    #[test]
    fn adversarial_missing_page_id_is_unreadable_output() {
        let err = page_id_from_html("<html><body>not notion</body></html>").unwrap_err();
        assert_eq!(err.code, ErrorCode::UnreadableOutput);
    }

    #[test]
    fn adversarial_userinfo_and_port_are_refused() {
        assert!(validate_page_url("https://user@noggi3d.notion.site/p").is_err());
        assert!(validate_page_url("https://noggi3d.notion.site:8080/p").is_err());
    }

    #[test]
    fn validation_public_hosts_are_allowed() {
        for url in [
            "https://noggi3d.notion.site/guilty-gear-style-summary",
            "https://www.notion.so/Some-Page-36a2ccea40b1809cb319cbf3a8792508",
            "https://notion.site/page",
            "https://notion.so/page",
        ] {
            assert!(validate_page_url(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn validation_page_id_extracted_from_bootstrap() {
        let html = r#"{"pageId":"36a2ccea-40b1-809c-b319-cbf3a8792508","spaceId":"x"}"#;
        assert_eq!(
            page_id_from_html(html).unwrap(),
            "36a2ccea-40b1-809c-b319-cbf3a8792508"
        );
    }

    #[test]
    fn validation_page_id_shape() {
        assert!(is_page_id("36a2ccea-40b1-809c-b319-cbf3a8792508"));
    }
}

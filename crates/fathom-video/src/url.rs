//! The §4.1 URL grammar: which strings name an ingestible
//! video. Hand-parsed on purpose — the grammar is a closed
//! allowlist (four hosts, four path forms, one id shape), and
//! anything outside it is an `invalid_request` refusal before
//! any child process exists (obligation 13's no-spawn leg).

use fathom_core::error::{ErrorCode, FathomError};

/// A validated video reference: the platform id and the one
/// canonical URL every fetch is made against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VideoRef {
    pub canonical_url: String,
    pub video_id: String,
}

const HOSTS: [&str; 4] = [
    "m.youtube.com",
    "www.youtube.com",
    "youtube.com",
    "youtu.be",
];

fn invalid(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::InvalidRequest, message)
}

/// The id grammar: exactly eleven characters of
/// `[A-Za-z0-9_-]` (YouTube-RE §4.1).
fn valid_id(id: &str) -> bool {
    id.len() == 11
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn id_or_refusal(id: &str) -> Result<VideoRef, FathomError> {
    if !valid_id(id) {
        return Err(invalid(format!(
            "'{id}' is not a video id: exactly 11 characters of [A-Za-z0-9_-]"
        )));
    }
    Ok(VideoRef {
        canonical_url: format!("https://www.youtube.com/watch?v={id}"),
        video_id: id.to_string(),
    })
}

fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            if key == name { Some(value) } else { None }
        })
        .next()
}

/// Parse one caller-supplied URL under the §4.1 grammar.
/// Playlist parameters are tolerated when a video id
/// resolves — the fetch template's `--no-playlist` governs
/// what is actually fetched; a playlist-only URL resolves
/// no id and is refused.
pub fn parse_video_url(raw: &str) -> Result<VideoRef, FathomError> {
    let trimmed = raw.trim();
    let (scheme, rest) = trimmed
        .split_once("://")
        .ok_or_else(|| invalid("the URL has no scheme; only http(s) YouTube URLs ingest"))?;
    if scheme != "http" && scheme != "https" {
        return Err(invalid(format!(
            "scheme '{scheme}' is not ingestible; only http(s) YouTube URLs ingest"
        )));
    }
    let no_fragment = rest.split('#').next().unwrap_or("");
    let authority_end = no_fragment.find(['/', '?']).unwrap_or(no_fragment.len());
    let authority = &no_fragment[..authority_end];
    if authority.contains('@') {
        return Err(invalid(
            "URLs with userinfo are refused: credentials never ride an ingest URL",
        ));
    }
    let host = authority
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if !HOSTS.contains(&host.as_str()) {
        return Err(invalid(format!(
            "host '{host}' is not an ingestible YouTube host"
        )));
    }
    let remainder = &no_fragment[authority_end..];
    let (path, query) = match remainder.split_once('?') {
        Some((path, query)) => (path, query),
        None => (remainder, ""),
    };
    if host == "youtu.be" {
        let id = path.strip_prefix('/').unwrap_or("");
        if id.contains('/') {
            return Err(invalid(
                "a youtu.be URL names exactly one path segment: the video id",
            ));
        }
        return id_or_refusal(id);
    }
    if path == "/watch" {
        return match query_param(query, "v") {
            Some(id) => id_or_refusal(id),
            None => Err(invalid(
                "a /watch URL with no 'v' parameter names no video \
                 (a playlist-only URL is not ingestible)",
            )),
        };
    }
    for prefix in ["/shorts/", "/live/"] {
        if let Some(id) = path.strip_prefix(prefix) {
            if id.contains('/') {
                return Err(invalid(format!(
                    "a {prefix} URL names exactly one path segment: the video id"
                )));
            }
            return id_or_refusal(id);
        }
    }
    Err(invalid(format!(
        "path '{path}' is not an ingestible video path \
         (/watch, /shorts/<id>, /live/<id>, or youtu.be/<id>)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_of(raw: &str) -> String {
        parse_video_url(raw).unwrap().video_id
    }

    #[test]
    fn validation_watch_shorts_live_and_shortlink_forms_resolve() {
        assert_eq!(
            id_of("https://www.youtube.com/watch?v=s9f9oa3Ae6c"),
            "s9f9oa3Ae6c"
        );
        assert_eq!(
            id_of("https://youtube.com/watch?v=s9f9oa3Ae6c&t=42"),
            "s9f9oa3Ae6c"
        );
        assert_eq!(
            id_of("https://m.youtube.com/watch?v=s9f9oa3Ae6c"),
            "s9f9oa3Ae6c"
        );
        assert_eq!(
            id_of("https://www.youtube.com/shorts/s9f9oa3Ae6c"),
            "s9f9oa3Ae6c"
        );
        assert_eq!(
            id_of("https://www.youtube.com/live/s9f9oa3Ae6c?si=x"),
            "s9f9oa3Ae6c"
        );
        assert_eq!(id_of("https://youtu.be/s9f9oa3Ae6c?t=9"), "s9f9oa3Ae6c");
        assert_eq!(id_of("http://youtu.be/s9f9oa3Ae6c#frag"), "s9f9oa3Ae6c");
    }

    #[test]
    fn validation_playlist_param_is_tolerated_when_an_id_resolves() {
        let parsed =
            parse_video_url("https://www.youtube.com/watch?v=s9f9oa3Ae6c&list=PL123&index=4")
                .unwrap();
        assert_eq!(
            parsed.canonical_url,
            "https://www.youtube.com/watch?v=s9f9oa3Ae6c"
        );
    }

    #[test]
    fn adversarial_userinfo_is_refused() {
        let err =
            parse_video_url("https://user:pass@www.youtube.com/watch?v=s9f9oa3Ae6c").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_non_platform_hosts_are_refused() {
        for raw in [
            "https://vimeo.com/s9f9oa3Ae6c",
            "https://www.youtube.com.evil.example/watch?v=s9f9oa3Ae6c",
            "https://notyoutube.com/watch?v=s9f9oa3Ae6c",
        ] {
            assert_eq!(
                parse_video_url(raw).unwrap_err().code,
                ErrorCode::InvalidRequest,
                "{raw}"
            );
        }
    }

    #[test]
    fn adversarial_playlist_only_and_id_shape_violations_are_refused() {
        for raw in [
            "https://www.youtube.com/playlist?list=PL123",
            "https://www.youtube.com/watch?list=PL123",
            "https://www.youtube.com/watch?v=short",
            "https://www.youtube.com/watch?v=s9f9oa3Ae6cX",
            "https://www.youtube.com/watch?v=s9f9oa3Ae6!",
            "https://www.youtube.com/shorts/",
            "https://youtu.be/s9f9oa3Ae6c/extra",
            "ftp://youtu.be/s9f9oa3Ae6c",
            "www.youtube.com/watch?v=s9f9oa3Ae6c",
        ] {
            assert_eq!(
                parse_video_url(raw).unwrap_err().code,
                ErrorCode::InvalidRequest,
                "{raw}"
            );
        }
    }
}

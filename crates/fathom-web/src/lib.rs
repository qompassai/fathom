//! fathom-web: the public Notion page-tree lane.
//!
//! One tool, `web_notion_tree`: given the URL of a public
//! Notion page, walk its complete block tree — the root page
//! and every child page, however deep — and return it as
//! deterministic markdown plus a block census.
//!
//! Why this exists: a public Notion page is a JavaScript
//! shell whose text is served in per-page chunks through
//! `loadCachedPageChunkV2`; a flat text fetch sees only the
//! root page's first chunk and misses every subsection that
//! lives on a child page. This lane reads the chunk API the
//! page itself uses, under the estate's fetch discipline:
//! public pages only, Notion hosts only, an owned `curl`
//! child under a fixed flag template with no credential
//! slot, named caps everywhere, and cap hits reported as
//! truncation flags rather than absorbed silently.
//!
//! The tool is Observe-class: the operator names it in
//! `allow_tools` before it may run (policy-first dispatch,
//! SPEC §8), because it causes network egress.
#![forbid(unsafe_code)]

mod render;
mod transport;
mod tree;
mod url;

use std::sync::Arc;

use serde_json::{Value, json};

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::sha256_hex;
use fathom_core::limits::{WEB_DEPTH_MAX, WEB_MARKDOWN_BYTES_MAX, WEB_PAGES_MAX};
use fathom_core::policy::ToolClass;
use fathom_core::registry::{Registry, descriptor, require_str};
use transport::{CurlTransport, NotionTransport};
use url::{page_id_from_html, validate_page_url};

/// Register this provider's tools with the registry.
pub fn register(registry: &mut Registry) {
    registry.register(
        descriptor(
            "web_notion_tree",
            ToolClass::Observe,
            "web",
            "Extract one public Notion page's complete block tree: the root page and every child page recursively, returned as deterministic markdown plus a per-page block census with a SHA-256 digest. Public pages on Notion hosts only; bounded by named caps, with truncation reported, never silent",
            json!({
                "type": "object",
                "properties": {
                    "include_raw": {"type": "boolean",
                        "description": "Also return the merged block map under `blocks` (default false)"},
                    "max_depth": {"type": "integer", "minimum": 0,
                        "description": "Child-page depth to walk (default and hard cap: WEB_DEPTH_MAX)"},
                    "max_pages": {"type": "integer", "minimum": 1,
                        "description": "Pages to fetch at most (default and hard cap: WEB_PAGES_MAX)"},
                    "url": {"type": "string",
                        "description": "A public Notion page URL (notion.so, notion.site, or a *.notion.site workspace)"},
                },
                "required": ["url"],
                "additionalProperties": false,
            }),
        ),
        Arc::new(web_notion_tree),
    );
}

/// An optional integer cap argument: absent means the hard
/// cap; a value outside `min..=hard` is a typed refusal (the
/// caller may only ever narrow a bound, never widen it).
fn optional_cap(args: &Value, field: &str, min: u64, hard: usize) -> Result<usize, FathomError> {
    match args.get(field) {
        None => Ok(hard),
        Some(value) => {
            let n = value.as_u64().ok_or_else(|| {
                FathomError::new(
                    ErrorCode::InvalidRequest,
                    format!("argument '{field}' must be an integer"),
                )
            })?;
            if n < min || n > hard as u64 {
                return Err(FathomError::new(
                    ErrorCode::InvalidRequest,
                    format!("argument '{field}' must be within {min}..={hard} (got {n})"),
                ));
            }
            Ok(n as usize)
        }
    }
}

fn web_notion_tree(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let url = validate_page_url(require_str(args, "url")?)?;
    let max_pages = optional_cap(args, "max_pages", 1, WEB_PAGES_MAX)?;
    let max_depth = optional_cap(args, "max_depth", 0, WEB_DEPTH_MAX)?;
    let include_raw = args
        .get("include_raw")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let scratch = config.state_dir.join("web");
    std::fs::create_dir_all(&scratch).map_err(|e| {
        FathomError::new(
            ErrorCode::ExecutionFailure,
            format!(
                "cannot create the web scratch dir {}: {e}",
                scratch.display()
            ),
        )
    })?;
    let transport = CurlTransport {
        program: config.web.fetcher_program.clone(),
        scratch,
    };
    let html = transport.fetch_page_html(&url)?;
    let root_page_id = page_id_from_html(&html)?;
    let assembled = tree::assemble(&transport, &root_page_id, max_pages, max_depth)?;
    let rendered = render::render(&assembled);
    let markdown_sha256 = sha256_hex(rendered.markdown.as_bytes());
    let (markdown, markdown_truncated) = if rendered.markdown.len() > WEB_MARKDOWN_BYTES_MAX {
        let mut cut = WEB_MARKDOWN_BYTES_MAX;
        while !rendered.markdown.is_char_boundary(cut) {
            cut -= 1;
        }
        (rendered.markdown[..cut].to_string(), true)
    } else {
        (rendered.markdown.clone(), false)
    };
    let mut redacted_block_ids: Vec<&String> = assembled.redacted_ids.iter().collect();
    redacted_block_ids.sort();
    let missing_block_ids: Vec<&String> = rendered.missing_block_ids.iter().collect();
    let pages: Vec<Value> = assembled
        .pages
        .iter()
        .map(|page| {
            let mut record = json!({
                "block_count": page.block_count,
                "chunk_truncated": page.chunk_truncated,
                "depth": page.depth,
                "id": page.id,
                "title": page.title,
            });
            if let Some(error) = &page.error {
                record["error"] = json!(error);
            }
            record
        })
        .collect();
    let mut result = json!({
        "block_type_counts": assembled.block_type_counts,
        "blocks_truncated": assembled.blocks_truncated,
        "depth_truncated": assembled.depth_truncated,
        "fetcher": config.web.fetcher_program.display().to_string(),
        "markdown": markdown,
        "markdown_sha256": markdown_sha256,
        "markdown_truncated": markdown_truncated,
        "missing_blocks": rendered.missing_block_ids.len(),
        "missing_block_ids": missing_block_ids,
        "pages": pages,
        "pages_truncated": assembled.pages_truncated,
        "redacted_block_ids": redacted_block_ids,
        "redacted_records": assembled.redacted_ids.len(),
        "root_page_id": root_page_id,
        "root_url": url,
        "total_blocks": assembled.blocks.len(),
    });
    if include_raw {
        result["blocks"] = Value::Object(
            assembled
                .blocks
                .iter()
                .map(|(id, block)| (id.clone(), block.clone()))
                .collect(),
        );
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::{ConfigFile, ProvidersFile, WebProviderFile};
    use fathom_core::registry::Registry as Reg;

    fn registry() -> Reg {
        let mut registry = Reg::new();
        register(&mut registry);
        registry
    }

    fn config(allow: &[&str]) -> Config {
        Config::from_file_form(ConfigFile {
            allow_tools: Some(allow.iter().map(|s| s.to_string()).collect()),
            providers: Some(ProvidersFile {
                web: Some(WebProviderFile {
                    fetcher_program: None,
                }),
                ..ProvidersFile::default()
            }),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    #[test]
    fn adversarial_observe_tool_is_denied_without_allow_tools() {
        let registry = registry();
        let err = registry
            .call(
                &config(&[]),
                "web_notion_tree",
                &json!({"url": "https://noggi3d.notion.site/x"}),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::AccessDenied);
    }

    #[test]
    fn adversarial_non_notion_url_is_refused_before_any_fetch() {
        let registry = registry();
        let err = registry
            .call(
                &config(&["web_notion_tree"]),
                "web_notion_tree",
                &json!({"url": "https://example.com/page"}),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn adversarial_cap_above_hard_max_is_refused() {
        let registry = registry();
        let err = registry
            .call(
                &config(&["web_notion_tree"]),
                "web_notion_tree",
                &json!({"url": "https://noggi3d.notion.site/x", "max_pages": 100000}),
            )
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }

    #[test]
    fn validation_catalog_carries_the_tool_as_observe() {
        let registry = registry();
        let descriptors = registry.descriptors();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].name, "web_notion_tree");
        assert_eq!(descriptors[0].tool_class.as_str(), "observe");
        assert_eq!(descriptors[0].provider, "web");
    }
}

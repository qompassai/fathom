//! Deterministic markdown rendering of an assembled tree.
//!
//! Pages render in breadth-first order under a `# <title>`
//! heading; blocks render in content order. The rendering is
//! a pure function of the tree — the same tree always renders
//! byte-identically, which is what makes the result's SHA-256
//! a meaningful evidence digest. A block type this renderer
//! does not know renders as an explicit unsupported-type line
//! with its children still walked. A reference the API does
//! not serve at all (a stale id in a content array - the
//! source renderer skips those too) is skipped and counted;
//! a reference that exists but is redacted renders as a
//! bracketed marker, because content exists and is withheld.

use std::collections::HashSet;

use serde_json::Value;

use crate::tree::{Tree, block_content, block_type, plain_field, rich_field};

/// What one render produced: the markdown and the ids of
/// block references that did not resolve in the tree
/// (sorted; the length is the missing census).
pub struct RenderOutcome {
    pub markdown: String,
    pub missing_block_ids: Vec<String>,
}

/// Render the whole tree.
pub fn render(tree: &Tree) -> RenderOutcome {
    let mut out = String::new();
    let mut missing: Vec<String> = Vec::new();
    for (index, page) in tree.pages.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let title = if page.title.is_empty() {
            "(untitled page)"
        } else {
            page.title.as_str()
        };
        out.push_str("# ");
        out.push_str(title);
        out.push_str("\n\n");
        if let Some(error) = &page.error {
            out.push_str(&format!("[page fetch failed: {error}]\n"));
            continue;
        }
        let mut visited: HashSet<String> = HashSet::from([page.id.clone()]);
        if let Some(root) = tree.blocks.get(&page.id) {
            for child in block_content(root) {
                render_block(tree, &child, 0, &mut visited, &mut out, &mut missing);
            }
        }
    }
    missing.sort();
    missing.dedup();
    RenderOutcome {
        markdown: out,
        missing_block_ids: missing,
    }
}

fn indent_of(depth: usize) -> String {
    "  ".repeat(depth)
}

fn push_line(out: &mut String, depth: usize, text: &str) {
    out.push_str(&indent_of(depth));
    out.push_str(text);
    out.push('\n');
}

fn render_children(
    tree: &Tree,
    block: &Value,
    depth: usize,
    visited: &mut HashSet<String>,
    out: &mut String,
    missing: &mut Vec<String>,
) {
    for child in block_content(block) {
        render_block(tree, &child, depth, visited, out, missing);
    }
}

fn render_block(
    tree: &Tree,
    id: &str,
    depth: usize,
    visited: &mut HashSet<String>,
    out: &mut String,
    missing: &mut Vec<String>,
) {
    if !visited.insert(id.to_string()) {
        return;
    }
    let Some(block) = tree.blocks.get(id) else {
        if tree.redacted_ids.contains(id) {
            push_line(out, depth, &format!("[redacted block: {id}]"));
        } else {
            missing.push(id.to_string());
        }
        return;
    };
    let kind = block_type(block);
    let title = rich_field(block, "title");
    match kind {
        "page" | "child_page" => {
            let label = plain_field(block, "title");
            push_line(out, depth, &format!("[child page: {label}]"));
        }
        "header" => push_line(out, depth, &format!("# {title}")),
        "sub_header" => push_line(out, depth, &format!("## {title}")),
        "sub_sub_header" => push_line(out, depth, &format!("### {title}")),
        "header_4" => push_line(out, depth, &format!("#### {title}")),
        "bulleted_list" => {
            push_line(out, depth, &format!("- {title}"));
            render_children(tree, block, depth + 1, visited, out, missing);
        }
        "numbered_list" => {
            push_line(out, depth, &format!("1. {title}"));
            render_children(tree, block, depth + 1, visited, out, missing);
        }
        "toggle" => {
            push_line(out, depth, &title);
            render_children(tree, block, depth + 1, visited, out, missing);
        }
        "quote" | "callout" => {
            push_line(out, depth, &format!("> {title}"));
            render_children(tree, block, depth, visited, out, missing);
        }
        "divider" => push_line(out, depth, "---"),
        "image" => {
            let caption = plain_field(block, "caption");
            let source = plain_field(block, "source");
            push_line(out, depth, &format!("![{caption}]({source})"));
        }
        "bookmark" => {
            let link = plain_field(block, "link");
            let label = if title.is_empty() {
                link.clone()
            } else {
                title.clone()
            };
            push_line(out, depth, &format!("[{label}]({link})"));
        }
        "code" => {
            let language = plain_field(block, "language");
            let code = plain_field(block, "title");
            let fence = if code.contains("```") { "````" } else { "```" };
            push_line(out, depth, &format!("{fence}{language}"));
            out.push_str(&code);
            out.push('\n');
            push_line(out, depth, fence);
        }
        "equation" => {
            let expression = plain_field(block, "title");
            push_line(out, depth, &format!("$${expression}$$"));
        }
        "table" => {
            render_children(tree, block, depth, visited, out, missing);
        }
        "table_row" => {
            let cells = table_cells(block);
            push_line(out, depth, &format!("| {} |", cells.join(" | ")));
        }
        "column" | "column_list" => {
            render_children(tree, block, depth, visited, out, missing);
        }
        "text" => {
            if !title.is_empty() {
                push_line(out, depth, &title);
            }
            render_children(tree, block, depth, visited, out, missing);
        }
        _ => {
            push_line(out, depth, &format!("[unsupported block type: {kind}]"));
            render_children(tree, block, depth, visited, out, missing);
        }
    }
}

/// One table row's cells, each flattened from its rich-text
/// segments (pipes escaped so the row stays one line).
fn table_cells(block: &Value) -> Vec<String> {
    let Some(cells) = block
        .get("properties")
        .and_then(|properties| properties.get("cells"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    cells
        .iter()
        .map(|cell| {
            let mut text = String::new();
            if let Some(segments) = cell.as_array() {
                for segment in segments {
                    if let Some(part) = segment.get(0).and_then(Value::as_str) {
                        text.push_str(part);
                    } else if let Some(part) = segment.as_str() {
                        text.push_str(part);
                    }
                }
            }
            text.replace('|', "\\|").replace('\n', " ")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::PageRecord;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn tree_with(blocks: Vec<(String, Value)>) -> Tree {
        let map: BTreeMap<String, Value> = blocks.into_iter().collect();
        Tree {
            block_type_counts: BTreeMap::new(),
            blocks: map,
            blocks_truncated: false,
            depth_truncated: false,
            pages: vec![PageRecord {
                block_count: 0,
                chunk_truncated: false,
                depth: 0,
                error: None,
                id: "root".to_string(),
                title: "Root".to_string(),
            }],
            pages_truncated: false,
            redacted_ids: HashSet::new(),
        }
    }

    fn block(kind: &str, title: &str, content: &[&str]) -> Value {
        json!({
            "type": kind,
            "properties": {"title": [[title]]},
            "content": content,
        })
    }

    #[test]
    fn validation_rendering_is_deterministic_and_ordered() {
        let tree = tree_with(vec![
            ("root".to_string(), block("page", "Root", &["h", "t", "l"])),
            ("h".to_string(), block("sub_header", "Deep Section", &[])),
            ("t".to_string(), block("text", "body text", &[])),
            ("l".to_string(), block("bulleted_list", "item", &["n"])),
            ("n".to_string(), block("text", "nested", &[])),
        ]);
        let outcome = render(&tree);
        assert!(outcome.missing_block_ids.is_empty());
        assert!(outcome.markdown.contains("## Deep Section"));
        assert!(outcome.markdown.contains("body text"));
        assert!(outcome.markdown.contains("- item"));
        assert!(outcome.markdown.contains("  nested"));
        // Same tree, same bytes.
        assert_eq!(render(&tree).markdown, outcome.markdown);
    }

    #[test]
    fn adversarial_unknown_type_is_named_never_dropped() {
        let tree = tree_with(vec![
            ("root".to_string(), block("page", "Root", &["x"])),
            ("x".to_string(), block("synced_block", "kept", &["y"])),
            ("y".to_string(), block("text", "inner", &[])),
        ]);
        let outcome = render(&tree);
        assert!(outcome.markdown.contains("[unsupported block type: synced_block]"));
        assert!(outcome.markdown.contains("inner"));
    }

    #[test]
    fn adversarial_missing_block_is_counted_not_rendered() {
        // A content id the API never serves is a stale
        // reference, not content: the source renderer skips
        // it, and so does this one - but the census counts it.
        let tree = tree_with(vec![(
            "root".to_string(),
            block("page", "Root", &["ghost"]),
        )]);
        let outcome = render(&tree);
        assert_eq!(outcome.missing_block_ids, vec!["ghost".to_string()]);
        assert!(!outcome.markdown.contains("ghost"));
    }
}

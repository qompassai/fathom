//! Chunk parsing and tree assembly.
//!
//! A public Notion page is a tree of blocks served in chunks:
//! one `loadCachedPageChunkV2` document per page, holding a
//! record map of that page's blocks. Blocks are double-wrapped
//! on the wire (`recordMap.block[id].value.value` is the block).
//! Child pages are blocks of type `page` whose own blocks live
//! in their own chunk — the "deepest subsections" a flat text
//! fetch never reaches. Assembly is a bounded breadth-first
//! walk: caps are named constants, cap hits are reported as
//! truncation flags in the result, never silently absorbed.

use std::collections::{BTreeMap, HashSet, VecDeque};

use serde_json::{Value, json};

use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::limits::{WEB_BLOCKS_MAX, WEB_CHUNKS_PER_PAGE_MAX};

use crate::transport::NotionTransport;

/// One assembled page: its census facts and, when its chunk
/// could not be fetched, the recorded failure. A failed child
/// page is a record, not a failed call — the rest of the tree
/// is still evidence.
#[derive(Clone, Debug)]
pub struct PageRecord {
    pub block_count: usize,
    pub chunk_truncated: bool,
    pub depth: usize,
    pub error: Option<String>,
    pub id: String,
    pub title: String,
}

/// The assembled tree: every fetched block by id, plus the
/// per-page census in breadth-first order.
#[derive(Clone, Debug)]
pub struct Tree {
    pub block_type_counts: BTreeMap<String, usize>,
    pub blocks: BTreeMap<String, Value>,
    pub blocks_truncated: bool,
    pub depth_truncated: bool,
    pub pages: Vec<PageRecord>,
    pub pages_truncated: bool,
    /// Ids the record map carried as redacted tombstones
    /// (`{"role": "none"}`, no block body): present in the
    /// census, never counted as blocks, and rendered as
    /// redacted rather than missing.
    pub redacted_ids: HashSet<String>,
}

/// The block's type string (`page`, `text`, `header`, ...);
/// records without one census as `unknown`.
pub fn block_type(block: &Value) -> &str {
    block
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

/// The block's ordered child block ids.
pub fn block_content(block: &Value) -> Vec<String> {
    block
        .get("content")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// One rich-text field's segments as (text, link) pairs. The
/// wire form is an array of `[text, annotations?]` segments;
/// the `a` annotation carries a link target, every other
/// annotation is presentation and flattens away.
pub fn rich_segments(block: &Value, field: &str) -> Vec<(String, Option<String>)> {
    let Some(segments) = block
        .get("properties")
        .and_then(|properties| properties.get(field))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    segments
        .iter()
        .map(|segment| {
            if let Some(text) = segment.as_str() {
                return (text.to_string(), None);
            }
            let text = segment
                .get(0)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let mut link = None;
            if let Some(annotations) = segment.get(1).and_then(Value::as_array) {
                for annotation in annotations {
                    if annotation.get(0).and_then(Value::as_str) == Some("a") {
                        link = annotation
                            .get(1)
                            .and_then(Value::as_str)
                            .map(str::to_string);
                    }
                }
            }
            (text, link)
        })
        .collect()
}

/// A rich-text field flattened to plain text (titles,
/// captions, URLs, code).
pub fn plain_field(block: &Value, field: &str) -> String {
    rich_segments(block, field)
        .into_iter()
        .map(|(text, _)| text)
        .collect()
}

/// A rich-text field rendered as markdown text: links keep
/// their targets, everything else is the plain text.
pub fn rich_field(block: &Value, field: &str) -> String {
    let mut out = String::new();
    for (text, link) in rich_segments(block, field) {
        match link {
            Some(url) => {
                out.push('[');
                out.push_str(&text);
                out.push_str("](");
                out.push_str(&url);
                out.push(')');
            }
            None => out.push_str(&text),
        }
    }
    out
}

/// One parsed chunk document: its blocks by id, the cursor
/// stack for the next chunk (`None` when the page is
/// complete), and the ids of any redacted tombstone records.
#[derive(Debug)]
pub struct ParsedChunk {
    pub blocks: BTreeMap<String, Value>,
    pub next_cursor: Option<Value>,
    pub redacted_ids: Vec<String>,
}

/// Parse one chunk document. A non-empty cursor stack means
/// the page has more chunks; the stack is returned so the
/// caller can hand it back verbatim. Records whose body the
/// public view may not see arrive as tombstones
/// (`{"role": "none"}` with no block): they are reported as
/// redacted ids, never silently dropped and never counted
/// as blocks.
pub fn parse_chunk(document: &Value) -> Result<ParsedChunk, FathomError> {
    let map = document
        .get("recordMap")
        .and_then(|record_map| record_map.get("block"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            FathomError::new(
                ErrorCode::UnreadableOutput,
                "the chunk document carries no recordMap.block object",
            )
        })?;
    let mut blocks = BTreeMap::new();
    let mut redacted = Vec::new();
    for (id, entry) in map {
        // Double-wrapped on the wire; a single-wrapped record
        // that still names its id is accepted (API drift is
        // absorbed at this seam, nowhere else).
        let inner = entry
            .get("value")
            .and_then(|value| value.get("value"))
            .filter(|inner| inner.get("id").is_some())
            .or_else(|| entry.get("value").filter(|inner| inner.get("id").is_some()));
        match inner {
            Some(block) => {
                blocks.insert(id.clone(), block.clone());
            }
            None => redacted.push(id.clone()),
        }
    }
    let next_cursor = document
        .get("cursor")
        .and_then(|cursor| cursor.get("stack"))
        .filter(|stack| stack.as_array().is_some_and(|items| !items.is_empty()))
        .cloned();
    Ok(ParsedChunk {
        blocks,
        next_cursor,
        redacted_ids: redacted,
    })
}

/// Child page ids referenced by one page's own blocks, in
/// content order, deduplicated. The walk stays inside the
/// page's chunk: a child page's blocks are not here.
fn discover_children(page_blocks: &BTreeMap<String, Value>, page_id: &str) -> Vec<String> {
    let mut children: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::from([page_id.to_string()]);
    let mut visited: HashSet<String> = HashSet::new();
    while let Some(id) = queue.pop_front() {
        if !visited.insert(id.clone()) {
            continue;
        }
        let Some(block) = page_blocks.get(&id) else {
            continue;
        };
        if id != page_id && matches!(block_type(block), "page" | "child_page") {
            if seen.insert(id.clone()) {
                children.push(id.clone());
            }
            continue;
        }
        for child in block_content(block) {
            queue.push_back(child);
        }
    }
    children
}

/// Assemble the full tree under `root_page_id` through
/// `transport`, bounded by `max_pages` / `max_depth` (already
/// validated against the hard caps by the caller).
pub fn assemble(
    transport: &dyn NotionTransport,
    root_page_id: &str,
    max_pages: usize,
    max_depth: usize,
) -> Result<Tree, FathomError> {
    let mut tree = Tree {
        block_type_counts: BTreeMap::new(),
        blocks: BTreeMap::new(),
        blocks_truncated: false,
        depth_truncated: false,
        pages: Vec::new(),
        pages_truncated: false,
        redacted_ids: HashSet::new(),
    };
    let mut queue: VecDeque<(String, usize)> = VecDeque::from([(root_page_id.to_string(), 0)]);
    let mut visited: HashSet<String> = HashSet::from([root_page_id.to_string()]);
    while let Some((page_id, depth)) = queue.pop_front() {
        if tree.pages.len() >= max_pages {
            tree.pages_truncated = true;
            break;
        }
        let is_root = tree.pages.is_empty();
        // Fetch every chunk of this page, following cursors.
        let mut page_blocks: BTreeMap<String, Value> = BTreeMap::new();
        let mut chunk_truncated = false;
        let mut error: Option<String> = None;
        let mut cursor = json!([]);
        let mut chunk_number: u64 = 0;
        loop {
            if chunk_number >= WEB_CHUNKS_PER_PAGE_MAX as u64 {
                chunk_truncated = true;
                break;
            }
            let fetched = transport
                .fetch_chunk(&page_id, chunk_number, &cursor)
                .and_then(|document| parse_chunk(&document));
            match fetched {
                Ok(parsed) => {
                    tree.redacted_ids.extend(parsed.redacted_ids);
                    page_blocks.extend(parsed.blocks);
                    match parsed.next_cursor {
                        Some(stack) => {
                            cursor = stack;
                            chunk_number += 1;
                        }
                        None => break,
                    }
                }
                Err(err) => {
                    if is_root {
                        return Err(err);
                    }
                    error = Some(err.message.clone());
                    break;
                }
            }
        }
        // Merge into the tree census under the block cap.
        for (id, block) in &page_blocks {
            if tree.blocks.contains_key(id) {
                continue;
            }
            if tree.blocks.len() >= WEB_BLOCKS_MAX {
                tree.blocks_truncated = true;
                break;
            }
            *tree
                .block_type_counts
                .entry(block_type(block).to_string())
                .or_insert(0) += 1;
            tree.blocks.insert(id.clone(), block.clone());
        }
        let title = page_blocks
            .get(&page_id)
            .map(|root| plain_field(root, "title"))
            .unwrap_or_default();
        tree.pages.push(PageRecord {
            block_count: page_blocks.len(),
            chunk_truncated,
            depth,
            error,
            id: page_id.clone(),
            title,
        });
        if tree.blocks_truncated {
            break;
        }
        // Enqueue this page's child pages in content order.
        for child in discover_children(&page_blocks, &page_id) {
            if visited.contains(&child) {
                continue;
            }
            if depth + 1 > max_depth {
                tree.depth_truncated = true;
                continue;
            }
            visited.insert(child.clone());
            queue.push_back((child, depth + 1));
        }
    }
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap as Map;

    const ROOT_CHUNK: &str = include_str!("../tests/fixtures/chunk-root.json");
    const SHADING_CHUNK: &str = include_str!("../tests/fixtures/chunk-shading.json");
    const ROOT_ID: &str = "36a2ccea-40b1-809c-b319-cbf3a8792508";
    const SHADING_ID: &str = "36a2ccea-40b1-8095-8d29-e30ccaff299f";

    /// Fixture transport: recorded chunk documents by page id,
    /// served in call order; an unlisted page is a typed
    /// failure, exactly like a dead child page upstream.
    struct FixtureTransport {
        chunks: Map<String, Vec<Value>>,
        served: RefCell<Map<String, usize>>,
    }

    impl FixtureTransport {
        fn new(chunks: Map<String, Vec<Value>>) -> Self {
            FixtureTransport {
                chunks,
                served: RefCell::new(Map::new()),
            }
        }
    }

    impl NotionTransport for FixtureTransport {
        fn fetch_chunk(
            &self,
            page_id: &str,
            _chunk_number: u64,
            _cursor_stack: &Value,
        ) -> Result<Value, FathomError> {
            let docs = self.chunks.get(page_id).ok_or_else(|| {
                FathomError::new(
                    ErrorCode::TargetUnavailable,
                    format!("fixture has no chunk for {page_id}"),
                )
            })?;
            let mut served = self.served.borrow_mut();
            let index = served.entry(page_id.to_string()).or_insert(0);
            let doc = docs.get(*index).ok_or_else(|| {
                FathomError::new(ErrorCode::TargetUnavailable, "fixture chunks exhausted")
            })?;
            *index += 1;
            Ok(doc.clone())
        }

        fn fetch_page_html(&self, _url: &str) -> Result<String, FathomError> {
            Ok(format!(r#"{{"pageId":"{ROOT_ID}"}}"#))
        }
    }

    fn doc(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn validation_root_fixture_parses_blocks_and_one_redacted_tombstone() {
        // The record map carries 37 entries: 36 block bodies
        // and one redacted tombstone ({"role": "none"}).
        let parsed = parse_chunk(&doc(ROOT_CHUNK)).unwrap();
        assert_eq!(parsed.blocks.len(), 36);
        assert_eq!(parsed.redacted_ids.len(), 1);
        assert!(parsed.next_cursor.is_none());
        let root = &parsed.blocks[ROOT_ID];
        assert_eq!(block_type(root), "page");
        assert_eq!(
            plain_field(root, "title"),
            "How Guilty Gear Achieves its 2D Look"
        );
    }

    #[test]
    fn validation_root_fixture_discovers_four_child_pages() {
        let parsed = parse_chunk(&doc(ROOT_CHUNK)).unwrap();
        let children = discover_children(&parsed.blocks, ROOT_ID);
        assert_eq!(children.len(), 4);
        assert!(children.contains(&SHADING_ID.to_string()));
    }

    #[test]
    fn validation_two_page_tree_merges_without_double_counting() {
        let mut chunks = Map::new();
        chunks.insert(ROOT_ID.to_string(), vec![doc(ROOT_CHUNK)]);
        chunks.insert(SHADING_ID.to_string(), vec![doc(SHADING_CHUNK)]);
        let transport = FixtureTransport::new(chunks);
        let tree = assemble(&transport, ROOT_ID, 64, 8).unwrap();
        // Root + Shading fetched; the other three children are
        // recorded failures, not a failed call.
        assert_eq!(tree.pages.len(), 5);
        let shading = tree
            .pages
            .iter()
            .find(|page| page.id == SHADING_ID)
            .unwrap();
        assert!(shading.error.is_none());
        assert_eq!(shading.title, "Shading");
        let failed: Vec<_> = tree
            .pages
            .iter()
            .filter(|page| page.error.is_some())
            .collect();
        assert_eq!(failed.len(), 3);
        // The union of both chunks' block ids, nothing more.
        let mut expected: HashSet<String> = HashSet::new();
        for text in [ROOT_CHUNK, SHADING_CHUNK] {
            let parsed = parse_chunk(&doc(text)).unwrap();
            expected.extend(parsed.blocks.keys().cloned());
        }
        assert_eq!(tree.blocks.len(), expected.len());
        assert!(!tree.pages_truncated);
    }

    #[test]
    fn validation_cursor_is_followed_until_exhausted() {
        // One page in two chunks: the first answers with a
        // non-empty cursor stack, the second completes it.
        let first = json!({
            "cursor": {"stack": [["opaque-token"]]},
            "recordMap": {"block": {
                "p": {"value": {"value": {"id": "p", "type": "page",
                    "properties": {"title": [["T"]]},
                    "content": ["a"]}}},
                "a": {"value": {"value": {"id": "a", "type": "text",
                    "properties": {"title": [["one"]]}}}}
            }}
        });
        let second = json!({
            "cursor": {"stack": []},
            "recordMap": {"block": {
                "b": {"value": {"value": {"id": "b", "type": "text",
                    "properties": {"title": [["two"]]}}}}
            }}
        });
        let mut chunks = Map::new();
        chunks.insert("p".to_string(), vec![first, second]);
        let transport = FixtureTransport::new(chunks);
        let tree = assemble(&transport, "p", 64, 8).unwrap();
        assert_eq!(tree.blocks.len(), 3);
        assert!(!tree.pages[0].chunk_truncated);
    }

    #[test]
    fn adversarial_root_chunk_failure_is_a_call_failure() {
        let transport = FixtureTransport::new(Map::new());
        let err = assemble(&transport, ROOT_ID, 64, 8).unwrap_err();
        assert_eq!(err.code, ErrorCode::TargetUnavailable);
    }

    #[test]
    fn adversarial_malformed_chunk_document_is_unreadable() {
        let err = parse_chunk(&json!({"recordMap": {}})).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnreadableOutput);
    }

    #[test]
    fn adversarial_page_cap_truncates_and_reports() {
        let mut chunks = Map::new();
        chunks.insert(ROOT_ID.to_string(), vec![doc(ROOT_CHUNK)]);
        let transport = FixtureTransport::new(chunks);
        let tree = assemble(&transport, ROOT_ID, 1, 8).unwrap();
        assert_eq!(tree.pages.len(), 1);
        assert!(tree.pages_truncated);
    }

    #[test]
    fn adversarial_depth_cap_truncates_and_reports() {
        let mut chunks = Map::new();
        chunks.insert(ROOT_ID.to_string(), vec![doc(ROOT_CHUNK)]);
        let transport = FixtureTransport::new(chunks);
        let tree = assemble(&transport, ROOT_ID, 64, 0).unwrap();
        assert_eq!(tree.pages.len(), 1);
        assert!(tree.depth_truncated);
    }
}

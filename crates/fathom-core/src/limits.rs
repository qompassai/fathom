//! Named resource bounds (SPEC §8).
//!
//! Every costly operation checks its bound before it starts. A
//! bound hit is a `resource_constraint` error or a reported
//! truncation in the evidence — never an unbounded retry.

/// Addresses answered by one per-address Ghidra query (mirrors the
/// export script's ADDRESS_QUERY_MAX).
pub const ADDRESS_QUERY_COUNT_MAX: usize = 32;

/// Canonical bytes of one retained archive census document
/// (readers SPEC §2.5).
pub const ARCHIVE_EXPORT_BYTES_MAX: usize = 33_554_432;

/// Bytes in one archive target for the seek-based readers
/// (readers SPEC §2.2): the RPA acceptance fixture is over
/// 1 GiB, past the whole-file bound below.
pub const ARCHIVE_TARGET_BYTES_MAX: u64 = 4_294_967_296;

/// Entries retained from one ASAR archive listing.
pub const ASAR_ENTRIES_MAX: usize = 100_000;

/// Atoms retained from one BEAM module's atom table (S6).
pub const BEAM_ATOMS_MAX: usize = 20_000;

/// Function-table rows (exports, locals, imports, lambdas)
/// retained from one BEAM module (S6).
pub const BEAM_FUNCTIONS_MAX: usize = 20_000;

/// Bytes in one byte-search pattern, wildcards included.
pub const BYTE_PATTERN_BYTES_MAX: usize = 64;

/// Patterns in one byte search (mirrors BYTE_PATTERN_MAX).
pub const BYTE_PATTERN_COUNT_MAX: usize = 32;

/// Drawables censused in one Cubism moc3 (game-extract lane).
pub const CUBISM_DRAWABLES_MAX: usize = 100_000;

/// Bytes per ID slot in a moc3 string table (format fact: IDs
/// are NUL-padded 64-byte records).
pub const CUBISM_ID_SLOT_BYTES: usize = 64;

/// Parameters censused in one Cubism moc3 (game-extract lane).
pub const CUBISM_PARAMETERS_MAX: usize = 100_000;

/// Parts censused in one Cubism moc3 (game-extract lane).
pub const CUBISM_PARTS_MAX: usize = 100_000;

/// Hops walked from one function in a call-graph neighborhood or
/// an API call-chain search.
pub const CALL_GRAPH_DEPTH_MAX: usize = 8;

/// Functions decompiled by one batch (mirrors DECOMPILE_BATCH_MAX).
pub const DECOMPILE_BATCH_COUNT_MAX: usize = 8;

/// Bytes of decompiled output retained per function dossier.
pub const DECOMPILE_BYTES_MAX: usize = 1_048_576;

/// Bytes decoded by one read-only disassembly request (mirrors
/// DISASSEMBLE_BYTES_MAX).
pub const DISASSEMBLE_BYTES_MAX: usize = 4_096;

/// Files inventoried under one directory target.
pub const FILE_COUNT_MAX: usize = 100_000;

/// Functions examined by one multi-function field-usage query
/// (each is its own Ghidra run).
pub const FIELD_USAGE_FUNCTION_COUNT_MAX: usize = 4;

/// Functions retained from one program inventory.
pub const FUNCTION_COUNT_MAX: usize = 5_000;

/// Wall-clock bound for one Ghidra provider run that performs a
/// Directory depth descended by one game-tree census.
pub const GAME_WALK_DEPTH_MAX: usize = 24;

/// Files inventoried by one game-tree census.
pub const GAME_WALK_FILES_MAX: usize = 200_000;

/// Total bytes one game-archive extraction may write.
pub const GAME_EXTRACT_BYTES_MAX: u64 = 4_294_967_296;

/// Largest pak target the Unreal reader will open. The
/// pak reader streams bounded ranges (footer, SHA-1-
/// verified index, per-entry spans) and never
/// materialises the target, so its bound is set for
/// real shipped titles rather than the shared archive
/// bound: the corpus's largest pak is 7.9 GB.
pub const PAK_TARGET_BYTES_MAX: u64 = 68_719_476_736;

/// Largest string the uasset census accepts in one
/// FString (names in real packages are short paths and
/// identifiers).
pub const UASSET_NAME_BYTES_MAX: u32 = 1_024;

/// Largest name table the uasset census will walk.
pub const UASSET_NAMES_MAX: u64 = 65_536;

/// Largest export map the uasset census will walk.
pub const UASSET_EXPORTS_MAX: u64 = 100_000;

/// Largest import map the uasset census will walk.
pub const UASSET_IMPORTS_MAX: u64 = 100_000;

/// Rows of any one map the uasset census lists in its
/// findings; totals are always reported in full.
pub const UASSET_LISTED_MAX: usize = 4_096;

/// Largest chunk count the GameMaker census will walk.
pub const GM_CHUNKS_MAX: usize = 4_096;

/// Largest entry count accepted from one GameMaker
/// chunk's count + offset table.
pub const GM_ENTRIES_MAX: u64 = 1_000_000;

/// Largest single string the GameMaker census reads.
pub const GM_STRING_BYTES_MAX: u32 = 65_536;

/// Largest STRG table the GameMaker census lists.
pub const GM_STRINGS_MAX: u64 = 100_000;

/// Largest entry count the XP3 census will walk.
pub const XP3_ENTRIES_MAX: usize = 100_000;

/// Largest index (stored or inflated) the XP3 reader
/// will materialise.
pub const XP3_INDEX_BYTES_MAX: u64 = 268_435_456;

/// Largest segment count accepted for one XP3 entry.
pub const XP3_SEGMENTS_MAX: usize = 1_024;

/// Largest file count the audio census will process in
/// one tree.
pub const AUDIO_FILES_MAX: usize = 100_000;

/// Bytes of file head the audio census reads for header
/// parsing (MP3 frame/Xing search and MP4 box search
/// need the most room).
pub const AUDIO_HEAD_BYTES_MAX: u64 = 1_048_576;

/// Largest node count the FBX census will walk.
pub const FBX_NODES_MAX: usize = 1_000_000;

/// Deepest nesting the FBX census will walk.
pub const FBX_DEPTH_MAX: usize = 64;

/// Largest glTF file the census will read whole.
pub const GLTF_BYTES_MAX: u64 = 268_435_456;

/// Largest node/mesh count accepted in one glTF
/// census.
pub const GLTF_ITEMS_MAX: usize = 100_000;

/// Largest single dialogue file the census will read.
pub const DIALOGUE_FILE_BYTES_MAX: u64 = 67_108_864;

/// Largest dialogue-file count in one census or dump.
pub const DIALOGUE_FILES_MAX: usize = 4_096;

/// Largest dialogue row count in one dump.
pub const DIALOGUE_ROWS_MAX: usize = 1_000_000;

/// first import (full auto-analysis of a subject with no imported
/// project yet), seconds. First import of a large debug binary is
/// measured in tens of minutes — a 76 MB Rust debug ELF took
/// 1128 s on primo — far past the repeat-run bound below; the
/// split gives a first import room to finish and populate the
/// cache while repeat runs stay tight. Owner ruling D-241
/// (2026-10-28): "raise the bound, test the heap."
pub const GHIDRA_FIRST_IMPORT_TIMEOUT_SECS: u64 = 1_800;

/// Default wall-clock bound for one Ghidra provider run against
/// an already-imported project (a re-export, not an analysis),
/// seconds.
pub const GHIDRA_TIMEOUT_SECS: u64 = 330;

/// Kernel symbols retained from one GPU code object (S7).
pub const GPU_KERNELS_MAX: usize = 5_000;

/// Listing instructions retained in one function dossier.
pub const INSTRUCTION_COUNT_MAX: usize = 2_000;

/// Rows one paged listing returns at most (`limit` ceiling).
pub const LIST_PAGE_ROWS_MAX: usize = 5_000;

/// Bytes captured from one child-process stream.
pub const OUTPUT_BYTES_MAX: usize = 8_388_608;

/// Ceiling on rows in one paged inventory read. A page is
/// additionally capped by the inventory's own count bound.
pub const PAGE_LIMIT_MAX: usize = 20_000;

/// Declared entries in one Unreal pak index (readers SPEC §2.3).
pub const PAK_ENTRIES_MAX: usize = 100_000;

/// Entries retained from one Godot PCK archive listing.
pub const PCK_ENTRIES_MAX: usize = 100_000;

/// Bytes captured from one `capture_process` stream.
pub const PROCESS_OUTPUT_BYTES_MAX: usize = 1_048_576;

/// Default wall-clock bound for one `capture_process` run, seconds.
pub const PROCESS_TIMEOUT_SECS: u64 = 60;

/// Serialized bytes of one reconstruction proof, stored or
/// inline (SPEC §4.1.9).
pub const PROOF_BYTES_MAX: usize = 1_048_576;

/// Claims in one reconstruction proof (SPEC §4.1.9).
pub const PROOF_CLAIMS_MAX: usize = 256;

/// Characters of one per-claim verification diagnostic
/// (SPEC §4.1.9).
pub const PROOF_DIAGNOSTIC_CHARS_MAX: usize = 512;

/// Evidence references bound to one claim (SPEC §4.1.9).
pub const PROOF_EVIDENCE_PER_CLAIM_MAX: usize = 32;

/// Proofs stored for one subject; a build past the cap is
/// refused, never a silent eviction (SPEC §4.1.9).
pub const PROOF_PER_SUBJECT_MAX: usize = 64;

/// Canonical bytes of one claim's statement facts (SPEC §4.1.9).
pub const PROOF_STATEMENT_BYTES_MAX: usize = 16_384;

/// Code objects retained from one .pyc code tree (S5).
pub const PYC_CODE_OBJECTS_MAX: usize = 5_000;

/// String constants censused per code object in a .pyc (S5).
pub const PYC_STRING_CONSTS_MAX: usize = 256;

/// Values the bounded .pyc marshal reader may construct (S5).
pub const PYC_VALUES_MAX: usize = 1_000_000;

/// Entries retained from one PyInstaller TOC (S5).
pub const PYINSTALLER_ENTRIES_MAX: usize = 100_000;

/// Module rows retained from one PyInstaller PYZ archive (S5).
pub const PYZ_MODULES_MAX: usize = 100_000;

/// Bytes in one free-text query argument (names, type strings,
/// prototypes, search terms, numbers).
pub const QUERY_TEXT_BYTES_MAX: usize = 512;

/// Decoded segment rows in one Ren'Py RPA index (readers SPEC §2.3).
pub const RPA_ENTRIES_MAX: usize = 100_000;

/// Entries in one RGSS archive.
pub const RGSS_ENTRIES_MAX: usize = 100_000;

/// Bytes in one RGSS entry name.
pub const RGSS_NAME_BYTES_MAX: u32 = 4_096;

/// Decompressed bytes of one Ren'Py RPA pickle index
/// (readers SPEC §2.3).
pub const RPA_INDEX_BYTES_MAX: usize = 33_554_432;

/// Values the restricted RPA pickle reader may construct
/// (readers SPEC §5.4).
pub const RPA_PICKLE_NODES_MAX: usize = 2_000_000;

/// Spec documents (`fathom-spec/1`) are read whole; the
/// cap keeps a hostile or corrupt record from becoming an
/// unbounded allocation.
pub const SPEC_DOCUMENT_BYTES_MAX: u64 = 33_554_432;

/// Evidence pointers one statement may carry. A claim cites
/// a handful of records, never an archive.
pub const SPEC_EVIDENCE_POINTERS_MAX: usize = 16;

/// Statements in one spec document. A behaviour unit is
/// stated in tens of claims; thousands means the unit is
/// not a unit.
pub const SPEC_STATEMENTS_MAX: usize = 4_096;

/// Rows in one spec data table (aligned with the Cubism
/// census bounds the tables derive from).
pub const SPEC_TABLE_ROWS_MAX: usize = 100_000;

/// Unknowns in one spec document. Each names its closing
/// probe; the cap keeps the gap list a list, not a dump.
pub const SPEC_UNKNOWNS_MAX: usize = 256;

/// Violations one validation verdict itemises. Past the
/// cap the spec is invalid either way; the verdict says
/// what it found first.
pub const SPEC_VIOLATIONS_MAX: usize = 256;

/// Checks one spec diff reports (the corpus harness shape
/// is ~113; the cap is headroom, not a target).
pub const SPEC_CHECKS_MAX: usize = 4_096;

/// Strings retained from one program inventory.
pub const STRING_COUNT_MAX: usize = 5_000;

/// Symbols retained from one program inventory.
pub const SYMBOL_COUNT_MAX: usize = 20_000;

/// Bytes in one analysis target (hashed and read by providers).
pub const TARGET_BYTES_MAX: u64 = 536_870_912;

/// Largest Texture2D width or height the extractor
/// accepts from a payload prefix (game-extract lane).
pub const TEXTURE_DIMENSION_MAX: i32 = 65_536;

/// Decompressed bytes of one UnityFS blocks-info blob
/// (readers SPEC §2.3).
pub const UNITY_BLOCKS_INFO_BYTES_MAX: usize = 16_777_216;

/// Total payload bytes one `extract_unity_bundle` call writes
/// (game-extract lane); entries past the bound are recorded as
/// skipped, never silently dropped.
pub const UNITY_EXTRACT_BYTES_MAX: u64 = 4_294_967_296;

/// Moc3 payloads carved from one MonoBehaviour's raw bytes
/// (game-extract lane).
pub const UNITY_EXTRACT_CARVES_MAX: usize = 256;

/// File identifiers (externals) retained per SerializedFile
/// by the MonoBehaviour census walk (BQ-2); script-type rows
/// share the bound on the same walk.
pub const UNITY_EXTERNALS_MAX: usize = 100_000;

/// Candidate files one `census_unity_monobehaviours` call
/// examines under its target directory (BQ-2); files past
/// the bound are reported, never silently dropped.
pub const UNITY_MB_FILES_MAX: usize = 4_096;

/// Object payload rows the MonoBehaviour census retains
/// per SerializedFile (BQ-2) — far above the shared
/// UNITY_OBJECTS_MAX record cap, because a census that
/// stops at the record cap is a floor, not a census; the
/// corpus's largest file declares 642,185 objects. Rows
/// past the bound are reported via the truncation flag.
pub const UNITY_MB_OBJECTS_MAX: usize = 4_000_000;

/// Directory depth one `census_unity_monobehaviours` call
/// descends under its target directory (BQ-2).
pub const UNITY_MB_WALK_DEPTH_MAX: usize = 6;

/// Directory nodes in one UnityFS bundle (readers SPEC §2.3).
pub const UNITY_NODES_MAX: usize = 100_000;

/// Object rows retained per SerializedFile; counts stay exact
/// past the cap (readers SPEC §2.3).
pub const UNITY_OBJECTS_MAX: usize = 100_000;

/// Type records retained per SerializedFile (readers SPEC §2.3).
pub const UNITY_TYPES_MAX: usize = 100_000;

/// Fetched media bytes for one video ingest (YouTube-RE
/// SPEC §11); checked at pre-flight against format
/// estimates, refused before download.
pub const VIDEO_BYTES_MAX: u64 = 8_589_934_592;

/// Chapter records retained per video ingest (YouTube-RE §11).
pub const VIDEO_CHAPTERS_MAX: usize = 256;

/// Bytes of one crystallization draft document (YouTube-RE
/// §11); named at Y1 though the drafting tool is Y5.
pub const VIDEO_DRAFT_BYTES_MAX: usize = 262_144;

/// Video duration admitted to ingest, seconds (YouTube-RE
/// §11); longer is refused at pre-flight.
pub const VIDEO_DURATION_SECS_MAX: u64 = 3_600;

/// Wall clock for one fetch child — media, captions, and
/// info (YouTube-RE §11).
pub const VIDEO_FETCH_TIMEOUT_SECS: u64 = 900;

/// Bytes of one retained frame PNG (YouTube-RE §11); also
/// the per-frame return bound in reads.
pub const VIDEO_FRAME_BYTES_MAX: usize = 8_388_608;

/// Minimum uniform-grid frame sampling interval, seconds
/// (YouTube-RE §11); the grid leg raises it to fit
/// `VIDEO_FRAMES_MAX`.
pub const VIDEO_FRAME_GRID_SECS: u64 = 2;

/// Frames retained per video ingest, both sampling legs
/// together (YouTube-RE §11).
pub const VIDEO_FRAMES_MAX: usize = 512;

/// Serialized bytes of one video guide document
/// (YouTube-RE §11).
pub const VIDEO_GUIDE_BYTES_MAX: usize = 1_048_576;

/// Steps (including gap and conflict records) in one video
/// guide (YouTube-RE §11).
pub const VIDEO_GUIDE_STEPS_MAX: usize = 256;

/// Total guide/spec revision cycles in one run before the
/// `bound_hit` stop record (YouTube-RE §11).
pub const VIDEO_ITERATIONS_MAX: u64 = 6;

/// Captured bytes of one `--dump-single-json` metadata
/// document (YouTube-RE §11, added at the D-184 corpus run:
/// real metadata for caption-rich videos exceeds the
/// generic OUTPUT_BYTES_MAX capture cap — the document
/// enumerates every caption track in every language).
pub const VIDEO_METADATA_BYTES_MAX: usize = 33_554_432;

/// `consult_phaedrus` rounds per guide/spec document
/// (YouTube-RE §11); named at Y1 though the loop is Y3.
pub const VIDEO_RESEARCH_ROUNDS_MAX: u64 = 3;

/// Unknowns consulted (and candidates filed) in one
/// research round (YouTube-RE §11).
pub const VIDEO_RESEARCH_UNKNOWNS_PER_ROUND_MAX: usize = 8;

/// Serialized bytes of one clean-room spec document
/// (YouTube-RE §11); named at Y1 though the tool is Y4.
pub const VIDEO_SPEC_BYTES_MAX: usize = 1_048_576;

/// Characters of one quoted fragment inside a clean-room
/// spec's requirements (YouTube-RE §11).
pub const VIDEO_SPEC_CODE_SPAN_CHARS_MAX: usize = 512;

/// Sections in one clean-room spec version (YouTube-RE §11).
pub const VIDEO_SPEC_SECTIONS_MAX: usize = 128;

/// Retained versions of one clean-room spec (YouTube-RE
/// §11); compose past it refuses, never evicts.
pub const VIDEO_SPEC_VERSIONS_MAX: usize = 32;

/// Bytes of one retained caption track, raw form
/// (YouTube-RE §11).
pub const VIDEO_TRANSCRIPT_BYTES_MAX: usize = 4_194_304;

/// Spans retained per video ingest (YouTube-RE §11).
pub const VIDEO_TRANSCRIPT_SPANS_MAX: usize = 20_000;

/// Blocks retained in one Notion page tree (web lane).
pub const WEB_BLOCKS_MAX: usize = 20_000;

/// Chunks followed for one page before the page is recorded
/// as chunk-truncated (web lane).
pub const WEB_CHUNKS_PER_PAGE_MAX: usize = 16;

/// Bytes of one `loadCachedPageChunkV2` document (web lane).
pub const WEB_CHUNK_BYTES_MAX: usize = 16_777_216;

/// Child-page depth walked from the root page (web lane).
pub const WEB_DEPTH_MAX: usize = 8;

/// Wall clock for one web fetch child — page HTML or one
/// chunk (web lane).
pub const WEB_FETCH_TIMEOUT_SECS: u64 = 30;

/// Markdown bytes returned inline by one web extraction;
/// longer renderings are truncated at a char boundary and
/// the digest still covers the complete rendering (web lane).
pub const WEB_MARKDOWN_BYTES_MAX: usize = 524_288;

/// Pages fetched for one Notion tree (web lane).
pub const WEB_PAGES_MAX: usize = 64;

/// Bytes of one public page's HTML bootstrap document
/// (web lane).
pub const WEB_PAGE_HTML_BYTES_MAX: usize = 4_194_304;

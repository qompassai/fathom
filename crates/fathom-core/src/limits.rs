//! Named resource bounds (SPEC §8).
//!
//! Every costly operation checks its bound before it starts. A
//! bound hit is a `resource_constraint` error or a reported
//! truncation in the evidence — never an unbounded retry.

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

/// Bytes of decompiled output retained per function dossier.
pub const DECOMPILE_BYTES_MAX: usize = 1_048_576;

/// Files inventoried under one directory target.
pub const FILE_COUNT_MAX: usize = 100_000;

/// Functions retained from one program inventory.
pub const FUNCTION_COUNT_MAX: usize = 5_000;

/// Default wall-clock bound for one Ghidra provider run, seconds.
pub const GHIDRA_TIMEOUT_SECS: u64 = 330;

/// Kernel symbols retained from one GPU code object (S7).
pub const GPU_KERNELS_MAX: usize = 5_000;

/// Listing instructions retained in one function dossier.
pub const INSTRUCTION_COUNT_MAX: usize = 2_000;

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

/// Decoded segment rows in one Ren'Py RPA index (readers SPEC §2.3).
pub const RPA_ENTRIES_MAX: usize = 100_000;

/// Decompressed bytes of one Ren'Py RPA pickle index
/// (readers SPEC §2.3).
pub const RPA_INDEX_BYTES_MAX: usize = 33_554_432;

/// Values the restricted RPA pickle reader may construct
/// (readers SPEC §5.4).
pub const RPA_PICKLE_NODES_MAX: usize = 2_000_000;

/// Strings retained from one program inventory.
pub const STRING_COUNT_MAX: usize = 5_000;

/// Symbols retained from one program inventory.
pub const SYMBOL_COUNT_MAX: usize = 20_000;

/// Bytes in one analysis target (hashed and read by providers).
pub const TARGET_BYTES_MAX: u64 = 536_870_912;

/// Decompressed bytes of one UnityFS blocks-info blob
/// (readers SPEC §2.3).
pub const UNITY_BLOCKS_INFO_BYTES_MAX: usize = 16_777_216;

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

//! Flutter/Dart AOT rung (D-1616): the pinned blutter tool
//! (worawit/blutter, MIT) run as a bounded child process over an
//! extracted Flutter library directory, with its outputs ingested
//! into evidence envelopes.
//!
//! Static-only discipline: blutter loads the Dart snapshot into
//! its own Dart VM dumper process (its `DartLoader` initialises
//! the VM with `--precompilation`, `start_kernel_isolate = false`,
//! and never invokes an application entry point — the blutter
//! sources contain no `Dart_Invoke` call), and fathom never
//! executes the target libraries themselves. The generated
//! `blutter_frida.js` is recorded as a referenced artifact only:
//! it is hashed and named in the evidence, never executed and
//! never sent to a device.
//!
//! The tool is observe-class: the registry's policy engine
//! default-denies it until the operator names `blutter_analyze`
//! in `allow_tools` (SPEC §8, the game-extract lane pattern).

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, Subject, subject_for_file};
use fathom_core::limits::{OUTPUT_BYTES_MAX, TARGET_BYTES_MAX};
use fathom_core::paths;
use fathom_core::process::{ProcessSpec, run};
use fathom_core::registry::{Registry, optional_str, require_str};

/// Wall-clock bound for one blutter run. A first run per Dart
/// version also builds the matching Dart VM library, which is
/// minutes-scale; repeat runs are far below this bound.
const BLUTTER_TIMEOUT_SECS: u64 = 1_800;

/// Bytes of one blutter output file read whole (pp.txt / objs.txt
/// of a large application stay well under this).
const BLUTTER_OUTPUT_FILE_BYTES_MAX: u64 = 268_435_456;

/// Assembly files censused in one blutter output tree.
const BLUTTER_ASM_FILES_MAX: usize = 4_096;

/// Object-pool records retained from one pp.txt.
const BLUTTER_POOL_RECORDS_MAX: usize = 200_000;

/// Characters retained from one object-pool record's value.
const BLUTTER_POOL_VALUE_CHARS_MAX: usize = 512;

/// Symbol records retained in the evidence; totals are always
/// computed over the full census, never over the retained page.
const BLUTTER_SYMBOLS_EVIDENCE_MAX: usize = 4_096;

/// Findings-candidate records retained in the evidence.
const BLUTTER_CANDIDATES_EVIDENCE_MAX: usize = 4_096;

/// ELF machine value for AArch64 (`EM_AARCH64`).
const ELF_MACHINE_AARCH64: u16 = 183;

/// ELF machine value for x86-64 (`EM_X86_64`); named for the
/// wrong-architecture adversarial tests.
#[cfg(test)]
const ELF_MACHINE_X86_64: u16 = 62;

/// Header bytes an ELF64 file must hold before its machine field
/// is readable (e_ehsize of the ELF64 header).
const ELF64_HEADER_BYTES: usize = 64;

/// Credential-like markers for findings candidates (D-1588 audit
/// hunt). A match is a candidate for human review, never a claim
/// that a credential was found.
const CREDENTIAL_MARKERS: &[&str] = &[
    "api_key",
    "apikey",
    "api-key",
    "client_secret",
    "password",
    "passwd",
    "private_key",
    "secret_key",
    "aws_secret",
    "bearer ",
];

/// The ELF header facts the rung decides on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ElfFacts {
    /// True for ELFCLASS64.
    pub is_64_bit: bool,
    /// The `e_machine` value (183 for AArch64).
    pub machine: u16,
}

/// Parse the ELF header facts from the first bytes of a file.
/// Fail-closed: a short buffer is `truncated`, a bad magic or an
/// unsupported class is `unsupported_target`. Only the documented
/// header layout is read (magic at 0, class at 4, `e_machine` as
/// a little-endian u16 at 18); section data is never consulted.
pub fn elf_facts(header: &[u8]) -> Result<ElfFacts, FathomError> {
    if header.len() < 16 {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!(
                "ELF header truncated: {} bytes, the 16-byte identification is incomplete",
                header.len()
            ),
        ));
    }
    if header[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "not an ELF file (bad magic)".to_string(),
        ));
    }
    let is_64_bit = match header[4] {
        2 => true,
        1 => false,
        other => {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                format!("unsupported ELF class byte {other}"),
            ));
        }
    };
    if header.len() < 20 {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!(
                "ELF header truncated: {} bytes, e_machine is unreadable",
                header.len()
            ),
        ));
    }
    // Flutter Android libraries are little-endian; a big-endian
    // data encoding (byte 5 == 2) is read as such, anything else
    // is refused rather than guessed.
    let machine = match header[5] {
        1 => u16::from_le_bytes([header[18], header[19]]),
        2 => u16::from_be_bytes([header[18], header[19]]),
        other => {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                format!("unsupported ELF data encoding byte {other}"),
            ));
        }
    };
    Ok(ElfFacts { is_64_bit, machine })
}

/// A validated Flutter library directory.
#[derive(Clone, Debug)]
pub struct FlutterLibDir {
    /// Path of `libapp.so` inside the directory.
    pub libapp: PathBuf,
    /// Path of `libflutter.so` inside the directory.
    pub libflutter: PathBuf,
    /// Header facts of `libapp.so`.
    pub app_facts: ElfFacts,
    /// Header facts of `libflutter.so`.
    pub flutter_facts: ElfFacts,
    /// Size of `libapp.so` in bytes.
    pub app_bytes: u64,
    /// Size of `libflutter.so` in bytes.
    pub flutter_bytes: u64,
}

/// Read the first bytes of one library and return its ELF facts,
/// enforcing the target size bound before any read.
fn library_facts(path: &Path) -> Result<(ElfFacts, u64), FathomError> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot stat {}: {e}", path.display()),
        )
    })?;
    if !metadata.is_file() {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if metadata.len() > TARGET_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "{} exceeds the {TARGET_BYTES_MAX}-byte target bound",
                path.display()
            ),
        ));
    }
    if metadata.len() < ELF64_HEADER_BYTES as u64 {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!(
                "{} is {} bytes, shorter than an ELF64 header",
                path.display(),
                metadata.len()
            ),
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    Ok((elf_facts(&bytes)?, metadata.len()))
}

/// Validate that `dir` holds a Flutter/Dart AOT arm64 library
/// pair. Every failure is a typed error: a missing `libapp.so`
/// is `target_unavailable`, a missing `libflutter.so`, a non-ELF
/// file, or a wrong-architecture file is `unsupported_target`,
/// and a truncated file is `truncated`. Nothing is claimed
/// about a directory that fails validation.
pub fn validate_flutter_lib_dir(dir: &Path) -> Result<FlutterLibDir, FathomError> {
    if !dir.is_dir() {
        return Err(FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("{} is not a directory", dir.display()),
        ));
    }
    let libapp = dir.join("libapp.so");
    if !libapp.is_file() {
        return Err(FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("{} holds no libapp.so", dir.display()),
        )
        .with_target(dir.display().to_string()));
    }
    let libflutter = dir.join("libflutter.so");
    if !libflutter.is_file() {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            format!(
                "{} holds libapp.so but no libflutter.so; not a complete \
                 Flutter library directory",
                dir.display()
            ),
        )
        .with_target(dir.display().to_string()));
    }
    let (app_facts, app_bytes) = library_facts(&libapp)?;
    let (flutter_facts, flutter_bytes) = library_facts(&libflutter)?;
    for (path, facts) in [(&libapp, app_facts), (&libflutter, flutter_facts)] {
        if facts.machine != ELF_MACHINE_AARCH64 {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                format!(
                    "{} is ELF machine {}, not AArch64 ({ELF_MACHINE_AARCH64}); \
                     this rung covers the arm64-v8a layout only",
                    path.display(),
                    facts.machine
                ),
            )
            .with_target(path.display().to_string()));
        }
        if !facts.is_64_bit {
            return Err(FathomError::new(
                ErrorCode::UnsupportedTarget,
                format!(
                    "{} is a 32-bit ELF; the arm64-v8a layout is 64-bit",
                    path.display()
                ),
            ));
        }
    }
    Ok(FlutterLibDir {
        libapp,
        libflutter,
        app_facts,
        flutter_facts,
        app_bytes,
        flutter_bytes,
    })
}

/// One object-pool record from pp.txt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolRecord {
    /// Pool offset (`pp+0x..`) as written by blutter.
    pub offset: u64,
    /// Record kind: the text before the first `:` (for example
    /// `String`, `Smi`, `Function`), or the whole description
    /// when it carries no kind prefix.
    pub kind: String,
    /// The record's value text, bounded to
    /// `BLUTTER_POOL_VALUE_CHARS_MAX` characters.
    pub value: String,
}

/// Parse statistics for one pp.txt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PpStats {
    /// Non-empty lines seen.
    pub lines_total: usize,
    /// Lines that are not pool records (excluding the header).
    pub lines_malformed: usize,
    /// Records dropped past `BLUTTER_POOL_RECORDS_MAX`.
    pub records_dropped: usize,
}

/// Parse blutter's pp.txt object-pool dump. The first line is
/// the `pool heap offset:` header; every later record line has
/// the form `[pp+0xOFFSET] <description>`. Malformed lines are
/// counted, never silently folded into records; a non-empty
/// file with zero records is an unreadable output.
pub fn parse_pp_txt(text: &str) -> Result<(Vec<PoolRecord>, PpStats), FathomError> {
    let mut records: Vec<PoolRecord> = Vec::new();
    let mut stats = PpStats::default();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with("pool heap offset:") {
            continue;
        }
        stats.lines_total += 1;
        let Some(record) = parse_pp_line(line) else {
            stats.lines_malformed += 1;
            continue;
        };
        if records.len() >= BLUTTER_POOL_RECORDS_MAX {
            stats.records_dropped += 1;
            continue;
        }
        records.push(record);
    }
    if records.is_empty() && stats.lines_total > 0 {
        return Err(FathomError::new(
            ErrorCode::UnreadableOutput,
            format!(
                "pp.txt held {} lines and no parseable pool records",
                stats.lines_total
            ),
        ));
    }
    Ok((records, stats))
}

/// Parse one `[pp+0xOFFSET] description` line.
fn parse_pp_line(line: &str) -> Option<PoolRecord> {
    let rest = line.strip_prefix("[pp+0x")?;
    let close = rest.find(']')?;
    let offset = u64::from_str_radix(&rest[..close], 16).ok()?;
    let description = rest[close + 1..].trim();
    if description.is_empty() {
        return None;
    }
    // The kind is the leading token (up to the first ':', ' ',
    // '<', or '('): blutter writes per-instance descriptions
    // (`Field <SomeClass.someField> ...`) whose full text is a
    // value, not a kind — grouping by the whole description
    // would mint one kind per field.
    let kind_end = description
        .find([':', ' ', '<', '('])
        .unwrap_or(description.len());
    let kind = description[..kind_end].to_string();
    let value = match description.split_once(':') {
        Some((_, value)) => value.trim().to_string(),
        None => description[kind_end..].trim().to_string(),
    };
    let value: String = value.chars().take(BLUTTER_POOL_VALUE_CHARS_MAX).collect();
    Some(PoolRecord {
        offset,
        kind,
        value,
    })
}

/// The string content of one pool record, when it is a Dart
/// string literal (`String: "..."` in pp.txt form).
pub fn pool_string_value(record: &PoolRecord) -> Option<&str> {
    if record.kind != "String" {
        return None;
    }
    let value = record.value.strip_prefix('"')?;
    value.strip_suffix('"').or(Some(value))
}

/// Classify one string as a findings candidate for the D-1588
/// audit hunt: `url` for URL-like values, `credential_like` for
/// values carrying a credential marker. Candidates are leads
/// for human review, honestly labelled — never findings.
pub fn candidate_kind(value: &str) -> Option<&'static str> {
    // A bare scheme fragment ("http", "https") is not an
    // endpoint candidate; a URL-like value carries a scheme
    // separator with a host behind it, or a domain/path shape.
    if (value.contains("://") && value.len() >= 10)
        || value.contains(".com/")
        || value.contains(".io/")
        || value.contains(".net/")
        || value.contains(".org/")
    {
        return Some("url");
    }
    let lower = value.to_ascii_lowercase();
    if CREDENTIAL_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        return Some("credential_like");
    }
    None
}

/// One library's asm census.
#[derive(Clone, Debug, Default)]
pub struct AsmLibrary {
    /// Library name from the `// lib:` header line.
    pub name: String,
    /// Library URL from the `// lib:` header line.
    pub url: String,
    /// Classes declared in the file (`// class id:` lines).
    pub classes: usize,
    /// Functions declared in the file (`// ** addr:` lines).
    pub functions: usize,
}

/// One function symbol from an asm file.
#[derive(Clone, Debug)]
pub struct AsmSymbol {
    /// Native address (`addr:` value), relative to the load base.
    pub address: u64,
    /// Code size in bytes (`size:` value).
    pub size: u64,
    /// The function head line that precedes the address line.
    pub name: String,
    /// The library file the symbol was read from.
    pub library: String,
}

/// The census over one blutter `asm/` output tree.
#[derive(Clone, Debug, Default)]
pub struct AsmCensus {
    /// Per-library rows, in file order.
    pub libraries: Vec<AsmLibrary>,
    /// Total classes over all libraries.
    pub classes_total: usize,
    /// Total functions over all libraries.
    pub functions_total: usize,
    /// Symbol records, capped at `BLUTTER_SYMBOLS_EVIDENCE_MAX`.
    pub symbols: Vec<AsmSymbol>,
    /// Files that could not be read as UTF-8 text.
    pub files_unreadable: usize,
}

/// Census one blutter `asm/` directory: one `.dart` file per
/// non-internal library, each opening with a `// lib:` header,
/// classes headed by `// class id:` lines, and functions headed
/// by a signature line followed by a `// ** addr:` line.
pub fn census_asm_dir(asm_dir: &Path) -> Result<AsmCensus, FathomError> {
    if !asm_dir.is_dir() {
        return Err(FathomError::new(
            ErrorCode::UnreadableOutput,
            format!(
                "blutter output holds no asm/ directory at {}",
                asm_dir.display()
            ),
        ));
    }
    let mut files: Vec<PathBuf> = Vec::new();
    collect_dart_files(asm_dir, asm_dir, &mut files)?;
    files.sort();
    let mut census = AsmCensus::default();
    for file in files {
        let text = match std::fs::read_to_string(&file) {
            Ok(text) => text,
            Err(_) => {
                census.files_unreadable += 1;
                continue;
            }
        };
        let rel = file
            .strip_prefix(asm_dir)
            .map(|rel| rel.display().to_string())
            .unwrap_or_else(|_| file.display().to_string());
        census_asm_file(&text, &rel, &mut census);
    }
    Ok(census)
}

/// Collect `.dart` files under `dir`, bounded and deterministic.
fn collect_dart_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), FathomError> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot list {}: {e}", dir.display()),
        )
    })?;
    let mut rows: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    rows.sort();
    for path in rows {
        if out.len() >= BLUTTER_ASM_FILES_MAX {
            return Err(FathomError::new(
                ErrorCode::ResourceConstraint,
                format!("asm census exceeds {BLUTTER_ASM_FILES_MAX} files"),
            )
            .with_target(root.display().to_string()));
        }
        if path.is_dir() {
            collect_dart_files(root, &path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "dart") {
            out.push(path);
        }
    }
    Ok(())
}

/// Fold one asm file into the census.
fn census_asm_file(text: &str, rel: &str, census: &mut AsmCensus) {
    let mut library = AsmLibrary {
        name: rel.to_string(),
        ..AsmLibrary::default()
    };
    let mut last_head = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(header) = trimmed.strip_prefix("// lib: ") {
            if let Some((name, url)) = header.split_once(", url: ") {
                library.name = name.trim().to_string();
                library.url = url.trim().to_string();
            }
        } else if trimmed.starts_with("// class id:") {
            library.classes += 1;
        } else if let Some(addr_line) = trimmed.strip_prefix("// ** addr:") {
            library.functions += 1;
            if census.symbols.len() < BLUTTER_SYMBOLS_EVIDENCE_MAX
                && let Some((address, size)) = parse_addr_line(addr_line)
            {
                census.symbols.push(AsmSymbol {
                    address,
                    size,
                    name: last_head.clone(),
                    library: library.name.clone(),
                });
            }
        } else if !trimmed.is_empty() && !trimmed.starts_with("//") {
            last_head = trimmed.to_string();
        }
    }
    census.classes_total += library.classes;
    census.functions_total += library.functions;
    census.libraries.push(library);
}

/// Parse the `0xADDR, size: 0xSIZE` tail of an addr line.
fn parse_addr_line(text: &str) -> Option<(u64, u64)> {
    let (addr, rest) = text.trim().split_once(',')?;
    let address = u64::from_str_radix(addr.trim().strip_prefix("0x")?, 16).ok()?;
    let size_text = rest.trim().strip_prefix("size:")?.trim();
    let size = u64::from_str_radix(size_text.strip_prefix("0x")?, 16).ok()?;
    Some((address, size))
}

/// Summary of one objs.txt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ObjsSummary {
    /// Object blocks (blank-line separated dumps).
    pub blocks: usize,
    /// Total bytes of the file.
    pub bytes: u64,
    /// Total lines of the file.
    pub lines: usize,
}

/// Summarise objs.txt: blutter writes one instance dump per
/// block, blocks separated by a blank line.
pub fn summarise_objs_txt(text: &str, bytes: u64) -> ObjsSummary {
    let blocks = text
        .split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .count();
    ObjsSummary {
        blocks,
        bytes,
        lines: text.lines().count(),
    }
}

/// The Dart version line blutter.py prints, parsed into facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DartVersionFacts {
    /// Dart version (for example `3.11.5`).
    pub version: String,
    /// Snapshot hash from libapp.so.
    pub snapshot_hash: String,
    /// Target triple tail (for example `android arm64`).
    pub target: String,
}

/// Parse `Dart version: V, Snapshot: H, Target: T` from
/// blutter.py's stdout. Absence is an honest `None`, never a
/// guessed version.
pub fn parse_dart_version_line(stdout: &str) -> Option<DartVersionFacts> {
    for line in stdout.lines() {
        let Some(rest) = line.strip_prefix("Dart version: ") else {
            continue;
        };
        let (version, rest) = rest.split_once(", Snapshot: ")?;
        let (snapshot_hash, target) = rest.split_once(", Target: ")?;
        return Some(DartVersionFacts {
            version: version.trim().to_string(),
            snapshot_hash: snapshot_hash.trim().to_string(),
            target: target.trim().to_string(),
        });
    }
    None
}

/// Locate the pinned blutter checkout: the operator names it
/// with `FATHOM_BLUTTER_DIR` (the estate's Ghidra pattern). The
/// directory must hold `blutter.py`.
pub fn locate_blutter() -> Option<PathBuf> {
    let dir = std::env::var("FATHOM_BLUTTER_DIR").ok()?;
    let dir = PathBuf::from(dir);
    if dir.join("blutter.py").is_file() {
        Some(dir)
    } else {
        None
    }
}

/// Read one blutter output file whole, under its size bound.
fn read_output_file(path: &Path) -> Result<String, FathomError> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("blutter output {} is missing: {e}", path.display()),
        )
    })?;
    if metadata.len() > BLUTTER_OUTPUT_FILE_BYTES_MAX {
        return Err(FathomError::new(
            ErrorCode::ResourceConstraint,
            format!(
                "blutter output {} exceeds {BLUTTER_OUTPUT_FILE_BYTES_MAX} bytes",
                path.display()
            ),
        ));
    }
    std::fs::read_to_string(path).map_err(|e| {
        FathomError::new(
            ErrorCode::UnreadableOutput,
            format!("cannot read blutter output {}: {e}", path.display()),
        )
    })
}

/// The `blutter_analyze` tool: run the pinned blutter over a
/// validated Flutter library directory and ingest its outputs.
pub fn blutter_analyze(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let target_raw = require_str(args, "target")?;
    let target = paths::validate_target(config, Path::new(target_raw))?;
    let output_dir = match optional_str(args, "output_dir") {
        Some(raw) => Some(paths::validate_output_dir(config, Path::new(raw))?),
        None => None,
    };
    analyze_with_blutter(config, &target, output_dir, locate_blutter())
}

/// The rung's work, with the blutter location explicit so tests
/// can drive it with a fixture blutter.
fn analyze_with_blutter(
    config: &Config,
    target: &Path,
    output_dir: Option<PathBuf>,
    blutter_dir: Option<PathBuf>,
) -> Result<Value, FathomError> {
    let libs = validate_flutter_lib_dir(target)?;
    let blutter_dir = blutter_dir.ok_or_else(|| {
        FathomError::new(
            ErrorCode::CapabilityUnavailable,
            "blutter is not located; set FATHOM_BLUTTER_DIR to the pinned \
             blutter checkout (the directory holding blutter.py)",
        )
        .with_remediation("Clone worawit/blutter at the pinned commit and set FATHOM_BLUTTER_DIR.")
    })?;
    let subject = subject_for_file(&libs.libapp)?;
    let out_dir = match output_dir {
        Some(dir) => dir,
        None => {
            let base = paths::state_subdir(config, "blutter")?;
            let named = base.join(&subject.sha256[..16]);
            std::fs::create_dir_all(&named).map_err(|e| {
                FathomError::new(
                    ErrorCode::ExecutionFailure,
                    format!("cannot create output directory {}: {e}", named.display()),
                )
            })?;
            named
        }
    };
    let outcome = run(&ProcessSpec {
        args: vec![
            blutter_dir.join("blutter.py").display().to_string(),
            target.display().to_string(),
            out_dir.display().to_string(),
        ],
        cwd: Some(blutter_dir.clone()),
        env: Vec::new(),
        output_cap: OUTPUT_BYTES_MAX,
        program: "python3".to_string(),
        timeout: Duration::from_secs(BLUTTER_TIMEOUT_SECS),
    })?;
    if outcome.timed_out {
        return Err(FathomError::new(
            ErrorCode::ProviderTimeout,
            format!("blutter exceeded {BLUTTER_TIMEOUT_SECS} seconds and was stopped"),
        ));
    }
    if outcome.exit_code != Some(0) {
        let stderr = String::from_utf8_lossy(&outcome.stderr);
        let excerpt: String = stderr.chars().take(512).collect();
        return Err(FathomError::new(
            ErrorCode::ExecutionFailure,
            format!(
                "blutter exited with {:?}; stderr excerpt: {excerpt}",
                outcome.exit_code
            ),
        ));
    }
    let stdout = String::from_utf8_lossy(&outcome.stdout).into_owned();
    build_evidence(&libs, &out_dir, &stdout, subject)
}

/// Ingest a finished blutter output tree into an evidence
/// envelope. Missing outputs are typed errors, never partial
/// claims; the frida script is a referenced artifact only.
fn build_evidence(
    libs: &FlutterLibDir,
    out_dir: &Path,
    stdout: &str,
    subject: Subject,
) -> Result<Value, FathomError> {
    let mut evidence = Evidence::new("blutter_analyze", "blutter").with_subject(subject);
    evidence.add_finding(Finding::new(
        "flutter_lib_dir",
        Confidence::Observed,
        json!({
            "libapp": {"path": libs.libapp.display().to_string(), "bytes": libs.app_bytes,
                "elf_machine": libs.app_facts.machine, "elf_64_bit": libs.app_facts.is_64_bit},
            "libflutter": {"path": libs.libflutter.display().to_string(),
                "bytes": libs.flutter_bytes, "elf_machine": libs.flutter_facts.machine,
                "elf_64_bit": libs.flutter_facts.is_64_bit},
            "layout": "lib/arm64-v8a",
        }),
    ));
    match parse_dart_version_line(stdout) {
        Some(facts) => evidence.add_finding(Finding::new(
            "dart_version",
            Confidence::Observed,
            json!({
                "version": facts.version,
                "snapshot_hash": facts.snapshot_hash,
                "target": facts.target,
                "source": "blutter.py stdout (extract_dart_info over libapp.so/libflutter.so)",
            }),
        )),
        None => evidence.add_unknown(
            "dart_version",
            "blutter.py printed no Dart version line; the version is unrecorded, not guessed",
        ),
    }
    let census = census_asm_dir(&out_dir.join("asm"))?;
    let libraries: Vec<Value> = census
        .libraries
        .iter()
        .map(|lib| {
            json!({"name": lib.name, "url": lib.url, "classes": lib.classes,
                "functions": lib.functions})
        })
        .collect();
    let symbols: Vec<Value> = census
        .symbols
        .iter()
        .map(|sym| {
            json!({"address": sym.address, "size": sym.size, "name": sym.name,
                "library": sym.library})
        })
        .collect();
    evidence.add_finding(Finding::new(
        "asm_census",
        Confidence::Observed,
        json!({
            "libraries": libraries,
            "libraries_total": census.libraries.len(),
            "classes_total": census.classes_total,
            "functions_total": census.functions_total,
            "symbols_retained": symbols.len(),
            "symbols": symbols,
            "files_unreadable": census.files_unreadable,
        }),
    ));
    let pp_text = read_output_file(&out_dir.join("pp.txt"))?;
    let (records, pp_stats) = parse_pp_txt(&pp_text)?;
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut candidates: Vec<Value> = Vec::new();
    let mut strings_total = 0_usize;
    for record in &records {
        *by_kind.entry(record.kind.clone()).or_default() += 1;
        if let Some(text) = pool_string_value(record) {
            strings_total += 1;
            if let Some(kind) = candidate_kind(text)
                && candidates.len() < BLUTTER_CANDIDATES_EVIDENCE_MAX
            {
                candidates.push(json!({
                    "candidate_kind": kind,
                    "value": text.chars().take(BLUTTER_POOL_VALUE_CHARS_MAX)
                        .collect::<String>(),
                    "pool_offset": record.offset,
                    "status": "candidate_for_review_not_a_finding",
                }));
            }
        }
    }
    evidence.add_finding(Finding::new(
        "object_pool",
        Confidence::Observed,
        json!({
            "records_total": records.len(),
            "records_by_kind": by_kind,
            "strings_total": strings_total,
            "lines_total": pp_stats.lines_total,
            "lines_malformed": pp_stats.lines_malformed,
            "records_dropped": pp_stats.records_dropped,
        }),
    ));
    if !candidates.is_empty() {
        evidence.add_finding(
            Finding::new(
                "pool_findings_candidates",
                Confidence::Inferred,
                json!({"candidates": candidates}),
            )
            .with_limitation(
                "Candidates are URL-like or credential-like pool strings flagged \
                 for the D-1588 audit hunt; each needs human verification before \
                 it is treated as an endpoint or a credential",
            ),
        );
    }
    let objs_path = out_dir.join("objs.txt");
    let objs_text = read_output_file(&objs_path)?;
    let objs_bytes = std::fs::metadata(&objs_path)
        .map(|meta| meta.len())
        .unwrap_or(0);
    let objs = summarise_objs_txt(&objs_text, objs_bytes);
    evidence.add_finding(Finding::new(
        "objs_summary",
        Confidence::Observed,
        json!({"blocks": objs.blocks, "bytes": objs.bytes, "lines": objs.lines}),
    ));
    let frida_path = out_dir.join("blutter_frida.js");
    if frida_path.is_file() {
        let (sha256, bytes) = fathom_core::evidence::hash_file(&frida_path)?;
        evidence.add_finding(Finding::new(
            "frida_artifact",
            Confidence::Observed,
            json!({
                "path": frida_path.display().to_string(),
                "sha256": sha256,
                "bytes": bytes,
                "executed": false,
                "sent_to_device": false,
                "disposition": "referenced_artifact_only",
            }),
        ));
    } else {
        evidence.add_unknown(
            "frida_artifact",
            "blutter wrote no blutter_frida.js; no frida artifact is recorded",
        );
    }
    evidence.coverage.examined = (census.functions_total + records.len()) as u64;
    evidence.coverage.total = evidence.coverage.examined;
    evidence.coverage.exhaustive = pp_stats.records_dropped == 0;
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::config::ConfigFile;

    fn elf64(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fathom-blutter-test-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config_with_root(root: &Path) -> Config {
        Config::from_file_form(ConfigFile {
            target_roots: Some(vec![root.to_path_buf()]),
            ..ConfigFile::default()
        })
        .unwrap()
    }

    fn write_lib_dir(dir: &Path, app: &[u8], flutter: Option<&[u8]>) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("libapp.so"), app).unwrap();
        if let Some(bytes) = flutter {
            std::fs::write(dir.join("libflutter.so"), bytes).unwrap();
        }
    }

    // ---- validation tests ----

    #[test]
    fn validation_valid_arm64_pair_is_accepted() {
        let dir = scratch("valid");
        let lib = dir.join("arm64-v8a");
        write_lib_dir(
            &lib,
            &elf64(ELF_MACHINE_AARCH64),
            Some(&elf64(ELF_MACHINE_AARCH64)),
        );
        let libs = validate_flutter_lib_dir(&lib).unwrap();
        assert_eq!(libs.app_facts.machine, ELF_MACHINE_AARCH64);
        assert_eq!(libs.app_bytes, 64);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn validation_pp_txt_records_parse() {
        let text = "pool heap offset: 0x1234\n\
                    [pp+0x10] String: \"https://example.com/api\"\n\
                    [pp+0x18] Smi: 0x2a\n\
                    [pp+0x20] Function: main (0x1000)\n";
        let (records, stats) = parse_pp_txt(text).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(stats.lines_malformed, 0);
        assert_eq!(records[0].kind, "String");
        assert_eq!(records[2].kind, "Function");
        assert_eq!(candidate_kind("https"), None);
        assert_eq!(
            pool_string_value(&records[0]),
            Some("https://example.com/api")
        );
        assert_eq!(candidate_kind("https://example.com/api"), Some("url"));
    }

    #[test]
    fn validation_dart_version_line_parses() {
        let facts = parse_dart_version_line(
            "Dart version: 3.11.5, Snapshot: abc123, Target: android arm64\nflags: x\n",
        )
        .unwrap();
        assert_eq!(facts.version, "3.11.5");
        assert_eq!(facts.snapshot_hash, "abc123");
        assert_eq!(parse_dart_version_line("no version here"), None);
    }

    #[test]
    fn validation_objs_summary_counts_blocks() {
        let summary = summarise_objs_txt("obj one\n\nobj two\nlines\n\n", 21);
        assert_eq!(summary.blocks, 2);
        assert_eq!(summary.bytes, 21);
    }

    #[test]
    fn validation_fake_blutter_run_ingests_evidence() {
        let root = scratch("fakerun");
        let lib = root.join("lib").join("arm64-v8a");
        write_lib_dir(
            &lib,
            &elf64(ELF_MACHINE_AARCH64),
            Some(&elf64(ELF_MACHINE_AARCH64)),
        );
        let fake = root.join("fake-blutter");
        std::fs::create_dir_all(&fake).unwrap();
        std::fs::write(
            fake.join("blutter.py"),
            "import os, sys\n\
             out = sys.argv[2]\n\
             os.makedirs(os.path.join(out, 'asm'), exist_ok=True)\n\
             open(os.path.join(out, 'asm', 'main.dart'), 'w').write(\
             '// lib: , url: package:app/main.dart\\n// class id: 10, size: 0x20\\nclass App {\\n  void run() {\\n    // ** addr: 0x1000, size: 0x40\\n  }\\n}\\n')\n\
             open(os.path.join(out, 'pp.txt'), 'w').write(\
             'pool heap offset: 0x0\\n[pp+0x10] String: \"https://api.example.com/v1\"\\n[pp+0x18] String: \"api_key = hunter2\"\\n[pp+0x20] Smi: 0x2a\\n')\n\
             open(os.path.join(out, 'objs.txt'), 'w').write('obj one\\n\\nobj two\\n')\n\
             open(os.path.join(out, 'blutter_frida.js'), 'w').write('// fixture\\n')\n\
             print('Dart version: 3.11.5, Snapshot: deadbeef, Target: android arm64')\n",
        )
        .unwrap();
        let config = config_with_root(&root);
        let out_dir = root.join("out");
        let value = analyze_with_blutter(&config, &lib, Some(out_dir), Some(fake)).unwrap();
        let findings = value["findings"].as_array().unwrap();
        let census = findings.iter().find(|f| f["kind"] == "asm_census").unwrap();
        assert_eq!(census["facts"]["classes_total"], 1);
        assert_eq!(census["facts"]["functions_total"], 1);
        let candidates = findings
            .iter()
            .find(|f| f["kind"] == "pool_findings_candidates")
            .unwrap();
        assert_eq!(
            candidates["facts"]["candidates"].as_array().unwrap().len(),
            2
        );
        let frida = findings
            .iter()
            .find(|f| f["kind"] == "frida_artifact")
            .unwrap();
        assert_eq!(frida["facts"]["executed"], false);
        assert_eq!(frida["facts"]["sent_to_device"], false);
        std::fs::remove_dir_all(&root).ok();
    }

    // ---- adversarial tests ----

    #[test]
    fn adversarial_missing_libflutter_is_refused() {
        let dir = scratch("noflutter");
        let lib = dir.join("arm64-v8a");
        write_lib_dir(&lib, &elf64(ELF_MACHINE_AARCH64), None);
        let err = validate_flutter_lib_dir(&lib).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_wrong_arch_in_arm64_slot_is_refused() {
        let dir = scratch("wrongarch");
        let lib = dir.join("arm64-v8a");
        write_lib_dir(
            &lib,
            &elf64(ELF_MACHINE_X86_64),
            Some(&elf64(ELF_MACHINE_AARCH64)),
        );
        let err = validate_flutter_lib_dir(&lib).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_truncated_elf_is_refused() {
        let dir = scratch("truncated");
        let lib = dir.join("arm64-v8a");
        write_lib_dir(
            &lib,
            &elf64(ELF_MACHINE_AARCH64)[..32],
            Some(&elf64(ELF_MACHINE_AARCH64)),
        );
        let err = validate_flutter_lib_dir(&lib).unwrap_err();
        assert_eq!(err.code, ErrorCode::Truncated);
        let facts_err = elf_facts(&[0x7f, b'E', b'L']).unwrap_err();
        assert_eq!(facts_err.code, ErrorCode::Truncated);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_empty_lib_dir_is_refused() {
        let dir = scratch("empty");
        let lib = dir.join("arm64-v8a");
        std::fs::create_dir_all(&lib).unwrap();
        let err = validate_flutter_lib_dir(&lib).unwrap_err();
        assert_eq!(err.code, ErrorCode::TargetUnavailable);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_non_elf_libapp_is_refused() {
        let dir = scratch("nonelf");
        let lib = dir.join("arm64-v8a");
        let text = vec![b'x'; 128];
        write_lib_dir(&lib, &text, Some(&elf64(ELF_MACHINE_AARCH64)));
        let err = validate_flutter_lib_dir(&lib).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedTarget);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn adversarial_pp_txt_without_records_is_refused() {
        let err = parse_pp_txt("pool heap offset: 0x0\ngarbage line\nmore garbage\n").unwrap_err();
        assert_eq!(err.code, ErrorCode::UnreadableOutput);
    }

    #[test]
    fn adversarial_unlocated_blutter_is_capability_unavailable() {
        let root = scratch("nolocate");
        let lib = root.join("lib").join("arm64-v8a");
        write_lib_dir(
            &lib,
            &elf64(ELF_MACHINE_AARCH64),
            Some(&elf64(ELF_MACHINE_AARCH64)),
        );
        let config = config_with_root(&root);
        let err = analyze_with_blutter(&config, &lib, None, None).unwrap_err();
        assert_eq!(err.code, ErrorCode::CapabilityUnavailable);
        std::fs::remove_dir_all(&root).ok();
    }
}

//! Ren'Py RPA archive reader (readers SPEC §5).
//!
//! Layout: a one-line ASCII header (`RPA-3.0 ` + hex index
//! offset + space-separated hex key parts; `RPA-2.0 ` +
//! offset only), data segments anywhere in the file, and a
//! zlib-compressed pickled index at the offset. Segment
//! offsets/lengths in RPA-3.0 are XORed with the header key.
//!
//! The pickle layer is the restricted interpreter of
//! readers SPEC §5.4: an allowlist of data-only opcodes over
//! a closed value domain. A real unpickler is never used —
//! pickle is a bytecode for a stack machine with opcodes
//! that import and call arbitrary code, so deserialising an
//! untrusted game archive with one would be remote code
//! execution by design. Anything outside the allowlist
//! refuses with the opcode named.
//!
//! Honesty contract: RPA carries NO in-format content
//! anchor (no per-file hash, no index hash). Segment SHA-256
//! values here are fathom-computed evidence, not verified
//! facts; the container record states this and coverage is
//! never exhaustive on that account.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::{
    ARCHIVE_TARGET_BYTES_MAX, RPA_ENTRIES_MAX, RPA_INDEX_BYTES_MAX, RPA_PICKLE_NODES_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};

/// The header line ends within the first 4 KiB.
const HEADER_LINE_MAX: usize = 4096;
/// Streaming chunk for segment hashing.
const HASH_CHUNK_BYTES: usize = 65_536;
/// Container nesting cap for the pickle interpreter.
const PICKLE_DEPTH_MAX: usize = 32;
/// Defensive materialisation cap: memoized clones may not
/// expand the index beyond four times its stored size.
const MATERIALIZED_BYTES_MAX: u64 = 4 * RPA_INDEX_BYTES_MAX as u64;

fn mismatch(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message.into())
        .with_target("renpy archive")
}

fn unsupported(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message.into()).with_target("renpy archive")
}

fn shape(message: String) -> FathomError {
    unsupported(format!("renpy index shape: {message}"))
}

fn resource(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ResourceConstraint, message.into()).with_target("renpy archive")
}

/// The closed value domain of the restricted interpreter
/// (readers SPEC §5.4). No other type can be constructed.
#[derive(Clone, Debug)]
enum PickleValue {
    Bytes(Vec<u8>),
    Dict(Vec<(PickleValue, PickleValue)>),
    Int(i64),
    List(Vec<PickleValue>),
    None,
    Str(String),
    Tuple(Vec<PickleValue>),
}

fn value_size(value: &PickleValue) -> u64 {
    match value {
        PickleValue::Bytes(bytes) => bytes.len() as u64,
        PickleValue::Dict(pairs) => {
            pairs
                .iter()
                .map(|(key, val)| value_size(key) + value_size(val))
                .sum::<u64>()
                + pairs.len() as u64
        }
        PickleValue::Int(_) | PickleValue::None => 1,
        PickleValue::List(items) | PickleValue::Tuple(items) => {
            items.iter().map(value_size).sum::<u64>() + items.len() as u64
        }
        PickleValue::Str(text) => text.len() as u64,
    }
}

/// Human opcode names for refusals, keyed by byte. Only the
/// names a refusal message needs; unknown bytes report their
/// hex value.
fn opcode_name(byte: u8) -> String {
    let name = match byte {
        0x81 => "NEWOBJ",
        0x82 => "EXT1",
        0x83 => "EXT2",
        0x84 => "EXT4",
        0x8A => "LONG1",
        0x8B => "LONG",
        0x8D => "BINBYTES8",
        0x8E => "EMPTY_SET",
        0x8F => "ADDITEMS",
        0x90 => "FROZENSET",
        0x91 => "NEWOBJ_EX",
        0x92 => "STACK_GLOBAL",
        0x93 => "MEMOIZE",
        0x96 => "BYTEARRAY8",
        b'F' => "BINFLOAT",
        b'N' => "NONE",
        b'P' => "PERSID",
        b'Q' => "BINPERSID",
        b'R' => "REDUCE",
        b'S' => "STRING",
        b'b' => "BUILD",
        b'c' => "GLOBAL",
        b'i' => "INST",
        b'o' => "OBJ",
        b'p' => "PUT",
        b'q' => "BINPUT",
        b'r' => "LONG_BINPUT",
        b'\x88' => "NEWTRUE",
        b'\x89' => "NEWFALSE",
        _ => return format!("0x{byte:02x}"),
    };
    name.to_string()
}

/// The restricted pickle interpreter: a bounded stack
/// machine over `PickleValue`. Any opcode outside the
/// allowlist refuses, naming the opcode.
struct Interpreter<'a> {
    bytes: &'a [u8],
    marks: Vec<usize>,
    materialized: u64,
    memo: HashMap<u32, (PickleValue, u64)>,
    memo_next: u32,
    nodes: usize,
    position: usize,
    stack: Vec<PickleValue>,
}

impl<'a> Interpreter<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Interpreter {
            bytes,
            marks: Vec::new(),
            materialized: 0,
            memo: HashMap::new(),
            memo_next: 0,
            nodes: 0,
            position: 0,
            stack: Vec::new(),
        }
    }

    fn read_byte(&mut self) -> Result<u8, FathomError> {
        let byte = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or_else(|| mismatch("renpy index ends mid-value"))?;
        self.position += 1;
        Ok(byte)
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], FathomError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| mismatch("renpy index ends mid-value"))?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn read_line(&mut self) -> Result<&'a [u8], FathomError> {
        let start = self.position;
        let mut at = start;
        while at < self.bytes.len() && self.bytes[at] != b'\n' {
            at += 1;
        }
        if at >= self.bytes.len() {
            return Err(mismatch("renpy index ends mid-value"));
        }
        self.position = at + 1;
        Ok(&self.bytes[start..at])
    }

    fn push(&mut self, value: PickleValue) -> Result<(), FathomError> {
        self.materialized += value_size(&value);
        if self.materialized > MATERIALIZED_BYTES_MAX {
            return Err(resource(format!(
                "renpy index materialises over {MATERIALIZED_BYTES_MAX} bytes through memo reuse"
            )));
        }
        self.stack.push(value);
        Ok(())
    }

    fn pop(&mut self) -> Result<PickleValue, FathomError> {
        self.stack
            .pop()
            .ok_or_else(|| shape("pickle stack underflow".to_string()))
    }

    fn pop_to_mark(&mut self) -> Result<Vec<PickleValue>, FathomError> {
        let mark = self
            .marks
            .pop()
            .ok_or_else(|| shape("pickle MARK expected".to_string()))?;
        Ok(self.stack.drain(mark..).collect())
    }

    fn top_list(&mut self) -> Result<&mut Vec<PickleValue>, FathomError> {
        match self.stack.last_mut() {
            Some(PickleValue::List(items)) => Ok(items),
            _ => Err(shape("pickle APPEND target is not a list".to_string())),
        }
    }

    fn assign(&mut self, key: PickleValue, value: PickleValue) -> Result<(), FathomError> {
        match self.stack.last_mut() {
            Some(PickleValue::Dict(pairs)) => {
                pairs.push((key, value));
                Ok(())
            }
            _ => Err(shape("pickle SETITEM target is not a dict".to_string())),
        }
    }

    fn run(mut self) -> Result<PickleValue, FathomError> {
        loop {
            let opcode = self.read_byte()?;
            self.nodes += 1;
            if self.nodes > RPA_PICKLE_NODES_MAX {
                return Err(resource(format!(
                    "renpy index exceeds RPA_PICKLE_NODES_MAX ({RPA_PICKLE_NODES_MAX}) opcodes"
                )));
            }
            match opcode {
                // STOP: the root value, alone on the stack.
                b'.' => {
                    if self.stack.len() != 1 {
                        return Err(shape(format!(
                            "pickle STOP with {} values on the stack",
                            self.stack.len()
                        )));
                    }
                    if self.position != self.bytes.len() {
                        return Err(mismatch("renpy index has trailing bytes after STOP"));
                    }
                    return Ok(self.stack.pop().unwrap());
                }
                // PROTO: version byte; data semantics are
                // version-independent across 0–5.
                0x80 => {
                    let version = self.read_byte()?;
                    if version > 5 {
                        return Err(shape(format!("pickle protocol {version}")));
                    }
                }
                // FRAME: 8-byte length, framing only.
                0x95 => {
                    let raw = self.read_bytes(8)?;
                    let length = u64::from_le_bytes(raw.try_into().unwrap());
                    if length > (self.bytes.len() - self.position) as u64 {
                        return Err(mismatch("renpy pickle frame overruns the index"));
                    }
                }
                b'(' => {
                    if self.marks.len() >= PICKLE_DEPTH_MAX {
                        return Err(shape(format!(
                            "pickle nesting deeper than {PICKLE_DEPTH_MAX}"
                        )));
                    }
                    self.marks.push(self.stack.len());
                }
                b'}' => self.push(PickleValue::Dict(Vec::new()))?,
                b']' => self.push(PickleValue::List(Vec::new()))?,
                b')' => self.push(PickleValue::Tuple(Vec::new()))?,
                // MEMOIZE: remember the stack top.
                0x94 => {
                    let top = self
                        .stack
                        .last()
                        .ok_or_else(|| shape("pickle MEMOIZE with an empty stack".to_string()))?
                        .clone();
                    let size = value_size(&top);
                    self.memo.insert(self.memo_next, (top, size));
                    self.memo_next += 1;
                }
                b'h' | b'j' => {
                    let index = if opcode == b'h' {
                        u32::from(self.read_byte()?)
                    } else {
                        u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap())
                    };
                    let (value, _) = self
                        .memo
                        .get(&index)
                        .ok_or_else(|| shape(format!("pickle memo miss at {index}")))?
                        .clone();
                    self.push(value)?;
                }
                b'J' => {
                    let value =
                        i64::from(i32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()));
                    self.push(PickleValue::Int(value))?;
                }
                b'K' => {
                    let value = i64::from(self.read_byte()?);
                    self.push(PickleValue::Int(value))?;
                }
                b'M' => {
                    let value =
                        i64::from(u16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()));
                    self.push(PickleValue::Int(value))?;
                }
                b'I' => {
                    let line = self.read_line()?;
                    let text = std::str::from_utf8(line)
                        .map_err(|_| shape("INT operand is not text".to_string()))?;
                    let value: i64 = text
                        .trim()
                        .parse()
                        .map_err(|_| shape(format!("INT operand '{text}' is not an integer")))?;
                    self.push(PickleValue::Int(value))?;
                }
                0x8A => {
                    let count = self.read_byte()? as usize;
                    if count > 8 {
                        return Err(shape(format!(
                            "LONG1 with {count} bytes does not fit the value domain"
                        )));
                    }
                    let raw = self.read_bytes(count)?.to_vec();
                    let mut value: i64 = 0;
                    for (i, byte) in raw.iter().enumerate() {
                        value |= i64::from(*byte) << (8 * i);
                    }
                    if count > 0 && raw[count - 1] & 0x80 != 0 {
                        value -= 1_i64 << (8 * count);
                    }
                    self.push(PickleValue::Int(value))?;
                }
                0x8C => {
                    let count = self.read_byte()? as usize;
                    let raw = self.read_bytes(count)?;
                    let text = String::from_utf8(raw.to_vec())
                        .map_err(|_| shape("SHORT_BINUNICODE is not UTF-8".to_string()))?;
                    self.push(PickleValue::Str(text))?;
                }
                b'X' => {
                    let count = u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap());
                    let raw = self.read_bytes(count as usize)?;
                    let text = String::from_utf8(raw.to_vec())
                        .map_err(|_| shape("BINUNICODE is not UTF-8".to_string()))?;
                    self.push(PickleValue::Str(text))?;
                }
                b'V' => {
                    let line = self.read_line()?;
                    let text = String::from_utf8(line.to_vec())
                        .map_err(|_| shape("UNICODE is not UTF-8".to_string()))?;
                    self.push(PickleValue::Str(text))?;
                }
                b'C' => {
                    let count = self.read_byte()? as usize;
                    let raw = self.read_bytes(count)?.to_vec();
                    self.push(PickleValue::Bytes(raw))?;
                }
                b'B' => {
                    let count = u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap());
                    let raw = self.read_bytes(count as usize)?.to_vec();
                    self.push(PickleValue::Bytes(raw))?;
                }
                b'N' => self.push(PickleValue::None)?,
                b't' => {
                    let items = self.pop_to_mark()?;
                    self.push(PickleValue::Tuple(items))?;
                }
                0x85 => {
                    let a = self.pop()?;
                    self.push(PickleValue::Tuple(vec![a]))?;
                }
                0x86 => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(PickleValue::Tuple(vec![a, b]))?;
                }
                0x87 => {
                    let c = self.pop()?;
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(PickleValue::Tuple(vec![a, b, c]))?;
                }
                b'l' => {
                    let items = self.pop_to_mark()?;
                    self.push(PickleValue::List(items))?;
                }
                b'a' => {
                    let value = self.pop()?;
                    self.top_list()?.push(value);
                }
                b'e' => {
                    let items = self.pop_to_mark()?;
                    self.top_list()?.extend(items);
                }
                b'd' => {
                    let items = self.pop_to_mark()?;
                    if items.len() % 2 != 0 {
                        return Err(shape("DICT with an odd item count".to_string()));
                    }
                    let mut pairs = Vec::with_capacity(items.len() / 2);
                    let mut iter = items.into_iter();
                    while let (Some(key), Some(value)) = (iter.next(), iter.next()) {
                        pairs.push((key, value));
                    }
                    self.push(PickleValue::Dict(pairs))?;
                }
                b's' => {
                    let value = self.pop()?;
                    let key = self.pop()?;
                    self.assign(key, value)?;
                }
                b'u' => {
                    let items = self.pop_to_mark()?;
                    if items.len() % 2 != 0 {
                        return Err(shape("SETITEMS with an odd item count".to_string()));
                    }
                    let mut iter = items.into_iter();
                    while let (Some(key), Some(value)) = (iter.next(), iter.next()) {
                        self.assign(key, value)?;
                    }
                }
                other => {
                    let name = opcode_name(other);
                    return Err(unsupported(format!(
                        "renpy index uses pickle opcode {name} (0x{other:02x}), outside the restricted interpreter's allowlist"
                    )));
                }
            }
        }
    }
}

/// One shaped segment: de-XORed offset/length and the
/// prefix bytes stored inside the declared length.
struct Segment {
    length: i64,
    offset: i64,
    prefix: Vec<u8>,
}

/// Shape the interpreted root into (path, segments) pairs.
/// Wrong shapes refuse, naming the deviation (SPEC §5.4).
fn shape_index(
    root: PickleValue,
    three_tuple: bool,
) -> Result<Vec<(String, Vec<Segment>)>, FathomError> {
    let PickleValue::Dict(pairs) = root else {
        return Err(shape("root is not a dict".to_string()));
    };
    let mut files = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        let PickleValue::Str(path) = key else {
            return Err(shape("a file key is not a string".to_string()));
        };
        let PickleValue::List(items) = value else {
            return Err(shape(format!("the value for '{path}' is not a list")));
        };
        let mut segments = Vec::with_capacity(items.len());
        for item in items {
            let PickleValue::Tuple(fields) = item else {
                return Err(shape(format!("a segment for '{path}' is not a tuple")));
            };
            let expected = if three_tuple { 3 } else { 2 };
            if fields.len() != expected {
                return Err(shape(format!(
                    "a segment for '{path}' has {} fields, expected {expected}",
                    fields.len()
                )));
            }
            let mut fields = fields.into_iter();
            let (Some(PickleValue::Int(offset)), Some(PickleValue::Int(length))) =
                (fields.next(), fields.next())
            else {
                return Err(shape(format!(
                    "a segment for '{path}' does not start with two integers"
                )));
            };
            let prefix = if three_tuple {
                match fields.next() {
                    Some(PickleValue::Bytes(bytes)) => bytes,
                    _ => {
                        return Err(shape(format!("a segment for '{path}' has no bytes prefix")));
                    }
                }
            } else {
                Vec::new()
            };
            segments.push(Segment {
                length,
                offset,
                prefix,
            });
        }
        files.push((path, segments));
    }
    Ok(files)
}

/// The parsed header line.
struct Header {
    index_offset: u64,
    key: u32,
    key_parts: u32,
    variant: &'static str,
}

fn parse_header(line: &str) -> Result<Header, FathomError> {
    if let Some(rest) = line.strip_prefix("RPA-3.2 ") {
        let _ = rest;
        return Err(unsupported(
            "RPA-3.2 archives are deferred: their index encoding differs and no estate fixture exists",
        ));
    }
    if let Some(rest) = line.strip_prefix("RPA-3.0 ") {
        let mut tokens = rest.split(' ');
        let offset = tokens.next().unwrap_or("");
        let index_offset = u64::from_str_radix(offset, 16)
            .map_err(|_| unsupported("RPA-3.0 header carries a non-hex index offset"))?;
        let mut key: u32 = 0;
        let mut parts: u32 = 0;
        for token in tokens {
            let part = u32::from_str_radix(token, 16)
                .map_err(|_| unsupported("RPA-3.0 header carries a non-hex key part"))?;
            key ^= part;
            parts += 1;
        }
        if parts == 0 {
            return Err(unsupported("RPA-3.0 header carries no key parts"));
        }
        return Ok(Header {
            index_offset,
            key,
            key_parts: parts,
            variant: "RPA-3.0",
        });
    }
    if let Some(rest) = line.strip_prefix("RPA-2.0 ") {
        let index_offset = u64::from_str_radix(rest.trim(), 16)
            .map_err(|_| unsupported("RPA-2.0 header carries a non-hex index offset"))?;
        return Ok(Header {
            index_offset,
            key: 0,
            key_parts: 0,
            variant: "RPA-2.0",
        });
    }
    Err(unsupported(
        "unrecognised archive header (expected an RPA-3.0 or RPA-2.0 line)",
    ))
}

/// Lowercase hex for a digest byte string.
fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// SHA-256 of a file range, streamed. `None` when the range
/// overruns the file or cannot be read.
fn sha256_range(file: &mut File, file_len: u64, offset: u64, count: u64) -> Option<String> {
    if offset.checked_add(count).is_none_or(|end| end > file_len) {
        return None;
    }
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut hasher = Sha256::new();
    let mut remaining = count;
    let mut buffer = [0_u8; HASH_CHUNK_BYTES];
    while remaining > 0 {
        let want =
            usize::try_from(remaining.min(HASH_CHUNK_BYTES as u64)).unwrap_or(HASH_CHUNK_BYTES);
        let read = file.read(&mut buffer[..want]).ok()?;
        if read == 0 {
            return None;
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Some(hex_bytes(&hasher.finalize()))
}

pub fn inspect_renpy_archive(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let subject_sha256 = subject.sha256.clone();
    let file_len = subject.size_bytes;
    let mut file = File::open(&path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot open target: {error}"),
        )
    })?;
    // Header: one line within the first 4 KiB.
    let head_len = usize::try_from(file_len.min(HEADER_LINE_MAX as u64)).unwrap_or(0);
    let mut head = vec![0_u8; head_len];
    file.read_exact(&mut head).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target header: {error}"),
        )
    })?;
    let newline = head
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| unsupported("no header line within the first 4 KiB"))?;
    let line = String::from_utf8_lossy(&head[..newline]).into_owned();
    let header = parse_header(line.trim_end())?;
    if header.index_offset >= file_len {
        return Err(FathomError::new(
            ErrorCode::Truncated,
            format!(
                "renpy index offset {} is at or past the file end ({file_len} bytes)",
                header.index_offset
            ),
        )
        .with_target("renpy archive"));
    }
    // Index: the zlib stream at the offset, decompressed
    // under a hard bound — never materialised unbounded.
    file.seek(SeekFrom::Start(header.index_offset))
        .map_err(|error| {
            FathomError::new(
                ErrorCode::TargetUnavailable,
                format!("cannot seek renpy target: {error}"),
            )
        })?;
    let index_bytes = {
        use flate2::read::ZlibDecoder;
        let decoder = ZlibDecoder::new(&file);
        let mut buffer = Vec::new();
        decoder
            .take(RPA_INDEX_BYTES_MAX as u64 + 1)
            .read_to_end(&mut buffer)
            .map_err(|_| mismatch("renpy index does not decompress"))?;
        if buffer.len() > RPA_INDEX_BYTES_MAX {
            return Err(resource(format!(
                "renpy index decompresses past RPA_INDEX_BYTES_MAX ({RPA_INDEX_BYTES_MAX})"
            )));
        }
        buffer
    };
    let root = Interpreter::new(&index_bytes).run()?;
    let files = shape_index(root, header.variant == "RPA-3.0")?;
    let segment_total: usize = files.iter().map(|(_, segs)| segs.len()).sum();
    if segment_total > RPA_ENTRIES_MAX {
        return Err(resource(format!(
            "renpy index declares {segment_total} segments, over RPA_ENTRIES_MAX ({RPA_ENTRIES_MAX})"
        )));
    }
    let mut rows: Vec<Value> = Vec::with_capacity(segment_total);
    let mut examined: u64 = 0;
    let mut overrun_count: u64 = 0;
    let mut total_declared: u64 = 0;
    for (path_entry, segments) in &files {
        for (position, segment) in segments.iter().enumerate() {
            let offset = segment.offset ^ i64::from(header.key);
            let length = segment.length ^ i64::from(header.key);
            total_declared += length.max(0) as u64;
            let stored = length - segment.prefix.len() as i64;
            let (sha256, status) = if offset < 0 || stored < 0 {
                (None, "unreadable")
            } else {
                match sha256_range(&mut file, file_len, offset as u64, stored as u64) {
                    Some(digest) => {
                        examined += 1;
                        (Some(digest), "hashed")
                    }
                    None => (None, "unreadable"),
                }
            };
            if status == "unreadable" {
                overrun_count += 1;
            }
            rows.push(json!({
                "declared_length": length,
                "offset": offset,
                "path": path_entry,
                "prefix_bytes": segment.prefix.len(),
                "segment": position,
                "sha256": sha256,
                "status": status,
                "stored_bytes": stored,
            }));
        }
    }
    let record = json!({
        "content_anchor": "none — RPA carries no in-format content hash; segment hashes are fathom-computed",
        "declared_files": files.len(),
        "declared_length_total": total_declared,
        "index_decompressed_bytes": index_bytes.len(),
        "index_offset": header.index_offset,
        "key": if header.variant == "RPA-3.0" { json!(header.key) } else { Value::Null },
        "key_parts": header.key_parts,
        "overrun_segments": overrun_count,
        "segments": segment_total,
        "variant": header.variant,
    });
    let doc_rows: Vec<Value> = rows
        .iter()
        .map(|row| {
            let mut doc_row = row.clone();
            let segment = row["segment"].as_u64().unwrap_or(0);
            doc_row["key"] = if segment == 0 {
                row["path"].clone()
            } else {
                json!(format!(
                    "{}#{}",
                    row["path"].as_str().unwrap_or(""),
                    segment
                ))
            };
            doc_row
        })
        .collect();
    let document = json!({
        "renpy_rpa": record.clone(),
        "renpy_rpa_entries": doc_rows,
        "renpy_rpa_entries_total": segment_total,
        "renpy_rpa_entries_truncated": false,
    });
    let mut evidence = Evidence::new("inspect_renpy_archive", "renpy");
    evidence.subject = Some(subject);
    let (digest, retention_note) =
        match proof::retain_export(config, &subject_sha256, "archive_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut facts = record;
    facts["export_digest"] = match &digest {
        Some(digest) => json!(digest),
        None => Value::Null,
    };
    evidence.add_finding(Finding::new("renpy_rpa", Confidence::Observed, facts));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": segment_total, "total": segment_total}),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    // The format's honesty limit, stated on every census:
    // hashes are computed, never verified against the
    // format, so coverage can never be exhaustive here.
    evidence.add_unknown(
        "content authenticity",
        "RPA carries no in-format content anchor; segment SHA-256 values are fathom-computed evidence, not verified facts",
    );
    if overrun_count > 0 {
        evidence.add_unknown(
            "entry data",
            format!(
                "{overrun_count} of {segment_total} segments overrun the file or declare impossible ranges; their rows carry no hash"
            ),
        );
    }
    evidence.coverage.examined = examined;
    evidence.coverage.total = segment_total as u64;
    evidence.coverage.exhaustive = false;
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Hand-assemble an RPA-3.0-shaped pickle index using
    /// only allowlisted opcodes: dict of path -> list of
    /// (offset, length, prefix) TUPLE3 segments.
    type SegmentSpec<'a> = (i32, i32, &'a [u8]);
    type FileSpec<'a> = (&'a str, Vec<SegmentSpec<'a>>);

    fn pickle_index_30(files: &[FileSpec]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\x80\x02"); // PROTO 2
        out.push(b'}'); // EMPTY_DICT
        out.push(0x94); // MEMOIZE
        for (path, segments) in files {
            out.push(0x8C); // SHORT_BINUNICODE
            out.push(path.len() as u8);
            out.extend_from_slice(path.as_bytes());
            out.push(0x94);
            out.push(b']'); // EMPTY_LIST
            out.push(0x94);
            for (offset, length, prefix) in segments {
                out.push(b'J'); // BININT
                out.extend_from_slice(&offset.to_le_bytes());
                out.push(b'J');
                out.extend_from_slice(&length.to_le_bytes());
                out.push(b'C'); // SHORT_BINBYTES
                out.push(prefix.len() as u8);
                out.extend_from_slice(prefix);
                out.push(0x87); // TUPLE3
                out.push(0x94);
                out.push(b'a'); // APPEND
            }
            out.push(b's'); // SETITEM
        }
        out.push(b'.'); // STOP
        out
    }

    fn pickle_index_20(files: &[(&str, Vec<(i32, i32)>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\x80\x02");
        out.push(b'}');
        out.push(0x94);
        for (path, segments) in files {
            out.push(0x8C);
            out.push(path.len() as u8);
            out.extend_from_slice(path.as_bytes());
            out.push(0x94);
            out.push(b']');
            out.push(0x94);
            for (offset, length) in segments {
                out.push(b'J');
                out.extend_from_slice(&offset.to_le_bytes());
                out.push(b'J');
                out.extend_from_slice(&length.to_le_bytes());
                out.push(0x86); // TUPLE2
                out.push(0x94);
                out.push(b'a');
            }
            out.push(b's');
        }
        out.push(b'.');
        out
    }

    const KEY: u32 = 0x4242_4242;

    /// Build an RPA-3.0 file: header line, then the given
    /// data segments laid out from the header end, then the
    /// compressed index. `segments` entries are
    /// (path, prefix, stored bytes); declared length is
    /// prefix + stored, values XORed with KEY.
    fn build_30(segments: &[(&str, &[u8], &[u8])]) -> Vec<u8> {
        let header_len = 34; // "RPA-3.0 " + 16 + " " + 8 + "\n"
        let mut data: Vec<u8> = Vec::new();
        let mut files: Vec<FileSpec> = Vec::new();
        for (path, prefix, stored) in segments {
            let offset = (header_len + data.len()) as i32;
            data.extend_from_slice(stored);
            let declared = (prefix.len() + stored.len()) as i32;
            files.push((
                path,
                vec![(offset ^ KEY as i32, declared ^ KEY as i32, prefix)],
            ));
        }
        let index_at = header_len + data.len();
        let mut out = format!("RPA-3.0 {index_at:016x} {KEY:08x}\n").into_bytes();
        assert_eq!(out.len(), header_len);
        out.extend_from_slice(&data);
        out.extend_from_slice(&zlib_compress(&pickle_index_30(&files)));
        out
    }

    fn build_20(segments: &[(&str, &[u8])]) -> Vec<u8> {
        let header_len = 25; // "RPA-2.0 " + 16 + "\n"
        let mut data: Vec<u8> = Vec::new();
        let mut files: Vec<(&str, Vec<(i32, i32)>)> = Vec::new();
        for (path, stored) in segments {
            let offset = (header_len + data.len()) as i32;
            data.extend_from_slice(stored);
            files.push((path, vec![(offset, stored.len() as i32)]));
        }
        let index_at = header_len + data.len();
        let mut out = format!("RPA-2.0 {index_at:016x}\n").into_bytes();
        assert_eq!(out.len(), header_len);
        out.extend_from_slice(&data);
        out.extend_from_slice(&zlib_compress(&pickle_index_20(&files)));
        out
    }

    fn run(test_name: &str, bytes: &[u8]) -> (PathBuf, Result<Value, FathomError>) {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("game.rpa");
        fs::write(&target, bytes).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": target.display().to_string()});
        let result = inspect_renpy_archive(&Registry::new(), &config, &args);
        (root, result)
    }

    fn rpa_facts(value: &Value) -> &Value {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "renpy_rpa")
            .map(|finding| &finding["facts"])
            .unwrap()
    }

    fn entry_rows(value: &Value) -> &Vec<Value> {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "entries")
            .and_then(|finding| finding["facts"]["entries"].as_array())
            .unwrap()
    }

    #[test]
    fn validation_rpa30_segments_hash_and_key_facts() {
        let bytes = build_30(&[
            ("script.rpyc", b"", b"compiled script bytes"),
            ("images/bg.png", b"PX", b"png-ish payload"),
        ]);
        let (root, result) = run("rpa30-basic", &bytes);
        let value = result.unwrap();
        let facts = rpa_facts(&value);
        assert_eq!(facts["variant"], "RPA-3.0");
        assert_eq!(facts["key"], KEY);
        assert_eq!(facts["key_parts"], 1);
        assert_eq!(facts["declared_files"], 2);
        assert_eq!(facts["segments"], 2);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "hashed");
        assert_eq!(
            rows[0]["sha256"],
            "3853e414b805a3532797758ebc10c62223bf1fc45d4d1bf5f7dac989fb72175b"
        );
        assert_eq!(rows[1]["prefix_bytes"], 2);
        assert_eq!(rows[1]["stored_bytes"], 15);
        assert_eq!(value["coverage"]["examined"], 2);
        // Never exhaustive: the format has no content anchor.
        assert_eq!(value["coverage"]["exhaustive"], false);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_rpa20_two_tuple_segments() {
        let bytes = build_20(&[("old.txt", b"legacy content")]);
        let (root, result) = run("rpa20-basic", &bytes);
        let value = result.unwrap();
        assert_eq!(rpa_facts(&value)["variant"], "RPA-2.0");
        assert_eq!(rpa_facts(&value)["key"], Value::Null);
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "hashed");
        assert_eq!(rows[0]["prefix_bytes"], 0);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_multi_segment_file_rows_carry_segment_numbers() {
        // Two segments for one path, assembled by hand
        // because build_30 emits one segment per file.
        let key = KEY as i32;
        let header_len = 34;
        let data = b"aaaabbbb";
        let files = vec![(
            "multi.bin",
            vec![
                (header_len ^ key, (4) ^ key, &b""[..]),
                ((header_len + 4) ^ key, (4) ^ key, &b""[..]),
            ],
        )];
        let index_at = header_len + data.len() as i32;
        let mut out = format!("RPA-3.0 {index_at:016x} {KEY:08x}\n").into_bytes();
        out.extend_from_slice(data);
        out.extend_from_slice(&zlib_compress(&pickle_index_30(&files)));
        let (root, result) = run("rpa30-multi", &out);
        let value = result.unwrap();
        let rows = entry_rows(&value);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["segment"], 0);
        assert_eq!(rows[1]["segment"], 1);
        assert_eq!(rows[1]["offset"], header_len + 4);
        fs::remove_dir_all(&root).ok();
    }

    // --------------------------------------------------------
    // Adversarial half.
    // --------------------------------------------------------

    #[test]
    fn adversarial_reduce_opcode_is_refused_by_name() {
        let mut pickle = Vec::new();
        pickle.extend_from_slice(b"\x80\x02}"); // PROTO, EMPTY_DICT
        pickle.push(b'R'); // REDUCE
        pickle.push(b'.');
        let mut bytes = format!("RPA-3.0 {:016x} {KEY:08x}\n", 34).into_bytes();
        // Index offset must point at the zlib stream: place
        // it right after the header and recompute.
        let index_at = bytes.len();
        bytes = format!("RPA-3.0 {index_at:016x} {KEY:08x}\n").into_bytes();
        bytes.extend_from_slice(&zlib_compress(&pickle));
        let (root, result) = run("rpa-reduce", &bytes);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        assert!(error.message.contains("REDUCE"), "{}", error.message);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_global_opcode_is_refused_by_name() {
        let mut pickle = Vec::new();
        pickle.extend_from_slice(b"\x80\x02cposix\nsystem\n."); // GLOBAL
        let mut bytes = Vec::new();
        let index_at = 34;
        bytes.extend_from_slice(format!("RPA-3.0 {index_at:016x} {KEY:08x}\n").as_bytes());
        bytes.extend_from_slice(&zlib_compress(&pickle));
        let (root, result) = run("rpa-global", &bytes);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        assert!(error.message.contains("GLOBAL"), "{}", error.message);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_bytearray8_is_refused_by_name() {
        let mut pickle = Vec::new();
        pickle.extend_from_slice(b"\x80\x05");
        pickle.push(0x96); // BYTEARRAY8
        pickle.extend_from_slice(&1_u64.to_le_bytes());
        pickle.push(b'X');
        pickle.push(b'.');
        let mut bytes = Vec::new();
        bytes.extend_from_slice(format!("RPA-3.0 {:016x} {KEY:08x}\n", 34).as_bytes());
        bytes.extend_from_slice(&zlib_compress(&pickle));
        let (root, result) = run("rpa-bytearray", &bytes);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        assert!(error.message.contains("BYTEARRAY8"), "{}", error.message);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_rpa32_header_refuses_as_deferred() {
        let bytes = b"RPA-3.2 0000000000000023 42424242\nrest".to_vec();
        let (root, result) = run("rpa32", &bytes);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        assert!(error.message.contains("RPA-3.2"), "{}", error.message);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_segment_overrun_is_a_row_not_a_failure() {
        let bytes = build_30(&[("ok.bin", b"", b"fine")]);
        // Rebuild with a segment offset pointing past EOF.
        let key = KEY as i32;
        let files = vec![("far.bin", vec![(999_999 ^ key, 10 ^ key, &b""[..])])];
        let mut out = format!("RPA-3.0 {:016x} {KEY:08x}\n", 34 + 4).into_bytes();
        out.extend_from_slice(b"data");
        out.extend_from_slice(&zlib_compress(&pickle_index_30(&files)));
        let (root, result) = run("rpa-overrun", &out);
        let value = result.unwrap();
        let rows = entry_rows(&value);
        assert_eq!(rows[0]["status"], "unreadable");
        assert_eq!(rows[0]["sha256"], Value::Null);
        assert_eq!(rpa_facts(&value)["overrun_segments"], 1);
        let _ = bytes;
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_truncated_index_is_an_integrity_mismatch() {
        let mut bytes = build_30(&[("a.bin", b"", b"payload")]);
        bytes.truncate(bytes.len() - 3);
        let (root, result) = run("rpa-truncated", &bytes);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_root_list_is_a_shape_refusal() {
        let pickle = b"\x80\x02]".to_vec(); // PROTO, EMPTY_LIST — then EOF mid-value
        let mut full = pickle.clone();
        full.push(b'.');
        let mut bytes = Vec::new();
        bytes.extend_from_slice(format!("RPA-3.0 {:016x} {KEY:08x}\n", 34).as_bytes());
        bytes.extend_from_slice(&zlib_compress(&full));
        let (root, result) = run("rpa-root-list", &bytes);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        assert!(
            error.message.contains("root is not a dict"),
            "{}",
            error.message
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_deep_nesting_is_refused() {
        let mut pickle = Vec::new();
        pickle.extend_from_slice(b"\x80\x02");
        // MARK × 40 > depth cap 32
        pickle.extend(std::iter::repeat_n(b'(', 40));
        pickle.push(b'.');
        let mut bytes = Vec::new();
        bytes.extend_from_slice(format!("RPA-3.0 {:016x} {KEY:08x}\n", 34).as_bytes());
        bytes.extend_from_slice(&zlib_compress(&pickle));
        let (root, result) = run("rpa-deep", &bytes);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        assert!(error.message.contains("nesting"), "{}", error.message);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_segment_count_over_cap_refuses() {
        // One file with RPA_ENTRIES_MAX + 1 zero-length
        // segments.
        let key = KEY as i32;
        let count = RPA_ENTRIES_MAX + 1;
        let segments: Vec<(i32, i32, &[u8])> =
            (0..count).map(|_| (34 ^ key, key, &b""[..])).collect();
        let files = vec![("many.bin", segments)];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(format!("RPA-3.0 {:016x} {KEY:08x}\n", 34).as_bytes());
        bytes.extend_from_slice(&zlib_compress(&pickle_index_30(&files)));
        let (root, result) = run("rpa-over-cap", &bytes);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceConstraint);
        fs::remove_dir_all(&root).ok();
    }
}

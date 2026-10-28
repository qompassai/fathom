//! Python bytecode (.pyc) and PyInstaller archive reader
//! (REA-adaptation S5), implemented directly.
//!
//! The .pyc side parses the header (PEP 552: magic, bit-field
//! flags, then a timestamp/source-size pair or a source hash)
//! and walks the marshalled module code object with a bounded,
//! hand-rolled marshal reader. Code-object fields are
//! interpreted per CPython version layout (2.7, 3.0–3.7,
//! 3.8–3.10, 3.11–3.13), routed by the header magic — an
//! unknown magic is a typed refusal, never a guess. The
//! inventory is the module's code-object tree (functions,
//! classes, lambdas) with names, argument counts, line
//! numbers, the module name table, and a bounded census of
//! string constants. Bytecode *instructions* are not decoded:
//! disassembly is a named NOT-IMPLEMENTED wall, stated in the
//! envelope's unknowns.
//!
//! The PyInstaller side locates the CArchive cookie
//! (`MEI\x0c\x0b\x0a\x0b\x0e`) — at end of file, or by a
//! bounded scan of the file tail when bytes follow the cookie
//! (signed/appended builds) — then reads the table of
//! contents and inventories every entry: directory facts plus
//! a SHA-256 of the stored bytes, and, for entries that carry
//! marshalled code (entry scripts, modules, and the nested
//! PYZ archive's modules, whose payloads are zlib-compressed
//! marshal), the decoded code-object name. A PYZ table of
//! contents is itself marshal, read by the same bounded
//! reader. Entries pointing outside the archive are overrun
//! unknowns, in the Godot reader's pattern: the directory's
//! claims are reported, never believed past the file's edge.
//!
//! Honesty contract: this reader never executes anything. A
//! marshal stream that breaks its bounds or its grammar is a
//! typed error; a version this reader does not know is named
//! NOT-IMPLEMENTED rather than silently misread.

use serde_json::{Value, json};
use std::io::Read as _;
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, sha256_hex, subject_for_file};
use fathom_core::limits::{
    PYC_CODE_OBJECTS_MAX, PYC_STRING_CONSTS_MAX, PYC_VALUES_MAX, PYINSTALLER_ENTRIES_MAX,
    PYZ_MODULES_MAX,
};
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};

/// The PyInstaller CArchive cookie magic.
const COOKIE_MAGIC: &[u8; 8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
/// Cookie length: 8 magic + 4 package length + 4 TOC offset +
/// 4 TOC length + 4 Python version + 64 library name bytes.
const COOKIE_LEN: usize = 88;
/// Tail window scanned for a cookie that is not at EOF.
const COOKIE_SCAN_BYTES: usize = 65_536;
/// One TOC entry's fixed header: 4 length + 4 position +
/// 4 stored length + 4 uncompressed length + 1 compression
/// flag + 1 typecode.
const TOC_ENTRY_HEADER_LEN: usize = 18;
/// Marshal nesting depth bound.
const MARSHAL_DEPTH_MAX: usize = 64;
/// One decompressed code payload's byte bound (marshal of one
/// module's code object).
const PAYLOAD_BYTES_MAX: usize = 33_554_432;
/// Header size for Python 3.7+ .pyc files (PEP 552).
const PYC_HEADER_LEN_MODERN: usize = 16;

// ----------------------------------------------------------------
// .pyc header

/// Which code-object field layout a .pyc version uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeLayout {
    /// Python 2.7: 14 fields, no keyword-only/positional-only
    /// counts, no qualname.
    Py2,
    /// Python 3.0–3.7: 15 fields.
    Py30,
    /// Python 3.8–3.10: 16 fields (adds positional-only count).
    Py38,
    /// Python 3.11–3.13: 17 fields (localsplus names/kinds,
    /// qualname, linetable, exception table).
    Py311,
}

/// Per-field shape of a marshalled code object, in field
/// order: `true` = a tagged marshal value, `false` = a raw
/// little-endian i32 (see the marshal reader's code branch).
fn code_field_kinds(layout: CodeLayout) -> &'static [bool] {
    // R = raw i32 scalar, O = tagged object value.
    const R: bool = false;
    const O: bool = true;
    match layout {
        // argcount, nlocals, stacksize, flags, code, consts,
        // names, varnames, freevars, cellvars, filename,
        // name, firstlineno, lnotab
        CodeLayout::Py2 => &[R, R, R, R, O, O, O, O, O, O, O, O, R, O],
        // + kwonlyargcount after argcount
        CodeLayout::Py30 => &[R, R, R, R, R, O, O, O, O, O, O, O, O, R, O],
        // + posonlyargcount after argcount
        CodeLayout::Py38 => &[R, R, R, R, R, R, O, O, O, O, O, O, O, O, R, O],
        // 3.11+ drops nlocals from the stream (it is
        // derived from localsplusnames on read): five raw
        // scalars (argcount, posonly, kwonly, stacksize,
        // flags), eight objects (code, consts, names,
        // localsplus names/kinds, filename, name, qualname),
        // firstlineno raw, then linetable + exceptiontable.
        CodeLayout::Py311 => &[R, R, R, R, R, O, O, O, O, O, O, O, O, R, O, O],
    }
}

/// Map a .pyc magic number (the little-endian u16 in bytes
/// 0–1) to its CPython version and code-object layout. Magics
/// follow CPython's `Lib/importlib/_bootstrap_external.py`
/// table; a magic outside the table is unknown, never guessed.
pub fn pyc_version(magic: u16) -> Option<(&'static str, CodeLayout)> {
    Some(match magic {
        62211 => ("2.7", CodeLayout::Py2),
        3000..=3199 => ("3.0", CodeLayout::Py30),
        3200..=3229 => ("3.2", CodeLayout::Py30),
        3230..=3279 => ("3.3", CodeLayout::Py30),
        3280..=3309 => ("3.4", CodeLayout::Py30),
        3310 => ("3.4", CodeLayout::Py30),
        3320..=3378 => ("3.5", CodeLayout::Py30),
        3379..=3393 => ("3.6", CodeLayout::Py30),
        3394..=3412 => ("3.7", CodeLayout::Py30),
        3413..=3424 => ("3.8", CodeLayout::Py38),
        3425..=3438 => ("3.9", CodeLayout::Py38),
        3439..=3494 => ("3.10", CodeLayout::Py38),
        3495..=3530 => ("3.11", CodeLayout::Py311),
        3531..=3570 => ("3.12", CodeLayout::Py311),
        3571..=3650 => ("3.13", CodeLayout::Py311),
        _ => return None,
    })
}

/// A parsed .pyc header.
#[derive(Debug)]
pub struct PycHeader {
    /// PEP 552 flags (3.7+ only; 0 before).
    pub flags: u32,
    /// True for a hash-based pyc (flags bit 0).
    pub hash_based: bool,
    /// Hash-based only: whether the runtime validates the
    /// source hash at import (flags bit 1).
    pub hash_check_source: bool,
    /// Byte length of the header.
    pub header_len: usize,
    /// The header magic number.
    pub magic: u16,
    /// Source size from a timestamp-based header (3.3+).
    pub source_size: Option<u32>,
    /// Source timestamp from a timestamp-based header.
    pub timestamp: Option<u32>,
    /// CPython version string for the magic, when known.
    pub version: Option<&'static str>,
}

/// Parse a .pyc header. Returns the header and the offset at
/// which the marshalled code object starts.
pub fn parse_pyc_header(bytes: &[u8]) -> Result<PycHeader, FathomError> {
    let unsupported = |message: String| {
        FathomError::new(ErrorCode::UnsupportedTarget, message).with_target("python pyc file")
    };
    if bytes.len() < 4 {
        return Err(unsupported(
            "file too small to be a Python .pyc".to_string(),
        ));
    }
    if bytes[2] != 0x0d || bytes[3] != 0x0a {
        return Err(unsupported(
            "missing the 0x0d 0x0a terminator of a .pyc magic".to_string(),
        ));
    }
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    let known = pyc_version(magic);
    let (version, _layout) = match known {
        Some(pair) => (Some(pair.0), Some(pair.1)),
        None => (None, None),
    };
    // Header shape by era: 3.7+ carries the PEP 552 flags
    // word; 3.3–3.6 carries timestamp+size directly; 2.7 and
    // 3.0–3.2 carry a timestamp alone after the magic.
    let modern = magic >= 3394;
    let mid = (3200..3394).contains(&magic);
    let header_len = if modern {
        PYC_HEADER_LEN_MODERN
    } else if mid {
        12
    } else {
        8
    };
    if bytes.len() < header_len {
        return Err(unsupported("file ends inside the .pyc header".to_string()));
    }
    let mut flags = 0_u32;
    let mut hash_based = false;
    let mut hash_check_source = false;
    let mut timestamp = None;
    let mut source_size = None;
    if modern {
        flags = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        hash_based = flags & 0x1 != 0;
        hash_check_source = flags & 0x2 != 0;
        if flags & !0x3 != 0 {
            return Err(unsupported(format!(
                "pyc flags word 0x{flags:08x} sets bits this reader does not know"
            )));
        }
        if !hash_based {
            timestamp = Some(u32::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
            ]));
            source_size = Some(u32::from_le_bytes([
                bytes[12], bytes[13], bytes[14], bytes[15],
            ]));
        }
    } else if mid {
        timestamp = Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
        source_size = Some(u32::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11],
        ]));
    } else {
        timestamp = Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
    }
    Ok(PycHeader {
        flags,
        hash_based,
        hash_check_source,
        header_len,
        magic,
        source_size,
        timestamp,
        version,
    })
}

// ----------------------------------------------------------------
// Bounded marshal reader

/// One decoded marshal value. Code objects keep their raw
/// field list; interpretation is per-version, in
/// `interpret_code`.
#[derive(Clone, Debug)]
pub enum MarshalValue {
    Bytes(Vec<u8>),
    Code(Vec<MarshalValue>),
    Dict(Vec<(MarshalValue, MarshalValue)>),
    Ellipsis,
    False,
    Float(f64),
    FrozenSet(Vec<MarshalValue>),
    Int(String),
    List(Vec<MarshalValue>),
    None,
    Set(Vec<MarshalValue>),
    Str(String),
    True,
    Tuple(Vec<MarshalValue>),
}

impl MarshalValue {
    fn as_str(&self) -> Option<&str> {
        match self {
            MarshalValue::Str(text) => Some(text),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            MarshalValue::Int(text) => text.parse().ok(),
            _ => None,
        }
    }

    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            MarshalValue::Bytes(data) => Some(data),
            _ => None,
        }
    }

    fn as_items(&self) -> Option<&[MarshalValue]> {
        match self {
            MarshalValue::Tuple(items) | MarshalValue::List(items) => Some(items),
            _ => None,
        }
    }
}

/// A bounded marshal stream reader. Every length is checked
/// against the remaining input; the value count and nesting
/// depth are capped; a reference to an unrecorded slot is a
/// typed error.
pub struct MarshalReader<'a> {
    bytes: &'a [u8],
    layout: CodeLayout,
    pos: usize,
    refs: Vec<Option<MarshalValue>>,
    values: usize,
}

impl<'a> MarshalReader<'a> {
    pub fn new(bytes: &'a [u8], layout: CodeLayout) -> Self {
        MarshalReader {
            bytes,
            layout,
            pos: 0,
            refs: Vec::new(),
            values: 0,
        }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn error(&self, message: String) -> FathomError {
        FathomError::new(ErrorCode::UnsupportedTarget, message).with_target("marshal stream")
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], FathomError> {
        if self.remaining() < count {
            return Err(self.error("marshal stream ends early".to_string()));
        }
        let slice = &self.bytes[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, FathomError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, FathomError> {
        let raw = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([raw[0], raw[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, FathomError> {
        let raw = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn read_i32(&mut self) -> Result<i32, FathomError> {
        Ok(self.read_u32()? as i32)
    }

    fn read_i64(&mut self) -> Result<i64, FathomError> {
        let raw = self.read_bytes(8)?;
        Ok(i64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]))
    }

    fn read_count(&mut self) -> Result<usize, FathomError> {
        let count = self.read_i32()?;
        if count < 0 {
            return Err(self.error("marshal stream carries a negative count".to_string()));
        }
        Ok(count as usize)
    }

    /// Read one value. `depth` is the current nesting depth.
    pub fn read_value(&mut self, depth: usize) -> Result<MarshalValue, FathomError> {
        if depth > MARSHAL_DEPTH_MAX {
            return Err(self.error("marshal nesting exceeds the depth bound".to_string()));
        }
        self.values += 1;
        if self.values > PYC_VALUES_MAX {
            return Err(self.error("marshal value count exceeds the bound".to_string()));
        }
        let raw = self.read_u8()?;
        let flagged = raw & 0x80 != 0;
        let kind = raw & 0x7f;
        // A flagged value reserves its reference slot before
        // its contents are read (references can be recursive).
        let slot = if flagged {
            self.refs.push(None);
            Some(self.refs.len() - 1)
        } else {
            None
        };
        let value = self.read_typed(kind, depth)?;
        if let Some(index) = slot {
            self.refs[index] = Some(value.clone());
        }
        Ok(value)
    }

    fn read_typed(&mut self, kind: u8, depth: usize) -> Result<MarshalValue, FathomError> {
        match kind {
            b'N' => Ok(MarshalValue::None),
            b'T' => Ok(MarshalValue::True),
            b'F' => Ok(MarshalValue::False),
            b'.' => Ok(MarshalValue::Ellipsis),
            b'S' => Err(self.error("marshal StopIteration sentinel out of place".to_string())),
            b'i' => Ok(MarshalValue::Int(self.read_i32()?.to_string())),
            b'I' => Ok(MarshalValue::Int(self.read_i64()?.to_string())),
            b'l' => self.read_long(),
            b'g' => {
                let raw = self.read_bytes(8)?;
                Ok(MarshalValue::Float(f64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ])))
            }
            b'f' => {
                let len = self.read_u8()? as usize;
                let text = self.read_text(len)?;
                text.parse::<f64>()
                    .map(MarshalValue::Float)
                    .map_err(|_| self.error("marshal float is not numeric text".to_string()))
            }
            b'x' | b'y' => {
                // Complex: two float-shaped parts; the value is
                // recorded as its real part only in census
                // terms, so both parts are consumed and the
                // pair collapses to a float marker.
                let _real = self.read_typed(if kind == b'y' { b'g' } else { b'f' }, depth + 1)?;
                let _imag = self.read_typed(if kind == b'y' { b'g' } else { b'f' }, depth + 1)?;
                Ok(MarshalValue::Float(0.0))
            }
            b's' | b'a' | b'A' | b't' | b'u' => {
                let len = self.read_count()?;
                let data = self.read_bytes(len)?.to_vec();
                if kind == b's' {
                    Ok(MarshalValue::Bytes(data))
                } else {
                    Ok(MarshalValue::Str(
                        String::from_utf8_lossy(&data).into_owned(),
                    ))
                }
            }
            b'z' | b'Z' => {
                let len = self.read_u8()? as usize;
                let data = self.read_bytes(len)?.to_vec();
                Ok(MarshalValue::Str(
                    String::from_utf8_lossy(&data).into_owned(),
                ))
            }
            b'r' | b'R' => {
                let index = self.read_count()?;
                match self.refs.get(index).and_then(|slot| slot.as_ref()) {
                    Some(value) => Ok(value.clone()),
                    None => {
                        Err(self
                            .error(format!("marshal reference {index} names no recorded value")))
                    }
                }
            }
            b'(' => {
                let count = self.read_count()?;
                self.read_sequence(count, depth).map(MarshalValue::Tuple)
            }
            b')' => {
                let count = self.read_u8()? as usize;
                self.read_sequence(count, depth).map(MarshalValue::Tuple)
            }
            b'[' => {
                let count = self.read_count()?;
                self.read_sequence(count, depth).map(MarshalValue::List)
            }
            b'<' => {
                let count = self.read_count()?;
                self.read_sequence(count, depth).map(MarshalValue::Set)
            }
            b'>' => {
                let count = self.read_count()?;
                self.read_sequence(count, depth)
                    .map(MarshalValue::FrozenSet)
            }
            b'{' => {
                let mut pairs = Vec::new();
                loop {
                    // A dict ends when the next key read is the
                    // null marker type byte '0'.
                    if self.remaining() == 0 {
                        return Err(self.error("marshal dict is unterminated".to_string()));
                    }
                    if self.bytes[self.pos] == b'0' {
                        self.pos += 1;
                        break;
                    }
                    let key = self.read_value(depth + 1)?;
                    let item = self.read_value(depth + 1)?;
                    pairs.push((key, item));
                    if pairs.len() > PYC_VALUES_MAX {
                        return Err(self.error("marshal dict exceeds the bound".to_string()));
                    }
                }
                Ok(MarshalValue::Dict(pairs))
            }
            b'c' => {
                // Marshal writes a code object's scalar
                // fields (counts, flags, first line) as RAW
                // little-endian i32s with no type tag; only
                // the object fields are tagged values. (This
                // is marshal.c's long-standing code shape —
                // reading the scalars as tagged values
                // desynchronises the stream on the first
                // code object.)
                let kinds = code_field_kinds(self.layout);
                let mut fields = Vec::with_capacity(kinds.len());
                for is_object in kinds {
                    if *is_object {
                        fields.push(self.read_value(depth + 1)?);
                    } else {
                        fields.push(MarshalValue::Int(self.read_i32()?.to_string()));
                    }
                }
                Ok(MarshalValue::Code(fields))
            }
            other => Err(self.error(format!(
                "marshal type byte 0x{other:02x} is not a known marshal type"
            ))),
        }
    }

    fn read_sequence(
        &mut self,
        count: usize,
        depth: usize,
    ) -> Result<Vec<MarshalValue>, FathomError> {
        if count > self.remaining() && count > 1024 {
            // Every value costs at least one byte; a count
            // beyond the remaining stream is malformed, and
            // checking here keeps the allocation honest.
            return Err(self.error("marshal sequence count exceeds the stream".to_string()));
        }
        let mut items = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            items.push(self.read_value(depth + 1)?);
        }
        Ok(items)
    }

    fn read_text(&mut self, len: usize) -> Result<String, FathomError> {
        let data = self.read_bytes(len)?;
        Ok(String::from_utf8_lossy(data).into_owned())
    }

    /// Marshal long: a signed digit count followed by
    /// base-2^15 digits, little-endian. Rendered to decimal
    /// with schoolbook arithmetic over the digit string.
    fn read_long(&mut self) -> Result<MarshalValue, FathomError> {
        let signed = self.read_i32()?;
        let negative = signed < 0;
        let digits = signed.unsigned_abs() as usize;
        if digits > 4096 {
            return Err(self.error("marshal long exceeds the digit bound".to_string()));
        }
        let mut limbs: Vec<u16> = Vec::with_capacity(digits);
        for _ in 0..digits {
            limbs.push(self.read_u16()?);
        }
        // Convert base-2^15 limbs to decimal by repeated
        // divide-by-10 over base-2^15 representation... done
        // the simple way: accumulate value = value * 2^15 +
        // limb into a decimal digit vector.
        let mut decimal: Vec<u8> = vec![0];
        for limb in limbs.iter().rev() {
            let mut carry = u32::from(*limb);
            for digit in decimal.iter_mut() {
                let current = u32::from(*digit) * 32768 + carry;
                *digit = (current % 10) as u8;
                carry = current / 10;
            }
            while carry > 0 {
                decimal.push((carry % 10) as u8);
                carry /= 10;
            }
        }
        while decimal.len() > 1 && *decimal.last().unwrap_or(&0) == 0 {
            decimal.pop();
        }
        let mut text: String = decimal
            .iter()
            .rev()
            .map(|digit| char::from(b'0' + digit))
            .collect();
        if negative && text != "0" {
            text.insert(0, '-');
        }
        Ok(MarshalValue::Int(text))
    }
}

// ----------------------------------------------------------------
// Code-object interpretation

/// One interpreted code object: a module, function, class
/// body, lambda, or comprehension.
#[derive(Debug)]
pub struct CodeInfo {
    pub argcount: i64,
    pub code_bytes: usize,
    pub const_count: usize,
    pub filename: String,
    pub first_line: i64,
    pub flags: i64,
    pub kind: &'static str,
    pub kwonly_argcount: i64,
    pub name: String,
    pub names: Vec<String>,
    pub nested: Vec<CodeInfo>,
    pub posonly_argcount: i64,
    pub qualname: String,
    pub string_consts: Vec<String>,
}

/// Field indices per layout: (argcount, posonly, kwonly,
/// flags, code, consts, names, filename, name, qualname,
/// first_line). `qualname` is None where the layout predates
/// it; the qualname is then derived from nesting.
struct LayoutFields {
    argcount: usize,
    code: usize,
    consts: usize,
    filename: usize,
    first_line: usize,
    flags: usize,
    kwonly: usize,
    name: usize,
    names: usize,
    posonly: Option<usize>,
    qualname: Option<usize>,
}

fn layout_fields(layout: CodeLayout) -> LayoutFields {
    match layout {
        CodeLayout::Py2 => LayoutFields {
            argcount: 0,
            code: 4,
            consts: 5,
            filename: 10,
            first_line: 12,
            flags: 3,
            kwonly: 0,
            name: 11,
            names: 6,
            posonly: None,
            qualname: None,
        },
        CodeLayout::Py30 => LayoutFields {
            argcount: 0,
            code: 5,
            consts: 6,
            filename: 11,
            first_line: 13,
            flags: 4,
            kwonly: 1,
            name: 12,
            names: 7,
            posonly: None,
            qualname: None,
        },
        CodeLayout::Py38 => LayoutFields {
            argcount: 0,
            code: 6,
            consts: 7,
            filename: 12,
            first_line: 14,
            flags: 5,
            kwonly: 2,
            name: 13,
            names: 8,
            posonly: Some(1),
            qualname: None,
        },
        CodeLayout::Py311 => LayoutFields {
            argcount: 0,
            code: 5,
            consts: 6,
            filename: 10,
            first_line: 13,
            flags: 4,
            kwonly: 2,
            name: 11,
            names: 7,
            posonly: Some(1),
            qualname: Some(12),
        },
    }
}

/// CO_ flag bits that say what a code object is.
const CO_GENERATOR: i64 = 0x20;
const CO_COROUTINE: i64 = 0x80;
const CO_ASYNC_GENERATOR: i64 = 0x200;

fn code_kind(name: &str, flags: i64, depth: usize) -> &'static str {
    if depth == 0 {
        "module"
    } else if name == "<lambda>" {
        "lambda"
    } else if name == "<genexpr>"
        || name == "<listcomp>"
        || name == "<setcomp>"
        || name == "<dictcomp>"
    {
        "comprehension"
    } else if flags & CO_ASYNC_GENERATOR != 0 {
        "async generator"
    } else if flags & CO_COROUTINE != 0 {
        "coroutine"
    } else if flags & CO_GENERATOR != 0 {
        "generator"
    } else {
        "function or class"
    }
}

/// Interpret one marshalled code value. Nested code objects
/// arrive as items of the parent's consts tuple.
fn interpret_code(
    value: &MarshalValue,
    layout: CodeLayout,
    depth: usize,
    budget: &mut usize,
) -> Result<CodeInfo, FathomError> {
    let MarshalValue::Code(fields) = value else {
        return Err(
            FathomError::new(ErrorCode::UnsupportedTarget, "value is not a code object")
                .with_target("marshal stream"),
        );
    };
    let index = layout_fields(layout);
    let get = |position: usize| -> Option<&MarshalValue> { fields.get(position) };
    let name = get(index.name)
        .and_then(MarshalValue::as_str)
        .unwrap_or("<unnamed>")
        .to_string();
    let flags = get(index.flags).and_then(MarshalValue::as_i64).unwrap_or(0);
    let consts = get(index.consts).and_then(MarshalValue::as_items);
    let mut string_consts: Vec<String> = Vec::new();
    let mut nested = Vec::new();
    if let Some(items) = consts {
        for item in items {
            match item {
                MarshalValue::Str(text) => {
                    if string_consts.len() < PYC_STRING_CONSTS_MAX {
                        string_consts.push(text.clone());
                    }
                }
                MarshalValue::Code(_) => {
                    if *budget == 0 {
                        break;
                    }
                    *budget -= 1;
                    nested.push(interpret_code(item, layout, depth + 1, budget)?);
                }
                _ => {}
            }
        }
    }
    let qualname = index
        .qualname
        .and_then(get)
        .and_then(MarshalValue::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| name.clone());
    Ok(CodeInfo {
        argcount: get(index.argcount)
            .and_then(MarshalValue::as_i64)
            .unwrap_or(0),
        code_bytes: get(index.code)
            .and_then(MarshalValue::as_bytes)
            .map(<[u8]>::len)
            .unwrap_or(0),
        const_count: consts.map(<[MarshalValue]>::len).unwrap_or(0),
        filename: get(index.filename)
            .and_then(MarshalValue::as_str)
            .unwrap_or_default()
            .to_string(),
        first_line: get(index.first_line)
            .and_then(MarshalValue::as_i64)
            .unwrap_or(0),
        flags,
        kind: code_kind(&name, flags, depth),
        kwonly_argcount: if matches!(layout, CodeLayout::Py2) {
            0
        } else {
            get(index.kwonly)
                .and_then(MarshalValue::as_i64)
                .unwrap_or(0)
        },
        name,
        names: get(index.names)
            .and_then(MarshalValue::as_items)
            .map(|items| {
                items
                    .iter()
                    .filter_map(MarshalValue::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        nested,
        posonly_argcount: index
            .posonly
            .and_then(get)
            .and_then(MarshalValue::as_i64)
            .unwrap_or(0),
        qualname,
        string_consts,
    })
}

/// A parsed .pyc: the header plus the module code tree.
#[derive(Debug)]
pub struct PycModule {
    pub header: PycHeader,
    pub root: CodeInfo,
    /// Marshalled bytes after the top-level code object
    /// (a well-formed pyc has none).
    pub trailing_bytes: usize,
}

/// Parse a complete .pyc from its bytes.
pub fn parse_pyc(bytes: &[u8]) -> Result<PycModule, FathomError> {
    let header = parse_pyc_header(bytes)?;
    let Some((_, layout)) = pyc_version(header.magic) else {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            format!(
                "pyc magic {} (0x{:04x}) names a CPython version this reader \
                     does not know — NOT-IMPLEMENTED for that version, never guessed",
                header.magic, header.magic
            ),
        )
        .with_target("python pyc file"));
    };
    let mut reader = MarshalReader::new(&bytes[header.header_len..], layout);
    let value = reader.read_value(0)?;
    let mut budget = PYC_CODE_OBJECTS_MAX;
    let root = interpret_code(&value, layout, 0, &mut budget)?;
    Ok(PycModule {
        header,
        root,
        trailing_bytes: reader.remaining(),
    })
}

/// Flatten a code tree into evidence rows (depth-first, the
/// module first), bounded by the code-object census bound.
fn code_rows(code: &CodeInfo, depth: usize, rows: &mut Vec<Value>) {
    if rows.len() >= PYC_CODE_OBJECTS_MAX {
        return;
    }
    rows.push(json!({
        "argcount": code.argcount,
        "code_bytes": code.code_bytes,
        "const_count": code.const_count,
        "depth": depth,
        "filename": code.filename,
        "first_line": code.first_line,
        "flags": code.flags,
        "kind": code.kind,
        "kwonly_argcount": code.kwonly_argcount,
        "name": code.name,
        "names": code.names,
        "posonly_argcount": code.posonly_argcount,
        "qualname": code.qualname,
        "string_consts": code.string_consts,
    }));
    for child in &code.nested {
        code_rows(child, depth + 1, rows);
    }
}

fn count_code(code: &CodeInfo) -> usize {
    1 + code.nested.iter().map(count_code).sum::<usize>()
}

// ----------------------------------------------------------------
// PyInstaller CArchive

/// One PyInstaller table-of-contents entry.
#[derive(Debug)]
pub struct PyiEntry {
    /// The entry is zlib-compressed in the archive.
    pub compressed: bool,
    pub name: String,
    /// Position of the stored bytes, relative to the
    /// archive's start.
    pub position: u32,
    /// Stored (possibly compressed) length.
    pub stored_len: u32,
    /// Typecode byte: 'b' binary, 'd' dependency, 'e'
    /// extension, 'l' splash, 'm' module, 'o' option, 's'
    /// script, 'x' data, 'z' PYZ archive, 'Z' zip archive.
    pub typecode: u8,
    /// Length after decompression.
    pub uncompressed_len: u32,
}

impl PyiEntry {
    pub fn typecode_name(&self) -> &'static str {
        match self.typecode {
            b'b' => "binary",
            b'd' => "dependency",
            b'e' => "extension",
            b'l' => "splash",
            b'm' => "module",
            b'o' => "option",
            b's' => "script",
            b'x' => "data",
            b'z' => "PYZ archive",
            b'Z' => "zip archive",
            _ => "unknown",
        }
    }
}

/// One module inside a PYZ archive.
#[derive(Debug)]
pub struct PyzModule {
    pub is_package: bool,
    /// Marshalled code-object name, decoded from the entry's
    /// decompressed payload (a derived fact: the payload is
    /// zlib + marshal, both read, never executed).
    pub code_name: Option<String>,
    pub name: String,
    pub stored_len: u32,
}

/// A parsed PYZ archive: the module table of the entry that
/// carries it.
#[derive(Debug)]
pub struct PyzArchive {
    pub modules: Vec<PyzModule>,
    pub pyc_magic: u16,
}

/// A parsed PyInstaller CArchive.
#[derive(Debug)]
pub struct PyiArchive {
    /// Absolute offset at which the archive (package) starts.
    pub archive_start: usize,
    /// Absolute offset of the cookie.
    pub cookie_offset: usize,
    pub entries: Vec<PyiEntry>,
    /// Bytes trailing the cookie (a cookie not at EOF).
    pub trailing_bytes: usize,
    /// Python library file name from the cookie.
    pub pylib_name: String,
    /// Python version integer from the cookie (e.g. 312).
    pub python_version: u32,
    /// The PYZ archive carried by the 'z' entry, if any and
    /// if it parsed; a PYZ that fails to parse is reported by
    /// the tool as an unknown, not silently dropped.
    pub pyz: Option<PyzArchive>,
    /// Why the PYZ did not parse, when it did not.
    pub pyz_failure: Option<String>,
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|raw| u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// True when a byte window carries a CArchive cookie (used
/// by artifact classification's bounded tail probe).
pub fn contains_cookie(window: &[u8]) -> bool {
    find_cookie(window).is_some()
}

/// Locate the cookie: exactly at EOF, else by scanning the
/// tail window (builds with appended data — signatures,
/// overlays — put bytes after the cookie).
fn find_cookie(bytes: &[u8]) -> Option<usize> {
    if bytes.len() >= COOKIE_LEN && &bytes[bytes.len() - COOKIE_LEN..][..8] == COOKIE_MAGIC {
        return Some(bytes.len() - COOKIE_LEN);
    }
    let window_start = bytes.len().saturating_sub(COOKIE_SCAN_BYTES + COOKIE_LEN);
    let window = &bytes[window_start..];
    (0..window.len().saturating_sub(8))
        .rev()
        .find(|&index| &window[index..index + 8] == COOKIE_MAGIC)
        .map(|index| window_start + index)
}

/// Parse a PyInstaller CArchive. Returns `None` when the
/// file carries no cookie (not a PyInstaller archive).
pub fn parse_pyinstaller(bytes: &[u8]) -> Result<Option<PyiArchive>, FathomError> {
    let unsupported = |message: String| {
        FathomError::new(ErrorCode::UnsupportedTarget, message).with_target("pyinstaller archive")
    };
    let Some(cookie_offset) = find_cookie(bytes) else {
        return Ok(None);
    };
    let cookie = &bytes[cookie_offset..cookie_offset + COOKIE_LEN];
    let package_len = read_be_u32(cookie, 8).unwrap_or(0) as usize;
    let toc_offset = read_be_u32(cookie, 12).unwrap_or(0) as usize;
    let toc_len = read_be_u32(cookie, 16).unwrap_or(0) as usize;
    let python_version = read_be_u32(cookie, 20).unwrap_or(0);
    let pylib_raw = &cookie[24..88];
    let pylib_name =
        String::from_utf8_lossy(&pylib_raw[..pylib_raw.iter().position(|b| *b == 0).unwrap_or(64)])
            .into_owned();
    let archive_end = cookie_offset + COOKIE_LEN;
    if package_len < COOKIE_LEN || package_len > archive_end {
        return Err(unsupported(format!(
            "cookie declares a package length of {package_len} bytes in a file \
             whose cookie ends at {archive_end} — the cookie is corrupt or foreign"
        )));
    }
    let archive_start = archive_end - package_len;
    let toc_start = archive_start
        .checked_add(toc_offset)
        .filter(|start| *start <= bytes.len())
        .ok_or_else(|| unsupported("TOC offset lands outside the file".to_string()))?;
    let toc_end = toc_start
        .checked_add(toc_len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| unsupported("TOC length runs past the end of the file".to_string()))?;
    let toc = &bytes[toc_start..toc_end];
    let mut entries = Vec::new();
    let mut pos = 0_usize;
    while pos < toc.len() {
        if toc.len() - pos < TOC_ENTRY_HEADER_LEN {
            return Err(unsupported("TOC ends inside an entry header".to_string()));
        }
        let entry_len = read_be_u32(toc, pos).unwrap_or(0) as usize;
        if entry_len < TOC_ENTRY_HEADER_LEN || pos + entry_len > toc.len() {
            return Err(unsupported(format!(
                "TOC entry at {pos} declares length {entry_len} outside the TOC"
            )));
        }
        let name_raw = &toc[pos + TOC_ENTRY_HEADER_LEN..pos + entry_len];
        let name = String::from_utf8_lossy(
            &name_raw[..name_raw
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(name_raw.len())],
        )
        .into_owned();
        entries.push(PyiEntry {
            compressed: toc[pos + 16] != 0,
            name,
            position: read_be_u32(toc, pos + 4).unwrap_or(0),
            stored_len: read_be_u32(toc, pos + 8).unwrap_or(0),
            typecode: toc[pos + 17],
            uncompressed_len: read_be_u32(toc, pos + 12).unwrap_or(0),
        });
        if entries.len() > PYINSTALLER_ENTRIES_MAX {
            return Err(unsupported(
                "TOC entry count exceeds the census bound".to_string(),
            ));
        }
        pos += entry_len;
    }
    // The PYZ archive (typecode 'z') nests a second archive
    // in its stored bytes; parse it now so the tool reports
    // one document.
    let mut pyz = None;
    let mut pyz_failure = None;
    if let Some(entry) = entries.iter().find(|entry| entry.typecode == b'z') {
        let start = archive_start + entry.position as usize;
        let end = start + entry.stored_len as usize;
        match bytes.get(start..end) {
            Some(stored) => match parse_pyz(stored) {
                Ok(parsed) => pyz = Some(parsed),
                Err(error) => pyz_failure = Some(error.message.clone()),
            },
            None => pyz_failure = Some("PYZ entry points outside the file".to_string()),
        }
    }
    Ok(Some(PyiArchive {
        archive_start,
        cookie_offset,
        entries,
        trailing_bytes: bytes.len() - archive_end,
        pylib_name,
        python_version,
        pyz,
        pyz_failure,
    }))
}

/// Parse a PYZ archive's table of contents and decode each
/// module's code-object name from its zlib-compressed
/// marshal payload.
pub fn parse_pyz(stored: &[u8]) -> Result<PyzArchive, FathomError> {
    let unsupported = |message: String| {
        FathomError::new(ErrorCode::UnsupportedTarget, message).with_target("pyz archive")
    };
    if stored.len() < 12 || &stored[0..4] != b"PYZ\0" {
        return Err(unsupported("missing the PYZ\\0 magic".to_string()));
    }
    let pyc_magic = u16::from_le_bytes([stored[4], stored[5]]);
    let Some((_, layout)) = pyc_version(pyc_magic) else {
        return Err(unsupported(format!(
            "PYZ carries pyc magic {pyc_magic}, a CPython version this reader \
             does not know — NOT-IMPLEMENTED for that version"
        )));
    };
    let toc_offset = read_be_u32(stored, 8).unwrap_or(0) as usize;
    if toc_offset >= stored.len() {
        return Err(unsupported(
            "PYZ TOC offset lands outside the archive".to_string(),
        ));
    }
    let mut reader = MarshalReader::new(&stored[toc_offset..], layout);
    let toc_value = reader.read_value(0)?;
    // The TOC's shape changed across PyInstaller versions:
    // a marshal dict of name -> (type, offset, length) in
    // older releases, a marshal list of (name, (type,
    // offset, length)) tuples in current ones. Both are
    // read; any other shape is refused by name.
    let pairs: Vec<(String, MarshalValue)> = match &toc_value {
        MarshalValue::Dict(entries) => entries
            .iter()
            .filter_map(|(key, value)| key.as_str().map(|name| (name.to_string(), value.clone())))
            .collect(),
        MarshalValue::Tuple(items) | MarshalValue::List(items) => items
            .iter()
            .filter_map(|item| {
                let pair = item.as_items()?;
                if pair.len() != 2 {
                    return None;
                }
                pair[0]
                    .as_str()
                    .map(|name| (name.to_string(), pair[1].clone()))
            })
            .collect(),
        _ => {
            return Err(unsupported(
                "PYZ TOC is neither a marshal dict nor a marshal list of pairs".to_string(),
            ));
        }
    };
    let mut modules = Vec::new();
    for (name, value) in &pairs {
        let name = name.as_str();
        let Some(items) = value.as_items() else {
            continue;
        };
        if items.len() != 3 {
            continue;
        }
        // PYZ item types: 0 = module, 1 = package,
        // 2 = namespace package (no payload).
        let is_package = items[0].as_i64().unwrap_or(0) == 1;
        let position = items[1].as_i64().unwrap_or(0);
        let length = items[2].as_i64().unwrap_or(0);
        if position < 0 || length < 0 {
            continue;
        }
        let (start, len) = (position as usize, length as usize);
        let code_name = stored
            .get(start..start + len)
            .and_then(|payload| decompress_zlib(payload, PAYLOAD_BYTES_MAX))
            .and_then(|plain| {
                let mut inner = MarshalReader::new(&plain, layout);
                let value = inner.read_value(0).ok()?;
                let mut budget = 1;
                interpret_code(&value, layout, 0, &mut budget).ok()
            })
            .map(|code| code.qualname);
        modules.push(PyzModule {
            is_package,
            code_name,
            name: name.to_string(),
            stored_len: length as u32,
        });
        if modules.len() > PYZ_MODULES_MAX {
            break;
        }
    }
    modules.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(PyzArchive { modules, pyc_magic })
}

/// Decompress one zlib stream with an output bound; a stream
/// that overruns the bound or fails to decode is `None`.
fn decompress_zlib(data: &[u8], bound: usize) -> Option<Vec<u8>> {
    let mut decoder = flate2::read::ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder
        .by_ref()
        .take(bound as u64)
        .read_to_end(&mut out)
        .ok()?;
    if out.len() >= bound {
        return None;
    }
    Some(out)
}

/// One entry's stored bytes, decompressed when the entry is
/// compressed. `None` when the entry is out of bounds or the
/// payload does not decode.
fn entry_payload(bytes: &[u8], archive: &PyiArchive, entry: &PyiEntry) -> Option<Vec<u8>> {
    let start = archive.archive_start.checked_add(entry.position as usize)?;
    let stored = bytes.get(start..start + entry.stored_len as usize)?;
    if entry.compressed {
        decompress_zlib(stored, PAYLOAD_BYTES_MAX)
    } else {
        Some(stored.to_vec())
    }
}

// ----------------------------------------------------------------
// Tool surface

/// Retain one census document under the subject's
/// `archive_census` export (readers SPEC §2.5), in the Godot
/// reader's pattern: retention failure degrades the run to
/// partial; the census facts stand.
fn retain_census(
    config: &Config,
    subject_sha256: &str,
    document: &Value,
) -> (Option<String>, Option<String>) {
    match proof::retain_export(config, subject_sha256, "archive_census", document) {
        Ok(digest) => (Some(digest), None),
        Err(error) => (
            None,
            Some(format!(
                "census retention failed ({}); the census facts stand, \
                 but no proof can bind this run",
                error.message
            )),
        ),
    }
}

fn pyc_evidence(
    bytes: &[u8],
    subject: fathom_core::evidence::Subject,
) -> Result<Value, FathomError> {
    let module = parse_pyc(bytes)?;
    let header = &module.header;
    let mut evidence = Evidence::new("inspect_python_artifact", "python");
    evidence.subject = Some(subject);
    evidence.add_finding(Finding::new(
        "python_pyc",
        Confidence::Observed,
        json!({
            "format": "pyc",
            "hash_based": header.hash_based,
            "hash_check_source": header.hash_check_source,
            "header_bytes": header.header_len,
            "magic": header.magic,
            "source_size": header.source_size,
            "timestamp": header.timestamp,
            "trailing_bytes_after_code": module.trailing_bytes,
            "version": header.version,
        }),
    ));
    let total = count_code(&module.root);
    let mut rows = Vec::new();
    code_rows(&module.root, 0, &mut rows);
    evidence.add_finding(Finding::new(
        "code_objects",
        Confidence::Observed,
        json!({
            "count": total,
            "filename": module.root.filename,
            "module_names": module.root.names,
            "objects": rows,
        }),
    ));
    evidence.add_unknown(
        "disassembly",
        "bytecode instructions are not decoded in this stage; the inventory is \
         code-object structure (names, arguments, constants), not a listing — \
         instruction decode is NOT-IMPLEMENTED",
    );
    if module.trailing_bytes > 0 {
        evidence.add_unknown(
            "trailing data",
            format!(
                "{} bytes follow the module code object; a well-formed .pyc has none",
                module.trailing_bytes
            ),
        );
    }
    evidence.coverage.examined = total as u64;
    evidence.coverage.total = total as u64;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

fn pyinstaller_evidence(
    config: &Config,
    bytes: &[u8],
    archive: &PyiArchive,
    subject: fathom_core::evidence::Subject,
) -> Result<Value, FathomError> {
    let subject_sha256 = subject.sha256.clone();
    let mut evidence = Evidence::new("inspect_python_artifact", "python");
    evidence.subject = Some(subject);
    let total = archive.entries.len();
    let mut examined: u64 = 0;
    let mut overrun_names: Vec<&str> = Vec::new();
    let mut rows: Vec<Value> = Vec::new();
    for entry in &archive.entries {
        let start = archive.archive_start + entry.position as usize;
        let stored = bytes.get(start..start + entry.stored_len as usize);
        let (sha256, status) = match stored {
            Some(data) => {
                examined += 1;
                (json!(sha256_hex(data)), "stored")
            }
            None => {
                overrun_names.push(entry.name.as_str());
                (Value::Null, "overrun")
            }
        };
        // Entry scripts and archive modules carry a marshalled
        // code object as their payload; decode its name as a
        // derived fact when the payload reads.
        let code_name = if matches!(entry.typecode, b's' | b'm') {
            entry_payload(bytes, archive, entry).and_then(|payload| entry_script_name(&payload))
        } else {
            None
        };
        rows.push(json!({
            "code_name": code_name,
            "compressed": entry.compressed,
            "key": entry.name,
            "name": entry.name,
            "position": start,
            "sha256": sha256,
            "status": status,
            "stored_len": entry.stored_len,
            "typecode": (entry.typecode as char).to_string(),
            "typecode_name": entry.typecode_name(),
            "uncompressed_len": entry.uncompressed_len,
        }));
    }
    let record = json!({
        "archive_start": archive.archive_start,
        "cookie_offset": archive.cookie_offset,
        "entries": total,
        "format": "pyinstaller",
        "pylib_name": archive.pylib_name,
        "python_version": archive.python_version,
        "trailing_bytes_after_cookie": archive.trailing_bytes,
    });
    let document = json!({
        "pyinstaller_archive": record.clone(),
        "pyinstaller_entries": rows.clone(),
        "pyinstaller_entries_total": total,
        "pyinstaller_entries_truncated": false,
    });
    let (digest, retention_note) = retain_census(config, &subject_sha256, &document);
    let mut archive_finding = Finding::new("pyinstaller_archive", Confidence::Observed, record);
    if let Some(digest) = &digest {
        archive_finding = archive_finding.with_limitation(format!(
            "census retained as the subject's archive_census export (digest {digest})"
        ));
    }
    evidence.add_finding(archive_finding);
    if let Some(note) = retention_note {
        evidence.add_unknown("retention", note);
    }
    evidence.add_finding(Finding::new(
        "pyinstaller_entries",
        Confidence::Observed,
        json!({"count": total, "entries": rows}),
    ));
    if let Some(pyz) = &archive.pyz {
        let module_rows: Vec<Value> = pyz
            .modules
            .iter()
            .map(|module| {
                json!({
                    "code_name": module.code_name,
                    "is_package": module.is_package,
                    "name": module.name,
                    "stored_len": module.stored_len,
                })
            })
            .collect();
        evidence.add_finding(Finding::new(
            "pyz_modules",
            Confidence::Observed,
            json!({
                "count": module_rows.len(),
                "modules": module_rows,
                "pyc_magic": pyz.pyc_magic,
            }),
        ));
    }
    if let Some(failure) = &archive.pyz_failure {
        evidence.add_unknown(
            "PYZ archive",
            format!("the bundled PYZ archive did not parse: {failure}"),
        );
    }
    if !overrun_names.is_empty() {
        evidence.add_unknown(
            "entry data",
            format!(
                "{} entries declare a position/length outside the archive \
                 (first: {}); the TOC's claims for them cannot be checked",
                overrun_names.len(),
                overrun_names[0]
            ),
        );
    }
    evidence.add_unknown(
        "entry payloads",
        "entry payloads are inventoried and hashed, not extracted to disk or \
         executed; script/module payloads contribute their code-object name only",
    );
    evidence.coverage.examined = examined;
    evidence.coverage.total = total as u64;
    evidence.coverage.exhaustive = examined == total as u64;
    Ok(evidence.to_value())
}

/// The code-object name of a marshalled script/module
/// payload. The payload's marshal layout follows the
/// archive's Python version; when that version is unknown
/// the name is not guessed.
fn entry_script_name(payload: &[u8]) -> Option<String> {
    // Marshal version differences that matter here are the
    // code layout; script payloads in archives produced by
    // supported Pythons use the Py311/Py38 shapes. Try the
    // newest layout family first, then the older one; a
    // payload that parses under neither yields no name.
    for layout in [CodeLayout::Py311, CodeLayout::Py38, CodeLayout::Py30] {
        let mut reader = MarshalReader::new(payload, layout);
        if let Ok(value) = reader.read_value(0) {
            let mut budget = 1;
            if let Ok(code) = interpret_code(&value, layout, 0, &mut budget) {
                return Some(code.qualname);
            }
        }
    }
    None
}

pub fn inspect_python_artifact(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target: {e}"),
        )
    })?;
    // A .pyc announces itself in its first four bytes (magic
    // + 0x0d 0x0a). Everything else is tried as a PyInstaller
    // archive; a file that is neither is refused by name.
    if bytes.len() >= 4 && bytes[2] == 0x0d && bytes[3] == 0x0a {
        return pyc_evidence(&bytes, subject);
    }
    match parse_pyinstaller(&bytes)? {
        Some(archive) => pyinstaller_evidence(config, &bytes, &archive, subject),
        None => Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "target is neither a Python .pyc nor a PyInstaller archive (no \
             CArchive cookie found)",
        )
        .with_target("python artifact")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PYC: &[u8] = include_bytes!("../tests/fixtures/sample_module.pyc");
    const SAMPLE_APP: &[u8] = include_bytes!("../tests/fixtures/sample_pyinstaller.bin");

    // -- Validation: real CPython-produced .pyc --------------

    #[test]
    fn validation_real_pyc_header_and_tree() {
        let module = parse_pyc(SAMPLE_PYC).expect("real pyc parses");
        assert_eq!(module.header.version, Some("3.12"));
        assert_eq!(module.header.magic, 3531);
        assert!(!module.header.hash_based);
        assert_eq!(module.trailing_bytes, 0);
        assert_eq!(module.root.name, "<module>");
        assert!(module.root.names.contains(&"json".to_string()));
        assert!(
            module
                .root
                .string_consts
                .contains(&"hello fathom".to_string())
        );
        let names: Vec<&str> = module
            .root
            .nested
            .iter()
            .map(|code| code.name.as_str())
            .collect();
        assert!(names.contains(&"greet"), "nested: {names:?}");
        assert!(names.contains(&"Widget"), "nested: {names:?}");
        assert!(names.contains(&"numbers"), "nested: {names:?}");
        assert!(names.contains(&"fetch"), "nested: {names:?}");
        let greet = module
            .root
            .nested
            .iter()
            .find(|code| code.name == "greet")
            .expect("greet exists");
        assert_eq!(greet.argcount, 2);
        assert_eq!(greet.qualname, "greet");
        let numbers = module
            .root
            .nested
            .iter()
            .find(|code| code.name == "numbers")
            .expect("numbers exists");
        assert_eq!(numbers.kind, "generator");
        let fetch = module
            .root
            .nested
            .iter()
            .find(|code| code.name == "fetch")
            .expect("fetch exists");
        assert_eq!(fetch.kind, "coroutine");
        assert_eq!(fetch.kwonly_argcount, 1);
    }

    // -- Validation: real PyInstaller-produced archive -------

    #[test]
    fn validation_real_pyinstaller_archive() {
        let archive = parse_pyinstaller(SAMPLE_APP)
            .expect("archive parses")
            .expect("cookie found");
        assert_eq!(archive.python_version, 312);
        assert_eq!(archive.pylib_name, "libpython3.12.so.1.0");
        assert_eq!(archive.archive_start, 512);
        assert_eq!(archive.trailing_bytes, 0);
        let names: Vec<&str> = archive
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, ["app_main", "PYZ-00.pyz", "readme.txt"]);
        let script = &archive.entries[0];
        assert_eq!(script.typecode, b's');
        assert_eq!(script.typecode_name(), "script");
        let pyz = archive.pyz.expect("PYZ parsed");
        assert_eq!(pyz.pyc_magic, 3531);
        let module_names: Vec<&str> = pyz
            .modules
            .iter()
            .map(|module| module.name.as_str())
            .collect();
        assert!(module_names.contains(&"sample_module"), "{module_names:?}");
        assert!(module_names.contains(&"inner_mod"), "{module_names:?}");
        let inner = pyz
            .modules
            .iter()
            .find(|module| module.name == "inner_mod")
            .expect("inner module");
        assert_eq!(inner.code_name.as_deref(), Some("<module>"));
    }

    // -- Adversarial ------------------------------------------

    #[test]
    fn adversarial_unknown_magic_is_refused_not_guessed() {
        let mut bytes = SAMPLE_PYC.to_vec();
        bytes[0] = 0xff;
        bytes[1] = 0x7f; // magic 0x7fff: no such CPython
        let error = parse_pyc(&bytes).expect_err("unknown magic refuses");
        assert!(
            error.message.contains("NOT-IMPLEMENTED"),
            "{}",
            error.message
        );
    }

    #[test]
    fn adversarial_truncated_pyc_errors() {
        let error = parse_pyc(&SAMPLE_PYC[..40]).expect_err("truncated stream errors");
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
    }

    #[test]
    fn adversarial_marshal_reference_to_nothing_errors() {
        // A lone reference opcode naming slot 0, with no
        // flagged value ever recorded.
        let mut reader = MarshalReader::new(&[b'r', 0, 0, 0, 0], CodeLayout::Py311);
        assert!(reader.read_value(0).is_err());
    }

    #[test]
    fn adversarial_marshal_negative_count_errors() {
        let mut reader = MarshalReader::new(&[b'(', 0xff, 0xff, 0xff, 0xff], CodeLayout::Py311);
        assert!(reader.read_value(0).is_err());
    }

    #[test]
    fn adversarial_cookie_with_impossible_package_length_errors() {
        let mut bytes = SAMPLE_APP.to_vec();
        let cookie = bytes.len() - COOKIE_LEN;
        // Package length larger than the file.
        bytes[cookie + 8..cookie + 12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_pyinstaller(&bytes).is_err());
    }

    #[test]
    fn adversarial_cookie_not_at_eof_is_found_by_scan() {
        let mut bytes = SAMPLE_APP.to_vec();
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // appended overlay
        let archive = parse_pyinstaller(&bytes)
            .expect("archive parses")
            .expect("cookie found by scan");
        assert_eq!(archive.trailing_bytes, 4);
        assert_eq!(archive.entries.len(), 3);
    }

    #[test]
    fn adversarial_plain_binary_is_not_an_archive() {
        assert!(
            parse_pyinstaller(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0])
                .expect("no error")
                .is_none()
        );
    }

    #[test]
    fn adversarial_toc_entry_length_overrun_errors() {
        let mut bytes = SAMPLE_APP.to_vec();
        let cookie = bytes.len() - COOKIE_LEN;
        let archive_start = 512;
        let toc_offset = read_be_u32(&bytes, cookie + 12).unwrap_or(0) as usize;
        let first_entry = archive_start + toc_offset;
        bytes[first_entry..first_entry + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_pyinstaller(&bytes).is_err());
    }

    #[test]
    fn adversarial_pyc_flags_with_unknown_bits_error() {
        let mut bytes = SAMPLE_PYC.to_vec();
        bytes[4] = 0x40; // flags bit 6: not a PEP 552 bit
        assert!(parse_pyc(&bytes).is_err());
    }
}

//! BEAM module reader (REA-adaptation S6), implemented
//! directly.
//!
//! A .beam file is an IFF form: `FOR1`, a big-endian form
//! size, `BEAM`, then chunks framed as a 4-byte name, a
//! big-endian size, the chunk bytes, and padding to a 4-byte
//! boundary. This reader inventories the chunks and decodes
//! the tables that carry the module's reverse-engineering
//! facts: the atom table (`Atom` latin-1 or `AtU8` UTF-8),
//! imports (`ImpT`), exports (`ExpT`), locals (`LocT`),
//! lambdas (`FunT`), the string table (`StrT`), and the
//! literal table (`LitT` — a zlib-compressed external-term
//! blob, walked with a bounded external-term reader that
//! counts terms and censuses their atoms, never materialises
//! them). The `Code` chunk contributes its header (instruction
//! set, opcode ceiling, label and function counts, the last
//! cross-checked against the function tables).
//!
//! Honesty contract: the opcode stream itself is not decoded
//! — opcode tables are instruction-set-versioned and a wrong
//! table would fabricate facts, so instruction decode is a
//! named NOT-IMPLEMENTED wall in the envelope's unknowns.
//! Atom indexes that resolve outside the atom table are
//! reported as unresolved rows, never dropped. Debug info
//! (`Dbgi`) is inventoried by presence; its contents are not
//! decoded in this stage.

use serde_json::{Value, json};
use std::io::Read as _;
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file};
use fathom_core::limits::{BEAM_ATOMS_MAX, BEAM_FUNCTIONS_MAX};
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

/// Literal-table decompression bound.
const LITT_BYTES_MAX: usize = 33_554_432;
/// External-term nesting depth bound.
const TERM_DEPTH_MAX: usize = 64;
/// Term census bound inside one literal table.
const TERM_COUNT_MAX: usize = 1_000_000;
/// String-table segment census bound.
const STRT_SEGMENTS_MAX: usize = 5_000;

/// One chunk's framing facts.
#[derive(Debug)]
pub struct BeamChunk {
    pub name: String,
    pub size: u32,
}

/// A function reference: name resolved through the atom
/// table (1-based); `name` is `None` when the atom index is
/// out of range — the row is kept, the gap is visible.
#[derive(Debug)]
pub struct BeamFunction {
    pub arity: u32,
    pub atom_index: u32,
    pub label: u32,
    pub name: Option<String>,
}

/// An imported function: module/name/arity atom references.
#[derive(Debug)]
pub struct BeamImport {
    pub arity: u32,
    pub function: Option<String>,
    pub function_atom: u32,
    pub module: Option<String>,
    pub module_atom: u32,
}

/// The Code chunk header.
#[derive(Debug)]
pub struct BeamCodeHeader {
    pub function_count: u32,
    pub instruction_set: u32,
    pub label_count: u32,
    pub opcode_max: u32,
    /// Bytes of opcode stream after the header (not decoded).
    pub opcode_bytes: usize,
}

/// A literal-table census: term count and the atoms the
/// bounded external-term walk met.
#[derive(Debug)]
pub struct BeamLiterals {
    pub atoms: Vec<String>,
    pub partial_reason: Option<String>,
    pub term_count: usize,
    pub uncompressed_len: usize,
}

/// A parsed BEAM module.
#[derive(Debug)]
pub struct BeamModule {
    /// Atom table encoding: "Atom" (latin-1) or "AtU8".
    pub atom_encoding: Option<&'static str>,
    pub atoms: Vec<String>,
    pub chunks: Vec<BeamChunk>,
    pub code: Option<BeamCodeHeader>,
    pub exports: Vec<BeamFunction>,
    /// The FOR1 size field disagrees with the file length.
    pub form_size_mismatch: bool,
    pub imports: Vec<BeamImport>,
    pub lambdas: Vec<BeamFunction>,
    pub literals: Option<BeamLiterals>,
    pub locals: Vec<BeamFunction>,
    /// String-table segments (the table is raw concatenated
    /// bytes; segments split on NUL where present).
    pub string_segments: Vec<String>,
    pub string_table_bytes: usize,
}

fn beam_error(message: String) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message).with_target("beam module")
}

fn be_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|raw| u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|raw| u16::from_be_bytes([raw[0], raw[1]]))
}

/// Parse a BEAM module from its full bytes.
pub fn parse_beam(bytes: &[u8]) -> Result<BeamModule, FathomError> {
    if bytes.len() < 12 || &bytes[0..4] != b"FOR1" || &bytes[8..12] != b"BEAM" {
        return Err(beam_error(
            "missing the FOR1/BEAM form header of a BEAM module".to_string(),
        ));
    }
    let declared = be_u32(bytes, 4).unwrap_or(0) as usize;
    let form_size_mismatch = declared + 8 != bytes.len();
    let mut module = BeamModule {
        atom_encoding: None,
        atoms: Vec::new(),
        chunks: Vec::new(),
        code: None,
        exports: Vec::new(),
        form_size_mismatch,
        imports: Vec::new(),
        lambdas: Vec::new(),
        literals: None,
        locals: Vec::new(),
        string_segments: Vec::new(),
        string_table_bytes: 0,
    };
    // Chunk bodies are needed in two passes (the atom table
    // resolves the other tables' indexes), so collect the
    // framed ranges first.
    let mut bodies: Vec<(String, &[u8])> = Vec::new();
    let mut pos = 12_usize;
    while pos < bytes.len() {
        if bytes.len() - pos < 8 {
            return Err(beam_error(format!(
                "chunk framing ends mid-header at byte {pos}"
            )));
        }
        let name = String::from_utf8_lossy(&bytes[pos..pos + 4]).into_owned();
        let size = be_u32(bytes, pos + 4).unwrap_or(0) as usize;
        let body_start = pos + 8;
        let body = bytes.get(body_start..body_start + size).ok_or_else(|| {
            beam_error(format!(
                "chunk {name} declares {size} bytes running past the end of the file"
            ))
        })?;
        module.chunks.push(BeamChunk {
            name: name.clone(),
            size: size as u32,
        });
        bodies.push((name, body));
        let padded = size + (4 - size % 4) % 4;
        pos = body_start + padded;
    }
    for (name, body) in &bodies {
        match name.as_str() {
            "Atom" => {
                module.atom_encoding = Some("Atom");
                module.atoms = parse_atoms(body, false)?;
            }
            "AtU8" => {
                module.atom_encoding = Some("AtU8");
                module.atoms = parse_atoms(body, true)?;
            }
            _ => {}
        }
    }
    let atoms = &module.atoms;
    for (name, body) in &bodies {
        match name.as_str() {
            "Code" => module.code = Some(parse_code_header(body)?),
            "ExpT" => module.exports = parse_functions(body, atoms)?,
            "FunT" => module.lambdas = parse_lambdas(body, atoms)?,
            "ImpT" => module.imports = parse_imports(body, atoms)?,
            "LitT" => module.literals = Some(parse_literals(body)),
            "LocT" => module.locals = parse_functions(body, atoms)?,
            "StrT" => {
                module.string_table_bytes = body.len();
                module.string_segments = string_segments(body);
            }
            _ => {}
        }
    }
    Ok(module)
}

fn parse_atoms(body: &[u8], utf8: bool) -> Result<Vec<String>, FathomError> {
    let count = be_u32(body, 0)
        .ok_or_else(|| beam_error("atom chunk ends inside its count".to_string()))?
        as usize;
    if count > BEAM_ATOMS_MAX {
        return Err(beam_error(format!(
            "atom count {count} exceeds the census bound"
        )));
    }
    let mut atoms = Vec::with_capacity(count);
    let mut pos = 4_usize;
    for _ in 0..count {
        let (len, width) = if utf8 {
            (
                be_u16(body, pos)
                    .ok_or_else(|| beam_error("atom chunk ends inside a length".to_string()))?
                    as usize,
                2,
            )
        } else {
            (
                *body
                    .get(pos)
                    .ok_or_else(|| beam_error("atom chunk ends inside a length".to_string()))?
                    as usize,
                1,
            )
        };
        pos += width;
        let raw = body
            .get(pos..pos + len)
            .ok_or_else(|| beam_error("atom chunk ends inside an atom".to_string()))?;
        atoms.push(String::from_utf8_lossy(raw).into_owned());
        pos += len;
    }
    Ok(atoms)
}

fn resolve_atom(atoms: &[String], index: u32) -> Option<String> {
    if index == 0 {
        return None;
    }
    atoms.get((index - 1) as usize).cloned()
}

fn parse_functions(body: &[u8], atoms: &[String]) -> Result<Vec<BeamFunction>, FathomError> {
    let count = be_u32(body, 0)
        .ok_or_else(|| beam_error("function table ends inside its count".to_string()))?
        as usize;
    if count > BEAM_FUNCTIONS_MAX {
        return Err(beam_error(format!(
            "function table count {count} exceeds the census bound"
        )));
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let base = 4 + index * 12;
        let atom_index = be_u32(body, base)
            .ok_or_else(|| beam_error("function table ends inside an entry".to_string()))?;
        rows.push(BeamFunction {
            arity: be_u32(body, base + 4).unwrap_or(0),
            atom_index,
            label: be_u32(body, base + 8).unwrap_or(0),
            name: resolve_atom(atoms, atom_index),
        });
    }
    Ok(rows)
}

fn parse_lambdas(body: &[u8], atoms: &[String]) -> Result<Vec<BeamFunction>, FathomError> {
    let count = be_u32(body, 0)
        .ok_or_else(|| beam_error("lambda table ends inside its count".to_string()))?
        as usize;
    if count > BEAM_FUNCTIONS_MAX {
        return Err(beam_error(format!(
            "lambda table count {count} exceeds the census bound"
        )));
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let base = 4 + index * 24;
        let atom_index = be_u32(body, base)
            .ok_or_else(|| beam_error("lambda table ends inside an entry".to_string()))?;
        rows.push(BeamFunction {
            arity: be_u32(body, base + 4).unwrap_or(0),
            atom_index,
            label: be_u32(body, base + 8).unwrap_or(0),
            name: resolve_atom(atoms, atom_index),
        });
    }
    Ok(rows)
}

fn parse_imports(body: &[u8], atoms: &[String]) -> Result<Vec<BeamImport>, FathomError> {
    let count = be_u32(body, 0)
        .ok_or_else(|| beam_error("import table ends inside its count".to_string()))?
        as usize;
    if count > BEAM_FUNCTIONS_MAX {
        return Err(beam_error(format!(
            "import table count {count} exceeds the census bound"
        )));
    }
    let mut rows = Vec::with_capacity(count);
    for index in 0..count {
        let base = 4 + index * 12;
        let module_atom = be_u32(body, base)
            .ok_or_else(|| beam_error("import table ends inside an entry".to_string()))?;
        let function_atom = be_u32(body, base + 4).unwrap_or(0);
        rows.push(BeamImport {
            arity: be_u32(body, base + 8).unwrap_or(0),
            function: resolve_atom(atoms, function_atom),
            function_atom,
            module: resolve_atom(atoms, module_atom),
            module_atom,
        });
    }
    Ok(rows)
}

fn parse_code_header(body: &[u8]) -> Result<BeamCodeHeader, FathomError> {
    if body.len() < 20 {
        return Err(beam_error(
            "Code chunk is smaller than its fixed header".to_string(),
        ));
    }
    Ok(BeamCodeHeader {
        function_count: be_u32(body, 16).unwrap_or(0),
        instruction_set: be_u32(body, 4).unwrap_or(0),
        label_count: be_u32(body, 12).unwrap_or(0),
        opcode_max: be_u32(body, 8).unwrap_or(0),
        opcode_bytes: body.len() - 20,
    })
}

fn string_segments(body: &[u8]) -> Vec<String> {
    let mut segments: Vec<String> = body
        .split(|byte| *byte == 0)
        .filter(|segment| segment.len() >= 2)
        .map(|segment| String::from_utf8_lossy(segment).into_owned())
        .collect();
    segments.truncate(STRT_SEGMENTS_MAX);
    segments
}

// ----------------------------------------------------------------
// Literal table: bounded external-term walk

fn parse_literals(body: &[u8]) -> BeamLiterals {
    let declared = be_u32(body, 0).unwrap_or(0) as usize;
    let compressed = &body[4.min(body.len())..];
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    let mut plain = Vec::new();
    let read = decoder
        .by_ref()
        .take(LITT_BYTES_MAX as u64)
        .read_to_end(&mut plain);
    match read {
        Ok(_) if plain.len() < LITT_BYTES_MAX => {
            let mut walk = TermWalk {
                atoms: Vec::new(),
                count: 0,
                partial: None,
            };
            if plain.first() == Some(&131) {
                let mut pos = 1_usize;
                let _ = walk_term(&plain, &mut pos, 0, &mut walk);
                if walk.partial.is_none() && pos != plain.len() {
                    walk.partial = Some(format!(
                        "{} trailing bytes after the literal terms",
                        plain.len() - pos
                    ));
                }
            } else {
                walk.partial =
                    Some("literal terms do not open with the ETF version byte 131".to_string());
            }
            BeamLiterals {
                atoms: walk.atoms,
                partial_reason: walk.partial,
                term_count: walk.count,
                uncompressed_len: plain.len(),
            }
        }
        _ => BeamLiterals {
            atoms: Vec::new(),
            partial_reason: Some(format!(
                "literal table declares {declared} uncompressed bytes; decompression \
                 failed or exceeded the bound"
            )),
            term_count: 0,
            uncompressed_len: 0,
        },
    }
}

struct TermWalk {
    atoms: Vec<String>,
    count: usize,
    partial: Option<String>,
}

impl TermWalk {
    fn fail(&mut self, reason: &str) {
        if self.partial.is_none() {
            self.partial = Some(reason.to_string());
        }
    }
}

fn term_bytes<'a>(bytes: &'a [u8], pos: &mut usize, count: usize) -> Option<&'a [u8]> {
    let slice = bytes.get(*pos..*pos + count)?;
    *pos += count;
    Some(slice)
}

fn term_u8(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    term_bytes(bytes, pos, 1).map(|raw| u32::from(raw[0]))
}

fn term_u16(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    term_bytes(bytes, pos, 2).map(|raw| u32::from_be_bytes([0, 0, raw[0], raw[1]]))
}

fn term_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    term_bytes(bytes, pos, 4).map(|raw| u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// Walk one external term at `pos`, counting it and censusing
/// its atoms. Returns false when the walk stopped early; the
/// reason is recorded on `walk`.
fn walk_term(bytes: &[u8], pos: &mut usize, depth: usize, walk: &mut TermWalk) -> bool {
    if depth > TERM_DEPTH_MAX {
        walk.fail("term nesting exceeds the depth bound");
        return false;
    }
    walk.count += 1;
    if walk.count > TERM_COUNT_MAX {
        walk.fail("term count exceeds the census bound");
        return false;
    }
    let Some(tag) = term_u8(bytes, pos) else {
        walk.fail("term stream ends inside a term");
        return false;
    };
    match tag {
        // SMALL_INTEGER_EXT, INTEGER_EXT.
        97 => term_bytes(bytes, pos, 1).is_some(),
        98 => term_bytes(bytes, pos, 4).is_some(),
        // FLOAT_EXT: 31-byte ASCII.
        99 => term_bytes(bytes, pos, 31).is_some(),
        // NEW_FLOAT_EXT.
        70 => term_bytes(bytes, pos, 8).is_some(),
        // ATOM_EXT / ATOM_UTF8_EXT / SMALL_ATOM(_UTF8)_EXT.
        100 | 118 => {
            let Some(len) = term_u16(bytes, pos) else {
                return false;
            };
            match term_bytes(bytes, pos, len as usize) {
                Some(raw) => {
                    if walk.atoms.len() < BEAM_ATOMS_MAX {
                        walk.atoms.push(String::from_utf8_lossy(raw).into_owned());
                    }
                    true
                }
                None => false,
            }
        }
        115 | 119 => {
            let Some(len) = term_u8(bytes, pos) else {
                return false;
            };
            match term_bytes(bytes, pos, len as usize) {
                Some(raw) => {
                    if walk.atoms.len() < BEAM_ATOMS_MAX {
                        walk.atoms.push(String::from_utf8_lossy(raw).into_owned());
                    }
                    true
                }
                None => false,
            }
        }
        // ATOM_CACHE_REF_EXT.
        82 => term_bytes(bytes, pos, 1).is_some(),
        // REFERENCE_EXT / PORT_EXT: node term, then a
        // 4-byte id and a 1-byte creation in both shapes.
        101 | 102 => walk_term(bytes, pos, depth + 1, walk) && term_bytes(bytes, pos, 5).is_some(),
        // PID_EXT: node term + id + serial + creation.
        103 => walk_term(bytes, pos, depth + 1, walk) && term_bytes(bytes, pos, 9).is_some(),
        // SMALL_TUPLE_EXT / LARGE_TUPLE_EXT.
        104 | 105 => {
            let arity = if tag == 104 {
                term_u8(bytes, pos)
            } else {
                term_u32(bytes, pos)
            };
            let Some(arity) = arity else { return false };
            for _ in 0..arity {
                if !walk_term(bytes, pos, depth + 1, walk) {
                    return false;
                }
            }
            true
        }
        // NIL_EXT.
        106 => true,
        // STRING_EXT.
        107 => {
            let Some(len) = term_u16(bytes, pos) else {
                return false;
            };
            term_bytes(bytes, pos, len as usize).is_some()
        }
        // LIST_EXT: length, elements, tail term.
        108 => {
            let Some(len) = term_u32(bytes, pos) else {
                return false;
            };
            for _ in 0..len {
                if !walk_term(bytes, pos, depth + 1, walk) {
                    return false;
                }
            }
            walk_term(bytes, pos, depth + 1, walk)
        }
        // BINARY_EXT.
        109 => {
            let Some(len) = term_u32(bytes, pos) else {
                return false;
            };
            term_bytes(bytes, pos, len as usize).is_some()
        }
        // BIT_BINARY_EXT.
        77 => {
            let Some(len) = term_u32(bytes, pos) else {
                return false;
            };
            term_bytes(bytes, pos, 1).is_some() && term_bytes(bytes, pos, len as usize).is_some()
        }
        // SMALL_BIG_EXT / LARGE_BIG_EXT.
        110 | 111 => {
            let size = if tag == 110 {
                term_u8(bytes, pos)
            } else {
                term_u32(bytes, pos)
            };
            let Some(size) = size else { return false };
            term_bytes(bytes, pos, 1).is_some() && term_bytes(bytes, pos, size as usize).is_some()
        }
        // EXPORT_EXT: module, function, arity terms.
        113 => {
            walk_term(bytes, pos, depth + 1, walk)
                && walk_term(bytes, pos, depth + 1, walk)
                && walk_term(bytes, pos, depth + 1, walk)
        }
        // NEW_REFERENCE_EXT.
        114 => {
            let Some(count) = term_u16(bytes, pos) else {
                return false;
            };
            walk_term(bytes, pos, depth + 1, walk)
                && term_bytes(bytes, pos, 4).is_some()
                && term_bytes(bytes, pos, count as usize * 4).is_some()
        }
        // MAP_EXT: arity, then key/value term pairs.
        116 => {
            let Some(arity) = term_u32(bytes, pos) else {
                return false;
            };
            for _ in 0..arity {
                if !walk_term(bytes, pos, depth + 1, walk)
                    || !walk_term(bytes, pos, depth + 1, walk)
                {
                    return false;
                }
            }
            true
        }
        // COMPRESSED: a u32 uncompressed size, then a zlib
        // stream (self-terminating) holding one more term.
        // The stream runs to the end of its enclosing buffer.
        80 => {
            if term_u32(bytes, pos).is_none() {
                return false;
            }
            let mut decoder = flate2::read::ZlibDecoder::new(&bytes[*pos..]);
            let mut plain = Vec::new();
            match decoder
                .by_ref()
                .take(LITT_BYTES_MAX as u64)
                .read_to_end(&mut plain)
            {
                Ok(_) => {
                    *pos = bytes.len();
                    let mut inner = 0_usize;
                    walk_term(&plain, &mut inner, depth + 1, walk)
                }
                Err(_) => {
                    walk.fail("compressed literal term does not decompress");
                    false
                }
            }
        }
        other => {
            walk.fail(&format!(
                "external term tag {other} is not walked by this reader"
            ));
            false
        }
    }
}

// ----------------------------------------------------------------
// Tool surface

fn function_rows(functions: &[BeamFunction]) -> Vec<Value> {
    functions
        .iter()
        .map(|function| {
            json!({
                "arity": function.arity,
                "atom_index": function.atom_index,
                "label": function.label,
                "name": function.name,
            })
        })
        .collect()
}

pub fn inspect_beam_module(
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
    let module = parse_beam(&bytes)?;
    let mut evidence = Evidence::new("inspect_beam_module", "beam");
    evidence.subject = Some(subject);
    // The module name is conventionally the first atom; it is
    // a derived fact, stated as such.
    let module_name = module.atoms.first().cloned();
    let chunk_rows: Vec<Value> = module
        .chunks
        .iter()
        .map(|chunk| json!({"name": chunk.name, "size": chunk.size}))
        .collect();
    evidence.add_finding(Finding::new(
        "beam",
        Confidence::Observed,
        json!({
            "atom_encoding": module.atom_encoding,
            "atoms": module.atoms.len(),
            "chunks": chunk_rows,
            "format": "BEAM",
            "form_size_mismatch": module.form_size_mismatch,
        }),
    ));
    if let Some(name) = &module_name {
        evidence.add_finding(
            Finding::new("module_name", Confidence::Derived, json!({"module": name}))
                .with_limitation(
                    "the module name is the atom table's first entry, by BEAM convention",
                ),
        );
    }
    evidence.add_finding(Finding::new(
        "atoms",
        Confidence::Observed,
        json!({"atoms": module.atoms, "count": module.atoms.len()}),
    ));
    if let Some(code) = &module.code {
        let table_functions = (module.exports.len() + module.locals.len()) as u32;
        evidence.add_finding(Finding::new(
            "code_header",
            Confidence::Observed,
            json!({
                "function_count": code.function_count,
                "function_count_matches_tables": code.function_count == table_functions,
                "instruction_set": code.instruction_set,
                "label_count": code.label_count,
                "opcode_bytes": code.opcode_bytes,
                "opcode_max": code.opcode_max,
                "table_function_count": table_functions,
            }),
        ));
    }
    evidence.add_finding(Finding::new(
        "exports",
        Confidence::Observed,
        json!({"count": module.exports.len(), "functions": function_rows(&module.exports)}),
    ));
    evidence.add_finding(Finding::new(
        "locals",
        Confidence::Observed,
        json!({"count": module.locals.len(), "functions": function_rows(&module.locals)}),
    ));
    if !module.lambdas.is_empty() {
        evidence.add_finding(Finding::new(
            "lambdas",
            Confidence::Observed,
            json!({"count": module.lambdas.len(), "functions": function_rows(&module.lambdas)}),
        ));
    }
    evidence.add_finding(Finding::new(
        "imports",
        Confidence::Observed,
        json!({
            "count": module.imports.len(),
            "imports": module.imports.iter().map(|import| json!({
                "arity": import.arity,
                "function": import.function,
                "function_atom": import.function_atom,
                "module": import.module,
                "module_atom": import.module_atom,
            })).collect::<Vec<_>>(),
        }),
    ));
    if let Some(literals) = &module.literals {
        let mut finding = Finding::new(
            "literals",
            Confidence::Observed,
            json!({
                "atoms": literals.atoms,
                "term_count": literals.term_count,
                "uncompressed_bytes": literals.uncompressed_len,
            }),
        );
        if let Some(reason) = &literals.partial_reason {
            finding = finding.with_limitation(format!("literal walk is partial: {reason}"));
        }
        evidence.add_finding(finding);
    }
    if module.string_table_bytes > 0 {
        evidence.add_finding(
            Finding::new(
                "string_table",
                Confidence::Observed,
                json!({
                    "bytes": module.string_table_bytes,
                    "segments": module.string_segments,
                }),
            )
            .with_limitation(
                "StrT is raw concatenated bytes referenced by offset from code; \
                 segments split on NUL are a census, not decoded string facts",
            ),
        );
    }
    let unresolved = module
        .exports
        .iter()
        .chain(module.locals.iter())
        .filter(|function| function.name.is_none())
        .count()
        + module
            .imports
            .iter()
            .filter(|import| import.module.is_none() || import.function.is_none())
            .count();
    if unresolved > 0 {
        evidence.add_unknown(
            "atom resolution",
            format!(
                "{unresolved} table rows carry atom indexes outside the atom \
                 table; their names are unknown, their indexes are in the rows"
            ),
        );
    }
    if module.form_size_mismatch {
        evidence.add_unknown(
            "form size",
            "the FOR1 size field disagrees with the file length; chunk framing \
             was followed as written, the size field was not believed",
        );
    }
    evidence.add_unknown(
        "instruction decode",
        "the Code chunk's opcode stream is inventoried by size, not decoded: \
         opcode tables are instruction-set-versioned and decoding against the \
         wrong table would fabricate facts — instruction decode is \
         NOT-IMPLEMENTED in this stage",
    );
    if module.chunks.iter().any(|chunk| chunk.name == "Dbgi") {
        evidence.add_unknown(
            "debug info",
            "a Dbgi chunk is present; its contents are inventoried by presence, \
             not decoded in this stage",
        );
    }
    evidence.coverage.examined = module.chunks.len() as u64;
    evidence.coverage.total = module.chunks.len() as u64;
    evidence.coverage.exhaustive = module.code.is_some();
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be32(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }

    /// Build a BEAM file by hand (independent construction
    /// from the parser): atoms, one export, one import, a
    /// code header, and a string table.
    fn build_beam() -> Vec<u8> {
        let mut atoms = Vec::new();
        atoms.extend_from_slice(&be32(4));
        for atom in ["demo_mod", "start", "helper", "lists"] {
            atoms.push(atom.len() as u8);
            atoms.extend_from_slice(atom.as_bytes());
        }
        let chunk = |name: &[u8; 4], body: &[u8]| -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(name);
            out.extend_from_slice(&be32(body.len() as u32));
            out.extend_from_slice(body);
            while out.len() % 4 != 0 {
                out.push(0);
            }
            out
        };
        let mut expt = Vec::new();
        expt.extend_from_slice(&be32(1));
        expt.extend_from_slice(&be32(2)); // function atom: start
        expt.extend_from_slice(&be32(2)); // arity 2
        expt.extend_from_slice(&be32(7)); // label
        let mut impt = Vec::new();
        impt.extend_from_slice(&be32(1));
        impt.extend_from_slice(&be32(4)); // module atom: lists
        impt.extend_from_slice(&be32(3)); // function atom: helper
        impt.extend_from_slice(&be32(1)); // arity 1
        let mut code = Vec::new();
        code.extend_from_slice(&be32(16)); // header size
        code.extend_from_slice(&be32(0)); // instruction set 0
        code.extend_from_slice(&be32(169)); // opcode max
        code.extend_from_slice(&be32(9)); // labels
        code.extend_from_slice(&be32(1)); // function count
        code.extend_from_slice(&[0x10, 0x20, 0x30]); // opcode bytes
        let mut file = Vec::new();
        file.extend_from_slice(b"FOR1");
        let mut form = Vec::new();
        form.extend_from_slice(b"BEAM");
        form.extend_from_slice(&chunk(b"Atom", &atoms));
        form.extend_from_slice(&chunk(b"ExpT", &expt));
        form.extend_from_slice(&chunk(b"ImpT", &impt));
        form.extend_from_slice(&chunk(b"Code", &code));
        form.extend_from_slice(&chunk(b"StrT", b"greeting\0world\0"));
        file.extend_from_slice(&be32(form.len() as u32));
        file.extend_from_slice(&form);
        file
    }

    #[test]
    fn validation_handbuilt_beam_parses() {
        let bytes = build_beam();
        let module = parse_beam(&bytes).expect("beam parses");
        assert!(!module.form_size_mismatch);
        assert_eq!(module.atom_encoding, Some("Atom"));
        assert_eq!(module.atoms, ["demo_mod", "start", "helper", "lists"]);
        assert_eq!(module.exports.len(), 1);
        assert_eq!(module.exports[0].name.as_deref(), Some("start"));
        assert_eq!(module.exports[0].arity, 2);
        assert_eq!(module.imports.len(), 1);
        assert_eq!(module.imports[0].module.as_deref(), Some("lists"));
        assert_eq!(module.imports[0].function.as_deref(), Some("helper"));
        let code = module.code.expect("code header");
        assert_eq!(code.function_count, 1);
        assert_eq!(code.opcode_max, 169);
        assert_eq!(code.opcode_bytes, 3);
        assert!(module.string_segments.contains(&"greeting".to_string()));
    }

    #[test]
    fn validation_litt_with_real_etf_terms() {
        // ETF: version 131, a list of two atoms (compressed
        // term table shape): list header + atom terms + nil.
        let mut etf = vec![131, 108, 0, 0, 0, 2];
        etf.extend_from_slice(&[100, 0, 3]);
        etf.extend_from_slice(b"foo");
        etf.extend_from_slice(&[100, 0, 3]);
        etf.extend_from_slice(b"bar");
        etf.push(106);
        let mut body = Vec::new();
        body.extend_from_slice(&be32(etf.len() as u32));
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        use std::io::Write as _;
        encoder.write_all(&etf).expect("encode");
        let compressed = encoder.finish().expect("finish");
        body.extend_from_slice(&compressed);
        let literals = parse_literals(&body);
        assert_eq!(literals.term_count, 4, "list + two atoms + nil tail");
        assert_eq!(literals.atoms, ["foo", "bar"]);
        assert!(
            literals.partial_reason.is_none(),
            "{:?}",
            literals.partial_reason
        );
    }

    #[test]
    fn adversarial_missing_form_header_refused() {
        assert!(parse_beam(b"NOPE........").is_err());
        assert!(parse_beam(b"FOR1\0\0\0\0XXXX").is_err());
    }

    #[test]
    fn adversarial_chunk_size_overrun_refused() {
        let mut bytes = build_beam();
        // Corrupt the first chunk's size to run past EOF.
        bytes[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_beam(&bytes).is_err());
    }

    #[test]
    fn adversarial_unresolved_atom_index_is_kept_not_dropped() {
        let mut bytes = build_beam();
        // Export's function atom index: form+Atom header is
        // long; find the ExpT chunk and rewrite its index to
        // an out-of-range atom (99).
        let needle = b"ExpT";
        let at = bytes
            .windows(4)
            .position(|window| window == needle)
            .expect("ExpT present");
        let entry = at + 8 + 4; // chunk header + table count
        bytes[entry..entry + 4].copy_from_slice(&99_u32.to_be_bytes());
        let module = parse_beam(&bytes).expect("beam parses");
        assert_eq!(module.exports.len(), 1);
        assert_eq!(module.exports[0].name, None);
        assert_eq!(module.exports[0].atom_index, 99);
    }

    #[test]
    fn adversarial_truncated_atom_chunk_errors() {
        let mut bytes = build_beam();
        bytes.truncate(30); // inside the Atom chunk
        assert!(parse_beam(&bytes).is_err());
    }
}

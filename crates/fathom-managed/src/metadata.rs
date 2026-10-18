//! .NET metadata, parsed manually per ECMA-335 (SPEC §9.3).
//!
//! Path: goblin PE -> CLI header (data directory 14) -> metadata
//! root (`BSJB`) -> streams (`#~`, `#Strings`, `#Blob`, `#GUID`)
//! -> table row geometry -> TypeDef / MethodDef / Field /
//! ImplMap / Assembly inventories. Every read is bounds-checked;
//! malformed metadata is `unsupported_target`, never a panic.
//! CIL method bodies are NOT decoded: method facts are
//! metadata-level (name, RVA, signature digest) and the handler
//! says so in its unknowns.

use serde::Serialize;
use std::collections::BTreeMap;

use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::sha256_hex;

// Table identifiers (ECMA-335 II.22).
mod table {
    pub const ASSEMBLY: usize = 32;
    pub const ASSEMBLY_REF: usize = 35;
    pub const FIELD: usize = 4;
    pub const IMPL_MAP: usize = 28;
    pub const METHOD_DEF: usize = 6;
    pub const MODULE: usize = 0;
    pub const MODULE_REF: usize = 26;
    pub const PARAM: usize = 8;
    pub const TYPE_DEF: usize = 2;
    pub const TYPE_REF: usize = 1;
}

/// One coded-index family: member tables in tag order, tag bits.
#[derive(Clone, Copy, PartialEq)]
struct Coded {
    tables: &'static [usize],
    tag_bits: u32,
}

const CODED_CUSTOM_ATTRIBUTE_TYPE: Coded = Coded {
    tables: &[6, 10],
    tag_bits: 3,
};
const CODED_HAS_CONSTANT: Coded = Coded {
    tables: &[4, 8, 23],
    tag_bits: 2,
};
const CODED_HAS_CUSTOM_ATTRIBUTE: Coded = Coded {
    tables: &[
        6, 4, 1, 2, 8, 10, 0, 14, 23, 20, 17, 26, 27, 32, 38, 39, 35, 42, 43, 44,
    ],
    tag_bits: 5,
};
const CODED_HAS_DECL_SECURITY: Coded = Coded {
    tables: &[2, 6, 32],
    tag_bits: 2,
};
const CODED_HAS_FIELD_MARSHAL: Coded = Coded {
    tables: &[4, 8],
    tag_bits: 1,
};
const CODED_HAS_SEMANTICS: Coded = Coded {
    tables: &[20, 23],
    tag_bits: 1,
};
const CODED_IMPLEMENTATION: Coded = Coded {
    tables: &[38, 35, 39],
    tag_bits: 2,
};
const CODED_MEMBER_FORWARDED: Coded = Coded {
    tables: &[4, 6],
    tag_bits: 1,
};
const CODED_MEMBER_REF_PARENT: Coded = Coded {
    tables: &[2, 1, 26, 6, 27],
    tag_bits: 3,
};
const CODED_METHOD_DEF_OR_REF: Coded = Coded {
    tables: &[6, 10],
    tag_bits: 1,
};
const CODED_RESOLUTION_SCOPE: Coded = Coded {
    tables: &[0, 26, 35, 1],
    tag_bits: 2,
};
const CODED_TYPE_DEF_OR_REF: Coded = Coded {
    tables: &[2, 1, 27],
    tag_bits: 2,
};
const CODED_TYPE_OR_METHOD_DEF: Coded = Coded {
    tables: &[2, 6],
    tag_bits: 1,
};

#[derive(Clone, Copy, PartialEq)]
enum Col {
    Blob,
    Coded(&'static Coded),
    Guid,
    Simple(usize),
    Str,
    U16,
    U32,
    U8,
}

/// Column schemas in ECMA-335 II.22 order, for every table whose
/// rows this parser may need to step over or read.
fn columns(table_id: usize) -> &'static [Col] {
    use Col::*;
    match table_id {
        0 => &[U16, Str, Guid, Guid, Guid],
        1 => &[Coded(&CODED_RESOLUTION_SCOPE), Str, Str],
        2 => &[
            U32,
            Str,
            Str,
            Coded(&CODED_TYPE_DEF_OR_REF),
            Simple(4),
            Simple(6),
        ],
        3 => &[Simple(4)],
        4 => &[U16, Str, Blob],
        5 => &[Simple(6)],
        6 => &[U32, U16, U16, Str, Blob, Simple(8)],
        7 => &[Simple(8)],
        8 => &[U16, U16, Str],
        9 => &[Simple(2), Coded(&CODED_TYPE_DEF_OR_REF)],
        10 => &[Coded(&CODED_MEMBER_REF_PARENT), Str, Blob],
        11 => &[U8, U8, Coded(&CODED_HAS_CONSTANT), Blob],
        12 => &[
            Coded(&CODED_HAS_CUSTOM_ATTRIBUTE),
            Coded(&CODED_CUSTOM_ATTRIBUTE_TYPE),
            Blob,
        ],
        13 => &[Coded(&CODED_HAS_FIELD_MARSHAL), Blob],
        14 => &[U16, Coded(&CODED_HAS_DECL_SECURITY), Blob],
        15 => &[U16, U32, Simple(2)],
        16 => &[U32, Simple(4)],
        17 => &[Blob],
        18 => &[Simple(2), Simple(20)],
        19 => &[Simple(20)],
        20 => &[U16, Str, Coded(&CODED_TYPE_DEF_OR_REF)],
        21 => &[Simple(2), Simple(23)],
        22 => &[Simple(23)],
        23 => &[U16, Str, Blob],
        24 => &[U16, Simple(6), Coded(&CODED_HAS_SEMANTICS)],
        25 => &[
            Simple(2),
            Coded(&CODED_METHOD_DEF_OR_REF),
            Coded(&CODED_METHOD_DEF_OR_REF),
        ],
        26 => &[Str],
        27 => &[Blob],
        28 => &[U16, Coded(&CODED_MEMBER_FORWARDED), Str, Simple(26)],
        29 => &[U32, Simple(4)],
        30 => &[U32, U32],
        31 => &[U32],
        32 => &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],
        33 => &[U32],
        34 => &[U32, U32, U32],
        35 => &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],
        36 => &[U32, Simple(35)],
        37 => &[U32, U32, U32, Simple(35)],
        38 => &[U32, Str, Blob],
        39 => &[U32, U32, Str, Str, Coded(&CODED_IMPLEMENTATION)],
        40 => &[U32, U32, Str, Coded(&CODED_IMPLEMENTATION)],
        41 => &[Simple(2), Simple(2)],
        42 => &[U16, U16, Coded(&CODED_TYPE_OR_METHOD_DEF), Str],
        43 => &[Coded(&CODED_METHOD_DEF_OR_REF), Blob],
        44 => &[Simple(42), Coded(&CODED_TYPE_DEF_OR_REF)],
        _ => &[],
    }
}

#[derive(Debug, Serialize)]
pub struct AssemblyInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct MethodInfo {
    pub flags: u16,
    pub impl_flags: u16,
    pub name: String,
    pub owner: String,
    pub param_count: usize,
    pub rva: u32,
    pub signature_bytes: usize,
    pub signature_sha256: String,
}

#[derive(Debug, Serialize)]
pub struct PInvokeInfo {
    pub import_name: String,
    pub method: String,
    pub module: String,
}

#[derive(Debug, Serialize)]
pub struct TypeInfo {
    pub extends: Option<String>,
    pub fields: Vec<String>,
    pub flags: u32,
    pub methods: Vec<String>,
    pub name: String,
    pub namespace: String,
}

#[derive(Debug, Serialize)]
pub struct ManagedInventory {
    pub assembly: Option<AssemblyInfo>,
    pub assembly_refs: Vec<String>,
    pub methods: Vec<MethodInfo>,
    pub module_name: Option<String>,
    pub pinvokes: Vec<PInvokeInfo>,
    pub runtime_version: String,
    pub table_rows: BTreeMap<String, u32>,
    pub type_refs: Vec<String>,
    pub types: Vec<TypeInfo>,
    pub user_strings: Vec<String>,
    pub user_strings_truncated: bool,
}

struct Heaps<'a> {
    blob: &'a [u8],
    strings: &'a [u8],
    user_strings: &'a [u8],
}

struct Tables<'a> {
    blob_size: usize,
    guid_size: usize,
    rows: [u32; 64],
    starts: [usize; 64],
    str_size: usize,
    bytes: &'a [u8],
}

impl Tables<'_> {
    fn simple_size(&self, table_id: usize) -> usize {
        if self.rows[table_id] < 65_536 { 2 } else { 4 }
    }

    fn coded_size(&self, coded: &Coded) -> usize {
        let max_rows = coded
            .tables
            .iter()
            .map(|t| self.rows[*t])
            .max()
            .unwrap_or(0);
        if max_rows < (1_u32 << (16 - coded.tag_bits)) {
            2
        } else {
            4
        }
    }

    fn col_size(&self, col: &Col) -> usize {
        match col {
            Col::Blob => self.blob_size,
            Col::Coded(coded) => self.coded_size(coded),
            Col::Guid => self.guid_size,
            Col::Simple(table_id) => self.simple_size(*table_id),
            Col::Str => self.str_size,
            Col::U16 => 2,
            Col::U32 => 4,
            Col::U8 => 1,
        }
    }

    fn row_size(&self, table_id: usize) -> usize {
        columns(table_id).iter().map(|col| self.col_size(col)).sum()
    }

    /// All column values of one row (indexes unresolved), in
    /// schema order. `row` is 0-based.
    fn row_values(&self, table_id: usize, row: usize) -> Result<Vec<u64>, FathomError> {
        let start = self.starts[table_id] + row * self.row_size(table_id);
        let mut values = Vec::new();
        let mut pos = start;
        for col in columns(table_id) {
            let size = self.col_size(col);
            values.push(read_uint(self.bytes, pos, size)?);
            pos += size;
        }
        Ok(values)
    }
}

fn malformed(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message.into())
}

fn read_uint(bytes: &[u8], pos: usize, size: usize) -> Result<u64, FathomError> {
    let slice = bytes
        .get(pos..pos + size)
        .ok_or_else(|| malformed("metadata read overruns the stream"))?;
    let mut value = 0_u64;
    for (index, byte) in slice.iter().enumerate() {
        value |= (*byte as u64) << (8 * index);
    }
    Ok(value)
}

fn read_u32_at(bytes: &[u8], pos: usize) -> Result<u32, FathomError> {
    Ok(read_uint(bytes, pos, 4)? as u32)
}

/// Decode a compressed unsigned integer (ECMA-335 II.23.2).
fn read_compressed(bytes: &[u8], pos: usize) -> Result<(u32, usize), FathomError> {
    let first = *bytes
        .get(pos)
        .ok_or_else(|| malformed("compressed integer overruns the heap"))?;
    if first & 0x80 == 0 {
        Ok((first as u32, 1))
    } else if first & 0xC0 == 0x80 {
        let second = *bytes
            .get(pos + 1)
            .ok_or_else(|| malformed("compressed integer overruns the heap"))?;
        Ok((((first & 0x3F) as u32) << 8 | second as u32, 2))
    } else if first & 0xE0 == 0xC0 {
        let mut value = (first & 0x1F) as u32;
        for i in 1..4 {
            let byte = *bytes
                .get(pos + i)
                .ok_or_else(|| malformed("compressed integer overruns the heap"))?;
            value = (value << 8) | byte as u32;
        }
        Ok((value, 4))
    } else {
        Err(malformed("invalid compressed integer lead byte"))
    }
}

fn heap_string(heaps: &Heaps, index: u64) -> String {
    let start = index as usize;
    if start == 0 || start >= heaps.strings.len() {
        return String::new();
    }
    let slice = &heaps.strings[start..];
    let end = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

fn heap_blob<'a>(heaps: &Heaps<'a>, index: u64) -> Result<&'a [u8], FathomError> {
    let start = index as usize;
    if start >= heaps.blob.len() {
        return Ok(&[]);
    }
    let (length, consumed) = read_compressed(heaps.blob, start)?;
    let begin = start + consumed;
    let end = begin + length as usize;
    heaps
        .blob
        .get(begin..end)
        .ok_or_else(|| malformed("blob overruns the heap"))
}

const USER_STRING_CHARS_MAX: usize = 512;
const USER_STRING_MAX: usize = 4096;

/// Decode the #US (user strings) heap (ECMA-335 II.24.2.4): a
/// reserved zero byte, then entries of a compressed length, that
/// many bytes of UTF-16LE character data, and one terminal flag
/// byte. These are the string literals `ldstr` loads — the
/// managed counterpart of a native binary's string table, and
/// the place user-facing markers live. Returns the strings and
/// whether the entry cap cut the heap short.
fn parse_user_strings(heap: &[u8]) -> Result<(Vec<String>, bool), FathomError> {
    let mut strings = Vec::new();
    let mut pos = 1_usize;
    while pos < heap.len() {
        if strings.len() >= USER_STRING_MAX {
            return Ok((strings, true));
        }
        let (byte_len, consumed) = read_compressed(heap, pos)?;
        let payload_start = pos + consumed;
        let payload_end = payload_start + byte_len as usize;
        let payload = heap
            .get(payload_start..payload_end)
            .ok_or_else(|| malformed("user string overruns the #US heap"))?;
        // The final payload byte is a terminal flag, not a char.
        let char_bytes = &payload[..payload.len().saturating_sub(1)];
        let units: Vec<u16> = char_bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let text: String = String::from_utf16_lossy(&units)
            .chars()
            .take(USER_STRING_CHARS_MAX)
            .collect();
        if !text.is_empty() {
            strings.push(text);
        }
        pos = payload_end;
    }
    Ok((strings, false))
}

/// Parse a whole PE file. `Ok(None)` = a PE with no CLI header
/// (native). Errors = not a PE, or managed metadata is malformed.
pub fn parse_pe(bytes: &[u8]) -> Result<Option<ManagedInventory>, FathomError> {
    let object = goblin::Object::parse(bytes)
        .map_err(|e| malformed(format!("not a parseable object file: {e}")))?;
    let goblin::Object::PE(pe) = object else {
        return Err(malformed("not a PE file"));
    };
    let optional = pe
        .header
        .optional_header
        .ok_or_else(|| malformed("PE has no optional header"))?;
    let Some(cli) = optional.data_directories.get_clr_runtime_header() else {
        return Ok(None);
    };
    let sections = &pe.sections;
    let cli_offset = rva_to_offset(sections, cli.virtual_address)
        .ok_or_else(|| malformed("CLI header RVA is outside every section"))?;
    let metadata_rva = read_u32_at(bytes, cli_offset + 8)?;
    let root_offset = rva_to_offset(sections, metadata_rva)
        .ok_or_else(|| malformed("metadata RVA is outside every section"))?;
    parse_metadata_root(bytes, root_offset)
}

fn rva_to_offset(sections: &[goblin::pe::section_table::SectionTable], rva: u32) -> Option<usize> {
    for section in sections {
        let span = section.virtual_size.max(section.size_of_raw_data);
        if rva >= section.virtual_address && rva < section.virtual_address + span {
            return Some((section.pointer_to_raw_data + (rva - section.virtual_address)) as usize);
        }
    }
    None
}

fn parse_metadata_root(bytes: &[u8], root: usize) -> Result<Option<ManagedInventory>, FathomError> {
    if read_u32_at(bytes, root)? != 0x424A_5342 {
        return Err(malformed("metadata root signature is not BSJB"));
    }
    let version_len = read_u32_at(bytes, root + 12)? as usize;
    let version_bytes = bytes
        .get(root + 16..root + 16 + version_len)
        .ok_or_else(|| malformed("runtime version string overruns the file"))?;
    let runtime_version = String::from_utf8_lossy(version_bytes)
        .trim_end_matches('\0')
        .to_string();
    let mut pos = root + 16 + version_len.div_ceil(4) * 4;
    let stream_count = read_uint(bytes, pos + 2, 2)? as usize;
    pos += 4;
    let mut streams: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for _ in 0..stream_count {
        let offset = read_u32_at(bytes, pos)? as usize;
        let size = read_u32_at(bytes, pos + 4)? as usize;
        let name_start = pos + 8;
        let mut name_end = name_start;
        while bytes.get(name_end).copied().unwrap_or(0) != 0 {
            name_end += 1;
            if name_end - name_start > 64 {
                return Err(malformed("stream name is unreasonably long"));
            }
        }
        let name = String::from_utf8_lossy(&bytes[name_start..name_end]).into_owned();
        let name_field = (name_end - name_start + 1).div_ceil(4) * 4;
        streams.insert(name, (root + offset, size));
        pos = name_start + name_field;
    }
    let stream = |name: &str| -> Result<&[u8], FathomError> {
        let (offset, size) = streams
            .get(name)
            .ok_or_else(|| malformed(format!("metadata stream {name} is missing")))?;
        bytes
            .get(*offset..offset + size)
            .ok_or_else(|| malformed(format!("metadata stream {name} overruns the file")))
    };
    let tables_bytes = stream("#~").or_else(|_| stream("#-"))?;
    let heaps = Heaps {
        blob: stream("#Blob")?,
        strings: stream("#Strings")?,
        // #US is optional in principle; its absence means no
        // user strings, not malformed metadata.
        user_strings: stream("#US").unwrap_or(&[]),
    };
    let tables = parse_tables_header(tables_bytes)?;
    extract_inventory(&tables, &heaps, runtime_version).map(Some)
}

fn parse_tables_header(bytes: &[u8]) -> Result<Tables<'_>, FathomError> {
    let heap_sizes = *bytes
        .get(6)
        .ok_or_else(|| malformed("tables stream header is truncated"))?;
    let valid = read_uint(bytes, 8, 8)?;
    let mut rows = [0_u32; 64];
    let mut pos = 24;
    for (table_id, row) in rows.iter_mut().enumerate() {
        if valid & (1_u64 << table_id) != 0 {
            *row = read_u32_at(bytes, pos)?;
            pos += 4;
        }
    }
    let mut tables = Tables {
        blob_size: if heap_sizes & 0x04 != 0 { 4 } else { 2 },
        guid_size: if heap_sizes & 0x02 != 0 { 4 } else { 2 },
        rows,
        starts: [0; 64],
        str_size: if heap_sizes & 0x01 != 0 { 4 } else { 2 },
        bytes,
    };
    let mut cursor = pos;
    for table_id in 0..64 {
        if rows[table_id] > 0 {
            tables.starts[table_id] = cursor;
            cursor += tables.row_size(table_id) * rows[table_id] as usize;
        }
    }
    if cursor > bytes.len() {
        return Err(malformed("table rows overrun the tables stream"));
    }
    Ok(tables)
}

fn coded_target(coded: &Coded, value: u64) -> (usize, usize) {
    let mask = (1_u64 << coded.tag_bits) - 1;
    let tag = (value & mask) as usize;
    let row = (value >> coded.tag_bits) as usize;
    let table_id = coded.tables.get(tag).copied().unwrap_or(usize::MAX);
    (table_id, row)
}

/// Name of a TypeDef/TypeRef row (1-based) for `extends` facts.
fn type_name(tables: &Tables, heaps: &Heaps, table_id: usize, row: usize) -> Option<String> {
    if row == 0 || row > tables.rows[table_id] as usize {
        return None;
    }
    let values = tables.row_values(table_id, row - 1).ok()?;
    match table_id {
        table::TYPE_DEF | table::TYPE_REF => {
            let name = heap_string(heaps, values[1]);
            let namespace = heap_string(heaps, values[2]);
            Some(if namespace.is_empty() {
                name
            } else {
                format!("{namespace}.{name}")
            })
        }
        _ => None,
    }
}

fn extract_inventory(
    tables: &Tables,
    heaps: &Heaps,
    runtime_version: String,
) -> Result<ManagedInventory, FathomError> {
    // MethodDef rows are needed by owner resolution and ImplMap.
    let mut method_names: BTreeMap<usize, String> = BTreeMap::new();
    let mut method_rows: Vec<Vec<u64>> = Vec::new();
    for row in 0..tables.rows[table::METHOD_DEF] as usize {
        let values = tables.row_values(table::METHOD_DEF, row)?;
        method_names.insert(row + 1, heap_string(heaps, values[3]));
        method_rows.push(values);
    }
    let field_names: BTreeMap<usize, String> = (0..tables.rows[table::FIELD] as usize)
        .map(|row| {
            let values = tables.row_values(table::FIELD, row)?;
            Ok((row + 1, heap_string(heaps, values[1])))
        })
        .collect::<Result<_, FathomError>>()?;

    let mut types = Vec::new();
    let type_count = tables.rows[table::TYPE_DEF] as usize;
    for row in 0..type_count {
        let values = tables.row_values(table::TYPE_DEF, row)?;
        let (extends_table, extends_row) = coded_target(&CODED_TYPE_DEF_OR_REF, values[3]);
        let field_begin = values[4] as usize;
        let field_end = if row + 1 < type_count {
            tables.row_values(table::TYPE_DEF, row + 1)?[4] as usize
        } else {
            tables.rows[table::FIELD] as usize + 1
        };
        let method_begin = values[5] as usize;
        let method_end = if row + 1 < type_count {
            tables.row_values(table::TYPE_DEF, row + 1)?[5] as usize
        } else {
            tables.rows[table::METHOD_DEF] as usize + 1
        };
        let fields = (field_begin..field_end)
            .filter_map(|index| field_names.get(&index).cloned())
            .collect();
        let methods = (method_begin..method_end)
            .filter_map(|index| method_names.get(&index).cloned())
            .collect();
        types.push(TypeInfo {
            extends: type_name(tables, heaps, extends_table, extends_row),
            fields,
            flags: values[0] as u32,
            methods,
            name: heap_string(heaps, values[1]),
            namespace: heap_string(heaps, values[2]),
        });
    }

    // Owners: type -> 1-based method range.
    let mut owner_of: BTreeMap<usize, String> = BTreeMap::new();
    for (index, type_info) in types.iter().enumerate() {
        let values = tables.row_values(table::TYPE_DEF, index)?;
        let begin = values[5] as usize;
        let end = if index + 1 < type_count {
            tables.row_values(table::TYPE_DEF, index + 1)?[5] as usize
        } else {
            tables.rows[table::METHOD_DEF] as usize + 1
        };
        let qualified = if type_info.namespace.is_empty() {
            type_info.name.clone()
        } else {
            format!("{}.{}", type_info.namespace, type_info.name)
        };
        for method_index in begin..end {
            owner_of.insert(method_index, qualified.clone());
        }
    }

    let mut methods = Vec::new();
    for (index, values) in method_rows.iter().enumerate() {
        let signature = heap_blob(heaps, values[4])?;
        let param_count = {
            let begin = values[5] as usize;
            let end = if index + 1 < method_rows.len() {
                method_rows[index + 1][5] as usize
            } else {
                tables.rows[table::PARAM] as usize + 1
            };
            end.saturating_sub(begin)
        };
        methods.push(MethodInfo {
            flags: values[2] as u16,
            impl_flags: values[1] as u16,
            name: heap_string(heaps, values[3]),
            owner: owner_of
                .get(&(index + 1))
                .cloned()
                .unwrap_or_else(|| "<global>".to_string()),
            param_count,
            rva: values[0] as u32,
            signature_bytes: signature.len(),
            signature_sha256: sha256_hex(signature),
        });
    }

    let mut pinvokes = Vec::new();
    for row in 0..tables.rows[table::IMPL_MAP] as usize {
        let values = tables.row_values(table::IMPL_MAP, row)?;
        let (member_table, member_row) = coded_target(&CODED_MEMBER_FORWARDED, values[1]);
        let method = if member_table == table::METHOD_DEF {
            method_names.get(&member_row).cloned().unwrap_or_default()
        } else {
            String::new()
        };
        let module_row = values[3] as usize;
        let module = if module_row >= 1 && module_row <= tables.rows[table::MODULE_REF] as usize {
            let module_values = tables.row_values(table::MODULE_REF, module_row - 1)?;
            heap_string(heaps, module_values[0])
        } else {
            String::new()
        };
        pinvokes.push(PInvokeInfo {
            import_name: heap_string(heaps, values[2]),
            method,
            module,
        });
    }

    let assembly = if tables.rows[table::ASSEMBLY] > 0 {
        let values = tables.row_values(table::ASSEMBLY, 0)?;
        Some(AssemblyInfo {
            name: heap_string(heaps, values[7]),
            version: format!("{}.{}.{}.{}", values[1], values[2], values[3], values[4]),
        })
    } else {
        None
    };
    let assembly_refs = (0..tables.rows[table::ASSEMBLY_REF] as usize)
        .map(|row| {
            let values = tables.row_values(table::ASSEMBLY_REF, row)?;
            Ok(heap_string(heaps, values[6]))
        })
        .collect::<Result<Vec<_>, FathomError>>()?;
    let type_refs = (0..tables.rows[table::TYPE_REF] as usize)
        .map(|row| {
            let values = tables.row_values(table::TYPE_REF, row)?;
            let name = heap_string(heaps, values[1]);
            let namespace = heap_string(heaps, values[2]);
            Ok(if namespace.is_empty() {
                name
            } else {
                format!("{namespace}.{name}")
            })
        })
        .collect::<Result<Vec<_>, FathomError>>()?;
    let module_name = if tables.rows[table::MODULE] > 0 {
        let values = tables.row_values(table::MODULE, 0)?;
        Some(heap_string(heaps, values[1]))
    } else {
        None
    };
    let mut table_rows = BTreeMap::new();
    for (table_id, &row_count) in tables.rows.iter().enumerate() {
        if row_count > 0 {
            table_rows.insert(format!("table_{table_id}"), row_count);
        }
    }
    let (user_strings, user_strings_truncated) = parse_user_strings(heaps.user_strings)?;
    Ok(ManagedInventory {
        assembly,
        assembly_refs,
        methods,
        module_name,
        pinvokes,
        runtime_version,
        table_rows,
        type_refs,
        types,
        user_strings,
        user_strings_truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_bad_signature_rejected() {
        let bytes = vec![0_u8; 256];
        assert!(parse_metadata_root(&bytes, 0).is_err());
    }

    #[test]
    fn adversarial_compressed_integer_edges() {
        assert_eq!(read_compressed(&[0x7f], 0).unwrap(), (127, 1));
        assert_eq!(read_compressed(&[0x80, 0x00], 0).unwrap(), (0, 2));
        assert!(read_compressed(&[0xe0], 0).is_err());
        assert!(read_compressed(&[], 0).is_err());
    }

    #[test]
    fn validation_coded_index_geometry() {
        // TypeDefOrRef threshold: 2^(16-2) = 16384 rows.
        let mut tables = Tables {
            blob_size: 2,
            guid_size: 2,
            rows: [0; 64],
            starts: [0; 64],
            str_size: 2,
            bytes: &[],
        };
        assert_eq!(tables.coded_size(&CODED_TYPE_DEF_OR_REF), 2);
        tables.rows[table::TYPE_DEF] = 20_000;
        assert_eq!(tables.coded_size(&CODED_TYPE_DEF_OR_REF), 4);
        let (table_id, row) = coded_target(&CODED_TYPE_DEF_OR_REF, 0b101);
        assert_eq!((table_id, row), (1, 1));
    }

    #[test]
    fn validation_minimal_tables_stream() {
        // Hand-built metadata root: one TypeDef row, one Field
        // row, one MethodDef row; strings heap carries the names.
        let strings: &[u8] = b"\0Widget\0System\0Object\0count\0Run\0";
        // Offsets: Widget=1, System=8, Object=15, count=22, Run=28.
        let mut tables_stream = Vec::new();
        tables_stream.extend_from_slice(&[0; 4]); // reserved
        tables_stream.extend_from_slice(&[2, 0]); // major, minor
        tables_stream.push(0); // heap sizes: 2-byte indexes
        tables_stream.push(0); // reserved
        let valid: u64 = (1 << 2) | (1 << 4) | (1 << 6);
        tables_stream.extend_from_slice(&valid.to_le_bytes());
        tables_stream.extend_from_slice(&[0; 8]); // sorted
        tables_stream.extend_from_slice(&1_u32.to_le_bytes()); // TypeDef rows
        tables_stream.extend_from_slice(&1_u32.to_le_bytes()); // Field rows
        tables_stream.extend_from_slice(&1_u32.to_le_bytes()); // MethodDef rows
        // TypeDef row: Flags u32, Name str, Namespace str,
        // Extends coded (TypeRef tag 1, row 0 => 1), FieldList=1,
        // MethodList=1.
        tables_stream.extend_from_slice(&0_u32.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        tables_stream.extend_from_slice(&8_u16.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        // Field row: Flags u16, Name str, Signature blob (empty=0).
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&22_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        // MethodDef row: RVA u32, Impl u16, Flags u16, Name str,
        // Signature blob (0), ParamList=1.
        tables_stream.extend_from_slice(&0x2000_u32.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&28_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());

        let tables = parse_tables_header(&tables_stream).unwrap();
        let heaps = Heaps {
            blob: &[0],
            strings,
            user_strings: &[],
        };
        let inventory = extract_inventory(&tables, &heaps, "v4.0.30319".to_string()).unwrap();
        assert_eq!(inventory.types.len(), 1);
        assert_eq!(inventory.types[0].name, "Widget");
        assert_eq!(inventory.types[0].namespace, "System");
        assert_eq!(inventory.types[0].fields, vec!["count".to_string()]);
        assert_eq!(inventory.types[0].methods, vec!["Run".to_string()]);
        assert_eq!(inventory.methods.len(), 1);
        assert_eq!(inventory.methods[0].owner, "System.Widget");
        assert_eq!(inventory.methods[0].rva, 0x2000);
    }

    /// Build one #US heap: reserved zero byte + entries.
    fn us_heap(entries: &[&str]) -> Vec<u8> {
        let mut heap = vec![0_u8];
        for entry in entries {
            let mut payload = Vec::new();
            for unit in entry.encode_utf16() {
                payload.extend_from_slice(&unit.to_le_bytes());
            }
            payload.push(0); // terminal flag byte
            assert!(payload.len() < 0x80);
            heap.push(payload.len() as u8);
            heap.extend_from_slice(&payload);
        }
        heap
    }

    #[test]
    fn validation_user_strings_decode() {
        let heap = us_heap(&["Hello", "FATHOM-CORPUS-MARKER-csharp-7f3a"]);
        let (strings, truncated) = parse_user_strings(&heap).unwrap();
        assert_eq!(
            strings,
            vec![
                "Hello".to_string(),
                "FATHOM-CORPUS-MARKER-csharp-7f3a".to_string()
            ]
        );
        assert!(!truncated);
    }

    #[test]
    fn adversarial_user_strings_overrun_rejected() {
        // Length prefix claims 127 payload bytes; one is present.
        let heap = vec![0_u8, 0x7f, b'A'];
        assert!(parse_user_strings(&heap).is_err());
    }

    #[test]
    fn adversarial_user_strings_cap_is_reported() {
        let mut heap = vec![0_u8];
        for _ in 0..(USER_STRING_MAX + 3) {
            heap.extend_from_slice(&[3, b'x', 0, 0]); // len 3: 'x' + terminal
        }
        let (strings, truncated) = parse_user_strings(&heap).unwrap();
        assert_eq!(strings.len(), USER_STRING_MAX);
        assert!(truncated);
    }
}

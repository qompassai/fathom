//! ECMA-335 schema reader: the type-system facts a
//! serialization-layout builder needs (SPEC §9.3 companion to
//! `metadata`): TypeDef flags and extends, Field flags and
//! signature blobs, TypeRef scopes, TypeSpec blobs, custom
//! attributes resolved to their type names, and the
//! ClassLayout / FieldLayout tables.
//!
//! `metadata` keeps names only and never reads the
//! CustomAttribute table; this module reads the schema in
//! full. It shares no geometry code with `metadata` on
//! purpose: the coded-index tables below are the ECMA-335
//! II.23.2 lists as written in the standard (22 tables for
//! HasCustomAttribute; CustomAttributeType tags 2 = MethodDef
//! and 3 = MemberRef), and the layout builder's correctness
//! rests on them. Every read is bounds-checked; malformed
//! metadata is `unsupported_target`, never a panic.

use std::collections::BTreeMap;

use fathom_core::error::{ErrorCode, FathomError};

// Table identifiers (ECMA-335 II.22).
mod table {
    pub const ASSEMBLY: usize = 32;
    pub const ASSEMBLY_REF: usize = 35;
    pub const CLASS_LAYOUT: usize = 15;
    pub const CUSTOM_ATTRIBUTE: usize = 12;
    pub const FIELD: usize = 4;
    pub const FIELD_LAYOUT: usize = 16;
    pub const MEMBER_REF: usize = 10;
    pub const METHOD_DEF: usize = 6;
    pub const MODULE: usize = 0;
    pub const TYPE_DEF: usize = 2;
    pub const TYPE_REF: usize = 1;
    pub const TYPE_SPEC: usize = 27;
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
        6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43,
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

/// Column schemas in ECMA-335 II.22 order, for every table
/// whose rows this parser may need to step over or read.
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

/// One Field row: flags, name, and the raw signature blob.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldSchema {
    pub flags: u16,
    pub name: String,
    pub signature: Vec<u8>,
}

/// One TypeDef row. Field and method ranges are 1-based row
/// ids, end-exclusive, in declaration order.
#[derive(Clone, Debug, PartialEq)]
pub struct TypeDefSchema {
    pub extends: Option<(usize, usize)>,
    pub field_begin: usize,
    pub field_end: usize,
    pub flags: u32,
    pub method_begin: usize,
    pub method_end: usize,
    pub name: String,
    pub namespace: String,
}

/// One TypeRef row: the referenced type's name and the
/// assembly its resolution scope names, when it names one.
#[derive(Clone, Debug, PartialEq)]
pub struct TypeRefSchema {
    pub name: String,
    pub namespace: String,
    pub scope_assembly: Option<String>,
}

/// The schema of one managed assembly.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AssemblySchema {
    /// AssemblyRef names in row order (row id = index + 1).
    pub assembly_refs: Vec<String>,
    /// Custom attributes by (parent table, parent row id):
    /// the attribute type names that resolved.
    pub attributes: BTreeMap<(usize, usize), Vec<String>>,
    /// ClassLayout table: TypeDef row id -> declared size.
    pub class_layouts: BTreeMap<usize, u32>,
    /// FieldLayout table: Field row id -> explicit offset.
    pub field_layouts: BTreeMap<usize, u32>,
    /// Field rows in row order (row id = index + 1).
    pub fields: Vec<FieldSchema>,
    pub name: String,
    /// TypeDef rows in row order (row id = index + 1).
    pub type_defs: Vec<TypeDefSchema>,
    /// TypeRef rows in row order (row id = index + 1).
    pub type_refs: Vec<TypeRefSchema>,
    /// TypeSpec signature blobs in row order (row id = index + 1).
    pub type_specs: Vec<Vec<u8>>,
}

/// A TypeDefOrRef / generic-parameter token: (table, row id).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TypeToken {
    pub row: usize,
    pub table: usize,
}

/// One node of a decoded signature type (ECMA-335 II.23.2).
/// `assembly` is the caller-assigned index of the assembly
/// whose token space this node was parsed in; signature
/// tokens are assembly-relative and substitution preserves
/// the index, exactly as parsed.
#[derive(Clone, Debug, PartialEq)]
pub struct SigType {
    pub assembly: usize,
    pub kind: SigKind,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SigKind {
    /// Multi-dimensional array: element type and rank.
    Array { elem: Box<SigType>, rank: u32 },
    ByRef(Box<SigType>),
    Class(TypeToken),
    GenericInst { args: Vec<SigType>, base: Box<SigType> },
    MVar(u32),
    Ptr(Box<SigType>),
    /// A leaf element type by its ECMA name: bool, char, i1,
    /// u1, i2, u2, i4, u4, i8, u8, r4, r8, string, object,
    /// void, i, u.
    Prim(&'static str),
    SzArray(Box<SigType>),
    ValueType(TypeToken),
    Var(u32),
}

struct Heaps<'a> {
    blob: &'a [u8],
    strings: &'a [u8],
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

fn coded_target(coded: &Coded, value: u64) -> (usize, usize) {
    let mask = (1_u64 << coded.tag_bits) - 1;
    let tag = (value & mask) as usize;
    let row = (value >> coded.tag_bits) as usize;
    let table_id = coded.tables.get(tag).copied().unwrap_or(usize::MAX);
    (table_id, row)
}

/// Parse a whole PE file into its schema. `Ok(None)` = a PE
/// with no CLI header (native). Errors = not a PE, or
/// managed metadata is malformed.
pub fn parse_schema(bytes: &[u8]) -> Result<Option<AssemblySchema>, FathomError> {
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

fn parse_metadata_root(
    bytes: &[u8],
    root: usize,
) -> Result<Option<AssemblySchema>, FathomError> {
    if read_u32_at(bytes, root)? != 0x424A_5342 {
        return Err(malformed("metadata root signature is not BSJB"));
    }
    let version_len = read_u32_at(bytes, root + 12)? as usize;
    let version_bytes = bytes
        .get(root + 16..root + 16 + version_len)
        .ok_or_else(|| malformed("runtime version string overruns the file"))?;
    let _runtime_version = String::from_utf8_lossy(version_bytes)
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
    };
    let tables = parse_tables_header(tables_bytes)?;
    extract_schema(&tables, &heaps).map(Some)
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

fn qualified(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    }
}

fn extract_schema(tables: &Tables, heaps: &Heaps) -> Result<AssemblySchema, FathomError> {
    let mut schema = AssemblySchema::default();
    if tables.rows[table::ASSEMBLY] > 0 {
        let values = tables.row_values(table::ASSEMBLY, 0)?;
        schema.name = heap_string(heaps, values[7]);
    }
    for row in 0..tables.rows[table::ASSEMBLY_REF] as usize {
        let values = tables.row_values(table::ASSEMBLY_REF, row)?;
        schema.assembly_refs.push(heap_string(heaps, values[6]));
    }
    // TypeRefs first: attribute resolution names them.
    let mut type_ref_names: Vec<String> = Vec::new();
    for row in 0..tables.rows[table::TYPE_REF] as usize {
        let values = tables.row_values(table::TYPE_REF, row)?;
        let (scope_table, scope_row) = coded_target(&CODED_RESOLUTION_SCOPE, values[0]);
        let scope_assembly = match scope_table {
            table::ASSEMBLY_REF => schema.assembly_refs.get(scope_row - 1).cloned(),
            table::MODULE => Some(schema.name.clone()),
            _ => None,
        };
        let name = heap_string(heaps, values[1]);
        let namespace = heap_string(heaps, values[2]);
        type_ref_names.push(qualified(&namespace, &name));
        schema.type_refs.push(TypeRefSchema {
            name,
            namespace,
            scope_assembly,
        });
    }
    for row in 0..tables.rows[table::FIELD] as usize {
        let values = tables.row_values(table::FIELD, row)?;
        schema.fields.push(FieldSchema {
            flags: values[0] as u16,
            name: heap_string(heaps, values[1]),
            signature: heap_blob(heaps, values[2])?.to_vec(),
        });
    }
    let type_count = tables.rows[table::TYPE_DEF] as usize;
    for row in 0..type_count {
        let values = tables.row_values(table::TYPE_DEF, row)?;
        let (extends_table, extends_row) = coded_target(&CODED_TYPE_DEF_OR_REF, values[3]);
        let field_end = if row + 1 < type_count {
            tables.row_values(table::TYPE_DEF, row + 1)?[4] as usize
        } else {
            tables.rows[table::FIELD] as usize + 1
        };
        let method_end = if row + 1 < type_count {
            tables.row_values(table::TYPE_DEF, row + 1)?[5] as usize
        } else {
            tables.rows[table::METHOD_DEF] as usize + 1
        };
        schema.type_defs.push(TypeDefSchema {
            extends: if extends_row == 0 {
                None
            } else {
                Some((extends_table, extends_row))
            },
            field_begin: values[4] as usize,
            field_end,
            flags: values[0] as u32,
            method_begin: values[5] as usize,
            method_end,
            name: heap_string(heaps, values[1]),
            namespace: heap_string(heaps, values[2]),
        });
    }
    for row in 0..tables.rows[table::TYPE_SPEC] as usize {
        let values = tables.row_values(table::TYPE_SPEC, row)?;
        schema.type_specs.push(heap_blob(heaps, values[0])?.to_vec());
    }
    for row in 0..tables.rows[table::CLASS_LAYOUT] as usize {
        let values = tables.row_values(table::CLASS_LAYOUT, row)?;
        schema
            .class_layouts
            .insert(values[2] as usize, values[1] as u32);
    }
    for row in 0..tables.rows[table::FIELD_LAYOUT] as usize {
        let values = tables.row_values(table::FIELD_LAYOUT, row)?;
        schema
            .field_layouts
            .insert(values[1] as usize, values[0] as u32);
    }
    extract_attributes(tables, heaps, &mut schema, &type_ref_names)?;
    Ok(schema)
}

fn extract_attributes(
    tables: &Tables,
    _heaps: &Heaps,
    schema: &mut AssemblySchema,
    type_ref_names: &[String],
) -> Result<(), FathomError> {
    // MemberRef parents, for constructor resolution.
    let mut member_ref_parents: BTreeMap<usize, (usize, usize)> = BTreeMap::new();
    for row in 0..tables.rows[table::MEMBER_REF] as usize {
        let values = tables.row_values(table::MEMBER_REF, row)?;
        member_ref_parents.insert(row + 1, coded_target(&CODED_MEMBER_REF_PARENT, values[0]));
    }
    // MethodDef owners, from the TypeDef method ranges.
    let mut method_owners: BTreeMap<usize, usize> = BTreeMap::new();
    for (index, type_def) in schema.type_defs.iter().enumerate() {
        for method_row in type_def.method_begin..type_def.method_end {
            method_owners.insert(method_row, index + 1);
        }
    }
    let type_name = |table_id: usize, row: usize| -> Option<String> {
        match table_id {
            table::TYPE_DEF => schema
                .type_defs
                .get(row - 1)
                .map(|td| qualified(&td.namespace, &td.name)),
            table::TYPE_REF => type_ref_names.get(row - 1).cloned(),
            table::TYPE_SPEC => Some("<typespec>".to_string()),
            _ => None,
        }
    };
    for row in 0..tables.rows[table::CUSTOM_ATTRIBUTE] as usize {
        let values = tables.row_values(table::CUSTOM_ATTRIBUTE, row)?;
        let (parent_table, parent_row) =
            coded_target(&CODED_HAS_CUSTOM_ATTRIBUTE, values[0]);
        // CustomAttributeType: only tags 2 (MethodDef) and 3
        // (MemberRef) are defined; the coded list in this
        // module exists for geometry, so decode the tag here.
        let ctor_value = values[1];
        let ctor_tag = ctor_value & ((1_u64 << CODED_CUSTOM_ATTRIBUTE_TYPE.tag_bits) - 1);
        let ctor_row = (ctor_value >> CODED_CUSTOM_ATTRIBUTE_TYPE.tag_bits) as usize;
        let attribute_name = match ctor_tag {
            2 => method_owners
                .get(&ctor_row)
                .and_then(|owner| type_name(table::TYPE_DEF, *owner)),
            3 => member_ref_parents.get(&ctor_row).and_then(|(pt, pr)| {
                if *pt == table::TYPE_DEF || *pt == table::TYPE_REF {
                    type_name(*pt, *pr)
                } else {
                    None
                }
            }),
            _ => None,
        };
        if let Some(name) = attribute_name {
            schema
                .attributes
                .entry((parent_table, parent_row))
                .or_default()
                .push(name);
        }
    }
    Ok(())
}

/// Parse one Type from a signature blob at `pos`; returns the
/// type and the position just past it (ECMA-335 II.23.2).
/// `assembly` is stamped onto every node produced.
pub fn parse_type(
    blob: &[u8],
    pos: usize,
    assembly: usize,
) -> Result<(SigType, usize), FathomError> {
    let code = *blob
        .get(pos)
        .ok_or_else(|| malformed("type overruns signature blob"))?;
    let mut pos = pos + 1;
    let kind = match code {
        0x01 => SigKind::Prim("void"),
        0x02 => SigKind::Prim("bool"),
        0x03 => SigKind::Prim("char"),
        0x04 => SigKind::Prim("i1"),
        0x05 => SigKind::Prim("u1"),
        0x06 => SigKind::Prim("i2"),
        0x07 => SigKind::Prim("u2"),
        0x08 => SigKind::Prim("i4"),
        0x09 => SigKind::Prim("u4"),
        0x0A => SigKind::Prim("i8"),
        0x0B => SigKind::Prim("u8"),
        0x0C => SigKind::Prim("r4"),
        0x0D => SigKind::Prim("r8"),
        0x0E => SigKind::Prim("string"),
        0x18 => SigKind::Prim("i"),
        0x19 => SigKind::Prim("u"),
        0x1C => SigKind::Prim("object"),
        0x0F => {
            let (elem, next) = parse_type(blob, pos, assembly)?;
            pos = next;
            SigKind::Ptr(Box::new(elem))
        }
        0x10 => {
            let (elem, next) = parse_type(blob, pos, assembly)?;
            pos = next;
            SigKind::ByRef(Box::new(elem))
        }
        0x11 | 0x12 => {
            let (token, used) = read_compressed(blob, pos)?;
            pos += used;
            let (table_id, row) = coded_target(&CODED_TYPE_DEF_OR_REF, u64::from(token));
            let token = TypeToken {
                row,
                table: table_id,
            };
            if code == 0x11 {
                SigKind::ValueType(token)
            } else {
                SigKind::Class(token)
            }
        }
        0x13 => {
            let (number, used) = read_compressed(blob, pos)?;
            pos += used;
            SigKind::Var(number)
        }
        0x1E => {
            let (number, used) = read_compressed(blob, pos)?;
            pos += used;
            SigKind::MVar(number)
        }
        0x1D => {
            let (elem, next) = parse_type(blob, pos, assembly)?;
            pos = next;
            SigKind::SzArray(Box::new(elem))
        }
        0x14 => {
            let (elem, mut next) = parse_type(blob, pos, assembly)?;
            let (rank, used) = read_compressed(blob, next)?;
            next += used;
            let (size_count, used) = read_compressed(blob, next)?;
            next += used;
            for _ in 0..size_count {
                let (_, used) = read_compressed(blob, next)?;
                next += used;
            }
            let (bound_count, used) = read_compressed(blob, next)?;
            next += used;
            for _ in 0..bound_count {
                let (_, used) = read_compressed(blob, next)?;
                next += used;
            }
            pos = next;
            SigKind::Array {
                elem: Box::new(elem),
                rank,
            }
        }
        0x15 => {
            let (base, mut next) = parse_type(blob, pos, assembly)?;
            let (argc, used) = read_compressed(blob, next)?;
            next += used;
            let mut args = Vec::new();
            for _ in 0..argc {
                let (arg, after) = parse_type(blob, next, assembly)?;
                args.push(arg);
                next = after;
            }
            pos = next;
            SigKind::GenericInst {
                args,
                base: Box::new(base),
            }
        }
        0x1F | 0x20 => {
            // CMOD_REQD / CMOD_OPT: a token, then the type.
            let (_, used) = read_compressed(blob, pos)?;
            return parse_type(blob, pos + used, assembly);
        }
        0x45 => return parse_type(blob, pos, assembly),
        _ => {
            return Err(malformed(format!(
                "unimplemented signature element type 0x{code:02x}"
            )));
        }
    };
    Ok((SigType { assembly, kind }, pos))
}

/// Parse a field signature blob (`FIELD` lead byte, then one
/// Type).
pub fn parse_field_signature(blob: &[u8], assembly: usize) -> Result<SigType, FathomError> {
    if blob.first() != Some(&0x06) {
        return Err(malformed(
            "field signature does not start with FIELD (0x06)",
        ));
    }
    let (sig, _) = parse_type(blob, 1, assembly)?;
    Ok(sig)
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
    fn adversarial_field_signature_lead_rejected() {
        assert!(parse_field_signature(&[0x07, 0x08], 0).is_err());
        assert!(parse_field_signature(&[], 0).is_err());
    }

    #[test]
    fn adversarial_signature_overrun_rejected() {
        // GENERICINST with a declared argument that is absent.
        assert!(parse_type(&[0x15, 0x12, 0x00], 0, 0).is_err());
        // SZARRAY with no element.
        assert!(parse_type(&[0x1D], 0, 0).is_err());
    }

    #[test]
    fn validation_coded_index_geometry() {
        // HasCustomAttribute carries 22 tables at 5 tag bits;
        // the Event table (9) is tag 5, GenericParamConstraint
        // (44) is tag 20, MethodSpec (43) is tag 21.
        assert_eq!(CODED_HAS_CUSTOM_ATTRIBUTE.tables.len(), 22);
        let (table_id, row) = coded_target(&CODED_HAS_CUSTOM_ATTRIBUTE, (7 << 5) | 5);
        assert_eq!((table_id, row), (9, 7));
        let (table_id, row) = coded_target(&CODED_HAS_CUSTOM_ATTRIBUTE, (3 << 5) | 20);
        assert_eq!((table_id, row), (44, 3));
        let (table_id, row) = coded_target(&CODED_HAS_CUSTOM_ATTRIBUTE, (1 << 5) | 21);
        assert_eq!((table_id, row), (43, 1));
        // CustomAttributeType tags: 2 = MethodDef, 3 = MemberRef.
        let (table_id, row) = coded_target(&CODED_TYPE_DEF_OR_REF, 0b101);
        assert_eq!((table_id, row), (1, 1));
    }

    #[test]
    fn validation_signature_decoding() {
        // FIELD, CLASS with TypeDefOrRef coded 9 (tag 1 =
        // TypeRef, row 2).
        let (sig, _) = parse_type(&[0x12, 0x09], 0, 3).unwrap();
        assert_eq!(
            sig,
            SigType {
                assembly: 3,
                kind: SigKind::Class(TypeToken { row: 2, table: 1 }),
            }
        );
        // FIELD signature: SZARRAY of i4.
        let sig = parse_field_signature(&[0x06, 0x1D, 0x08], 0).unwrap();
        assert_eq!(
            sig.kind,
            SigKind::SzArray(Box::new(SigType {
                assembly: 0,
                kind: SigKind::Prim("i4"),
            }))
        );
        // GENERICINST over VALUETYPE coded 6 (tag 2 = TypeSpec,
        // row 1) with one VAR argument.
        let (sig, _) = parse_type(&[0x15, 0x11, 0x06, 0x01, 0x13, 0x00], 0, 0).unwrap();
        let SigKind::GenericInst { args, base } = &sig.kind else {
            panic!("expected genericinst");
        };
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].kind, SigKind::Var(0));
        assert_eq!(
            base.kind,
            SigKind::ValueType(TypeToken { row: 1, table: 27 })
        );
    }

    /// Hand-built tables stream + heaps: one TypeDef (Widget,
    /// extends TypeRef row 1), one Field carrying a
    /// [SerializeField] attribute recorded through a MemberRef
    /// constructor, one TypeSpec blob.
    fn fixture_schema() -> AssemblySchema {
        let strings: &[u8] = b"\0Asm\0Widget\0System\0Object\0count\0UnityEngine\0SerializeField\0";
        // Offsets: Asm=1, Widget=5, System=12, Object=19,
        // count=26, UnityEngine=32, SerializeField=44.
        let blob: &[u8] = b"\0\x02\x06\x08\x02\x01\x00\x06\x15\x11\x06\x01\x13\x00";
        // Blob offsets (length-prefixed entries): 1 = field sig
        // (06 08), 4 = attr value (prolog 01 00, content unused),
        // 7 = typespec sig (15 11 06 01 13 00).
        let mut tables_stream = Vec::new();
        tables_stream.extend_from_slice(&[0; 4]);
        tables_stream.extend_from_slice(&[2, 0]);
        tables_stream.push(0);
        tables_stream.push(0);
        let valid: u64 = (1 << 1) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 10) | (1 << 12)
            | (1 << 27) | (1 << 32) | (1 << 35);
        tables_stream.extend_from_slice(&valid.to_le_bytes());
        tables_stream.extend_from_slice(&[0; 8]);
        for rows in [2_u32, 1, 1, 1, 1, 1, 1, 1, 1] {
            tables_stream.extend_from_slice(&rows.to_le_bytes());
        }
        // Table 1 (TypeRef) row 1: ResolutionScope coded
        // (AssemblyRef row 1 => tag 2 => 1<<2|2 = 6), Name,
        // Namespace. Row 2: the SerializeField attribute type in
        // namespace UnityEngine (offsets 44 / 32).
        tables_stream.extend_from_slice(&6_u16.to_le_bytes());
        tables_stream.extend_from_slice(&19_u16.to_le_bytes());
        tables_stream.extend_from_slice(&12_u16.to_le_bytes());
        tables_stream.extend_from_slice(&6_u16.to_le_bytes());
        tables_stream.extend_from_slice(&44_u16.to_le_bytes());
        tables_stream.extend_from_slice(&32_u16.to_le_bytes());
        // Table 2 (TypeDef): Flags, Name, Namespace, Extends
        // coded (TypeRef row 1 => 1<<2|1 = 5), FieldList=1,
        // MethodList=1.
        tables_stream.extend_from_slice(&0_u32.to_le_bytes());
        tables_stream.extend_from_slice(&5_u16.to_le_bytes());
        tables_stream.extend_from_slice(&12_u16.to_le_bytes());
        tables_stream.extend_from_slice(&5_u16.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        // Table 4 (Field): Flags, Name, Signature blob (offset 1).
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&26_u16.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        // Table 6 (MethodDef): RVA, Impl, Flags, Name,
        // Signature blob (offset 0), ParamList.
        tables_stream.extend_from_slice(&0_u32.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&26_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        // Table 10 (MemberRef): Class coded MemberRefParent
        // (TypeRef row 2 => tag 1 => 2<<3|1 = 17), Name ".ctor",
        // Signature blob (offset 0).
        tables_stream.extend_from_slice(&17_u16.to_le_bytes());
        tables_stream.extend_from_slice(&26_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        // Table 12 (CustomAttribute): Parent coded
        // HasCustomAttribute (Field row 1 => tag 1 => 1<<5|1 =
        // 33), Type coded CustomAttributeType (MemberRef row 1
        // => tag 3 => 1<<3|3 = 11), Value blob (offset 4).
        tables_stream.extend_from_slice(&33_u16.to_le_bytes());
        tables_stream.extend_from_slice(&11_u16.to_le_bytes());
        tables_stream.extend_from_slice(&4_u16.to_le_bytes());
        // Table 27 (TypeSpec): Signature blob (offset 7).
        tables_stream.extend_from_slice(&7_u16.to_le_bytes());
        // Table 32 (Assembly): HashAlgId, versions, Flags,
        // PublicKey blob (0), Name (offset 1), Culture (0).
        tables_stream.extend_from_slice(&0_u32.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u32.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        // Table 35 (AssemblyRef): versions, Flags, PublicKey
        // blob (0), Name (offset 12 => "System"), Culture (0),
        // HashValue blob (0).
        tables_stream.extend_from_slice(&1_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u32.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&12_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());
        tables_stream.extend_from_slice(&0_u16.to_le_bytes());

        let tables = parse_tables_header(&tables_stream).unwrap();
        let heaps = Heaps { blob, strings };
        extract_schema(&tables, &heaps).unwrap()
    }

    #[test]
    fn validation_schema_extraction() {
        let schema = fixture_schema();
        assert_eq!(schema.name, "Asm");
        assert_eq!(schema.assembly_refs, vec!["System".to_string()]);
        assert_eq!(schema.type_defs.len(), 1);
        let type_def = &schema.type_defs[0];
        assert_eq!(type_def.name, "Widget");
        assert_eq!(type_def.namespace, "System");
        assert_eq!(type_def.extends, Some((1, 1)));
        assert_eq!((type_def.field_begin, type_def.field_end), (1, 2));
        assert_eq!(schema.fields.len(), 1);
        assert_eq!(schema.fields[0].name, "count");
        assert_eq!(schema.fields[0].signature, vec![0x06, 0x08]);
        assert_eq!(schema.type_refs.len(), 2);
        assert_eq!(schema.type_refs[0].name, "Object");
        assert_eq!(
            schema.type_refs[0].scope_assembly,
            Some("System".to_string())
        );
        assert_eq!(schema.type_refs[1].name, "SerializeField");
        assert_eq!(schema.type_refs[1].namespace, "UnityEngine");
        assert_eq!(schema.type_specs, vec![vec![0x15, 0x11, 0x06, 0x01, 0x13, 0x00]]);
        // The attribute lands on (Field, row 1) under its
        // qualified type name, resolved through the MemberRef.
        assert_eq!(
            schema.attributes.get(&(4, 1)).map(Vec::as_slice),
            Some(&["UnityEngine.SerializeField".to_string()][..])
        );
    }
}

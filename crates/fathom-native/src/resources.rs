//! PE resource-directory census: the `.rsrc` inventory
//! of a Windows executable, with the resource types an
//! analyst actually reads decoded — dialogs to JSON,
//! icon groups reassembled into `.ico` form, bitmaps
//! into `.bmp` form, manifests as text.
//!
//! The PE parse is hand-rolled (DOS header, COFF,
//! optional header, sections, data directories); the
//! resource walk is the standard three-level tree
//! (type → name → language) with every offset checked
//! against the resource region and a visited-set so a
//! lying directory cannot loop the walk.
//!
//! Honesty contract: a leaf's bytes are hashed as
//! stored; decoded forms (dialog JSON, .ico, .bmp) are
//! reported by hash and size, never as payload dumps. A
//! resource type this reader does not decode is a
//! generic hashed row, not a gap dressed as coverage. A
//! leaf whose structured payload does not parse carries
//! a `parse_error` fact; the census continues.

use serde_json::{Value, json};
use std::collections::HashSet;
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{
    Confidence, Evidence, Finding, sha256_hex, subject_for_file_with_bound,
};
use fathom_core::limits::ARCHIVE_TARGET_BYTES_MAX;
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};

/// Resource leaf cap: past it the census refuses rather
/// than truncating silently.
const RES_LEAVES_MAX: usize = 100_000;
/// Manifest text is inlined only up to this size.
const MANIFEST_INLINE_MAX: usize = 65_536;
/// Dialog control cap inside one template.
const DIALOG_CONTROLS_MAX: usize = 512;

/// One PE section header.
#[derive(Debug)]
pub struct PeSection {
    pub name: String,
    pub raw_pointer: u32,
    pub raw_size: u32,
    pub virtual_address: u32,
    pub virtual_size: u32,
}

/// The parsed PE head: COFF + optional-header facts and
/// the data directories (index, RVA, size).
#[derive(Debug)]
pub struct PeHead {
    pub characteristics: u16,
    /// Data directories as (rva, size); index 2 is the
    /// resource directory, 14 the COM descriptor (.NET).
    pub directories: Vec<(u32, u32)>,
    pub dll_characteristics: u16,
    pub dotnet: bool,
    pub is_64: bool,
    pub machine: u16,
    pub sections: Vec<PeSection>,
    pub subsystem: u16,
}

impl PeHead {
    /// The architecture name for the COFF machine value.
    pub fn arch(&self) -> &'static str {
        match self.machine {
            0x014c => "x86",
            0x8664 => "x86_64",
            0x01c0 => "arm",
            0x01c4 => "armv7",
            0xaa64 => "arm64",
            0x0200 => "ia64",
            _ => "unknown",
        }
    }

    /// Map an RVA to a file offset through the sections.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            let span = section.virtual_size.max(section.raw_size);
            if rva >= section.virtual_address && rva < section.virtual_address + span {
                let delta = rva - section.virtual_address;
                if delta < section.raw_size {
                    return usize::try_from(section.raw_pointer + delta).ok();
                }
                return None;
            }
        }
        if rva < 0x1000 {
            // Header-mapped RVAs (before the first section).
            return usize::try_from(rva).ok();
        }
        None
    }

    /// The (rva, size) of one data directory, when set.
    pub fn directory(&self, index: usize) -> Option<(u32, u32)> {
        self.directories
            .get(index)
            .copied()
            .filter(|(rva, size)| *rva != 0 && *size != 0)
    }
}

fn mismatch(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::ArtifactIntegrityMismatch, message.into())
        .with_target("pe resources")
}

fn truncated(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::Truncated, message.into()).with_target("pe resources")
}

fn unsupported(message: impl Into<String>) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message.into()).with_target("pe resources")
}

/// Bounds-checked little-endian reader over the file.
struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], position: usize) -> Self {
        Cursor { bytes, position }
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], FathomError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| truncated("pe structure overruns the file"))?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn read_u16(&mut self) -> Result<u16, FathomError> {
        Ok(u16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    fn read_u32(&mut self) -> Result<u32, FathomError> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    fn seek(&mut self, position: usize) -> Result<(), FathomError> {
        if position > self.bytes.len() {
            return Err(truncated("pe structure offset overruns the file"));
        }
        self.position = position;
        Ok(())
    }
}

/// Parse the PE head. Typed refusals for non-PE input
/// and truncated structures.
pub fn parse_pe(bytes: &[u8]) -> Result<PeHead, FathomError> {
    if bytes.len() < 64 || &bytes[0..2] != b"MZ" {
        return Err(unsupported("missing MZ signature; not a PE file"));
    }
    let mut cursor = Cursor::new(bytes, 0x3c);
    let pe_offset = usize::try_from(cursor.read_u32()?)
        .map_err(|_| truncated("PE header offset does not fit this platform"))?;
    cursor.seek(pe_offset)?;
    if cursor.read_bytes(4)? != b"PE\0\0" {
        return Err(unsupported("missing PE signature; not a PE file"));
    }
    let machine = cursor.read_u16()?;
    let section_count = cursor.read_u16()? as usize;
    cursor.read_bytes(12)?; // timestamp, symbol table, symbol count
    let optional_size = cursor.read_u16()? as usize;
    let characteristics = cursor.read_u16()?;
    if section_count > 96 {
        return Err(mismatch(format!(
            "PE declares an implausible section count {section_count}"
        )));
    }
    let optional_start = cursor.position;
    let mut head_probe = Cursor::new(bytes, optional_start);
    let magic = head_probe.read_u16()?;
    let is_64 = match magic {
        0x10b => false,
        0x20b => true,
        other => {
            return Err(unsupported(format!(
                "optional-header magic 0x{other:04x} is not PE32 or PE32+"
            )));
        }
    };
    // Subsystem and DLL characteristics sit at fixed
    // offsets in both optional-header layouts.
    let mut fixed = Cursor::new(bytes, optional_start);
    fixed.read_bytes(68)?;
    let subsystem = fixed.read_u16()?;
    let dll_characteristics = fixed.read_u16()?;
    let (count_at, dirs_at) = if is_64 { (108, 112) } else { (92, 96) };
    let mut dirs_cursor = Cursor::new(bytes, optional_start);
    dirs_cursor.read_bytes(count_at)?;
    let dir_count = (dirs_cursor.read_u32()? as usize).min(16);
    dirs_cursor.seek(optional_start + dirs_at)?;
    let mut directories = Vec::with_capacity(dir_count);
    for _ in 0..dir_count {
        let rva = dirs_cursor.read_u32()?;
        let size = dirs_cursor.read_u32()?;
        directories.push((rva, size));
    }
    while directories.len() < 16 {
        directories.push((0, 0));
    }
    let dotnet = directories[14].0 != 0;
    let sections_at = optional_start + optional_size;
    let mut sections_cursor = Cursor::new(bytes, sections_at);
    let mut sections = Vec::with_capacity(section_count);
    for _ in 0..section_count {
        let raw_name = sections_cursor.read_bytes(8)?;
        let name_end = raw_name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..name_end]).into_owned();
        let virtual_size = sections_cursor.read_u32()?;
        let virtual_address = sections_cursor.read_u32()?;
        let raw_size = sections_cursor.read_u32()?;
        let raw_pointer = sections_cursor.read_u32()?;
        sections_cursor.read_bytes(16)?;
        sections.push(PeSection {
            name,
            raw_pointer,
            raw_size,
            virtual_address,
            virtual_size,
        });
    }
    Ok(PeHead {
        characteristics,
        directories,
        dll_characteristics,
        dotnet,
        is_64,
        machine,
        sections,
        subsystem,
    })
}

/// Shannon entropy (bits per byte) of a byte string.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0_u64; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// One resource key: a numeric ID or a name string.
#[derive(Clone, Debug, PartialEq)]
enum ResKey {
    Id(u32),
    Name(String),
}

impl ResKey {
    fn json(&self) -> Value {
        match self {
            ResKey::Id(id) => json!(id),
            ResKey::Name(name) => json!(name),
        }
    }
}

/// One resource leaf: a data entry reached by walking
/// the directory tree.
#[derive(Debug)]
struct ResLeaf {
    id: ResKey,
    language: u16,
    offset: usize,
    size: u32,
    type_key: ResKey,
}

/// The resource type name for a numeric type ID.
fn type_name(type_id: u32) -> Option<&'static str> {
    Some(match type_id {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        17 => "RT_DLGINIT",
        19 => "RT_PLUGPLAY",
        20 => "RT_VXD",
        21 => "RT_ANICURSOR",
        22 => "RT_ANIICON",
        23 => "RT_HTML",
        24 => "RT_MANIFEST",
        _ => return None,
    })
}

/// Walk the resource directory tree from `base` (the
/// file offset of the resource directory). Directory and
/// data-entry offsets are relative to `base`; data RVAs
/// are image RVAs, translated through the section table.
/// A visited set on subdirectory offsets keeps a cyclic
/// directory from looping the walk.
fn walk_resources(
    bytes: &[u8],
    head: &PeHead,
    base: usize,
    size: usize,
) -> Result<Vec<ResLeaf>, FathomError> {
    let region_end = base
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| truncated("resource region overruns the file"))?;
    let mut leaves: Vec<ResLeaf> = Vec::new();
    let mut visited: HashSet<usize> = HashSet::new();
    // Stack of (directory offset, key path so far, depth).
    let mut stack: Vec<(usize, Vec<ResKey>, usize)> = vec![(0, Vec::new(), 0)];
    while let Some((dir_rel, path, depth)) = stack.pop() {
        if depth > 4 {
            return Err(mismatch("resource directory nests past its three levels"));
        }
        if !visited.insert(dir_rel) {
            return Err(mismatch("resource directory contains a cycle"));
        }
        let dir_at = base + dir_rel;
        let mut cursor = Cursor::new(bytes, dir_at);
        cursor.read_bytes(12)?; // characteristics, timestamp, versions
        let named = cursor.read_u16()? as usize;
        let ids = cursor.read_u16()? as usize;
        let count = named + ids;
        if count > 4096 {
            return Err(mismatch(format!(
                "resource directory declares an implausible entry count {count}"
            )));
        }
        for _ in 0..count {
            let name_field = cursor.read_u32()?;
            let target_field = cursor.read_u32()?;
            let key = if name_field & 0x8000_0000 != 0 {
                let string_rel = (name_field & 0x7fff_ffff) as usize;
                let string_at = base + string_rel;
                if string_at >= region_end {
                    return Err(mismatch("resource name string overruns the region"));
                }
                let mut string_cursor = Cursor::new(bytes, string_at);
                let units = string_cursor.read_u16()? as usize;
                if units > 1024 {
                    return Err(mismatch("resource name string is implausibly long"));
                }
                let raw = string_cursor.read_bytes(units * 2)?;
                let code_units: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes(*pair))
                    .collect();
                ResKey::Name(
                    String::from_utf16(&code_units)
                        .map_err(|_| mismatch("resource name is not valid UTF-16"))?,
                )
            } else {
                ResKey::Id(name_field & 0xffff)
            };
            let mut child_path = path.clone();
            child_path.push(key);
            if target_field & 0x8000_0000 != 0 {
                let sub_rel = (target_field & 0x7fff_ffff) as usize;
                if base + sub_rel >= region_end {
                    return Err(mismatch("resource subdirectory overruns the region"));
                }
                stack.push((sub_rel, child_path, depth + 1));
            } else {
                // Data entry: RVA, size, codepage, reserved.
                let entry_rel = target_field as usize;
                let entry_at = base + entry_rel;
                if entry_at >= region_end {
                    return Err(mismatch("resource data entry overruns the region"));
                }
                let mut entry_cursor = Cursor::new(bytes, entry_at);
                let data_rva = entry_cursor.read_u32()?;
                let data_size = entry_cursor.read_u32()?;
                entry_cursor.read_bytes(8)?;
                if child_path.len() != 3 {
                    return Err(mismatch(
                        "resource data entry does not sit at the language level",
                    ));
                }
                let data_offset = head
                    .rva_to_offset(data_rva)
                    .filter(|offset| {
                        offset
                            .checked_add(data_size as usize)
                            .is_some_and(|end| end <= bytes.len())
                    })
                    .ok_or_else(|| {
                        mismatch("resource data RVA/size overruns the file's sections")
                    })?;
                leaves.push(ResLeaf {
                    id: child_path[1].clone(),
                    language: match &child_path[2] {
                        ResKey::Id(id) => *id as u16,
                        ResKey::Name(_) => 0,
                    },
                    offset: data_offset,
                    size: data_size,
                    type_key: child_path[0].clone(),
                });
                if leaves.len() > RES_LEAVES_MAX {
                    return Err(FathomError::new(
                        ErrorCode::ResourceConstraint,
                        format!("resource leaves exceed RES_LEAVES_MAX ({RES_LEAVES_MAX})"),
                    )
                    .with_target("pe resources"));
                }
            }
        }
    }
    Ok(leaves)
}

/// A UTF-16LE NUL-terminated string field, or — when its
/// first word is 0xFFFF — a resource ordinal.
enum SzOrOrd {
    Ordinal(u16),
    Text(String),
}

impl SzOrOrd {
    fn json(&self) -> Value {
        match self {
            SzOrOrd::Ordinal(ordinal) => json!({"ordinal": ordinal}),
            SzOrOrd::Text(text) => json!(text),
        }
    }
}

/// Cursor over one structured resource payload (dialog
/// templates). Errors are plain strings: a payload that
/// does not parse is a row fact, never a census failure.
struct BlobCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BlobCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        BlobCursor { bytes, position: 0 }
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| "payload ends mid-structure".to_string())?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    fn i16(&mut self) -> Result<i16, String> {
        Ok(i16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }

    /// Align to a 4-byte boundary, relative to the
    /// template start — the dialog layout rule.
    fn align4(&mut self) {
        self.position = self.position.div_ceil(4) * 4;
    }

    /// A NUL-terminated UTF-16LE string (may be empty).
    fn utf16z(&mut self) -> Result<String, String> {
        let mut units: Vec<u16> = Vec::new();
        loop {
            let unit = self.u16()?;
            if unit == 0 {
                break;
            }
            units.push(unit);
            if units.len() > 4096 {
                return Err("string field is implausibly long".to_string());
            }
        }
        String::from_utf16(&units).map_err(|_| "string field is not valid UTF-16".to_string())
    }

    fn sz_or_ord(&mut self) -> Result<SzOrOrd, String> {
        let first = self.u16()?;
        if first == 0xffff {
            return Ok(SzOrOrd::Ordinal(self.u16()?));
        }
        if first == 0 {
            return Ok(SzOrOrd::Text(String::new()));
        }
        let mut units = vec![first];
        loop {
            let unit = self.u16()?;
            if unit == 0 {
                break;
            }
            units.push(unit);
            if units.len() > 4096 {
                return Err("string field is implausibly long".to_string());
            }
        }
        String::from_utf16(&units)
            .map(SzOrOrd::Text)
            .map_err(|_| "string field is not valid UTF-16".to_string())
    }
}

/// The window-class name for a predefined class atom.
fn class_atom_name(atom: u16) -> Option<&'static str> {
    Some(match atom {
        0x0080 => "Button",
        0x0081 => "Edit",
        0x0082 => "Static",
        0x0083 => "ListBox",
        0x0084 => "ScrollBar",
        0x0085 => "ComboBox",
        _ => return None,
    })
}

/// Resolve a dialog class field: a predefined atom
/// becomes its name; anything else stays as written.
fn class_json(field: &SzOrOrd) -> Value {
    match field {
        SzOrOrd::Ordinal(atom) => match class_atom_name(*atom) {
            Some(name) => json!(name),
            None => json!({"atom": atom}),
        },
        SzOrOrd::Text(text) => json!(text),
    }
}

/// `DS_SETFONT` / `DS_FIXEDSYS`: the template carries a
/// font description.
const DS_SETFONT: u32 = 0x0000_0040;
const DS_FIXEDSYS: u32 = 0x0000_0008;

/// Decode one dialog template (DLGTEMPLATE or
/// DLGTEMPLATEEX) to JSON. The extended form is the one
/// whose first words are `01 00 FF FF` — dialog version
/// 1, signature 0xFFFF, in that order.
fn parse_dialog(data: &[u8]) -> Result<Value, String> {
    let mut cursor = BlobCursor::new(data);
    let extended = data.len() >= 4 && cursor.u16()? == 1 && cursor.u16()? == 0xffff;
    if !extended {
        cursor = BlobCursor::new(data);
    }
    let mut out = serde_json::Map::new();
    out.insert("extended".into(), json!(extended));
    let (style, ex_style, help_id) = if extended {
        let help_id = cursor.u32()?;
        let ex_style = cursor.u32()?;
        let style = cursor.u32()?;
        (style, ex_style, Some(help_id))
    } else {
        let style = cursor.u32()?;
        let ex_style = cursor.u32()?;
        (style, ex_style, None)
    };
    if let Some(help_id) = help_id {
        out.insert("help_id".into(), json!(help_id));
    }
    out.insert("style".into(), json!(format!("0x{style:08x}")));
    out.insert("ex_style".into(), json!(format!("0x{ex_style:08x}")));
    let count = cursor.u16()? as usize;
    if count > DIALOG_CONTROLS_MAX {
        return Err(format!(
            "dialog declares an implausible control count {count}"
        ));
    }
    let rect: Vec<i16> = (0..4).map(|_| cursor.i16()).collect::<Result<_, _>>()?;
    out.insert("rect".into(), json!(rect));
    out.insert("menu".into(), cursor.sz_or_ord()?.json());
    out.insert("window_class".into(), class_json(&cursor.sz_or_ord()?));
    let title = cursor.utf16z()?;
    out.insert("title".into(), json!(title));
    if style & (DS_SETFONT | DS_FIXEDSYS) != 0 {
        let size = cursor.u16()?;
        let font = if extended {
            let weight = cursor.u16()?;
            let italic = cursor.u8()?;
            let charset = cursor.u8()?;
            json!({
                "charset": charset,
                "italic": italic != 0,
                "name": cursor.utf16z()?,
                "size": size,
                "weight": weight,
            })
        } else {
            json!({"name": cursor.utf16z()?, "size": size})
        };
        out.insert("font".into(), font);
    }
    let mut controls: Vec<Value> = Vec::with_capacity(count);
    for _ in 0..count {
        cursor.align4();
        let mut control = serde_json::Map::new();
        if extended {
            control.insert("help_id".into(), json!(cursor.u32()?));
            control.insert("ex_style".into(), json!(format!("0x{:08x}", cursor.u32()?)));
            control.insert("style".into(), json!(format!("0x{:08x}", cursor.u32()?)));
        } else {
            control.insert("style".into(), json!(format!("0x{:08x}", cursor.u32()?)));
            control.insert("ex_style".into(), json!(format!("0x{:08x}", cursor.u32()?)));
        }
        let rect: Vec<i16> = (0..4).map(|_| cursor.i16()).collect::<Result<_, _>>()?;
        control.insert("rect".into(), json!(rect));
        if extended {
            control.insert("id".into(), json!(cursor.u32()?));
        } else {
            control.insert("id".into(), json!(cursor.u16()?));
        }
        control.insert("class".into(), class_json(&cursor.sz_or_ord()?));
        control.insert("title".into(), cursor.sz_or_ord()?.json());
        let extra = cursor.u16()? as usize;
        cursor.bytes(extra)?;
        controls.push(Value::Object(control));
    }
    out.insert("controls".into(), json!(controls));
    out.insert("control_count".into(), json!(count));
    Ok(Value::Object(out))
}

/// One icon-group image entry (14 bytes on disk).
struct IconImage {
    bit_count: u16,
    bytes_in_res: u32,
    color_count: u8,
    height: u8,
    id: u16,
    planes: u16,
    width: u8,
}

/// Parse an RT_GROUP_ICON payload's directory.
fn parse_icon_group(data: &[u8]) -> Result<(u16, Vec<IconImage>), String> {
    let mut cursor = BlobCursor::new(data);
    let reserved = cursor.u16()?;
    let kind = cursor.u16()?;
    if reserved != 0 || kind != 1 {
        return Err(format!(
            "icon group header is not an ICONDIR (reserved {reserved}, type {kind})"
        ));
    }
    let count = cursor.u16()? as usize;
    if count > 256 {
        return Err(format!(
            "icon group declares an implausible image count {count}"
        ));
    }
    let mut images = Vec::with_capacity(count);
    for _ in 0..count {
        let width = cursor.u8()?;
        let height = cursor.u8()?;
        let color_count = cursor.u8()?;
        cursor.u8()?; // reserved
        let planes = cursor.u16()?;
        let bit_count = cursor.u16()?;
        let bytes_in_res = cursor.u32()?;
        let id = cursor.u16()?;
        images.push(IconImage {
            bit_count,
            bytes_in_res,
            color_count,
            height,
            id,
            planes,
            width,
        });
    }
    Ok((kind, images))
}

/// Rebuild the `.ico` file for one icon group from the
/// RT_ICON payloads (by ID). Returns the ico bytes and
/// the per-image rows; an image whose payload is absent
/// or size-lying is a row with `missing: true` and stops
/// the reconstruction (the hash would be a lie).
fn reconstruct_ico<'a>(
    kind: u16,
    images: &[IconImage],
    icon_payload: &dyn Fn(u16) -> Option<&'a [u8]>,
) -> (Option<Vec<u8>>, Vec<Value>) {
    let mut rows: Vec<Value> = Vec::new();
    let mut payloads: Vec<&[u8]> = Vec::new();
    let mut complete = true;
    for image in images {
        let payload = icon_payload(image.id)
            .filter(|payload| payload.len() as u64 == u64::from(image.bytes_in_res));
        match payload {
            Some(payload) => {
                payloads.push(payload);
                rows.push(json!({
                    "bit_count": image.bit_count,
                    "bytes": image.bytes_in_res,
                    "color_count": image.color_count,
                    "height": if image.height == 0 { 256 } else { u32::from(image.height) },
                    "id": image.id,
                    "missing": false,
                    "planes": image.planes,
                    "width": if image.width == 0 { 256 } else { u32::from(image.width) },
                }));
            }
            None => {
                complete = false;
                rows.push(json!({
                    "bit_count": image.bit_count,
                    "bytes": image.bytes_in_res,
                    "id": image.id,
                    "missing": true,
                }));
            }
        }
    }
    if !complete {
        return (None, rows);
    }
    let mut ico: Vec<u8> = Vec::new();
    ico.extend_from_slice(&0_u16.to_le_bytes());
    ico.extend_from_slice(&kind.to_le_bytes());
    ico.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len();
    for (image, payload) in images.iter().zip(&payloads) {
        ico.push(image.width);
        ico.push(image.height);
        ico.push(image.color_count);
        ico.push(0);
        ico.extend_from_slice(&image.planes.to_le_bytes());
        ico.extend_from_slice(&image.bit_count.to_le_bytes());
        ico.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        ico.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += payload.len();
    }
    for payload in &payloads {
        ico.extend_from_slice(payload);
    }
    (Some(ico), rows)
}

/// Rebuild the `.bmp` file for one RT_BITMAP payload
/// (a DIB): the 14-byte file header plus the stored
/// bytes. Header facts come from the DIB header itself
/// (core or info layout).
fn reconstruct_bmp(data: &[u8]) -> Result<(Vec<u8>, Value), String> {
    let mut cursor = BlobCursor::new(data);
    let header_size = cursor.u32()?;
    let (width, height, bit_count, palette_entries) = if header_size == 12 {
        let width = i32::from(cursor.u16()?);
        let height = i32::from(cursor.u16()?);
        cursor.u16()?; // planes
        let bit_count = cursor.u16()?;
        (width, height, bit_count, 0_u32)
    } else if header_size >= 40 {
        let width = cursor.u32()? as i32;
        let height = cursor.u32()? as i32;
        cursor.u16()?; // planes
        let bit_count = cursor.u16()?;
        cursor.bytes((header_size - 16) as usize)?;
        let clr_used = if header_size >= 40 {
            // biClrUsed sits at offset 32 in the info header.
            let mut probe = BlobCursor::new(data);
            probe.bytes(32)?;
            probe.u32()?
        } else {
            0
        };
        let palette = if bit_count <= 8 {
            if clr_used != 0 {
                clr_used
            } else {
                1_u32 << bit_count
            }
        } else {
            clr_used
        };
        (width, height, bit_count, palette)
    } else {
        return Err(format!(
            "bitmap header size {header_size} is not a DIB layout"
        ));
    };
    let data_offset = 14 + header_size + palette_entries * 4;
    let mut bmp: Vec<u8> = Vec::with_capacity(14 + data.len());
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&((14 + data.len()) as u32).to_le_bytes());
    bmp.extend_from_slice(&0_u32.to_le_bytes());
    bmp.extend_from_slice(&data_offset.to_le_bytes());
    bmp.extend_from_slice(data);
    Ok((
        bmp,
        json!({
            "bit_count": bit_count,
            "height": height,
            "width": width,
        }),
    ))
}

/// The DLL-characteristics flag names set in the word.
pub fn dll_characteristic_names(word: u16) -> Vec<&'static str> {
    let flags: [(u16, &str); 9] = [
        (0x0020, "high_entropy_va"),
        (0x0040, "dynamic_base"),
        (0x0080, "force_integrity"),
        (0x0100, "nx_compat"),
        (0x0200, "no_isolation"),
        (0x0400, "no_seh"),
        (0x0800, "no_bind"),
        (0x4000, "guard_cf"),
        (0x8000, "terminal_server_aware"),
    ];
    flags
        .iter()
        .filter(|(bit, _)| word & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

pub fn inspect_pe_resources(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file_with_bound(&path, ARCHIVE_TARGET_BYTES_MAX)?;
    let subject_sha256 = subject.sha256.clone();
    let bytes = std::fs::read(&path).map_err(|error| {
        FathomError::new(
            ErrorCode::TargetUnavailable,
            format!("cannot read target: {error}"),
        )
    })?;
    let head = parse_pe(&bytes)?;
    let mut unknowns: Vec<(String, String)> = Vec::new();
    let mut rows: Vec<Value> = Vec::new();
    let mut type_counts: std::collections::BTreeMap<String, u64> = Default::default();
    let (resource_rva, resource_size, leaves) = match head.directory(2) {
        Some((rva, size)) => {
            let base = head
                .rva_to_offset(rva)
                .ok_or_else(|| mismatch("resource directory RVA does not map to the file"))?;
            let leaves = walk_resources(&bytes, &head, base, size as usize)?;
            (rva, size, leaves)
        }
        None => {
            unknowns.push((
                "resources".to_string(),
                "the PE carries no resource data directory; there is no .rsrc inventory"
                    .to_string(),
            ));
            (0, 0, Vec::new())
        }
    };
    // RT_ICON payloads by ID, for icon-group reconstruction.
    let icon_payloads: std::collections::HashMap<u16, &[u8]> = leaves
        .iter()
        .filter(|leaf| leaf.type_key == ResKey::Id(3))
        .filter_map(|leaf| match &leaf.id {
            ResKey::Id(id) => Some((
                *id as u16,
                &bytes[leaf.offset..leaf.offset + leaf.size as usize],
            )),
            ResKey::Name(_) => None,
        })
        .collect();
    let mut dialog_failures: u64 = 0;
    for leaf in &leaves {
        let data = &bytes[leaf.offset..leaf.offset + leaf.size as usize];
        let type_id = match &leaf.type_key {
            ResKey::Id(id) => Some(*id),
            ResKey::Name(_) => None,
        };
        let type_label = match (&leaf.type_key, type_id.and_then(type_name)) {
            (_, Some(name)) => name.to_string(),
            (ResKey::Name(name), None) => name.clone(),
            (ResKey::Id(id), None) => format!("RT_{id}"),
        };
        *type_counts.entry(type_label.clone()).or_insert(0) += 1;
        let mut row = json!({
            "id": leaf.id.json(),
            "language": leaf.language,
            "sha256": sha256_hex(data),
            "size": leaf.size,
            "type": type_label,
            "type_id": type_id,
        });
        match type_id {
            Some(5) => match parse_dialog(data) {
                Ok(dialog) => row["dialog"] = dialog,
                Err(error) => {
                    dialog_failures += 1;
                    row["parse_error"] = json!(error);
                }
            },
            Some(14) => match parse_icon_group(data) {
                Ok((kind, images)) => {
                    let (ico, image_rows) =
                        reconstruct_ico(kind, &images, &|id| icon_payloads.get(&id).copied());
                    row["icon_group"] = json!({
                        "ico_bytes": ico.as_ref().map(Vec::len),
                        "ico_sha256": ico.as_ref().map(|ico| sha256_hex(ico)),
                        "images": image_rows,
                    });
                }
                Err(error) => {
                    row["parse_error"] = json!(error);
                }
            },
            Some(2) => match reconstruct_bmp(data) {
                Ok((bmp, facts)) => {
                    row["bitmap"] = json!({
                        "bit_count": facts["bit_count"],
                        "bmp_bytes": bmp.len(),
                        "bmp_sha256": sha256_hex(&bmp),
                        "height": facts["height"],
                        "width": facts["width"],
                    });
                }
                Err(error) => {
                    row["parse_error"] = json!(error);
                }
            },
            Some(24) => {
                if leaf.size as usize <= MANIFEST_INLINE_MAX {
                    if let Ok(text) = std::str::from_utf8(data) {
                        row["manifest_text"] = json!(text.strip_prefix('\u{feff}').unwrap_or(text));
                    } else {
                        row["manifest_note"] = json!("manifest is not valid UTF-8; hashed only");
                    }
                } else {
                    row["manifest_note"] = json!("manifest exceeds the inline bound; hashed only");
                }
            }
            Some(10) => {
                let first: Vec<u8> = data.iter().take(16).copied().collect();
                row["first16"] = json!(
                    first
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join("")
                );
            }
            Some(3) => {
                row["icon_format"] = json!(if data.starts_with(&[0x89, 0x50, 0x4e, 0x47]) {
                    "png"
                } else {
                    "dib"
                });
            }
            _ => {}
        }
        rows.push(row);
    }
    if dialog_failures > 0 {
        unknowns.push((
            "dialog decode".to_string(),
            format!(
                "{dialog_failures} RT_DIALOG payloads did not parse; their rows carry parse_error facts"
            ),
        ));
    }
    let sections: Vec<Value> = head
        .sections
        .iter()
        .map(|section| {
            json!({
                "name": section.name,
                "raw_size": section.raw_size,
                "virtual_address": section.virtual_address,
                "virtual_size": section.virtual_size,
            })
        })
        .collect();
    let record = json!({
        "arch": head.arch(),
        "characteristics": format!("0x{:04x}", head.characteristics),
        "dll_characteristics": dll_characteristic_names(head.dll_characteristics),
        "dotnet": head.dotnet,
        "entries": rows.len(),
        "is_64": head.is_64,
        "machine": format!("0x{:04x}", head.machine),
        "resource_rva": resource_rva,
        "resource_size": resource_size,
        "sections": sections,
        "subsystem": head.subsystem,
        "types": type_counts,
    });
    let document = json!({
        "pe_resources": record.clone(),
        "pe_resource_entries": rows.clone(),
        "pe_resource_entries_total": rows.len(),
    });
    let mut evidence = Evidence::new("inspect_pe_resources", "pe");
    evidence.subject = Some(subject);
    let (digest, retention_note) =
        match proof::retain_export(config, &subject_sha256, "pe_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    let mut facts = record;
    facts["export_digest"] = match &digest {
        Some(digest) => json!(digest),
        None => Value::Null,
    };
    evidence.add_finding(Finding::new("pe_resources", Confidence::Observed, facts));
    evidence.add_finding(Finding::new(
        "entries",
        Confidence::Observed,
        json!({"entries": rows, "returned": rows.len(), "total": leaves.len()}),
    ));
    if let Some(note) = retention_note {
        unknowns.push((
            "retention".to_string(),
            format!(
                "census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        ));
    }
    for (aspect, reason) in unknowns {
        evidence.add_unknown(aspect, reason);
    }
    evidence.coverage.examined = leaves.len() as u64;
    evidence.coverage.total = leaves.len() as u64;
    evidence.coverage.exhaustive = evidence.unknowns.is_empty();
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn w16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn w32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn wi16(out: &mut Vec<u8>, value: i16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn utf16z(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in text.encode_utf16().chain([0]) {
            w16(&mut out, unit);
        }
        out
    }

    fn align4(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    /// A DLGTEMPLATEEX ("01 00 FF FF" first) with a font
    /// and two controls: a Button "OK" and a Static
    /// "Name:".
    fn ex_dialog() -> Vec<u8> {
        let mut d = Vec::new();
        w16(&mut d, 1);
        w16(&mut d, 0xffff);
        w32(&mut d, 0); // help id
        w32(&mut d, 0); // ex style
        w32(&mut d, 0x9000_0040); // WS_POPUP | WS_VISIBLE | DS_SETFONT
        w16(&mut d, 2); // control count
        for value in [10_i16, 10, 200, 100] {
            wi16(&mut d, value);
        }
        w16(&mut d, 0); // menu: empty
        w16(&mut d, 0); // class: empty
        d.extend_from_slice(&utf16z("Settings"));
        w16(&mut d, 9); // font size
        w16(&mut d, 400); // font weight
        d.push(0); // italic
        d.push(1); // charset
        d.extend_from_slice(&utf16z("Segoe UI"));
        align4(&mut d);
        w32(&mut d, 0);
        w32(&mut d, 0);
        w32(&mut d, 0x5001_0000);
        for value in [5_i16, 5, 60, 20] {
            wi16(&mut d, value);
        }
        w32(&mut d, 1); // id
        w16(&mut d, 0xffff);
        w16(&mut d, 0x0080); // class atom: Button
        d.extend_from_slice(&utf16z("OK"));
        w16(&mut d, 0); // extra count
        align4(&mut d);
        w32(&mut d, 0);
        w32(&mut d, 0);
        w32(&mut d, 0x5000_0000);
        for value in [5_i16, 30, 60, 12] {
            wi16(&mut d, value);
        }
        w32(&mut d, 0xffff_ffff); // id: IDC_STATIC
        w16(&mut d, 0xffff);
        w16(&mut d, 0x0082); // class atom: Static
        d.extend_from_slice(&utf16z("Name:"));
        w16(&mut d, 0);
        d
    }

    /// A classic DLGTEMPLATE with one Edit control.
    fn classic_dialog() -> Vec<u8> {
        let mut d = Vec::new();
        w32(&mut d, 0x8000_0040); // WS_POPUP | DS_SETFONT
        w32(&mut d, 0);
        w16(&mut d, 1);
        for value in [0_i16, 0, 120, 60] {
            wi16(&mut d, value);
        }
        w16(&mut d, 0);
        w16(&mut d, 0);
        d.extend_from_slice(&utf16z("Legacy"));
        w16(&mut d, 8);
        d.extend_from_slice(&utf16z("MS Shell Dlg"));
        align4(&mut d);
        w32(&mut d, 0x5000_0000);
        w32(&mut d, 0);
        for value in [4_i16, 4, 100, 14] {
            wi16(&mut d, value);
        }
        w16(&mut d, 1001);
        w16(&mut d, 0xffff);
        w16(&mut d, 0x0081); // Edit
        w16(&mut d, 0); // title: empty
        w16(&mut d, 0);
        d
    }

    struct TestLeaf {
        data: Vec<u8>,
        id: u16,
        lang: u16,
        type_id: u32,
    }

    fn leaf(type_id: u32, id: u16, data: Vec<u8>) -> TestLeaf {
        TestLeaf {
            data,
            id,
            lang: 0x0409,
            type_id,
        }
    }

    fn put_entry(region: &mut [u8], at: usize, name: u32, target: u32) {
        region[at..at + 4].copy_from_slice(&name.to_le_bytes());
        region[at + 4..at + 8].copy_from_slice(&target.to_le_bytes());
    }

    /// Build a minimal PE32+ (x86_64) with a `.rsrc`
    /// section holding the given leaves, all IDs (no name
    /// strings), resource VA 0x1000, raw at 0x400.
    fn build_pe(leaves: &[TestLeaf], dotnet: bool) -> Vec<u8> {
        let mut types: Vec<u32> = Vec::new();
        for entry in leaves {
            if !types.contains(&entry.type_id) {
                types.push(entry.type_id);
            }
        }
        let mut ids_by_type: Vec<Vec<u16>> = Vec::new();
        for type_id in &types {
            let mut ids: Vec<u16> = Vec::new();
            for entry in leaves.iter().filter(|l| l.type_id == *type_id) {
                if !ids.contains(&entry.id) {
                    ids.push(entry.id);
                }
            }
            ids_by_type.push(ids);
        }
        // Node sizes in layout order: root, type nodes, id
        // nodes.
        let mut node_sizes: Vec<usize> = vec![16 + 8 * types.len()];
        for ids in &ids_by_type {
            node_sizes.push(16 + 8 * ids.len());
        }
        for (type_id, ids) in types.iter().zip(&ids_by_type) {
            for id in ids {
                let count = leaves
                    .iter()
                    .filter(|l| l.type_id == *type_id && l.id == *id)
                    .count();
                node_sizes.push(16 + 8 * count);
            }
        }
        let mut node_offsets: Vec<usize> = Vec::new();
        let mut cursor = 0_usize;
        for size in &node_sizes {
            node_offsets.push(cursor);
            cursor += size;
        }
        let data_entries_at = cursor;
        let blobs_at = data_entries_at + 16 * leaves.len();
        let mut blob_offsets: Vec<usize> = Vec::new();
        let mut blob_cursor = blobs_at;
        for entry in leaves {
            blob_offsets.push(blob_cursor);
            blob_cursor += entry.data.len();
        }
        let region_len = blob_cursor;
        let mut region = vec![0_u8; region_len];
        // Root entries.
        for (index, type_id) in types.iter().enumerate() {
            put_entry(
                &mut region,
                node_offsets[0] + 16 + 8 * index,
                *type_id,
                0x8000_0000 | node_offsets[1 + index] as u32,
            );
        }
        region[node_offsets[0] + 14..node_offsets[0] + 16]
            .copy_from_slice(&(types.len() as u16).to_le_bytes());
        // Type nodes and id nodes.
        let mut id_node_index = 1 + types.len();
        for (type_index, (type_id, ids)) in types.iter().zip(&ids_by_type).enumerate() {
            let node = node_offsets[1 + type_index];
            region[node + 14..node + 16].copy_from_slice(&(ids.len() as u16).to_le_bytes());
            for (id_index, id) in ids.iter().enumerate() {
                put_entry(
                    &mut region,
                    node + 16 + 8 * id_index,
                    u32::from(*id),
                    0x8000_0000 | node_offsets[id_node_index] as u32,
                );
                let id_node = node_offsets[id_node_index];
                let members: Vec<usize> = leaves
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| l.type_id == *type_id && l.id == *id)
                    .map(|(index, _)| index)
                    .collect();
                region[id_node + 14..id_node + 16]
                    .copy_from_slice(&(members.len() as u16).to_le_bytes());
                for (slot, leaf_index) in members.iter().enumerate() {
                    put_entry(
                        &mut region,
                        id_node + 16 + 8 * slot,
                        u32::from(leaves[*leaf_index].lang),
                        (data_entries_at + 16 * leaf_index) as u32,
                    );
                }
                id_node_index += 1;
            }
        }
        // Data entries and blobs.
        for (index, entry) in leaves.iter().enumerate() {
            let at = data_entries_at + 16 * index;
            region[at..at + 4]
                .copy_from_slice(&((0x1000 + blob_offsets[index]) as u32).to_le_bytes());
            region[at + 4..at + 8].copy_from_slice(&(entry.data.len() as u32).to_le_bytes());
            region[blob_offsets[index]..blob_offsets[index] + entry.data.len()]
                .copy_from_slice(&entry.data);
        }
        // PE wrapper.
        let mut out = vec![0_u8; 0x400];
        out[0..2].copy_from_slice(b"MZ");
        out[0x3c..0x40].copy_from_slice(&128_u32.to_le_bytes());
        out[128..132].copy_from_slice(b"PE\0\0");
        let coff = 132;
        out[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        out[coff + 2..coff + 4].copy_from_slice(&2_u16.to_le_bytes());
        out[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes());
        out[coff + 18..coff + 20].copy_from_slice(&0x2022_u16.to_le_bytes());
        let opt = coff + 20;
        out[opt..opt + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        out[opt + 68..opt + 70].copy_from_slice(&3_u16.to_le_bytes());
        out[opt + 70..opt + 72].copy_from_slice(&0x4140_u16.to_le_bytes());
        out[opt + 108..opt + 112].copy_from_slice(&16_u32.to_le_bytes());
        let dirs = opt + 112;
        out[dirs + 16..dirs + 20].copy_from_slice(&0x1000_u32.to_le_bytes());
        out[dirs + 20..dirs + 24].copy_from_slice(&(region_len as u32).to_le_bytes());
        if dotnet {
            out[dirs + 112..dirs + 116].copy_from_slice(&0x2000_u32.to_le_bytes());
            out[dirs + 116..dirs + 120].copy_from_slice(&72_u32.to_le_bytes());
        }
        let sections = opt + 240;
        out[sections..sections + 8].copy_from_slice(b".rsrc\0\0\0");
        out[sections + 8..sections + 12].copy_from_slice(&(region_len as u32).to_le_bytes());
        out[sections + 12..sections + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        out[sections + 16..sections + 20].copy_from_slice(&(region_len as u32).to_le_bytes());
        out[sections + 20..sections + 24].copy_from_slice(&0x400_u32.to_le_bytes());
        out[sections + 40..sections + 48].copy_from_slice(b".text\0\0\0");
        out[sections + 48..sections + 52].copy_from_slice(&16_u32.to_le_bytes());
        out[sections + 52..sections + 56].copy_from_slice(&0x2000_u32.to_le_bytes());
        out[sections + 56..sections + 60].copy_from_slice(&16_u32.to_le_bytes());
        out[sections + 60..sections + 64]
            .copy_from_slice(&((0x400 + region_len) as u32).to_le_bytes());
        out.resize(0x400 + region_len + 16, 0);
        out[0x400..0x400 + region_len].copy_from_slice(&region);
        out
    }

    fn run_inspect(test_name: &str, bytes: &[u8]) -> (PathBuf, Value) {
        let (root, result) = run_result(test_name, bytes);
        (root, result.unwrap())
    }

    fn run_result(test_name: &str, bytes: &[u8]) -> (PathBuf, Result<Value, FathomError>) {
        let root = std::env::temp_dir().join(format!(
            "fathom-native-test-{}-{test_name}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("game.exe");
        fs::write(&target, bytes).unwrap();
        let config = Config::from_toml_str(&format!(
            "state_dir = {:?}\ntarget_roots = [{:?}]\n",
            root.join("state"),
            root,
        ))
        .unwrap();
        let args = json!({"target": target.display().to_string()});
        (root, inspect_pe_resources(&Registry::new(), &config, &args))
    }

    fn pe_facts(value: &Value) -> &Value {
        &value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "pe_resources")
            .expect("pe_resources finding")["facts"]
    }

    fn pe_rows(value: &Value) -> &Vec<Value> {
        value["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["kind"] == "entries")
            .expect("entries finding")["facts"]["entries"]
            .as_array()
            .unwrap()
    }

    fn row_of<'a>(value: &'a Value, type_name: &str, id: u64) -> &'a Value {
        pe_rows(value)
            .iter()
            .find(|row| row["type"] == type_name && row["id"] == id)
            .unwrap_or_else(|| panic!("row {type_name}/{id}"))
    }

    /// The standard fixture set: two dialogs, an icon
    /// group with two icons, a bitmap, a manifest, RCDATA.
    fn fixture_leaves() -> (Vec<TestLeaf>, Vec<u8>, Vec<u8>) {
        let png_icon: Vec<u8> = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4];
        let dib_icon: Vec<u8> = vec![0x28, 0x00, 0x00, 0x00, 16, 0, 0, 0, 32, 0, 0, 0];
        let mut group = Vec::new();
        w16(&mut group, 0);
        w16(&mut group, 1);
        w16(&mut group, 2);
        for (width, bit_count, bytes, id) in [
            (32_u8, 32_u16, png_icon.len() as u32, 101_u16),
            (16, 32, dib_icon.len() as u32, 102),
        ] {
            group.push(width);
            group.push(width);
            group.push(0);
            group.push(0);
            w16(&mut group, 1);
            w16(&mut group, bit_count);
            w32(&mut group, bytes);
            w16(&mut group, id);
        }
        let mut dib = Vec::new();
        w32(&mut dib, 40);
        w32(&mut dib, 2);
        w32(&mut dib, 2);
        w16(&mut dib, 1);
        w16(&mut dib, 24);
        dib.extend_from_slice(&[0_u8; 24]);
        dib.extend_from_slice(&[7_u8; 16]);
        let leaves = vec![
            leaf(5, 1, ex_dialog()),
            leaf(5, 2, classic_dialog()),
            leaf(14, 1, group),
            leaf(3, 101, png_icon.clone()),
            leaf(3, 102, dib_icon.clone()),
            leaf(2, 7, dib),
            leaf(24, 1, b"<assembly><id>test</id></assembly>".to_vec()),
            leaf(10, 9, (0..20_u8).collect()),
        ];
        (leaves, png_icon, dib_icon)
    }

    #[test]
    fn validation_full_resource_census() {
        let (leaves, png_icon, dib_icon) = fixture_leaves();
        let bytes = build_pe(&leaves, false);
        let (root, value) = run_inspect("pe-full", &bytes);
        assert_eq!(value["status"], "complete");
        let facts = pe_facts(&value);
        assert_eq!(facts["arch"], "x86_64");
        assert_eq!(facts["dotnet"], false);
        assert_eq!(facts["entries"], 8);
        assert_eq!(facts["types"]["RT_DIALOG"], 2);
        assert_eq!(facts["types"]["RT_ICON"], 2);
        // Extended dialog decodes to JSON.
        let dialog = &row_of(&value, "RT_DIALOG", 1)["dialog"];
        assert_eq!(dialog["extended"], true);
        assert_eq!(dialog["title"], "Settings");
        assert_eq!(dialog["font"]["name"], "Segoe UI");
        assert_eq!(dialog["font"]["size"], 9);
        assert_eq!(dialog["control_count"], 2);
        assert_eq!(dialog["controls"][0]["class"], "Button");
        assert_eq!(dialog["controls"][0]["title"], "OK");
        assert_eq!(dialog["controls"][0]["id"], 1);
        assert_eq!(dialog["controls"][1]["class"], "Static");
        assert_eq!(dialog["controls"][1]["title"], "Name:");
        // Classic dialog too.
        let classic = &row_of(&value, "RT_DIALOG", 2)["dialog"];
        assert_eq!(classic["extended"], false);
        assert_eq!(classic["title"], "Legacy");
        assert_eq!(classic["controls"][0]["class"], "Edit");
        assert_eq!(classic["controls"][0]["id"], 1001);
        // Icon group reconstruction matches a hand-built ico.
        let mut ico = Vec::new();
        w16(&mut ico, 0);
        w16(&mut ico, 1);
        w16(&mut ico, 2);
        let mut offset = 6 + 32;
        for (width, payload) in [(32_u8, &png_icon), (16, &dib_icon)] {
            ico.push(width);
            ico.push(width);
            ico.push(0);
            ico.push(0);
            w16(&mut ico, 1);
            w16(&mut ico, 32);
            w32(&mut ico, payload.len() as u32);
            w32(&mut ico, offset as u32);
            offset += payload.len();
        }
        ico.extend_from_slice(&png_icon);
        ico.extend_from_slice(&dib_icon);
        let group_row = row_of(&value, "RT_GROUP_ICON", 1);
        assert_eq!(
            group_row["icon_group"]["ico_sha256"],
            json!(sha256_hex(&ico))
        );
        assert_eq!(group_row["icon_group"]["ico_bytes"], json!(ico.len()));
        assert_eq!(group_row["icon_group"]["images"][0]["missing"], false);
        // Bitmap reconstruction.
        let bitmap_row = row_of(&value, "RT_BITMAP", 7);
        assert_eq!(bitmap_row["bitmap"]["width"], 2);
        assert_eq!(bitmap_row["bitmap"]["bit_count"], 24);
        // Manifest inlined; RCDATA fingerprinted.
        let manifest_row = row_of(&value, "RT_MANIFEST", 1);
        assert!(
            manifest_row["manifest_text"]
                .as_str()
                .unwrap()
                .contains("<assembly>")
        );
        let rcdata_row = row_of(&value, "RT_RCDATA", 9);
        assert_eq!(rcdata_row["first16"], "000102030405060708090a0b0c0d0e0f");
        // Icon format sniffing.
        assert_eq!(row_of(&value, "RT_ICON", 101)["icon_format"], "png");
        assert_eq!(row_of(&value, "RT_ICON", 102)["icon_format"], "dib");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_dotnet_directory_flag() {
        let (leaves, _, _) = fixture_leaves();
        let bytes = build_pe(&leaves, true);
        let (root, value) = run_inspect("pe-dotnet", &bytes);
        assert_eq!(pe_facts(&value)["dotnet"], true);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn validation_no_resources_is_an_unknown() {
        let (leaves, _, _) = fixture_leaves();
        let mut bytes = build_pe(&leaves, false);
        // Zero the resource data-directory entry (optional
        // header at 152, directories at +112, entry 2 at
        // +16): the PE now carries no .rsrc at all.
        bytes[152 + 112 + 16..152 + 112 + 24].copy_from_slice(&[0_u8; 8]);
        let (root, value) = run_inspect("pe-empty", &bytes);
        assert_eq!(value["status"], "partial");
        assert_eq!(pe_facts(&value)["entries"], 0);
        assert!(
            value["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unknown| unknown["aspect"] == "resources")
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_not_a_pe_is_refused() {
        let (root, result) = run_result("pe-notpe", b"just some text, not an executable");
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedTarget);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_truncated_resource_region_is_typed() {
        let (leaves, _, _) = fixture_leaves();
        let mut bytes = build_pe(&leaves, false);
        bytes.truncate(0x400 + 40);
        let (root, result) = run_result("pe-truncated", &bytes);
        assert!(result.is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_directory_count_lie_is_typed() {
        let (leaves, _, _) = fixture_leaves();
        let mut bytes = build_pe(&leaves, false);
        // Root directory id-count field (resource base +
        // 14) claims 5000 entries.
        bytes[0x400 + 14..0x400 + 16].copy_from_slice(&5000_u16.to_le_bytes());
        let (root, result) = run_result("pe-count-lie", &bytes);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_directory_cycle_is_typed() {
        let (leaves, _, _) = fixture_leaves();
        let mut bytes = build_pe(&leaves, false);
        // The first type node sits right after the root
        // (root = 16 + 8*6 entries). Point its first entry
        // back at the root (offset 0, subdirectory bit).
        let root_entries = 6;
        let type_node = 16 + 8 * root_entries;
        let entry_at = 0x400 + type_node + 16 + 4;
        bytes[entry_at..entry_at + 4].copy_from_slice(&0x8000_0000_u32.to_le_bytes());
        let (root, result) = run_result("pe-cycle", &bytes);
        let error = result.unwrap_err();
        assert_eq!(error.code, ErrorCode::ArtifactIntegrityMismatch);
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn adversarial_dialog_garbage_is_a_row_fact() {
        let leaves = vec![leaf(5, 1, vec![1, 2, 3])];
        let bytes = build_pe(&leaves, false);
        let (root, value) = run_inspect("pe-dialog-garbage", &bytes);
        assert_eq!(value["status"], "partial");
        let row = &pe_rows(&value)[0];
        assert!(row.get("parse_error").is_some());
        assert!(
            value["unknowns"]
                .as_array()
                .unwrap()
                .iter()
                .any(|unknown| unknown["aspect"] == "dialog decode")
        );
        fs::remove_dir_all(&root).ok();
    }
}

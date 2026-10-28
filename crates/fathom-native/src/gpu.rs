//! GPU code-object reader (REA-adaptation S7), implemented
//! directly over goblin's ELF reader.
//!
//! Three subject shapes, one tool:
//!
//! - A standalone AMDGPU code object: an ELF whose machine
//!   is `EM_AMDGPU` (224). The reader reports the ABI facts
//!   (OSABI lane, code-object version from the ABI version
//!   byte, target from the `e_flags` machine field, XNACK and
//!   SRAMECC feature fields), the sections, the kernel
//!   inventory (FUNC symbols in executable sections plus
//!   their `.kd` kernel-descriptor objects), and the kernel
//!   metadata from the `NT_AMDGPU_METADATA` note — MessagePack
//!   for code-object v3+, YAML for v2, read with a bounded
//!   hand-rolled MessagePack reader.
//! - A Clang offload bundle (`__CLANG_OFFLOAD_BUNDLE__`):
//!   the entry table (target id, offset, size), with AMDGCN
//!   entries recursed into as code objects.
//! - A host binary with bundles *embedded* in it (the fat
//!   binary shape): the bundle magic is located by a bounded
//!   scan and each bundle is read as above. This is the
//!   curative case — GPU code that head classification reads
//!   as an ordinary host executable.
//!
//! Honesty contract: instruction streams are inventoried,
//! never decoded (no GPU ISA disassembly is claimed); a
//! metadata blob that is neither MessagePack nor YAML-shaped
//! is an unknown, not a guess; bundle entries pointing
//! outside the file are overrun rows, never believed.

use serde_json::{Value, json};
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file};
use fathom_core::limits::GPU_KERNELS_MAX;
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

/// ELF machine number for AMDGPU.
pub const EM_AMDGPU: u16 = 224;
/// The Clang offload-bundle magic.
pub const OFFLOAD_BUNDLE_MAGIC: &[u8; 24] = b"__CLANG_OFFLOAD_BUNDLE__";
/// Note type carrying AMDGPU kernel metadata.
const NT_AMDGPU_METADATA: u32 = 32;
/// Embedded bundles found by the host scan are capped.
const BUNDLE_SCAN_MAX: usize = 16;
/// MessagePack walk bounds.
const MSGPACK_DEPTH_MAX: usize = 32;
const MSGPACK_VALUES_MAX: usize = 100_000;

/// Decoded `e_flags` facts for an AMDGPU code object.
#[derive(Debug)]
pub struct GpuTarget {
    /// Raw e_flags word.
    pub flags: u32,
    /// Machine (target) field: the low byte of e_flags.
    pub mach: u32,
    /// Target name for the machine values this reader can
    /// name with confidence; numeric otherwise.
    pub mach_name: Option<&'static str>,
    /// SRAMECC feature field (bits 10–11): none/any/off/on.
    pub sramecc: &'static str,
    /// XNACK feature field (bits 8–9): none/any/off/on.
    pub xnack: &'static str,
}

fn feature_field(flags: u32, shift: u32) -> &'static str {
    match (flags >> shift) & 0x3 {
        0 => "unspecified",
        1 => "any",
        2 => "off",
        _ => "on",
    }
}

/// Decode the target facts from an AMDGPU ELF's flags.
pub fn gpu_target(flags: u32) -> GpuTarget {
    let mach = flags & 0xff;
    GpuTarget {
        flags,
        mach,
        mach_name: match mach {
            0x2c => Some("gfx900"),
            0x2d => Some("gfx902"),
            0x2e => Some("gfx904"),
            0x2f => Some("gfx906"),
            0x30 => Some("gfx908"),
            0x31 => Some("gfx909"),
            0x32 => Some("gfx90c"),
            0x3f => Some("gfx90a"),
            _ => None,
        },
        sramecc: feature_field(flags, 10),
        xnack: feature_field(flags, 8),
    }
}

/// One kernel from the symbol table.
#[derive(Debug)]
pub struct GpuKernel {
    pub has_descriptor: bool,
    pub name: String,
    pub size: u64,
}

/// A parsed AMDGPU code object.
#[derive(Debug)]
pub struct GpuCodeObject {
    /// EI_ABIVERSION: code-object version is this + 2 for
    /// the HSA lane.
    pub abi_version: u8,
    pub kernels: Vec<GpuKernel>,
    /// Kernel metadata (msgpack decoded to JSON, or the YAML
    /// text's kernel names as a derived extraction).
    pub metadata: Option<Value>,
    /// Why metadata is absent/unread, when it is.
    pub metadata_note: Option<String>,
    pub osabi: u8,
    pub sections: Vec<Value>,
    pub target: GpuTarget,
}

fn gpu_error(message: String) -> FathomError {
    FathomError::new(ErrorCode::UnsupportedTarget, message).with_target("gpu code object")
}

/// True when the bytes are an ELF for the AMDGPU machine.
pub fn is_amdgpu_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 20
        && &bytes[0..4] == b"\x7fELF"
        && u16::from_le_bytes([bytes[18], bytes[19]]) == EM_AMDGPU
}

/// Parse one AMDGPU code object from its bytes.
pub fn parse_gpu_elf(bytes: &[u8]) -> Result<GpuCodeObject, FathomError> {
    let elf =
        goblin::elf::Elf::parse(bytes).map_err(|e| gpu_error(format!("ELF parse failed: {e}")))?;
    if elf.header.e_machine != EM_AMDGPU {
        return Err(gpu_error(format!(
            "ELF machine {} is not EM_AMDGPU (224)",
            elf.header.e_machine
        )));
    }
    let osabi = elf.header.e_ident[goblin::elf::header::EI_OSABI];
    let abi_version = elf.header.e_ident[goblin::elf::header::EI_ABIVERSION];
    let mut sections = Vec::new();
    let mut executable: Vec<usize> = Vec::new();
    for (index, section) in elf.section_headers.iter().enumerate() {
        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
        if section.sh_flags & u64::from(goblin::elf::section_header::SHF_EXECINSTR) != 0 {
            executable.push(index);
        }
        sections.push(json!({
            "index": index,
            "name": name,
            "size": section.sh_size,
            "type": section.sh_type,
        }));
    }
    // Kernel inventory: FUNC symbols defined in executable
    // sections; a `<name>.kd` OBJECT symbol marks the
    // kernel descriptor's presence.
    let mut descriptors: Vec<String> = Vec::new();
    let mut kernels: Vec<GpuKernel> = Vec::new();
    for symbol in elf.syms.iter() {
        let name = elf.strtab.get_at(symbol.st_name).unwrap_or("");
        if name.is_empty() || symbol.st_shndx == 0 {
            continue;
        }
        if symbol.st_type() == goblin::elf::sym::STT_OBJECT {
            if let Some(base) = name.strip_suffix(".kd") {
                descriptors.push(base.to_string());
            }
            continue;
        }
        if symbol.st_type() == goblin::elf::sym::STT_FUNC && executable.contains(&symbol.st_shndx) {
            kernels.push(GpuKernel {
                has_descriptor: false,
                name: name.to_string(),
                size: symbol.st_size,
            });
        }
    }
    for kernel in &mut kernels {
        kernel.has_descriptor = descriptors.iter().any(|base| base == &kernel.name);
    }
    kernels.sort_by(|a, b| a.name.cmp(&b.name));
    kernels.truncate(GPU_KERNELS_MAX);
    // Kernel metadata: the NT_AMDGPU_METADATA note in any
    // SHT_NOTE section.
    let mut metadata = None;
    let mut metadata_note = None;
    for section in &elf.section_headers {
        if section.sh_type != goblin::elf::section_header::SHT_NOTE {
            continue;
        }
        let start = section.sh_offset as usize;
        let Some(note_bytes) = bytes.get(start..start + section.sh_size as usize) else {
            continue;
        };
        for (name, n_type, desc) in iter_notes(note_bytes) {
            if n_type != NT_AMDGPU_METADATA || name != "AMDGPU" {
                continue;
            }
            match parse_gpu_metadata(desc) {
                Ok(value) => metadata = Some(value),
                Err(note_text) => metadata_note = Some(note_text),
            }
        }
    }
    if metadata.is_none() && metadata_note.is_none() {
        metadata_note = Some("no NT_AMDGPU_METADATA note is present".to_string());
    }
    Ok(GpuCodeObject {
        abi_version,
        kernels,
        metadata,
        metadata_note,
        osabi,
        sections,
        target: gpu_target(elf.header.e_flags),
    })
}

/// Iterate the notes in one SHT_NOTE section body: each is
/// a namesz/descsz/type triple of little-endian u32s, a
/// NUL-terminated name padded to 4 bytes, and the descriptor
/// padded to 4 bytes. Malformed framing ends the iteration.
fn iter_notes(body: &[u8]) -> Vec<(String, u32, &[u8])> {
    let mut notes = Vec::new();
    let mut pos = 0_usize;
    while pos + 12 <= body.len() {
        let field = |offset: usize| -> u32 {
            u32::from_le_bytes([
                body[pos + offset],
                body[pos + offset + 1],
                body[pos + offset + 2],
                body[pos + offset + 3],
            ])
        };
        let namesz = field(0) as usize;
        let descsz = field(4) as usize;
        let n_type = field(8);
        let name_start = pos + 12;
        let Some(name_raw) = body.get(name_start..name_start + namesz) else {
            break;
        };
        let name = String::from_utf8_lossy(name_raw)
            .trim_end_matches('\0')
            .to_string();
        let desc_start = name_start + namesz.div_ceil(4) * 4;
        let Some(desc) = body.get(desc_start..desc_start + descsz) else {
            break;
        };
        notes.push((name, n_type, desc));
        pos = desc_start + descsz.div_ceil(4) * 4;
    }
    notes
}

/// Parse AMDGPU metadata: MessagePack (v3+) decoded to JSON;
/// YAML (v2) reduced to its kernel names as a derived fact.
fn parse_gpu_metadata(desc: &[u8]) -> Result<Value, String> {
    if desc.is_empty() {
        return Err("metadata note is empty".to_string());
    }
    let first = desc[0];
    if (0x80..=0x8f).contains(&first) || first == 0xde || first == 0xdf {
        let mut reader = MsgpackReader {
            bytes: desc,
            pos: 0,
            values: 0,
        };
        return reader
            .read_value(0)
            .map_err(|message| format!("metadata MessagePack did not decode: {message}"));
    }
    if let Ok(text) = std::str::from_utf8(desc)
        && (text.contains("Kernels:") || text.contains("amdhsa.kernels"))
    {
        // YAML v2 metadata: kernel entries carry a
        // `Name:` field. Extract those names only; the
        // full YAML document is retained as text size.
        let names: Vec<Value> = text
            .lines()
            .filter_map(|line| line.trim().strip_prefix("Name:"))
            .map(|name| json!({"name": name.trim()}))
            .collect();
        return Ok(json!({
            "format": "yaml (code object v2)",
            "kernel_names": names,
            "text_bytes": desc.len(),
        }));
    }
    Err("metadata note is neither MessagePack nor YAML-shaped".to_string())
}

// ----------------------------------------------------------------
// Bounded MessagePack reader (to JSON)

struct MsgpackReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    values: usize,
}

impl MsgpackReader<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], String> {
        let slice = self
            .bytes
            .get(self.pos..self.pos + count)
            .ok_or_else(|| "msgpack stream ends early".to_string())?;
        self.pos += count;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn uint(&mut self, width: usize) -> Result<u64, String> {
        let raw = self.take(width)?;
        let mut value = 0_u64;
        for byte in raw {
            value = (value << 8) | u64::from(*byte);
        }
        Ok(value)
    }

    fn read_value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MSGPACK_DEPTH_MAX {
            return Err("msgpack nesting exceeds the depth bound".to_string());
        }
        self.values += 1;
        if self.values > MSGPACK_VALUES_MAX {
            return Err("msgpack value count exceeds the bound".to_string());
        }
        let marker = self.byte()?;
        match marker {
            0x00..=0x7f => Ok(json!(marker)),
            0xe0..=0xff => Ok(json!(marker as i8)),
            0x80..=0x8f => self.read_map((marker & 0x0f) as usize, depth),
            0x90..=0x9f => self.read_array((marker & 0x0f) as usize, depth),
            0xa0..=0xbf => self.read_str((marker & 0x1f) as usize),
            0xc0 => Ok(Value::Null),
            0xc2 => Ok(json!(false)),
            0xc3 => Ok(json!(true)),
            0xc4..=0xc6 => {
                let len = self.uint(usize::from(marker - 0xc4) + 1)? as usize;
                let raw = self.take(len)?;
                Ok(json!({"$bin_hex_prefix": hex_prefix(raw), "len": len}))
            }
            0xc7..=0xc9 => {
                let width = usize::from(marker - 0xc7) + 1;
                let len = self.uint(width)? as usize;
                let ext_type = self.byte()?;
                self.take(len)?;
                Ok(json!({"$ext_type": ext_type, "len": len}))
            }
            0xca => {
                let raw = self.take(4)?;
                Ok(json!(f32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]])))
            }
            0xcb => {
                let raw = self.take(8)?;
                Ok(json!(f64::from_be_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]
                ])))
            }
            0xcc..=0xcf => {
                let width = 1_usize << (marker - 0xcc);
                Ok(json!(self.uint(width)?))
            }
            0xd0..=0xd3 => {
                let width = 1_usize << (marker - 0xd0);
                let raw = self.take(width)?;
                let mut value = i64::from(raw[0] as i8);
                for byte in &raw[1..] {
                    value = (value << 8) | i64::from(*byte);
                }
                Ok(json!(value))
            }
            0xd4..=0xd8 => {
                let len = 1_usize << (marker - 0xd4);
                let ext_type = self.byte()?;
                self.take(len)?;
                Ok(json!({"$ext_type": ext_type, "len": len}))
            }
            0xd9..=0xdb => {
                let len = self.uint(1_usize << (marker - 0xd9))? as usize;
                self.read_str(len)
            }
            0xdc | 0xdd => {
                let len = self.uint(2_usize << (marker - 0xdc))? as usize;
                self.read_array(len, depth)
            }
            0xde | 0xdf => {
                let len = self.uint(2_usize << (marker - 0xde))? as usize;
                self.read_map(len, depth)
            }
            other => Err(format!("msgpack marker 0x{other:02x} is not known")),
        }
    }

    fn read_str(&mut self, len: usize) -> Result<Value, String> {
        let raw = self.take(len)?;
        Ok(json!(String::from_utf8_lossy(raw)))
    }

    fn read_array(&mut self, len: usize, depth: usize) -> Result<Value, String> {
        let mut items = Vec::with_capacity(len.min(4096));
        for _ in 0..len {
            items.push(self.read_value(depth + 1)?);
        }
        Ok(json!(items))
    }

    fn read_map(&mut self, len: usize, depth: usize) -> Result<Value, String> {
        let mut map = serde_json::Map::with_capacity(len.min(4096));
        for _ in 0..len {
            let key = self.read_value(depth + 1)?;
            let value = self.read_value(depth + 1)?;
            let key_text = match &key {
                Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            map.insert(key_text, value);
        }
        Ok(Value::Object(map))
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(16)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// ----------------------------------------------------------------
// Clang offload bundles

/// One offload-bundle entry.
#[derive(Debug)]
pub struct BundleEntry {
    /// Absolute offset of the entry's bytes in the file.
    pub offset: usize,
    pub size: usize,
    pub target_id: String,
}

/// A parsed offload bundle starting at `base` in the file.
#[derive(Debug)]
pub struct OffloadBundle {
    pub base: usize,
    pub entries: Vec<BundleEntry>,
}

/// Locate offload-bundle magics in a file image (bounded).
pub fn find_offload_bundles(bytes: &[u8]) -> Vec<usize> {
    let mut found = Vec::new();
    let mut start = 0_usize;
    while start + OFFLOAD_BUNDLE_MAGIC.len() <= bytes.len() && found.len() < BUNDLE_SCAN_MAX {
        match bytes[start..]
            .windows(OFFLOAD_BUNDLE_MAGIC.len())
            .position(|window| window == OFFLOAD_BUNDLE_MAGIC)
        {
            Some(index) => {
                found.push(start + index);
                start += index + OFFLOAD_BUNDLE_MAGIC.len();
            }
            None => break,
        }
    }
    found
}

/// Parse the bundle header at `base`. Entry offsets in the
/// bundle are relative to the bundle's start.
pub fn parse_offload_bundle(bytes: &[u8], base: usize) -> Result<OffloadBundle, FathomError> {
    let at = |offset: usize, count: usize| -> Option<&[u8]> {
        bytes.get(base.checked_add(offset)?..base.checked_add(offset + count)?)
    };
    let u64_at = |offset: usize| -> Option<u64> {
        at(offset, 8).map(|raw| {
            u64::from_le_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ])
        })
    };
    if at(0, 24) != Some(OFFLOAD_BUNDLE_MAGIC) {
        return Err(gpu_error(format!(
            "no offload-bundle magic at offset {base}"
        )));
    }
    let count = u64_at(24)
        .ok_or_else(|| gpu_error("bundle header ends inside the entry count".to_string()))?
        as usize;
    if count > 1024 {
        return Err(gpu_error(format!(
            "bundle declares {count} entries, beyond the census bound"
        )));
    }
    let mut entries = Vec::with_capacity(count);
    let mut pos = 32_usize;
    for _ in 0..count {
        let offset = u64_at(pos)
            .ok_or_else(|| gpu_error("bundle entry table is truncated".to_string()))?
            as usize;
        let size = u64_at(pos + 8)
            .ok_or_else(|| gpu_error("bundle entry table is truncated".to_string()))?
            as usize;
        let id_len = u64_at(pos + 16)
            .ok_or_else(|| gpu_error("bundle entry table is truncated".to_string()))?
            as usize;
        let id_raw = at(pos + 24, id_len)
            .ok_or_else(|| gpu_error("bundle entry id runs past the file".to_string()))?;
        entries.push(BundleEntry {
            offset: base + offset,
            size,
            target_id: String::from_utf8_lossy(id_raw).into_owned(),
        });
        pos += 24 + id_len;
    }
    Ok(OffloadBundle { base, entries })
}

// ----------------------------------------------------------------
// Tool surface

fn code_object_facts(object: &GpuCodeObject) -> Value {
    json!({
        "abi_version_byte": object.abi_version,
        "code_object_version": object.abi_version.saturating_add(2),
        "kernels": object.kernels.iter().map(|kernel| json!({
            "has_descriptor": kernel.has_descriptor,
            "name": kernel.name,
            "size": kernel.size,
        })).collect::<Vec<_>>(),
        "metadata": object.metadata,
        "metadata_note": object.metadata_note,
        "osabi": object.osabi,
        "sections": object.sections,
        "target": {
            "e_flags": object.target.flags,
            "mach": object.target.mach,
            "mach_name": object.target.mach_name,
            "sramecc": object.target.sramecc,
            "xnack": object.target.xnack,
        },
    })
}

fn bundle_rows(bytes: &[u8], bundle: &OffloadBundle, evidence: &mut Evidence) -> Vec<Value> {
    let mut rows = Vec::new();
    for entry in &bundle.entries {
        let mut row = json!({
            "offset": entry.offset,
            "size": entry.size,
            "target_id": entry.target_id,
        });
        match bytes.get(entry.offset..entry.offset + entry.size) {
            Some(slice) if is_amdgpu_elf(slice) => match parse_gpu_elf(slice) {
                Ok(object) => {
                    row["gpu"] = code_object_facts(&object);
                }
                Err(error) => {
                    row["gpu_error"] = json!(error.message);
                }
            },
            Some(_) => {
                row["kind"] = json!("not an AMDGPU code object");
            }
            None => {
                row["kind"] = json!("overrun: entry points outside the file");
                evidence.add_unknown(
                    "bundle entry",
                    format!(
                        "bundle entry {} declares bytes outside the file",
                        entry.target_id
                    ),
                );
            }
        }
        rows.push(row);
    }
    rows
}

pub fn inspect_gpu_code_object(
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
    let mut evidence = Evidence::new("inspect_gpu_code_object", "gpu");
    evidence.subject = Some(subject);
    if is_amdgpu_elf(&bytes) {
        let object = parse_gpu_elf(&bytes)?;
        if object.metadata.is_none()
            && let Some(note) = &object.metadata_note
        {
            evidence.add_unknown("kernel metadata", note.clone());
        }
        evidence.add_finding(Finding::new(
            "gpu_code_object",
            Confidence::Observed,
            code_object_facts(&object),
        ));
        evidence.add_unknown(
            "instruction decode",
            "GPU kernel instruction streams are inventoried by section and \
             symbol size, not disassembled — no GPU ISA decoder is implemented \
             in this stage",
        );
        evidence.coverage.examined = 1;
        evidence.coverage.total = 1;
        evidence.coverage.exhaustive = true;
        return Ok(evidence.to_value());
    }
    let bases = find_offload_bundles(&bytes);
    if bases.is_empty() {
        return Err(gpu_error(
            "target is neither an AMDGPU code object nor a file carrying a \
             Clang offload bundle"
                .to_string(),
        ));
    }
    let mut bundles_json = Vec::new();
    for base in &bases {
        let bundle = parse_offload_bundle(&bytes, *base)?;
        let rows = bundle_rows(&bytes, &bundle, &mut evidence);
        bundles_json.push(json!({"base": base, "entries": rows}));
    }
    evidence.add_finding(Finding::new(
        "offload_bundles",
        Confidence::Observed,
        json!({"bundles": bundles_json, "count": bases.len()}),
    ));
    evidence.add_unknown(
        "instruction decode",
        "GPU kernel instruction streams are inventoried, not disassembled — \
         no GPU ISA decoder is implemented in this stage",
    );
    evidence.coverage.examined = bases.len() as u64;
    evidence.coverage.total = bases.len() as u64;
    evidence.coverage.exhaustive = true;
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ELF: &[u8] = include_bytes!("../tests/fixtures/amdgpu_kernel.elf");
    const SAMPLE_BUNDLE: &[u8] = include_bytes!("../tests/fixtures/clang_offload_bundle.bin");

    #[test]
    fn validation_real_shaped_code_object() {
        assert!(is_amdgpu_elf(SAMPLE_ELF));
        let object = parse_gpu_elf(SAMPLE_ELF).expect("code object parses");
        assert_eq!(object.osabi, 64);
        assert_eq!(object.abi_version, 1);
        assert_eq!(object.target.mach_name, Some("gfx900"));
        assert_eq!(object.target.xnack, "any");
        let names: Vec<&str> = object
            .kernels
            .iter()
            .map(|kernel| kernel.name.as_str())
            .collect();
        assert_eq!(names, ["kernel_a", "kernel_b"]);
        assert!(object.kernels[0].has_descriptor);
        assert!(!object.kernels[1].has_descriptor);
        let metadata = object.metadata.expect("metadata decoded");
        let kernels = metadata["amdhsa.kernels"].as_array().expect("kernel list");
        assert_eq!(kernels.len(), 2);
        assert_eq!(kernels[0][".name"], "kernel_a");
        assert_eq!(kernels[0][".sgpr_count"], 16);
    }

    #[test]
    fn validation_offload_bundle_with_embedded_gpu() {
        let bases = find_offload_bundles(SAMPLE_BUNDLE);
        assert_eq!(bases, [0]);
        let bundle = parse_offload_bundle(SAMPLE_BUNDLE, 0).expect("bundle parses");
        assert_eq!(bundle.entries.len(), 2);
        assert_eq!(bundle.entries[0].target_id, "host-x86_64-unknown-linux-gnu");
        assert_eq!(bundle.entries[1].target_id, "amdgcn-amd-amdhsa--gfx900");
        let entry = &bundle.entries[1];
        let slice = &SAMPLE_BUNDLE[entry.offset..entry.offset + entry.size];
        assert!(is_amdgpu_elf(slice));
    }

    #[test]
    fn adversarial_non_amdgpu_elf_refused_by_parser() {
        // Flip the machine field to x86-64 (62).
        let mut bytes = SAMPLE_ELF.to_vec();
        bytes[18] = 62;
        bytes[19] = 0;
        assert!(!is_amdgpu_elf(&bytes));
        assert!(parse_gpu_elf(&bytes).is_err());
    }

    #[test]
    fn adversarial_bundle_entry_count_beyond_bound_refused() {
        let mut bytes = SAMPLE_BUNDLE.to_vec();
        bytes[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_offload_bundle(&bytes, 0).is_err());
    }

    #[test]
    fn adversarial_truncated_msgpack_metadata_is_a_note_not_a_panic() {
        // Corrupt the note's msgpack: cut the metadata map
        // short by shrinking the note section is complex;
        // instead call the metadata parser on a truncated
        // map directly.
        let result = parse_gpu_metadata(&[0x81, 0xa3, b'f', b'o']);
        assert!(result.is_err());
    }

    #[test]
    fn adversarial_plain_elf_is_not_a_gpu_object() {
        let mut bytes = vec![0_u8; 64];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[18] = 62; // x86-64
        assert!(!is_amdgpu_elf(&bytes));
        assert!(find_offload_bundles(&bytes).is_empty());
    }
}

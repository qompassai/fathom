//! Binary layout inspection with goblin (SPEC §9.1): container
//! facts read directly from the file — no engine. Mitigation
//! entries are candidates with their basis named; presence in a
//! header is evidence about the artifact, not a proof about its
//! runtime behavior.

use serde_json::{Value, json};
use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::FathomError;
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file};
use fathom_core::paths;
use fathom_core::registry::{Registry, require_str};

const PT_GNU_RELRO: u32 = 0x6474_e552;
const PT_GNU_STACK: u32 = 0x6474_e551;
const DT_BIND_NOW: u64 = 24;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;
const DLL_ASLR: u16 = 0x0040;
const DLL_CFG: u16 = 0x4000;
const DLL_NO_SEH: u16 = 0x0400;
const DLL_NX: u16 = 0x0100;
const PF_X: u32 = 1;
const SYMBOL_NAMES_LISTED_MAX: usize = 256;

pub fn inspect_binary_layout(
    _: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value, FathomError> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    let subject = subject_for_file(&path)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        FathomError::new(
            fathom_core::error::ErrorCode::TargetUnavailable,
            format!("cannot read target: {e}"),
        )
    })?;
    let mut evidence = Evidence::new("inspect_binary_layout", "native-layout");
    evidence.subject = Some(subject);
    evidence.coverage.examined = 1;
    evidence.coverage.total = 1;
    match goblin::Object::parse(&bytes) {
        Ok(goblin::Object::Archive(archive)) => {
            let members: Vec<&str> = archive.members().into_iter().collect();
            evidence.add_finding(Finding::new(
                "layout",
                Confidence::Observed,
                json!({
                    "format": "archive",
                    "member_count": members.len(),
                    "members_sample": members.iter().take(64).collect::<Vec<_>>(),
                }),
            ));
            evidence.coverage.exhaustive = true;
        }
        Ok(goblin::Object::Elf(elf)) => elf_layout(&mut evidence, &elf),
        Ok(goblin::Object::Mach(mach)) => mach_layout(&mut evidence, &mach, &bytes),
        Ok(goblin::Object::PE(pe)) => pe_layout(&mut evidence, &pe),
        Ok(goblin::Object::Unknown(magic)) => {
            evidence.add_finding(Finding::new(
                "layout",
                Confidence::Observed,
                json!({"format": "unknown", "magic": format!("{magic:#06x}")}),
            ));
            evidence.add_unknown("layout", "goblin does not recognize this container format");
        }
        Ok(_) => {
            evidence.add_finding(Finding::new(
                "layout",
                Confidence::Observed,
                json!({"format": "other"}),
            ));
            evidence.add_unknown(
                "layout",
                "goblin parsed a container kind this tool does not detail yet",
            );
        }
        Err(error) => {
            evidence.add_finding(Finding::new(
                "layout",
                Confidence::Observed,
                json!({"format": "unparseable", "parser_error": error.to_string()}),
            ));
            evidence.add_unknown("layout", "the container parser rejected the file");
        }
    }
    Ok(evidence.to_value())
}

fn elf_layout(evidence: &mut Evidence, elf: &goblin::elf::Elf) {
    let header = &elf.header;
    let machine = match header.e_machine {
        3 => "x86".to_string(),
        40 => "ARM".to_string(),
        62 => "x86-64".to_string(),
        183 => "AArch64".to_string(),
        243 => "RISC-V".to_string(),
        other => format!("machine-{other}"),
    };
    let program_headers: Vec<Value> = elf
        .program_headers
        .iter()
        .map(|ph| {
            json!({
                "flags": flags_rwe(ph.p_flags),
                "memsz": ph.p_memsz,
                "type": phdr_type_name(ph.p_type),
                "vaddr": format!("{:#x}", ph.p_vaddr),
            })
        })
        .collect();
    let sections: Vec<Value> = elf
        .section_headers
        .iter()
        .map(|sh| {
            json!({
                "address": format!("{:#x}", sh.sh_addr),
                "name": elf.shdr_strtab.get_at(sh.sh_name).unwrap_or(""),
                "size": sh.sh_size,
            })
        })
        .collect();
    evidence.add_finding(Finding::new(
        "layout",
        Confidence::Observed,
        json!({
            "byte_order": if header.e_ident[5] == 1 { "little" } else { "big" },
            "class_bits": if header.e_ident[4] == 2 { 64 } else { 32 },
            "dynamic_symbol_count": elf.dynsyms.len(),
            "entry": format!("{:#x}", header.e_entry),
            "format": "ELF",
            "interpreter": elf.interpreter,
            "libraries": elf.libraries,
            "machine": machine,
            "object_type": header.e_type,
            "program_headers": program_headers,
            "relocation_count": elf.dynrelas.iter().count()
                + elf.dynrels.iter().count()
                + elf.pltrelocs.iter().count(),
            "sections": sections,
            "symbol_count": elf.syms.len(),
        }),
    ));

    // SPEC §9.1 names symbols, not just counts: report bounded
    // name rows for both ELF symbol tables, mirroring the Mach-O
    // exports/imports sample pattern. Without this the layout of
    // an unstripped binary identifies no function at all.
    let (dynamic_rows, dynamic_named, dynamic_truncated) =
        elf_symbol_rows(elf.dynsyms.iter().map(|sym| {
            (
                elf.dynstrtab.get_at(sym.st_name).unwrap_or(""),
                sym.st_type(),
                sym.st_shndx != 0,
            )
        }));
    let (symbol_rows, symbol_named, symbol_truncated) =
        elf_symbol_rows(elf.syms.iter().map(|sym| {
            (
                elf.strtab.get_at(sym.st_name).unwrap_or(""),
                sym.st_type(),
                sym.st_shndx != 0,
            )
        }));
    evidence.add_finding(Finding::new(
        "symbols",
        Confidence::Observed,
        json!({
            "dynamic": {
                "count": elf.dynsyms.len(),
                "named": dynamic_named,
                "rows": dynamic_rows,
                "truncated": dynamic_truncated,
            },
            "static": {
                "count": elf.syms.len(),
                "named": symbol_named,
                "rows": symbol_rows,
                "truncated": symbol_truncated,
            },
        }),
    ));

    let gnu_stack = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_type == PT_GNU_STACK);
    let nx_stack = gnu_stack.map(|ph| ph.p_flags & PF_X == 0);
    let relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);
    let bind_now = elf.dynamic.as_ref().is_some_and(|dynamic| {
        dynamic.dyns.iter().any(|d| {
            d.d_tag == DT_BIND_NOW
                || (d.d_tag == DT_FLAGS && d.d_val & DF_BIND_NOW != 0)
                || (d.d_tag == DT_FLAGS_1 && d.d_val & DF_1_NOW != 0)
        })
    });
    let canary = elf
        .dynsyms
        .iter()
        .any(|sym| elf.dynstrtab.get_at(sym.st_name) == Some("__stack_chk_fail"));
    evidence.add_finding(Finding::new(
        "mitigation_candidates",
        Confidence::Derived,
        json!({
            "candidates": [
                {"basis": "PT_GNU_RELRO segment plus BIND_NOW dynamic flags",
                 "name": "full_relro", "present": relro && bind_now},
                {"basis": "PT_GNU_RELRO segment present",
                 "name": "relro", "present": relro},
                {"basis": "PT_GNU_STACK without PF_X",
                 "name": "nx_stack", "present": nx_stack},
                {"basis": "dynamic symbol __stack_chk_fail",
                 "name": "stack_canary", "present": canary},
            ],
        }),
    ));
    evidence.coverage.exhaustive = true;
}

/// Bounded name rows for one ELF symbol table: (rows, named
/// count, truncated). Empty names (the null symbol) are skipped;
/// the row cap keeps a huge table from flooding the envelope,
/// with truncation reported rather than silent.
fn elf_symbol_rows<'a>(
    symbols: impl Iterator<Item = (&'a str, u8, bool)>,
) -> (Vec<Value>, usize, bool) {
    let mut rows: Vec<Value> = Vec::new();
    let mut named: usize = 0;
    for (name, st_type, defined) in symbols {
        if name.is_empty() {
            continue;
        }
        named += 1;
        if rows.len() < SYMBOL_NAMES_LISTED_MAX {
            rows.push(json!({
                "defined": defined,
                "name": name,
                "type": elf_symbol_type_name(st_type),
            }));
        }
    }
    let truncated = named > rows.len();
    (rows, named, truncated)
}

fn elf_symbol_type_name(st_type: u8) -> &'static str {
    match st_type {
        0 => "notype",
        1 => "object",
        2 => "function",
        3 => "section",
        4 => "file",
        5 => "common",
        6 => "tls",
        _ => "other",
    }
}

/// Names listed in the exports/imports samples of one Mach-O
/// projection.
const MACH_NAMES_LISTED_MAX: usize = 256;

fn mach_layout(evidence: &mut Evidence, mach: &goblin::mach::Mach, bytes: &[u8]) {
    match mach {
        goblin::mach::Mach::Binary(binary) => {
            evidence.add_finding(Finding::new(
                "layout",
                Confidence::Observed,
                json!({
                    "cpu": mach_cpu_name(binary.header.cputype),
                    "cpu_type": binary.header.cputype,
                    "file_type": mach_file_type_name(binary.header.filetype),
                    "format": "Mach-O",
                    "is_64": binary.is_64,
                    "little_endian": binary.little_endian,
                    "load_command_count": binary.load_commands.len(),
                }),
            ));
            let (projection, export_error) = mach_projection(binary);
            evidence.add_finding(
                Finding::new("mach_dylib_projection", Confidence::Observed, projection)
                    .with_limitation(
                        "Projection lists the load commands, libraries, rpaths, and symbols the binary declares; it does not resolve the load graph against any filesystem.",
                    ),
            );
            if let Some(error) = export_error {
                evidence.add_unknown(
                    "mach_exports",
                    format!("export trie did not decode: {error}"),
                );
            }
            evidence.coverage.exhaustive = true;
        }
        goblin::mach::Mach::Fat(fat) => {
            let arches = fat.arches().unwrap_or_default();
            evidence.add_finding(Finding::new(
                "layout",
                Confidence::Observed,
                json!({
                    "arch_count": arches.len(),
                    "architectures": arches
                        .iter()
                        .map(|arch| json!({
                            "cpu": mach_cpu_name(arch.cputype),
                            "cpu_type": arch.cputype,
                            "offset": arch.offset,
                            "size": arch.size,
                        }))
                        .collect::<Vec<_>>(),
                    "format": "Mach-O fat",
                }),
            ));
            let mut projections = Vec::new();
            let mut all_projected = true;
            for arch in &arches {
                match goblin::mach::MachO::parse(arch.slice(bytes), 0) {
                    Ok(binary) => {
                        let (mut projection, _) = mach_projection(&binary);
                        if let Some(map) = projection.as_object_mut() {
                            map.insert("cpu".to_string(), json!(mach_cpu_name(arch.cputype)));
                        }
                        projections.push(projection);
                    }
                    Err(error) => {
                        all_projected = false;
                        evidence.add_unknown(
                            format!("mach_arch_{}", arch.cputype),
                            format!("architecture slice did not parse: {error}"),
                        );
                    }
                }
            }
            evidence.add_finding(
                Finding::new(
                    "mach_dylib_projection",
                    Confidence::Observed,
                    json!({"architectures": projections}),
                )
                .with_limitation(
                    "Projection lists what each architecture slice declares; it does not resolve the load graph against any filesystem.",
                ),
            );
            evidence.coverage.exhaustive = all_projected;
        }
    }
}

/// The dylib projection for one Mach-O (SPEC §9.4 Apple-deep):
/// load commands, linked dylibs, rpaths, segments, exports and
/// imports where the binary carries the data for them. Returns
/// the facts plus the export-trie error, when one occurred.
fn mach_projection(binary: &goblin::mach::MachO) -> (Value, Option<String>) {
    let load_commands: Vec<Value> = binary
        .load_commands
        .iter()
        .map(|command| {
            json!({
                "cmd": goblin::mach::load_command::cmd_to_str(command.command.cmd()),
                "cmdsize": command.command.cmdsize(),
                "offset": command.offset,
            })
        })
        .collect();
    let segments: Vec<Value> = binary
        .segments
        .iter()
        .map(|segment| {
            json!({
                "file_offset": segment.fileoff,
                "file_size": segment.filesize,
                "name": segment_name(&segment.segname),
                "section_count": segment.nsects,
                "vm_address": format!("{:#x}", segment.vmaddr),
                "vm_size": segment.vmsize,
            })
        })
        .collect();
    let (exports, export_error) = match binary.exports() {
        Ok(exports) => (
            json!({
                "count": exports.len(),
                "sample": exports
                    .iter()
                    .take(MACH_NAMES_LISTED_MAX)
                    .map(|export| export.name.clone())
                    .collect::<Vec<_>>(),
            }),
            None,
        ),
        Err(error) => (Value::Null, Some(error.to_string())),
    };
    let imports = match binary.imports() {
        Ok(imports) => json!({
            "count": imports.len(),
            "sample": imports
                .iter()
                .take(MACH_NAMES_LISTED_MAX)
                .map(|import| json!({"dylib": import.dylib, "name": import.name}))
                .collect::<Vec<_>>(),
        }),
        Err(_) => Value::Null,
    };
    let uuid = binary.load_commands.iter().find_map(|command| {
        if let goblin::mach::load_command::CommandVariant::Uuid(uuid_command) = &command.command {
            Some(mach_uuid_string(&uuid_command.uuid))
        } else {
            None
        }
    });
    (
        json!({
            "entry": format!("{:#x}", binary.entry),
            "exports": exports,
            "imports": imports,
            "install_name": binary.name,
            "libraries": binary.libs,
            "load_commands": load_commands,
            "rpaths": binary.rpaths,
            "segments": segments,
            "symbol_count": binary
                .symbols
                .as_ref()
                .map(|symbols| symbols.iter().count()),
            "uuid": uuid,
        }),
        export_error,
    )
}

fn mach_cpu_name(cputype: u32) -> String {
    match cputype {
        7 => "x86".to_string(),
        0x0100_0007 => "x86-64".to_string(),
        12 => "arm".to_string(),
        0x0100_000c => "arm64".to_string(),
        0x0200_000c => "arm64_32".to_string(),
        18 => "ppc".to_string(),
        0x0100_0012 => "ppc64".to_string(),
        other => format!("cputype-{other}"),
    }
}

fn mach_file_type_name(filetype: u32) -> String {
    match filetype {
        1 => "object".to_string(),
        2 => "execute".to_string(),
        3 => "fvmlib".to_string(),
        4 => "core".to_string(),
        5 => "preload".to_string(),
        6 => "dylib".to_string(),
        7 => "dylinker".to_string(),
        8 => "bundle".to_string(),
        9 => "dylib_stub".to_string(),
        10 => "dsym".to_string(),
        11 => "kext".to_string(),
        other => format!("filetype-{other}"),
    }
}

fn mach_uuid_string(uuid: &[u8; 16]) -> String {
    let hex: Vec<String> = uuid.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        hex[0..4].concat(),
        hex[4..6].concat(),
        hex[6..8].concat(),
        hex[8..10].concat(),
        hex[10..16].concat()
    )
}

fn segment_name(segname: &[u8; 16]) -> String {
    let end = segname
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(segname.len());
    String::from_utf8_lossy(&segname[..end]).into_owned()
}

fn pe_layout(evidence: &mut Evidence, pe: &goblin::pe::PE) {
    let sections: Vec<Value> = pe
        .sections
        .iter()
        .map(|section| {
            let raw_name: String = section
                .name
                .iter()
                .take_while(|b| **b != 0)
                .map(|b| *b as char)
                .collect();
            json!({
                "characteristics": format!("{:#010x}", section.characteristics),
                "name": raw_name,
                "raw_size": section.size_of_raw_data,
                "virtual_address": format!("{:#x}", section.virtual_address),
                "virtual_size": section.virtual_size,
            })
        })
        .collect();
    let mut dll_counts: Vec<(String, usize)> = Vec::new();
    for import in &pe.imports {
        match dll_counts
            .iter_mut()
            .find(|(dll, _)| dll.as_str() == import.dll)
        {
            Some((_, count)) => *count += 1,
            None => dll_counts.push((import.dll.to_string(), 1)),
        }
    }
    dll_counts.sort();
    let dll_characteristics = pe
        .header
        .optional_header
        .map(|header| header.windows_fields.dll_characteristics)
        .unwrap_or(0);
    evidence.add_finding(Finding::new(
        "layout",
        Confidence::Observed,
        json!({
            "dll_characteristics": format!("{dll_characteristics:#06x}"),
            "export_count": pe.exports.len(),
            "format": "PE",
            "import_dlls": dll_counts.iter()
                .map(|(dll, count)| json!({"count": count, "dll": dll}))
                .collect::<Vec<_>>(),
            "import_total": pe.imports.len(),
            "machine": format!("{:#06x}", pe.header.coff_header.machine),
            "sections": sections,
        }),
    ));
    evidence.add_finding(Finding::new(
        "mitigation_candidates",
        Confidence::Derived,
        json!({
            "candidates": [
                {"basis": "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
                 "name": "aslr", "present": dll_characteristics & DLL_ASLR != 0},
                {"basis": "IMAGE_DLLCHARACTERISTICS_GUARD_CF",
                 "name": "cfg", "present": dll_characteristics & DLL_CFG != 0},
                {"basis": "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
                 "name": "nx", "present": dll_characteristics & DLL_NX != 0},
                {"basis": "IMAGE_DLLCHARACTERISTICS_NO_SEH clear",
                 "name": "seh", "present": dll_characteristics & DLL_NO_SEH == 0},
            ],
        }),
    ));
    evidence.coverage.exhaustive = true;
}

fn phdr_type_name(p_type: u32) -> String {
    match p_type {
        0 => "PT_NULL".to_string(),
        1 => "PT_LOAD".to_string(),
        2 => "PT_DYNAMIC".to_string(),
        3 => "PT_INTERP".to_string(),
        4 => "PT_NOTE".to_string(),
        6 => "PT_PHDR".to_string(),
        7 => "PT_TLS".to_string(),
        PT_GNU_RELRO => "PT_GNU_RELRO".to_string(),
        PT_GNU_STACK => "PT_GNU_STACK".to_string(),
        other => format!("{other:#x}"),
    }
}

fn flags_rwe(flags: u32) -> String {
    let mut out = String::with_capacity(3);
    out.push(if flags & 4 != 0 { 'R' } else { '-' });
    out.push(if flags & 2 != 0 { 'W' } else { '-' });
    out.push(if flags & 1 != 0 { 'X' } else { '-' });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF64: header + one PT_GNU_STACK (RW) program
    /// header. Enough for goblin to parse and for the NX-stack
    /// candidate to read present.
    fn minimal_elf() -> Vec<u8> {
        let mut bytes = vec![0_u8; 64 + 56];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2; // ELFCLASS64
        bytes[5] = 1; // little endian
        bytes[6] = 1; // version
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes()); // ET_DYN
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes()); // x86-64
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum
        bytes[64..68].copy_from_slice(&PT_GNU_STACK.to_le_bytes());
        bytes[68..72].copy_from_slice(&6_u32.to_le_bytes()); // PF_R | PF_W
        bytes
    }

    #[test]
    fn adversarial_garbage_is_not_a_layout() {
        let parsed = goblin::Object::parse(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(matches!(parsed, Ok(goblin::Object::Unknown(_)) | Err(_)));
    }

    #[test]
    fn validation_minimal_elf_parses() {
        let bytes = minimal_elf();
        let object = goblin::Object::parse(&bytes).unwrap();
        let goblin::Object::Elf(elf) = object else {
            panic!("expected ELF");
        };
        assert_eq!(elf.header.e_machine, 62);
        assert_eq!(elf.program_headers.len(), 1);
        assert_eq!(elf.program_headers[0].p_type, PT_GNU_STACK);
    }

    #[test]
    fn validation_symbol_rows_carry_names_and_types() {
        let triples: Vec<(&str, u8, bool)> = vec![
            ("corpus_fib", 2, true),
            ("corpus_marker", 1, true),
            ("puts", 2, false),
        ];
        let (rows, named, truncated) = elf_symbol_rows(triples.into_iter());
        assert_eq!(named, 3);
        assert!(!truncated);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["name"], "corpus_fib");
        assert_eq!(rows[0]["type"], "function");
        assert_eq!(rows[2]["defined"], false);
    }

    #[test]
    fn adversarial_symbol_rows_skip_empty_and_cap() {
        let mut triples: Vec<(String, u8, bool)> = vec![(String::new(), 0, false)];
        for i in 0..(SYMBOL_NAMES_LISTED_MAX + 5) {
            triples.push((format!("sym_{i}"), 2, true));
        }
        let (rows, named, truncated) =
            elf_symbol_rows(triples.iter().map(|(n, t, d)| (n.as_str(), *t, *d)));
        assert_eq!(named, SYMBOL_NAMES_LISTED_MAX + 5);
        assert_eq!(rows.len(), SYMBOL_NAMES_LISTED_MAX);
        assert!(truncated);
    }
    /// A minimal Mach-O 64 dylib: header + LC_ID_DYLIB +
    /// LC_SEGMENT_64 + LC_UUID.
    fn minimal_macho() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xfeed_facf_u32.to_le_bytes());
        bytes.extend_from_slice(&0x0100_0007_u32.to_le_bytes()); // x86-64
        bytes.extend_from_slice(&3_u32.to_le_bytes()); // cpusubtype
        bytes.extend_from_slice(&6_u32.to_le_bytes()); // MH_DYLIB
        bytes.extend_from_slice(&3_u32.to_le_bytes()); // ncmds
        bytes.extend_from_slice(&144_u32.to_le_bytes()); // sizeofcmds
        bytes.extend_from_slice(&0_u32.to_le_bytes()); // flags
        bytes.extend_from_slice(&0_u32.to_le_bytes()); // reserved
        // LC_ID_DYLIB, cmdsize 48, name at offset 24.
        bytes.extend_from_slice(&0x0d_u32.to_le_bytes());
        bytes.extend_from_slice(&48_u32.to_le_bytes());
        bytes.extend_from_slice(&24_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        let name = b"/usr/lib/libdemo.dylib\0";
        bytes.extend_from_slice(name);
        bytes.resize(32 + 48, 0); // pad the command to its cmdsize
        // LC_SEGMENT_64, cmdsize 72.
        bytes.extend_from_slice(&0x19_u32.to_le_bytes());
        bytes.extend_from_slice(&72_u32.to_le_bytes());
        let mut segname = [0_u8; 16];
        segname[..6].copy_from_slice(b"__TEXT");
        bytes.extend_from_slice(&segname);
        bytes.extend([0_u8; 72 - 8 - 16]);
        // LC_UUID, cmdsize 24.
        bytes.extend_from_slice(&0x1b_u32.to_le_bytes());
        bytes.extend_from_slice(&24_u32.to_le_bytes());
        bytes.extend(0_u8..16);
        bytes
    }

    #[test]
    fn validation_macho_projection_names_install_and_uuid() {
        let bytes = minimal_macho();
        let object = goblin::Object::parse(&bytes).unwrap();
        let goblin::Object::Mach(goblin::mach::Mach::Binary(binary)) = &object else {
            panic!("expected a Mach-O binary");
        };
        let (projection, export_error) = mach_projection(binary);
        assert!(export_error.is_none());
        assert_eq!(projection["install_name"], "/usr/lib/libdemo.dylib");
        assert_eq!(projection["uuid"], "00010203-0405-0607-0809-0a0b0c0d0e0f");
        assert_eq!(projection["load_commands"].as_array().unwrap().len(), 3);
        assert_eq!(projection["segments"][0]["name"], "__TEXT",);
        assert_eq!(mach_cpu_name(binary.header.cputype), "x86-64");
        assert_eq!(mach_file_type_name(binary.header.filetype), "dylib");
    }

    #[test]
    fn validation_macho_fat_projection_covers_each_arch() {
        let binary = minimal_macho();
        let mut fat = Vec::new();
        fat.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        fat.extend_from_slice(&1_u32.to_be_bytes());
        fat.extend_from_slice(&0x0100_0007_u32.to_be_bytes());
        fat.extend_from_slice(&3_u32.to_be_bytes());
        fat.extend_from_slice(&4096_u32.to_be_bytes());
        fat.extend_from_slice(&(binary.len() as u32).to_be_bytes());
        fat.extend_from_slice(&12_u32.to_be_bytes());
        fat.resize(4096, 0);
        fat.extend_from_slice(&binary);
        let object = goblin::Object::parse(&fat).unwrap();
        let goblin::Object::Mach(mach) = &object else {
            panic!("expected a fat Mach-O");
        };
        let mut evidence = Evidence::new("inspect_binary_layout", "native-layout");
        mach_layout(&mut evidence, mach, &fat);
        let projection = evidence
            .findings
            .iter()
            .find(|finding| finding.kind == "mach_dylib_projection")
            .expect("projection finding");
        assert_eq!(
            projection.facts["architectures"][0]["install_name"],
            "/usr/lib/libdemo.dylib"
        );
        assert!(evidence.coverage.exhaustive);
    }

    #[test]
    fn adversarial_truncated_macho_is_a_parse_failure_not_a_panic() {
        let bytes = minimal_macho();
        let truncated = &bytes[..40];
        let parsed = goblin::Object::parse(truncated);
        assert!(matches!(parsed, Err(_) | Ok(goblin::Object::Unknown(_))));
    }

    #[test]
    fn adversarial_macho_without_trie_has_empty_exports_not_an_error() {
        let bytes = minimal_macho();
        let object = goblin::Object::parse(&bytes).unwrap();
        let goblin::Object::Mach(goblin::mach::Mach::Binary(binary)) = &object else {
            panic!("expected a Mach-O binary");
        };
        let (projection, export_error) = mach_projection(binary);
        assert!(export_error.is_none());
        assert_eq!(projection["exports"]["count"], 0);
        assert_eq!(projection["imports"]["count"], 0);
    }
}

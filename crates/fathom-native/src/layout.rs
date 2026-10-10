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
        Ok(goblin::Object::Mach(mach)) => mach_layout(&mut evidence, &mach),
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

fn mach_layout(evidence: &mut Evidence, mach: &goblin::mach::Mach) {
    match mach {
        goblin::mach::Mach::Binary(binary) => {
            evidence.add_finding(Finding::new(
                "layout",
                Confidence::Observed,
                json!({
                    "cpu_type": binary.header.cputype,
                    "format": "Mach-O",
                    "load_command_count": binary.load_commands.len(),
                }),
            ));
            evidence.add_unknown(
                "mach_detail",
                "Mach-O load-command detail is staged behind the binary inventory",
            );
        }
        goblin::mach::Mach::Fat(fat) => {
            evidence.add_finding(Finding::new(
                "layout",
                Confidence::Observed,
                json!({
                    "arch_count": fat.arches().map(|arches| arches.len()).unwrap_or(0),
                    "format": "Mach-O fat",
                }),
            ));
            evidence.add_unknown(
                "mach_detail",
                "per-architecture Mach-O detail is staged behind the binary inventory",
            );
        }
    }
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
}

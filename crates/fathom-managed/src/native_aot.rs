//! NativeAOT screening for PEs with no CLI header
//! (REA-adaptation S8), implemented directly.
//!
//! A NativeAOT image is a native PE: no CLI header, no BSJB
//! metadata root — `parse_pe` returns `None` for it exactly
//! as for a C++ binary. What distinguishes it is the
//! ahead-of-time .NET runtime baked into the image, and that
//! runtime leaves independent families of traces:
//!
//! - **Component strings.** The NativeAOT runtime is linked
//!   from `System.Private.*` assemblies whose names survive
//!   as UTF-8 strings in the image (`System.Private.CoreLib`
//!   and its companions: TypeLoader, Reflection.Execution,
//!   StackTraceMetadata). Distinct components are counted
//!   separately — one stray string proves nothing.
//! - **Runtime helper exports.** Images that export symbols
//!   carry the runtime's `Rh*` helper surface (`RhpNewFast`,
//!   `RhpAssignRef`, `RhGetRuntimeHelper`, ...).
//!
//! Classification rule: at least two distinct component
//! strings, plus either a runtime-helper export or a third
//! component. The verdict is `Derived` confidence — a screen,
//! not a parse. Below the bar, the screen's hits are still
//! reported as observed facts and the PE stays "native, not
//! classified": a single marker never promotes a binary.
//!
//! The inventory beyond the screen is bounded and stated:
//! the section table, the export table, and a census of
//! type-name-shaped UTF-8 strings (dotted identifiers) from
//! the image. The NativeFormat metadata graph itself — the
//! type/method tables a full NativeAOT reader would decode —
//! is NOT-IMPLEMENTED in this stage and is named as an
//! unknown wherever a classification is made: no type or
//! method fact is ever inferred from the string census.

use serde::Serialize;

/// Component-name needles: NativeAOT runtime assemblies.
/// (System.Private.Jit is deliberately absent — that is the
/// CoreCLR JIT, not AOT evidence.)
const COMPONENT_NEEDLES: &[&str] = &[
    "System.Private.CoreLib",
    "System.Private.DisabledReflection",
    "System.Private.Reflection.Execution",
    "System.Private.StackTraceMetadata",
    "System.Private.TypeLoader",
];

/// Type-name census bound.
const TYPE_NAME_CENSUS_MAX: usize = 500;
/// String-run scan bounds for the census.
const TYPE_NAME_LEN_MIN: usize = 6;
const TYPE_NAME_LEN_MAX: usize = 256;

/// One section's framing facts.
#[derive(Debug, Serialize)]
pub struct SectionFact {
    pub name: String,
    pub raw_size: u32,
    pub virtual_size: u32,
}

/// The screen's outcome for one PE.
#[derive(Debug)]
pub struct NativeAotScreen {
    /// The classification rule fired.
    pub classified: bool,
    /// Distinct System.Private.* component strings found.
    pub component_strings: Vec<String>,
    /// Runtime-helper (`Rh*`) export names found.
    pub runtime_exports: Vec<String>,
    pub sections: Vec<SectionFact>,
    /// Dotted, type-name-shaped UTF-8 strings (derived
    /// census — string facts, not type facts).
    pub type_name_census: Vec<String>,
}

/// True for the runtime-helper export shape: the `Rhp*`
/// family (`RhpNewFast` — lowercase p, uppercase after) or
/// the `Rh<Upper>*` family (`RhGetRuntimeHelper`).
fn is_runtime_export(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("Rh") else {
        return false;
    };
    if let Some(after_p) = rest.strip_prefix('p') {
        return after_p
            .chars()
            .next()
            .is_some_and(|third| third.is_ascii_uppercase());
    }
    rest.chars()
        .next()
        .is_some_and(|third| third.is_ascii_uppercase())
}

/// Byte-substring search for one needle; returns the first
/// offset.
fn find_subslice(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || bytes.len() < needle.len() {
        return None;
    }
    bytes
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Census of type-name-shaped strings: maximal printable
/// runs over the dotted-identifier charset, filtered to
/// runs that start with an uppercase letter, contain a dot,
/// and end alphanumeric — the shape of .NET type and
/// namespace names in an image's string data.
fn type_name_census(bytes: &[u8]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut start: Option<usize> = None;
    let in_charset = |byte: u8| -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'`' | b'+' | b'<' | b'>')
    };
    let flush = |found: &mut Vec<String>, from: usize, to: usize| {
        if to - from < TYPE_NAME_LEN_MIN || to - from > TYPE_NAME_LEN_MAX {
            return;
        }
        let text = &bytes[from..to];
        let Ok(text) = std::str::from_utf8(text) else {
            return;
        };
        let shaped = text.as_bytes()[0].is_ascii_uppercase()
            && text.contains('.')
            && text
                .bytes()
                .last()
                .is_some_and(|b| b.is_ascii_alphanumeric());
        if shaped && !found.iter().any(|seen| seen == text) {
            found.push(text.to_string());
        }
    };
    for (index, byte) in bytes.iter().enumerate() {
        if in_charset(*byte) {
            if start.is_none() {
                start = Some(index);
            }
        } else if let Some(from) = start.take() {
            flush(&mut found, from, index);
            if found.len() >= TYPE_NAME_CENSUS_MAX {
                break;
            }
        }
    }
    if let Some(from) = start {
        flush(&mut found, from, bytes.len());
    }
    found.sort();
    found.truncate(TYPE_NAME_CENSUS_MAX);
    found
}

/// Screen one PE image (already known to carry no CLI
/// header). Export names are supplied by the caller's PE
/// parse so the screen itself is pure byte work.
pub fn screen_native_aot(bytes: &[u8], export_names: &[String]) -> NativeAotScreen {
    let component_strings: Vec<String> = COMPONENT_NEEDLES
        .iter()
        .filter(|needle| find_subslice(bytes, needle.as_bytes()).is_some())
        .map(|needle| needle.to_string())
        .collect();
    let runtime_exports: Vec<String> = export_names
        .iter()
        .filter(|name| is_runtime_export(name))
        .cloned()
        .collect();
    let classified = component_strings.len() >= 2
        && (!runtime_exports.is_empty() || component_strings.len() >= 3);
    NativeAotScreen {
        classified,
        component_strings,
        runtime_exports,
        sections: Vec::new(),
        type_name_census: if classified {
            type_name_census(bytes)
        } else {
            Vec::new()
        },
    }
}

/// Screen one whole PE file: parse with goblin for the
/// section and export tables, then run the byte screen.
/// A file goblin cannot read as a PE screens as
/// unclassified with no sections.
pub fn analyze_pe(bytes: &[u8]) -> NativeAotScreen {
    let mut export_names: Vec<String> = Vec::new();
    let mut sections: Vec<SectionFact> = Vec::new();
    if let Ok(goblin::Object::PE(pe)) = goblin::Object::parse(bytes) {
        export_names = pe
            .exports
            .iter()
            .filter_map(|export| export.name)
            .map(str::to_string)
            .collect();
        sections = pe
            .sections
            .iter()
            .map(|section| SectionFact {
                name: section.name().unwrap_or("").to_string(),
                raw_size: section.size_of_raw_data,
                virtual_size: section.virtual_size,
            })
            .collect();
    }
    let mut screen = screen_native_aot(bytes, &export_names);
    screen.sections = sections;
    screen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image_with(parts: &[&[u8]]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for part in parts {
            bytes.extend_from_slice(part);
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn validation_two_components_and_an_export_classify() {
        let bytes = image_with(&[
            b"System.Private.CoreLib",
            b"System.Private.TypeLoader",
            b"System.Widgets.Runner",
        ]);
        let exports = vec!["RhpNewFast".to_string(), "main".to_string()];
        let screen = screen_native_aot(&bytes, &exports);
        assert!(screen.classified);
        assert_eq!(screen.component_strings.len(), 2);
        assert_eq!(screen.runtime_exports, ["RhpNewFast"]);
        assert!(
            screen
                .type_name_census
                .contains(&"System.Widgets.Runner".to_string())
        );
    }

    #[test]
    fn validation_three_components_classify_without_exports() {
        let bytes = image_with(&[
            b"System.Private.CoreLib",
            b"System.Private.Reflection.Execution",
            b"System.Private.StackTraceMetadata",
        ]);
        let screen = screen_native_aot(&bytes, &[]);
        assert!(screen.classified);
    }

    #[test]
    fn adversarial_single_component_does_not_classify() {
        let bytes = image_with(&[b"System.Private.CoreLib", b"unrelated text"]);
        let exports = vec!["RhpNewFast".to_string(), "RhpAssignRef".to_string()];
        let screen = screen_native_aot(&bytes, &exports);
        assert!(!screen.classified);
        assert_eq!(screen.component_strings.len(), 1);
        // The hits are still facts even when they do not
        // promote the binary.
        assert_eq!(screen.runtime_exports.len(), 2);
    }

    #[test]
    fn adversarial_exports_alone_do_not_classify() {
        let bytes = image_with(&[b"a wholly native image"]);
        let exports = vec!["RhpNewFast".to_string()];
        let screen = screen_native_aot(&bytes, &exports);
        assert!(!screen.classified);
        assert!(screen.component_strings.is_empty());
    }

    #[test]
    fn adversarial_jit_string_is_not_aot_evidence() {
        let bytes = image_with(&[
            b"System.Private.CoreLib",
            b"System.Private.Jit",
            b"System.Private.Jit",
        ]);
        let screen = screen_native_aot(&bytes, &[]);
        assert!(!screen.classified);
        assert_eq!(screen.component_strings.len(), 1);
    }

    #[test]
    fn validation_handbuilt_pe_screens_through_goblin() {
        let bytes = build_minimal_pe(
            b"System.Private.CoreLib\0System.Private.TypeLoader\0System.Private.StackTraceMetadata\0",
        );
        let screen = analyze_pe(&bytes);
        assert_eq!(screen.sections.len(), 1);
        assert_eq!(screen.sections[0].name, ".rdata");
        assert!(
            screen.classified,
            "three components classify; got {:?}",
            screen.component_strings
        );
    }

    #[test]
    fn adversarial_handbuilt_pe_two_components_stays_native() {
        let bytes = build_minimal_pe(b"System.Private.CoreLib\0System.Private.TypeLoader\0");
        let screen = analyze_pe(&bytes);
        assert!(!screen.classified);
        assert_eq!(screen.component_strings.len(), 2);
    }

    /// A minimal PE32+ with one `.rdata` section and no CLI
    /// header (data directory 14 is zero), hand-built.
    fn build_minimal_pe(section_data: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x200];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        bytes[coff..coff + 2].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(&240_u16.to_le_bytes());
        let opt = coff + 20;
        bytes[opt..opt + 2].copy_from_slice(&0x20b_u16.to_le_bytes());
        bytes[opt + 32..opt + 36].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[opt + 36..opt + 40].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[opt + 56..opt + 60].copy_from_slice(&0x2000_u32.to_le_bytes());
        bytes[opt + 60..opt + 64].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes[opt + 108..opt + 112].copy_from_slice(&16_u32.to_le_bytes());
        let section = opt + 240;
        bytes[section..section + 8].copy_from_slice(b".rdata\0\0");
        let raw = section_data.len() as u32;
        bytes[section + 8..section + 12].copy_from_slice(&raw.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000_u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&raw.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200_u32.to_le_bytes());
        bytes.extend_from_slice(section_data);
        bytes
    }
}

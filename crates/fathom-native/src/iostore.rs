//! Unreal IoStore container header census (R5).
//!
//! Reads the `FIoStoreTocHeader` of one `.utoc` file and
//! reports the facts that are certain from the header:
//! the container version, the compression block size,
//! the directory index size, and the partition count,
//! plus the byte sizes of the `.utoc` and its paired
//! `.ucas`. The field offsets (u32 words 7, 8, and 9
//! after the version word) were verified consistent
//! across both corpus containers (HypnoGen's `global`
//! and game containers) and close against the files'
//! total sizes.
//!
//! Named gaps, deliberately not guessed: the chunk
//! entry table's serialized layout does not close from
//! the corpus samples alone (two candidate entry widths
//! each contradict one container's size), so no chunk
//! count is reported; the directory index body and
//! chunk extraction (which additionally needs the
//! compression codecs, Oodle among them) are not
//! attempted.

use std::path::Path;

use fathom_core::config::Config;
use fathom_core::error::{ErrorCode, FathomError};
use fathom_core::evidence::{Confidence, Evidence, Finding, subject_for_file_with_bound};
use fathom_core::limits::PAK_TARGET_BYTES_MAX;
use fathom_core::paths;
use fathom_core::proof;
use fathom_core::registry::{Registry, require_str};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, FathomError>;

/// The 16-byte UTOC magic: `-==--==--==--==-`.
const UTOC_MAGIC: &[u8; 16] = b"-==--==--==--==-";
/// The header fields this census reads end at byte 56.
const HEADER_BYTES_MIN: usize = 56;

/// Read one little-endian u32 at `at`.
fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn inspect_iostore_container(
    _registry: &Registry,
    config: &Config,
    args: &Value,
) -> Result<Value> {
    let path = paths::validate_target(config, Path::new(require_str(args, "target")?))?;
    if path.extension().and_then(|ext| ext.to_str()) != Some("utoc") {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "inspect_iostore_container expects a .utoc target",
        ));
    }
    let subject = subject_for_file_with_bound(&path, PAK_TARGET_BYTES_MAX)?;
    let sha256 = subject.sha256.clone();
    let utoc_bytes = subject.size_bytes;
    let mut evidence = Evidence::new("inspect_iostore_container", "unreal_iostore");
    evidence.subject = Some(subject);
    let head = {
        use std::io::Read;
        let mut file = std::fs::File::open(&path).map_err(|error| {
            FathomError::new(
                ErrorCode::ArtifactIntegrityMismatch,
                format!("cannot open utoc: {error}"),
            )
        })?;
        let mut buffer = vec![0u8; HEADER_BYTES_MIN];
        let mut filled = 0usize;
        while filled < HEADER_BYTES_MIN {
            match file.read(&mut buffer[filled..]) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(error) => {
                    return Err(FathomError::new(
                        ErrorCode::ArtifactIntegrityMismatch,
                        format!("cannot read utoc header: {error}"),
                    ));
                }
            }
        }
        buffer.truncate(filled);
        buffer
    };
    if head.len() < HEADER_BYTES_MIN || &head[0..16] != UTOC_MAGIC {
        return Err(FathomError::new(
            ErrorCode::UnsupportedTarget,
            "target lacks the IoStore UTOC magic (-==--==--==--==-)",
        ));
    }
    let version = u32_at(&head, 16).unwrap_or(0);
    let compression_block_size = u32_at(&head, 44).unwrap_or(0);
    let directory_index_size = u32_at(&head, 48).unwrap_or(0);
    let partition_count = u32_at(&head, 52).unwrap_or(0);
    let ucas_path = path.with_extension("ucas");
    let ucas_bytes = std::fs::metadata(&ucas_path).ok().map(|meta| meta.len());
    let document = json!({
        "compression_block_size": compression_block_size,
        "directory_index_size": directory_index_size,
        "partition_count": partition_count,
        "version": version,
    });
    let (digest, retention_note) =
        match proof::retain_export(config, &sha256, "iostore_census", &document) {
            Ok(digest) => (Some(digest), None),
            Err(error) => (None, Some(error.message)),
        };
    evidence.add_finding(Finding::new(
        "iostore_container",
        Confidence::Observed,
        json!({
            "compression_block_size": compression_block_size,
            "directory_index_size": directory_index_size,
            "export_digest": digest,
            "format": "Unreal IoStore container (utoc/ucas)",
            "partition_count": partition_count,
            "target_sha256": sha256,
            "ucas_bytes": ucas_bytes,
            "utoc_bytes": utoc_bytes,
            "version": version,
        }),
    ));
    if let Some(note) = retention_note {
        evidence.add_unknown(
            "retention",
            format!(
                "census retention failed ({note}); the census facts stand, but no proof can bind this run"
            ),
        );
    }
    evidence.add_unknown(
        "chunk entries",
        "the chunk entry table layout does not close from the corpus samples; no chunk count is reported",
    );
    evidence.add_unknown(
        "directory index",
        "the directory index body is not parsed; only its header-declared size is reported",
    );
    evidence.add_unknown(
        "chunk extraction",
        "chunk payloads are not extracted; IoStore compression (Oodle) is outside this reader",
    );
    Ok(evidence.to_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_header_words_land_at_their_offsets() {
        let mut head = vec![0u8; HEADER_BYTES_MIN];
        head[0..16].copy_from_slice(UTOC_MAGIC);
        head[16..20].copy_from_slice(&5u32.to_le_bytes());
        head[44..48].copy_from_slice(&65_536u32.to_le_bytes());
        head[48..52].copy_from_slice(&15_458u32.to_le_bytes());
        head[52..56].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(u32_at(&head, 16), Some(5));
        assert_eq!(u32_at(&head, 44), Some(65_536));
        assert_eq!(u32_at(&head, 48), Some(15_458));
        assert_eq!(u32_at(&head, 52), Some(1));
        assert_eq!(&head[0..16], UTOC_MAGIC);
    }

    #[test]
    fn adversarial_short_read_yields_no_word() {
        assert_eq!(u32_at(&[1, 2], 0), None);
        assert_eq!(u32_at(&[], 44), None);
    }
}

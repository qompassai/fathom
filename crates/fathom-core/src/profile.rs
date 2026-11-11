//! Launch-time tool profiles (D-910).
//!
//! A profile is deterministic launch configuration: it scopes
//! which of the catalog a launch serves, so a client's tools/list
//! handshake carries only the surface its task needs. The default
//! profile (`core`) serves the discovery/evidence spine; named
//! packs add one lane's providers each and combine freely; the
//! `full` profile serves the complete catalog unfiltered.
//!
//! Profiles decide presence only. Execute-class policy
//! (`allow_tools`, see `policy`) still decides which served tools
//! may run, and no tool is reachable *only* through a profile: the
//! full surface is always one explicit `full` launch away. Skill
//! or trigger layers may recommend a pack, but they are advisory —
//! this module is the deterministic gate they recommend into.

use std::collections::BTreeSet;

use crate::error::{ErrorCode, FathomError};

/// Provider labels every profile serves: session identity,
/// evidence bundles, and the reconstruction ledger/spec/proof
/// spine. `spec` rides with `core` because `spec_record` is the
/// third leg of that workflow (ledger -> spec -> proof).
pub const CORE_PROVIDERS: &[&str] = &["core", "spec"];

/// The profile keyword that serves only [`CORE_PROVIDERS`].
pub const PROFILE_CORE: &str = "core";

/// The profile keyword that serves the complete catalog.
pub const PROFILE_FULL: &str = "full";

/// Environment variable consulted between the `--profile`
/// argument and the config file's `tool_profile` field.
pub const PROFILE_ENV_VAR: &str = "FATHOM_TOOL_PROFILE";

/// One named pack: the provider labels it adds beyond
/// [`CORE_PROVIDERS`]. Packs are disjoint by provider (asserted
/// in this module's tests), so a provider belongs to exactly one
/// pack and the union of all packs plus core is the catalog.
struct Pack {
    name: &'static str,
    providers: &'static [&'static str],
}

/// The pack table, alphabetical by pack name. A new provider
/// label joins exactly one pack here in the same change that
/// registers it; the composition tests fail until it does.
const PACKS: &[Pack] = &[
    Pack {
        name: "art",
        providers: &["art"],
    },
    Pack {
        name: "games",
        providers: &[
            "artifact",
            "audio",
            "beam",
            "blender",
            "cri",
            "cubism",
            "dialogue",
            "fmod",
            "game",
            "gamemaker",
            "godot",
            "gpu",
            "kirikiri",
            "local",
            "mesh",
            "native-layout",
            "pe",
            "python",
            "renpy",
            "rpgmaker",
            "ui",
            "unity",
            "unreal",
        ],
    },
    Pack {
        name: "ghidra",
        providers: &["ghidra", "ghidra-il2cpp"],
    },
    Pack {
        name: "js",
        providers: &["asar", "javascript"],
    },
    Pack {
        name: "managed",
        providers: &["managed"],
    },
    Pack {
        name: "media",
        providers: &["video"],
    },
    Pack {
        name: "observe",
        providers: &["android", "browser", "evm", "firmware", "process"],
    },
    Pack {
        name: "web",
        providers: &["web"],
    },
];

/// A resolved launch profile: the full catalog, or core plus a
/// set of packs. Construct via [`ToolProfile::parse`] or
/// [`Default`]; the resolved form cannot name an unknown pack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolProfile {
    full: bool,
    packs: BTreeSet<&'static str>,
}

impl Default for ToolProfile {
    /// The default launch profile: `core`.
    fn default() -> Self {
        ToolProfile {
            full: false,
            packs: BTreeSet::new(),
        }
    }
}

impl ToolProfile {
    /// The full profile: the complete catalog, no filter.
    pub fn full() -> ToolProfile {
        ToolProfile {
            full: true,
            packs: BTreeSet::new(),
        }
    }

    /// Parse a profile spec: `core`, `full`, or a comma-separated
    /// list of pack names (optionally including `core`, which is
    /// always served anyway). Matching is exact and lowercase.
    /// Fail-closed: an empty spec, an empty segment, an unknown
    /// pack, or `full` combined with anything else is a
    /// `configuration_invalid` error naming the valid choices.
    pub fn parse(spec: &str) -> Result<ToolProfile, FathomError> {
        let invalid = |reason: String| FathomError::new(ErrorCode::ConfigurationInvalid, reason);
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err(invalid(
                "tool profile spec is empty (name core, full, or a pack)".to_string(),
            ));
        }
        let mut profile = ToolProfile::default();
        let mut saw_full = false;
        let mut segments = 0usize;
        for segment in trimmed.split(',') {
            segments += 1;
            let name = segment.trim();
            if name.is_empty() {
                return Err(invalid(format!(
                    "tool profile spec '{spec}' contains an empty segment"
                )));
            }
            match name {
                PROFILE_FULL => saw_full = true,
                PROFILE_CORE => {}
                _ => {
                    let pack = PACKS.iter().find(|pack| pack.name == name).ok_or_else(|| {
                        invalid(format!(
                            "tool profile names unknown pack '{name}' (valid: core, full, {})",
                            Self::pack_names().join(", ")
                        ))
                    })?;
                    profile.packs.insert(pack.name);
                }
            }
        }
        if saw_full {
            if segments > 1 {
                return Err(invalid(
                    "tool profile 'full' stands alone; combine packs instead (e.g. games,media)"
                        .to_string(),
                ));
            }
            return Ok(ToolProfile::full());
        }
        Ok(profile)
    }

    /// Whether this profile serves the complete catalog.
    pub fn is_full(&self) -> bool {
        self.full
    }

    /// Whether a tool with this provider label is served.
    pub fn serves_provider(&self, provider: &str) -> bool {
        if self.full || CORE_PROVIDERS.contains(&provider) {
            return true;
        }
        self.packs
            .iter()
            .filter_map(|name| Self::pack(name))
            .any(|pack| pack.providers.contains(&provider))
    }

    /// The canonical spec string (`core`, `core+games,media`,
    /// `full`): what `doctor` and `session_info` report.
    pub fn spec_string(&self) -> String {
        if self.full {
            return PROFILE_FULL.to_string();
        }
        if self.packs.is_empty() {
            return PROFILE_CORE.to_string();
        }
        let joined: Vec<&str> = self.packs.iter().copied().collect();
        format!("core+{}", joined.join(","))
    }

    /// Every pack name, alphabetical (the table's own order).
    pub fn pack_names() -> Vec<&'static str> {
        PACKS.iter().map(|pack| pack.name).collect()
    }

    /// The provider labels one pack adds, if the pack exists.
    pub fn pack_providers(name: &str) -> Option<&'static [&'static str]> {
        Self::pack(name).map(|pack| pack.providers)
    }

    fn pack(name: &str) -> Option<&'static Pack> {
        PACKS.iter().find(|pack| pack.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_default_is_core_only() {
        let profile = ToolProfile::default();
        assert!(!profile.is_full());
        assert!(profile.serves_provider("core"));
        assert!(profile.serves_provider("spec"));
        assert!(!profile.serves_provider("ghidra"));
        assert!(!profile.serves_provider("video"));
        assert_eq!(profile.spec_string(), "core");
    }

    #[test]
    fn validation_full_serves_every_provider() {
        let profile = ToolProfile::parse("full").unwrap();
        assert!(profile.is_full());
        assert!(profile.serves_provider("ghidra"));
        assert!(profile.serves_provider("anything-at-all"));
        assert_eq!(profile.spec_string(), "full");
    }

    #[test]
    fn validation_packs_combine_dedupe_and_keep_core() {
        let profile = ToolProfile::parse(" media, core ,games,media ").unwrap();
        assert!(profile.serves_provider("core"));
        assert!(profile.serves_provider("video"));
        assert!(profile.serves_provider("unity"));
        assert!(!profile.serves_provider("ghidra"));
        assert_eq!(profile.spec_string(), "core+games,media");
    }

    #[test]
    fn adversarial_unknown_pack_is_a_typed_error() {
        let err = ToolProfile::parse("ghidraa").unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigurationInvalid);
        assert!(
            err.message.contains("unknown pack 'ghidraa'"),
            "{}",
            err.message
        );
    }

    #[test]
    fn adversarial_full_combined_is_an_error() {
        let err = ToolProfile::parse("full,games").unwrap_err();
        assert_eq!(err.code, ErrorCode::ConfigurationInvalid);
    }

    #[test]
    fn adversarial_empty_and_blank_segments_are_errors() {
        for spec in ["", "   ", "games,,media", "games,"] {
            let err = ToolProfile::parse(spec).unwrap_err();
            assert_eq!(err.code, ErrorCode::ConfigurationInvalid, "spec: {spec}");
        }
    }

    #[test]
    fn adversarial_pack_names_are_case_exact() {
        assert!(ToolProfile::parse("FULL").is_err());
        assert!(ToolProfile::parse("Games").is_err());
    }

    #[test]
    fn validation_pack_table_is_alphabetical_disjoint_and_core_free() {
        let names = ToolProfile::pack_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "pack table stays alphabetical");
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for name in &names {
            for provider in ToolProfile::pack_providers(name).unwrap() {
                assert!(
                    !CORE_PROVIDERS.contains(provider),
                    "pack {name} re-lists core provider {provider}"
                );
                assert!(
                    seen.insert(provider),
                    "provider {provider} appears in two packs"
                );
            }
        }
    }
}

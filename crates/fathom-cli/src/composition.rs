//! The composition root: builds the one tool registry every
//! surface serves (upstream's composition layer, SPEC §2), then
//! scopes it to the launch's tool profile (D-910). The registry a
//! surface serves IS the profile's catalog: the full profile
//! applies no filter, so its registry is the unmodified build.

use fathom_core::profile::ToolProfile;
use fathom_core::registry::Registry;

use crate::core_tools;

/// Build the registry for one launch: core tools plus every
/// provider, filtered to `profile`.
pub fn build_registry(profile: &ToolProfile) -> Registry {
    let mut registry = Registry::new();
    core_tools::register(&mut registry);
    fathom_art::register(&mut registry);
    fathom_js::register(&mut registry);
    fathom_managed::register(&mut registry);
    fathom_native::register(&mut registry);
    fathom_observe::register(&mut registry);
    fathom_video::register(&mut registry);
    fathom_web::register(&mut registry);
    registry.retain_profile(profile);
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use fathom_core::profile::CORE_PROVIDERS;

    fn names(profile: &ToolProfile) -> Vec<String> {
        build_registry(profile)
            .descriptors()
            .iter()
            .map(|d| d.name.clone())
            .collect()
    }

    #[test]
    fn validation_default_profile_serves_only_the_core_spine() {
        let expected: Vec<String> = [
            "build_reconstruction_obligation_ledger",
            "compare_artifacts",
            "delete_reconstruction_proof",
            "export_evidence_bundle",
            "session_info",
            "spec_record",
            "verify_evidence_bundle",
            "verify_reconstruction_proof",
        ]
        .iter()
        .map(|name| name.to_string())
        .collect();
        assert_eq!(names(&ToolProfile::default()), expected);
    }

    #[test]
    fn validation_media_profile_adds_the_capture_lane() {
        let names = names(&ToolProfile::parse("media").unwrap());
        assert!(names.contains(&"capture_danbooru_media".to_string()));
        assert!(names.contains(&"observe_captured_media".to_string()));
        assert!(names.contains(&"session_info".to_string()));
        assert!(!names.contains(&"analyze_function".to_string()));
    }

    #[test]
    fn validation_every_full_catalog_provider_has_exactly_one_home() {
        // Coverage law (D-910): each provider label in the full
        // catalog is core, or belongs to exactly one pack — a new
        // provider cannot ship without a pack decision.
        for descriptor in build_registry(&ToolProfile::full()).descriptors() {
            let provider = descriptor.provider.as_str();
            let in_core = CORE_PROVIDERS.contains(&provider);
            let pack_homes = ToolProfile::pack_names()
                .iter()
                .filter(|name| {
                    ToolProfile::pack_providers(name)
                        .unwrap()
                        .contains(&provider)
                })
                .count();
            assert!(
                (in_core && pack_homes == 0) || (!in_core && pack_homes == 1),
                "provider {provider} (tool {}) has in_core={in_core}, pack_homes={pack_homes}",
                descriptor.name
            );
        }
    }

    #[test]
    fn validation_full_profile_is_the_complete_catalog() {
        // The full build is the reference every profile scopes
        // from; its size is the census of record (185 at D-910).
        assert_eq!(build_registry(&ToolProfile::full()).len(), 185);
    }
}

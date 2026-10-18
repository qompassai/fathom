//! The composition root: builds the one tool registry every
//! surface serves (upstream's composition layer, SPEC §2).

use fathom_core::registry::Registry;

use crate::core_tools;

/// Build the complete registry: core tools plus every provider.
pub fn build_registry() -> Registry {
    let mut registry = Registry::new();
    core_tools::register(&mut registry);
    fathom_art::register(&mut registry);
    fathom_js::register(&mut registry);
    fathom_managed::register(&mut registry);
    fathom_native::register(&mut registry);
    fathom_observe::register(&mut registry);
    registry
}

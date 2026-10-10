//! The composition root: builds the one tool registry every
//! surface serves (upstream's composition layer, SPEC §2).

use rea_core::registry::Registry;

use crate::core_tools;

/// Build the complete registry: core tools plus every provider.
pub fn build_registry() -> Registry {
    let mut registry = Registry::new();
    core_tools::register(&mut registry);
    rea_js::register(&mut registry);
    rea_managed::register(&mut registry);
    rea_native::register(&mut registry);
    rea_observe::register(&mut registry);
    registry
}

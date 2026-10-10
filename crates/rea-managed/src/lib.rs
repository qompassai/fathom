//! rea-managed: .NET assembly analysis.
//!
//! PE headers via goblin; CLI metadata via a manual ECMA-335
//! reader (metadata root, streams, table geometry, TypeDef /
//! MethodDef / ImplMap inventories, IL byte digests). Decoded-CIL
//! listings are scaffolded (SPEC §9.3). Stage 1 registers the
//! catalog as a scaffold; stage 3 builds the handler.
#![forbid(unsafe_code)]

use rea_core::policy::ToolClass;
use rea_core::registry::{Registry, descriptor, target_schema};

/// Register this provider's tools with the registry.
pub fn register(registry: &mut Registry) {
    registry.register_not_implemented(
        descriptor(
            "inspect_managed_assembly",
            ToolClass::Read,
            "managed",
            ".NET metadata inventory: identity, types, methods, P/Invoke, IL digests",
            target_schema(),
        ),
        "§9.3",
    );
}

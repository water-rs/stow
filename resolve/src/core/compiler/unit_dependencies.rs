//! [`IsArtifact`] — the only `unit_dependencies` type the resolver needs.
//!
//! `cargo::core::compiler::unit_dependencies::build_unit_dependencies` turns a
//! resolved graph into the unit-graph the build runner schedules. `cargo
//! metadata` never builds units, so that machinery is not ported.

/// A boolean-like to indicate if a `Unit` is an artifact or not.
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum IsArtifact {
    Yes,
    No,
}

impl IsArtifact {
    pub fn is_true(&self) -> bool {
        matches!(self, IsArtifact::Yes)
    }
}

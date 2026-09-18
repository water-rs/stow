//! Crate coordinates ([`CrateId`]) and the canonical [`FeatureSet`] used in
//! artifact identity hashing.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Identifies a specific crate version from crates.io.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CrateId {
    /// crates.io package name.
    pub name: String,
    /// Published package version.
    pub version: semver::Version,
}

impl fmt::Display for CrateId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

/// Sorted, deduplicated feature set.
///
/// `BTreeSet` ensures deterministic iteration order, which is critical for
/// producing identical hashes across platforms and invocations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FeatureSet(pub BTreeSet<String>);

impl FeatureSet {
    /// Create an empty — already canonical — feature set.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Whether the set contains no features.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Compute a short hash of the feature set for use in OCI tags.
    /// Returns first 8 hex chars of BLAKE3 hash over sorted features.
    #[must_use]
    pub fn short_hash(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        for f in &self.0 {
            hasher.update(f.as_bytes());
        }
        hex::encode(&hasher.finalize().as_bytes()[..4])
    }
}

impl Default for FeatureSet {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<String> for FeatureSet {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

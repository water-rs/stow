use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RlibMetadata {
    name: String,
    version: String,
    arch: String,
    rustc_version: String,
    features: Vec<String>,
    flags: Vec<String>,
    env: BTreeMap<String, String>,
    hash: String,   // the sccache hash of the metadata
    sha256: String, // the sha256 of the rlib file
}
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum CachedArtifact {
    Rlib(RlibMetadata),
    // We can also cache the .d file and .rmeta file if needed
}

impl CachedArtifact {
    pub fn hash(&self) -> String {
        match self {
            CachedArtifact::Rlib(metadata) => metadata.hash.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CachedCrate {
    name: String,
    version: String,
    arifacts: Vec<CachedArtifact>,
}

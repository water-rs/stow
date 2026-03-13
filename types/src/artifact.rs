use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crate_info::{CrateId, FeatureSet};
use crate::platform::{Profile, RustcVersion, Target};

/// The kind of artifact we're caching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// rlib + rmeta for library crates (compiled for TARGET).
    Rlib,
    /// Dynamic library for proc-macro crates (compiled for HOST).
    /// Contains .so (Linux), .dylib (macOS), or .dll (Windows).
    ProcMacro,
}

impl ArtifactKind {
    pub fn as_str(&self) -> &str {
        match self {
            ArtifactKind::Rlib => "rlib",
            ArtifactKind::ProcMacro => "proc-macro",
        }
    }
}

/// Semantic artifact identity — used for BUILD PLANNING and ANALYTICS only.
///
/// NOT the cache lookup key! Cache lookup uses the composite key
/// `(c_metadata, target, rustc_version)` where `c_metadata` comes from
/// cargo's `-C metadata` flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactKey {
    pub crate_id: CrateId,
    pub features: FeatureSet,
    /// For Rlib: compilation target. For ProcMacro: HOST triple.
    pub target: Target,
    pub rustc_version: RustcVersion,
    /// Observed from actual rustc args, not assumed.
    pub profile: Profile,
    pub kind: ArtifactKind,
}

/// Metadata stored in OCI manifest alongside the artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub key: ArtifactKey,
    pub rlib_sha256: String,
    pub rmeta_sha256: Option<String>,
    pub has_native_artifacts: bool,
    pub built_at: String,
    pub builder_run_id: u64,
    pub stow_version: String,
}

/// Build script outputs for crates with C/C++ dependencies.
///
/// This is what makes `-sys` crate caching possible. All fields are
/// captured from the build script output directory in CI and replayed
/// on the client machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeArtifacts {
    /// Static libraries (.a / .lib files) produced by the build script.
    pub static_libs: Vec<NativeLib>,
    /// All `cargo:` directives from the build script output.
    /// Includes rustc-link-lib, rustc-link-search, rustc-cfg, rustc-env, etc.
    /// Excludes `rerun-if-*` directives (irrelevant for cached artifacts).
    pub cargo_directives: Vec<String>,
    /// DEP_CRATENAME_KEY=VALUE environment variables for downstream crates.
    pub dep_env_vars: BTreeMap<String, String>,
    /// Generated files from the build script's OUT_DIR.
    /// Stored as (relative_path, contents) pairs.
    pub out_dir_files: Vec<OutDirFile>,
}

/// A static library produced by a build script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeLib {
    /// Library name (e.g., "ring-core").
    pub name: String,
    /// SHA-256 of the library file bytes.
    pub bytes_sha256: String,
}

/// A file from the build script's OUT_DIR, stored with its relative path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutDirFile {
    /// Path relative to OUT_DIR.
    pub relative_path: String,
    /// File contents as raw bytes.
    #[serde(with = "base64_bytes")]
    pub contents: Vec<u8>,
}

/// Serde helper for encoding Vec<u8> as base64 in JSON.
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let encoded = hex::encode(bytes);
        encoded.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use serde::de::Error;
        let encoded = String::deserialize(d)?;
        hex::decode(&encoded).map_err(D::Error::custom)
    }
}

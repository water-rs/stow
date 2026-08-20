use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crate_info::{CrateId, FeatureSet};
use crate::platform::{Profile, RustcVersion, Target};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RustCrateType {
    Lib,
    Rlib,
    Dylib,
    Cdylib,
    Staticlib,
    ProcMacro,
}

// Order by the wire string, not declaration order: producers sort
// `crate_types` lists with this `Ord` while validators compare the
// serialized strings, and the two must agree ("cdylib" < "rlib" even
// though `Rlib` is declared first).
impl Ord for RustCrateType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for RustCrateType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl RustCrateType {
    #[must_use] 
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Lib => "lib",
            Self::Rlib => "rlib",
            Self::Dylib => "dylib",
            Self::Cdylib => "cdylib",
            Self::Staticlib => "staticlib",
            Self::ProcMacro => "proc-macro",
        }
    }
}

/// The kind of artifact we're caching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ArtifactKind {
    /// rlib + rmeta for library crates (compiled for TARGET).
    Rlib,
    /// Dynamic library for dylib crates (compiled for TARGET).
    Dylib,
    /// Dynamic library for proc-macro crates (compiled for HOST).
    /// Contains .so (Linux), .dylib (macOS), or .dll (Windows).
    ProcMacro,
}

impl ArtifactKind {
    #[must_use] 
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Rlib => "rlib",
            Self::Dylib => "dylib",
            Self::ProcMacro => "proc-macro",
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
    pub crate_types: Vec<RustCrateType>,
    /// For Rlib: compilation target. For `ProcMacro`: HOST triple.
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
    /// `DEP_CRATENAME_KEY=VALUE` environment variables for downstream crates.
    pub dep_env_vars: BTreeMap<String, String>,
    /// Generated files from the build script's `OUT_DIR`.
    /// Stored as (`relative_path`, contents) pairs.
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

/// One file from the build script's `OUT_DIR`, listed by path and digest.
///
/// The bytes live in the bundle's native archive layer, not here. They used to
/// be hex-encoded inline in [`crate::bundle::ArtifactBlobConfig`], which the
/// edge writes twice per bundle and never compresses: jemalloc-sys' ~333 MB
/// `OUT_DIR` became a 1.27 GB download, against 136.8 MB for every compiled
/// output of fd's entire dependency graph put together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutDirFile {
    /// Path relative to `OUT_DIR`.
    pub relative_path: String,
    /// SHA-256 of the file's bytes, hex-encoded.
    pub sha256: String,
}

#[cfg(test)]
mod tests {
    use super::RustCrateType;

    #[test]
    fn crate_type_ordering_matches_wire_strings() {
        let mut all = vec![
            RustCrateType::Lib,
            RustCrateType::Rlib,
            RustCrateType::Dylib,
            RustCrateType::Cdylib,
            RustCrateType::Staticlib,
            RustCrateType::ProcMacro,
        ];
        all.sort();
        let strings: Vec<&str> = all.iter().map(RustCrateType::as_str).collect();
        let mut sorted_strings = strings.clone();
        sorted_strings.sort_unstable();
        assert_eq!(
            strings, sorted_strings,
            "producers sort crate_types with Ord while validators compare wire strings; the orders must agree"
        );
    }
}

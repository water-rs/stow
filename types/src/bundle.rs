use serde::{Deserialize, Serialize};

use crate::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};
use crate::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson, TargetTriple,
    WireRustcVersion,
};
use crate::platform::Profile;

pub const STOW_BUNDLE_MEDIA_TYPE: &str = "application/vnd.stow.bundle.v1+tar";
pub const STOW_BATCH_BUNDLE_MEDIA_TYPE: &str = "application/vnd.stow.batch.v1+tar";
pub const STOW_RLIB_MEDIA_TYPE: &str = "application/vnd.stow.rlib.v1";
pub const STOW_RMETA_MEDIA_TYPE: &str = "application/vnd.stow.rmeta.v1";
pub const STOW_DYLIB_MEDIA_TYPE: &str = "application/vnd.stow.dylib.v1";
pub const STOW_PROC_MACRO_MEDIA_TYPE: &str = "application/vnd.stow.proc-macro.v1";
pub const STOW_ZSTD_MEDIA_TYPE_SUFFIX: &str = "+zstd";
pub const STOW_BUNDLE_MANIFEST_PATH: &str = "manifest.json";
pub const STOW_BATCH_MANIFEST_PATH: &str = "batch-manifest.json";
pub const STOW_BATCH_BUNDLES_DIR: &str = "bundles";
pub const STOW_OCI_MANIFEST_PATH: &str = "oci/manifest.json";
pub const STOW_OCI_CONFIG_PATH: &str = "oci/config.json";
pub const STOW_SIGSTORE_PAYLOAD_DIR: &str = "sigstore";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBundleManifest {
    pub oci_reference: String,
    pub oci_digest: String,
    pub config: ArtifactBlobConfig,
    pub sigstore_signatures: Vec<SigstoreSignature>,
}

/// Embedded JSON config describing one artifact bundle's identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBlobConfig {
    /// Stable hash of the trusted build's exact rustc invocation identity.
    pub compile_key: String,
    /// Crate name.
    pub crate_name: CrateName,
    /// Crate version.
    pub crate_version: CrateVersion,
    /// Cargo `-C metadata` value.
    pub c_metadata: CMetadata,
    /// Cargo `-C extra-filename` suffix.
    pub extra_filename: String,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Sorted dependency identities driving the cache key.
    pub dependency_c_metadata_json: DependencyCMetadataJson,
    /// JSON-encoded compile keys of dependencies.
    pub dependency_compile_keys_json: String,
    /// Cargo profile.
    pub profile: Profile,
    /// Sorted, deduplicated emit modes.
    pub emit: Vec<String>,
    /// Bundle size in bytes.
    pub artifact_size: u64,
    /// Artifact kind.
    pub kind: ArtifactKind,
    /// Declared crate types.
    pub crate_types: Vec<RustCrateType>,
    /// Files in this bundle.
    pub outputs: Vec<ArtifactBundleFile>,
    /// Optional native artifacts.
    pub native: Option<NativeArtifacts>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBundleFile {
    pub file_name: String,
    pub media_type: String,
    pub sha256: String,
}

impl ArtifactBundleFile {
    #[must_use] 
    pub fn storage_media_type(&self) -> String {
        format!("{}{}", self.media_type, STOW_ZSTD_MEDIA_TYPE_SUFFIX)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigstoreSignature {
    pub payload_path: String,
    pub signature: String,
    pub certificate_pem: String,
    pub rekor_bundle_json: Option<String>,
}

/// Manifest describing one batch artifact request response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBatchManifest {
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Per-artifact entries (one per request entry, including misses).
    pub entries: Vec<ArtifactBatchManifestEntry>,
}

/// One entry in a batch artifact response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBatchManifestEntry {
    /// Crate name.
    pub crate_name: CrateName,
    /// Cargo `-C metadata` value.
    pub c_metadata: CMetadata,
    /// Path to the bundle within the tar, or `None` if the artifact is missing.
    pub bundle_path: Option<String>,
}

use serde::{Deserialize, Serialize};

use crate::artifact::{ArtifactKind, NativeArtifacts, RustCrateType};

pub const STOW_BUNDLE_MEDIA_TYPE: &str = "application/vnd.stow.bundle.v1+tar";
pub const STOW_RLIB_MEDIA_TYPE: &str = "application/vnd.stow.rlib.v1";
pub const STOW_RMETA_MEDIA_TYPE: &str = "application/vnd.stow.rmeta.v1";
pub const STOW_DYLIB_MEDIA_TYPE: &str = "application/vnd.stow.dylib.v1";
pub const STOW_PROC_MACRO_MEDIA_TYPE: &str = "application/vnd.stow.proc-macro.v1";
pub const STOW_BUNDLE_MANIFEST_PATH: &str = "manifest.json";
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBlobConfig {
    pub crate_name: String,
    pub crate_version: String,
    pub c_metadata: String,
    pub target: String,
    pub rustc_version: String,
    pub features_json: String,
    pub artifact_size: u64,
    pub kind: ArtifactKind,
    pub crate_types: Vec<RustCrateType>,
    pub outputs: Vec<ArtifactBundleFile>,
    pub native: Option<NativeArtifacts>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBundleFile {
    pub file_name: String,
    pub media_type: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigstoreSignature {
    pub payload_path: String,
    pub signature: String,
    pub certificate_pem: String,
    pub rekor_bundle_json: Option<String>,
}

use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactKind;

pub const STOW_BUNDLE_MEDIA_TYPE: &str = "application/vnd.stow.bundle.v1+tar";
pub const STOW_RLIB_MEDIA_TYPE: &str = "application/vnd.stow.rlib.v1";
pub const STOW_RMETA_MEDIA_TYPE: &str = "application/vnd.stow.rmeta.v1";
pub const STOW_PROC_MACRO_MEDIA_TYPE: &str = "application/vnd.stow.proc-macro.v1";
pub const STOW_BUNDLE_MANIFEST_PATH: &str = "manifest.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBundleManifest {
    pub config: ArtifactBlobConfig,
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
    pub rlib: Option<ArtifactBundleFile>,
    pub rmeta: Option<ArtifactBundleFile>,
    pub proc_macro: Option<ArtifactBundleFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactBundleFile {
    pub file_name: String,
    pub media_type: String,
    pub sha256: String,
}

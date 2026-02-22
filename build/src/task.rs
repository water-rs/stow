use std::{collections::BTreeMap, path::Path, process::Command};

use stow_types::RlibMetadata;

pub fn build() {
    let cmd = Command::new("cargo")
        .arg("build")
        .status()
        .expect("failed to execute cargo build");
}

// Upload the rlib to Github Container Registry
pub fn upload_rlib(path: &Path, metadata: RlibMetadata) {}

use std::{collections::BTreeMap, path::Path, process::Command};

use stow_types::{CachedCrate, RlibMetadata};

pub fn build() {
    let cmd = Command::new("cargo")
        .arg("build")
        .status()
        .expect("failed to execute cargo build");
}

// Upload the rlib to Github Container Registry
pub fn upload_cache(path: &Path, cache: CachedCrate) {
    // Upload each file to Github Container Registry
    todo!()
}

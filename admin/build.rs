//! Selects `scripts/signing-ld.sh` as the `stow-admin` binary's linker
//! when `STOW_LOCAL_SIGNING_IDENTITY` is set on a macOS build — see
//! `docs/USAGE.md`, "Local code signing". Unset, or on any other target
//! OS, the script emits nothing but the rerun trigger, so the compile is
//! byte-for-byte what it is without this file.

use std::env;
use std::ffi::OsStr;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=STOW_LOCAL_SIGNING_IDENTITY");
    let Some(identity) = env::var_os("STOW_LOCAL_SIGNING_IDENTITY") else {
        return;
    };
    if env::var_os("CARGO_CFG_TARGET_OS").as_deref() != Some(OsStr::new("macos")) {
        return;
    }
    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("cargo always sets CARGO_MANIFEST_DIR");
    let linker = Path::new(&manifest_dir)
        .parent()
        .expect("the manifest lives in admin/, under the repository root")
        .join("scripts/signing-ld.sh");
    // rustc-env forwards the identity to the linker invocation the
    // `--ld-path` flag selects, so the wrapper sees it even where plain
    // env inheritance would not reach; being fingerprinted, it also
    // re-links (re-signs) the binary when the identity changes.
    println!("cargo:rustc-env=STOW_LOCAL_SIGNING_IDENTITY={}", identity.to_string_lossy());
    println!("cargo:rustc-link-arg-bin=stow-admin=--ld-path={}", linker.display());
}

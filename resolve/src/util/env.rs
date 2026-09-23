//! Process environment access for the vendored tree.
//!
//! `wasm32-unknown-unknown` has no environment: every `std::env` accessor
//! (`var`, `var_os`, `vars_os`, `current_dir`, ...) traps in
//! `sys/env/unsupported.rs`. The vendored sources therefore read the
//! environment only through this module, which answers on wasm the values a
//! bare process would see — every variable absent, the working directory at
//! the VFS root.
//!
//! Joining and splitting path lists (`join_paths`, `split_paths`) and the
//! `consts` table are pure and stay `std::env`'s own items.

use std::ffi::OsString;
use std::path::PathBuf;

/// `std::env::var`: `Err(NotPresent)` on wasm.
#[cfg(not(target_family = "wasm"))]
pub fn var(key: &str) -> Result<String, std::env::VarError> {
    std::env::var(key)
}

/// `std::env::var`: `Err(NotPresent)` on wasm.
#[cfg(target_family = "wasm")]
pub fn var(_key: &str) -> Result<String, std::env::VarError> {
    Err(std::env::VarError::NotPresent)
}

/// `std::env::var_os`: `None` on wasm.
#[cfg(not(target_family = "wasm"))]
pub fn var_os(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

/// `std::env::var_os`: `None` on wasm.
#[cfg(target_family = "wasm")]
pub fn var_os(_key: &str) -> Option<OsString> {
    None
}

/// `std::env::vars_os`: empty on wasm.
#[cfg(not(target_family = "wasm"))]
pub fn vars_os() -> impl Iterator<Item = (OsString, OsString)> {
    std::env::vars_os()
}

/// `std::env::vars_os`: empty on wasm.
#[cfg(target_family = "wasm")]
pub fn vars_os() -> impl Iterator<Item = (OsString, OsString)> {
    std::iter::empty()
}

/// `std::env::current_dir`: the VFS root on wasm.
///
/// Every path the resolver walks is absolute inside the installed
/// [`crate::util::fs::Vfs`] (`MemoryVfs` under the worker), so `/` is the
/// only truthful cwd there is.
#[cfg(not(target_family = "wasm"))]
pub fn current_dir() -> std::io::Result<PathBuf> {
    std::env::current_dir()
}

/// `std::env::current_dir`: the VFS root on wasm.
#[cfg(target_family = "wasm")]
pub fn current_dir() -> std::io::Result<PathBuf> {
    Ok(PathBuf::from("/"))
}

//! `stow-rustc-shim` — the resolver's rustc shim as its own binary,
//! for tests: `tests/offline.rs` copies it via
//! `env!("CARGO_BIN_EXE_stow-rustc-shim")`. Production copies
//! `stow-admin`, a multi-call binary that dispatches a
//! `rustc-shim-*` `argv[0]` to the same [`stow_resolver::shim::run`].

fn main() {
    stow_resolver::shim::run();
}

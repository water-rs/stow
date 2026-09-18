# stow-shim

Cross-crate helpers for [stow](https://github.com/water-rs/stow), a public
prebuilt cache for Rust.

* Materialization of the rustc/cc wrapper shims shared by the CLI and the
  trusted CI runner (native targets only).
* The incremental `artifacts` table column list the edge worker (D1) and the
  mock registry (SQLite) both migrate against.
* The shared zstd compression level for OCI layers, behind the `zstd`
  feature (off by default because `zstd-sys` does not build for the edge
  worker's `wasm32-unknown-unknown` target).

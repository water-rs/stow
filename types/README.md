# stow-types

Shared wire and identity types for [stow](https://github.com/water-rs/stow), a
public prebuilt cache for Rust.

The crate carries the HTTP payloads the CLI, edge worker, scheduler, and
trusted CI exchange; the validated identity newtypes (`CrateName`,
`CrateVersion`, `FeaturesJson`, `TargetTriple`, `WireRustcVersion`,
`CMetadata`, `DependencyCMetadataJson`) that enforce the five-element artifact
identity tuple at the serde boundary; the OCI bundle manifest layout; and the
rustc-argument parser that derives cache identity from a captured invocation.

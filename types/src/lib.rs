//! Shared API and identity types for the stow workspace.
//!
//! The crate contains the wire types CI, edge, scheduler, and CLI exchange
//! over HTTP / D1, plus the identity newtypes (`CrateName`, `CMetadata`,
//! `TargetTriple`, `WireRustcVersion`, `FeaturesJson`,
//! `DependencyCMetadataJson`) that enforce the five-element artifact identity
//! tuple at compile time.

pub mod api;
pub mod artifact;
pub mod bundle;
pub mod capture;
pub mod crate_info;
pub mod error;
pub mod hash;
pub mod identity;
pub mod native_capture;
pub mod platform;
pub mod public_cache;
pub mod registry;
pub mod rustc;
pub mod trusted_builder;
pub mod upload_plan;
pub mod versioning;

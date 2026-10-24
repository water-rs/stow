//! Shared API and identity types for the stow workspace.
//!
//! The crate contains the wire types CI, edge, scheduler, and CLI exchange
//! over HTTP, plus the identity newtypes (`CrateName`, `CMetadata`,
//! `TargetTriple`, `WireRustcVersion`, `FeaturesJson`,
//! `DependencyCMetadataJson`) that enforce the five-element artifact identity
//! tuple at compile time.

pub mod admission;
pub mod analytics;
pub mod api;
pub mod artifact;
pub mod bundle;
pub mod bundle_schema;
pub mod capture;
pub mod ci;
pub mod crate_info;
pub mod do_budgets;
pub mod env_name;
pub mod error;
pub mod feature_sets;
pub mod fixture;
pub mod glibc;
pub mod hash;
pub mod identity;
pub mod index;
pub mod launch_model;
pub mod local_ci;
pub mod native_capture;
pub mod platform;
pub mod pow;
pub mod preheat_cost;
pub mod public_cache;
pub mod records;
pub mod registry;
pub mod runs;
pub mod rustc;
pub mod task_graph;
pub mod transient;
pub mod trusted_builder;
pub mod unit_graph;
pub mod upload_plan;
pub mod versioning;

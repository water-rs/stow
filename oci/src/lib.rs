//! OCI registry machinery shared by `stow-build` (artifact publish) and
//! `stow-admin` (artifact index publish).
//!
//! One registry session, one credential type, one signing path: the CI
//! publish stage and the index publisher push to GHCR and sign with cosign
//! exactly the same way, so neither carries its own copy.

mod artifacts;
mod client;
mod index;
mod registry;
mod sign;

pub use artifacts::{
    UploadOutcome, pull_signature_materials, push_artifacts, push_artifacts_with, republish_bundle,
};
pub use client::{RegistryError, RegistrySession};
pub use index::{IndexPublishOutcome, publish_index, published_index_content_sha256};
pub use registry::{RegistryBase, RegistryCredentials, pull_blob_verified, pull_tagged_manifest};
pub use sign::sign_artifact;

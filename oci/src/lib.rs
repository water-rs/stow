//! OCI registry machinery shared by `stow-build` (artifact publish) and
//! `stow-admin` (artifact index publish).
//!
//! One registry client, one credential type, one signing path: the CI
//! publish stage and the index publisher push to GHCR and sign with cosign
//! exactly the same way, so neither carries its own copy.

mod artifacts;
mod index;
mod registry;
mod sign;

pub use artifacts::{UploadOutcome, pull_signature_materials, push_artifacts, republish_bundle};
pub use index::{IndexPublishOutcome, publish_index, published_index_content_sha256};
pub use registry::{
    RegistryBase, RegistryCredentials, pull_blob_by_digest, pull_blob_verified,
    pull_tagged_manifest, registry_client,
};
pub use sign::sign_artifact;

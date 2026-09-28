//! OCI registry machinery shared by `stow-build` (artifact publish) and
//! `stow-admin` (artifact index publish).
//!
//! One registry session, one credential type, one signing path: the CI
//! publish stage and the index publisher push to GHCR and sign with cosign
//! exactly the same way, so neither carries its own copy.

mod artifacts;
mod client;
mod index;
mod records;
mod registry;
mod sign;
pub mod verify;

pub use artifacts::{UploadOutcome, pull_signature_materials, push_artifacts, push_artifacts_with};
pub use client::{RegistryError, RegistrySession};
pub use index::{
    IndexPublishOutcome, PulledFolded, PulledIndex, publish_folded, publish_index,
    published_index_content_sha256, pull_folded, pull_index, pull_published_index,
};
pub use records::{
    PulledRecords, RecordsPublishOutcome, list_records_tags, pull_records, pull_records_by_tag,
    push_records, push_records_with,
};
pub use registry::{RegistryBase, RegistryCredentials, pull_blob_verified, pull_tagged_manifest};
pub use sign::sign_artifact;

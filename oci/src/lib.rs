//! OCI registry machinery shared by `stow-build` (artifact publish) and
//! `stow-admin` (artifact index publish).
//!
//! One registry session, one credential type, one signing path: the CI
//! publish stage and the index publisher push to GHCR and sign keyless
//! exactly the same way, so neither carries its own copy.

mod artifacts;
mod client;
mod index;
mod publisher;
mod records;
mod registry;
mod repack;
pub mod retry;
mod sign;
mod throttle;
pub mod verify;

pub use artifacts::{
    UploadOutcome, publish_packed, pull_pushed_signature_materials, pull_signature_materials,
    push_artifacts, push_artifacts_with, verify_artifact_signature,
};
pub use client::{
    OPERATOR_LOG_FILTER, RegistryError, RegistryHttp, RegistrySession, TransportPolicy,
};
pub use index::{
    IndexPublishOutcome, PulledFolded, PulledIndex, publish_folded, publish_index,
    published_index_content_sha256, pull_folded, pull_index, pull_published_index,
};
pub use oci_client::Reference;
pub use publisher::Publisher;
pub use records::{
    PulledRecords, RecordsPublishOutcome, list_records_tags, pull_records, pull_records_by_tag,
    push_records, push_records_with,
};
pub use registry::{RegistryBase, RegistryCredentials, pull_blob_verified, pull_tagged_manifest};
pub use repack::repack_record;
pub use sign::{FULCIO_URL, KeylessSigner, REKOR_URL, SigstoreServices, put_signed_manifest};
pub use throttle::WriteBudget;

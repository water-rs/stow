//! The building blocks of the one-time re-sign of every published
//! signature from one certificate identity to another.
//!
//! Neither identity is named here: a caller supplies the policy the old
//! signatures verify under and the one the new ones must, so this module
//! outlives no identity. It is deleted with the re-sign tools that call it.
//!
//! Three kinds of signed content are covered, each by its own function:
//!
//! * a signed manifest that stays as it is (a records artifact, an index
//!   slice, its folded set): [`resign_manifest`] adds a signature layer
//!   under the new identity to the manifest's `.sig` image, after checking
//!   the old one;
//! * a node, whose bundle tar carries its only signature: [`resign_node`]
//!   reads the node from its bundle, republishes its pack under the new
//!   identity and returns the row naming the new bundle;
//! * the tag space of a rustc's repository, every tag of which belongs to
//!   one of those kinds or is refused ([`classify_tag`]).

use std::collections::BTreeSet;

use oci_client::Reference;
use oci_client::manifest::OciImageManifest;
/// The policy accepting one exact certificate subject from one issuer —
/// what a caller verifies the old identity's signatures with.
pub use sigstore::bundle::verify::policy::Identity as ExactIdentity;
/// The trait a caller's policies implement.
pub use sigstore::bundle::verify::policy::VerificationPolicy;
use stow_types::api::{ArtifactRecord, CI_TARGET_TRIPLES};
use stow_types::bundle::{BundleSignatureMaterial, STOW_BUNDLE_PACK_PATH, STOW_PACK_MEDIA_TYPE};
use stow_types::bundle_schema::canonical_output_indices;
use stow_types::error::Context as _;
use stow_types::identity::WireRustcVersion;
use stow_types::records::{
    BuildRecords, BuildRun, RECORDS_SIGNATURES_ANNOTATION, RecordsSignature,
    RecordsSignatureEnvelope, is_records_tag, parse_records_tag, published_tag, task_id_hash,
};

use crate::artifacts::{publish_packed, pull_listed_signature_materials, pull_signature_materials};
use crate::bundle::pull_bundle;
use crate::client::RegistrySession;
use crate::migrate_records::{marker_material_matches, validate_legacy_records_manifest};
use crate::records::{
    PulledRecords, RecordsPublishOutcome, parse_signed_records_manifest,
    pull_listed_records_by_tag, push_records_with, records_manifest_with_envelope,
};
use crate::registry::pull_blob_verified;
use crate::verify::{Trust, payload_docker_reference, verify_materials};

/// What a tag of a rustc's repository is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    /// `records-<rustc>-<task hash>[-<run>-<attempt>]`: a signed records
    /// artifact.
    Records,
    /// `built-<rustc>-<task hash>`: the marker naming a task's records
    /// manifest.
    Built,
    /// A node's artifact tag, `<crate>.<version>-<target>-<rustc>-<features>-<c_metadata>[-<kind>]`.
    Node,
    /// `<node tag>.bundle`: the node's assembled bundle.
    Bundle,
    /// `sha256-<hex>.sig`: a cosign signature image.
    Signature,
    /// `index.<target>.<rustc>`.
    Index,
    /// `folded.<target>.<rustc>`.
    Folded,
}

/// A tag that belongs to none of the kinds the repository holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownTag(pub String);

impl std::fmt::Display for UnknownTag {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "unknown tag {:?}: it is not a records, built, node, bundle, signature, index or folded tag of this rustc",
            self.0
        )
    }
}

impl std::error::Error for UnknownTag {}

/// The kind of `tag` in `rustc_version`'s repository.
///
/// # Errors
///
/// [`UnknownTag`] when the tag belongs to no kind, including a records,
/// built, index or folded tag of another rustc or a slice of a target that
/// is not built for.
pub fn classify_tag(tag: &str, rustc_version: &WireRustcVersion) -> Result<TagClass, UnknownTag> {
    let rustc = rustc_version.as_str();
    let unknown = || UnknownTag(tag.to_owned());
    if is_records_tag(tag) {
        if parse_records_tag(tag).is_some_and(|parsed| parsed.rustc_version == rustc) {
            return Ok(TagClass::Records);
        }
    } else if tag.starts_with("built-") {
        let is_marker = tag
            .strip_prefix(&format!("built-{rustc}-"))
            .is_some_and(|hash| {
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            });
        if is_marker {
            return Ok(TagClass::Built);
        }
    }
    if let Some(digest) = tag
        .strip_prefix("sha256-")
        .and_then(|rest| rest.strip_suffix(".sig"))
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Ok(TagClass::Signature);
    }
    for (prefix, class) in [("index.", TagClass::Index), ("folded.", TagClass::Folded)] {
        if let Some(target) = tag
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(&format!(".{rustc}")))
            && CI_TARGET_TRIPLES.contains(&target)
        {
            return Ok(class);
        }
    }
    if let Some(node) = tag.strip_suffix(stow_types::registry::BUNDLE_TAG_SUFFIX) {
        return if is_node_tag(node, rustc) {
            Ok(TagClass::Bundle)
        } else {
            Err(unknown())
        };
    }
    if is_node_tag(tag, rustc) {
        return Ok(TagClass::Node);
    }
    Err(unknown())
}

/// Whether `tag` ends the way a node's artifact tag does:
/// `-<target>-<rustc>-<8 hex>-<1..=64 hex>` and an optional kind suffix.
fn is_node_tag(tag: &str, rustc: &str) -> bool {
    let tag = ["-dy", "-pm", "-bs"]
        .iter()
        .find_map(|suffix| tag.strip_suffix(suffix))
        .unwrap_or(tag);
    let hex = |text: &str, lengths: std::ops::RangeInclusive<usize>| {
        lengths.contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    let Some((rest, c_metadata)) = tag.rsplit_once('-') else {
        return false;
    };
    let Some((rest, features)) = rest.rsplit_once('-') else {
        return false;
    };
    let Some(head_and_target) = rest.strip_suffix(&format!("-{rustc}")) else {
        return false;
    };
    hex(c_metadata, 1..=64)
        && hex(features, 8..=8)
        && head_and_target.contains('.')
        && head_and_target.contains('-')
}

/// The policy the old signatures verify under and the one the new ones
/// must satisfy.
#[derive(Debug)]
pub struct Identities<'a, O, N> {
    /// Accepts the signatures being replaced.
    pub old: &'a O,
    /// Accepts the signatures being made.
    pub new: &'a N,
}

impl<O, N> Clone for Identities<'_, O, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<O, N> Copy for Identities<'_, O, N> {}

/// What [`resign_manifest`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resigned {
    /// The manifest already carried a signature layer under the new
    /// identity binding this reference; nothing was written.
    Already,
    /// The old signature verified and a new layer was added.
    Signed,
}

/// Add a signature under the new identity to the signed manifest
/// `manifest_digest`, which stays exactly as it is.
///
/// The new identity is checked first, so a rerun writes nothing for a
/// manifest it already signed. Otherwise a layer under the old identity must
/// verify for `identity_reference` at `manifest_digest`, and `sign` signs the
/// same digest under the new one.
///
/// `reference` is the transport reference the signature materials are
/// pulled through; the signatures bind the canonical `identity_reference`.
///
/// # Errors
///
/// The signature image cannot be read, no layer verifies under the old
/// identity, or signing fails.
pub async fn resign_manifest<O, N, S, Fut, T>(
    session: &RegistrySession,
    trust: &Trust,
    reference: &Reference,
    identity_reference: &str,
    manifest_digest: &str,
    identities: Identities<'_, O, N>,
    sign: &S,
) -> stow_types::error::Result<Resigned>
where
    O: VerificationPolicy + Sync,
    N: VerificationPolicy + Sync,
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<T>> + Send,
{
    let Identities { old, new } = identities;
    let materials = pull_signature_materials(session, reference, manifest_digest).await?;
    if verify_materials(trust, identity_reference, manifest_digest, &materials, new).is_ok() {
        return Ok(Resigned::Already);
    }
    verify_materials(trust, identity_reference, manifest_digest, &materials, old)
        .wrap_err_with(|| format!("verify {identity_reference} under the old identity"))?;
    sign(identity_reference.to_owned(), manifest_digest.to_owned()).await?;
    Ok(Resigned::Signed)
}

struct FetchedRecords {
    pulled: PulledRecords,
    inlined: bool,
    outer_bytes: Vec<u8>,
}

async fn pull_records_for_resign(
    session: &RegistrySession,
    tag: &str,
) -> stow_types::error::Result<FetchedRecords> {
    let reference = session.reference(tag)?;
    let (raw_bytes, manifest_digest) = session
        .pull_listed_manifest(&reference)
        .await
        .map_err(|error| stow_types::stow_error!("pull records manifest {reference}: {error}"))?;
    let manifest: OciImageManifest = serde_json::from_slice(&raw_bytes)
        .wrap_err_with(|| format!("decode records manifest {reference}"))?;
    if manifest
        .annotations
        .as_ref()
        .is_some_and(|map| map.contains_key(RECORDS_SIGNATURES_ANNOTATION))
    {
        let (task_id, signed_digest, envelope, descriptor) =
            parse_signed_records_manifest(&reference, &manifest)?;
        let bytes = pull_blob_verified(session, descriptor).await?;
        let records: BuildRecords = serde_json::from_slice(&bytes).map_err(|error| {
            stow_types::stow_error!("decode records layer of {reference}: {error}")
        })?;
        return Ok(FetchedRecords {
            pulled: PulledRecords {
                records,
                oci_reference: reference.to_string(),
                manifest_digest,
                signed_digest,
                task_id,
                envelope,
            },
            inlined: true,
            outer_bytes: raw_bytes,
        });
    }
    let task_id = validate_legacy_records_manifest(&reference, &manifest)?;
    let materials = pull_listed_signature_materials(session, &reference, &manifest_digest).await?;
    let signatures = materials
        .iter()
        .map(RecordsSignature::from_material)
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    let bytes = pull_blob_verified(session, &manifest.layers[0]).await?;
    let records: BuildRecords = serde_json::from_slice(&bytes)
        .map_err(|error| stow_types::stow_error!("decode records layer of {reference}: {error}"))?;
    let signed_manifest = String::from_utf8(raw_bytes.clone())
        .map_err(|error| stow_types::stow_error!("legacy manifest {reference} UTF-8: {error}"))?;
    Ok(FetchedRecords {
        pulled: PulledRecords {
            records,
            oci_reference: reference.to_string(),
            manifest_digest: manifest_digest.clone(),
            signed_digest: manifest_digest,
            task_id,
            envelope: RecordsSignatureEnvelope {
                signed_manifest,
                signatures,
            },
        },
        inlined: false,
        outer_bytes: raw_bytes,
    })
}

/// Add an inline signature under the new identity to `pulled`'s records manifest.
///
/// Skips signing when the manifest already carries a valid signature under the
/// new identity; otherwise verifies the old identity first (stow#1515,
/// stow#1627). Returns the resulting `(Resigned, Option<Vec<u8>>)` —
/// `Some(outer_bytes)` when the tag's manifest was rewritten so the task's
/// `built-` marker can mirror the newest build.
///
/// # Errors
/// Fails when the manifest fails verification under the old identity, signing
/// fails, or writing the updated manifest fails.
pub async fn resign_records<O, N, S, Fut>(
    session: &RegistrySession,
    trust: &Trust,
    reference: &Reference,
    identity_reference: &str,
    pulled: &mut PulledRecords,
    identities: Identities<'_, O, N>,
    sign: &S,
) -> stow_types::error::Result<(Resigned, Option<Vec<u8>>)>
where
    O: VerificationPolicy + Sync,
    N: VerificationPolicy + Sync,
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>> + Send,
{
    resign_fetched_records(
        session,
        trust,
        reference,
        identity_reference,
        pulled,
        true,
        identities,
        sign,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn resign_fetched_records<O, N, S, Fut>(
    session: &RegistrySession,
    trust: &Trust,
    reference: &Reference,
    identity_reference: &str,
    pulled: &mut PulledRecords,
    inlined: bool,
    identities: Identities<'_, O, N>,
    sign: &S,
) -> stow_types::error::Result<(Resigned, Option<Vec<u8>>)>
where
    O: VerificationPolicy + Sync,
    N: VerificationPolicy + Sync,
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>> + Send,
{
    let Identities { old, new } = identities;
    if pulled.verify(trust, identity_reference, new).is_ok() {
        if inlined {
            return Ok((Resigned::Already, None));
        }
        let outer_bytes = records_manifest_with_envelope(&pulled.envelope)?;
        pulled.manifest_digest = session
            .put_manifest(reference, &outer_bytes)
            .await
            .map_err(|error| {
                stow_types::stow_error!("write inlined records manifest {reference}: {error}")
            })?;
        return Ok((Resigned::Signed, Some(outer_bytes)));
    }
    pulled
        .verify(trust, identity_reference, old)
        .wrap_err_with(|| format!("verify {identity_reference} under the old identity"))?;
    let material = sign(identity_reference.to_owned(), pulled.signed_digest.clone()).await?;
    pulled
        .envelope
        .signatures
        .push(RecordsSignature::from_material(&material)?);
    let outer_bytes = records_manifest_with_envelope(&pulled.envelope)?;
    pulled.manifest_digest = session
        .put_manifest(reference, &outer_bytes)
        .await
        .map_err(|error| {
            stow_types::stow_error!("write re-signed records manifest {reference}: {error}")
        })?;
    Ok((Resigned::Signed, Some(outer_bytes)))
}

/// What [`resign_node`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeResigned {
    /// The row's bundle already verifies under the new identity.
    Already,
    /// The node was republished: the row to publish in place of the old.
    Republished(Box<ArtifactRecord>),
}

/// Republish the node `record` names under the new identity.
///
/// The node is read from its bundle and trusted only after: the bundle
/// hashes to the record's `bundle_digest`, the manifest it carries to the
/// record's `oci_digest`, a signature it carries verifies under the old
/// identity for the record's `oci_reference`, the config and the pack hash
/// to their descriptors, and every file of the pack hashes to the SHA-256
/// the signed config records. The same config and pack then publish
/// through a build's own path: the manifest is byte-identical, so its
/// digest does not move, and the bundle, which carries the new identity's
/// signature alone, is new — so the row's `bundle_digest` and
/// `bundle_size` are.
///
/// `sign` signs the manifest digest under the new identity and publishes
/// nothing itself: the bundle carries the signature. A node whose bundle
/// already verifies under the new identity is left alone.
///
/// # Errors
///
/// A check fails, the node is not in the single-pack layout, republishing
/// does not reproduce the record's manifest digest, or a push fails.
pub async fn resign_node<O, N, S, Fut>(
    session: &RegistrySession,
    trust: &Trust,
    identities: Identities<'_, O, N>,
    record: &ArtifactRecord,
    sign: &S,
) -> stow_types::error::Result<NodeResigned>
where
    O: VerificationPolicy + Sync,
    N: VerificationPolicy + Sync,
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>> + Send,
{
    let Identities { old, new } = identities;
    let oci_reference = record.oci_reference.as_str();
    let bundle = pull_bundle(session, record).await?;
    if bundle.verify(trust, new).is_ok() {
        return Ok(NodeResigned::Already);
    }
    bundle
        .verify(trust, old)
        .wrap_err_with(|| format!("verify {oci_reference} under the old identity"))?;
    let [layer] = bundle.manifest.layers.as_slice() else {
        return Err(stow_types::stow_error!(
            "{oci_reference} is not in the single-pack layout; repack it before re-signing"
        ));
    };
    if layer.media_type != STOW_PACK_MEDIA_TYPE {
        return Err(stow_types::stow_error!(
            "{oci_reference} is not in the single-pack layout; repack it before re-signing"
        ));
    }

    let pack = bundle.layer(STOW_BUNDLE_PACK_PATH, layer)?.to_vec();
    let files = bundle.config.packed_files().cloned().collect::<Vec<_>>();
    let canonical_indices = canonical_output_indices(&bundle.config)
        .wrap_err_with(|| format!("validate canonical outputs of {oci_reference}"))?;
    let mut cleaned = bundle.config.clone();
    let (cleaned_config_bytes, cleaned_pack, stripped_legacy) =
        if canonical_indices.len() == bundle.config.outputs.len() {
            let pack = smol::unblock(move || {
                let expected = files.iter().collect::<Vec<_>>();
                stow_shim::unpack(&pack, &expected).map(|_| pack)
            })
            .await
            .wrap_err_with(|| format!("check the pack of {oci_reference}"))?;
            (bundle.config_bytes.clone(), pack, false)
        } else {
            // Pre-`stow#1495` bundles included cargo's per-invocation alias copy
            // alongside the stable-named outputs; strip the alias copy after
            // verifying every file's hash against the old signed config.
            let has_native_archive = bundle.config.native_archive.is_some();
            let orig_outputs_len = bundle.config.outputs.len();
            let unpacked = smol::unblock(move || {
                let expected = files.iter().collect::<Vec<_>>();
                stow_shim::unpack(&pack, &expected)
            })
            .await
            .wrap_err_with(|| format!("check the pack of {oci_reference}"))?;
            let mut retained_outputs = Vec::with_capacity(canonical_indices.len());
            let mut retained_bytes: Vec<(&str, &[u8])> =
                Vec::with_capacity(canonical_indices.len() + usize::from(has_native_archive));
            let mut artifact_size = 0u64;
            for &index in &canonical_indices {
                let output = bundle.config.outputs[index].clone();
                let bytes = &unpacked[index];
                artifact_size =
                    artifact_size.saturating_add(u64::try_from(bytes.len()).map_err(|_| {
                        stow_types::stow_error!("output of {oci_reference} exceeds u64 bytes")
                    })?);
                retained_outputs.push(output);
                retained_bytes.push((
                    bundle.config.outputs[index].file_name.as_str(),
                    bytes.as_slice(),
                ));
            }
            if let Some(native) = &bundle.config.native_archive {
                retained_bytes.push((
                    native.file_name.as_str(),
                    unpacked[orig_outputs_len].as_slice(),
                ));
            }
            let cleaned_pack = stow_shim::pack(&retained_bytes)
                .wrap_err_with(|| format!("re-pack canonical outputs of {oci_reference}"))?;
            cleaned.outputs = retained_outputs;
            cleaned.artifact_size = artifact_size;
            let cleaned_config_bytes = serde_json::to_vec(&cleaned)?;
            (cleaned_config_bytes, cleaned_pack, true)
        };

    let published = publish_packed(
        session,
        oci_reference,
        &cleaned,
        &cleaned_config_bytes,
        &cleaned_pack,
        sign,
    )
    .await?;
    if !stripped_legacy && published.oci_digest != record.oci_digest {
        return Err(stow_types::stow_error!(
            "republishing {oci_reference} produced {}, not the recorded {}",
            published.oci_digest,
            record.oci_digest
        ));
    }
    Ok(NodeResigned::Republished(Box::new(ArtifactRecord {
        oci_digest: published.oci_digest,
        artifact_size: cleaned.artifact_size,
        bundle_digest: published.bundle_digest,
        bundle_size: published.bundle_size,
        ..record.clone()
    })))
}

/// Whether the bundle `record` names carries a signature verifying under
/// `policy` for the record's reference and digest.
///
/// # Errors
///
/// The bundle cannot be pulled or fails a check of
/// [`crate::PulledBundle`].
pub async fn bundle_verifies(
    session: &RegistrySession,
    trust: &Trust,
    record: &ArtifactRecord,
    policy: &(impl VerificationPolicy + Sync),
) -> stow_types::error::Result<bool> {
    Ok(pull_bundle(session, record)
        .await?
        .verify(trust, policy)
        .is_ok())
}

/// The two signatures a re-sign makes, each under the new identity.
#[derive(Debug)]
pub struct Signers<'a, S, D> {
    /// Signs a records manifest and appends the signature to its `.sig`
    /// image.
    pub records: &'a S,
    /// Signs a node's manifest for its bundle and publishes nothing itself.
    pub node: &'a D,
}

/// What [`resign_task`] did.
#[derive(Debug)]
pub struct TaskResigned {
    /// Task id carried by the task's records manifests.
    pub task_id: Option<String>,
    /// Records tags that gained a signature.
    pub records_signed: usize,
    /// Records tags that already carried one under the new identity.
    pub records_already: usize,
    /// Nodes republished under the new identity.
    pub nodes_republished: usize,
    /// Nodes whose bundle already verified under the new identity.
    pub nodes_already: usize,
    /// The new records artifact, when any node was republished.
    pub published: Option<RecordsPublishOutcome>,
    /// Outer inline-signed manifest bytes of the task's newest build when no
    /// new records artifact was pushed, so a legacy `built-` marker can mirror it.
    pub newest_outer_bytes: Option<Vec<u8>>,
}

/// Re-sign one task's records and nodes under the new identity.
///
/// Each of its records tags is re-signed in place, each live row's node is
/// republished ([`resign_node`]), and — when any node was republished — one
/// new records artifact under `build` carries the task's rows, which the
/// index fold applies over the older tags' rows.
///
/// `tags` are the task's records tags, newest build first. The live rows
/// are the newest tag's row for each node, as the index fold resolves them.
/// Nothing is written for a task that already verifies under the new
/// identity throughout.
///
/// # Errors
///
/// A records artifact cannot be read or fails its checks, or any
/// [`resign_manifest`] or [`resign_node`] error.
pub async fn resign_task<O, N, S, Fut, D, DFut>(
    session: &RegistrySession,
    trust: &Trust,
    rustc_version: &WireRustcVersion,
    tags: &[&str],
    identities: Identities<'_, O, N>,
    build: BuildRun,
    signers: Signers<'_, S, D>,
) -> stow_types::error::Result<TaskResigned>
where
    O: VerificationPolicy + Sync,
    N: VerificationPolicy + Sync,
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>> + Send,
    D: Fn(String, String) -> DFut + Send + Sync,
    DFut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>> + Send,
{
    let Signers {
        records: sign,
        node: sign_node,
    } = signers;
    let mut outcome = TaskResigned {
        task_id: None,
        records_signed: 0,
        records_already: 0,
        nodes_republished: 0,
        nodes_already: 0,
        published: None,
        newest_outer_bytes: None,
    };
    let mut pulled = Vec::with_capacity(tags.len());
    let mut newest_rewritten: Option<Vec<u8>> = None;
    let mut newest_existing_outer: Option<Vec<u8>> = None;
    for (index, tag) in tags.iter().enumerate() {
        let mut fetched = pull_records_for_resign(session, tag).await?;
        let reference = session.reference(tag)?;
        let (resigned, rewritten) = resign_fetched_records(
            session,
            trust,
            &reference,
            &reference.to_string(),
            &mut fetched.pulled,
            fetched.inlined,
            identities,
            sign,
        )
        .await?;
        match resigned {
            Resigned::Signed => {
                outcome.records_signed += 1;
                if index == 0 {
                    newest_rewritten = rewritten;
                }
            }
            Resigned::Already => {
                outcome.records_already += 1;
                if index == 0 {
                    newest_existing_outer = Some(fetched.outer_bytes);
                }
            }
        }
        pulled.push(fetched.pulled);
    }
    let Some(first) = pulled.first() else {
        return Ok(outcome);
    };
    outcome.task_id = Some(first.task_id.clone());
    let rows =
        resign_live_nodes(session, trust, identities, &pulled, sign_node, &mut outcome).await?;
    if outcome.nodes_republished == 0 {
        if let Some(outer_bytes) = &newest_rewritten {
            let marker =
                session.reference(&published_tag(rustc_version.as_str(), &first.task_id))?;
            session
                .put_manifest(&marker, outer_bytes)
                .await
                .map_err(|error| {
                    stow_types::stow_error!("update published marker {marker}: {error}")
                })?;
        }
        outcome.newest_outer_bytes = newest_rewritten.or(newest_existing_outer);
        return Ok(outcome);
    }
    let local_programs = first.records.local_programs.clone();
    outcome.published = Some(
        push_records_with(
            session,
            rustc_version,
            &first.task_id,
            build,
            &BuildRecords {
                artifacts: rows,
                local_programs,
            },
            sign,
        )
        .await?,
    );
    Ok(outcome)
}

async fn resign_live_nodes<O, N, D, DFut>(
    session: &RegistrySession,
    trust: &Trust,
    identities: Identities<'_, O, N>,
    pulled: &[PulledRecords],
    sign_node: &D,
    outcome: &mut TaskResigned,
) -> stow_types::error::Result<Vec<ArtifactRecord>>
where
    O: VerificationPolicy + Sync,
    N: VerificationPolicy + Sync,
    D: Fn(String, String) -> DFut + Send + Sync,
    DFut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>> + Send,
{
    let mut seen = BTreeSet::new();
    let live = pulled
        .iter()
        .flat_map(|records| &records.records.artifacts)
        .filter(|record| seen.insert(record.oci_reference.as_str()))
        .collect::<Vec<_>>();
    let mut rows = Vec::with_capacity(live.len());
    for record in live {
        match resign_node(session, trust, identities, record, sign_node).await? {
            NodeResigned::Already => {
                outcome.nodes_already += 1;
                rows.push(record.clone());
            }
            NodeResigned::Republished(row) => {
                outcome.nodes_republished += 1;
                rows.push(*row);
            }
        }
    }
    Ok(rows)
}

/// Ensure a `built-<rustc>-<hash>` marker carries an inline records signature
/// under `identities.new`, updating legacy `.sig` or old-identity markers when needed.
///
/// # Errors
/// Fails when the marker cannot be pulled, verified under either identity, or updated.
pub async fn resign_marker<O, N, S, Fut>(
    session: &RegistrySession,
    trust: &Trust,
    rustc_version: &WireRustcVersion,
    tag: &str,
    newest_records_outer: Option<&[u8]>,
    identities: Identities<'_, O, N>,
    sign: &S,
) -> stow_types::error::Result<Resigned>
where
    O: VerificationPolicy + Sync,
    N: VerificationPolicy + Sync,
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>> + Send,
{
    let Identities { old, new } = identities;
    let reference = session.reference(tag)?;
    let repository = format!("{}/{}", reference.registry(), reference.repository());
    let (raw_bytes, manifest_digest) = session
        .pull_listed_manifest(&reference)
        .await
        .map_err(|error| stow_types::stow_error!("pull marker manifest {reference}: {error}"))?;
    let manifest: OciImageManifest = serde_json::from_slice(&raw_bytes)
        .wrap_err_with(|| format!("decode marker manifest {reference}"))?;
    let inlined = manifest
        .annotations
        .as_ref()
        .is_some_and(|map| map.contains_key(RECORDS_SIGNATURES_ANNOTATION));
    if inlined {
        let pulled = pull_listed_records_by_tag(session, tag).await?;
        if pulled.verify_marker(trust, &repository, rustc_version.as_str(), new) {
            return Ok(Resigned::Already);
        }
    }
    if let Some(outer_bytes) = newest_records_outer {
        session
            .put_manifest(&reference, outer_bytes)
            .await
            .map_err(|error| stow_types::stow_error!("write marker {reference}: {error}"))?;
        return verify_updated_marker(session, trust, &reference, &repository, rustc_version, new)
            .await;
    }
    resign_orphan_marker(
        session,
        trust,
        &reference,
        &repository,
        rustc_version,
        &raw_bytes,
        &manifest_digest,
        &manifest,
        inlined,
        Identities { old, new },
        sign,
    )
    .await
}

async fn verify_updated_marker<N: VerificationPolicy + Sync>(
    session: &RegistrySession,
    trust: &Trust,
    reference: &Reference,
    repository: &str,
    rustc_version: &WireRustcVersion,
    new: &N,
) -> stow_types::error::Result<Resigned> {
    let pulled = pull_listed_records_by_tag(session, reference.tag().unwrap_or_default()).await?;
    if pulled.verify_marker(trust, repository, rustc_version.as_str(), new) {
        Ok(Resigned::Signed)
    } else {
        Err(stow_types::stow_error!(
            "marker {reference} carries no inline records signature for {} under the new identity",
            pulled.signed_digest
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn resign_orphan_marker<O, N, S, Fut>(
    session: &RegistrySession,
    trust: &Trust,
    reference: &Reference,
    repository: &str,
    rustc_version: &WireRustcVersion,
    raw_bytes: &[u8],
    manifest_digest: &str,
    manifest: &OciImageManifest,
    inlined: bool,
    identities: Identities<'_, O, N>,
    sign: &S,
) -> stow_types::error::Result<Resigned>
where
    O: VerificationPolicy + Sync,
    N: VerificationPolicy + Sync,
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>> + Send,
{
    let Identities { old, new } = identities;
    let (task_id, signed_digest, mut envelope, materials) = if inlined {
        let (task_id, signed_digest, envelope, descriptor) =
            parse_signed_records_manifest(reference, manifest)?;
        let bytes = pull_blob_verified(session, descriptor).await?;
        let _: BuildRecords = serde_json::from_slice(&bytes)
            .map_err(|error| stow_types::stow_error!("decode marker layer {reference}: {error}"))?;
        let materials = envelope.materials();
        (task_id, signed_digest, envelope, materials)
    } else {
        let task_id = validate_legacy_records_manifest(reference, manifest)?;
        let bytes = pull_blob_verified(session, &manifest.layers[0]).await?;
        let _: BuildRecords = serde_json::from_slice(&bytes)
            .map_err(|error| stow_types::stow_error!("decode marker layer {reference}: {error}"))?;
        let materials =
            pull_listed_signature_materials(session, reference, manifest_digest).await?;
        let signatures = materials
            .iter()
            .map(RecordsSignature::from_material)
            .collect::<stow_types::error::Result<Vec<_>>>()?;
        let signed_manifest = String::from_utf8(raw_bytes.to_vec())
            .map_err(|error| stow_types::stow_error!("legacy marker {reference} UTF-8: {error}"))?;
        (
            task_id,
            manifest_digest.to_owned(),
            RecordsSignatureEnvelope {
                signed_manifest,
                signatures,
            },
            materials,
        )
    };
    let expected_hash = task_id_hash(&task_id);
    let already_new = materials.iter().any(|material| {
        marker_material_matches(
            trust,
            repository,
            rustc_version.as_str(),
            expected_hash.as_str(),
            &signed_digest,
            material,
            new,
        )
    });
    if !already_new {
        let bound = materials
            .iter()
            .find(|material| {
                marker_material_matches(
                    trust,
                    repository,
                    rustc_version.as_str(),
                    expected_hash.as_str(),
                    &signed_digest,
                    material,
                    old,
                )
            })
            .and_then(|material| payload_docker_reference(&material.payload_bytes))
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "marker {reference}@{signed_digest} has no records signature under the old identity"
                )
            })?;
        let material = sign(bound, signed_digest).await?;
        envelope
            .signatures
            .push(RecordsSignature::from_material(&material)?);
    }
    let outer_bytes = records_manifest_with_envelope(&envelope)?;
    session
        .put_manifest(reference, &outer_bytes)
        .await
        .map_err(|error| stow_types::stow_error!("write re-signed marker {reference}: {error}"))?;
    verify_updated_marker(session, trust, reference, repository, rustc_version, new).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rustc() -> WireRustcVersion {
        WireRustcVersion::parse("1.99.0").unwrap()
    }

    #[test]
    fn every_kind_of_tag_the_repository_holds_classifies() {
        let hash = "0123456789abcdef".repeat(4);
        let target = CI_TARGET_TRIPLES[0];
        let node = "serde.1.0.0-x86_64-linux-1.99.0-0a1b2c3d-deadbeef";
        for (tag, class) in [
            (format!("records-1.99.0-{hash}"), TagClass::Records),
            (format!("records-1.99.0-{hash}-9-1"), TagClass::Records),
            (format!("built-1.99.0-{hash}"), TagClass::Built),
            (node.to_owned(), TagClass::Node),
            (format!("{node}-pm"), TagClass::Node),
            (format!("{node}-dy.bundle"), TagClass::Bundle),
            (format!("sha256-{hash}.sig"), TagClass::Signature),
            (format!("index.{target}.1.99.0"), TagClass::Index),
            (format!("folded.{target}.1.99.0"), TagClass::Folded),
            // A crate named like a slice is still a node.
            (
                "index.1.0.0-x86_64-linux-1.99.0-0a1b2c3d-deadbeef".to_owned(),
                TagClass::Node,
            ),
        ] {
            assert_eq!(classify_tag(&tag, &rustc()), Ok(class), "{tag}");
        }
    }

    #[test]
    fn a_tag_of_no_kind_is_refused() {
        let hash = "0123456789abcdef".repeat(4);
        let target = CI_TARGET_TRIPLES[0];
        for tag in [
            "latest".to_owned(),
            format!("records-1.98.0-{hash}"),
            format!("built-1.98.0-{hash}"),
            "built-1.99.0-abc".to_owned(),
            format!("index.{target}.1.98.0"),
            "index.not-a-target.1.99.0".to_owned(),
            format!("sha256-{}.sig", "ab"),
            "serde.1.0.0-x86_64-linux-1.98.0-0a1b2c3d-deadbeef".to_owned(),
            "serde.1.0.0-x86_64-linux-1.99.0-0a1b2c3d-deadbeef.sbom".to_owned(),
            "serde.1.0.0.bundle".to_owned(),
        ] {
            assert_eq!(
                classify_tag(&tag, &rustc()),
                Err(UnknownTag(tag.clone())),
                "{tag}"
            );
        }
    }
}

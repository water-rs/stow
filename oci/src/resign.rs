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
//! * a node, whose bundle tar carries the signature material the CLI
//!   verifies: [`resign_node`] republishes the node's pack under the new
//!   identity and returns the row naming the new bundle;
//! * the tag space of a rustc's repository, every tag of which belongs to
//!   one of those kinds or is refused ([`classify_tag`]).

use std::collections::BTreeSet;
use std::io::Read as _;

use oci_client::Reference;
use oci_client::manifest::OciImageManifest;
/// The policy accepting one exact certificate subject from one issuer —
/// what a caller verifies the old identity's signatures with.
pub use sigstore::bundle::verify::policy::Identity as ExactIdentity;
/// The trait a caller's policies implement.
pub use sigstore::bundle::verify::policy::VerificationPolicy;
use stow_types::api::{ArtifactRecord, CI_TARGET_TRIPLES};
use stow_types::bundle::{
    ArtifactBlobConfig, ArtifactBundleManifest, BundleSignatureMaterial, STOW_BUNDLE_MANIFEST_PATH,
    STOW_PACK_MEDIA_TYPE, STOW_SIGSTORE_PAYLOAD_DIR,
};
use stow_types::error::Context as _;
use stow_types::identity::WireRustcVersion;
use stow_types::records::{BuildRecords, BuildRun, is_records_tag, parse_records_tag};
use stow_types::registry::verify_oci_digest;

use crate::artifacts::{publish_packed, pull_signature_materials};
use crate::client::RegistrySession;
use crate::records::{RecordsPublishOutcome, pull_records_by_tag, push_records_with};
use crate::registry::pull_blob_verified;
use crate::verify::{Trust, verify_materials};

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
/// The node is trusted only after: the manifest hashes to the record's
/// `oci_digest`, its signature verifies under the old identity (or already
/// under the new one) for the record's `oci_reference`, the config blob and
/// the pack hash to their descriptors, and every file of the pack hashes to
/// the SHA-256 the signed config records. The same config and pack then
/// publish through a build's own path: the manifest is byte-identical, so
/// its digest does not move; the signature image gains a layer under the new
/// identity; and the bundle, which carries that layer alone, is new — so
/// the row's `bundle_digest` and `bundle_size` are.
///
/// A node whose bundle already verifies under the new identity is left
/// alone, and a signature layer a crashed earlier attempt already made is
/// reused instead of signed again.
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
    let by_digest = session.digest_reference(&record.oci_digest)?;
    let (manifest_bytes, manifest_digest) = session
        .pull_manifest(&by_digest)
        .await
        .map_err(|error| stow_types::stow_error!("pull manifest of {oci_reference}: {error}"))?;
    if manifest_digest != record.oci_digest {
        return Err(stow_types::stow_error!(
            "the manifest of {oci_reference} hashes to {manifest_digest}, the record names {}",
            record.oci_digest
        ));
    }
    let manifest: OciImageManifest = serde_json::from_slice(&manifest_bytes)
        .wrap_err_with(|| format!("parse manifest of {oci_reference}"))?;
    let [layer] = manifest.layers.as_slice() else {
        return Err(stow_types::stow_error!(
            "{oci_reference} is not in the single-pack layout; repack it before re-signing"
        ));
    };
    if layer.media_type != STOW_PACK_MEDIA_TYPE {
        return Err(stow_types::stow_error!(
            "{oci_reference} is not in the single-pack layout; repack it before re-signing"
        ));
    }

    let materials = pull_signature_materials(session, &by_digest, &manifest_digest).await?;
    let existing = materials.iter().find(|material| {
        verify_materials(
            trust,
            oci_reference,
            &manifest_digest,
            std::slice::from_ref(*material),
            new,
        )
        .is_ok()
    });
    if existing.is_some() && bundle_verifies(session, trust, record, new).await? {
        return Ok(NodeResigned::Already);
    }
    if existing.is_none() {
        verify_materials(trust, oci_reference, &manifest_digest, &materials, old)
            .wrap_err_with(|| format!("verify {oci_reference} under the old identity"))?;
    }

    let config_bytes = pull_blob_verified(session, &manifest.config).await?;
    let config: ArtifactBlobConfig = serde_json::from_slice(&config_bytes)
        .wrap_err_with(|| format!("parse config of {oci_reference}"))?;
    let pack = pull_blob_verified(session, layer).await?;
    let files = config.packed_files().cloned().collect::<Vec<_>>();
    let pack = smol::unblock(move || {
        let expected = files.iter().collect::<Vec<_>>();
        stow_shim::unpack(&pack, &expected).map(|_| pack)
    })
    .await
    .wrap_err_with(|| format!("check the pack of {oci_reference}"))?;

    let reuse = existing.cloned();
    let sign_or_reuse = |reference: String, digest: String| {
        let reuse = reuse.clone();
        async move {
            match reuse {
                Some(material) => Ok(material),
                None => sign(reference, digest).await,
            }
        }
    };
    let published = publish_packed(
        session,
        oci_reference,
        &config,
        &config_bytes,
        &pack,
        &sign_or_reuse,
    )
    .await?;
    if published.oci_digest != record.oci_digest {
        return Err(stow_types::stow_error!(
            "republishing {oci_reference} produced {}, not the recorded {}",
            published.oci_digest,
            record.oci_digest
        ));
    }
    Ok(NodeResigned::Republished(Box::new(ArtifactRecord {
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
/// The bundle cannot be pulled, does not hash to its digest, or is not a
/// bundle tar.
pub async fn bundle_verifies(
    session: &RegistrySession,
    trust: &Trust,
    record: &ArtifactRecord,
    policy: &(impl VerificationPolicy + Sync),
) -> stow_types::error::Result<bool> {
    let bytes = session
        .pull_blob(&record.bundle_digest)
        .await
        .map_err(|error| {
            stow_types::stow_error!("pull bundle {}: {error}", record.bundle_digest)
        })?;
    verify_oci_digest(&bytes, &record.bundle_digest).map_err(|error| {
        stow_types::stow_error!("verify bundle {}: {error}", record.bundle_digest)
    })?;
    let materials = smol::unblock(move || bundle_signatures(&bytes))
        .await
        .wrap_err_with(|| format!("read bundle {}", record.bundle_digest))?;
    Ok(verify_materials(
        trust,
        &record.oci_reference,
        &record.oci_digest,
        &materials,
        policy,
    )
    .is_ok())
}

/// What [`resign_task`] did.
#[derive(Debug)]
pub struct TaskResigned {
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
pub async fn resign_task<O, N, S, Fut>(
    session: &RegistrySession,
    trust: &Trust,
    rustc_version: &WireRustcVersion,
    tags: &[&str],
    identities: Identities<'_, O, N>,
    build: BuildRun,
    sign: &S,
) -> stow_types::error::Result<TaskResigned>
where
    O: VerificationPolicy + Sync,
    N: VerificationPolicy + Sync,
    S: Fn(String, String) -> Fut + Send + Sync,
    Fut: Future<Output = stow_types::error::Result<BundleSignatureMaterial>> + Send,
{
    let mut outcome = TaskResigned {
        records_signed: 0,
        records_already: 0,
        nodes_republished: 0,
        nodes_already: 0,
        published: None,
    };
    let mut pulled = Vec::with_capacity(tags.len());
    for tag in tags {
        let records = pull_records_by_tag(session, tag).await?;
        let reference = session.reference(tag)?;
        let resigned = resign_manifest(
            session,
            trust,
            &reference,
            &reference.to_string(),
            &records.manifest_digest,
            identities,
            sign,
        )
        .await?;
        match resigned {
            Resigned::Signed => outcome.records_signed += 1,
            Resigned::Already => outcome.records_already += 1,
        }
        pulled.push(records);
    }
    let Some(first) = pulled.first() else {
        return Ok(outcome);
    };
    let mut seen = BTreeSet::new();
    let live = pulled
        .iter()
        .flat_map(|records| &records.records.artifacts)
        .filter(|record| seen.insert(record.oci_reference.as_str()))
        .collect::<Vec<_>>();
    let mut rows = Vec::with_capacity(live.len());
    for record in live {
        match resign_node(session, trust, identities, record, sign).await? {
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
    if outcome.nodes_republished == 0 {
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

/// The signature materials a bundle tar carries: its manifest's signatures,
/// each with its payload entry.
fn bundle_signatures(bytes: &[u8]) -> stow_types::error::Result<Vec<BundleSignatureMaterial>> {
    let mut archive = tar::Archive::new(bytes);
    let mut manifest = None;
    let mut payloads = std::collections::BTreeMap::new();
    for entry in archive.entries().wrap_err("read the bundle entries")? {
        let mut entry = entry.wrap_err("read a bundle entry")?;
        let path = entry
            .path()
            .wrap_err("read a bundle entry path")?
            .to_string_lossy()
            .into_owned();
        let signature_payload = path
            .strip_prefix(STOW_SIGSTORE_PAYLOAD_DIR)
            .is_some_and(|rest| rest.starts_with('/'));
        if path != STOW_BUNDLE_MANIFEST_PATH && !signature_payload {
            continue;
        }
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .wrap_err_with(|| format!("read bundle entry {path}"))?;
        if path == STOW_BUNDLE_MANIFEST_PATH {
            manifest = Some(
                serde_json::from_slice::<ArtifactBundleManifest>(&contents)
                    .wrap_err("parse the bundle manifest")?,
            );
        } else {
            payloads.insert(path, contents);
        }
    }
    let manifest = manifest.ok_or_else(|| stow_types::stow_error!("the bundle has no manifest"))?;
    manifest
        .sigstore_signatures
        .into_iter()
        .map(|signature| {
            let payload_bytes = payloads.remove(&signature.payload_path).ok_or_else(|| {
                stow_types::stow_error!("the bundle lacks {}", signature.payload_path)
            })?;
            Ok(BundleSignatureMaterial {
                payload_path: signature.payload_path,
                payload_bytes,
                signature: signature.signature,
                certificate_pem: signature.certificate_pem,
                rekor_bundle_json: signature.rekor_bundle_json,
            })
        })
        .collect()
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

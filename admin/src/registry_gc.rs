//! `stow-admin registry gc` — delete every version of the `stow-cache`
//! GHCR package that no kept toolchain's published state reaches
//! (stow#730).
//!
//! Every publish leaves superseded manifests behind: an `index`/ `folded`
//! republish untags the previous manifest, a rebuilt task's old `records`
//! artifact and its bundles stay tagged forever, and cosign's
//! `sha256-<digest>[.sig]` signature manifests accumulate under no other
//! retention. The command enumerates the package's versions through the
//! GitHub REST packages API, classifies each by tag shape, pulls the kept
//! toolchains' slices, folded sets and records through the anonymous OCI
//! session, and deletes whatever nothing keeps — except versions younger
//! than `--min-age-hours`, since a build pushes its bundle before its
//! records and a fresh bundle is legitimately unreferenced for a while.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::index_cmd::index_tag_parts;
use clap::{Args, Subcommand};
use futures_util::{StreamExt as _, TryStreamExt as _};
use stow_types::api::ArtifactRecord;
use stow_types::identity::WireRustcVersion;
use stow_types::index::{ArtifactIndex, folded_tag, folded_tag_parts};
use stow_types::records::{RECORDS_ARTIFACT_TYPE, parse_records_tag};
use stow_types::registry::{
    GHCR_REPOSITORY, artifact_bundle_tag, is_sha256_digest, oci_reference_tag,
};
use stow_types::stow_error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::github;
use crate::render::{self, Output, Table};

/// Package-version fan-out for content pulls and deletes — the same
/// bound `index export` pulls records under (`index_cmd`'s
/// `RECORDS_PULL_CONCURRENCY`): independent registry reads overlap,
/// never unbounded.
const GC_CONCURRENCY: usize = 16;

/// The listing page size the versions endpoint serves.
const VERSIONS_PAGE: &str = "?per_page=100";

#[derive(Args)]
pub struct RegistryArgs {
    #[command(subcommand)]
    pub command: RegistryCommand,
}

#[derive(Subcommand)]
pub enum RegistryCommand {
    /// Delete every `stow-cache` package version no kept slice reaches.
    /// Reports without `--delete`; the operator names the surviving
    /// toolchains explicitly because a new stable's slices may not exist
    /// yet while the previous one still serves users.
    Gc(GcArgs),
}

#[derive(Args)]
pub struct GcArgs {
    /// Toolchain whose published state survives — repeatable.
    #[arg(long, required = true)]
    pub keep_rustc: Vec<String>,
    /// A package version created or updated within this many hours is
    /// never deleted.
    #[arg(long, default_value_t = 24)]
    pub min_age_hours: u64,
    /// Delete the garbage versions. Without it the command only reports.
    #[arg(long)]
    pub delete: bool,
}

pub async fn run(token: &str, args: RegistryArgs, output: Output) -> stow_types::error::Result<()> {
    match args.command {
        RegistryCommand::Gc(args) => gc(token, args, output).await,
    }
}

/// One `GET …/versions` row: the manifest digest in `name`, the tags it
/// carries, and the timestamps the age guard reads.
#[derive(Debug, serde::Deserialize)]
struct PackageVersion {
    /// GitHub's version id — the DELETE path's key.
    id: u64,
    /// The manifest digest (`sha256:<hex>`).
    name: String,
    created_at: String,
    updated_at: String,
    metadata: VersionMetadata,
}

#[derive(Debug, serde::Deserialize)]
struct VersionMetadata {
    container: ContainerMetadata,
}

#[derive(Debug, serde::Deserialize)]
struct ContainerMetadata {
    #[serde(default)]
    tags: Vec<String>,
}

/// What one tag of a package version names. The classifier shares the
/// producers' parsers — [`index_tag_parts`]/[`folded_tag_parts`] for the
/// slice pair, [`parse_records_tag`] for records, the cosign tag shape
/// for signatures, and [`artifact_bundle_tag`] for the publish's
/// artifact/bundle pair.
#[derive(Debug)]
enum TagClass<'a> {
    /// `index.<target>.<rustc>` — a published index slice.
    Slice { target: &'a str, rustc: &'a str },
    /// `folded.<target>.<rustc>` — the slice's folded-set companion. The
    /// target is unused: the keep rule reads only the companion tag.
    Folded { rustc: &'a str },
    /// `records-<rustc>-<task hash>[-<run id>-<attempt>]` — one build's
    /// records artifact.
    Records { rustc: &'a str },
    /// `sha256-<hex>[.sig]` — the signature or referrer manifest of
    /// subject `sha256:<hex>`.
    Signature { subject: String },
    /// `<tag>` / `<tag>.bundle` — a build's signed artifact manifest and
    /// its bundle manifest. `bundle` is true on the `.bundle` half.
    Bundle { artifact_tag: &'a str, bundle: bool },
}

impl TagClass<'_> {
    /// The report's class label.
    fn name(&self) -> &'static str {
        match self {
            Self::Slice { .. } => "slice",
            Self::Folded { .. } => "folded",
            Self::Records { .. } => "records",
            Self::Signature { .. } => "signature",
            Self::Bundle { .. } => "bundle",
        }
    }
}

/// Classify one tag. `None` is an unknown shape — the command refuses
/// to delete anything while an unrecognized tag exists.
fn classify_tag(tag: &str) -> Option<TagClass<'_>> {
    if let Some((target, rustc)) = index_tag_parts(tag) {
        return Some(TagClass::Slice { target, rustc });
    }
    if let Some((_target, rustc)) = folded_tag_parts(tag) {
        return Some(TagClass::Folded { rustc });
    }
    if let Some(records) = parse_records_tag(tag) {
        return Some(TagClass::Records {
            rustc: records.rustc_version,
        });
    }
    if let Some(subject) = signature_subject(tag) {
        return Some(TagClass::Signature { subject });
    }
    artifact_bundle_tag(tag).map(|stem| TagClass::Bundle {
        artifact_tag: stem,
        bundle: tag.ends_with(stow_types::registry::BUNDLE_TAG_SUFFIX),
    })
}

/// The `sha256:<hex>` manifest digest a `sha256-<hex>[.sig]` tag signs —
/// the cosign tag layout `sigstore_signature_tag` produces, and the OCI
/// 1.1 referrers fallback tag with the `.sig` absent.
fn signature_subject(tag: &str) -> Option<String> {
    let hex = tag.strip_prefix("sha256-")?;
    let hex = hex.strip_suffix(".sig").unwrap_or(hex);
    let digest = format!("sha256:{hex}");
    is_sha256_digest(&digest).then_some(digest)
}

/// One listed version distilled to what the keep rules read.
struct Version {
    /// GitHub's version id — the DELETE path's key.
    id: u64,
    /// The manifest digest (`sha256:<hex>`).
    digest: String,
    /// The tags the version carries; empty is the untagged class.
    tags: Vec<String>,
    /// Inside `--min-age-hours` — garbage but never deleted.
    too_young: bool,
}

/// The fields of a decoded [`ArtifactRecord`] the keep rules read —
/// extracted at pull time so evaluation needs no record machinery.
struct RecordFact {
    /// Manifest digest of the record's signed artifact.
    oci_digest: String,
    /// The artifact tag of `oci_reference` — the `.bundle` stem.
    artifact_tag: String,
    /// The bundle blob digest index rows name.
    bundle_digest: String,
}

/// What the content pulls answered for the tags that name data —
/// everything the keep rules need, gathered under [`GC_CONCURRENCY`].
#[derive(Default)]
struct Facts {
    /// `index.<t>.<R>` → the slice's rows' bundle digests. Present only
    /// when the pulled slice decoded under the current index format.
    slice_bundles: BTreeMap<String, BTreeSet<String>>,
    /// `folded.<t>.<R>` → the records tags the folded set lists.
    folded: BTreeMap<String, Vec<String>>,
    /// `records-*` → the decoded rows' facts, or the layer's decode
    /// error text.
    records: BTreeMap<String, Result<Vec<RecordFact>, String>>,
}

/// One version's fate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Fate {
    Kept,
    Garbage,
    /// Garbage the age guard shelters.
    TooYoung,
}

/// The evaluation's output: the keep set, per-version fates and the
/// aggregates the report prints.
#[derive(Debug)]
struct Evaluation {
    /// Manifest digests the kept state reaches.
    keep: BTreeSet<String>,
    /// Per class label: kept / garbage / too-young counts.
    classes: BTreeMap<&'static str, [u64; 3]>,
    /// Decode-error message → how many garbage records artifacts failed
    /// with it.
    records_errors: BTreeMap<String, u64>,
    /// `(version id, display)` of every garbage version old enough to
    /// delete.
    delete: Vec<(u64, String)>,
}

/// The keep-set evaluation, pure: every rule the brief's table states.
///
/// A version is kept when its manifest digest lands in the keep set:
/// a kept toolchain's decodable `index.<t>.<R>` plus its `folded.<t>.<R>`
/// companion, a kept toolchain's records artifact that decodes and is
/// either not folded yet or still bundles a row a kept slice serves, the
/// artifact manifests and `.bundle` manifests those kept records name,
/// and every signature/referrer whose subject is kept. Everything else
/// — untagged manifests included — is garbage unless the age guard
/// shelters it.
///
/// # Errors
///
/// The sorted list of tags no classifier recognized — the command fails
/// before deleting anything.
fn evaluate(
    versions: &[Version],
    keep_rustc: &BTreeSet<String>,
    facts: &Facts,
) -> Result<Evaluation, Vec<String>> {
    let mut unknown = Vec::new();
    for version in versions {
        for tag in &version.tags {
            if classify_tag(tag).is_none() {
                unknown.push(tag.clone());
            }
        }
    }
    if !unknown.is_empty() {
        unknown.sort();
        unknown.dedup();
        return Err(unknown);
    }

    let mut keep: BTreeSet<String> = BTreeSet::new();
    // Folded tags whose sibling slice decoded — `folded.<t>.<R>` for each
    // live `index.<t>.<R>`.
    let mut live_folded: BTreeSet<String> = BTreeSet::new();
    // Bundle digests every kept slice's rows serve.
    let mut slice_bundles: BTreeSet<String> = BTreeSet::new();
    for version in versions {
        for tag in &version.tags {
            if let TagClass::Slice { target, rustc } = classify_tag(tag).expect("classified")
                && keep_rustc.contains(rustc)
                && let Some(bundles) = facts.slice_bundles.get(tag)
            {
                keep.insert(version.digest.clone());
                slice_bundles.extend(bundles.iter().cloned());
                live_folded.insert(folded_tag(target, rustc));
            }
        }
    }
    // Records tags every kept folded set lists — a folded set is kept
    // only beside its slice.
    let mut folded_membership: BTreeSet<String> = BTreeSet::new();
    for version in versions {
        for tag in &version.tags {
            if let TagClass::Folded { rustc, .. } = classify_tag(tag).expect("classified")
                && keep_rustc.contains(rustc)
                && live_folded.contains(tag.as_str())
            {
                keep.insert(version.digest.clone());
                if let Some(tags) = facts.folded.get(tag) {
                    folded_membership.extend(tags.iter().cloned());
                }
            }
        }
    }
    // Kept records artifacts contribute their records' artifact
    // manifests (by `oci_digest`) and artifact tags (the `.bundle` stem).
    let mut keep_oci_digests: BTreeSet<String> = BTreeSet::new();
    let mut keep_artifact_tags: BTreeSet<String> = BTreeSet::new();
    let mut records_errors: BTreeMap<String, u64> = BTreeMap::new();
    for version in versions {
        for tag in &version.tags {
            let TagClass::Records { rustc } = classify_tag(tag).expect("classified") else {
                continue;
            };
            if !keep_rustc.contains(rustc) {
                continue;
            }
            let kept = match facts.records.get(tag) {
                Some(Ok(records)) => {
                    let folded_in = folded_membership.contains(tag);
                    let live = records
                        .iter()
                        .any(|record| slice_bundles.contains(&record.bundle_digest));
                    // Folded and no record still bundled in a kept slice:
                    // the superseded export. Otherwise the artifact is
                    // unexported yet, or live — both keep.
                    !folded_in || live
                }
                Some(Err(message)) => {
                    *records_errors.entry(message.clone()).or_default() += 1;
                    false
                }
                None => false,
            };
            if kept {
                keep.insert(version.digest.clone());
                if let Some(Ok(records)) = facts.records.get(tag) {
                    for record in records {
                        keep_oci_digests.insert(record.oci_digest.clone());
                        keep_artifact_tags.insert(record.artifact_tag.clone());
                    }
                }
            }
        }
    }
    // Bundle manifests and signatures resolve against the keep set the
    // records pass finished.
    for version in versions {
        for tag in &version.tags {
            match classify_tag(tag).expect("classified") {
                TagClass::Bundle {
                    artifact_tag,
                    bundle: true,
                } if keep_artifact_tags.contains(artifact_tag) => {
                    keep.insert(version.digest.clone());
                }
                TagClass::Bundle { bundle: false, .. }
                    if keep_oci_digests.contains(&version.digest) =>
                {
                    keep.insert(version.digest.clone());
                }
                TagClass::Signature { subject } if keep.contains(&subject) => {
                    keep.insert(version.digest.clone());
                }
                _ => {}
            }
        }
    }

    let mut classes: BTreeMap<&'static str, [u64; 3]> = BTreeMap::new();
    let mut delete = Vec::new();
    for version in versions {
        let class = version
            .tags
            .first()
            .map(|tag| classify_tag(tag).expect("classified").name())
            .unwrap_or("untagged");
        let fate = if keep.contains(&version.digest) {
            Fate::Kept
        } else if version.too_young {
            Fate::TooYoung
        } else {
            Fate::Garbage
        };
        classes.entry(class).or_default()[fate as usize] += 1;
        if fate == Fate::Garbage {
            delete.push((
                version.id,
                format!("{} ({})", version.digest, version.tags.join(", ")),
            ));
        }
    }
    Ok(Evaluation {
        keep,
        classes,
        records_errors,
        delete,
    })
}

/// The gc report's plan half — serializable for `--json`.
#[derive(Debug, serde::Serialize)]
struct GcPlan {
    keep_rustc: Vec<String>,
    min_age_hours: u64,
    /// Class label → `{kept, garbage, too_young}` counts.
    classes: BTreeMap<String, ClassCounts>,
    /// Decode error → garbage records artifact count.
    undecodable_records: BTreeMap<String, u64>,
    /// Versions `--delete` removes (`digest (tags)`).
    delete: Vec<String>,
    /// The version ids behind `delete` — execution state, not report.
    #[serde(skip)]
    delete_ids: Vec<u64>,
}

#[derive(Debug, serde::Serialize)]
struct ClassCounts {
    kept: u64,
    garbage: u64,
    too_young: u64,
}

/// What `--delete` did.
#[derive(Debug, serde::Serialize)]
struct GcOutcome {
    deleted: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    failed: Vec<String>,
}

async fn gc(token: &str, args: GcArgs, output: Output) -> stow_types::error::Result<()> {
    let mut keep_rustc = BTreeSet::new();
    for rustc in &args.keep_rustc {
        keep_rustc.insert(
            WireRustcVersion::parse(rustc)
                .map_err(|error| stow_error!("--keep-rustc {rustc}: {error}"))?
                .as_str()
                .to_owned(),
        );
    }
    let (org, package) = GHCR_REPOSITORY
        .split_once('/')
        .expect("GHCR_REPOSITORY is org/package");
    let versions: Vec<PackageVersion> = github::get_pages(
        token,
        &format!("/orgs/{org}/packages/container/{package}/versions{VERSIONS_PAGE}"),
    )
    .await?;

    let now = OffsetDateTime::now_utc();
    let min_age = time::Duration::hours(i64::try_from(args.min_age_hours).unwrap_or(i64::MAX));
    let mut distilled = Vec::with_capacity(versions.len());
    for version in versions {
        let touched = [&version.created_at, &version.updated_at]
            .into_iter()
            .map(|stamp| {
                OffsetDateTime::parse(stamp, &Rfc3339)
                    .map_err(|error| stow_error!("version {} timestamp: {error}", version.id))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .expect("two timestamps");
        distilled.push(Version {
            id: version.id,
            digest: version.name,
            tags: version.metadata.container.tags,
            too_young: now - touched < min_age,
        });
    }

    let base = crate::index_cmd::registry_base()?;
    let http = stow_oci::RegistryHttp::new().await?;
    let session = base.session(&http);
    let facts = gather(&session, &base, &distilled, &keep_rustc).await?;

    let evaluation = evaluate(&distilled, &keep_rustc, &facts).map_err(|unknown| {
        stow_error!(
            "refusing to run: unrecognized package tags — {}",
            unknown.join(", ")
        )
    })?;
    tracing::info!(
        kept_manifests = evaluation.keep.len(),
        deleting = evaluation.delete.len(),
        "registry gc evaluated {} versions",
        distilled.len()
    );

    let plan = GcPlan {
        keep_rustc: keep_rustc.iter().cloned().collect(),
        min_age_hours: args.min_age_hours,
        classes: evaluation
            .classes
            .iter()
            .map(|(class, [kept, garbage, too_young])| {
                (
                    (*class).to_owned(),
                    ClassCounts {
                        kept: *kept,
                        garbage: *garbage,
                        too_young: *too_young,
                    },
                )
            })
            .collect(),
        undecodable_records: evaluation.records_errors,
        delete: evaluation
            .delete
            .iter()
            .map(|(_, show)| show.clone())
            .collect(),
        delete_ids: evaluation.delete.iter().map(|(id, _)| *id).collect(),
    };

    let mut outcome = None;
    if args.delete {
        let mut deleted = 0_u64;
        let mut failed = Vec::new();
        let deletes = futures_util::stream::iter(plan.delete_ids.iter().map(|id| async move {
            github::delete_path(
                token,
                &format!("/orgs/{org}/packages/container/{package}/versions/{id}"),
            )
            .await
            .map_err(|error| format!("version {id}: {error}"))
        }))
        .buffered(GC_CONCURRENCY)
        .collect::<Vec<_>>();
        for result in deletes.await {
            match result {
                Ok(()) => deleted += 1,
                Err(error) => failed.push(error),
            }
        }
        outcome = Some(GcOutcome { deleted, failed });
    }

    let envelope = render::Planned {
        dry_run: !args.delete,
        plan,
        result: outcome,
    };
    let failed = envelope
        .result
        .as_ref()
        .map(|outcome| outcome.failed.clone())
        .unwrap_or_default();
    render::emit(output, &envelope, |envelope| human(envelope))?;
    if failed.is_empty() {
        Ok(())
    } else {
        Err(stow_error!("registry gc: {}", failed.join("; ")))
    }
}

fn human(envelope: &render::Planned<GcPlan, GcOutcome>) -> String {
    let plan = &envelope.plan;
    let mut out = format!(
        "registry gc: keeping rustc {}\n",
        plan.keep_rustc.join(", ")
    );
    let mut table = Table::new(&["class", "kept", "garbage", "too young"]);
    for (class, counts) in &plan.classes {
        table.push([
            class.clone(),
            counts.kept.to_string(),
            counts.garbage.to_string(),
            counts.too_young.to_string(),
        ]);
    }
    if !table.is_empty() {
        let _ = write!(out, "{}", table.render());
    }
    if !plan.undecodable_records.is_empty() {
        let _ = writeln!(out, "\nundecodable records artifacts:");
        for (message, count) in &plan.undecodable_records {
            let _ = writeln!(out, "  {count} × {message}");
        }
    }
    if let Some(result) = &envelope.result {
        let _ = write!(out, "\ndeleted {} version(s)", result.deleted);
        for failure in &result.failed {
            let _ = write!(out, "\n  failed: {failure}");
        }
    }
    let _ = write!(out, "\n{}", render::plan_footer(envelope.dry_run));
    out
}

/// Pull every kept toolchain's content the keep rules read: each
/// `index.<t>.<R>` slice (a slice that does not decode keeps nothing),
/// then the `folded.<t>.<R>` companions of the slices that decoded, and
/// every `records-<R>-*` artifact's rows (a layer that does not decode
/// records a decode error rather than failing the run). Transport
/// failures stay fatal — a registry blip must not read as garbage.
async fn gather(
    session: &stow_oci::RegistrySession,
    base: &stow_oci::RegistryBase,
    versions: &[Version],
    keep_rustc: &BTreeSet<String>,
) -> stow_types::error::Result<Facts> {
    let mut facts = Facts::default();

    let slice_tags: Vec<String> = versions
        .iter()
        .flat_map(|version| version.tags.iter())
        .filter(|tag| {
            matches!(classify_tag(tag), Some(TagClass::Slice { rustc, .. }) if keep_rustc.contains(rustc))
        })
        .cloned()
        .collect();
    let slices = futures_util::stream::iter(slice_tags.iter().map(|tag| {
        let (target, rustc) = index_tag_parts(tag).expect("slice tag");
        let target = target.to_owned();
        let rustc = rustc.to_owned();
        async move {
            let pulled = stow_oci::pull_index(session, base, &target, &rustc).await?;
            let decoded = pulled.and_then(|pulled| ArtifactIndex::decode(&pulled.bytes).ok());
            Ok::<_, stow_types::error::Error>((tag.clone(), decoded))
        }
    }))
    .buffered(GC_CONCURRENCY)
    .try_collect::<Vec<_>>()
    .await?;
    let mut live_folded = Vec::new();
    for (tag, index) in slices {
        if let Some(index) = index {
            facts.slice_bundles.insert(
                tag.clone(),
                index
                    .rows
                    .iter()
                    .map(|row| row.bundle_digest.clone())
                    .collect(),
            );
            let (target, rustc) = index_tag_parts(&tag).expect("slice tag");
            live_folded.push((
                folded_tag(target, rustc),
                target.to_owned(),
                rustc.to_owned(),
            ));
        }
    }

    // The folded companions of live slices only — a folded set beside a
    // slice of another format is garbage, so pulling it decides nothing.
    let folded_tags: Vec<String> = versions
        .iter()
        .flat_map(|version| version.tags.iter())
        .filter(|tag| {
            matches!(classify_tag(tag), Some(TagClass::Folded { rustc, .. }) if keep_rustc.contains(rustc))
        })
        .filter(|tag| live_folded.iter().any(|(folded, _, _)| folded == *tag))
        .cloned()
        .collect();
    let folded = futures_util::stream::iter(folded_tags.iter().map(|tag| {
        let (target, rustc) = folded_tag_parts(tag).expect("folded tag");
        let target = target.to_owned();
        let rustc = rustc.to_owned();
        async move {
            let pulled = stow_oci::pull_folded(session, base, &target, &rustc).await?;
            Ok::<_, stow_types::error::Error>((tag.clone(), pulled.map(|pulled| pulled.tags)))
        }
    }))
    .buffered(GC_CONCURRENCY)
    .try_collect::<Vec<_>>()
    .await?;
    for (tag, tags) in folded {
        if let Some(tags) = tags {
            facts.folded.insert(tag, tags);
        }
    }

    let records_tags: Vec<String> = versions
        .iter()
        .flat_map(|version| version.tags.iter())
        .filter(|tag| {
            matches!(classify_tag(tag), Some(TagClass::Records { rustc }) if keep_rustc.contains(rustc))
        })
        .cloned()
        .collect();
    let records = futures_util::stream::iter(records_tags.iter().map(|tag| async move {
        let pulled = pull_records_facts(session, base, tag).await?;
        Ok::<_, stow_types::error::Error>((tag.clone(), pulled))
    }))
    .buffered(GC_CONCURRENCY)
    .try_collect::<Vec<_>>()
    .await?;
    for (tag, facts_) in records {
        facts.records.insert(tag, facts_);
    }
    Ok(facts)
}

/// Pull one `records-*` artifact's layer and decode it into the record
/// facts the keep rules read. Transport failures are the outer `Err`
/// (fatal); a layer that does not decode under the current
/// [`ArtifactRecord`] schema is the inner `Err` — garbage with its
/// message grouped in the report.
async fn pull_records_facts(
    session: &stow_oci::RegistrySession,
    base: &stow_oci::RegistryBase,
    tag: &str,
) -> stow_types::error::Result<Result<Vec<RecordFact>, String>> {
    let reference = base.reference(tag)?;
    let (_digest, manifest) = stow_oci::pull_tagged_manifest(session, &reference).await?;
    if manifest.artifact_type.as_deref() != Some(RECORDS_ARTIFACT_TYPE) {
        return Ok(Err(format!(
            "{reference} is not a records artifact (artifactType {:?})",
            manifest.artifact_type
        )));
    }
    let Some(descriptor) = manifest.layers.first() else {
        return Ok(Err(format!("records artifact {reference} has no layers")));
    };
    let bytes = stow_oci::pull_blob_verified(session, descriptor).await?;
    let records = serde_json::from_slice::<Vec<ArtifactRecord>>(&bytes)
        .map_err(|error| format!("decode records layer of {reference}: {error}"));
    Ok(records.map(|records| {
        records
            .iter()
            .map(|record| RecordFact {
                oci_digest: record.oci_digest.clone(),
                artifact_tag: oci_reference_tag(&record.oci_reference)
                    .unwrap_or_default()
                    .to_owned(),
                bundle_digest: record.bundle_digest.clone(),
            })
            .collect()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(id: u64, tags: &[&str], too_young: bool) -> Version {
        Version {
            id,
            digest: format!("sha256:{id:064x}"),
            tags: tags.iter().map(|tag| (*tag).to_owned()).collect(),
            too_young,
        }
    }

    fn record(oci_digest: &str, tag: &str, bundle_digest: &str) -> RecordFact {
        RecordFact {
            oci_digest: oci_digest.to_owned(),
            artifact_tag: tag.to_owned(),
            bundle_digest: bundle_digest.to_owned(),
        }
    }

    const R: &str = "1.98.1";

    fn kept() -> BTreeSet<String> {
        BTreeSet::from([R.to_owned()])
    }

    #[test]
    fn tag_shapes_classify() {
        assert!(matches!(
            classify_tag("index.x86_64-unknown-linux-gnu.1.98.1"),
            Some(TagClass::Slice { .. })
        ));
        assert!(matches!(
            classify_tag("folded.x86_64-unknown-linux-gnu.1.98.1"),
            Some(TagClass::Folded { .. })
        ));
        assert!(matches!(
            classify_tag(
                "records-1.98.1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-123-1"
            ),
            Some(TagClass::Records { .. })
        ));
        assert!(matches!(
            classify_tag(
                "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sig"
            ),
            Some(TagClass::Signature { .. })
        ));
        assert!(matches!(
            classify_tag("sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Some(TagClass::Signature { .. })
        ));
        assert!(matches!(
            classify_tag("serde.1.0.219-x86_64-linux-1.98.1-0123abcd-fedcba9876543210.bundle"),
            Some(TagClass::Bundle { bundle: true, .. })
        ));
        assert!(matches!(
            classify_tag("serde.1.0.219-x86_64-linux-1.98.1-0123abcd-fedcba9876543210"),
            Some(TagClass::Bundle { bundle: false, .. })
        ));
        assert!(classify_tag("latest").is_none());
        assert!(classify_tag("records-not-a-records-tag").is_none());
    }

    fn evaluate_ids(versions: &[Version], facts: &Facts) -> Result<Evaluation, Vec<String>> {
        evaluate(versions, &kept(), facts)
    }

    /// The ids `evaluation` marks for deletion.
    fn deleted(evaluation: &Evaluation) -> BTreeSet<u64> {
        evaluation.delete.iter().map(|(id, _)| *id).collect()
    }

    /// `sha256:<id as 64 hex>` — the digest `version()` assigns id `id`.
    fn digest(id: u64) -> String {
        format!("sha256:{id:064x}")
    }

    /// A live slice keeps its folded companion, the unexported records
    /// artifact, the records whose bundles the slice serves, those
    /// records' artifact and bundle manifests, and their signatures.
    /// A folded-superseded records artifact and everything only it
    /// reached are garbage.
    #[test]
    fn the_keep_rules_reach_through_slices_records_and_bundles() {
        let slice = "index.x86_64-unknown-linux-gnu.1.98.1";
        let folded = "folded.x86_64-unknown-linux-gnu.1.98.1";
        let live_records =
            "records-1.98.1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1-1";
        let dead_records =
            "records-1.98.1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-1-1";
        let live_artifact = "serde.1.0.219-x86_64-linux-1.98.1-0123abcd-fedcba9876543210";
        let dead_artifact = "serde.1.0.100-x86_64-linux-1.98.1-0123abcd-eeeeeeeeeeeeeeee";
        let versions = vec![
            version(1, &[slice], false),
            version(2, &[folded], false),
            version(3, &[live_records], false),
            version(4, &[dead_records], false),
            // The live record's artifact manifest, digest-addressed by
            // the record's `oci_digest`.
            version(5, &[live_artifact], false),
            version(6, &[&format!("{live_artifact}.bundle")], false),
            version(7, &[&format!("{dead_artifact}.bundle")], false),
            // A signature of the slice manifest follows its subject; a
            // signature of the dead artifact manifest does not.
            version(8, &[&format!("{}.sig", digest(1).replace(':', "-"))], false),
            version(9, &[&format!("{}.sig", digest(5).replace(':', "-"))], false),
            version(10, &[], false), // superseded manifest, untagged
        ];

        let mut facts = Facts::default();
        facts.slice_bundles.insert(
            slice.to_owned(),
            BTreeSet::from(["sha256:bundle-live".to_owned()]),
        );
        facts
            .folded
            .insert(folded.to_owned(), vec![dead_records.to_owned()]);
        // The live records artifact is folded AND serves a slice row.
        facts.records.insert(
            live_records.to_owned(),
            Ok(vec![record(
                &digest(5),
                live_artifact,
                "sha256:bundle-live",
            )]),
        );
        // The dead one is folded and serves nothing — superseded.
        facts.records.insert(
            dead_records.to_owned(),
            Ok(vec![record(
                &digest(7),
                dead_artifact,
                "sha256:bundle-dead",
            )]),
        );

        let evaluation = evaluate(&versions, &kept(), &facts).expect("classified");
        let deleted: BTreeSet<u64> = evaluation.delete.iter().map(|(id, _)| *id).collect();
        // kept: slice, folded, live records, live artifact manifest,
        // its bundle manifest, and the signatures of kept manifests.
        for id in [1, 2, 3, 5, 6, 8, 9] {
            assert!(
                evaluation.keep.contains(&digest(id)),
                "id {id} should be kept"
            );
            assert!(!deleted.contains(&id));
        }
        // garbage: superseded records, its bundle, and the untagged
        // manifest.
        for id in [4, 7, 10] {
            assert!(deleted.contains(&id), "id {id} should be deleted");
        }
    }

    /// An unexported records artifact — named by no kept folded set —
    /// stays even when nothing in the slice references it.
    #[test]
    fn an_unexported_records_artifact_is_kept() {
        let tag =
            "records-1.98.1-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc-1-1";
        let artifact = "serde.1.0.1-x86_64-linux-1.98.1-0123abcd-fedcba9876543210";
        let digest = format!("sha256:{}", "d".repeat(64));
        let versions = vec![
            version(1, &[tag], false),
            Version {
                id: 2,
                digest: digest.clone(),
                tags: vec![artifact.to_owned()],
                too_young: false,
            },
            version(3, &[&format!("{artifact}.bundle")], false),
        ];
        let mut facts = Facts::default();
        facts.records.insert(
            tag.to_owned(),
            Ok(vec![record(&digest, artifact, "sha256:b")]),
        );
        let evaluation = evaluate_ids(&versions, &facts).expect("classified");
        for v in &versions {
            assert!(evaluation.keep.contains(&v.digest), "id {}", v.id);
        }
        assert!(evaluation.delete.is_empty());
    }

    /// A records artifact that does not decode is garbage, its decode
    /// error grouped in the report — and a bundle only it referenced is
    /// garbage with it.
    #[test]
    fn an_undecodable_records_artifact_is_garbage_with_its_bundles() {
        let tag =
            "records-1.98.1-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd-1-1";
        let artifact = "serde.1.0.1-x86_64-linux-1.98.1-0123abcd-fedcba9876543210";
        let versions = vec![
            version(1, &[tag], false),
            version(2, &[&format!("{artifact}.bundle")], false),
        ];
        let mut facts = Facts::default();
        facts.records.insert(
            tag.to_owned(),
            Err("decode records layer: missing field `unit_shape`".to_owned()),
        );
        let evaluation = evaluate(&versions, &kept(), &facts).expect("classified");
        assert_eq!(evaluation.delete.len(), 2);
        assert_eq!(
            evaluation
                .records_errors
                .get("decode records layer: missing field `unit_shape`"),
            Some(&1)
        );
    }

    /// A slice or folded set of a rustc outside the keep set is garbage;
    /// so is a kept rustc's slice that does not decode — and its folded
    /// companion with it.
    #[test]
    fn other_rustcs_and_undecodable_slices_are_garbage() {
        let kept_slice = "index.aarch64-apple-darwin.1.98.1";
        let versions = vec![
            version(1, &[kept_slice], false),
            version(2, &["index.x86_64-unknown-linux-gnu.1.98.1"], false),
            version(3, &["index.aarch64-apple-darwin.1.97.0"], false),
            version(4, &["folded.x86_64-unknown-linux-gnu.1.98.1"], false),
            version(5, &["folded.aarch64-apple-darwin.1.97.0"], false),
            version(6, &["folded.aarch64-apple-darwin.1.98.1"], false),
        ];
        let mut facts = Facts::default();
        // Only the aarch64 slice of the kept rustc decoded; the x86_64
        // one pulled but did not (foreign format) — it is absent here.
        facts
            .slice_bundles
            .insert(kept_slice.to_owned(), BTreeSet::new());
        let evaluation = evaluate_ids(&versions, &facts).expect("classified");
        let deleted = deleted(&evaluation);
        assert!(evaluation.keep.contains(&digest(1)), "the live slice keeps");
        assert!(
            evaluation.keep.contains(&digest(6)),
            "a live slice's folded companion keeps"
        );
        for id in [2, 3, 4, 5] {
            assert!(deleted.contains(&id), "id {id} should be deleted");
        }
    }

    /// The age guard shelters every garbage class — a fresh manifest is
    /// a publish in flight, not waste.
    #[test]
    fn young_garbage_is_never_deleted() {
        let versions = vec![
            version(1, &[], true),                                    // untagged but fresh
            version(2, &["index.aarch64-apple-darwin.1.97.0"], true), // old rustc, fresh
            version(3, &[], false),
        ];
        let evaluation = evaluate(&versions, &kept(), &Facts::default()).expect("classified");
        assert_eq!(
            evaluation.delete,
            [(
                3,
                "sha256:0000000000000000000000000000000000000000000000000000000000000003 ()"
                    .to_owned()
            )]
        );
    }

    /// An unrecognized tag fails the whole run before anything is
    /// deleted.
    #[test]
    fn an_unknown_tag_fails_the_run() {
        let versions = vec![version(1, &["weird-tag"], false)];
        let error = evaluate(&versions, &kept(), &Facts::default()).expect_err("unknown tag");
        assert_eq!(error, vec!["weird-tag".to_owned()]);
    }
}
//! `stow-admin index migrate-records`: one-time migration of a rustc's
//! `records-*` and `built-*` manifests from standalone `.sig` images to
//! inline `dev.stow.records.signatures` annotations (stow#1627).
//!
//! No new signature is created: each legacy tag's `.sig` materials are
//! verified against the pinned `build-crate.yml` release-tag identity and
//! embedded into its manifest annotation; tags already carrying the
//! inline annotation are verified and skipped. Deleted with
//! `stow_oci::migrate_records` once run across active rustc repositories.

use std::collections::BTreeMap;

use clap::Args;
use futures_util::StreamExt as _;
use stow_oci::migrate_records::{RecordsTagMigration, migrate_marker_tag, migrate_records_tag};
use stow_oci::verify::{ReleaseIdentity, Trust};
use stow_types::identity::WireRustcVersion;
use stow_types::records::{BuildRun, is_records_tag, parse_records_tag};
use stow_types::registry::{CacheRepository, cache_repository};
use stow_types::stow_error;
use stow_types::trusted_builder::TrustedWorkflow;

use crate::index_cmd::registry_base;
use crate::render;

/// Default tasks migrated concurrently; registry writes are bounded by
/// [`stow_oci::WriteBudget`].
const DEFAULT_MIGRATE_CONCURRENCY: usize = 16;

#[derive(Args)]
pub struct IndexMigrateRecordsArgs {
    /// The rustc whose `records-*` and `built-*` tags are migrated.
    #[arg(long)]
    rustc_version: String,
    /// Tasks migrated concurrently.
    #[arg(long, default_value_t = DEFAULT_MIGRATE_CONCURRENCY)]
    concurrency: usize,
}

#[derive(Debug, Default, serde::Serialize)]
struct Summary {
    records_migrated: usize,
    records_already: usize,
    markers_migrated: usize,
    markers_already: usize,
    failed: usize,
}

type TaskBuilds = BTreeMap<String, Vec<(Option<BuildRun>, String)>>;

struct MigrateContext<'a> {
    session: &'a stow_oci::RegistrySession,
    repository: &'a CacheRepository,
    trust: &'a Trust,
    policy: &'a ReleaseIdentity,
    concurrency: usize,
}

/// Migrate every `records-<rustc>-*` and `built-<rustc>-*` tag of
/// `args.rustc_version`.
pub async fn run(args: IndexMigrateRecordsArgs) -> stow_types::error::Result<()> {
    let rustc_version = WireRustcVersion::parse(&args.rustc_version)
        .map_err(|error| stow_error!("--rustc-version: {error}"))?;
    let concurrency = args.concurrency.max(1);
    let base = registry_base()?;
    let credentials = stow_oci::RegistryCredentials::from_env()?;
    let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    let budget = stow_oci::WriteBudget::from_env()?;
    let repository = cache_repository(&rustc_version);
    let session = base.push_session(&repository, &credentials, &http, &budget);
    let trust = stow_oci::verify::records_trust().await?;
    let policy = ReleaseIdentity::new(TrustedWorkflow::BUILD);

    let tags = session
        .list_tags()
        .await
        .map_err(|error| stow_error!("list tags: {error}"))?;

    let (by_task, markers) = partition_tags(tags, &rustc_version);
    let ctx = MigrateContext {
        session: &session,
        repository: &repository,
        trust: &trust,
        policy: &policy,
        concurrency,
    };

    let mut summary = Summary::default();
    let newest_by_hash = migrate_task_builds(&ctx, by_task, &mut summary).await;
    migrate_markers(&ctx, &rustc_version, markers, &newest_by_hash, &mut summary).await;

    render::emit_line(&serde_json::to_string(&summary)?);
    if summary.failed > 0 {
        return Err(stow_error!(
            "{} tasks or markers of {rustc_version} failed to migrate ({summary:?})",
            summary.failed
        ));
    }
    Ok(())
}

fn partition_tags(
    tags: Vec<String>,
    rustc_version: &WireRustcVersion,
) -> (TaskBuilds, Vec<(String, String)>) {
    let built_prefix = format!("built-{rustc_version}-");
    let mut by_task: TaskBuilds = BTreeMap::new();
    let mut markers: Vec<(String, String)> = Vec::new();
    for tag in tags {
        if is_records_tag(&tag) {
            if let Some(parsed) = parse_records_tag(&tag)
                && parsed.rustc_version == rustc_version.as_str()
            {
                by_task
                    .entry(parsed.task_hash.to_owned())
                    .or_default()
                    .push((parsed.build, tag));
            }
        } else if let Some(hash) = tag.strip_prefix(&built_prefix)
            && hash.len() == 64
            && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            markers.push((hash.to_owned(), tag));
        }
    }
    (by_task, markers)
}

async fn migrate_task_builds(
    ctx: &MigrateContext<'_>,
    by_task: TaskBuilds,
    summary: &mut Summary,
) -> BTreeMap<String, Vec<u8>> {
    let mut newest_by_hash: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut task_outcomes =
        futures_util::stream::iter(by_task.into_iter().map(|(task_hash, mut builds)| {
            let (session, repository, trust, policy) =
                (ctx.session, ctx.repository, ctx.trust, ctx.policy);
            async move {
                builds.sort_unstable_by(|left, right| right.cmp(left));
                let mut migrated = 0usize;
                let mut already = 0usize;
                let mut newest_outer = None;
                for (index, (_, tag)) in builds.into_iter().enumerate() {
                    let outcome = migrate_records_tag(
                        session,
                        trust,
                        &repository.reference(&tag),
                        &tag,
                        policy,
                    )
                    .await
                    .map_err(|error| error.wrap_err(format!("migrate {tag}")))?;
                    let outer = match outcome {
                        RecordsTagMigration::Migrated { outer_bytes } => {
                            migrated += 1;
                            outer_bytes
                        }
                        RecordsTagMigration::Already { outer_bytes } => {
                            already += 1;
                            outer_bytes
                        }
                    };
                    if index == 0 {
                        newest_outer = Some(outer);
                    }
                }
                Ok::<_, stow_types::error::Error>((task_hash, migrated, already, newest_outer))
            }
        }))
        .buffer_unordered(ctx.concurrency);

    while let Some(outcome) = task_outcomes.next().await {
        match outcome {
            Ok((task_hash, migrated, already, newest_outer)) => {
                summary.records_migrated += migrated;
                summary.records_already += already;
                if let Some(outer) = newest_outer {
                    newest_by_hash.insert(task_hash, outer);
                }
            }
            Err(error) => {
                summary.failed += 1;
                tracing::error!(%error, "migrating task records failed");
            }
        }
    }
    newest_by_hash
}

async fn migrate_markers(
    ctx: &MigrateContext<'_>,
    rustc_version: &WireRustcVersion,
    markers: Vec<(String, String)>,
    newest_by_hash: &BTreeMap<String, Vec<u8>>,
    summary: &mut Summary,
) {
    let canonical_repo = format!("ghcr.io/{}", ctx.repository.path());
    let mut marker_outcomes =
        futures_util::stream::iter(markers.into_iter().map(|(task_hash, tag)| {
            let newest = newest_by_hash.get(&task_hash).map(Vec::as_slice);
            let (session, canonical_repo, trust, policy, rustc) = (
                ctx.session,
                canonical_repo.as_str(),
                ctx.trust,
                ctx.policy,
                rustc_version.as_str(),
            );
            async move {
                migrate_marker_tag(session, trust, canonical_repo, rustc, &tag, newest, policy)
                    .await
                    .map_err(|error| error.wrap_err(format!("migrate marker {tag}")))
            }
        }))
        .buffer_unordered(ctx.concurrency);

    while let Some(outcome) = marker_outcomes.next().await {
        match outcome {
            Ok(RecordsTagMigration::Migrated { .. }) => summary.markers_migrated += 1,
            Ok(RecordsTagMigration::Already { .. }) => summary.markers_already += 1,
            Err(error) => {
                summary.failed += 1;
                tracing::error!(%error, "migrating built- marker failed");
            }
        }
    }
}

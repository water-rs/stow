//! `stow-build repack`: rewrite published nodes into the single-pack layout.
//!
//! Runs in `build-crate.yml` under the same identity builds sign with, in
//! a job that compiles nothing: every node it touches is read back from
//! GHCR, verified (the records artifact and the node's own signature under
//! the pinned builder identity, then every file's SHA-256), packed, and
//! published through the build's publish path. Each task whose rows
//! changed gets a new signed records artifact under this run's tag, which
//! the next index export folds over the old rows.
//!
//! A task whose rows are all packed is read and left alone, so a sweep is
//! safe to rerun and a second sweep after in-flight builds drain only
//! touches what they published in the old layout.

use std::collections::{BTreeMap, BTreeSet};

use futures_util::StreamExt as _;
use stow_oci::{RegistryCredentials, RegistryHttp, RegistrySession};
use stow_types::api::ArtifactRecord;
use stow_types::identity::WireRustcVersion;
use stow_types::records::{BuildRun, parse_records_tag};
use stow_types::registry::cache_repository;
use stow_types::trusted_builder::CERTIFICATE_IDENTITY;

/// What one sweep did.
#[derive(Debug, Default, serde::Serialize)]
pub struct Sweep {
    /// Tasks whose records were examined.
    pub tasks: usize,
    /// Tasks that had a node to repack and now have a new records artifact.
    pub repacked_tasks: usize,
    /// Nodes repacked across those tasks.
    pub repacked_nodes: usize,
    /// Tasks that failed; each is named in the log.
    pub failed_tasks: usize,
}

/// Everything one task's repack reads from.
struct Sweeper<'a> {
    session: &'a RegistrySession,
    credentials: &'a RegistryCredentials,
    http: &'a RegistryHttp,
    trust: &'a stow_oci::verify::Trust,
    rustc_version: &'a WireRustcVersion,
    build: BuildRun,
}

/// Repack every task of `rustc_version`, at most `concurrency` tasks at
/// once.
///
/// `concurrency` bounds tasks in flight, not cores: each node's
/// compression already uses every core of the machine.
///
/// # Errors
///
/// Returns an error when the registry cannot be listed or any task failed;
/// the tasks that succeeded stay published either way.
pub async fn run(
    rustc_version: &WireRustcVersion,
    concurrency: usize,
    build: BuildRun,
) -> stow_types::error::Result<Sweep> {
    let credentials = RegistryCredentials::from_env()?;
    let http = RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    let session = credentials.session(&cache_repository(rustc_version), &http)?;
    let trust = stow_oci::verify::records_trust().await?;
    let tags = stow_oci::list_records_tags(&session)
        .await
        .map_err(|error| stow_types::stow_error!("list records tags: {error}"))?;
    let tasks = tasks_newest_first(&tags, rustc_version);
    tracing::info!(tasks = tasks.len(), %rustc_version, concurrency, "repack sweep starts");

    let sweeper = Sweeper {
        session: &session,
        credentials: &credentials,
        http: &http,
        trust: &trust,
        rustc_version,
        build,
    };
    let mut sweep = Sweep {
        tasks: tasks.len(),
        ..Sweep::default()
    };
    let mut outcomes = futures_util::stream::iter(tasks.iter().map(|tags| sweeper.task(tags)))
        .buffer_unordered(concurrency);
    while let Some(outcome) = outcomes.next().await {
        match outcome {
            Ok(0) => {}
            Ok(nodes) => {
                sweep.repacked_tasks += 1;
                sweep.repacked_nodes += nodes;
            }
            Err(error) => {
                sweep.failed_tasks += 1;
                tracing::error!(%error, "repack task failed");
            }
        }
    }
    if sweep.failed_tasks > 0 {
        return Err(stow_types::stow_error!(
            "{} of {} tasks failed to repack; the rest are published ({sweep:?})",
            sweep.failed_tasks,
            sweep.tasks
        ));
    }
    Ok(sweep)
}

/// The `records-*` tags of `rustc_version` grouped by task, each group
/// newest build first — the reverse of the order the index fold applies
/// them in.
fn tasks_newest_first<'a>(
    tags: &'a [String],
    rustc_version: &WireRustcVersion,
) -> Vec<Vec<&'a str>> {
    let mut by_task: BTreeMap<&str, Vec<(Option<BuildRun>, &str)>> = BTreeMap::new();
    for tag in tags {
        let Some(parsed) = parse_records_tag(tag) else {
            continue;
        };
        if parsed.rustc_version == rustc_version.as_str() {
            by_task
                .entry(parsed.task_hash)
                .or_default()
                .push((parsed.build, tag));
        }
    }
    by_task
        .into_values()
        .map(|mut builds| {
            builds.sort_unstable_by(|left, right| right.cmp(left));
            builds.into_iter().map(|(_, tag)| tag).collect()
        })
        .collect()
}

impl Sweeper<'_> {
    /// Repack one task whose records tags are `tags`, newest first.
    /// Returns how many nodes were repacked; zero publishes nothing.
    async fn task(&self, tags: &[&str]) -> stow_types::error::Result<usize> {
        let mut pulled = Vec::with_capacity(tags.len());
        for tag in tags {
            let records = stow_oci::pull_records_by_tag(self.session, tag).await?;
            let reference = self.session.reference(tag)?;
            stow_oci::verify_artifact_signature(
                self.session,
                self.trust,
                &reference,
                &cache_repository(self.rustc_version).reference(tag),
                &records.manifest_digest,
                CERTIFICATE_IDENTITY,
            )
            .await?;
            pulled.push(records);
        }
        let Some(task_id) = pulled.first().map(|records| records.task_id.clone()) else {
            return Ok(0);
        };
        // The rows the index serves: a newer tag's row replaces an older
        // tag's row for the same node.
        let mut seen = BTreeSet::new();
        let live = pulled
            .iter()
            .flat_map(|records| &records.records)
            .filter(|record| seen.insert(record.oci_reference.as_str()))
            .collect::<Vec<_>>();

        let sign = |reference: String, digest: String| {
            let credentials = self.credentials.clone();
            async move { stow_oci::sign_artifact(&reference, &digest, &credentials).await }
        };
        let mut rows: Vec<ArtifactRecord> = Vec::with_capacity(live.len());
        let mut repacked = 0;
        for record in live {
            let row = stow_oci::repack_record(
                self.session,
                self.trust,
                CERTIFICATE_IDENTITY,
                record,
                &sign,
            )
            .await?;
            if row.is_some() {
                repacked += 1;
            }
            rows.push(row.unwrap_or_else(|| record.clone()));
        }
        if repacked == 0 {
            return Ok(0);
        }
        let published = stow_oci::push_records(
            self.credentials,
            self.http,
            self.rustc_version,
            &task_id,
            self.build,
            &rows,
        )
        .await?;
        tracing::info!(task_id, repacked, records_tag = %published.tag, "repacked task");
        Ok(repacked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tasks_group_by_hash_newest_first_and_ignore_other_rustcs() {
        let hash = blake3::hash(b"task-a").to_hex();
        let other = blake3::hash(b"task-b").to_hex();
        let tags = vec![
            format!("records-1.99.0-{hash}"),
            format!("records-1.99.0-{hash}-9-1"),
            format!("records-1.99.0-{hash}-10-1"),
            format!("records-1.98.0-{other}-3-1"),
            format!("records-1.99.0-{other}-4-1"),
            "built-1.99.0-abc".to_owned(),
        ];
        let rustc = WireRustcVersion::parse("1.99.0").unwrap();
        let mut tasks = tasks_newest_first(&tags, &rustc);
        tasks.sort();
        let mut expected = vec![
            vec![tags[2].as_str(), tags[1].as_str(), tags[0].as_str()],
            vec![tags[4].as_str()],
        ];
        expected.sort();
        assert_eq!(tasks, expected);
    }
}

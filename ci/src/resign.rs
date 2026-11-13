//! `stow-build resign`: the one-time re-sign of a rustc's repository from
//! the branch identity to the release-tag identity.
//!
//! Until the release-tag switch, `build-crate.yml` signed at
//! `refs/heads/main`; readers now accept release tags only, so everything
//! published before is signed again under the tag this run executes at.
//! The tool is deleted once the operator's run has finished (stow#1517), and
//! the old identity lives here alone.
//!
//! Every tag of the repository is classified first and an unknown tag fails
//! the run before anything is written. Then, per task:
//!
//! * each of its records tags is re-signed in place — the manifest is
//!   unchanged and its `.sig` image gains a layer;
//! * each live row's node (the newest row per node, as the index fold
//!   resolves them) is republished under the new identity: the CLI verifies
//!   a node from the signature material in its bundle tar, so the bundle,
//!   and with it the row's `bundle_digest`, is new;
//! * when any row changed, one new records artifact under this run's tag
//!   carries the task's rows, which the next index export folds over the
//!   old ones.
//!
//! Finally every `built-` marker is checked to resolve to a re-signed
//! records manifest. A rerun skips what already verifies under the new
//! identity, so it writes nothing once a run has finished.

use futures_util::StreamExt as _;
use stow_oci::resign::{
    ExactIdentity, Identities, TagClass, TaskResigned, classify_tag, resign_task,
};
use stow_oci::verify::ReleaseIdentity;
use stow_oci::{Publisher, RegistryHttp, RegistrySession};
use stow_types::identity::WireRustcVersion;
use stow_types::records::BuildRun;
use stow_types::registry::cache_repository;
use stow_types::trusted_builder::{CERTIFICATE_ISSUER, TrustedWorkflow};

/// The certificate subject `build-crate.yml` signed under before the
/// release-tag switch.
const OLD_BUILD_IDENTITY: &str =
    "https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/heads/main";

/// What one run did.
#[derive(Debug, Default, serde::Serialize)]
pub struct Sweep {
    /// Tasks examined.
    pub tasks: usize,
    /// Records tags that gained a signature.
    pub records_signed: usize,
    /// Records tags that already carried one under the new identity.
    pub records_already: usize,
    /// Nodes republished under the new identity.
    pub nodes_republished: usize,
    /// Nodes whose bundle already verified under the new identity.
    pub nodes_already: usize,
    /// Tasks that got a new records artifact.
    pub tasks_published: usize,
    /// `built-` markers resolving to a re-signed records manifest.
    pub markers: usize,
    /// Tasks and markers that failed; each is named in the log.
    pub failed: usize,
}

/// Everything one task's re-sign reads from and writes with.
struct Resigner<'a> {
    session: &'a RegistrySession,
    publisher: &'a Publisher,
    trust: &'a stow_oci::verify::Trust,
    rustc_version: &'a WireRustcVersion,
    old: ExactIdentity,
    new: ReleaseIdentity,
    build: BuildRun,
}

/// The tags a run acts on.
#[derive(Debug, PartialEq, Eq)]
struct Plan<'a> {
    /// Records tags, whose tasks are re-signed.
    records: Vec<String>,
    /// `built-` markers, checked after the tasks.
    markers: Vec<&'a str>,
}

/// Classify every tag of the repository. Nodes are reached through their
/// records' rows, bundles are rewritten with them, signature images grow
/// with their manifests, and `stow-admin index resign` owns the slices, so
/// none of those is acted on here — but every tag must be of a known kind.
///
/// # Errors
///
/// A tag of no known kind; nothing is written before this check.
fn plan<'a>(
    tags: &'a [String],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Plan<'a>> {
    let mut unknown = Vec::new();
    let mut plan = Plan {
        records: Vec::new(),
        markers: Vec::new(),
    };
    for tag in tags {
        match classify_tag(tag, rustc_version) {
            Ok(TagClass::Records) => plan.records.push(tag.clone()),
            Ok(TagClass::Built) => plan.markers.push(tag),
            Ok(_) => {}
            Err(error) => unknown.push(error.to_string()),
        }
    }
    if unknown.is_empty() {
        Ok(plan)
    } else {
        Err(stow_types::stow_error!(
            "{} tags of {rustc_version} are of no known kind; nothing was re-signed:\n{}",
            unknown.len(),
            unknown.join("\n")
        ))
    }
}

/// Re-sign every task of `rustc_version`'s repository, at most
/// `concurrency` tasks at once.
///
/// # Errors
///
/// The registry cannot be listed, a tag is unknown, or any task or marker
/// failed; what succeeded stays published either way.
pub async fn run(
    rustc_version: &WireRustcVersion,
    concurrency: usize,
    build: BuildRun,
) -> stow_types::error::Result<Sweep> {
    let http = RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    let trust = stow_oci::verify::records_trust().await?;
    let publisher = Publisher::from_env(http, &trust, TrustedWorkflow::BUILD)?;
    let session = publisher.session(&cache_repository(rustc_version))?;
    let tags = session
        .list_tags()
        .await
        .map_err(|error| stow_types::stow_error!("list tags: {error}"))?;

    let Plan { records, markers } = plan(&tags, rustc_version)?;
    let tasks = crate::repack::tasks_newest_first(&records, rustc_version);
    tracing::info!(
        tasks = tasks.len(),
        markers = markers.len(),
        %rustc_version,
        concurrency,
        "re-sign starts"
    );

    let resigner = Resigner {
        session: &session,
        publisher: &publisher,
        trust: &trust,
        rustc_version,
        old: ExactIdentity::new(OLD_BUILD_IDENTITY, CERTIFICATE_ISSUER),
        new: ReleaseIdentity::new(TrustedWorkflow::BUILD),
        build,
    };
    let mut sweep = Sweep {
        tasks: tasks.len(),
        ..Sweep::default()
    };
    let mut outcomes = futures_util::stream::iter(tasks.iter().map(|tags| resigner.task(tags)))
        .buffer_unordered(concurrency);
    while let Some(outcome) = outcomes.next().await {
        match outcome {
            Ok(outcome) => {
                sweep.records_signed += outcome.records_signed;
                sweep.records_already += outcome.records_already;
                sweep.nodes_republished += outcome.nodes_republished;
                sweep.nodes_already += outcome.nodes_already;
                sweep.tasks_published += usize::from(outcome.published.is_some());
            }
            Err(error) => {
                sweep.failed += 1;
                tracing::error!(%error, "re-signing a task failed");
            }
        }
    }
    drop(outcomes);

    // The markers resolve to records manifests the tasks above re-signed,
    // so they are checked once every task has finished.
    let mut checks = futures_util::stream::iter(markers.iter().map(|tag| resigner.marker(tag)))
        .buffer_unordered(concurrency);
    while let Some(outcome) = checks.next().await {
        match outcome {
            Ok(()) => sweep.markers += 1,
            Err(error) => {
                sweep.failed += 1;
                tracing::error!(%error, "a built marker does not resolve to a re-signed records manifest");
            }
        }
    }
    if sweep.failed > 0 {
        return Err(stow_types::stow_error!(
            "{} tasks or markers of {rustc_version} failed to re-sign; the rest are published ({sweep:?})",
            sweep.failed
        ));
    }
    Ok(sweep)
}

impl Resigner<'_> {
    /// Re-sign one task whose records tags are `tags`, newest first.
    async fn task(&self, tags: &[&str]) -> stow_types::error::Result<TaskResigned> {
        let sign = |reference: String, digest: String| async move {
            self.publisher
                .signer()
                .sign(self.session, &reference, &digest)
                .await
        };
        let outcome = resign_task(
            self.session,
            self.trust,
            self.rustc_version,
            tags,
            Identities {
                old: &self.old,
                new: &self.new,
            },
            self.build,
            &sign,
        )
        .await?;
        if let Some(published) = &outcome.published {
            tracing::info!(
                republished = outcome.nodes_republished,
                records_tag = %published.tag,
                "re-signed task"
            );
        }
        Ok(outcome)
    }

    /// Check that the `built-` marker `tag` resolves to a records manifest
    /// carrying a signature under the new identity.
    async fn marker(&self, tag: &str) -> stow_types::error::Result<()> {
        let reference = self.session.reference(tag)?;
        let digest = self
            .session
            .fetch_manifest_digest(&reference)
            .await
            .map_err(|error| stow_types::stow_error!("head marker {reference}: {error}"))?;
        if crate::marker_signature_verified(
            self.session,
            self.trust,
            &reference,
            &digest,
            &self.new,
        )
        .await?
        {
            Ok(())
        } else {
            Err(stow_types::stow_error!(
                "marker {reference} names {digest}, which no records tag of this repository \
                 carries a new-identity signature for"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The old subject is the build workflow at the branch, the exact
    /// string the pre-switch signer's certificates carried.
    #[test]
    fn the_old_identity_is_the_build_workflow_on_main() {
        assert_eq!(
            OLD_BUILD_IDENTITY,
            format!("{}refs/heads/main", TrustedWorkflow::BUILD.san_stem())
        );
    }

    #[test]
    fn an_unknown_tag_fails_the_plan_before_anything_is_written() {
        let rustc = WireRustcVersion::parse("1.99.0").unwrap();
        let hash = "0123456789abcdef".repeat(4);
        let known = vec![
            format!("records-1.99.0-{hash}-9-1"),
            format!("built-1.99.0-{hash}"),
            "serde.1.0.0-x86_64-linux-1.99.0-0a1b2c3d-deadbeef".to_owned(),
        ];
        let planned = plan(&known, &rustc).expect("known tags plan");
        assert_eq!(planned.records, [known[0].clone()]);
        assert_eq!(planned.markers, [known[1].as_str()]);

        let mut tags = known;
        tags.push("scratch".to_owned());
        let error = plan(&tags, &rustc).expect_err("an unknown tag fails");
        assert!(error.to_string().contains("\"scratch\""), "{error}");
    }
}

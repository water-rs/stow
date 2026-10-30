//! `stow-admin preheat manual` — the operator's preheat submission
//! lane (stow#880). It resolves the graph on the operator's machine
//! and submits one dependency tree per source to the scheduler's
//! operations entry point at the caller's `--priority`. The scheduler
//! owns dispatch from there — layering, polling, reruns and index
//! publishes are its machinery, so this lane ends where the submit
//! returns. No second dispatcher remains.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use clap::Args;
use futures_util::{StreamExt as _, TryStreamExt as _};
use keyring_core::api::CredentialStoreApi;
use oci_client::manifest::OciImageManifest;
use stow_types::api::{EnqueueRequest, SubmissionSource, SubmissionTree};
use stow_types::identity::{CrateName, CrateVersion, TargetTriple, WireRustcVersion};
use stow_types::index::{ArtifactIndexRow, STOW_INDEX_MEDIA_TYPE, index_tag};
use stow_types::public_cache::{UnitInvocation, required_unit_shapes};
use stow_types::registry::{CacheRepository, cache_repository};
use stow_types::stow_error;
use stow_types::task_graph::TaskNodeIdentity;

use crate::Edge;
use crate::render::{self, Output};

/// Concurrent slice pulls while reading coverage — `CI_TARGET_TRIPLES`
/// stays under this, but the bound stands regardless.
const SLICE_PULL_CONCURRENCY: usize = 8;

/// `stow-admin preheat manual` arguments.
#[derive(Debug, Args)]
pub struct ManualArgs {
    /// Crate list file — one `name` or `name@version` line per entry; a
    /// bare name resolves to the newest non-yanked release. `#`
    /// comments and blank lines are ignored.
    #[arg(long, conflicts_with = "projects")]
    pub crates: Option<PathBuf>,
    /// A projects list in the `preheat/projects.toml` shape —
    /// `[[project]] repo = "https://github.com/<owner>/<name>"`.
    #[arg(long)]
    pub projects: Option<PathBuf>,
    /// Pinned source trees (stow#558) for `--projects` entries whose
    /// git checkout does not carry every Rust input — see
    /// `preheat/source-trees.toml`. Only meaningful with `--projects`.
    #[arg(long, requires = "projects", conflicts_with_all = ["crates", "dirs"])]
    pub source_trees: Option<PathBuf>,
    /// Comma-separated local project directories — resolved like a
    /// `--projects` entry (cargo's own resolver, the tree's `Cargo.lock`
    /// dropped). Each directory is mutated: pass a disposable copy.
    /// The mock lane seeds the wave with a consumer project's own graph.
    #[arg(long, conflicts_with_all = ["crates", "projects"], value_delimiter = ',')]
    pub dirs: Option<Vec<PathBuf>>,
    /// The stable rustc every task pins — `1.85.0`-style.
    #[arg(long)]
    rustc_version: String,
    /// Comma-separated CI target triples to resolve for — defaults to
    /// every `CI_TARGET_TRIPLES` entry. The mock lane narrows it to the
    /// host triple.
    #[arg(long, value_delimiter = ',')]
    targets: Option<Vec<String>>,
    /// The priority the tasks enter the rank with, as a multiple of the
    /// CLI miss's (stow#879): `--priority 30` is the website class —
    /// the same operand `stow-admin submit` takes.
    #[arg(long, default_value_t = 30)]
    priority: i64,
    /// Submit the batch. Without it the command prints the plan and exits
    /// 0 without enqueuing.
    #[arg(long)]
    pub yes: bool,
}

/// Entry point — `stow-admin preheat manual`.
pub async fn run(
    args: ManualArgs,
    output: Output,
    store: &(impl CredentialStoreApi + Sync),
) -> stow_types::error::Result<()> {
    if args.crates.is_none() && args.projects.is_none() && args.dirs.is_none() {
        return Err(stow_error!(
            "one of --crates, --projects or --dirs is required"
        ));
    }
    // The edge is connected up front under `--yes` — a missing
    // `STOW_EDGE_URL` fails before the resolve spends its minutes.
    let edge = Edge::connect_to_submit(store, args.yes)?;
    let rustc_version = WireRustcVersion::parse(args.rustc_version.clone())
        .map_err(|error| stow_error!("--rustc-version: {error}"))?;
    let targets = crate::preheat::ci_targets(args.targets.clone())?
        .iter()
        .map(|target| {
            TargetTriple::parse(target.clone())
                .map_err(|error| stow_error!("--targets `{target}`: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let resolved = resolve_sources(&args, &targets, &rustc_version).await?;
    let source = SubmissionSource::Operations {
        priority: args.priority.saturating_mul(100),
    };
    let mut trees = resolved
        .sources
        .iter()
        .map(|tasks| SubmissionTree::from_enqueue_requests(source, tasks))
        .collect::<Result<Vec<_>, _>>()?;
    if trees.is_empty() {
        if !resolved.unresolved_projects.is_empty() {
            return Err(unresolved_projects_error(&resolved.unresolved_projects));
        }
        render::emit_line("no tasks resolved");
        return Ok(());
    }
    // The plan renders the substituted ids, so substitute before it.
    substitute_against_published(&mut trees).await?;
    render::mutation(
        output,
        trees,
        |envelope: &render::Planned<Vec<SubmissionTree>, crate::projects::SubmitOutcome>| {
            use std::fmt::Write as _;
            let nodes: usize = envelope.plan.iter().map(|tree| tree.nodes.len()).sum();
            let mut out = format!(
                "{} task(s) in {} tree(s), operations priority {}\n",
                nodes,
                envelope.plan.len(),
                args.priority
            );
            for node in envelope.plan.iter().flat_map(|tree| &tree.nodes) {
                let _ = writeln!(
                    out,
                    "  {} {} {} {} rustc={}",
                    node.crate_name,
                    node.version,
                    node.target,
                    node.features_json.raw(),
                    node.rustc_version,
                );
            }
            if let Some(result) = &envelope.result {
                let _ = writeln!(
                    out,
                    "submitted {}, inserted {}, dropped {} in {} batch(es)",
                    result.submitted, result.inserted, result.dropped, result.batches
                );
            }
            let _ = write!(out, "{}", render::plan_footer(envelope.dry_run));
            out
        },
        edge.as_ref().map(|edge| {
            async move |trees: &Vec<SubmissionTree>| {
                crate::projects::submit_chunked(edge, trees).await
            }
        }),
    )
    .await?;
    if !resolved.unresolved_projects.is_empty() {
        return Err(unresolved_projects_error(&resolved.unresolved_projects));
    }
    Ok(())
}

/// The projects lane's partial failure — reported after the wave
/// submits like the driver's own finish report did.
fn unresolved_projects_error(unresolved: &[String]) -> stow_types::error::Error {
    stow_error!(
        "{} project(s) failed to resolve:\n{}",
        unresolved.len(),
        unresolved.join("\n")
    )
}

/// The per-source resolve loop's progress line and its accumulators:
/// one `collect` per delivered source — `Ok` tasks land as one entry
/// of `sources` (each becomes one submission tree), an `Err` appends
/// `"{source}: {error}"` to `failures`.
struct SourceProgress {
    done: usize,
    total: usize,
    started: std::time::Instant,
}

impl SourceProgress {
    fn new(total: usize) -> Self {
        Self {
            done: 0,
            total,
            started: std::time::Instant::now(),
        }
    }

    /// Record one delivered source: log its completion, then fold it
    /// into the wave's accumulators.
    fn collect(
        &mut self,
        source: impl std::fmt::Display,
        result: Result<Vec<EnqueueRequest>, String>,
        sources: &mut Vec<Vec<EnqueueRequest>>,
        failures: &mut Vec<String>,
    ) {
        self.done += 1;
        match result {
            Ok(tasks) => {
                tracing::info!(
                    %source,
                    tasks = tasks.len(),
                    done = self.done,
                    total = self.total,
                    elapsed_s = self.started.elapsed().as_secs_f64(),
                    "resolved source"
                );
                sources.push(tasks);
            }
            Err(error) => {
                tracing::warn!(
                    %source,
                    %error,
                    done = self.done,
                    total = self.total,
                    elapsed_s = self.started.elapsed().as_secs_f64(),
                    "source resolve failed"
                );
                failures.push(format!("{source}: {error}"));
            }
        }
    }
}

/// What the source lanes produced: one task list per resolved source,
/// and the `--projects` repositories that failed to resolve. A
/// projects failure is reported after the submit rather than aborting
/// the wave; a `--crates` or `--dirs` failure still aborts before
/// submission.
struct ResolvedSources {
    /// One entry per resolved source — each becomes one
    /// [`SubmissionTree`] rooted at that source's own nodes.
    sources: Vec<Vec<EnqueueRequest>>,
    /// `"<repo>: <reason>"`, the string `SourceProgress::collect`
    /// builds — only the `--projects` lane feeds this.
    unresolved_projects: Vec<String>,
}

/// Read every input into per-source task lists: a crates file resolves
/// each line's newest non-yanked release (or the `@`-pinned one) with
/// the crate lane; a projects file resolves each listed repository's
/// git tree with the projects lane; `--dirs` resolves each local
/// directory the same way.
async fn resolve_sources(
    args: &ManualArgs,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<ResolvedSources> {
    // Version lookup runs sequentially (crates.io's pace gate); the
    // resolves then fan out on the pool.
    let mut jobs: Vec<(String, semver::Version)> = Vec::new();
    let mut failures = Vec::new();
    if let Some(path) = &args.crates {
        for (name, pinned) in load_crate_list(path).await? {
            match resolve_named_release(name.as_str(), pinned).await {
                Ok(release) => jobs.push((name.as_str().to_owned(), release)),
                Err(error) => failures.push(format!("{name}: {error}")),
            }
        }
    }
    let targets = targets.to_vec();
    let rustc_version = rustc_version.clone();
    let projects = args.projects.clone();
    let source_trees = args.source_trees.clone();
    let dirs = args.dirs.clone();
    let (sources, failures, unresolved_projects) = tokio::task::spawn_blocking(move || {
        let pool = crate::resolve::ResolvePool::new(&rustc_version)?;
        let mut sources = Vec::new();
        let mut unresolved_projects = Vec::new();
        if !jobs.is_empty() {
            let mut progress = SourceProgress::new(jobs.len());
            pool.run(
                &jobs,
                |resolver, runtime, (name, version)| {
                    crate::resolve::resolve_crate(
                        resolver,
                        runtime,
                        name,
                        version,
                        &targets,
                        &rustc_version,
                        0,
                    )
                    .map(|source| {
                        source
                            .targets
                            .into_iter()
                            .flat_map(|(_target, tasks)| tasks)
                            .collect::<Vec<EnqueueRequest>>()
                    })
                },
                |_, (name, version), result| {
                    progress.collect(
                        format_args!("{name}@{version}"),
                        result,
                        &mut sources,
                        &mut failures,
                    );
                },
            )?;
        }
        if let Some(path) = &projects {
            resolve_projects_lane(
                &pool,
                path,
                source_trees.as_ref(),
                &targets,
                &rustc_version,
                &mut sources,
                &mut unresolved_projects,
            )?;
        }
        if let Some(dirs) = &dirs {
            let mut progress = SourceProgress::new(dirs.len());
            pool.run(
                dirs,
                |resolver, _runtime, dir| {
                    crate::projects::resolve_project_dir(resolver, dir, &targets, &rustc_version)
                },
                |_, dir, result| {
                    progress.collect(dir.display(), result, &mut sources, &mut failures);
                },
            )?;
        }
        Ok::<_, stow_types::error::Error>((sources, failures, unresolved_projects))
    })
    .await
    .expect("resolve pool panicked")?;
    if !failures.is_empty() {
        return Err(stow_error!(
            "resolve failed for {} source(s):\n{}",
            failures.len(),
            failures.join("\n")
        ));
    }
    Ok(ResolvedSources {
        sources,
        unresolved_projects,
    })
}

/// The `--projects` lane inside `resolve_sources`: load the file and
/// the declared source trees, then fan the repositories over the pool.
/// A repository that fails to resolve lands in `unresolved_projects`
/// — reported after the submit (stow#572) — rather than aborting the
/// wave like a `--crates` or `--dirs` failure.
fn resolve_projects_lane(
    pool: &crate::resolve::ResolvePool,
    projects: &Path,
    source_trees: Option<&PathBuf>,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    sources: &mut Vec<Vec<EnqueueRequest>>,
    unresolved_projects: &mut Vec<String>,
) -> stow_types::error::Result<()> {
    let repos = tokio::runtime::Handle::current()
        .block_on(crate::projects::load_projects_file(projects))?;
    let trees = crate::source_trees::load_optional_source_trees(source_trees, &repos)?;
    let mut progress = SourceProgress::new(repos.len());
    pool.run(
        &repos,
        |resolver, _runtime, repo| {
            crate::projects::resolve_repository(
                resolver,
                repo,
                targets,
                rustc_version,
                trees.as_ref().and_then(|trees| trees.get(repo)),
            )
        },
        |_, repo, result| {
            progress.collect(repo, result, sources, unresolved_projects);
        },
    )?;
    Ok(())
}

/// The crate list's version semantics — `name@version` names that
/// non-yanked release exactly, a bare name takes the newest non-yanked.
async fn resolve_named_release(
    name: &str,
    pinned: Option<CrateVersion>,
) -> stow_types::error::Result<semver::Version> {
    let releases = crate::crates_io::index_releases(name).await?;
    if let Some(pinned) = pinned {
        let wanted = pinned.to_string();
        return if releases
            .iter()
            .any(|release| release.version == *pinned.as_semver() && !release.yanked)
        {
            Ok(pinned.as_semver().clone())
        } else {
            Err(stow_error!("crates.io lists no non-yanked {name} {wanted}"))
        };
    }
    let latest = crate::crates_io::latest_version(&releases)
        .ok_or_else(|| stow_error!("crates.io lists no non-yanked release of {name}"))?;
    semver::Version::parse(&latest).map_err(|error| stow_error!("{name} version {latest}: {error}"))
}

/// Parse a crate list file: `name` or `name@version` per line, `#`
/// comments and blanks ignored.
async fn load_crate_list(
    path: &Path,
) -> stow_types::error::Result<Vec<(CrateName, Option<CrateVersion>)>> {
    let raw = tokio::fs::read(path)
        .await
        .map_err(|error| stow_error!("read {}: {error}", path.display()))?;
    let text = String::from_utf8(raw)
        .map_err(|error| stow_error!("{} is not UTF-8: {error}", path.display()))?;
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let (name, version) = crate::coverage::parse_crate_spec(line)
            .map_err(|error| stow_error!("{}:{}: {error}", path.display(), index + 1))?;
        entries.push((name, version));
    }
    if entries.is_empty() {
        return Err(stow_error!("{} lists no crates", path.display()));
    }
    Ok(entries)
}

/// The runner-family host triple `target`'s host-side nodes mint on.
fn host_triple(target: &TargetTriple) -> String {
    stow_types::api::runner_family(target.as_str()).map_or_else(
        || target.as_str().to_owned(),
        |family| family.host_triple().to_owned(),
    )
}

/// The set of task ids the published slices already serve — semantic
/// identity coverage per the queue gate's shape rules: a host-side node
/// needs both invocation spellings' linked rows; a target-side node the
/// linked+unlinked pair of its own spelling. `pub` for the request
/// lane, which reports its `cached` roots off this set.
pub async fn covered_nodes(
    index: &Index<'_>,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    spellings: &BTreeMap<String, stow_types::public_cache::ExplicitSpelling>,
) -> stow_types::error::Result<BTreeSet<String>> {
    let mut covered = BTreeSet::new();
    // Slice pulls are reads — fan them out under the bounded
    // concurrency every index pull in this crate shares.
    let rows_per_target: Vec<Option<Vec<ArtifactIndexRow>>> = futures_util::stream::iter(
        targets
            .iter()
            .map(|target| published_slice_rows(index, target, rustc_version)),
    )
    .buffered(SLICE_PULL_CONCURRENCY)
    .try_collect()
    .await?;
    for (target, rows) in targets.iter().zip(rows_per_target) {
        let Some(rows) = rows else { continue };
        covered.extend(covered_slice_nodes(
            &rows,
            target,
            rustc_version,
            spellings,
        )?);
    }
    Ok(covered)
}

fn covered_slice_nodes(
    rows: &[ArtifactIndexRow],
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
    spellings: &BTreeMap<String, stow_types::public_cache::ExplicitSpelling>,
) -> stow_types::error::Result<BTreeSet<String>> {
    let mut shapes = HashMap::<_, BTreeSet<_>>::new();
    for row in rows {
        let shape = row.unit_shape;
        let dependency_identity = row.dependency_identity()?;
        let host_side = shape.side == stow_types::public_cache::UnitSide::Host;
        if host_side && host_triple(target) != target.as_str() {
            return Err(stow_error!("host row reported in non-host slice {target}"));
        }
        let identity = TaskNodeIdentity {
            crate_name: row.crate_name.clone(),
            version: row.version.clone(),
            features_json: row.features_json.clone(),
            target: target.clone(),
            rustc_version: rustc_version.clone(),
            host_side,
            profile: row.node_profile,
        };
        shapes
            .entry((identity, dependency_identity.clone()))
            .or_default()
            .insert(shape);
    }
    let invocation = if host_triple(target) == target.as_str() {
        UnitInvocation::Native
    } else {
        UnitInvocation::Target
    };
    Ok(shapes
        .into_iter()
        .filter(|((identity, context), served)| {
            // The flag the node's own request carries — rows for nodes
            // nothing asked about answer the historical two-shape rule.
            let spelling = spellings
                .get(&identity.task_id(context))
                .copied()
                .unwrap_or_default();
            required_unit_shapes(identity.host_side, invocation, spelling)
                .iter()
                .all(|shape| served.contains(shape))
        })
        .map(|((identity, context), _)| identity.task_id(&context))
        .collect())
}

/// Pull every target's published slice and answer the covered set —
/// the shared entry [`covered_nodes`] is the typed half of.
pub async fn contextual_coverage(
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    spellings: &BTreeMap<String, stow_types::public_cache::ExplicitSpelling>,
) -> stow_types::error::Result<BTreeSet<String>> {
    let base = crate::index_cmd::registry_base()?;
    let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    let repository = cache_repository(rustc_version);
    let session = base.session(&repository, &http);
    let trust = stow_oci::verify::records_trust().await?;
    covered_nodes(
        &Index {
            session: &session,
            repository: &repository,
            trust: &trust,
        },
        targets,
        rustc_version,
        spellings,
    )
    .await
}

/// Pull and verify the `index.<target>.<rustc>` slices the superset
/// substitution pool reads (stow#881): the same verified rows
/// `covered_nodes` answers coverage from, kept with their slice
/// coordinates so a row's task identity is reconstructable.
pub async fn published_slices(
    pairs: &BTreeSet<(TargetTriple, WireRustcVersion)>,
) -> stow_types::error::Result<Vec<stow_types::api::PublishedIndexSlice>> {
    let base = crate::index_cmd::registry_base()?;
    let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    let trust = stow_oci::verify::records_trust().await?;
    // The cache repository is per-rustc; group the pull by it.
    let mut by_rustc = BTreeMap::<&WireRustcVersion, Vec<&TargetTriple>>::new();
    for (target, rustc_version) in pairs {
        by_rustc.entry(rustc_version).or_default().push(target);
    }
    let mut slices = Vec::new();
    for (rustc_version, targets) in by_rustc {
        let repository = cache_repository(rustc_version);
        let session = base.session(&repository, &http);
        let index = Index {
            session: &session,
            repository: &repository,
            trust: &trust,
        };
        let rows_per_target: Vec<Option<Vec<ArtifactIndexRow>>> = futures_util::stream::iter(
            targets
                .iter()
                .map(|target| published_slice_rows(&index, target, rustc_version)),
        )
        .buffered(SLICE_PULL_CONCURRENCY)
        .try_collect()
        .await?;
        for (target, rows) in targets.iter().zip(rows_per_target) {
            if let Some(rows) = rows {
                slices.push(stow_types::api::PublishedIndexSlice {
                    target: (*target).clone(),
                    rustc_version: rustc_version.clone(),
                    rows,
                });
            }
        }
    }
    Ok(slices)
}

/// Serve every contained feature set in `trees` from its smallest
/// containing set (stow#881). The pool is the batch plus the published
/// sets in the signed slices covering the batch's own (target, rustc)
/// pairs; a host-side node's `target` is its family's host triple, so
/// the pairs cover host slices too.
pub async fn substitute_against_published(
    trees: &mut [SubmissionTree],
) -> stow_types::error::Result<()> {
    let pairs = trees
        .iter()
        .flat_map(|tree| &tree.nodes)
        .map(|node| (node.target.clone(), node.rustc_version.clone()))
        .collect::<BTreeSet<_>>();
    let published = published_slices(&pairs).await?;
    SubmissionTree::substitute_contained_sets(trees, &published)
}

/// The three handles the index-slice pulls share — `pub` so the
/// request lane pulls the same verified slices.
pub struct Index<'a> {
    pub session: &'a stow_oci::RegistrySession,
    pub repository: &'a CacheRepository,
    pub trust: &'a stow_oci::verify::Trust,
}

/// Pull and verify the published `index.<target>.<rustc>` slice —
/// `None` when the tag does not exist (a fresh registry serves an empty
/// catalog, not an error).
pub async fn published_slice_rows(
    index: &Index<'_>,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<Option<Vec<ArtifactIndexRow>>> {
    let tag = index_tag(target.as_str(), rustc_version.as_str());
    let reference = index.session.reference(&tag)?;
    let (bytes, manifest_digest) = match index.session.pull_manifest(&reference).await {
        Ok(pair) => pair,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => return Err(stow_error!("pull index {reference}: {error}")),
    };
    let manifest: OciImageManifest = serde_json::from_slice(&bytes)
        .map_err(|error| stow_error!("parse index manifest {reference}: {error}"))?;
    let [layer] = manifest.layers.as_slice() else {
        return Err(stow_error!(
            "index manifest {reference} carries {} layers, expected exactly one",
            manifest.layers.len()
        ));
    };
    if layer.media_type != STOW_INDEX_MEDIA_TYPE {
        return Err(stow_error!(
            "index manifest {reference} layer is {}, expected {STOW_INDEX_MEDIA_TYPE}",
            layer.media_type
        ));
    }
    let blob = stow_oci::pull_blob_verified(index.session, layer).await?;
    let materials =
        stow_oci::pull_signature_materials(index.session, &reference, &manifest_digest).await?;
    stow_oci::verify::verify_materials(
        index.trust,
        &index.repository.reference(&tag),
        &manifest_digest,
        &materials,
        stow_types::trusted_builder::INDEX_CERTIFICATE_IDENTITY,
    )?;
    let index = crate::index_cmd::decode_published_slice(&reference, rustc_version, &blob)?;
    if index.header.target.as_str() != target.as_str()
        || index.header.rustc_version.as_str() != rustc_version.as_str()
    {
        return Err(stow_error!(
            "index slice {tag} was published for {}@{}",
            index.header.target.as_str(),
            index.header.rustc_version.as_str()
        ));
    }
    Ok(Some(index.rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The manual wave's only reach toward builds is the trusted
    /// submit: one POST of the resolved trees to
    /// `/api/v1/scheduler/tasks/submit`, every tree stamped
    /// `operations` at the caller's priority operand.
    #[tokio::test]
    async fn submit_posts_operations_trees_at_caller_priority() {
        let server = crate::test_server::Loopback::start(vec![crate::test_server::Step::Respond {
            status: 200,
            retry_after: None,
            body: r#"{"submitted":1,"inserted":1,"dropped":0}"#,
        }])
        .await;
        let edge = crate::Edge::for_test(server.url.clone());
        let node = stow_types::api::SubmissionNode {
            task_id: "walkdir-2.5.0-x86_64_unknown_linux_gnu-1.90.0-d00".to_owned(),
            crate_name: "walkdir".parse().expect("crate name"),
            version: CrateVersion::new(semver::Version::new(2, 5, 0)),
            features_json: stow_types::identity::FeaturesJson::canonicalize(vec![
                "default".to_owned(),
            ])
            .expect("features"),
            target: TargetTriple::parse("x86_64-unknown-linux-gnu".to_owned()).expect("target"),
            rustc_version: WireRustcVersion::parse("1.90.0".to_owned()).expect("rustc"),
            host_side: false,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::default(),
            preserve_lockfile: false,
            dependency_identity: stow_types::identity::DependencyIdentity::leaf()
                .expect("leaf identity"),
            deps: vec![],
            downloads: 0,
            profile: stow_types::node_profile::NodeProfile::Dev,
        };
        let tree = SubmissionTree {
            source: SubmissionSource::Operations { priority: 3_000 },
            roots: vec![0],
            nodes: vec![node],
        };
        crate::submit(&edge, &[tree]).await.expect("submit");
        let requests = server.join().await;
        let [request] = requests.as_slice() else {
            panic!("expected exactly one submit POST, saw {}", requests.len());
        };
        assert_eq!(request.head.method.as_str(), "POST");
        assert_eq!(request.head.uri.path(), "/api/v1/scheduler/tasks/submit");
        let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json body");
        assert_eq!(
            body[0]["source"],
            serde_json::json!({ "kind": "operations", "priority": 3000 })
        );
    }

    /// stow#844: `published_slice_rows` treats a package that does not
    /// exist as the empty index — GHCR's `403 DENIED` on the anonymous
    /// token exchange reads `None`, the same answer a missing tag gives.
    #[tokio::test]
    async fn published_slice_rows_reads_a_missing_package_as_none() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let server = crate::test_server::Loopback::start_on(
            listener,
            base.clone(),
            vec![
                crate::test_server::Step::RespondWith {
                    status: 401,
                    retry_after: None,
                    headers: vec![(
                        "www-authenticate".to_owned(),
                        format!("Bearer realm=\"{base}/token\",service=\"mock-registry\""),
                    )],
                    body: "",
                },
                crate::test_server::Step::Respond {
                    status: 403,
                    retry_after: None,
                    body: r#"{"errors":[{"code":"DENIED","message":"requested access to the resource is denied"}]}"#,
                },
            ],
        );
        let base = stow_oci::RegistryBase::parse(&server.url).expect("registry base");
        let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT)
            .await
            .expect("registry http");
        let rustc_version = WireRustcVersion::parse("9.99.9").expect("rustc");
        let repository = cache_repository(&rustc_version);
        let session = base.session(&repository, &http);
        let trust = stow_oci::verify::Trust::MockKey(std::path::PathBuf::from("/unused"));
        let index = Index {
            session: &session,
            repository: &repository,
            trust: &trust,
        };

        let rows = published_slice_rows(
            &index,
            &TargetTriple::parse("x86_64-unknown-linux-gnu").expect("target"),
            &rustc_version,
        )
        .await
        .expect("a missing package is the empty index");
        assert!(rows.is_none());
        let _ = server.join().await;
    }
}

//! Worker-side graph resolution through `stow-resolve`.
//!
//! Every lane that expands a name into build tasks — the human request
//! lane, the preheat lanes (crates.io binaries and GitHub projects), and
//! the register-scope closure check — resolves the published manifest
//! itself rather than walking crates.io metadata by hand. The resolver is
//! cargo's own code carried into `stow-resolve`; the worker supplies the
//! three things a real `cargo` invocation would have read from the machine:
//!
//! - the manifest source: the `.crate` tarball from `static.crates.io`,
//!   or the GitHub repo tarball for the projects lane, unpacked into a
//!   [`MemoryVfs`]. A `Cargo.lock` a `.crate` ships stays in place, so the
//!   resolve lands on the pins `cargo install --locked` reproduces — the
//!   projects lane drops the committed lockfile so its resolve lands on
//!   the latest semver-compatible versions, as it did when the admin CLI
//!   ran `cargo metadata` locally;
//! - the registry: cargo's sparse-index machinery over a [`worker::Fetch`]
//!   transport, with the index `.cache` files persisting under the shared
//!   in-memory cargo home for the whole request;
//! - the toolchain truth: `rustc -vV` and `rustc --print cfg` vendored per
//!   rustc release in [`stow_resolve::rustc_data`], keyed by the task's
//!   `rustc_version`. A resolve for an unvendored version is a truthful
//!   error.
//!
//! One `cargo metadata --filter-platform` invocation resolves exactly one
//! requested platform — host-dep features unify across that build's edges
//! alone — so a multi-target request resolves once per target. Index
//! fetches are shared through the request's single [`MemoryVfs`], so the
//! per-target cost is the graph walk, not the network.

// Resolve futures are `!Send` by construction — `Rc` HTTP clients and the
// thread-local ambient VFS — and every caller wraps them in
// `IntoSendFuture`, which is safe on the single-threaded isolate.
#![allow(clippy::future_not_send)]

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use crate::dependency_resolver::{
    PackageKey, load_cached_artifacts_for_keys, serialize_feature_set,
};
use crate::errors::ResolverError;
use semver::Version;
use skyzen_services::Db;
use stow_resolve::api::{self, StowResolveInput, StowUnit, StowUnitKey, StowUnitKind};
use stow_resolve::rustc_data;
use stow_resolve::util::context::{Env, GlobalContext};
use stow_resolve::util::fs::{MemoryVfs, set_vfs};
use stow_resolve::util::network::http_async::{Client, HttpClient};
use stow_resolve::util::shell::Shell;
use stow_types::api::{EnqueueDependency, EnqueueRequest, EnqueueSource, runner_family};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};

/// The fetch transport the resolve machinery drives.
pub type ResolveHttp = Rc<dyn HttpClient>;

/// The HTTP client for production resolves: [`worker::Fetch`] on wasm32.
///
/// On the host the edge runs only unit tests, which inject
/// [`stow_resolve::testing::RecordedHttp`] instead.
#[cfg(target_family = "wasm")]
#[must_use]
pub fn fetch_http() -> ResolveHttp {
    Rc::new(WorkerFetchHttp)
}

/// The host-side transport. The edge runs production resolves only on
/// wasm; on the host — where `stow-edge` compiles for tests — fetching
/// through the worker transport cannot exist, and callers inject
/// [`stow_resolve::testing::RecordedHttp`] for anything a test needs.
/// This client answers with a truthful error rather than an implicit
/// fallback.
#[cfg(not(target_family = "wasm"))]
#[must_use]
pub fn fetch_http() -> ResolveHttp {
    struct HostUnavailable;
    impl HttpClient for HostUnavailable {
        fn request<'a>(
            &'a self,
            request: http::Request<Vec<u8>>,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = stow_resolve::util::errors::CargoResult<http::Response<Vec<u8>>>,
                    > + 'a,
            >,
        > {
            Box::pin(async move {
                Err(anyhow::format_err!(
                    "the worker fetch transport is unavailable on the host;                      inject a fixture client ({}) for tests",
                    request.uri()
                ))
            })
        }
    }
    Rc::new(HostUnavailable)
}

/// A node in the per-platform task graph — the full identity a scheduler
/// task carries minus `rustc_version` (shared by the wave): crate,
/// version, resolved feature set, and the triple the unit compiles on.
/// Host-side units (proc-macros, build dependencies) key at the runner
/// family's host triple, not the consumer's target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TaskNode {
    /// Crate name.
    crate_name: CrateName,
    /// Crate version.
    version: CrateVersion,
    /// Canonical features JSON (sorted array).
    features_json: String,
    /// Compilation target triple the unit keys on.
    target: String,
}

/// What one target's resolve produced for the request lane: the enqueue
/// batch plus the root's outcome inputs. Shape matches the old
/// `CrateRequestPlan` so `api.rs` call sites keep their fields.
pub struct CrateRequestPlan {
    /// One task per uncovered node in the resolved closure.
    pub enqueue_requests: Vec<EnqueueRequest>,
    /// Whether the root's artifact already exists in the catalog.
    pub root_cached: bool,
    /// Whether the requested package publishes a library target.
    pub root_has_library: bool,
    /// The root task's canonical features JSON.
    pub root_features_json: String,
}

/// One workspace (a `.crate` package or a repo checkout) held in memory
/// for the request's whole per-target fan-out: `vfs` carries the source
/// tree and doubles as the cargo home root so index `.cache` files live
/// across the resolves.
struct SourceWorkspace {
    /// The shared in-memory filesystem.
    vfs: Rc<MemoryVfs>,
    /// Root manifest the resolves read.
    manifest_path: PathBuf,
    /// Packages with a `[[bin]]` target among workspace members — the
    /// binaries lane's `has_binary` answer, taken from cargo's own target
    /// knowledge rather than the crates.io record.
    has_binary: bool,
    /// Whether the tree carried a `Cargo.lock` into the resolve.
    ships_lockfile: bool,
}

/// The in-memory tree every resolve in this request shares.
const WORKSPACE_DIR: &str = "/ws";

/// Expand one crate request into a per-target task plan — the request
/// lane's expansion. The `.crate` tarball is fetched once for the whole
/// fan-out; each target gets its own resolve because cargo unifies
/// host-dep features per requested platform.
///
/// # Errors
/// [`ResolverError`] on fetch, parse, or resolution failures.
pub async fn expand_crate_request_on_targets(
    db: &Db,
    crate_name: &CrateName,
    version: &Version,
    seed_features: &BTreeSet<String>,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
) -> Result<Vec<(TargetTriple, CrateRequestPlan)>, ResolverError> {
    let source = crate_workspace(crate_name, version, /* keep lockfile */ true).await?;
    let mut plans = Vec::with_capacity(targets.len());
    for target in targets {
        let output = resolve_workspace(
            &source,
            seed_features,
            seed_features.is_empty(),
            target,
            rustc_version,
        )
        .await?;
        plans.push((
            target.clone(),
            plan_from_output(db, &output, crate_name, version, rustc_version).await?,
        ));
    }
    Ok(plans)
}

/// The name/version closure a dispatched task may publish — every package
/// the resolve pulls into the unit graph is inside it. Register-scope
/// check for `task_binding`, replacing the old crates.io closure walk.
///
/// # Errors
/// [`ResolverError`] on fetch, parse, or resolution failures.
pub async fn expand_task_closure(
    crate_name: &CrateName,
    version: &Version,
    seed_features: &BTreeSet<String>,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
) -> Result<BTreeSet<(CrateName, CrateVersion)>, ResolverError> {
    let source = crate_workspace(crate_name, version, /* keep lockfile */ true).await?;
    let output = resolve_workspace(
        &source,
        seed_features,
        seed_features.is_empty(),
        target,
        rustc_version,
    )
    .await?;
    output
        .units
        .iter()
        .map(|unit| {
            Ok((
                CrateName::parse(unit.name.clone()).map_err(ResolverError::Identity)?,
                CrateVersion::new(
                    semver::Version::parse(&unit.version).expect("resolver emits semver versions"),
                ),
            ))
        })
        .collect::<Result<_, ResolverError>>()
}

/// What an admin resolve lane learns about the source: publish-shape
/// flags plus the per-target task batch.
pub struct SourceResolve {
    /// Whether the source ships a `[[bin]]` — the binaries lane's skip
    /// condition, taken from cargo's own target knowledge.
    pub has_binary: bool,
    /// Whether the root package ships a library target.
    pub has_library: bool,
    /// Whether the source shipped a `Cargo.lock` the resolve honored —
    /// a `.crate`'s bundled lockfile; a project's committed one is
    /// dropped before the resolve, so the flag reads `false` there.
    pub ships_lockfile: bool,
    /// One task batch per requested target, in request order.
    pub targets: Vec<(TargetTriple, Vec<EnqueueRequest>)>,
}

/// The admin crate lane: resolve one published `.crate` into tasks. The
/// tarball's bundled `Cargo.lock` stays in place — the `cargo install
/// --locked` resolve — and the emitted tasks carry
/// `preserve_lockfile: false` since the flag names the task crate's own
/// lockfile, not the source's.
///
/// # Errors
/// [`ResolverError`] on fetch, parse, or resolution failures.
pub async fn resolve_crate(
    crate_name: &CrateName,
    version: &Version,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    downloads: u64,
) -> Result<SourceResolve, ResolverError> {
    let source = crate_workspace(crate_name, version, true).await?;
    source_resolve(&source, targets, rustc_version, downloads).await
}

/// The projects lane: resolve a GitHub repository's workspace into crate
/// tasks. The tarball is fetched from codeload and the committed
/// `Cargo.lock` is dropped — a project contributes names and feature
/// sets, never version pins.
///
/// # Errors
/// [`ResolverError`] on fetch, parse, or resolution failures.
pub async fn resolve_github_project(
    repo: &str,
    git_ref: &str,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    downloads: u64,
) -> Result<SourceResolve, ResolverError> {
    let source = github_workspace(repo, git_ref).await?;
    source_resolve(&source, targets, rustc_version, downloads).await
}

/// Resolve a prepared workspace once per target into tasks + flags.
async fn source_resolve(
    source: &SourceWorkspace,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    downloads: u64,
) -> Result<SourceResolve, ResolverError> {
    let seed_features = BTreeSet::new();
    let mut has_library = false;
    let mut batches = Vec::with_capacity(targets.len());
    for target in targets {
        let output =
            resolve_workspace(source, &seed_features, false, target, rustc_version).await?;
        if output.roots.iter().any(|key| key.kind == StowUnitKind::Lib) {
            has_library = true;
        }
        let (requests, _) = enqueue_requests_from_output(
            &output,
            rustc_version,
            EnqueueSource::CrateUpdate,
            downloads,
        );
        batches.push((target.clone(), requests));
    }
    Ok(SourceResolve {
        has_binary: source.has_binary,
        has_library,
        ships_lockfile: source.ships_lockfile,
        targets: batches,
    })
}

/// Download and unpack one published `.crate` into memory.
async fn crate_workspace(
    crate_name: &CrateName,
    version: &Version,
    keep_lockfile: bool,
) -> Result<SourceWorkspace, ResolverError> {
    let url = format!("https://static.crates.io/crates/{crate_name}/{crate_name}-{version}.crate");
    let bytes = get_bytes(&fetch_http(), &url).await?;
    let files = unpack_tar_gz(&bytes).map_err(|error| {
        ResolverError::CratesIo(format!("unpack {crate_name}-{version}.crate: {error}"))
    })?;
    build_workspace(files, keep_lockfile)
}

/// Download and unpack one GitHub repo tarball into memory.
async fn github_workspace(repo: &str, git_ref: &str) -> Result<SourceWorkspace, ResolverError> {
    let url = format!("https://codeload.github.com/{repo}/tar.gz/{git_ref}");
    let bytes = get_bytes(&fetch_http(), &url).await?;
    let files = unpack_tar_gz(&bytes).map_err(|error| {
        ResolverError::CratesIo(format!("unpack {repo}@{git_ref} tarball: {error}"))
    })?;
    build_workspace(files, false)
}

/// Lay the unpacked tree into a fresh [`MemoryVfs`], find the root
/// manifest, and report whether any member ships a `[[bin]]`.
fn build_workspace(
    files: BTreeMap<PathBuf, Vec<u8>>,
    keep_lockfile: bool,
) -> Result<SourceWorkspace, ResolverError> {
    let vfs = Rc::new(MemoryVfs::new());
    let root = PathBuf::from(WORKSPACE_DIR);
    // The manifest the lane's admission picked: the shallowest
    // `Cargo.lock` whose directory also carries `Cargo.toml` — a
    // lockfile roots the workspace it pins. Repos the admission let
    // through always have one; for a tarball without any lock (or a
    // `.crate`, whose package is the root) the root manifest answers.
    let manifest_path = select_manifest(&files)
        .map(|manifest| root.join(&manifest))
        .ok_or_else(|| ResolverError::BadRequest("tarball contains no Cargo.toml".to_owned()))?;
    let ships_lockfile = keep_lockfile && files.contains_key(Path::new("Cargo.lock"));
    let mut has_binary = false;
    for (path, data) in files {
        // `[[bin]]` detection: a manifest target table or `src/main.rs` /
        // `src/bin/*` presence — cargo's own convention. The lib member
        // of a `.crate` is the root package; binaries may live anywhere
        // in a project workspace.
        if path.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml")
            && String::from_utf8_lossy(&data).contains("[[bin]]")
        {
            has_binary = true;
        }
        let components: Vec<&str> = path
            .components()
            .filter_map(|c| match c {
                Component::Normal(name) => name.to_str(),
                _ => None,
            })
            .collect();
        // cargo's bin autodiscovery: src/main.rs, src/bin/*.rs,
        // src/bin/*/main.rs — the same shapes `inspect_crate_archive`
        // used.
        has_binary |= match components.as_slice() {
            ["src", "main.rs"] | ["src", "bin", _, "main.rs"] => true,
            ["src", "bin", name] => Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("rs")),
            _ => false,
        };
        if keep_lockfile || path != Path::new("Cargo.lock") {
            vfs.insert(root.join(path), data);
        }
    }
    Ok(SourceWorkspace {
        vfs,
        manifest_path,
        has_binary,
        ships_lockfile,
    })
}

/// The manifest the projects lane resolves: the shallowest `Cargo.lock`
/// whose directory also carries `Cargo.toml` — matching
/// `projects.rs`'s `select_manifest` so a lockfile nested under
/// `src-tauri/`, `rust/`, `cli/` or `crates/` picks that directory's
/// manifest — else the shallowest `Cargo.toml` at all.
fn select_manifest(files: &BTreeMap<PathBuf, Vec<u8>>) -> Option<PathBuf> {
    let manifest_dirs: BTreeMap<PathBuf, PathBuf> = files
        .keys()
        .filter(|path| path.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml"))
        .map(|path| {
            (
                path.parent().map_or_else(PathBuf::new, Path::to_path_buf),
                path.clone(),
            )
        })
        .collect();
    // Shallowest lockfile first, lexicographic within a depth — the
    // order `select_manifest` in the admin lane used.
    let mut lock_dirs: Vec<PathBuf> = files
        .keys()
        .filter(|path| path.file_name().and_then(|n| n.to_str()) == Some("Cargo.lock"))
        .filter_map(|path| path.parent().map(Path::to_path_buf))
        .collect();
    lock_dirs.sort_by(|a, b| {
        a.components()
            .count()
            .cmp(&b.components().count())
            .then_with(|| a.cmp(b))
    });
    for dir in lock_dirs {
        if let Some(manifest) = manifest_dirs.get(&dir) {
            return Some(manifest.clone());
        }
    }
    manifest_dirs
        .into_iter()
        .min_by_key(|(dir, _)| (dir.components().count(), dir.clone()))
        .map(|(_, manifest)| manifest)
}

/// Unpack a gzipped tarball into `(stripped_path, bytes)` pairs: the
/// archive's single top-level directory is stripped and `pax_global_header`
/// entries skipped — the same normalization the harness's corpus loader
/// applies.
fn unpack_tar_gz(bytes: &[u8]) -> anyhow::Result<BTreeMap<PathBuf, Vec<u8>>> {
    use anyhow::Context as _;
    use std::io::Read as _;

    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut out = BTreeMap::new();
    for entry in archive.entries().context("read tarball entries")? {
        let mut entry = entry.context("read tarball entry")?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path().context("entry path")?.into_owned();
        let mut components = path.components();
        // Strip the archive's top-level directory.
        let Some(Component::Normal(_top)) = components.next() else {
            continue;
        };
        let rel: PathBuf = components.as_path().to_path_buf();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data).context("read entry body")?;
        out.insert(rel, data);
    }
    Ok(out)
}

/// One request's resolved units for one target assembled into the
/// request-lane plan: enqueue batch plus the root's cached/library flags.
async fn plan_from_output(
    db: &Db,
    output: &api::StowResolveOutput,
    crate_name: &CrateName,
    version: &Version,
    rustc_version: &WireRustcVersion,
) -> Result<CrateRequestPlan, ResolverError> {
    let (nodes, edges) = task_graph(output)?;
    let root_key = output
        .roots
        .iter()
        .find(|key| key.kind == StowUnitKind::Lib)
        .map(|key| TaskNode {
            crate_name: crate_name.clone(),
            version: CrateVersion::new(version.clone()),
            features_json: unit_features(output, key).unwrap_or_default(),
            target: key.platform.clone(),
        });
    let covered = covered_nodes(db, &nodes, rustc_version).await?;
    let (enqueue_requests, _) = enqueue_requests_inner(
        &nodes,
        &edges,
        &covered,
        rustc_version,
        EnqueueSource::HumanRequest,
        0,
    );
    let root_has_library = root_key.is_some();
    let root_features_json = root_key
        .as_ref()
        .map_or_else(|| "[]".to_owned(), |key| key.features_json.clone());
    let root_cached = root_key.as_ref().is_some_and(|key| covered.contains(key));
    Ok(CrateRequestPlan {
        enqueue_requests,
        root_cached,
        root_has_library,
        root_features_json,
    })
}

/// Assemble the enqueue batch for a resolve output: `(requests, nodes)`.
fn enqueue_requests_from_output(
    output: &api::StowResolveOutput,
    rustc_version: &WireRustcVersion,
    source: EnqueueSource,
    downloads: u64,
) -> (Vec<EnqueueRequest>, BTreeSet<TaskNode>) {
    let nodes_edges = task_graph(output);
    let (nodes, edges) = match nodes_edges {
        Ok(pair) => pair,
        Err(error) => {
            tracing::warn!(%error, "unit graph assembly failed — no tasks");
            return (Vec::new(), BTreeSet::new());
        }
    };
    enqueue_requests_inner(
        &nodes,
        &edges,
        &BTreeSet::new(),
        rustc_version,
        source,
        downloads,
    )
}

/// The lib-unit graph the wave machinery works on: every task node and
/// its task-level dependency edges.
///
/// Every task node and its task-level edges.
type TaskGraph = (BTreeSet<TaskNode>, BTreeMap<TaskNode, BTreeSet<TaskNode>>);

/// A node's task deps are the lib units its own build must find in the
/// cache: its normal-dependency lib units (the lib unit's `deps` of kind
/// `Lib`), plus the build-dependency lib units its build script links
/// (the compile unit's `deps` of kind `Lib`). Run and compile units are
/// interior — they happen inside the owning lib's task and mint no task
/// of their own.
fn task_graph(output: &api::StowResolveOutput) -> Result<TaskGraph, ResolverError> {
    let by_key = |name: &str, version: &str, platform: &str, side| {
        output.units.iter().find(|unit| {
            unit.name == name
                && unit.version == version
                && unit.key.platform == platform
                && unit.key.side == side
                && unit.key.kind == StowUnitKind::Lib
        })
    };
    let node_of = |unit: &StowUnit| -> Result<TaskNode, ResolverError> {
        Ok(TaskNode {
            crate_name: CrateName::parse(unit.name.clone()).map_err(ResolverError::Identity)?,
            version: CrateVersion::new(
                semver::Version::parse(&unit.version).expect("resolver emits semver versions"),
            ),
            features_json: serialize_feature_set(
                &unit.features.iter().cloned().collect::<BTreeSet<_>>(),
            )?,
            target: unit.key.platform.clone(),
        })
    };
    let mut nodes = BTreeSet::new();
    let mut edges = BTreeMap::<TaskNode, BTreeSet<TaskNode>>::new();
    for unit in &output.units {
        if unit.key.kind != StowUnitKind::Lib {
            continue;
        }
        let node = node_of(unit)?;
        nodes.insert(node.clone());
        let entry = edges.entry(node).or_default();
        // Normal-dep libs.
        for dep in &unit.deps {
            if dep.key.kind != StowUnitKind::Lib {
                continue;
            }
            if let Some(dep_unit) = by_key(&dep.name, &dep.version, &dep.key.platform, dep.key.side)
            {
                entry.insert(node_of(dep_unit)?);
            }
        }
        // Build-dep libs: the package's own build-script compile unit,
        // dedup'd by feature set as `emit_units` produced it.
        let compile = output.units.iter().find(|candidate| {
            candidate.key.kind == StowUnitKind::BuildScript
                && candidate.name == unit.name
                && candidate.version == unit.version
                && candidate.features == unit.features
        });
        if let Some(compile) = compile {
            for dep in &compile.deps {
                if dep.key.kind != StowUnitKind::Lib {
                    continue;
                }
                if let Some(dep_unit) =
                    by_key(&dep.name, &dep.version, &dep.key.platform, dep.key.side)
                {
                    entry.insert(node_of(dep_unit)?);
                }
            }
        }
    }
    Ok((nodes, edges))
}

/// Decode a canonical features JSON string back into the typed form.
fn features_json(raw: &str) -> FeaturesJson {
    let features: Vec<String> = serde_json::from_str(raw).expect("canonical features json");
    FeaturesJson::from_sorted(features).expect("serialize_feature_set sorted")
}

/// The feature set of the unit `key` points at.
fn unit_features(output: &api::StowResolveOutput, key: &StowUnitKey) -> Option<String> {
    let unit = output.units.iter().find(|unit| &unit.key == key)?;
    serialize_feature_set(&unit.features.iter().cloned().collect::<BTreeSet<_>>()).ok()
}

/// Nodes the artifact catalog already covers, per platform: each node's
/// `target` is the triple its artifact is keyed under, so coverage is
/// looked up per platform group — host units resolve against the host
/// triple's rows.
async fn covered_nodes(
    db: &Db,
    nodes: &BTreeSet<TaskNode>,
    rustc_version: &WireRustcVersion,
) -> Result<BTreeSet<TaskNode>, ResolverError> {
    let mut covered = BTreeSet::new();
    let mut by_platform: BTreeMap<&str, BTreeSet<(PackageKey, String)>> = BTreeMap::new();
    for node in nodes {
        by_platform
            .entry(node.target.as_str())
            .or_default()
            .insert((
                PackageKey {
                    crate_name: node.crate_name.clone(),
                    version: node.version.as_semver().clone(),
                },
                node.features_json.clone(),
            ));
    }
    for (platform, key_pairs) in by_platform {
        let semantic =
            load_cached_artifacts_for_keys(db, platform, rustc_version.as_str(), &key_pairs)
                .await?;
        let semantic: BTreeSet<(CrateName, semver::Version, String)> = semantic
            .into_iter()
            .map(|(key, features)| (key.crate_name, key.version, features))
            .collect();
        covered.extend(
            nodes
                .iter()
                .filter(|node| {
                    node.target == platform
                        && semantic.contains(&(
                            node.crate_name.clone(),
                            node.version.as_semver().clone(),
                            node.features_json.clone(),
                        ))
                })
                .cloned(),
        );
    }
    Ok(covered)
}

/// Emit one [`EnqueueRequest`] per uncovered node, dominator-ordered: a
/// node inside another uncovered node's closure rides on its dominator's
/// `depends_on`, as the old `build_enqueue_requests` shaped it — except
/// each node carries its own `target` now.
fn enqueue_requests_inner(
    nodes: &BTreeSet<TaskNode>,
    edges: &BTreeMap<TaskNode, BTreeSet<TaskNode>>,
    covered: &BTreeSet<TaskNode>,
    rustc_version: &WireRustcVersion,
    source: EnqueueSource,
    downloads: u64,
) -> (Vec<EnqueueRequest>, BTreeSet<TaskNode>) {
    let uncovered: BTreeSet<TaskNode> = nodes
        .iter()
        .filter(|n| !covered.contains(*n))
        .cloned()
        .collect();
    let dominators = immediate_dominators(nodes, edges, &uncovered);
    let mut requests = Vec::new();
    for node in &uncovered {
        let depends_on = dominators
            .get(node)
            .map(|dominator| EnqueueDependency {
                crate_name: dominator.crate_name.clone(),
                version: dominator.version.clone(),
                features_json: features_json(&dominator.features_json),
                target: TargetTriple::parse(&dominator.target)
                    .expect("resolver emits CI or host triples"),
                rustc_version: rustc_version.clone(),
            })
            .into_iter()
            .collect::<Vec<_>>();
        requests.push(EnqueueRequest {
            crate_name: node.crate_name.clone(),
            version: node.version.clone(),
            features_json: features_json(&node.features_json),
            target: TargetTriple::parse(&node.target).expect("resolver emits CI or host triples"),
            rustc_version: rustc_version.clone(),
            downloads,
            source,
            depends_on,
            preserve_lockfile: false,
        });
    }
    (requests, uncovered)
}

/// For every uncovered node that lies in the transitive closure of
/// another uncovered node, the uncovered node with the smallest closure
/// containing it; ties break on node order. Mirrors
/// `dependency_resolver::immediate_dominators` over the platform-keyed
/// node space.
fn immediate_dominators(
    nodes: &BTreeSet<TaskNode>,
    edges: &BTreeMap<TaskNode, BTreeSet<TaskNode>>,
    uncovered: &BTreeSet<TaskNode>,
) -> BTreeMap<TaskNode, TaskNode> {
    use fixedbitset::FixedBitSet;

    let keys: Vec<TaskNode> = nodes.iter().cloned().collect();
    let index_of: BTreeMap<TaskNode, usize> = keys
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, k)| (k, i))
        .collect();
    let mut closure: Vec<FixedBitSet> = keys
        .iter()
        .map(|key| {
            let mut bits = FixedBitSet::with_capacity(keys.len());
            for dep in edges.get(key).into_iter().flatten() {
                if let Some(&dep_index) = index_of.get(dep) {
                    bits.insert(dep_index);
                }
            }
            bits
        })
        .collect();
    let mut changed = true;
    while changed {
        changed = false;
        for node in 0..keys.len() {
            let before = closure[node].count_ones(..);
            let reachable = closure[node].ones().collect::<Vec<_>>();
            for dep in reachable {
                let dep_closure = closure[dep].clone();
                closure[node].union_with(&dep_closure);
            }
            if closure[node].count_ones(..) != before {
                changed = true;
            }
        }
    }
    let mut dominators = BTreeMap::new();
    for (node, key) in keys.iter().enumerate() {
        if !uncovered.contains(key) {
            continue;
        }
        let immediate = (0..keys.len())
            .filter(|&candidate| {
                candidate != node
                    && uncovered.contains(&keys[candidate])
                    && closure[candidate].contains(node)
            })
            .min_by_key(|&candidate| (closure[candidate].count_ones(..), candidate));
        if let Some(dominator) = immediate {
            dominators.insert(key.clone(), keys[dominator].clone());
        }
    }
    dominators
}

/// `GET` the URL body — one fetch, no retry: the index machinery retries
/// on its own machinery's `Retry` policy; tarballs and one-shot GETs pass
/// through the same transport.
async fn get_bytes(client: &ResolveHttp, url: &str) -> Result<Vec<u8>, ResolverError> {
    let request = http::Request::get(url)
        .body(Vec::new())
        .map_err(|error| ResolverError::CratesIo(format!("build request {url}: {error}")))?;
    let response = client
        .request(request)
        .await
        .map_err(|error| ResolverError::CratesIo(format!("fetch {url}: {error}")))?;
    let (parts, body) = response.into_parts();
    if !(200..300).contains(&parts.status.as_u16()) {
        return Err(ResolverError::CratesIo(format!(
            "{url} returned HTTP {}",
            parts.status
        )));
    }
    Ok(body)
}

/// Run one resolve against the shared workspace for one target.
async fn resolve_workspace(
    source: &SourceWorkspace,
    seed_features: &BTreeSet<String>,
    no_default_features: bool,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
) -> Result<api::StowResolveOutput, ResolverError> {
    let host_triple = runner_family(target.as_str())
        .ok_or_else(|| {
            ResolverError::BadRequest(format!("`{}` is not a CI target", target.as_str()))
        })?
        .host_triple()
        .to_string();
    let verbose = rustc_data::verbose_version(rustc_version.as_str()).ok_or_else(|| {
        ResolverError::BadRequest(format!(
            "no vendored rustc data for version `{rustc_version}`"
        ))
    })?;
    let mut cfg_keys = BTreeSet::from([host_triple.clone()]);
    cfg_keys.insert(target.as_str().to_owned());
    let cfg = rustc_data::cfg_map(rustc_version.as_str(), cfg_keys.iter().map(String::as_str))
        .map_err(|triple| {
            ResolverError::BadRequest(format!(
                "no vendored `rustc --print cfg` for `{triple}` at `{rustc_version}`"
            ))
        })?;

    // The ambient VFS is thread-local and resolves interleave on the
    // isolate's single thread — serialize the section that depends on it.
    let _permit = resolve_permit().await;
    set_vfs(source.vfs.clone());
    let mut gctx = GlobalContext::new_for_resolve(
        PathBuf::from(WORKSPACE_DIR),
        PathBuf::from("/cargo-home"),
        Shell::new(),
        Env::new(),
        false,
    )
    .map_err(|error| ResolverError::CratesIo(format!("resolver context: {error}")))?;
    gctx.set_http(Client::new(fetch_http()));
    api::resolve(
        &gctx,
        StowResolveInput {
            manifest_path: source.manifest_path.clone(),
            filter_platforms: vec![target.as_str().to_owned()],
            host_triple,
            features: seed_features.iter().cloned().collect(),
            all_features: false,
            no_default_features,
            rustc_verbose_version: verbose.to_owned(),
            cfg,
        },
    )
    .await
    .map_err(|error| ResolverError::CratesIo(format!("resolve failed: {error:#}")))
}

// One-flight-at-a-time gate for the ambient-VFS section: futures holding
// the permit are the only code that reads `fs::current()`, so at most
// one resolve per isolate may be in flight.
thread_local! {
    static PERMIT_HELD: Cell<bool> = const { Cell::new(false) };
    static PERMIT_QUEUE: RefCell<VecDeque<Waker>> = const { RefCell::new(VecDeque::new()) };
}

/// RAII guard for the ambient-VFS critical section.
struct ResolvePermit;

impl Drop for ResolvePermit {
    fn drop(&mut self) {
        PERMIT_HELD.with(|held| held.set(false));
        PERMIT_QUEUE.with(|queue| {
            if let Some(waker) = queue.borrow_mut().pop_front() {
                waker.wake();
            }
        });
    }
}

/// Wait for the ambient-VFS critical section.
fn resolve_permit() -> impl std::future::Future<Output = ResolvePermit> {
    std::future::poll_fn(|cx: &mut Context<'_>| {
        let free = PERMIT_HELD.with(|held| !held.get());
        if free {
            PERMIT_HELD.with(|held| held.set(true));
            Poll::Ready(ResolvePermit)
        } else {
            PERMIT_QUEUE.with(|queue| queue.borrow_mut().push_back(cx.waker().clone()));
            Poll::Pending
        }
    })
}

/// The production HTTP transport: `worker::Fetch`.
#[cfg(target_family = "wasm")]
struct WorkerFetchHttp;

#[cfg(target_family = "wasm")]
impl HttpClient for WorkerFetchHttp {
    fn request<'a>(
        &'a self,
        request: http::Request<Vec<u8>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = stow_resolve::util::errors::CargoResult<http::Response<Vec<u8>>>,
                > + 'a,
        >,
    > {
        use skyzen_cloudflare::worker::send::IntoSendFuture as _;
        use skyzen_cloudflare::{CfFetch, worker};
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let _ = body; // GET requests carry no payload.
            let headers = worker::Headers::new();
            for (name, value) in &parts.headers {
                headers
                    .set(
                        name.as_str(),
                        value.to_str().map_err(|error| {
                            anyhow::format_err!("invalid header value for `{name}`: {error}")
                        })?,
                    )
                    .map_err(|error| anyhow::format_err!("set header `{name}`: {error}"))?;
            }
            let mut init = worker::RequestInit::new();
            init.with_method(worker::Method::Get).with_headers(headers);
            let request = worker::Request::new_with_init(parts.uri.to_string().as_str(), &init)
                .map_err(|error| anyhow::format_err!("build fetch {}: {error}", parts.uri))?;
            let mut response = CfFetch
                .request(&request)
                .into_send()
                .await
                .map_err(|error| anyhow::format_err!("fetch {}: {error}", parts.uri))?;
            let status = http::StatusCode::from_u16(response.status_code())
                .unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
            let mut builder = http::Response::builder().status(status);
            for (name, value) in response.headers().entries() {
                builder = builder.header(name.as_str(), value.as_str());
            }
            let bytes = response
                .bytes()
                .into_send()
                .await
                .map_err(|error| anyhow::format_err!("read {}: {error}", parts.uri))?;
            builder
                .body(bytes)
                .map_err(|error| anyhow::format_err!("build response: {error}"))
        })
    }
}

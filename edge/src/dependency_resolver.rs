use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;

use fixedbitset::FixedBitSet;
use futures_util::stream::{self, StreamExt};
use semver::{Version, VersionReq};
use skyzen_services::Db;
use stow_types::api::{
    CrateRequestState, CrateRequestTarget, DependencyGraphEntry, EnqueueDependency, EnqueueRequest,
    EnqueueSource, QueueTaskStatus, ResolvedDependencyGraphEntry,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use stow_types::public_cache::stable_c_metadata_for_compile_key;

use crate::errors::ResolverError;
use crate::sql_batch;

const CACHE_TTL_SQL: &str = "-6 hours";
const MAX_EXPANDED_TASKS: usize = 4096;

/// The client-visible limit error every expanded-task cap reports:
/// handlers render it as a `413` naming the count and the cap rather than
/// a redacted 500.
const fn limit_exceeded(what: &'static str, got: usize) -> ResolverError {
    ResolverError::LimitExceeded {
        what,
        got,
        limit: MAX_EXPANDED_TASKS,
    }
}

/// Format tag stored inside every `crate_version_graph_cache.graph_json`
/// payload. Version 1 is the pre-tag shape — rows without this field (or
/// with a different value) are treated as misses and re-fetched, so a
/// stale-format row is never served.
const VERSION_GRAPH_FORMAT: u32 = 3;

/// Just the format tag of a cached `graph_json` row; rows written before
/// the tag existed have none.
#[derive(serde::Deserialize)]
struct VersionGraphTag {
    #[serde(default)]
    format_version: Option<u32>,
}

/// Network boundary for crates.io metadata lookups.
///
/// One lookup returns the crate's whole published release list: the
/// registry index ships every version's features, dependencies, and yanked
/// flag in a single per-crate file, so callers resolving several versions
/// of one crate never pay a second fetch. Production passes the
/// Cloudflare-fetch-backed client from [`crate::crates_io`]; host-side
/// tests can substitute a stub so every piece of resolver logic stays
/// testable off-wasm.
///
/// The `Send` bounds keep every resolver caller's future `Send`: `Sync` on
/// the trait makes `&impl CratesIo` sendable across awaits, and `Send` on
/// the returned futures does the same for the lookups themselves.
pub trait CratesIo: Sync {
    /// Every published release of `crate_name`, in registry order.
    /// [`ResolverError::CrateNotPublished`] when the crate does not exist.
    fn package_metadata(
        &self,
        crate_name: &str,
    ) -> impl Future<Output = Result<Vec<PublishedRelease>, ResolverError>> + Send;

    /// crates.io's own search, most relevant first, capped at `limit`
    /// results. Backs the request form's crate field.
    fn search(
        &self,
        query: &str,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<CratesIoSearchHit>, ResolverError>> + Send;
}

/// One published release of a crate, as the registry index reports it.
#[derive(Debug, Clone)]
pub struct PublishedRelease {
    /// The release's semver version.
    pub version: Version,
    /// Whether the release is yanked — yanked releases still resolve an
    /// exact pin but never satisfy a semver range.
    pub yanked: bool,
    /// Feature map (`feature -> enabled items`) the release declares.
    pub features: BTreeMap<String, Vec<String>>,
    /// Dependency list the release declares — the `optional` flags decide
    /// which implicit features exist.
    pub dependencies: Vec<CratesIoDependency>,
}

/// One crate from a crates.io search response, with version numbers left
/// unparsed the way crates.io lists them.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CratesIoSearchHit {
    /// Crate name.
    pub name: String,
    /// One-line description, when the crate has one.
    pub description: Option<String>,
    /// Newest non-prerelease version, absent for a crate that has only ever
    /// published prereleases.
    pub max_stable_version: Option<String>,
    /// Newest version of any kind.
    pub max_version: String,
    /// All-time downloads.
    pub downloads: u64,
}

/// The miss plan `POST /api/v1/admissions` mints tickets for: one
/// [`EnqueueRequest`] per graph node the artifact catalog does not cover.
pub struct ExpandedSchedulerPlan {
    /// Uncovered nodes, dominator-ordered.
    pub enqueue_requests: Vec<EnqueueRequest>,
}

/// Canonicalize a batch of enqueue requests, dropping the ones no canonical
/// task can exist for (a version crates.io does not publish, or a
/// `depends_on` that cannot resolve).
///
/// The work is batched at every stage: every crate named by a request or a
/// `depends_on` edge resolves its versions through one TTL-cache read per
/// `IN`-clause chunk, cold names fetch the index once per crate — the same
/// releases then serve the graph builds — and fresh cache rows write back
/// in multi-row upsert batches. A `max_expanded_tasks`-sized preheat costs
/// a handful of D1 statements plus one upstream fetch per cold crate,
/// instead of ~2+D sequential round trips per request.
pub async fn canonicalize_enqueue_requests(
    db: &Db,
    crates_io: &impl CratesIo,
    requests: Vec<EnqueueRequest>,
    fetch_concurrency: usize,
) -> Result<Vec<EnqueueRequest>, ResolverError> {
    let mut names = BTreeSet::<CrateName>::new();
    for request in &requests {
        names.insert(request.crate_name.clone());
        for dependency in &request.depends_on {
            names.insert(dependency.crate_name.clone());
        }
    }
    let (versions_by_name, mut releases_by_name) =
        load_canonical_versions(db, crates_io, &names, fetch_concurrency).await?;

    // Canonical versions resolve in memory: every name's published list is
    // already materialized, so each request and each `depends_on` edge is
    // one semver match against it.
    let resolve = |crate_name: &CrateName, requested: &Version| {
        let requirement = compatible_requirement(requested);
        let version_req = VersionReq::parse(&requirement).map_err(|error| {
            ResolverError::Invariant(format!(
                "parse dependency requirement {crate_name} {requirement}: {error}"
            ))
        })?;
        Ok::<Option<Version>, ResolverError>(
            versions_by_name
                .get(crate_name)
                .and_then(|versions| versions.iter().find(|version| version_req.matches(version)))
                .cloned(),
        )
    };
    let mut resolved =
        Vec::<(EnqueueRequest, Version, Vec<Version>)>::with_capacity(requests.len());
    for request in requests {
        let Some(canonical_version) = resolve(&request.crate_name, request.version.as_semver())?
        else {
            continue;
        };
        let mut dependency_versions = Vec::with_capacity(request.depends_on.len());
        let mut resolvable = true;
        for dependency in &request.depends_on {
            if let Some(version) = resolve(&dependency.crate_name, dependency.version.as_semver())?
            {
                dependency_versions.push(version);
            } else {
                resolvable = false;
                break;
            }
        }
        if resolvable {
            resolved.push((request, canonical_version, dependency_versions));
        }
    }

    // Root graphs resolve through the same batched cache path as the
    // catalog graph endpoint; the releases fetched for the versions phase
    // serve their graph builds too — no crate's index file is fetched
    // twice.
    let keys = resolved
        .iter()
        .map(|(request, canonical_version, _)| PackageKey {
            crate_name: request.crate_name.clone(),
            version: canonical_version.clone(),
        })
        .collect::<BTreeSet<_>>();
    let graphs = load_canonical_graphs(
        db,
        crates_io,
        &keys,
        &mut releases_by_name,
        fetch_concurrency,
    )
    .await?;

    let mut canonical = Vec::with_capacity(resolved.len());
    for (request, canonical_version, dependency_versions) in resolved {
        let key = PackageKey {
            crate_name: request.crate_name.clone(),
            version: canonical_version.clone(),
        };
        let graph = graphs.get(&key).ok_or_else(|| {
            ResolverError::Invariant(format!(
                "resolved version graph missing for {} {}",
                key.crate_name, key.version
            ))
        })?;
        let seed_features = normalize_feature_set(request.features_json.features().to_vec())?;
        let features_json =
            canonical_features_from_set(&resolve_local_features(graph, &seed_features))?;
        let mut depends_on = Vec::with_capacity(request.depends_on.len());
        for (dependency, version) in request.depends_on.iter().zip(dependency_versions) {
            let features = normalize_feature_set(dependency.features_json.features().to_vec())?;
            depends_on.push(EnqueueDependency {
                version: CrateVersion::new(version),
                features_json: canonical_features_from_set(&features)?,
                ..dependency.clone()
            });
        }
        canonical.push(EnqueueRequest {
            version: CrateVersion::new(canonical_version),
            features_json,
            depends_on,
            ..request
        });
    }
    Ok(canonical)
}

/// Versions phase of [`canonicalize_enqueue_requests`]: batched TTL-cache
/// reads for every name the requests touch, one index fetch per cold name,
/// batched write-backs. Returns the published versions per name — sorted
/// newest-first like [`parse_versions_json`] produces — plus the releases
/// memo that lets the graph phase reuse the same fetches.
async fn load_canonical_versions(
    db: &Db,
    crates_io: &impl CratesIo,
    names: &BTreeSet<CrateName>,
    fetch_concurrency: usize,
) -> Result<
    (
        BTreeMap<CrateName, Vec<Version>>,
        BTreeMap<CrateName, Vec<PublishedRelease>>,
    ),
    ResolverError,
> {
    let mut versions_by_name = load_versions_cache(db, names).await?;
    let cold_version_names = names
        .iter()
        .filter(|name| !versions_by_name.contains_key(*name))
        .cloned()
        .collect::<BTreeSet<_>>();
    let fetched = fetch_releases_by_name(crates_io, cold_version_names, fetch_concurrency).await?;
    let mut fresh_versions = Vec::<(CrateName, String)>::new();
    let mut releases_by_name = BTreeMap::new();
    for (name, releases) in fetched {
        let versions = releases
            .iter()
            .filter(|release| !release.yanked)
            .map(|release| release.version.to_string())
            .collect::<Vec<_>>();
        let versions_json = serde_json::to_string(&versions)
            .map_err(|error| format!("serialize versions cache {name}: {error}"))?;
        versions_by_name.insert(
            name.clone(),
            parse_versions_json(name.as_str(), &versions_json)?,
        );
        fresh_versions.push((name.clone(), versions_json));
        releases_by_name.insert(name, releases);
    }
    upsert_versions_cache(db, &fresh_versions).await;
    Ok((versions_by_name, releases_by_name))
}

/// Graph phase of [`canonicalize_enqueue_requests`]: pair-keyed TTL-cache
/// reads for the resolved `(crate_name, version)` keys, index fetches only
/// for names the versions phase did not already fetch, batched write-backs.
async fn load_canonical_graphs(
    db: &Db,
    crates_io: &impl CratesIo,
    keys: &BTreeSet<PackageKey>,
    releases_by_name: &mut BTreeMap<CrateName, Vec<PublishedRelease>>,
    fetch_concurrency: usize,
) -> Result<BTreeMap<PackageKey, VersionGraph>, ResolverError> {
    let mut graphs = load_version_graph_cache(db, keys).await?;
    let cold_graph_names = keys
        .iter()
        .filter(|key| !graphs.contains_key(*key) && !releases_by_name.contains_key(&key.crate_name))
        .map(|key| key.crate_name.clone())
        .collect::<BTreeSet<_>>();
    for (name, releases) in
        fetch_releases_by_name(crates_io, cold_graph_names, fetch_concurrency).await?
    {
        releases_by_name.insert(name, releases);
    }
    let cold_graph_keys = keys
        .iter()
        .filter(|key| !graphs.contains_key(*key))
        .cloned()
        .collect::<Vec<_>>();
    let mut fresh_graphs = Vec::<(PackageKey, String)>::new();
    for key in cold_graph_keys {
        let releases = releases_by_name.get(&key.crate_name).ok_or_else(|| {
            ResolverError::Invariant(format!("metadata batch skipped crate {}", key.crate_name))
        })?;
        let release = releases
            .iter()
            .find(|release| release.version == key.version)
            .ok_or_else(|| ResolverError::VersionNotPublished {
                crate_name: key.crate_name.as_str().to_owned(),
                version: key.version.to_string(),
            })?;
        let graph = VersionGraph {
            format_version: VERSION_GRAPH_FORMAT,
            features: release.features.clone(),
            dependencies: release.dependencies.clone(),
        };
        let graph_json = serde_json::to_string(&graph).map_err(|error| {
            format!(
                "serialize version graph {} {}: {error}",
                key.crate_name, key.version
            )
        })?;
        fresh_graphs.push((key.clone(), graph_json));
        graphs.insert(key.clone(), graph);
    }
    upsert_version_graphs(db, &fresh_graphs).await;
    Ok(graphs)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageKey {
    pub crate_name: CrateName,
    pub version: Version,
}

/// Cached per-version crates.io metadata (D1 `crate_version_graph_cache`).
///
/// `format_version` is the cache's schema tag: [`fetch_version_graph_cached`]
/// serves a row only when it parses *and* carries the current
/// [`VERSION_GRAPH_FORMAT`], so every payload field is required — nothing
/// defaults to a shape an older writer might not have produced.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct VersionGraph {
    format_version: u32,
    features: BTreeMap<String, Vec<String>>,
    dependencies: Vec<CratesIoDependency>,
}

/// One dependency entry from a crate version's crates.io dependency list.
/// Every field is required on the wire: cache rows predating a field are
/// rejected by the `format_version` check before they can be served, and
/// crates.io always reports each of these.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CratesIoDependency {
    /// The name this edge is declared under in the dependent's manifest.
    /// For a renamed dependency (`alias = { package = "real" }`) this is
    /// `alias`: the name every feature expression spells, and the implicit
    /// feature name when `optional` is set. Equal to [`Self::crate_id`]
    /// whenever the manifest did not rename the dependency.
    pub name: String,
    /// The crate this edge actually resolves to on crates.io — `real` for
    /// `alias = { package = "real" }`. This is what gets built; it is never
    /// what a feature expression names.
    pub crate_id: String,
    /// Whether the dependency is optional — cargo grants an implicit
    /// feature named after [`Self::name`] unless a declared feature
    /// references it through `dep:<name>`.
    pub optional: bool,
    /// Semver requirement string (`"^1.0"`, `"*"`, ...).
    pub req: String,
    /// Dependency kind. Dev dependencies are never part of a closure built
    /// for a library consumer.
    pub kind: CratesIoDependencyKind,
    /// Features this edge explicitly enables on the dependency.
    pub features: Vec<String>,
    /// Whether this edge enables the dependency's `default` feature.
    pub default_features: bool,
    /// Platform restriction — a `cfg(...)` expression or a bare target
    /// triple — or `None` when the edge applies on every target.
    pub target: Option<String>,
}

impl Default for CratesIoDependency {
    fn default() -> Self {
        Self {
            name: String::new(),
            crate_id: String::new(),
            optional: false,
            req: any_version_req(),
            kind: CratesIoDependencyKind::Normal,
            features: Vec::new(),
            default_features: true,
            target: None,
        }
    }
}

fn any_version_req() -> String {
    "*".to_owned()
}

/// Cargo dependency kind as reported by crates.io metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CratesIoDependencyKind {
    /// A `[dependencies]` edge — part of the built closure.
    #[default]
    Normal,
    /// A `[dev-dependencies]` edge — never compiled for a dependency build.
    Dev,
    /// A `[build-dependencies]` edge — compiled for the build script.
    Build,
}

#[derive(Debug, skyzen::FromRow)]
struct CachedArtifactRow {
    compile_key: String,
    crate_name: String,
    version: String,
    features_json: String,
    c_metadata: String,
    dependency_c_metadata_json: String,
}

/// Decode a stored canonical features-json string into the structured wire type.
fn parse_canonical_features_json(raw: &str) -> Result<FeaturesJson, ResolverError> {
    let parsed: Vec<String> = serde_json::from_str(raw)
        .map_err(|error| ResolverError::Json(format!("parse features_json `{raw}`: {error}")))?;
    FeaturesJson::from_sorted(parsed).map_err(ResolverError::Identity)
}

pub async fn expand_scheduler_requests(
    db: &Db,
    target: &str,
    rustc_version: &str,
    roots: &[DependencyGraphEntry],
    expanded_entries: &[ResolvedDependencyGraphEntry],
) -> Result<ExpandedSchedulerPlan, ResolverError> {
    let target_typed = TargetTriple::parse(target).map_err(|error| error.to_string())?;
    let rustc_version_typed =
        WireRustcVersion::parse(rustc_version).map_err(|error| error.to_string())?;
    let exact_graph = exact_graph_from_request(roots, expanded_entries)?;
    let semantic_keys =
        load_cached_artifacts(db, target, rustc_version, &exact_graph.feature_json_by_key).await?;

    let requests = build_enqueue_requests(
        &exact_graph.feature_json_by_key,
        &exact_graph.dependency_keys_by_key,
        &semantic_keys,
        &BTreeSet::new(),
        &target_typed,
        &rustc_version_typed,
        EnqueueSource::CacheMiss,
    )?;
    Ok(ExpandedSchedulerPlan {
        enqueue_requests: requests,
    })
}

/// Turn an exact graph (`feature_json_by_key` + `dependency_keys_by_key`)
/// into one [`EnqueueRequest`] per node the cache does not already cover.
/// `source` decides the scheduler lane the tasks land in: the miss path
/// passes [`EnqueueSource::CacheMiss`], the human request API passes
/// [`EnqueueSource::HumanRequest`].
///
/// A trusted build publishes every library crate in the task's closure,
/// so an uncovered node that lies inside another uncovered node's closure
/// is *dominated*: its dominator's build produces its artifact too. The
/// queue edges therefore run from a dominated node to its immediate
/// dominator (the uncovered node with the smallest closure containing it),
/// which makes the dominators dispatch first and holds the dominated tasks
/// back until each dominator completes or fails. When the dominator
/// succeeds, the scheduler's claim-time coverage check retires the
/// dominated task without a build; when it fails, the dominated task
/// builds on its own exactly as before — the old leaf-first behaviour is
/// the failure path, not the default.
fn build_enqueue_requests(
    feature_json_by_key: &BTreeMap<PackageKey, String>,
    dependency_keys_by_key: &BTreeMap<PackageKey, BTreeSet<PackageKey>>,
    cached_semantic_keys: &BTreeSet<(PackageKey, String)>,
    no_library: &BTreeSet<PackageKey>,
    target_typed: &TargetTriple,
    rustc_version_typed: &WireRustcVersion,
    source: EnqueueSource,
) -> Result<Vec<EnqueueRequest>, ResolverError> {
    let dominators = immediate_dominators(
        feature_json_by_key,
        dependency_keys_by_key,
        cached_semantic_keys,
        no_library,
    )?;
    let mut requests = Vec::<EnqueueRequest>::new();
    for node_key in dependency_keys_by_key.keys() {
        let features_json = feature_json_by_key.get(node_key).cloned().ok_or_else(|| {
            format!(
                "missing serialized feature set for {} {}",
                node_key.crate_name, node_key.version
            )
        })?;
        if cached_semantic_keys.contains(&(node_key.clone(), features_json.clone()))
            || no_library.contains(node_key)
        {
            continue;
        }
        let depends_on = dominators
            .get(node_key)
            .map(|dominator| {
                let raw = feature_json_by_key.get(dominator).ok_or_else(|| {
                    ResolverError::from(format!(
                        "missing serialized feature set for dominator {} {}",
                        dominator.crate_name, dominator.version
                    ))
                })?;
                let dominator_features_json = parse_canonical_features_json(raw)?;
                Ok::<_, ResolverError>(EnqueueDependency {
                    crate_name: dominator.crate_name.clone(),
                    version: CrateVersion::new(dominator.version.clone()),
                    features_json: dominator_features_json,
                    target: target_typed.clone(),
                    rustc_version: rustc_version_typed.clone(),
                })
            })
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();
        let features_json_typed = parse_canonical_features_json(features_json.as_str())?;
        requests.push(EnqueueRequest {
            crate_name: node_key.crate_name.clone(),
            version: CrateVersion::new(node_key.version.clone()),
            features_json: features_json_typed,
            target: target_typed.clone(),
            rustc_version: rustc_version_typed.clone(),
            downloads: 0,
            source,
            depends_on,
            preserve_lockfile: false,
        });
    }
    Ok(requests)
}

/// For every uncovered node that lies in the transitive closure of another
/// uncovered node, the uncovered node with the smallest closure that
/// contains it; ties break on key order. Nodes no other uncovered node
/// reaches — the roots of the wave — are absent from the map.
///
/// Closures are computed over the whole exact graph, covered nodes
/// included: a covered intermediate does not stop its dominator's build
/// from producing everything beneath it. Cargo graphs are acyclic for the
/// normal and build edges the exact graph carries, but the fixpoint below
/// does not rely on it.
fn immediate_dominators(
    feature_json_by_key: &BTreeMap<PackageKey, String>,
    dependency_keys_by_key: &BTreeMap<PackageKey, BTreeSet<PackageKey>>,
    cached_semantic_keys: &BTreeSet<(PackageKey, String)>,
    no_library: &BTreeSet<PackageKey>,
) -> Result<BTreeMap<PackageKey, PackageKey>, ResolverError> {
    let keys = dependency_keys_by_key.keys().collect::<Vec<_>>();
    let index_of = keys
        .iter()
        .enumerate()
        .map(|(index, key)| ((*key).clone(), index))
        .collect::<BTreeMap<_, _>>();
    let direct = keys
        .iter()
        .map(|key| {
            let mut bits = FixedBitSet::with_capacity(keys.len());
            for dependency in &dependency_keys_by_key[*key] {
                // A dependency the exact graph did not expand is outside
                // the closure the resolver plans for; it cannot be built
                // by anyone in this wave, so it takes no part in dominance.
                if let Some(&dependency_index) = index_of.get(dependency) {
                    bits.insert(dependency_index);
                }
            }
            bits
        })
        .collect::<Vec<_>>();
    let mut closure = direct;
    let mut changed = true;
    while changed {
        changed = false;
        for node in 0..keys.len() {
            let before = closure[node].count_ones(..);
            let reachable = closure[node].ones().collect::<Vec<_>>();
            for dependency in reachable {
                let dependency_closure = closure[dependency].clone();
                closure[node].union_with(&dependency_closure);
            }
            if closure[node].count_ones(..) != before {
                changed = true;
            }
        }
    }
    let uncovered = keys
        .iter()
        .map(|key| {
            let features_json = feature_json_by_key.get(*key).ok_or_else(|| {
                format!(
                    "missing serialized feature set for {} {}",
                    key.crate_name, key.version
                )
            })?;
            Ok(
                !cached_semantic_keys.contains(&((*key).clone(), features_json.clone()))
                    && !no_library.contains(*key),
            )
        })
        .collect::<Result<Vec<bool>, ResolverError>>()?;
    let mut dominators = BTreeMap::new();
    for (node, key) in keys.iter().enumerate() {
        if !uncovered[node] {
            continue;
        }
        let immediate = (0..keys.len())
            .filter(|&candidate| {
                candidate != node && uncovered[candidate] && closure[candidate].contains(node)
            })
            .min_by_key(|&candidate| (closure[candidate].count_ones(..), candidate));
        if let Some(dominator) = immediate {
            dominators.insert((*key).clone(), keys[dominator].clone());
        }
    }
    Ok(dominators)
}

/// Newest non-prerelease, non-yanked published version of `crate_name`, or
/// `None` when the crate has no stable release. `*` never matches
/// prereleases and `published_version_nums` already drops yanked releases.
pub async fn latest_published_version(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
) -> Result<Option<Version>, ResolverError> {
    resolve_dependency_version(db, crates_io, crate_name, "*").await
}

/// `Some(version)` when `crate_name@version` is published and not yanked.
pub async fn published_version(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
    version: &Version,
) -> Result<Option<Version>, ResolverError> {
    resolve_dependency_version(db, crates_io, crate_name, &format!("={version}")).await
}

/// Assemble the per-target outcome of a crate request from the artifact
/// hit flag and the root task's scheduler state after enqueueing.
///
/// `was_queued` records whether the task already had a queue row when the
/// request arrived — that is what distinguishes `Queued` from
/// `AlreadyQueued`. `status` is the post-enqueue [`RequestStatus`]; it must
/// exist whenever `root_cached` is false (the submit just wrote the row).
///
/// # Errors
/// [`ResolverError::Invariant`] when a non-cached root has no queue row.
pub fn crate_request_target(
    target: &TargetTriple,
    root_task_id: &str,
    root_cached: bool,
    root_has_library: bool,
    was_queued: bool,
    status: Option<&stow_types::api::RequestStatus>,
) -> Result<CrateRequestTarget, ResolverError> {
    if !root_has_library {
        return Ok(CrateRequestTarget {
            target: target.clone(),
            state: CrateRequestState::ClosureQueued,
            task_id: None,
            human_lane_position: None,
        });
    }
    if root_cached {
        return Ok(CrateRequestTarget {
            target: target.clone(),
            state: CrateRequestState::Cached,
            task_id: None,
            human_lane_position: None,
        });
    }
    let status = status.ok_or_else(|| {
        ResolverError::Invariant(format!(
            "task {root_task_id} has no queue row after human-lane enqueue"
        ))
    })?;
    let state = match status.status {
        // A row the submit just resurrected out of `failed` or `partial`
        // is queued work again — only the pre-existing-row flag separates
        // the two queued reports. `blocked` is still queued work: the
        // dependency it waits on is what's failed, not the request.
        QueueTaskStatus::Pending
        | QueueTaskStatus::Blocked
        | QueueTaskStatus::Failed
        | QueueTaskStatus::Partial => {
            if was_queued {
                CrateRequestState::AlreadyQueued
            } else {
                CrateRequestState::Queued
            }
        }
        QueueTaskStatus::Dispatched | QueueTaskStatus::Running => CrateRequestState::Building,
        QueueTaskStatus::Completed => CrateRequestState::Cached,
    };
    Ok(CrateRequestTarget {
        target: target.clone(),
        state,
        task_id: Some(root_task_id.to_owned()),
        human_lane_position: status.human_lane_position,
    })
}

struct ExactExpandedGraph {
    feature_json_by_key: BTreeMap<PackageKey, String>,
    dependency_keys_by_key: BTreeMap<PackageKey, BTreeSet<PackageKey>>,
}

fn exact_graph_from_request(
    roots: &[DependencyGraphEntry],
    expanded_entries: &[ResolvedDependencyGraphEntry],
) -> Result<ExactExpandedGraph, ResolverError> {
    if expanded_entries.is_empty() {
        return Err(ResolverError::Invariant(
            "dependency graph request is missing expanded_entries".to_owned(),
        ));
    }
    if expanded_entries.len() > MAX_EXPANDED_TASKS {
        return Err(limit_exceeded(
            "expanded dependency graph entries",
            expanded_entries.len(),
        ));
    }

    let mut feature_json_by_key = BTreeMap::<PackageKey, String>::new();
    let mut dependency_keys_by_key = BTreeMap::<PackageKey, BTreeSet<PackageKey>>::new();

    for entry in expanded_entries {
        let key = PackageKey {
            crate_name: entry.crate_name.clone(),
            version: entry.version.clone(),
        };
        let features = normalize_feature_set(entry.features.clone())?;
        let features_json = serialize_feature_set(&features)?;
        if feature_json_by_key
            .insert(key.clone(), features_json)
            .is_some()
        {
            return Err(ResolverError::Invariant(format!(
                "duplicate expanded dependency graph entry for {} {}",
                key.crate_name, key.version
            )));
        }
        let dependency_keys = entry
            .dependencies
            .iter()
            .map(|dependency| PackageKey {
                crate_name: dependency.crate_name.clone(),
                version: dependency.version.clone(),
            })
            .collect::<BTreeSet<_>>();
        dependency_keys_by_key.insert(key.clone(), dependency_keys);
    }

    for (package_key, dependency_keys) in &dependency_keys_by_key {
        for dependency_key in dependency_keys {
            if feature_json_by_key.contains_key(dependency_key) {
                continue;
            }
            return Err(ResolverError::Invariant(format!(
                "expanded dependency graph is missing {} {} required by {} {}",
                dependency_key.crate_name,
                dependency_key.version,
                package_key.crate_name,
                package_key.version
            )));
        }
    }

    for root in roots {
        let root_key = PackageKey {
            crate_name: root.crate_name.clone(),
            version: root.version.clone(),
        };
        if !feature_json_by_key.contains_key(&root_key) {
            return Err(ResolverError::Invariant(format!(
                "expanded dependency graph is missing root {} {}",
                root_key.crate_name, root_key.version
            )));
        }
    }

    Ok(ExactExpandedGraph {
        feature_json_by_key,
        dependency_keys_by_key,
    })
}

async fn load_cached_artifacts(
    db: &Db,
    target: &str,
    rustc_version: &str,
    feature_json_by_key: &BTreeMap<PackageKey, String>,
) -> Result<BTreeSet<(PackageKey, String)>, ResolverError> {
    let key_pairs = feature_json_by_key
        .iter()
        .map(|(key, features_json)| (key.clone(), features_json.clone()))
        .collect::<BTreeSet<_>>();
    load_cached_artifacts_for_keys(db, target, rustc_version, &key_pairs).await
}

/// [`load_cached_artifacts`] over a set of `(key, features)` pairs —
/// `stow-resolve`'s node space keys coverage the same way but can carry
/// two feature sets for one `(name, version)` on a platform, which a map
/// cannot express.
pub async fn load_cached_artifacts_for_keys(
    db: &Db,
    target: &str,
    rustc_version: &str,
    key_pairs: &BTreeSet<(PackageKey, String)>,
) -> Result<BTreeSet<(PackageKey, String)>, ResolverError> {
    if key_pairs.is_empty() {
        return Ok(BTreeSet::new());
    }

    let crate_names = key_pairs
        .iter()
        .map(|(key, _)| key.crate_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut cached_rows = Vec::<CachedArtifactRow>::new();
    for batch in crate_names.chunks(sql_batch::SQLITE_IN_CLAUSE_BATCH_SIZE) {
        let sql = format!(
            "SELECT compile_key, crate_name, version, features_json, c_metadata, dependency_c_metadata_json \
             FROM artifacts \
             WHERE target = ? AND rustc_version = ? AND crate_name IN ({})",
            sql_batch::placeholders(batch.len())
        );
        let mut query = db.query(&sql).bind(target).bind(rustc_version);
        for crate_name in batch {
            query = query.bind(crate_name.as_str());
        }
        let mut rows = query
            .fetch_all::<CachedArtifactRow>()
            .await
            .map_err(|error| format!("load cached semantic keys: {error}"))?;
        cached_rows.append(&mut rows);
    }

    // Complete the chain universe: candidate rows reference dependency
    // artifacts by (crate_name, c_metadata) that may not semantically match
    // this request's graph (they came from another preheat's feature
    // unification) yet are perfectly fetchable — the CLI resolves closure
    // dependencies by identity, not by this request's semantic keys. Pull
    // every referenced-but-unloaded canonical row so reachability reflects
    // "closed within D1", not "closed within this request's candidates".
    let cached_rows = complete_chain_rows(db, target, rustc_version, cached_rows).await?;

    let candidates = resolve_reachable_cached_rows(key_pairs, cached_rows)?;
    Ok(candidates
        .iter()
        .map(|candidate| candidate.semantic_key.clone())
        .collect::<BTreeSet<_>>())
}

fn resolve_reachable_cached_rows(
    key_pairs: &BTreeSet<(PackageKey, String)>,
    rows: Vec<CachedArtifactRow>,
) -> Result<Vec<ReachableCandidateRow>, ResolverError> {
    let IndexedRows {
        candidates,
        candidate_index,
        chain_rows,
        chain_index,
    } = partition_cached_rows(key_pairs, rows)?;

    // Reachability fixpoint over the union of candidates and chain rows:
    // a node is reachable when every dependency identity it references is a
    // reachable node. Nodes are addressed as (is_chain, index).
    let mut reachable_candidates = BTreeSet::<usize>::new();
    let mut reachable_chain = BTreeSet::<usize>::new();
    let mut progressed = true;
    while progressed {
        progressed = false;
        let reach_check = |identity: &DependencyIdentity,
                           reachable_candidates: &BTreeSet<usize>,
                           reachable_chain: &BTreeSet<usize>| {
            let key = (
                canonical_crate_name(&identity.crate_name),
                identity.c_metadata.clone(),
            );
            candidate_index
                .get(&key)
                .is_some_and(|index| reachable_candidates.contains(index))
                || chain_index
                    .get(&key)
                    .is_some_and(|index| reachable_chain.contains(index))
        };
        for (index, candidate) in candidates.iter().enumerate() {
            if reachable_candidates.contains(&index) {
                continue;
            }
            if candidate
                .dependency_identities
                .iter()
                .all(|identity| reach_check(identity, &reachable_candidates, &reachable_chain))
            {
                reachable_candidates.insert(index);
                progressed = true;
            }
        }
        for (index, chain_row) in chain_rows.iter().enumerate() {
            if reachable_chain.contains(&index) {
                continue;
            }
            if chain_row
                .dependency_identities
                .iter()
                .all(|identity| reach_check(identity, &reachable_candidates, &reachable_chain))
            {
                reachable_chain.insert(index);
                progressed = true;
            }
        }
    }

    Ok(candidates
        .into_iter()
        .enumerate()
        .filter(|(index, _)| reachable_candidates.contains(index))
        .map(|(_, candidate)| candidate)
        .collect())
}

/// Partition cached rows by request match: rows whose (package, features)
/// pair is in `key_pairs` become candidates; every other canonical row is a
/// chain row another candidate's closure may reference. Rows failing the
/// canonical-metadata check are dropped.
fn partition_cached_rows(
    key_pairs: &BTreeSet<(PackageKey, String)>,
    rows: Vec<CachedArtifactRow>,
) -> Result<IndexedRows, ResolverError> {
    let mut candidates = Vec::<ReachableCandidateRow>::new();
    let mut candidate_index = BTreeMap::<(String, String), usize>::new();
    let mut chain_rows = Vec::<ChainRow>::new();
    let mut chain_index = BTreeMap::<(String, String), usize>::new();

    for row in rows {
        if !cached_row_has_canonical_metadata(&row)? {
            continue;
        }
        let dependency_identities =
            serde_json::from_str::<Vec<DependencyIdentity>>(&row.dependency_c_metadata_json)
                .map_err(|error| {
                    format!(
                        "parse cached dependency_c_metadata_json for {} {} {}: {error}",
                        row.crate_name, row.version, row.c_metadata
                    )
                })?;
        let dependency_identities = canonicalize_dependency_identities(dependency_identities);
        let identity_key = (
            canonical_crate_name(&row.crate_name),
            row.c_metadata.clone(),
        );

        let version = Version::parse(&row.version)
            .map_err(|error| format!("parse cached semver {}: {error}", row.version))?;
        let package_key = PackageKey {
            crate_name: CrateName::parse(row.crate_name.as_str())
                .map_err(|error| format!("cached crate_name `{}`: {error}", row.crate_name))?,
            version,
        };
        let semantic_key = (package_key, row.features_json.clone());
        if key_pairs.contains(&semantic_key) {
            if let Some(existing_index) = candidate_index.get(&identity_key).copied() {
                if !deduplicate_cached_candidate(
                    &candidates[existing_index],
                    &semantic_key,
                    &row,
                    &dependency_identities,
                ) {
                    return Err(ResolverError::Invariant(format!(
                        "conflicting cached artifact identity {} {}",
                        identity_key.0, identity_key.1
                    )));
                }
                continue;
            }
            candidate_index.insert(identity_key, candidates.len());
            candidates.push(ReachableCandidateRow {
                semantic_key,
                row,
                dependency_identities,
            });
            continue;
        }

        // Not a semantic match for this request, but still a canonical
        // artifact another candidate's closure may reference.
        if chain_index.contains_key(&identity_key) || candidate_index.contains_key(&identity_key) {
            continue;
        }
        chain_index.insert(identity_key, chain_rows.len());
        chain_rows.push(ChainRow {
            dependency_identities,
        });
    }

    Ok(IndexedRows {
        candidates,
        candidate_index,
        chain_rows,
        chain_index,
    })
}

/// Iteratively load canonical rows referenced by already-loaded rows'
/// dependency chains until the set is closed under chain references.
async fn complete_chain_rows(
    db: &Db,
    target: &str,
    rustc_version: &str,
    mut rows: Vec<CachedArtifactRow>,
) -> Result<Vec<CachedArtifactRow>, ResolverError> {
    // Chains form a DAG over build outputs, so depth is bounded by the
    // dependency graph's height; the cap only guards corrupted data.
    const MAX_CHAIN_DEPTH: usize = 64;

    let mut seen = rows
        .iter()
        .map(|row| row.c_metadata.clone())
        .collect::<BTreeSet<_>>();
    let mut frontier: Vec<usize> = (0..rows.len()).collect();
    for _ in 0..MAX_CHAIN_DEPTH {
        let mut wanted = BTreeSet::<String>::new();
        for index in std::mem::take(&mut frontier) {
            let identities = serde_json::from_str::<Vec<DependencyIdentity>>(
                &rows[index].dependency_c_metadata_json,
            )
            .map_err(|error| {
                format!(
                    "parse cached dependency_c_metadata_json for {} {} {}: {error}",
                    rows[index].crate_name, rows[index].version, rows[index].c_metadata
                )
            })?;
            for identity in identities {
                if !seen.contains(&identity.c_metadata) {
                    wanted.insert(identity.c_metadata);
                }
            }
        }
        if wanted.is_empty() {
            return Ok(rows);
        }
        let wanted = wanted.into_iter().collect::<Vec<_>>();
        for batch in wanted.chunks(sql_batch::SQLITE_IN_CLAUSE_BATCH_SIZE) {
            let sql = format!(
                "SELECT compile_key, crate_name, version, features_json, c_metadata, dependency_c_metadata_json \
                 FROM artifacts \
                 WHERE target = ? AND rustc_version = ? AND c_metadata IN ({})",
                sql_batch::placeholders(batch.len())
            );
            let mut query = db.query(&sql).bind(target).bind(rustc_version);
            for c_metadata in batch {
                query = query.bind(c_metadata.as_str());
            }
            let fetched = query
                .fetch_all::<CachedArtifactRow>()
                .await
                .map_err(|error| format!("load chain-referenced cached rows: {error}"))?;
            for row in fetched {
                if seen.insert(row.c_metadata.clone()) {
                    frontier.push(rows.len());
                    rows.push(row);
                }
            }
        }
        // Referenced rows that do not exist in D1 stay absent; their
        // dependents are simply unreachable. Stop looking them up again.
        for c_metadata in &wanted {
            seen.insert(c_metadata.clone());
        }
        if frontier.is_empty() {
            return Ok(rows);
        }
    }
    Err(ResolverError::Invariant(
        "dependency chain completion exceeded the maximum depth — cyclic or corrupted chain data"
            .to_owned(),
    ))
}

fn cached_row_has_canonical_metadata(row: &CachedArtifactRow) -> Result<bool, ResolverError> {
    let stable_c_metadata =
        stable_c_metadata_for_compile_key(&row.compile_key).map_err(|error| {
            format!(
                "compute stable c_metadata for {} {} {}: {error}",
                row.crate_name, row.version, row.compile_key
            )
        })?;
    Ok(stable_c_metadata == row.c_metadata)
}

fn canonicalize_dependency_identities(
    mut dependency_identities: Vec<DependencyIdentity>,
) -> Vec<DependencyIdentity> {
    dependency_identities.sort_by(|left, right| {
        canonical_crate_name(&left.crate_name)
            .cmp(&canonical_crate_name(&right.crate_name))
            .then(left.c_metadata.cmp(&right.c_metadata))
    });
    dependency_identities
}

fn deduplicate_cached_candidate(
    existing: &ReachableCandidateRow,
    semantic_key: &SemanticKey,
    row: &CachedArtifactRow,
    dependency_identities: &[DependencyIdentity],
) -> bool {
    if existing.semantic_key != *semantic_key
        || existing.dependency_identities != dependency_identities
    {
        return false;
    }
    if row.c_metadata != existing.row.c_metadata {
        return false;
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
struct DependencyIdentity {
    crate_name: String,
    c_metadata: String,
}

#[derive(Debug)]
struct ReachableCandidateRow {
    semantic_key: (PackageKey, String),
    row: CachedArtifactRow,
    dependency_identities: Vec<DependencyIdentity>,
}

/// A canonical row that is not a semantic match for the current request but
/// participates in candidates' dependency closures.
#[derive(Debug)]
struct ChainRow {
    dependency_identities: Vec<DependencyIdentity>,
}

/// Cached rows partitioned by request match — semantic candidates and
/// chain-only rows, each indexed by (canonical crate name, `c_metadata`).
#[derive(Debug)]
struct IndexedRows {
    candidates: Vec<ReachableCandidateRow>,
    candidate_index: BTreeMap<(String, String), usize>,
    chain_rows: Vec<ChainRow>,
    chain_index: BTreeMap<(String, String), usize>,
}

/// Semantic identity `(package, features_json)` a reachability candidate is
/// keyed on.
type SemanticKey = (PackageKey, String);

fn canonical_crate_name(crate_name: impl AsRef<str>) -> String {
    crate_name.as_ref().replace('-', "_")
}

async fn fetch_version_graph_cached(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
    version: &Version,
) -> Result<VersionGraph, ResolverError> {
    let cached_graph_json = db
        .query(
            "SELECT graph_json \
             FROM crate_version_graph_cache \
             WHERE crate_name = ? AND version = ? AND fetched_at >= datetime('now', ?)",
        )
        .bind(crate_name)
        .bind(version.to_string())
        .bind(CACHE_TTL_SQL)
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| {
            format!("load crate_version_graph_cache {crate_name} {version}: {error}")
        })?;
    if let Some(graph_json) = cached_graph_json {
        // The format tag decides whether the row is this payload shape at
        // all; only a current-format row is parsed, and a current-format
        // row that fails to parse is corruption, not a miss.
        let tag: VersionGraphTag = serde_json::from_str(&graph_json).map_err(|error| {
            ResolverError::Json(format!(
                "read cached version graph tag {crate_name} {version}: {error}"
            ))
        })?;
        if tag.format_version == Some(VERSION_GRAPH_FORMAT) {
            return serde_json::from_str(&graph_json).map_err(|error| {
                ResolverError::Json(format!(
                    "parse cached version graph {crate_name} {version}: {error}"
                ))
            });
        }
        tracing::debug!(
            crate_name,
            %version,
            cached_format = ?tag.format_version,
            current_format = VERSION_GRAPH_FORMAT,
            "refetching version graph cached in an older payload format"
        );
    }

    let graph = version_graph_for(crates_io, crate_name, version).await?;
    let graph_json = serde_json::to_string(&graph)
        .map_err(|error| format!("serialize version graph {crate_name} {version}: {error}"))?;
    // A rejected upsert costs only the cache write; the fetched graph is
    // still the right answer, and turning a degraded cache into a 500 was
    // the production outage this row failed to prevent.
    if let Err(error) = db
        .query(
            "INSERT INTO crate_version_graph_cache (crate_name, version, graph_json, fetched_at) \
             VALUES (?, ?, ?, datetime('now')) \
             ON CONFLICT(crate_name, version) DO UPDATE SET graph_json = excluded.graph_json, fetched_at = excluded.fetched_at",
        )
        .bind(crate_name)
        .bind(version.to_string())
        .bind(graph_json)
        .execute()
        .await
    {
        tracing::error!(
            crate_name,
            %version,
            %error,
            "version graph cache upsert failed; serving uncached graph"
        );
    }
    Ok(graph)
}

/// The [`VersionGraph`] for one published release, from the crate's
/// registry metadata: [`ResolverError::CrateNotPublished`] when the index
/// does not list the crate, [`ResolverError::VersionNotPublished`] when it
/// lists no such release.
async fn version_graph_for(
    crates_io: &impl CratesIo,
    crate_name: &str,
    version: &Version,
) -> Result<VersionGraph, ResolverError> {
    let releases = crates_io.package_metadata(crate_name).await?;
    let release = releases
        .iter()
        .find(|release| &release.version == version)
        .ok_or_else(|| ResolverError::VersionNotPublished {
            crate_name: crate_name.to_owned(),
            version: version.to_string(),
        })?;
    Ok(VersionGraph {
        format_version: VERSION_GRAPH_FORMAT,
        features: release.features.clone(),
        dependencies: release.dependencies.clone(),
    })
}

/// Resolve `requirement` against crates.io's published versions, returning
/// `None` when nothing matches — a request whose version does not exist
/// upstream has no canonical task to mint.
async fn resolve_dependency_version(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
    requirement: &str,
) -> Result<Option<Version>, ResolverError> {
    let version_req = VersionReq::parse(requirement).map_err(|error| {
        ResolverError::Invariant(format!(
            "parse dependency requirement {crate_name} {requirement}: {error}"
        ))
    })?;
    let versions = fetch_versions_cached(db, crates_io, crate_name).await?;
    Ok(versions
        .into_iter()
        .find(|version| version_req.matches(version)))
}

async fn fetch_versions_cached(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
) -> Result<Vec<Version>, ResolverError> {
    let cached_versions_json = db
        .query(
            "SELECT versions_json \
             FROM crate_versions_cache \
             WHERE crate_name = ? AND fetched_at >= datetime('now', ?)",
        )
        .bind(crate_name)
        .bind(CACHE_TTL_SQL)
        .fetch_scalar_optional::<String>()
        .await
        .map_err(|error| format!("load crate_versions_cache {crate_name}: {error}"))?;
    if let Some(versions_json) = cached_versions_json {
        return parse_versions_json(crate_name, &versions_json);
    }

    let versions = crates_io
        .package_metadata(crate_name)
        .await?
        .iter()
        .filter(|release| !release.yanked)
        .map(|release| release.version.to_string())
        .collect::<Vec<_>>();
    let versions_json = serde_json::to_string(&versions)
        .map_err(|error| format!("serialize versions cache {crate_name}: {error}"))?;
    // Same contract as the graph cache above: a rejected cache write
    // degrades latency, not correctness, so it must not fail the request.
    if let Err(error) = db
        .query(
            "INSERT INTO crate_versions_cache (crate_name, versions_json, fetched_at) \
             VALUES (?, ?, datetime('now')) \
             ON CONFLICT(crate_name) DO UPDATE SET versions_json = excluded.versions_json, fetched_at = excluded.fetched_at",
        )
        .bind(crate_name)
        .bind(versions_json.clone())
        .execute()
        .await
    {
        tracing::error!(
            crate_name,
            %error,
            "versions cache upsert failed; serving uncached versions"
        );
    }
    parse_versions_json(crate_name, &versions_json)
}

/// Published, non-yanked versions of `crate_name`, newest first, served
/// from the same TTL-bounded D1 cache the resolver uses.
pub async fn published_versions(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
) -> Result<Vec<Version>, ResolverError> {
    fetch_versions_cached(db, crates_io, crate_name).await
}

/// One published version's `[features]` table and dependency list — what a
/// caller needs to know which features it may select.
pub struct VersionFeatureGraph {
    /// Declared `[features]` table, feature name to the items it enables.
    pub features: BTreeMap<String, Vec<String>>,
    /// Declared dependencies; the optional ones carry implicit features.
    pub dependencies: Vec<CratesIoDependency>,
}

/// Fetch [`VersionFeatureGraph`] through the resolver's TTL-bounded D1
/// cache, so a catalog lookup and a graph expansion of the same version
/// share one crates.io round trip.
pub async fn version_feature_graph(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
    version: &Version,
) -> Result<VersionFeatureGraph, ResolverError> {
    let graph = fetch_version_graph_cached(db, crates_io, crate_name, version).await?;
    Ok(VersionFeatureGraph {
        features: graph.features,
        dependencies: graph.dependencies,
    })
}

fn parse_versions_json(
    crate_name: &str,
    versions_json: &str,
) -> Result<Vec<Version>, ResolverError> {
    let mut versions = serde_json::from_str::<Vec<String>>(versions_json)
        .map_err(|error| format!("parse versions_json for {crate_name}: {error}"))?
        .into_iter()
        .map(|version| {
            Version::parse(&version)
                .map_err(|error| format!("parse cached semver {crate_name} {version}: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    versions.sort_by(|left, right| right.cmp(left));
    Ok(versions)
}

/// Fetch `package_metadata` for each crate in `names` with at most
/// `fetch_concurrency` index requests in flight. One fetch returns every
/// published release of a crate, so callers deduplicate the cold set by
/// crate name — never by `(name, version)` pair — and the returned map
/// serves both version resolution and graph construction without a
/// second round trip.
async fn fetch_releases_by_name(
    crates_io: &impl CratesIo,
    names: BTreeSet<CrateName>,
    fetch_concurrency: usize,
) -> Result<BTreeMap<CrateName, Vec<PublishedRelease>>, ResolverError> {
    let fetched = stream::iter(names)
        .map(|crate_name| async move {
            let releases = crates_io.package_metadata(crate_name.as_str()).await?;
            Ok::<_, ResolverError>((crate_name, releases))
        })
        .buffer_unordered(fetch_concurrency)
        .collect::<Vec<_>>()
        .await;
    let mut releases_by_name = BTreeMap::new();
    for result in fetched {
        let (crate_name, releases) = result?;
        releases_by_name.insert(crate_name, releases);
    }
    Ok(releases_by_name)
}

/// Write freshly built version graphs back to `crate_version_graph_cache`
/// in multi-row upsert batches. Same contract as the single-row path: the
/// graphs already live in the caller's response, so a rejected write only
/// loses the warm for the next caller and must not fail this one.
async fn upsert_version_graphs(db: &Db, fresh: &[(PackageKey, String)]) {
    for chunk in fresh.chunks(sql_batch::VERSION_GRAPH_CACHE_UPSERT_BATCH_SIZE) {
        let sql = format!(
            "INSERT INTO crate_version_graph_cache (crate_name, version, graph_json, fetched_at) \
             VALUES {} \
             ON CONFLICT(crate_name, version) \
             DO UPDATE SET graph_json = excluded.graph_json, fetched_at = excluded.fetched_at",
            sql_batch::values_rows("(?, ?, ?, datetime('now'))", chunk.len())
        );
        let mut query = db.query(&sql);
        for (key, graph_json) in chunk {
            query = query
                .bind(key.crate_name.as_str())
                .bind(key.version.to_string())
                .bind(graph_json.as_str());
        }
        if let Err(error) = query.execute().await {
            tracing::error!(
                %error,
                rows = chunk.len(),
                "version graph cache batch upsert failed; serving uncached graphs"
            );
        }
    }
}

#[derive(Debug, skyzen::FromRow)]
struct VersionsCacheRow {
    crate_name: String,
    versions_json: String,
}

/// Load the TTL-fresh `crate_versions_cache` rows for `names` in
/// IN-clause batches — the batched counterpart of
/// [`fetch_versions_cached`]'s single-row read. Names absent from the
/// result are cold and fetch the index instead.
async fn load_versions_cache(
    db: &Db,
    names: &BTreeSet<CrateName>,
) -> Result<BTreeMap<CrateName, Vec<Version>>, ResolverError> {
    let mut versions_by_name = BTreeMap::new();
    let names = names.iter().collect::<Vec<_>>();
    for batch in names.chunks(sql_batch::VERSIONS_CACHE_READ_BATCH_SIZE) {
        let sql = format!(
            "SELECT crate_name, versions_json FROM crate_versions_cache \
             WHERE crate_name IN ({}) AND fetched_at >= datetime('now', ?)",
            sql_batch::placeholders(batch.len())
        );
        let mut query = db.query(&sql);
        for name in batch {
            query = query.bind(name.as_str());
        }
        let rows = query
            .bind(CACHE_TTL_SQL)
            .fetch_all::<VersionsCacheRow>()
            .await
            .map_err(|error| format!("load crate_versions_cache batch: {error}"))?;
        for row in rows {
            versions_by_name.insert(
                CrateName::parse(row.crate_name.as_str())?,
                parse_versions_json(&row.crate_name, &row.versions_json)?,
            );
        }
    }
    Ok(versions_by_name)
}

/// Write freshly fetched version lists back to `crate_versions_cache` in
/// multi-row upsert batches — the batched counterpart of
/// [`fetch_versions_cached`]'s single-row write. A rejected write only
/// loses the warm for the next caller and must not fail the response.
async fn upsert_versions_cache(db: &Db, fresh: &[(CrateName, String)]) {
    for chunk in fresh.chunks(sql_batch::VERSIONS_CACHE_UPSERT_BATCH_SIZE) {
        let sql = format!(
            "INSERT INTO crate_versions_cache (crate_name, versions_json, fetched_at) \
             VALUES {} \
             ON CONFLICT(crate_name) \
             DO UPDATE SET versions_json = excluded.versions_json, fetched_at = excluded.fetched_at",
            sql_batch::values_rows("(?, ?, datetime('now'))", chunk.len())
        );
        let mut query = db.query(&sql);
        for (crate_name, versions_json) in chunk {
            query = query.bind(crate_name.as_str()).bind(versions_json.as_str());
        }
        if let Err(error) = query.execute().await {
            tracing::error!(
                %error,
                rows = chunk.len(),
                "versions cache batch upsert failed; serving uncached versions"
            );
        }
    }
}

#[derive(Debug, skyzen::FromRow)]
struct VersionGraphCacheRow {
    crate_name: String,
    version: String,
    graph_json: String,
}

/// Load the TTL-fresh `crate_version_graph_cache` rows for `keys` in
/// pair-keyed IN-clause batches. Rows missing, expired, or in an older
/// payload format are absent from the result and become cold fetches —
/// the same three-way split the single-row
/// [`fetch_version_graph_cached`] makes.
async fn load_version_graph_cache(
    db: &Db,
    keys: &BTreeSet<PackageKey>,
) -> Result<BTreeMap<PackageKey, VersionGraph>, ResolverError> {
    let keys = keys.iter().collect::<Vec<_>>();
    let mut graphs = BTreeMap::<PackageKey, VersionGraph>::new();
    for batch in keys.chunks(sql_batch::VERSION_GRAPH_CACHE_READ_BATCH_SIZE) {
        let sql = format!(
            "SELECT crate_name, version, graph_json \
             FROM crate_version_graph_cache \
             WHERE (crate_name, version) IN ({}) \
               AND fetched_at >= datetime('now', ?)",
            sql_batch::values_rows("(?, ?)", batch.len())
        );
        let mut query = db.query(&sql);
        for key in batch {
            query = query
                .bind(key.crate_name.as_str())
                .bind(key.version.to_string());
        }
        let rows = query
            .bind(CACHE_TTL_SQL)
            .fetch_all::<VersionGraphCacheRow>()
            .await
            .map_err(|error| format!("load crate_version_graph_cache batch: {error}"))?;
        for row in rows {
            // The format tag decides whether the row is this payload shape
            // at all; only a current-format row is parsed, and a
            // current-format row that fails to parse is corruption, not a
            // miss.
            let tag: VersionGraphTag = serde_json::from_str(&row.graph_json).map_err(|error| {
                ResolverError::Json(format!(
                    "read cached version graph tag {} {}: {error}",
                    row.crate_name, row.version
                ))
            })?;
            if tag.format_version != Some(VERSION_GRAPH_FORMAT) {
                tracing::debug!(
                    crate_name = %row.crate_name,
                    version = %row.version,
                    cached_format = ?tag.format_version,
                    current_format = VERSION_GRAPH_FORMAT,
                    "refetching version graph cached in an older payload format"
                );
                continue;
            }
            let graph = serde_json::from_str(&row.graph_json).map_err(|error| {
                ResolverError::Json(format!(
                    "parse cached version graph {} {}: {error}",
                    row.crate_name, row.version
                ))
            })?;
            graphs.insert(
                PackageKey {
                    crate_name: CrateName::parse(row.crate_name.as_str())?,
                    version: Version::parse(row.version.as_str()).map_err(|error| {
                        format!(
                            "parse cached version {} {}: {error}",
                            row.crate_name, row.version
                        )
                    })?,
                },
                graph,
            );
        }
    }
    Ok(graphs)
}

/// Every feature name a caller may legitimately ask for on one crate
/// version: the declared `[features]` keys plus the implicit feature cargo
/// grants each optional dependency — minus the optional dependencies some
/// declared feature reaches through `dep:<name>`, which hides the implicit
/// one.
pub fn selectable_features(
    features: &BTreeMap<String, Vec<String>>,
    dependencies: &[CratesIoDependency],
) -> BTreeSet<String> {
    let dep_referenced = features
        .values()
        .flat_map(|items| items.iter())
        .filter_map(|item| item.strip_prefix("dep:"))
        .collect::<BTreeSet<_>>();
    features
        .keys()
        .cloned()
        .chain(
            dependencies
                .iter()
                .filter(|dependency| dependency.optional)
                .map(|dependency| dependency.name.as_str())
                .filter(|name| !dep_referenced.contains(name))
                .map(ToOwned::to_owned),
        )
        .collect()
}

fn resolve_local_features(
    graph: &VersionGraph,
    seed_features: &BTreeSet<String>,
) -> BTreeSet<String> {
    // Seed features that the crate's real feature graph does not declare are
    // dropped here, before any task identity is minted: an arbitrary feature
    // string must not create a new canonical identity. When every seed is
    // bogus the result is the canonical empty set, and every "bogus-feature"
    // variant of a crate collapses onto one task id.
    //
    // The valid seed set is the declared [features] keys plus the implicit
    // feature cargo grants every optional dependency — unless a declared
    // feature references that dependency through `dep:<name>`, which hides
    // the implicit feature.
    let selectable = selectable_features(&graph.features, &graph.dependencies);
    let mut features = seed_features
        .iter()
        .filter(|feature| selectable.contains(feature.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut queue = features.iter().cloned().collect::<VecDeque<String>>();
    while let Some(feature) = queue.pop_front() {
        let Some(items) = graph.features.get(&feature) else {
            continue;
        };
        for item in items {
            if item.starts_with("dep:") || item.contains('/') {
                continue;
            }
            if features.insert(item.clone()) {
                queue.push_back(item.clone());
            }
        }
    }
    features
}

/// Build a canonical `FeaturesJson` from a normalized feature set.
fn canonical_features_from_set(features: &BTreeSet<String>) -> Result<FeaturesJson, ResolverError> {
    FeaturesJson::from_sorted(features.iter().cloned().collect()).map_err(ResolverError::Identity)
}

fn compatible_requirement(version: &Version) -> String {
    format!("^{version}")
}

/// Validate and deduplicate a requested feature list — the same shape check
/// `/api/v1/enqueue` applies, exposed for `POST /api/v1/requests`.
///
/// # Errors
/// [`ResolverError::Invariant`] on an empty, over-long, or non-ASCII
/// feature name.
pub fn normalize_feature_set(features: Vec<String>) -> Result<BTreeSet<String>, ResolverError> {
    let mut set = BTreeSet::<String>::new();
    for feature in features {
        validate_feature_name(feature.as_str())?;
        set.insert(feature);
    }
    Ok(set)
}

/// Canonical `features_json` for a resolved feature set: the sorted list
/// JSON-encoded — the same string [`FeaturesJson::raw`] produces and the
/// identity column every task id hashes.
///
/// # Errors
/// [`ResolverError::Json`] if the set fails to serialize.
pub fn serialize_feature_set(features: &BTreeSet<String>) -> Result<String, ResolverError> {
    serde_json::to_string(&features.iter().cloned().collect::<Vec<_>>())
        .map_err(|error| ResolverError::Json(format!("serialize feature set: {error}")))
}

fn validate_feature_name(feature: &str) -> Result<(), ResolverError> {
    if feature.is_empty()
        || feature.len() > 128
        || !feature
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(ResolverError::Invariant(format!(
            "invalid feature name: {feature}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use semver::Version;
    use stow_types::api::{
        DependencyGraphEntry, EnqueueSource, ResolvedDependencyGraphDependency,
        ResolvedDependencyGraphEntry,
    };
    use stow_types::identity::CrateName;

    use super::{
        CachedArtifactRow, PackageKey, build_enqueue_requests, exact_graph_from_request,
        immediate_dominators, resolve_reachable_cached_rows,
    };

    fn key(name: &str, version: &str) -> PackageKey {
        PackageKey {
            crate_name: CrateName::parse(name).unwrap(),
            version: Version::parse(version).unwrap(),
        }
    }

    #[test]
    fn exact_graph_preserves_client_resolved_lockfile_versions() {
        let humansize_key = key("humansize", "2.1.3");
        let libm_key = key("libm", "0.2.8");
        let unexpected_libm_key = key("libm", "0.2.16");
        let exact_graph = exact_graph_from_request(
            &[DependencyGraphEntry {
                crate_name: humansize_key.crate_name.clone(),
                version: humansize_key.version.clone(),
                features: vec!["std".to_owned()],
            }],
            &[
                ResolvedDependencyGraphEntry {
                    crate_name: humansize_key.crate_name.clone(),
                    version: humansize_key.version.clone(),
                    features: vec!["std".to_owned()],
                    dependencies: vec![ResolvedDependencyGraphDependency {
                        crate_name: libm_key.crate_name.clone(),
                        version: libm_key.version.clone(),
                    }],
                },
                ResolvedDependencyGraphEntry {
                    crate_name: libm_key.crate_name.clone(),
                    version: libm_key.version.clone(),
                    features: Vec::new(),
                    dependencies: Vec::new(),
                },
            ],
        )
        .unwrap();

        assert!(exact_graph.feature_json_by_key.contains_key(&humansize_key));
        assert!(exact_graph.feature_json_by_key.contains_key(&libm_key));
        assert!(
            !exact_graph
                .feature_json_by_key
                .contains_key(&unexpected_libm_key)
        );
        assert_eq!(
            exact_graph.dependency_keys_by_key.get(&humansize_key),
            Some(&BTreeSet::from([libm_key.clone()])),
        );
        assert_eq!(
            exact_graph.feature_json_by_key.get(&libm_key),
            Some(&"[]".to_owned()),
        );
    }

    #[test]
    fn reachable_rows_follow_compile_key_dependency_identities() {
        let same_file_key = key("same-file", "1.0.6");
        let walkdir_key = key("walkdir", "2.5.0");
        let key_pairs = BTreeSet::from([
            (same_file_key, "[]".to_owned()),
            (walkdir_key, "[]".to_owned()),
        ]);
        let rows = vec![
            CachedArtifactRow {
                compile_key: "72e2ded9fa67e0a172e2ded9fa67e0a1".to_owned(),
                crate_name: "same-file".to_owned(),
                version: "1.0.6".to_owned(),
                features_json: "[]".to_owned(),
                c_metadata: "72e2ded9fa67e0a1".to_owned(),
                dependency_c_metadata_json: "[]".to_owned(),
            },
            CachedArtifactRow {
                compile_key: "1c0d7420b566b7a21c0d7420b566b7a2".to_owned(),
                crate_name: "walkdir".to_owned(),
                version: "2.5.0".to_owned(),
                features_json: "[]".to_owned(),
                c_metadata: "1c0d7420b566b7a2".to_owned(),
                dependency_c_metadata_json:
                    r#"[{"crate_name":"same_file","c_metadata":"72e2ded9fa67e0a1"}]"#.to_owned(),
            },
        ];

        let reachable = resolve_reachable_cached_rows(&key_pairs, rows).unwrap();

        assert_eq!(reachable.len(), 2);
        assert_eq!(reachable[0].row.crate_name, "same-file");
        assert_eq!(reachable[1].row.crate_name, "walkdir");
    }

    #[test]
    fn rows_with_uncached_dependency_identities_are_not_reachable() {
        let walkdir_key = key("walkdir", "2.5.0");
        let key_pairs = BTreeSet::from([(walkdir_key, "[]".to_owned())]);
        let rows = vec![CachedArtifactRow {
            compile_key: "1c0d7420b566b7a21c0d7420b566b7a2".to_owned(),
            crate_name: "walkdir".to_owned(),
            version: "2.5.0".to_owned(),
            features_json: "[]".to_owned(),
            c_metadata: "1c0d7420b566b7a2".to_owned(),
            dependency_c_metadata_json:
                r#"[{"crate_name":"same_file","c_metadata":"72e2ded9fa67e0a1"}]"#.to_owned(),
        }];

        let reachable = resolve_reachable_cached_rows(&key_pairs, rows).unwrap();

        assert!(reachable.is_empty());
    }

    #[test]
    fn chain_only_rows_satisfy_reachability() {
        // walkdir semantically matches the request; its chain references a
        // same-file artifact whose features do NOT match this request's
        // semantic keys (another preheat's unification). The candidate must
        // stay reachable — the chain row covers its dependency identity.
        let walkdir_key = key("walkdir", "2.5.0");
        let key_pairs = BTreeSet::from([(walkdir_key, "[]".to_owned())]);
        let rows = vec![
            CachedArtifactRow {
                compile_key: "1c0d7420b566b7a21c0d7420b566b7a2".to_owned(),
                crate_name: "walkdir".to_owned(),
                version: "2.5.0".to_owned(),
                features_json: "[]".to_owned(),
                c_metadata: "1c0d7420b566b7a2".to_owned(),
                dependency_c_metadata_json:
                    r#"[{"crate_name":"same_file","c_metadata":"72e2ded9fa67e0a1"}]"#.to_owned(),
            },
            CachedArtifactRow {
                compile_key: "72e2ded9fa67e0a172e2ded9fa67e0a1".to_owned(),
                crate_name: "same-file".to_owned(),
                version: "1.0.6".to_owned(),
                features_json: r#"["unstable"]"#.to_owned(),
                c_metadata: "72e2ded9fa67e0a1".to_owned(),
                dependency_c_metadata_json: "[]".to_owned(),
            },
        ];

        let reachable = resolve_reachable_cached_rows(&key_pairs, rows).unwrap();

        assert_eq!(reachable.len(), 1);
        assert_eq!(reachable[0].row.crate_name, "walkdir");
    }

    #[test]
    fn candidate_dependency_names_may_differ_from_the_analyzed_graph() {
        // A cached row may have been captured with externs that differ from
        // the analyzed graph's manifest-level dependency list (feature-gated
        // optionals, build-dep-only externs). As long as its chain resolves,
        // it stays usable.
        let bitflags_key = key("bitflags", "2.11.0");
        let key_pairs = BTreeSet::from([(bitflags_key, "[]".to_owned())]);
        let rows = vec![CachedArtifactRow {
            compile_key: "aaaaaaaaaaaaaaaaffffffffffffffff".to_owned(),
            crate_name: "bitflags".to_owned(),
            version: "2.11.0".to_owned(),
            features_json: "[]".to_owned(),
            c_metadata: "aaaaaaaaaaaaaaaa".to_owned(),
            dependency_c_metadata_json: "[]".to_owned(),
        }];

        let reachable = resolve_reachable_cached_rows(&key_pairs, rows).unwrap();

        assert_eq!(reachable.len(), 1);
    }

    #[test]
    fn duplicate_compile_key_rows_with_same_semantics_are_deduplicated() {
        let ignore_key = key("ignore", "0.4.25");
        let walkdir_key = key("walkdir", "2.5.0");
        let key_pairs = BTreeSet::from([
            (ignore_key.clone(), "[]".to_owned()),
            (walkdir_key.clone(), "[]".to_owned()),
        ]);
        let _ = (ignore_key, walkdir_key);
        let canonical_ignore_row = || CachedArtifactRow {
            compile_key: "aaaaaaaaaaaaaaaaffffffffffffffff".to_owned(),
            crate_name: "ignore".to_owned(),
            version: "0.4.25".to_owned(),
            features_json: "[]".to_owned(),
            c_metadata: "aaaaaaaaaaaaaaaa".to_owned(),
            dependency_c_metadata_json:
                r#"[{"crate_name":"walkdir","c_metadata":"9999999999999999"}]"#.to_owned(),
        };
        let rows = vec![
            // Legacy row whose c_metadata does not match its compile_key's
            // stable prefix: filtered by the canonical-metadata check.
            CachedArtifactRow {
                c_metadata: "bbbbbbbbbbbbbbbb".to_owned(),
                ..canonical_ignore_row()
            },
            canonical_ignore_row(),
            // Exact duplicate of the canonical row: deduplicated.
            canonical_ignore_row(),
            CachedArtifactRow {
                compile_key: "9999999999999999eeeeeeeeeeeeeeee".to_owned(),
                crate_name: "walkdir".to_owned(),
                version: "2.5.0".to_owned(),
                features_json: "[]".to_owned(),
                c_metadata: "9999999999999999".to_owned(),
                dependency_c_metadata_json: "[]".to_owned(),
            },
        ];

        let reachable = resolve_reachable_cached_rows(&key_pairs, rows).unwrap();

        assert_eq!(reachable.len(), 2);
        assert_eq!(reachable[0].row.crate_name, "ignore");
        assert_eq!(reachable[0].row.c_metadata, "aaaaaaaaaaaaaaaa");
        assert_eq!(reachable[1].row.crate_name, "walkdir");
    }

    #[test]
    fn local_features_drop_seeds_the_crate_does_not_declare() {
        use super::{VersionGraph, resolve_local_features};
        use std::collections::BTreeMap;

        let graph = VersionGraph {
            format_version: super::VERSION_GRAPH_FORMAT,
            features: BTreeMap::from([
                ("default".to_owned(), Vec::new()),
                ("derive".to_owned(), vec!["dep:serde_derive".to_owned()]),
                ("full".to_owned(), vec!["derive".to_owned()]),
            ]),
            dependencies: Vec::new(),
        };
        // "bogus" is dropped before any task id exists; "full" survives and
        // drags its declared "derive" expansion in.
        let resolved = resolve_local_features(
            &graph,
            &BTreeSet::from(["bogus".to_owned(), "full".to_owned()]),
        );
        assert_eq!(
            resolved,
            BTreeSet::from(["full".to_owned(), "derive".to_owned()])
        );
    }

    #[test]
    fn local_features_all_bogus_collapses_to_the_empty_set() {
        use super::{VersionGraph, resolve_local_features};
        use std::collections::BTreeMap;

        let graph = VersionGraph {
            format_version: super::VERSION_GRAPH_FORMAT,
            features: BTreeMap::from([("std".to_owned(), Vec::new())]),
            dependencies: Vec::new(),
        };
        // Every bogus-feature variant of a crate collapses onto the one
        // canonical empty-feature task identity.
        assert!(resolve_local_features(&graph, &BTreeSet::from(["bogus".to_owned()])).is_empty());
    }

    #[test]
    fn local_features_keep_implicit_optional_dependency_features() {
        use super::{CratesIoDependency, VersionGraph, resolve_local_features};
        use std::collections::BTreeMap;

        // slab's real shape: `serde` is an optional dependency no declared
        // feature references through `dep:`, so cargo grants an implicit
        // `serde` feature that must survive validation.
        let graph = VersionGraph {
            format_version: super::VERSION_GRAPH_FORMAT,
            features: BTreeMap::from([
                ("default".to_owned(), vec!["std".to_owned()]),
                ("std".to_owned(), Vec::new()),
            ]),
            dependencies: vec![CratesIoDependency {
                name: "serde".to_owned(),
                crate_id: "serde".to_owned(),
                optional: true,
                ..CratesIoDependency::default()
            }],
        };
        let resolved = resolve_local_features(
            &graph,
            &BTreeSet::from(["serde".to_owned(), "bogus".to_owned()]),
        );
        assert_eq!(resolved, BTreeSet::from(["serde".to_owned()]));
    }

    #[test]
    fn local_features_drop_dep_referenced_optional_dependencies() {
        use super::{CratesIoDependency, VersionGraph, resolve_local_features};
        use std::collections::BTreeMap;

        // When a declared feature references `dep:foo`, cargo hides the
        // implicit `foo` feature — `foo` as a seed is bogus like any other
        // undeclared name.
        let graph = VersionGraph {
            format_version: super::VERSION_GRAPH_FORMAT,
            features: BTreeMap::from([("full".to_owned(), vec!["dep:foo".to_owned()])]),
            dependencies: vec![CratesIoDependency {
                name: "foo".to_owned(),
                crate_id: "foo".to_owned(),
                optional: true,
                ..CratesIoDependency::default()
            }],
        };
        assert!(resolve_local_features(&graph, &BTreeSet::from(["foo".to_owned()])).is_empty());
    }

    #[test]
    fn a_renamed_optional_dependency_is_seeded_by_its_declared_name() {
        use super::{CratesIoDependency, VersionGraph, resolve_local_features};
        use std::collections::BTreeMap;

        // `cookie_crate = { package = "cookie", optional = true }`: the
        // implicit feature is `cookie_crate`, and `cookie` is only the crate
        // that gets built. Seeding by the package name must be rejected the
        // way any undeclared name is.
        let graph = VersionGraph {
            format_version: super::VERSION_GRAPH_FORMAT,
            features: BTreeMap::new(),
            dependencies: vec![CratesIoDependency {
                name: "cookie_crate".to_owned(),
                crate_id: "cookie".to_owned(),
                optional: true,
                ..CratesIoDependency::default()
            }],
        };

        assert_eq!(
            resolve_local_features(&graph, &BTreeSet::from(["cookie_crate".to_owned()])),
            BTreeSet::from(["cookie_crate".to_owned()])
        );
        assert!(resolve_local_features(&graph, &BTreeSet::from(["cookie".to_owned()])).is_empty());
    }

    /// `CratesIo` stub serving canned published versions, feature maps, and
    /// dependency lists, so canonicalization runs entirely off-network in
    /// tests.
    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Debug, Default)]
    pub(super) struct StubCratesIo {
        pub(super) versions: std::collections::BTreeMap<String, Vec<String>>,
        pub(super) features: std::collections::BTreeMap<
            (String, String),
            std::collections::BTreeMap<String, Vec<String>>,
        >,
        pub(super) dependencies:
            std::collections::BTreeMap<(String, String), Vec<super::CratesIoDependency>>,
        /// Version numbers the stub reports as yanked, keyed by crate name.
        /// Defaults to none — tests that exercise the yank filter opt in.
        pub(super) yanked: std::collections::BTreeMap<String, Vec<String>>,
        /// Count of `package_metadata` calls, for tests asserting the cold
        /// path deduplicates index fetches by crate name.
        pub(super) fetches: std::sync::atomic::AtomicU64,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl super::CratesIo for StubCratesIo {
        /// Crates absent from `versions` model a crates.io 404 — the
        /// crate is not published at all, distinct from one published
        /// with no matching version (`versions` entry with an empty or
        /// non-matching list).
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "the CratesIo trait signature is async; the stub has nothing to await"
        )]
        async fn package_metadata(
            &self,
            crate_name: &str,
        ) -> Result<Vec<super::PublishedRelease>, super::ResolverError> {
            self.fetches
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let versions = self.versions.get(crate_name).ok_or_else(|| {
                super::ResolverError::CrateNotPublished {
                    crate_name: crate_name.to_owned(),
                }
            })?;
            let yanked = self.yanked.get(crate_name);
            Ok(versions
                .iter()
                .map(|version| super::PublishedRelease {
                    version: Version::parse(version).expect("stub semver"),
                    yanked: yanked.is_some_and(|list| list.contains(version)),
                    features: self
                        .features
                        .get(&(crate_name.to_owned(), version.clone()))
                        .cloned()
                        .unwrap_or_default(),
                    dependencies: self
                        .dependencies
                        .get(&(crate_name.to_owned(), version.clone()))
                        .cloned()
                        .unwrap_or_default(),
                })
                .collect())
        }

        /// Substring match over the canned crate names, newest canned
        /// version reported as both the max and max-stable version.
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "the CratesIo trait signature is async; the stub has nothing to await"
        )]
        async fn search(
            &self,
            query: &str,
            limit: u32,
        ) -> Result<Vec<super::CratesIoSearchHit>, super::ResolverError> {
            Ok(self
                .versions
                .iter()
                .filter(|(name, _)| name.contains(query))
                .take(limit as usize)
                .map(|(name, versions)| super::CratesIoSearchHit {
                    name: name.clone(),
                    description: Some(format!("{name} test fixture")),
                    max_stable_version: versions.last().cloned(),
                    max_version: versions.last().cloned().unwrap_or_default(),
                    downloads: 1,
                })
                .collect())
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn enqueue_request(
        crate_name: &str,
        version: &str,
        features: &[&str],
    ) -> stow_types::api::EnqueueRequest {
        stow_types::api::EnqueueRequest {
            crate_name: crate_name.parse().expect("valid crate name"),
            version: version.parse().expect("valid semver"),
            features_json: stow_types::identity::FeaturesJson::canonicalize(
                features
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
            )
            .expect("valid features"),
            target: "x86_64-unknown-linux-gnu".parse().expect("valid target"),
            rustc_version: "1.85.0".parse().expect("valid rustc version"),
            downloads: 0,
            source: stow_types::api::EnqueueSource::CacheMiss,
            depends_on: Vec::new(),
            preserve_lockfile: false,
        }
    }

    fn graph(edges: &[(&str, &[&str])]) -> BTreeMap<PackageKey, BTreeSet<PackageKey>> {
        edges
            .iter()
            .map(|(node, dependencies)| {
                (
                    key(node, "1.0.0"),
                    dependencies.iter().map(|dep| key(dep, "1.0.0")).collect(),
                )
            })
            .collect()
    }

    fn features(
        graph: &BTreeMap<PackageKey, BTreeSet<PackageKey>>,
    ) -> BTreeMap<PackageKey, String> {
        graph
            .keys()
            .map(|key| (key.clone(), "[]".to_owned()))
            .collect()
    }

    fn covered(names: &[&str]) -> BTreeSet<(PackageKey, String)> {
        names
            .iter()
            .map(|name| (key(name, "1.0.0"), "[]".to_owned()))
            .collect()
    }

    fn dominator_names(dominators: &BTreeMap<PackageKey, PackageKey>) -> Vec<(String, String)> {
        dominators
            .iter()
            .map(|(node, dominator)| {
                (
                    node.crate_name.as_str().to_owned(),
                    dominator.crate_name.as_str().to_owned(),
                )
            })
            .collect()
    }

    /// A chain root → mid → leaf: every node hangs off the nearest
    /// uncovered node above it, so the root dispatches first and the
    /// others are retired when its publish lands.
    #[test]
    fn immediate_dominator_is_the_nearest_uncovered_ancestor() {
        let graph = graph(&[("root", &["mid"]), ("mid", &["leaf"]), ("leaf", &[])]);
        let dominators = immediate_dominators(
            &features(&graph),
            &graph,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .expect("dominators");
        assert_eq!(
            dominator_names(&dominators),
            [
                ("leaf".to_owned(), "mid".to_owned()),
                ("mid".to_owned(), "root".to_owned()),
            ]
        );
    }

    /// A covered intermediate is skipped over, not treated as a wall: the
    /// root's build still produces the leaf beneath the covered crate.
    #[test]
    fn covered_intermediates_do_not_break_dominance() {
        let graph = graph(&[("root", &["mid"]), ("mid", &["leaf"]), ("leaf", &[])]);
        let dominators = immediate_dominators(
            &features(&graph),
            &graph,
            &covered(&["mid"]),
            &BTreeSet::new(),
        )
        .expect("dominators");
        assert_eq!(
            dominator_names(&dominators),
            [("leaf".to_owned(), "root".to_owned())]
        );
    }

    /// Two independent roots sharing a leaf: the leaf follows the smaller
    /// closure, and the roots themselves have no dominator.
    #[test]
    fn shared_leaf_follows_the_smallest_containing_closure() {
        let graph = graph(&[
            ("big", &["extra", "leaf"]),
            ("extra", &[]),
            ("small", &["leaf"]),
            ("leaf", &[]),
        ]);
        let dominators = immediate_dominators(
            &features(&graph),
            &graph,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
        .expect("dominators");
        assert_eq!(
            dominator_names(&dominators),
            [
                ("extra".to_owned(), "big".to_owned()),
                ("leaf".to_owned(), "small".to_owned()),
            ]
        );
    }

    /// The enqueue requests carry exactly one `depends_on` edge per
    /// dominated node, pointing at its dominator, and none for a root.
    #[test]
    fn enqueue_requests_depend_on_the_dominator_only() {
        let graph = graph(&[("root", &["a", "b"]), ("a", &["b"]), ("b", &[])]);
        let requests = build_enqueue_requests(
            &features(&graph),
            &graph,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &"x86_64-unknown-linux-gnu".parse().expect("target"),
            &"1.98.0".parse().expect("rustc"),
            EnqueueSource::CacheMiss,
        )
        .expect("requests");
        let edges = requests
            .iter()
            .map(|request| {
                (
                    request.crate_name.as_str().to_owned(),
                    request
                        .depends_on
                        .iter()
                        .map(|dependency| dependency.crate_name.as_str().to_owned())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            edges,
            [
                ("a".to_owned(), vec!["root".to_owned()]),
                ("b".to_owned(), vec!["a".to_owned()]),
                ("root".to_owned(), Vec::new()),
            ]
        );
    }
}

/// Async resolver tests: drive canonicalization against a real in-memory
/// `SQLite` so the versions/graph cache tables the resolver writes are
/// exercised by the same statements production runs.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod sqlite_tests {
    use std::collections::BTreeMap;

    use super::expand_scheduler_requests;
    use super::tests::{StubCratesIo, enqueue_request};

    #[tokio::test]
    async fn canonicalize_snaps_version_and_drops_bogus_features() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;
        let crates_io = StubCratesIo {
            versions: BTreeMap::from([(
                "serde".to_owned(),
                vec!["1.0.0".to_owned(), "1.0.5".to_owned()],
            )]),
            features: BTreeMap::from([(
                ("serde".to_owned(), "1.0.5".to_owned()),
                BTreeMap::from([("derive".to_owned(), vec!["dep:serde_derive".to_owned()])]),
            )]),
            dependencies: BTreeMap::new(),
            ..StubCratesIo::default()
        };

        let canonical = super::canonicalize_enqueue_requests(
            &db,
            &crates_io,
            vec![enqueue_request("serde", "1.0.0", &["bogus", "derive"])],
            8,
        )
        .await
        .expect("canonicalize");

        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical[0].version.to_string(), "1.0.5");
        assert_eq!(
            canonical[0].features_json.features(),
            &["derive".to_owned()]
        );
    }

    #[tokio::test]
    async fn canonicalize_drops_requests_for_unpublished_versions() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;
        let crates_io = StubCratesIo {
            versions: BTreeMap::from([("serde".to_owned(), vec!["1.0.5".to_owned()])]),
            features: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            ..StubCratesIo::default()
        };

        // No published version satisfies ^9.9.9 — no task id is minted.
        let canonical = super::canonicalize_enqueue_requests(
            &db,
            &crates_io,
            vec![
                enqueue_request("serde", "9.9.9", &[]),
                enqueue_request("serde", "1.0.0", &[]),
            ],
            8,
        )
        .await
        .expect("canonicalize");

        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical[0].version.to_string(), "1.0.5");
    }

    #[tokio::test]
    async fn canonicalize_keeps_implicit_optional_dependency_features() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;
        // slab 0.4's real shape: `serde` is an optional dependency with no
        // `dep:` reference, so it is a valid implicit feature; `bogus` is not.
        let crates_io = StubCratesIo {
            versions: BTreeMap::from([("slab".to_owned(), vec!["0.4.11".to_owned()])]),
            features: BTreeMap::from([(
                ("slab".to_owned(), "0.4.11".to_owned()),
                BTreeMap::from([
                    ("default".to_owned(), vec!["std".to_owned()]),
                    ("std".to_owned(), Vec::new()),
                ]),
            )]),
            dependencies: BTreeMap::from([(
                ("slab".to_owned(), "0.4.11".to_owned()),
                vec![super::CratesIoDependency {
                    name: "serde".to_owned(),
                    crate_id: "serde".to_owned(),
                    optional: true,
                    ..super::CratesIoDependency::default()
                }],
            )]),
            ..StubCratesIo::default()
        };

        let canonical = super::canonicalize_enqueue_requests(
            &db,
            &crates_io,
            vec![enqueue_request("slab", "0.4.11", &["serde", "bogus"])],
            8,
        )
        .await
        .expect("canonicalize");

        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical[0].features_json.features(), &["serde".to_owned()]);
    }

    /// Two serde roots plus a `depends_on` edge share one index fetch per
    /// crate name — serde's releases serve both its versions check and its
    /// feature graph — and a second pass over warm caches fetches nothing.
    #[tokio::test]
    async fn canonicalize_batches_fetches_per_crate_and_reuses_caches() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;
        let crates_io = StubCratesIo {
            versions: BTreeMap::from([
                (
                    "serde".to_owned(),
                    vec!["1.0.0".to_owned(), "1.0.5".to_owned()],
                ),
                ("slab".to_owned(), vec!["0.4.11".to_owned()]),
            ]),
            ..StubCratesIo::default()
        };
        let mut with_dep = enqueue_request("serde", "1.0.0", &[]);
        with_dep.depends_on.push(EnqueueDependency {
            crate_name: "slab".parse().expect("name"),
            version: "0.4.0".parse().expect("semver"),
            features_json: FeaturesJson::canonicalize(Vec::new()).expect("features"),
            target: TARGET.parse().expect("target"),
            rustc_version: RUSTC.parse().expect("rustc"),
        });

        let canonical = super::canonicalize_enqueue_requests(
            &db,
            &crates_io,
            vec![with_dep, enqueue_request("serde", "1.0.5", &[])],
            8,
        )
        .await
        .expect("canonicalize");

        assert_eq!(canonical.len(), 2);
        assert_eq!(canonical[0].version.to_string(), "1.0.5");
        assert_eq!(canonical[0].depends_on[0].version.to_string(), "0.4.11");
        assert_eq!(
            crates_io.fetches.load(std::sync::atomic::Ordering::Relaxed),
            2
        );

        // Warm pass: the versions and graph caches cover every name and
        // resolved key — no crates.io round trips.
        let warm = super::canonicalize_enqueue_requests(
            &db,
            &crates_io,
            vec![enqueue_request("serde", "1.0.0", &[])],
            8,
        )
        .await
        .expect("warm canonicalize");
        assert_eq!(warm.len(), 1);
        assert_eq!(
            crates_io.fetches.load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }

    use std::collections::BTreeSet;

    use stow_types::api::{
        CrateRequestState, EnqueueDependency, QueueTaskStatus, RequestStatus, TaskLane,
    };
    use stow_types::identity::{
        CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
    };

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
    const RUSTC: &str = "1.85.0";

    fn linux_target() -> TargetTriple {
        TargetTriple::parse(TARGET).expect("target")
    }

    fn rustc() -> WireRustcVersion {
        WireRustcVersion::parse(RUSTC).expect("rustc")
    }

    fn dep(
        crate_id: &str,
        req: &str,
        kind: super::CratesIoDependencyKind,
        target: Option<&str>,
    ) -> super::CratesIoDependency {
        super::CratesIoDependency {
            name: crate_id.to_owned(),
            crate_id: crate_id.to_owned(),
            req: req.to_owned(),
            kind,
            target: target.map(str::to_owned),
            ..super::CratesIoDependency::default()
        }
    }

    /// `root 1.0.0` depends on `lib-a` (normal, `^2`) and `dev-only`
    /// (dev kind), plus `win-only` gated on `cfg(windows)`; `lib-a` depends
    /// on `transitive`. Also covers optional-dep enabling via an implicit
    /// feature.
    fn closure_stub() -> StubCratesIo {
        StubCratesIo {
            versions: BTreeMap::from([
                (
                    "root".to_owned(),
                    vec![
                        "0.9.0".to_owned(),
                        "1.0.0-alpha.1".to_owned(),
                        "1.0.0".to_owned(),
                    ],
                ),
                (
                    "lib-a".to_owned(),
                    vec!["2.0.0".to_owned(), "2.1.0".to_owned()],
                ),
                ("transitive".to_owned(), vec!["0.1.0".to_owned()]),
                ("dev-only".to_owned(), vec!["1.0.0".to_owned()]),
                ("win-only".to_owned(), vec!["1.0.0".to_owned()]),
            ]),
            features: BTreeMap::from([
                (
                    ("root".to_owned(), "1.0.0".to_owned()),
                    BTreeMap::from([("default".to_owned(), Vec::new())]),
                ),
                (
                    ("lib-a".to_owned(), "2.1.0".to_owned()),
                    BTreeMap::from([("default".to_owned(), Vec::new())]),
                ),
            ]),
            dependencies: BTreeMap::from([
                (
                    ("root".to_owned(), "1.0.0".to_owned()),
                    vec![
                        dep("lib-a", "^2.0", super::CratesIoDependencyKind::Normal, None),
                        dep("dev-only", "^1", super::CratesIoDependencyKind::Dev, None),
                        dep(
                            "win-only",
                            "^1",
                            super::CratesIoDependencyKind::Normal,
                            Some("cfg(windows)"),
                        ),
                    ],
                ),
                (
                    ("lib-a".to_owned(), "2.1.0".to_owned()),
                    vec![dep(
                        "transitive",
                        "^0.1",
                        super::CratesIoDependencyKind::Build,
                        None,
                    )],
                ),
            ]),
            ..StubCratesIo::default()
        }
    }

    #[tokio::test]
    async fn latest_published_version_picks_newest_stable() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;
        let crates_io = closure_stub();

        let latest = super::latest_published_version(&db, &crates_io, "root")
            .await
            .expect("resolve")
            .expect("published");
        // 1.0.0-alpha.1 must never win over 1.0.0, and 0.9.0 is older.
        assert_eq!(latest.to_string(), "1.0.0");

        let exact = super::published_version(
            &db,
            &crates_io,
            "root",
            &semver::Version::parse("0.9.0").expect("version"),
        )
        .await
        .expect("resolve");
        assert_eq!(
            exact.map(|version| version.to_string()),
            Some("0.9.0".to_owned())
        );
        let missing = super::published_version(
            &db,
            &crates_io,
            "root",
            &semver::Version::parse("9.9.9").expect("version"),
        )
        .await
        .expect("resolve");
        assert_eq!(missing, None);
    }

    /// A crate crates.io does not know at all — the stub's absent
    /// `versions` key, i.e. the client's HTTP 404 — must surface as the
    /// typed not-found, never as a decode/internal error, so handlers can
    /// answer 404 instead of 500.
    #[tokio::test]
    async fn unpublished_crate_yields_crate_not_published() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;
        let crates_io = closure_stub();

        let error = super::latest_published_version(&db, &crates_io, "never-published")
            .await
            .expect_err("an unpublished crate must error, not resolve to None");
        assert!(
            matches!(
                error,
                super::ResolverError::CrateNotPublished { ref crate_name }
                    if crate_name == "never-published"
            ),
            "expected CrateNotPublished, got {error:?}"
        );

        let error = super::published_version(
            &db,
            &crates_io,
            "never-published",
            &semver::Version::parse("1.0.0").expect("version"),
        )
        .await
        .expect_err("exact-version lookup of an unpublished crate must error");
        assert!(
            matches!(error, super::ResolverError::CrateNotPublished { .. }),
            "expected CrateNotPublished, got {error:?}"
        );
    }

    /// A `graph_json` row written before `format_version` existed parses
    /// into nothing the resolver may serve: it is a cache miss and the
    /// crates.io data is fetched (and cached) fresh.
    #[tokio::test]
    async fn old_format_graph_cache_row_is_not_served() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;
        // The v1 row shape: no `format_version`, dependency entries the
        // current schema would reject — but none of that is reached,
        // because the tag is checked before the payload is trusted.
        db.query(
            "INSERT INTO crate_version_graph_cache (crate_name, version, graph_json, fetched_at) \
             VALUES (?, ?, ?, datetime('now'))",
        )
        .bind("root".to_owned())
        .bind("1.0.0".to_owned())
        .bind(r#"{"features":{},"dependencies":[]}"#.to_owned())
        .execute()
        .await
        .expect("insert old-format row");
        let crates_io = closure_stub();

        let graph = super::fetch_version_graph_cached(
            &db,
            &crates_io,
            "root",
            &semver::Version::parse("1.0.0").expect("version"),
        )
        .await
        .expect("fetch");

        assert_eq!(
            graph.format_version,
            super::VERSION_GRAPH_FORMAT,
            "the served graph must be a freshly-fetched current-format one"
        );
        assert_eq!(
            graph.dependencies.len(),
            3,
            "root@1.0.0 has three declared deps in the stub; the stale row had none"
        );
    }

    #[test]
    fn crate_request_target_assembles_states() {
        let target = linux_target();
        let status = |queue_status: QueueTaskStatus, position: Option<u32>| RequestStatus {
            task_id: "task".to_owned(),
            crate_name: CrateName::parse("root").expect("name"),
            version: CrateVersion::new(semver::Version::parse("1.0.0").expect("version")),
            features_json: FeaturesJson::default(),
            target: linux_target(),
            rustc_version: rustc(),
            lane: TaskLane::Human,
            status: queue_status,
            human_lane_position: position,
            blocked_by: None,
            preserve_lockfile: false,
        };

        let cached = super::crate_request_target(&target, "task", true, true, false, None)
            .expect("cached outcome");
        assert_eq!(cached.state, CrateRequestState::Cached);
        assert_eq!(cached.task_id, None);

        let queued = super::crate_request_target(
            &target,
            "task",
            false,
            true,
            false,
            Some(&status(QueueTaskStatus::Pending, Some(3))),
        )
        .expect("queued outcome");
        assert_eq!(queued.state, CrateRequestState::Queued);
        assert_eq!(queued.task_id.as_deref(), Some("task"));
        assert_eq!(queued.human_lane_position, Some(3));

        let already = super::crate_request_target(
            &target,
            "task",
            false,
            true,
            true,
            Some(&status(QueueTaskStatus::Pending, Some(1))),
        )
        .expect("already queued outcome");
        assert_eq!(already.state, CrateRequestState::AlreadyQueued);

        let building = super::crate_request_target(
            &target,
            "task",
            false,
            true,
            true,
            Some(&status(QueueTaskStatus::Running, None)),
        )
        .expect("building outcome");
        assert_eq!(building.state, CrateRequestState::Building);
        assert_eq!(building.human_lane_position, None);

        assert!(
            super::crate_request_target(&target, "task", false, true, false, None).is_err(),
            "a non-cached root without a queue row is an invariant violation"
        );

        let no_library = super::crate_request_target(&target, "task", false, false, false, None)
            .expect("closure-only outcome");
        assert_eq!(no_library.state, CrateRequestState::ClosureQueued);
        assert_eq!(no_library.task_id, None);
        assert_eq!(no_library.human_lane_position, None);
    }

    /// The batched cache read returns only TTL-fresh, current-format rows:
    /// `warm` is a hit, `stale` is past the 6-hour TTL and `absent` has no
    /// row — both become cold fetches upstream.
    #[tokio::test]
    async fn batched_version_graph_cache_read_splits_hits_misses_and_expired() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;

        let graph_json = serde_json::to_string(&super::VersionGraph {
            format_version: super::VERSION_GRAPH_FORMAT,
            features: BTreeMap::from([("default".to_owned(), Vec::new())]),
            dependencies: Vec::new(),
        })
        .expect("serialize");
        db.query(
            "INSERT INTO crate_version_graph_cache (crate_name, version, graph_json, fetched_at) \
             VALUES (?, ?, ?, datetime('now'))",
        )
        .bind("warm".to_owned())
        .bind("1.0.0".to_owned())
        .bind(graph_json.clone())
        .execute()
        .await
        .expect("insert fresh row");
        db.query(
            "INSERT INTO crate_version_graph_cache (crate_name, version, graph_json, fetched_at) \
             VALUES (?, ?, ?, datetime('now', '-7 hours'))",
        )
        .bind("stale".to_owned())
        .bind("1.0.0".to_owned())
        .bind(graph_json)
        .execute()
        .await
        .expect("insert expired row");

        let key = |name: &str| super::PackageKey {
            crate_name: CrateName::parse(name).expect("name"),
            version: semver::Version::parse("1.0.0").expect("version"),
        };
        let keys = BTreeSet::from([key("warm"), key("stale"), key("absent")]);
        let graphs = super::load_version_graph_cache(&db, &keys)
            .await
            .expect("load");

        assert!(graphs.contains_key(&key("warm")), "fresh row is a hit");
        assert!(
            !graphs.contains_key(&key("stale")),
            "row past the cache TTL is cold"
        );
        assert!(!graphs.contains_key(&key("absent")), "missing row is cold");
    }

    /// The issue-81/91 scenario, moved to the admissions lane: a fully
    /// uncovered `WaterUI`-scale request — 130 direct entries over an
    /// 830-node expanded graph — expands to one enqueue request per node.
    /// Misses go to the miss log as one Analytics Engine point per
    /// uncovered node — D1 sees zero writes.
    #[tokio::test]
    async fn admissions_uncovered_waterui_scale_graph_logs_misses_without_d1_writes() {
        const DIRECT: usize = 130;
        const EXPANDED: usize = 830;

        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;
        let entries = (0..DIRECT)
            .map(|index| stow_types::api::DependencyGraphEntry {
                crate_name: CrateName::parse(format!("dep-{index:04}")).expect("name"),
                version: semver::Version::parse("1.0.0").expect("version"),
                features: Vec::new(),
            })
            .collect::<Vec<_>>();
        let expanded = (0..EXPANDED)
            .map(|index| stow_types::api::ResolvedDependencyGraphEntry {
                crate_name: CrateName::parse(format!("dep-{index:04}")).expect("name"),
                version: semver::Version::parse("1.0.0").expect("version"),
                features: Vec::new(),
                dependencies: Vec::new(),
            })
            .collect::<Vec<_>>();

        let outcome = expand_scheduler_requests(&db, TARGET, RUSTC, &entries, &expanded)
            .await
            .expect("expansion");

        assert_eq!(outcome.enqueue_requests.len(), EXPANDED);
        // Demand analytics are Analytics Engine points, not D1 rows: the
        // handler-side write produces one `graph` point per uncovered
        // node and the misses table sees zero writes.
        let miss_log = crate::miss_logger::RecordingMissLog::default();
        crate::miss_logger::log_graph_misses(
            &miss_log,
            crate::stats::AnalyticsConsent::ALLOWED,
            &outcome.enqueue_requests,
        );
        {
            let points = miss_log.points.lock().expect("miss points");
            assert_eq!(points.len(), EXPANDED);
            assert!(
                points.iter().all(|point| point[7] == "graph"),
                "every recorded point is a graph-path miss"
            );
            drop(points);
        }
        let miss_rows = db
            .query("SELECT COUNT(*) FROM dependency_graph_misses")
            .fetch_scalar::<u64>()
            .await
            .expect("miss count");
        assert_eq!(miss_rows, 0);
    }

    /// A graph over the `MAX_EXPANDED_TASKS` cap is a client-visible limit
    /// error naming the observed count and the limit — never the bare
    /// 500 a redacted invariant used to produce.
    #[test]
    fn expanded_graph_over_limit_yields_named_limit_error() {
        let over_limit = super::MAX_EXPANDED_TASKS + 1;
        let expanded = (0..over_limit)
            .map(|index| stow_types::api::ResolvedDependencyGraphEntry {
                crate_name: CrateName::parse(format!("dep-{index:04}")).expect("name"),
                version: semver::Version::parse("1.0.0").expect("version"),
                features: Vec::new(),
                dependencies: Vec::new(),
            })
            .collect::<Vec<_>>();

        let error = super::exact_graph_from_request(&[], &expanded)
            .err()
            .expect("an over-limit graph must be rejected");
        match error {
            super::ResolverError::LimitExceeded { got, limit, .. } => {
                assert_eq!(got, over_limit);
                assert_eq!(limit, super::MAX_EXPANDED_TASKS);
            }
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    /// The production outage behind this contract: D1's write-quota
    /// rejection made every cold graph fetch a 500 even though reads and
    /// the upstream fetch still worked. A `RAISE` trigger reproduces the
    /// exact shape — writes abort, reads pass — and the fetched graph
    /// must be served uncached rather than erroring.
    #[tokio::test]
    async fn rejected_graph_cache_write_still_serves_the_graph() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;
        db.query(
            "CREATE TRIGGER deny_graph_cache_write \
             BEFORE INSERT ON crate_version_graph_cache \
             BEGIN SELECT RAISE(ABORT, 'write blocked'); END",
        )
        .execute()
        .await
        .expect("deny trigger");
        let crates_io = StubCratesIo {
            versions: BTreeMap::from([("cfg-if".to_owned(), vec!["1.0.4".to_owned()])]),
            features: BTreeMap::from([(
                ("cfg-if".to_owned(), "1.0.4".to_owned()),
                BTreeMap::from([("rustc-dep-of-std".to_owned(), vec![])]),
            )]),
            dependencies: BTreeMap::new(),
            ..StubCratesIo::default()
        };

        let graph = super::fetch_version_graph_cached(
            &db,
            &crates_io,
            "cfg-if",
            &semver::Version::parse("1.0.4").expect("version"),
        )
        .await
        .expect("a rejected cache write must not fail the request");
        assert!(graph.features.contains_key("rustc-dep-of-std"));

        let cached = db
            .query("SELECT COUNT(*) FROM crate_version_graph_cache")
            .fetch_scalar::<u64>()
            .await
            .expect("cache row count");
        assert_eq!(cached, 0, "the aborted write must leave no row");
    }
}

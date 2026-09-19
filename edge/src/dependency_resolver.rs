use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;

use futures_util::stream::{self, StreamExt};
use semver::{Version, VersionReq};
use skyzen_services::Db;
use stow_types::api::{
    BatchArtifactRequestEntry, CrateRequestState, CrateRequestTarget, DependencyGraphEntry,
    EnqueueDependency, EnqueueRequest, EnqueueSource, QueueTaskStatus,
    ResolvedDependencyGraphEntry,
};
use stow_types::identity::{
    CMetadata, CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::public_cache::stable_c_metadata_for_compile_key;

use crate::errors::ResolverError;
use crate::sql_batch;

const CACHE_TTL_SQL: &str = "-6 hours";
const MAX_EXPANDED_TASKS: usize = 4096;

/// Format tag stored inside every `crate_version_graph_cache.graph_json`
/// payload. Version 1 is the pre-tag shape — rows without this field (or
/// with a different value) are treated as misses and re-fetched, so a
/// stale-format row is never served.
const VERSION_GRAPH_FORMAT: u32 = 2;

/// Just the format tag of a cached `graph_json` row; rows written before
/// the tag existed have none.
#[derive(serde::Deserialize)]
struct VersionGraphTag {
    #[serde(default)]
    format_version: Option<u32>,
}

/// Network boundary for crates.io metadata lookups.
///
/// Production passes the Cloudflare-fetch-backed client from
/// [`crate::crates_io`]; host-side tests can substitute a stub so every piece
/// of resolver logic stays testable off-wasm.
///
/// The `Send` bounds keep every resolver caller's future `Send`: `Sync` on
/// the trait makes `&impl CratesIo` sendable across awaits, and `Send` on
/// the returned futures does the same for the lookups themselves.
pub trait CratesIo: Sync {
    /// Feature map (`feature -> enabled items`) declared by one published
    /// crate version.
    fn version_features(
        &self,
        crate_name: &str,
        version: &Version,
    ) -> impl Future<Output = Result<BTreeMap<String, Vec<String>>, ResolverError>> + Send;

    /// Dependency list declared by one published crate version — the
    /// `optional` flags decide which implicit features exist.
    fn version_dependencies(
        &self,
        crate_name: &str,
        version: &Version,
    ) -> impl Future<Output = Result<Vec<CratesIoDependency>, ResolverError>> + Send;

    /// Non-yanked published version numbers for a crate, as listed by
    /// crates.io (unparsed).
    fn published_version_nums(
        &self,
        crate_name: &str,
    ) -> impl Future<Output = Result<Vec<String>, ResolverError>> + Send;
}

pub struct ExpandedSchedulerPlan {
    pub enqueue_requests: Vec<EnqueueRequest>,
    pub expanded_cached: usize,
    pub expanded_total: usize,
    pub expanded_entries: Vec<DependencyGraphEntry>,
    pub prefetch_artifacts: Vec<BatchArtifactRequestEntry>,
}

/// Canonicalize a batch of enqueue requests, dropping the ones no canonical
/// task can exist for (a version crates.io does not publish, or a
/// `depends_on` that cannot resolve).
pub async fn canonicalize_enqueue_requests(
    db: &Db,
    crates_io: &impl CratesIo,
    requests: Vec<EnqueueRequest>,
) -> Result<Vec<EnqueueRequest>, ResolverError> {
    let mut canonical = Vec::with_capacity(requests.len());
    for request in requests {
        if let Some(request) = canonicalize_enqueue_request(db, crates_io, request).await? {
            canonical.push(request);
        }
    }
    Ok(canonical)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PackageKey {
    crate_name: CrateName,
    version: Version,
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
    /// Dependency name as declared in the manifest (the implicit feature
    /// name when `optional` is set).
    pub crate_id: String,
    /// Whether the dependency is optional — cargo grants an implicit
    /// feature of the same name unless a declared feature references it
    /// through `dep:<name>`.
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

struct CachedArtifacts {
    semantic_keys: BTreeSet<(PackageKey, String)>,
    prefetch_artifacts: Vec<BatchArtifactRequestEntry>,
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
    let cached = load_cached_artifacts(
        db,
        target,
        rustc_version,
        &exact_graph.feature_json_by_key,
        &exact_graph.root_keys,
    )
    .await?;
    let expanded_total = exact_graph.feature_json_by_key.len();
    let expanded_cached = exact_graph
        .feature_json_by_key
        .iter()
        .filter(|(node_key, features_json)| {
            cached
                .semantic_keys
                .contains(&((*node_key).clone(), (*features_json).clone()))
        })
        .count();

    let requests = build_enqueue_requests(
        &exact_graph.feature_json_by_key,
        exact_graph.dependency_keys_by_key,
        &cached.semantic_keys,
        &target_typed,
        &rustc_version_typed,
        EnqueueSource::CacheMiss,
    )?;
    Ok(ExpandedSchedulerPlan {
        enqueue_requests: requests,
        expanded_cached,
        expanded_total,
        expanded_entries: exact_graph.expanded_entries,
        prefetch_artifacts: cached.prefetch_artifacts,
    })
}

/// Turn an exact graph (`feature_json_by_key` + `dependency_keys_by_key`)
/// into one [`EnqueueRequest`] per node the cache does not already cover.
/// `source` decides the scheduler lane the tasks land in: the miss path
/// passes [`EnqueueSource::CacheMiss`], the human request API passes
/// [`EnqueueSource::HumanRequest`].
fn build_enqueue_requests(
    feature_json_by_key: &BTreeMap<PackageKey, String>,
    dependency_keys_by_key: BTreeMap<PackageKey, BTreeSet<PackageKey>>,
    cached_semantic_keys: &BTreeSet<(PackageKey, String)>,
    target_typed: &TargetTriple,
    rustc_version_typed: &WireRustcVersion,
    source: EnqueueSource,
) -> Result<Vec<EnqueueRequest>, ResolverError> {
    let mut requests = Vec::<EnqueueRequest>::new();
    for (node_key, dependency_keys) in dependency_keys_by_key {
        let features_json = feature_json_by_key.get(&node_key).cloned().ok_or_else(|| {
            format!(
                "missing serialized feature set for {} {}",
                node_key.crate_name, node_key.version
            )
        })?;
        if cached_semantic_keys.contains(&(node_key.clone(), features_json.clone())) {
            continue;
        }
        let depends_on = dependency_keys
            .into_iter()
            .filter_map(|dependency_key| {
                let dependency_features_json = feature_json_by_key.get(&dependency_key).cloned()?;
                if cached_semantic_keys
                    .contains(&(dependency_key.clone(), dependency_features_json.clone()))
                {
                    return None;
                }
                let dep_features_json =
                    match parse_canonical_features_json(dependency_features_json.as_str()) {
                        Ok(value) => value,
                        Err(error) => {
                            tracing::error!(
                                %error,
                                "skipping dependency with invalid features_json"
                            );
                            return None;
                        }
                    };
                Some(EnqueueDependency {
                    crate_name: dependency_key.crate_name.clone(),
                    version: CrateVersion::new(dependency_key.version),
                    features_json: dep_features_json,
                    target: target_typed.clone(),
                    rustc_version: rustc_version_typed.clone(),
                })
            })
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
            project_source: None,
        });
    }
    Ok(requests)
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

/// The enqueue plan `POST /api/v1/requests` produces for one target.
pub struct CrateRequestPlan {
    /// Human-lane tasks covering the part of the dependency closure the
    /// cache does not already cover on this target.
    pub enqueue_requests: Vec<EnqueueRequest>,
    /// Whether the requested crate itself is already cached on this target.
    pub root_cached: bool,
    /// Canonical features resolved for the requested crate — the root
    /// package's unified feature set as the task identity records it.
    pub root_features_json: String,
}

/// Expand `(crate_name, version, seed_features)` into the human-lane tasks
/// the request API needs on `target`: the root crate plus every normal and
/// build dependency in its crates.io closure, skipping packages the cache
/// already covers.
pub async fn expand_crate_request(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &CrateName,
    version: &Version,
    seed_features: &BTreeSet<String>,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
) -> Result<CrateRequestPlan, ResolverError> {
    let root_key = PackageKey {
        crate_name: crate_name.clone(),
        version: version.clone(),
    };
    let nodes =
        expand_crate_closure(db, crates_io, &root_key, seed_features, target.as_str()).await?;
    let mut feature_json_by_key = BTreeMap::<PackageKey, String>::new();
    let mut dependency_keys_by_key = BTreeMap::<PackageKey, BTreeSet<PackageKey>>::new();
    for (key, node) in nodes {
        feature_json_by_key.insert(key.clone(), serialize_feature_set(&node.features)?);
        dependency_keys_by_key.insert(key, node.depends_on);
    }
    let root_keys = BTreeSet::from([root_key.clone()]);
    let cached = load_cached_artifacts(
        db,
        target.as_str(),
        rustc_version.as_str(),
        &feature_json_by_key,
        &root_keys,
    )
    .await?;
    let root_features_json = feature_json_by_key.get(&root_key).cloned().ok_or_else(|| {
        format!(
            "expanded closure is missing root {} {}",
            root_key.crate_name, root_key.version
        )
    })?;
    let root_cached = cached
        .semantic_keys
        .contains(&(root_key, root_features_json.clone()));
    let enqueue_requests = build_enqueue_requests(
        &feature_json_by_key,
        dependency_keys_by_key,
        &cached.semantic_keys,
        target,
        rustc_version,
        EnqueueSource::HumanRequest,
    )?;
    Ok(CrateRequestPlan {
        enqueue_requests,
        root_cached,
        root_features_json,
    })
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
    was_queued: bool,
    status: Option<&stow_types::api::RequestStatus>,
) -> Result<CrateRequestTarget, ResolverError> {
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
        // A row the submit just resurrected out of `failed` is queued work
        // again — only the pre-existing-row flag separates the two queued
        // reports.
        QueueTaskStatus::Pending | QueueTaskStatus::Failed => {
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

/// One resolved package inside a human request's dependency closure.
struct ClosureNode {
    /// Unified feature set every incoming edge requests.
    features: BTreeSet<String>,
    /// Exact packages this node depends on.
    depends_on: BTreeSet<PackageKey>,
}

/// Walk crates.io metadata from `root_key` outward — resolving each
/// dependency edge's version requirement against published releases and
/// unifying feature sets across every edge reaching a package — until the
/// whole normal+build closure reachable on `target` is expanded.
///
/// Feature unification runs to a fixpoint: a package revisited with new
/// feature seeds is re-expanded so newly enabled optional dependencies
/// join the closure.
async fn expand_crate_closure(
    db: &Db,
    crates_io: &impl CratesIo,
    root_key: &PackageKey,
    seed_features: &BTreeSet<String>,
    target: &str,
) -> Result<BTreeMap<PackageKey, ClosureNode>, ResolverError> {
    let mut seeds = BTreeMap::<PackageKey, BTreeSet<String>>::new();
    let mut nodes = BTreeMap::<PackageKey, ClosureNode>::new();
    let mut pending = VecDeque::from([(root_key.clone(), seed_features.clone())]);

    while let Some((key, new_seeds)) = pending.pop_front() {
        let entry = seeds.entry(key.clone()).or_default();
        let mut grew = false;
        for seed in new_seeds {
            grew |= entry.insert(seed);
        }
        if !grew && nodes.contains_key(&key) {
            continue;
        }
        if nodes.len() >= MAX_EXPANDED_TASKS {
            return Err(ResolverError::Invariant(format!(
                "dependency closure exceeds limit {MAX_EXPANDED_TASKS}"
            )));
        }
        let node_seeds = seeds.get(&key).cloned().unwrap_or_default();
        let graph =
            fetch_version_graph_cached(db, crates_io, key.crate_name.as_str(), &key.version)
                .await?;
        let features = resolve_local_features(&graph, &node_seeds);

        // Which dependencies does the resolved feature set enable? `dep:x`
        // and `x/feat` items both enable x; `x?/feat` only applies a feature
        // when x is already enabled. Renamed optional deps (`dep:alias`
        // where the manifest alias differs from crate_id) cannot be matched
        // back to their edge from this metadata alone and are skipped.
        let mut enabled_deps = BTreeSet::<String>::new();
        let mut dep_feature_seeds = BTreeMap::<String, BTreeSet<String>>::new();
        for feature in &features {
            let Some(items) = graph.features.get(feature) else {
                continue;
            };
            for item in items {
                if let Some(dep) = item.strip_prefix("dep:") {
                    enabled_deps.insert(dep.to_owned());
                } else if let Some((dep, dep_feature)) = item.split_once('/') {
                    if let Some(weak) = dep.strip_suffix('?') {
                        dep_feature_seeds
                            .entry(weak.to_owned())
                            .or_default()
                            .insert(dep_feature.to_owned());
                    } else {
                        enabled_deps.insert(dep.to_owned());
                        dep_feature_seeds
                            .entry(dep.to_owned())
                            .or_default()
                            .insert(dep_feature.to_owned());
                    }
                }
            }
        }

        let mut depends_on = BTreeSet::<PackageKey>::new();
        for dep in &graph.dependencies {
            if dep.kind == CratesIoDependencyKind::Dev {
                continue;
            }
            // An optional dep joins the closure only when a `dep:`/`x/feat`
            // item selected it or its implicit feature survived validation.
            if dep.optional
                && !enabled_deps.contains(&dep.crate_id)
                && !features.contains(&dep.crate_id)
            {
                continue;
            }
            if let Some(spec) = &dep.target
                && !dep_target_matches(spec, target)
            {
                continue;
            }
            let Some(dep_version) =
                resolve_dependency_version(db, crates_io, &dep.crate_id, &dep.req).await?
            else {
                tracing::warn!(
                    crate_name = %dep.crate_id,
                    req = %dep.req,
                    "skipping dependency with no published version match"
                );
                continue;
            };
            let dep_key = PackageKey {
                crate_name: CrateName::parse(dep.crate_id.as_str())?,
                version: dep_version,
            };
            let mut dep_seeds = BTreeSet::<String>::new();
            if dep.default_features {
                dep_seeds.insert("default".to_owned());
            }
            dep_seeds.extend(dep.features.iter().cloned());
            if let Some(extra) = dep_feature_seeds.get(&dep.crate_id) {
                dep_seeds.extend(extra.iter().cloned());
            }
            depends_on.insert(dep_key.clone());
            pending.push_back((dep_key, dep_seeds));
        }
        nodes.insert(
            key,
            ClosureNode {
                features,
                depends_on,
            },
        );
    }
    Ok(nodes)
}

/// Whether a crates.io `target` restriction — a `cfg(...)` expression or a
/// bare target triple — applies to `target_triple`. Specs that cannot be
/// evaluated include the dependency: dropping a real edge would silently
/// break the ordering guarantee, while an extra task is a wasted build at
/// worst.
fn dep_target_matches(spec: &str, target_triple: &str) -> bool {
    if spec.starts_with("cfg") {
        let expression = match cfg_expr::Expression::parse(spec) {
            Ok(expression) => expression,
            Err(error) => {
                tracing::warn!(spec, %error, "unparseable dependency target spec — including dependency");
                return true;
            }
        };
        let Some(target_info) = cfg_expr::targets::get_builtin_target_by_triple(target_triple)
        else {
            tracing::warn!(
                spec,
                target_triple,
                "unknown builtin target — including dependency"
            );
            return true;
        };
        expression.eval(|predicate| match predicate {
            cfg_expr::Predicate::Target(target) => target.matches(target_info),
            _ => true,
        })
    } else {
        spec == target_triple
    }
}

struct ExactExpandedGraph {
    feature_json_by_key: BTreeMap<PackageKey, String>,
    dependency_keys_by_key: BTreeMap<PackageKey, BTreeSet<PackageKey>>,
    root_keys: BTreeSet<PackageKey>,
    expanded_entries: Vec<DependencyGraphEntry>,
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
        return Err(ResolverError::Invariant(format!(
            "expanded dependency task list exceeds limit {MAX_EXPANDED_TASKS}"
        )));
    }

    let mut feature_json_by_key = BTreeMap::<PackageKey, String>::new();
    let mut dependency_keys_by_key = BTreeMap::<PackageKey, BTreeSet<PackageKey>>::new();
    let mut normalized_entries = Vec::<DependencyGraphEntry>::with_capacity(expanded_entries.len());

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
        let crate_name = CrateName::parse(key.crate_name.as_str())
            .map_err(|error| format!("normalized entry crate_name: {error}"))?;
        normalized_entries.push(DependencyGraphEntry {
            crate_name,
            version: key.version.clone(),
            features: features.into_iter().collect(),
        });
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

    let root_keys = roots
        .iter()
        .map(|root| PackageKey {
            crate_name: root.crate_name.clone(),
            version: root.version.clone(),
        })
        .collect::<BTreeSet<_>>();
    for root_key in &root_keys {
        if feature_json_by_key.contains_key(root_key) {
            continue;
        }
        return Err(ResolverError::Invariant(format!(
            "expanded dependency graph is missing root {} {}",
            root_key.crate_name, root_key.version
        )));
    }

    normalized_entries.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.version.cmp(&right.version))
            .then(left.features.cmp(&right.features))
    });

    Ok(ExactExpandedGraph {
        feature_json_by_key,
        dependency_keys_by_key,
        root_keys,
        expanded_entries: normalized_entries,
    })
}

async fn load_cached_artifacts(
    db: &Db,
    target: &str,
    rustc_version: &str,
    feature_json_by_key: &BTreeMap<PackageKey, String>,
    root_keys: &BTreeSet<PackageKey>,
) -> Result<CachedArtifacts, ResolverError> {
    let key_pairs = feature_json_by_key
        .iter()
        .map(|(key, features_json)| (key.clone(), features_json.clone()))
        .collect::<BTreeSet<_>>();
    if key_pairs.is_empty() {
        return Ok(CachedArtifacts {
            semantic_keys: BTreeSet::new(),
            prefetch_artifacts: Vec::new(),
        });
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

    let reachable = resolve_reachable_cached_rows(&key_pairs, cached_rows)?;
    let semantic_keys = reachable
        .candidates
        .iter()
        .map(|candidate| candidate.semantic_key.clone())
        .collect::<BTreeSet<_>>();
    let selected_prefetch_rows =
        select_prefetch_candidates(feature_json_by_key, root_keys, &reachable)?;
    // Prefetch the full closure of every selected candidate: the CLI's
    // injection walk loads chain dependencies locally and pays a per-artifact
    // network round trip for each one missing from the batch.
    let prefetch_artifacts = reachable.closure_artifacts(&selected_prefetch_rows);
    let mut prefetch_entries = Vec::with_capacity(prefetch_artifacts.len());
    for (crate_name_raw, c_metadata_raw) in prefetch_artifacts {
        let crate_name = CrateName::parse(crate_name_raw.as_str())
            .map_err(|error| format!("prefetch crate_name `{crate_name_raw}`: {error}"))?;
        let c_metadata = CMetadata::parse(c_metadata_raw.as_str())
            .map_err(|error| format!("prefetch c_metadata `{c_metadata_raw}`: {error}"))?;
        prefetch_entries.push(BatchArtifactRequestEntry {
            crate_name,
            c_metadata,
        });
    }
    Ok(CachedArtifacts {
        semantic_keys,
        prefetch_artifacts: prefetch_entries,
    })
}

fn resolve_reachable_cached_rows(
    key_pairs: &BTreeSet<(PackageKey, String)>,
    rows: Vec<CachedArtifactRow>,
) -> Result<ReachableRows, ResolverError> {
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

    let mut kept_candidates = Vec::new();
    let mut kept_candidate_index = BTreeMap::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        if reachable_candidates.contains(&index) {
            kept_candidate_index.insert(
                (
                    canonical_crate_name(&candidate.row.crate_name),
                    candidate.row.c_metadata.clone(),
                ),
                kept_candidates.len(),
            );
            kept_candidates.push(candidate);
        }
    }
    let mut kept_chain = Vec::new();
    let mut kept_chain_index = BTreeMap::new();
    for (index, chain_row) in chain_rows.into_iter().enumerate() {
        if reachable_chain.contains(&index) {
            kept_chain_index.insert(
                (
                    canonical_crate_name(&chain_row.row.crate_name),
                    chain_row.row.c_metadata.clone(),
                ),
                kept_chain.len(),
            );
            kept_chain.push(chain_row);
        }
    }

    Ok(ReachableRows {
        candidates: kept_candidates,
        candidate_index: kept_candidate_index,
        chain_rows: kept_chain,
        chain_index: kept_chain_index,
    })
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
            row,
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
    row: CachedArtifactRow,
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

/// Reachability result: semantic candidates plus the chain-only rows their
/// closures may traverse, both restricted to fully-resolvable nodes.
#[derive(Debug)]
struct ReachableRows {
    candidates: Vec<ReachableCandidateRow>,
    candidate_index: BTreeMap<(String, String), usize>,
    chain_rows: Vec<ChainRow>,
    chain_index: BTreeMap<(String, String), usize>,
}

impl ReachableRows {
    /// Every (`crate_name`, `c_metadata`) in the transitive closure of the
    /// selected candidate indices — the exact set the CLI must hold locally
    /// to inject those candidates without per-artifact round trips.
    fn closure_artifacts(&self, selected: &BTreeSet<usize>) -> BTreeSet<(String, String)> {
        let mut visited_candidates = BTreeSet::<usize>::new();
        let mut visited_chain = BTreeSet::<usize>::new();
        let mut artifacts = BTreeSet::new();
        let mut stack: Vec<(bool, usize)> = selected.iter().map(|&index| (false, index)).collect();
        while let Some((is_chain, index)) = stack.pop() {
            let (row, identities) = if is_chain {
                if !visited_chain.insert(index) {
                    continue;
                }
                let chain_row = &self.chain_rows[index];
                (&chain_row.row, &chain_row.dependency_identities)
            } else {
                if !visited_candidates.insert(index) {
                    continue;
                }
                let candidate = &self.candidates[index];
                (&candidate.row, &candidate.dependency_identities)
            };
            artifacts.insert((row.crate_name.clone(), row.c_metadata.clone()));
            for identity in identities {
                let key = (
                    canonical_crate_name(&identity.crate_name),
                    identity.c_metadata.clone(),
                );
                if let Some(&dependency_index) = self.candidate_index.get(&key) {
                    stack.push((false, dependency_index));
                } else if let Some(&dependency_index) = self.chain_index.get(&key) {
                    stack.push((true, dependency_index));
                }
            }
        }
        artifacts
    }
}

fn select_prefetch_candidates(
    feature_json_by_key: &BTreeMap<PackageKey, String>,
    root_keys: &BTreeSet<PackageKey>,
    reachable: &ReachableRows,
) -> Result<BTreeSet<usize>, ResolverError> {
    let mut candidates_by_semantic_key = BTreeMap::<SemanticKey, Vec<usize>>::new();
    for (index, candidate) in reachable.candidates.iter().enumerate() {
        candidates_by_semantic_key
            .entry(candidate.semantic_key.clone())
            .or_default()
            .push(index);
    }
    for indices in candidates_by_semantic_key.values_mut() {
        indices.sort_by(|left, right| {
            reachable.candidates[*left]
                .row
                .c_metadata
                .cmp(&reachable.candidates[*right].row.c_metadata)
        });
    }

    // Roots are selected independently: every reachable candidate proves its
    // own closure by construction, and one uncoverable root must not zero
    // out the prefetch for everything else. Dependencies are pulled in by
    // chain identity via `ReachableRows::closure_artifacts`, so no cross-root
    // assignment consistency is required for correctness — the CLI validates
    // each injected artifact against its recorded identity chain anyway.
    let mut selected = BTreeSet::<usize>::new();
    for root_key in root_keys {
        let features_json = feature_json_by_key.get(root_key).cloned().ok_or_else(|| {
            format!(
                "missing root feature json for {} {}",
                root_key.crate_name, root_key.version
            )
        })?;
        let semantic_key = (root_key.clone(), features_json);
        let Some(indices) = candidates_by_semantic_key.get(&semantic_key) else {
            continue;
        };
        // All emit/kind variants of the root are useful: `check` injects the
        // rmeta-only artifact while `build` injects the linkable one.
        selected.extend(indices.iter().copied());
    }
    Ok(selected)
}

/// Semantic identity `(package, features_json)` used during prefetch selection.
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

    let graph = VersionGraph {
        format_version: VERSION_GRAPH_FORMAT,
        features: crates_io.version_features(crate_name, version).await?,
        dependencies: crates_io.version_dependencies(crate_name, version).await?,
    };
    let graph_json = serde_json::to_string(&graph)
        .map_err(|error| format!("serialize version graph {crate_name} {version}: {error}"))?;
    db.query(
        "INSERT INTO crate_version_graph_cache (crate_name, version, graph_json, fetched_at) \
         VALUES (?, ?, ?, datetime('now')) \
         ON CONFLICT(crate_name, version) DO UPDATE SET graph_json = excluded.graph_json, fetched_at = excluded.fetched_at",
    )
    .bind(crate_name)
    .bind(version.to_string())
    .bind(graph_json)
    .execute()
    .await
    .map_err(|error| format!("upsert crate_version_graph_cache {crate_name} {version}: {error}"))?;
    Ok(graph)
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

    let versions = crates_io.published_version_nums(crate_name).await?;
    let versions_json = serde_json::to_string(&versions)
        .map_err(|error| format!("serialize versions cache {crate_name}: {error}"))?;
    db.query(
        "INSERT INTO crate_versions_cache (crate_name, versions_json, fetched_at) \
         VALUES (?, ?, datetime('now')) \
         ON CONFLICT(crate_name) DO UPDATE SET versions_json = excluded.versions_json, fetched_at = excluded.fetched_at",
    )
    .bind(crate_name)
    .bind(versions_json.clone())
    .execute()
    .await
    .map_err(|error| format!("upsert crate_versions_cache {crate_name}: {error}"))?;
    parse_versions_json(crate_name, &versions_json)
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

pub async fn resolve_root_features(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
    version: &Version,
    seed_features: &BTreeSet<String>,
) -> Result<BTreeSet<String>, ResolverError> {
    let graph = fetch_version_graph_cached(db, crates_io, crate_name, version).await?;
    Ok(resolve_local_features(&graph, seed_features))
}

/// One root package whose seed features resolve against its published
/// crates.io feature graph.
pub struct RootFeatureRequest {
    /// Crate name.
    pub crate_name: CrateName,
    /// Exact version to resolve against.
    pub version: Version,
    /// Feature names the request seeds; names the graph does not declare
    /// are dropped by [`resolve_local_features`].
    pub seed_features: BTreeSet<String>,
}

/// Resolve every request's seed features in one batched pass — the batch
/// endpoint's answer to [`resolve_root_features`], which is the per-request
/// path. The `crate_version_graph_cache` rows for all requested
/// `(crate_name, version)` pairs load in pair-keyed IN-clause batches under
/// the same TTL the single-row load applies; pairs with no current-format
/// fresh row fetch crates.io with at most `fetch_concurrency` requests in
/// flight, and the fresh graphs write back in multi-row upsert batches. A
/// `max_expanded_tasks`-sized direct list therefore costs a handful of D1
/// statements instead of a read and a write per entry.
///
/// Returns one resolved feature set per input request, in input order.
pub async fn resolve_root_features_batch(
    db: &Db,
    crates_io: &impl CratesIo,
    requests: &[RootFeatureRequest],
    fetch_concurrency: usize,
) -> Result<Vec<BTreeSet<String>>, ResolverError> {
    let keys = requests
        .iter()
        .map(|request| PackageKey {
            crate_name: request.crate_name.clone(),
            version: request.version.clone(),
        })
        .collect::<BTreeSet<_>>();
    let mut graphs = load_version_graph_cache(db, &keys).await?;

    let cold = keys
        .iter()
        .filter(|key| !graphs.contains_key(*key))
        .cloned()
        .collect::<Vec<_>>();
    let fetched = stream::iter(cold)
        .map(|key| async move {
            let graph = VersionGraph {
                format_version: VERSION_GRAPH_FORMAT,
                features: crates_io
                    .version_features(key.crate_name.as_str(), &key.version)
                    .await?,
                dependencies: crates_io
                    .version_dependencies(key.crate_name.as_str(), &key.version)
                    .await?,
            };
            Ok::<_, ResolverError>((key, graph))
        })
        .buffer_unordered(fetch_concurrency)
        .collect::<Vec<_>>()
        .await;
    let mut fresh = Vec::with_capacity(fetched.len());
    for result in fetched {
        let (key, graph) = result?;
        let graph_json = serde_json::to_string(&graph).map_err(|error| {
            format!(
                "serialize version graph {} {}: {error}",
                key.crate_name, key.version
            )
        })?;
        fresh.push((key.clone(), graph_json));
        graphs.insert(key, graph);
    }
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
        query
            .execute()
            .await
            .map_err(|error| format!("upsert crate_version_graph_cache batch: {error}"))?;
    }

    requests
        .iter()
        .map(|request| {
            let key = PackageKey {
                crate_name: request.crate_name.clone(),
                version: request.version.clone(),
            };
            let graph = graphs.get(&key).ok_or_else(|| {
                ResolverError::Invariant(format!(
                    "resolved version graph missing for {} {}",
                    key.crate_name, key.version
                ))
            })?;
            Ok(resolve_local_features(graph, &request.seed_features))
        })
        .collect()
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
    let dep_referenced = graph
        .features
        .values()
        .flat_map(|items| items.iter())
        .filter_map(|item| item.strip_prefix("dep:"))
        .collect::<BTreeSet<_>>();
    let implicit_features = graph
        .dependencies
        .iter()
        .filter(|dependency| dependency.optional)
        .map(|dependency| dependency.crate_id.as_str())
        .filter(|name| !dep_referenced.contains(name))
        .collect::<BTreeSet<_>>();
    let mut features = seed_features
        .iter()
        .filter(|feature| {
            graph.features.contains_key(feature.as_str())
                || implicit_features.contains(feature.as_str())
        })
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

/// Canonicalize one enqueue request: snap the version to the newest
/// semver-compatible release and resolve the seed features against the
/// crate's real feature graph (bogus seeds are dropped inside
/// [`resolve_root_features`]). `None` means no canonical task exists — the
/// request names a version crates.io does not publish — so no task id is
/// ever minted for it.
async fn canonicalize_enqueue_request(
    db: &Db,
    crates_io: &impl CratesIo,
    request: EnqueueRequest,
) -> Result<Option<EnqueueRequest>, ResolverError> {
    let requested_version = request.version.as_semver().clone();
    let Some(canonical_version) = resolve_dependency_version(
        db,
        crates_io,
        request.crate_name.as_str(),
        compatible_requirement(&requested_version).as_str(),
    )
    .await?
    else {
        return Ok(None);
    };
    let seed_features = normalize_feature_set(request.features_json.features().to_vec())?;
    let features = resolve_root_features(
        db,
        crates_io,
        request.crate_name.as_str(),
        &canonical_version,
        &seed_features,
    )
    .await?;
    let features_json = canonical_features_from_set(&features)?;
    let mut depends_on = Vec::with_capacity(request.depends_on.len());
    for dependency in request.depends_on {
        match canonicalize_enqueue_dependency(db, crates_io, dependency).await? {
            Some(dependency) => depends_on.push(dependency),
            None => return Ok(None),
        }
    }
    Ok(Some(EnqueueRequest {
        version: CrateVersion::new(canonical_version),
        features_json,
        depends_on,
        ..request
    }))
}

async fn canonicalize_enqueue_dependency(
    db: &Db,
    crates_io: &impl CratesIo,
    dependency: EnqueueDependency,
) -> Result<Option<EnqueueDependency>, ResolverError> {
    let requested_version = dependency.version.as_semver().clone();
    let Some(canonical_version) = resolve_dependency_version(
        db,
        crates_io,
        dependency.crate_name.as_str(),
        compatible_requirement(&requested_version).as_str(),
    )
    .await?
    else {
        return Ok(None);
    };
    let features = dependency.features_json.features().to_vec();
    let features = normalize_feature_set(features)?;
    Ok(Some(EnqueueDependency {
        version: CrateVersion::new(canonical_version),
        features_json: canonical_features_from_set(&features)?,
        ..dependency
    }))
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
    use std::collections::BTreeSet;

    use semver::Version;
    use stow_types::api::{
        DependencyGraphEntry, ResolvedDependencyGraphDependency, ResolvedDependencyGraphEntry,
    };
    use stow_types::identity::CrateName;

    use super::{
        CachedArtifactRow, PackageKey, exact_graph_from_request, resolve_reachable_cached_rows,
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
            exact_graph.expanded_entries.iter().find(|entry| {
                entry.crate_name == libm_key.crate_name && entry.version == libm_key.version
            }),
            Some(&DependencyGraphEntry {
                crate_name: libm_key.crate_name.clone(),
                version: libm_key.version.clone(),
                features: Vec::new(),
            }),
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

        assert_eq!(reachable.candidates.len(), 2);
        assert_eq!(reachable.candidates[0].row.crate_name, "same-file");
        assert_eq!(reachable.candidates[1].row.crate_name, "walkdir");
        assert!(reachable.chain_rows.is_empty());
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

        assert!(reachable.candidates.is_empty());
    }

    #[test]
    fn chain_only_rows_satisfy_reachability_and_join_the_prefetch_closure() {
        // walkdir semantically matches the request; its chain references a
        // same-file artifact whose features do NOT match this request's
        // semantic keys (another preheat's unification). The candidate must
        // stay reachable and the chain row must ride along in the closure.
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

        assert_eq!(reachable.candidates.len(), 1);
        assert_eq!(reachable.candidates[0].row.crate_name, "walkdir");
        assert_eq!(reachable.chain_rows.len(), 1);
        assert_eq!(reachable.chain_rows[0].row.crate_name, "same-file");

        let closure = reachable.closure_artifacts(&BTreeSet::from([0]));
        assert!(closure.contains(&("walkdir".to_owned(), "1c0d7420b566b7a2".to_owned())));
        assert!(closure.contains(&("same-file".to_owned(), "72e2ded9fa67e0a1".to_owned())));
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

        assert_eq!(reachable.candidates.len(), 1);
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

        assert_eq!(reachable.candidates.len(), 2);
        assert_eq!(reachable.candidates[0].row.crate_name, "ignore");
        assert_eq!(reachable.candidates[0].row.c_metadata, "aaaaaaaaaaaaaaaa");
        assert_eq!(reachable.candidates[1].row.crate_name, "walkdir");
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
                crate_id: "foo".to_owned(),
                optional: true,
                ..CratesIoDependency::default()
            }],
        };
        assert!(resolve_local_features(&graph, &BTreeSet::from(["foo".to_owned()])).is_empty());
    }

    /// `CratesIo` stub serving canned published versions, feature maps, and
    /// dependency lists, so canonicalization runs entirely off-network in
    /// tests.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) struct StubCratesIo {
        pub(super) versions: std::collections::BTreeMap<String, Vec<String>>,
        pub(super) features: std::collections::BTreeMap<
            (String, String),
            std::collections::BTreeMap<String, Vec<String>>,
        >,
        pub(super) dependencies:
            std::collections::BTreeMap<(String, String), Vec<super::CratesIoDependency>>,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl super::CratesIo for StubCratesIo {
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "the CratesIo trait signature is async; the stub has nothing to await"
        )]
        async fn version_features(
            &self,
            crate_name: &str,
            version: &Version,
        ) -> Result<std::collections::BTreeMap<String, Vec<String>>, super::ResolverError> {
            Ok(self
                .features
                .get(&(crate_name.to_owned(), version.to_string()))
                .cloned()
                .unwrap_or_default())
        }

        #[expect(
            clippy::unused_async_trait_impl,
            reason = "the CratesIo trait signature is async; the stub has nothing to await"
        )]
        async fn version_dependencies(
            &self,
            crate_name: &str,
            version: &Version,
        ) -> Result<Vec<super::CratesIoDependency>, super::ResolverError> {
            Ok(self
                .dependencies
                .get(&(crate_name.to_owned(), version.to_string()))
                .cloned()
                .unwrap_or_default())
        }

        /// Crates absent from `versions` model a crates.io 404 — the
        /// crate is not published at all, distinct from one published
        /// with no matching version (`versions` entry with an empty or
        /// non-matching list).
        #[expect(
            clippy::unused_async_trait_impl,
            reason = "the CratesIo trait signature is async; the stub has nothing to await"
        )]
        async fn published_version_nums(
            &self,
            crate_name: &str,
        ) -> Result<Vec<String>, super::ResolverError> {
            self.versions.get(crate_name).cloned().ok_or_else(|| {
                super::ResolverError::CrateNotPublished {
                    crate_name: crate_name.to_owned(),
                }
            })
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
            project_source: None,
        }
    }
}

/// Async resolver tests: drive canonicalization against a real in-memory
/// `SQLite` so the versions/graph cache tables the resolver writes are
/// exercised by the same statements production runs.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod sqlite_tests {
    use std::collections::BTreeMap;

    use super::tests::{StubCratesIo, enqueue_request};

    #[tokio::test]
    async fn canonicalize_snaps_version_and_drops_bogus_features() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::ensure_schema(&db).await.expect("schema");
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
        };

        let canonical = super::canonicalize_enqueue_requests(
            &db,
            &crates_io,
            vec![enqueue_request("serde", "1.0.0", &["bogus", "derive"])],
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
        crate::db::ensure_schema(&db).await.expect("schema");
        let crates_io = StubCratesIo {
            versions: BTreeMap::from([("serde".to_owned(), vec!["1.0.5".to_owned()])]),
            features: BTreeMap::new(),
            dependencies: BTreeMap::new(),
        };

        // No published version satisfies ^9.9.9 — no task id is minted.
        let canonical = super::canonicalize_enqueue_requests(
            &db,
            &crates_io,
            vec![
                enqueue_request("serde", "9.9.9", &[]),
                enqueue_request("serde", "1.0.0", &[]),
            ],
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
        crate::db::ensure_schema(&db).await.expect("schema");
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
                    crate_id: "serde".to_owned(),
                    optional: true,
                    ..super::CratesIoDependency::default()
                }],
            )]),
        };

        let canonical = super::canonicalize_enqueue_requests(
            &db,
            &crates_io,
            vec![enqueue_request("slab", "0.4.11", &["serde", "bogus"])],
        )
        .await
        .expect("canonicalize");

        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical[0].features_json.features(), &["serde".to_owned()]);
    }

    use std::collections::BTreeSet;

    use stow_types::api::{
        CrateRequestState, EnqueueSource, QueueTaskStatus, RequestStatus, TaskLane,
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
        }
    }

    #[tokio::test]
    async fn expand_crate_request_enqueues_full_closure_in_human_lane() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::ensure_schema(&db).await.expect("schema");
        let crates_io = closure_stub();

        let plan = super::expand_crate_request(
            &db,
            &crates_io,
            &CrateName::parse("root").expect("name"),
            &semver::Version::parse("1.0.0").expect("version"),
            &BTreeSet::from(["default".to_owned()]),
            &linux_target(),
            &rustc(),
        )
        .await
        .expect("expand");

        assert!(!plan.root_cached);
        // lib-a resolves ^2.0 to 2.1.0; transitive rides along via the
        // build edge; dev-only and win-only are excluded on linux.
        let mut names = plan
            .enqueue_requests
            .iter()
            .map(|request| request.crate_name.as_str().to_owned())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(names, vec!["lib-a", "root", "transitive"]);
        assert!(
            plan.enqueue_requests
                .iter()
                .all(|request| request.source == EnqueueSource::HumanRequest),
            "every closure task must enter the human lane"
        );

        let lib_a = plan
            .enqueue_requests
            .iter()
            .find(|request| request.crate_name.as_str() == "lib-a")
            .expect("lib-a task");
        assert_eq!(lib_a.version.to_string(), "2.1.0");
        let root = plan
            .enqueue_requests
            .iter()
            .find(|request| request.crate_name.as_str() == "root")
            .expect("root task");
        assert_eq!(root.depends_on.len(), 1);
        assert_eq!(root.depends_on[0].crate_name.as_str(), "lib-a");
        assert_eq!(
            lib_a
                .depends_on
                .iter()
                .map(|dependency| dependency.crate_name.as_str())
                .collect::<Vec<_>>(),
            vec!["transitive"]
        );
    }

    #[tokio::test]
    async fn expand_crate_request_includes_platform_deps_only_on_matching_target() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::ensure_schema(&db).await.expect("schema");
        let crates_io = closure_stub();

        let windows = TargetTriple::parse(WINDOWS_TARGET).expect("target");
        let plan = super::expand_crate_request(
            &db,
            &crates_io,
            &CrateName::parse("root").expect("name"),
            &semver::Version::parse("1.0.0").expect("version"),
            &BTreeSet::from(["default".to_owned()]),
            &windows,
            &rustc(),
        )
        .await
        .expect("expand");

        assert!(
            plan.enqueue_requests
                .iter()
                .any(|request| request.crate_name.as_str() == "win-only"),
            "cfg(windows) dep must join the closure on a windows target"
        );
        assert!(
            plan.enqueue_requests
                .iter()
                .all(|request| request.target.as_str() == WINDOWS_TARGET)
        );
    }

    #[tokio::test]
    async fn expand_crate_request_reports_root_cached_and_skips_it() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::ensure_schema(&db).await.expect("schema");
        let crates_io = closure_stub();
        crate::db::insert_artifact_record(
            &db,
            &stow_types::api::ArtifactRecord {
                compile_key: "aaaaaaaaaaaaaaaaffffffffffffffff".to_owned(),
                c_metadata: stow_types::identity::CMetadata::parse("aaaaaaaaaaaaaaaa")
                    .expect("c_metadata"),
                extra_filename: "-aaaaaaaaaaaaaaaa".to_owned(),
                target: linux_target(),
                rustc_version: rustc(),
                profile: stow_types::platform::Profile {
                    opt_level: "0".to_owned(),
                    debuginfo: 0,
                    debug_assertions: true,
                    overflow_checks: true,
                    panic: stow_types::platform::PanicStrategy::Unwind,
                },
                emit: vec!["link".to_owned()],
                crate_name: CrateName::parse("root").expect("name"),
                version: CrateVersion::new(semver::Version::parse("1.0.0").expect("version")),
                features_json: FeaturesJson::canonicalize(vec!["default".to_owned()])
                    .expect("features"),
                dependency_c_metadata_json: stow_types::identity::DependencyCMetadataJson::default(
                ),
                oci_reference:
                    "ghcr.io/water-rs/stow-cache:root.1.0.0-x86_64-linux-1.85.0-abcdef012345-aaaaaaaaaaaaaaaa"
                        .to_owned(),
                oci_digest:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                has_native: false,
                artifact_kind: stow_types::artifact::ArtifactKind::Rlib,
                crate_types: vec![stow_types::artifact::RustCrateType::Rlib],
                artifact_size: 1,
            },
        )
        .await
        .expect("insert artifact");

        let plan = super::expand_crate_request(
            &db,
            &crates_io,
            &CrateName::parse("root").expect("name"),
            &semver::Version::parse("1.0.0").expect("version"),
            &BTreeSet::from(["default".to_owned()]),
            &linux_target(),
            &rustc(),
        )
        .await
        .expect("expand");

        assert!(plan.root_cached);
        assert!(
            plan.enqueue_requests
                .iter()
                .all(|request| request.crate_name.as_str() != "root"),
            "a cached root must not be re-enqueued"
        );
        assert!(
            plan.enqueue_requests
                .iter()
                .any(|request| request.crate_name.as_str() == "lib-a")
        );
    }

    #[tokio::test]
    async fn latest_published_version_picks_newest_stable() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::ensure_schema(&db).await.expect("schema");
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
        crate::db::ensure_schema(&db).await.expect("schema");
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
        crate::db::ensure_schema(&db).await.expect("schema");
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
        };

        let cached = super::crate_request_target(&target, "task", true, false, None)
            .expect("cached outcome");
        assert_eq!(cached.state, CrateRequestState::Cached);
        assert_eq!(cached.task_id, None);

        let queued = super::crate_request_target(
            &target,
            "task",
            false,
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
            Some(&status(QueueTaskStatus::Pending, Some(1))),
        )
        .expect("already queued outcome");
        assert_eq!(already.state, CrateRequestState::AlreadyQueued);

        let building = super::crate_request_target(
            &target,
            "task",
            false,
            true,
            Some(&status(QueueTaskStatus::Running, None)),
        )
        .expect("building outcome");
        assert_eq!(building.state, CrateRequestState::Building);
        assert_eq!(building.human_lane_position, None);

        assert!(
            super::crate_request_target(&target, "task", false, false, None).is_err(),
            "a non-cached root without a queue row is an invariant violation"
        );
    }

    /// The batched cache read returns only TTL-fresh, current-format rows:
    /// `warm` is a hit, `stale` is past the 6-hour TTL and `absent` has no
    /// row — both become cold fetches upstream.
    #[tokio::test]
    async fn batched_version_graph_cache_read_splits_hits_misses_and_expired() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::ensure_schema(&db).await.expect("schema");

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

    /// The issue-81 scenario: a fully cold 600-entry analysis runs the
    /// batched read → bounded fetch → batched upsert → batched miss-record
    /// pipeline to completion and records one miss per uncovered expanded
    /// node.
    #[tokio::test]
    async fn analyze_cold_600_entry_graph_records_600_misses() {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::ensure_schema(&db).await.expect("schema");
        // Every (crate, version) misses the stub's maps too: features and
        // dependencies come back empty, so all 600 entries are cold and
        // resolve to the canonical empty feature set.
        let crates_io = StubCratesIo {
            versions: BTreeMap::new(),
            features: BTreeMap::new(),
            dependencies: BTreeMap::new(),
        };
        let entries = (0..600)
            .map(|index| stow_types::api::DependencyGraphEntry {
                crate_name: CrateName::parse(format!("dep-{index:04}")).expect("name"),
                version: semver::Version::parse("1.0.0").expect("version"),
                features: Vec::new(),
            })
            .collect::<Vec<_>>();
        let expanded = entries
            .iter()
            .map(|entry| stow_types::api::ResolvedDependencyGraphEntry {
                crate_name: entry.crate_name.clone(),
                version: entry.version.clone(),
                features: entry.features.clone(),
                dependencies: Vec::new(),
            })
            .collect::<Vec<_>>();

        let outcome = crate::db::analyze_dependency_graph(
            &db, &crates_io, TARGET, RUSTC, &entries, &expanded, 8,
        )
        .await
        .expect("analysis");

        assert_eq!(outcome.enqueue_requests.len(), 600);
        let miss_rows = db
            .query("SELECT COUNT(*) FROM dependency_graph_misses")
            .fetch_scalar::<u64>()
            .await
            .expect("miss count");
        assert_eq!(miss_rows, 600);
        // Every fresh graph landed in the cache, so a warm pass fetches
        // nothing from crates.io.
        let cache_rows = db
            .query("SELECT COUNT(*) FROM crate_version_graph_cache")
            .fetch_scalar::<u64>()
            .await
            .expect("cache count");
        assert_eq!(cache_rows, 600);
    }
}

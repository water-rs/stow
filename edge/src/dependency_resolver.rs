use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use semver::{Version, VersionReq};
use stow_types::api::{
    CrateRequestState, CrateRequestTarget, DependencyGraphEntry, EnqueueRequest, EnqueueSource,
    QueueTaskStatus, ResolvedDependencyGraphEntry, runner_family,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};
use stow_types::node_profile::NodeProfile;
use stow_types::public_cache::ExplicitSpelling;
use stow_types::task_graph::{DigestEntry, TaskNodeIdentity, shared_dependency_identities};

use crate::errors::ResolverError;

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

/// Format tag stored inside every cached version-graph payload. Version 1 is the pre-tag shape — rows without this field (or
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

/// Where the resolver's crates.io answers are cached — the Workers
/// Cache API (`CfCache`) in production, a stub in host tests, the same
/// seam [`crate::rust_channel::ChannelCache`] uses. `get` serves a
/// still-fresh value or `None`; `put` stores under the caller's key with
/// the shared TTL the caller's [`CACHE_TTL_SECONDS`] sets on the stored
/// response.
pub trait CratesIoCache: Sync {
    /// The stored body under `key`, or `None` when absent or expired.
    fn get(&self, key: &str)
    -> impl Future<Output = Result<Option<Vec<u8>>, ResolverError>> + Send;

    /// Store `body` under `key`.
    fn put(&self, key: &str, body: &[u8])
    -> impl Future<Output = Result<(), ResolverError>> + Send;
}

/// The Workers-Cache entry lifetime for crates.io answers — the same
/// six hours the cache carried.
pub const CACHE_TTL_SECONDS: u32 = 6 * 60 * 60;

/// The cache key namespaces: `/crates-io/versions/<crate>` and
/// `/crates-io/version-graph/<crate>/<version>` under the internal
/// cache domain `crate::cache` prefixes.
fn versions_key(crate_name: &str) -> String {
    format!("versions/{crate_name}")
}

fn version_graph_key(crate_name: &str, version: &Version) -> String {
    format!("version-graph/{crate_name}/{version}")
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
    /// Uncovered nodes.
    pub enqueue_requests: Vec<EnqueueRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageKey {
    pub crate_name: CrateName,
    pub version: Version,
}

/// Cached per-version crates.io metadata (the Workers Cache `version-graph` entries).
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

/// Decode a stored canonical features-json string into the structured wire type.
fn parse_canonical_features_json(raw: &str) -> Result<FeaturesJson, ResolverError> {
    let parsed: Vec<String> = serde_json::from_str(raw)
        .map_err(|error| ResolverError::Json(format!("parse features_json `{raw}`: {error}")))?;
    FeaturesJson::from_sorted(parsed).map_err(ResolverError::Identity)
}

pub fn expand_scheduler_requests(
    target: &str,
    rustc_version: &str,
    roots: &[DependencyGraphEntry],
    expanded_entries: &[ResolvedDependencyGraphEntry],
) -> Result<ExpandedSchedulerPlan, ResolverError> {
    let target_typed = TargetTriple::parse(target).map_err(|error| error.to_string())?;
    let rustc_version_typed =
        WireRustcVersion::parse(rustc_version).map_err(|error| error.to_string())?;
    let exact_graph = exact_graph_from_request(roots, expanded_entries)?;
    // A consumer target outside `CI_TARGET_TRIPLES` has no runner
    // family, so its host units have no host triple to mint on —
    // refuse rather than mint nodes that block their dependents.
    if runner_family(target).is_none()
        && exact_graph
            .dependency_keys_by_key
            .keys()
            .any(|key| key.host_side)
    {
        return Err(ResolverError::BadRequest(format!(
            "`{target}` is not a CI target; host units cannot be minted for it"
        )));
    }
    // Every entry's dependency subgraph is client-supplied — minted
    // off the build's own `cargo --unit-graph` — so a dep the coverage
    // prune drops still carries its real context (stow#588). The
    // explicit-spelling flag travels the same way: the caller derived
    // it from its unit graph, and the edge answers it for coverage,
    // the queue row and the dispatched payload (stow#736). One shared
    // bottom-up pass over the subgraphs' union yields each node's
    // Merkle dependency digest — the context an artifact must have
    // been published under to cover it (stow#790) — and is the wire's
    // resolve check: a subgraph that does not resolve, or two
    // declarations of one node that disagree, is refused rather than
    // minted (stow#588). The declared-id check still rides the ticket
    // path — `/api/v1/enqueue` already refuses
    // `ticket.task_id != request.task_id()`.
    let context_by_key = node_contexts(
        &exact_graph,
        expanded_entries,
        &target_typed,
        &rustc_version_typed,
    )?;
    let requests = build_enqueue_requests(
        &exact_graph.feature_json_by_key,
        &exact_graph.dependency_keys_by_key,
        &context_by_key,
        &target_typed,
        &rustc_version_typed,
        EnqueueSource::CacheMiss,
    )?;
    Ok(ExpandedSchedulerPlan {
        enqueue_requests: requests,
    })
}

/// The per-node context map for `expanded_entries`: each entry's
/// carried subgraph and its explicit-spelling flag. The shared
/// bottom-up pass over the subgraphs' union is the wire's resolve
/// check (stow#588): a subgraph that does not resolve, or two
/// declarations of one node that disagree, is refused rather than
/// minted. The digest itself is not carried — the task id recomputes
/// it from the submitted subgraph.
fn node_contexts(
    exact_graph: &ExactExpandedGraph,
    expanded_entries: &[ResolvedDependencyGraphEntry],
    target_typed: &TargetTriple,
    rustc_version_typed: &WireRustcVersion,
) -> Result<BTreeMap<ExpandedNodeKey, ExpandedNodeContext>, ResolverError> {
    let mut identities = Vec::with_capacity(expanded_entries.len());
    for entry in expanded_entries {
        let key = ExpandedNodeKey {
            package: PackageKey {
                crate_name: entry.crate_name.clone(),
                version: entry.version.clone(),
            },
            host_side: entry.host_side,
            profile: entry.profile,
        };
        let features_json = exact_graph.feature_json_by_key.get(&key).ok_or_else(|| {
            ResolverError::Invariant(format!(
                "missing serialized feature set for {} {}",
                key.package.crate_name, key.package.version
            ))
        })?;
        identities.push(TaskNodeIdentity {
            crate_name: entry.crate_name.clone(),
            version: CrateVersion::new(entry.version.clone()),
            features_json: parse_canonical_features_json(features_json)?,
            target: node_target(&key, target_typed),
            rustc_version: rustc_version_typed.clone(),
            host_side: entry.host_side,
            profile: entry.profile,
        });
    }
    let digest_entries = expanded_entries
        .iter()
        .zip(&identities)
        .map(|(entry, identity)| DigestEntry {
            identity,
            root_spelling: entry.explicit_spelling,
            subgraph: &entry.dependency_subgraph,
        })
        .collect::<Vec<_>>();
    shared_dependency_identities(&digest_entries).map_err(|error| {
        ResolverError::BadRequest(format!("dependency subgraphs do not resolve: {error}"))
    })?;
    let mut context_by_key = BTreeMap::new();
    for entry in expanded_entries {
        let key = ExpandedNodeKey {
            package: PackageKey {
                crate_name: entry.crate_name.clone(),
                version: entry.version.clone(),
            },
            host_side: entry.host_side,
            profile: entry.profile,
        };
        if context_by_key
            .insert(
                key,
                ExpandedNodeContext {
                    subgraph: entry.dependency_subgraph.clone(),
                    explicit_spelling: entry.explicit_spelling,
                },
            )
            .is_some()
        {
            return Err(ResolverError::Invariant(format!(
                "duplicate expanded dependency graph entry for {} {}",
                entry.crate_name, entry.version
            )));
        }
    }
    Ok(context_by_key)
}

/// The platform a node's task keys on: the consumer's target for
/// target-side nodes, the runner family's host triple for host-side
/// nodes. `expand_scheduler_requests` refuses a host-side graph on a
/// target outside every family before this runs, so the fallback here
/// is unreachable in practice.
fn node_target(node_key: &ExpandedNodeKey, target_typed: &TargetTriple) -> TargetTriple {
    let triple = if node_key.host_side {
        runner_family(target_typed.as_str())
            .map_or_else(|| target_typed.as_str(), |family| family.host_triple())
    } else {
        target_typed.as_str()
    };
    TargetTriple::parse(triple).expect("triples come from the runner family")
}

/// Turn an exact graph (`feature_json_by_key` + `dependency_keys_by_key`)
/// into one [`EnqueueRequest`] per node the cache does not already cover.
/// `source` decides the scheduler lane the tasks land in: the miss path
/// passes [`EnqueueSource::CacheMiss`], the human request API passes
/// [`EnqueueSource::HumanRequest`].
fn build_enqueue_requests(
    feature_json_by_key: &BTreeMap<ExpandedNodeKey, String>,
    dependency_keys_by_key: &BTreeMap<ExpandedNodeKey, BTreeSet<ExpandedNodeKey>>,
    context_by_key: &BTreeMap<ExpandedNodeKey, ExpandedNodeContext>,
    target_typed: &TargetTriple,
    rustc_version_typed: &WireRustcVersion,
    source: EnqueueSource,
) -> Result<Vec<EnqueueRequest>, ResolverError> {
    let mut requests = Vec::<EnqueueRequest>::new();
    for node_key in dependency_keys_by_key.keys() {
        let features_json = feature_json_by_key.get(node_key).cloned().ok_or_else(|| {
            format!(
                "missing serialized feature set for {} {}",
                node_key.package.crate_name, node_key.package.version
            )
        })?;
        let features_json_typed = parse_canonical_features_json(features_json.as_str())?;
        let context = context_by_key.get(node_key).ok_or_else(|| {
            format!(
                "missing node context for {} {}",
                node_key.package.crate_name, node_key.package.version
            )
        })?;
        let request = EnqueueRequest {
            crate_name: node_key.package.crate_name.clone(),
            version: CrateVersion::new(node_key.package.version.clone()),
            features_json: features_json_typed,
            target: node_target(node_key, target_typed),
            rustc_version: rustc_version_typed.clone(),
            downloads: 0,
            source,
            dependency_subgraph: context.subgraph.clone(),
            preserve_lockfile: false,
            host_side: node_key.host_side,
            profile: node_key.profile,
            explicit_spelling: context.explicit_spelling,
        };
        // The subgraph already resolved when the node's context was
        // built — a wire that does not resolve never mints a context
        // (stow#588), and its digest is what the coverage prune keyed
        // on (stow#790).
        requests.push(request);
    }
    Ok(requests)
}

/// Newest non-prerelease, non-yanked published version of `crate_name`, or
/// `None` when the crate has no stable release. `*` never matches
/// prereleases and `published_version_nums` already drops yanked releases.
pub async fn latest_published_version(
    cache: &impl CratesIoCache,
    crates_io: &impl CratesIo,
    crate_name: &str,
) -> Result<Option<Version>, ResolverError> {
    resolve_dependency_version(cache, crates_io, crate_name, "*").await
}

/// `Some(version)` when `crate_name@version` is published and not yanked.
pub async fn published_version(
    cache: &impl CratesIoCache,
    crates_io: &impl CratesIo,
    crate_name: &str,
    version: &Version,
) -> Result<Option<Version>, ResolverError> {
    resolve_dependency_version(cache, crates_io, crate_name, &format!("={version}")).await
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
        // A row the submit just resurrected out of `failed` is queued
        // work again — only the pre-existing-row flag separates the two
        // queued reports. `blocked` is still queued work: the
        // dependency it waits on is what's failed, not the request.
        QueueTaskStatus::Pending | QueueTaskStatus::Blocked | QueueTaskStatus::Failed => {
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

/// A node of the expanded graph keyed on crate, version, and host
/// side — the same package a build needs on both sides is two nodes,
/// one compiling for the consumer's target and one for the runner
/// family's host.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExpandedNodeKey {
    /// Crate and version.
    package: PackageKey,
    /// Whether the node compiles for the build host.
    host_side: bool,
    /// The named profile the node builds under.
    profile: NodeProfile,
}

struct ExactExpandedGraph {
    feature_json_by_key: BTreeMap<ExpandedNodeKey, String>,
    dependency_keys_by_key: BTreeMap<ExpandedNodeKey, BTreeSet<ExpandedNodeKey>>,
}

/// What one expanded-graph entry carries per node: the client-minted
/// dependency subgraph, the explicit-spelling flag the caller derived
/// from its unit graph (stow#736), and the node's Merkle dependency
/// digest resolved out of that subgraph — the context an artifact must
/// have been published under to count as covering the node (stow#790).
struct ExpandedNodeContext {
    subgraph: stow_types::api::TaskSubgraph,
    explicit_spelling: ExplicitSpelling,
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

    let mut feature_json_by_key = BTreeMap::<ExpandedNodeKey, String>::new();
    let mut dependency_keys_by_key = BTreeMap::<ExpandedNodeKey, BTreeSet<ExpandedNodeKey>>::new();

    for entry in expanded_entries {
        let key = ExpandedNodeKey {
            package: PackageKey {
                crate_name: entry.crate_name.clone(),
                version: entry.version.clone(),
            },
            host_side: entry.host_side,
            profile: entry.profile,
        };
        let features = normalize_feature_set(entry.features.clone())?;
        let features_json = serialize_feature_set(&features)?;
        if feature_json_by_key
            .insert(key.clone(), features_json)
            .is_some()
        {
            return Err(ResolverError::Invariant(format!(
                "duplicate expanded dependency graph entry for {} {}",
                key.package.crate_name, key.package.version
            )));
        }
        let dependency_keys = entry
            .dependencies
            .iter()
            .map(|dependency| ExpandedNodeKey {
                package: PackageKey {
                    crate_name: dependency.crate_name.clone(),
                    version: dependency.version.clone(),
                },
                host_side: dependency.host_side,
                profile: dependency.profile,
            })
            .collect::<BTreeSet<_>>();
        dependency_keys_by_key.insert(key.clone(), dependency_keys);
    }

    for (node_key, dependency_keys) in &dependency_keys_by_key {
        for dependency_key in dependency_keys {
            if feature_json_by_key.contains_key(dependency_key) {
                continue;
            }
            return Err(ResolverError::Invariant(format!(
                "expanded dependency graph is missing {} {} required by {} {}",
                dependency_key.package.crate_name,
                dependency_key.package.version,
                node_key.package.crate_name,
                node_key.package.version
            )));
        }
    }

    for root in roots {
        let root_key = PackageKey {
            crate_name: root.crate_name.clone(),
            version: root.version.clone(),
        };
        if !feature_json_by_key
            .keys()
            .any(|key| key.package == root_key)
        {
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

async fn fetch_version_graph_cached(
    cache: &impl CratesIoCache,
    crates_io: &impl CratesIo,
    crate_name: &str,
    version: &Version,
) -> Result<VersionGraph, ResolverError> {
    if let Some(graph_json) = cache.get(&version_graph_key(crate_name, version)).await? {
        let graph_json = String::from_utf8(graph_json).map_err(|error| {
            ResolverError::Json(format!("cached version graph is not UTF-8: {error}"))
        })?;
        // The format tag decides whether the entry is this payload shape
        // at all; only a current-format entry is parsed, and a
        // current-format entry that fails to parse is corruption, not a
        // miss.
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
    cache
        .put(
            &version_graph_key(crate_name, version),
            graph_json.as_bytes(),
        )
        .await?;
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
    cache: &impl CratesIoCache,
    crates_io: &impl CratesIo,
    crate_name: &str,
    requirement: &str,
) -> Result<Option<Version>, ResolverError> {
    let version_req = VersionReq::parse(requirement).map_err(|error| {
        ResolverError::Invariant(format!(
            "parse dependency requirement {crate_name} {requirement}: {error}"
        ))
    })?;
    let versions = fetch_versions_cached(cache, crates_io, crate_name).await?;
    Ok(versions
        .into_iter()
        .find(|version| version_req.matches(version)))
}

async fn fetch_versions_cached(
    cache: &impl CratesIoCache,
    crates_io: &impl CratesIo,
    crate_name: &str,
) -> Result<Vec<Version>, ResolverError> {
    if let Some(versions_json) = cache.get(&versions_key(crate_name)).await? {
        let versions_json = String::from_utf8(versions_json).map_err(|error| {
            ResolverError::Json(format!("cached versions list is not UTF-8: {error}"))
        })?;
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
    cache
        .put(&versions_key(crate_name), versions_json.as_bytes())
        .await?;
    parse_versions_json(crate_name, &versions_json)
}

/// Published, non-yanked versions of `crate_name`, newest first, served
/// from the same TTL-bounded Workers Cache the resolver uses.
pub async fn published_versions(
    cache: &impl CratesIoCache,
    crates_io: &impl CratesIo,
    crate_name: &str,
) -> Result<Vec<Version>, ResolverError> {
    fetch_versions_cached(cache, crates_io, crate_name).await
}

/// One published version's `[features]` table and dependency list — what a
/// caller needs to know which features it may select.
pub struct VersionFeatureGraph {
    /// Declared `[features]` table, feature name to the items it enables.
    pub features: BTreeMap<String, Vec<String>>,
    /// Declared dependencies; the optional ones carry implicit features.
    pub dependencies: Vec<CratesIoDependency>,
}

/// Fetch [`VersionFeatureGraph`] through the resolver's TTL-bounded Workers Cache
/// cache, so a catalog lookup and a graph expansion of the same version
/// share one crates.io round trip.
pub async fn version_feature_graph(
    cache: &impl CratesIoCache,
    crates_io: &impl CratesIo,
    crate_name: &str,
    version: &Version,
) -> Result<VersionFeatureGraph, ResolverError> {
    let graph = fetch_version_graph_cached(cache, crates_io, crate_name, version).await?;
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

/// Validate and deduplicate a requested feature list — the same shape check
/// `/api/v1/enqueue` applies, exposed for `POST /api/v1/requests`.
///
/// # Errors
/// [`ResolverError::Identity`] on a feature name cargo's grammar rejects.
pub fn normalize_feature_set(features: Vec<String>) -> Result<BTreeSet<String>, ResolverError> {
    let mut set = BTreeSet::<String>::new();
    for feature in features {
        stow_types::identity::validate_feature_name(feature.as_str())
            .map_err(ResolverError::Identity)?;
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
        CratesIoCache, ExpandedNodeKey, PackageKey, build_enqueue_requests,
        exact_graph_from_request,
    };

    /// The cache stub standing in for the Workers Cache API: `None` on
    /// every `get` unless a test seeds it, `put` records what would be
    /// stored.
    #[derive(Default)]
    pub(super) struct StubCache {
        pub(super) stored: std::collections::BTreeMap<String, Vec<u8>>,
        pub(super) puts: std::sync::Mutex<Vec<String>>,
        pub(super) fail_put: bool,
    }

    #[allow(clippy::unused_async_trait_impl)]
    impl CratesIoCache for StubCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, crate::errors::ResolverError> {
            Ok(self.stored.get(key).cloned())
        }

        async fn put(&self, key: &str, _body: &[u8]) -> Result<(), crate::errors::ResolverError> {
            self.puts.lock().expect("puts").push(key.to_owned());
            if self.fail_put {
                return Err(crate::errors::ResolverError::Cache(
                    "stub put rejected".to_owned(),
                ));
            }
            Ok(())
        }
    }

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
                    host_side: false,
                    explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                    dependencies: vec![ResolvedDependencyGraphDependency {
                        crate_name: libm_key.crate_name.clone(),
                        version: libm_key.version.clone(),
                        host_side: false,
                        profile: stow_types::node_profile::NodeProfile::Dev,
                    }],
                    dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                    profile: stow_types::node_profile::NodeProfile::Dev,
                },
                ResolvedDependencyGraphEntry {
                    crate_name: libm_key.crate_name.clone(),
                    version: libm_key.version.clone(),
                    features: Vec::new(),
                    host_side: false,
                    explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                    dependencies: Vec::new(),
                    dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                    profile: stow_types::node_profile::NodeProfile::Dev,
                },
            ],
        )
        .unwrap();

        let humansize_node = ExpandedNodeKey {
            package: humansize_key,
            host_side: false,
            profile: stow_types::node_profile::NodeProfile::Dev,
        };
        let libm_node = ExpandedNodeKey {
            package: libm_key,
            host_side: false,
            profile: stow_types::node_profile::NodeProfile::Dev,
        };
        assert!(
            exact_graph
                .feature_json_by_key
                .contains_key(&humansize_node)
        );
        assert!(exact_graph.feature_json_by_key.contains_key(&libm_node));
        assert!(!exact_graph.feature_json_by_key.keys().any(|node| {
            node.package.crate_name == unexpected_libm_key.crate_name
                && node.package.version == unexpected_libm_key.version
        }));
        assert_eq!(
            exact_graph.dependency_keys_by_key.get(&humansize_node),
            Some(&BTreeSet::from([libm_node.clone()])),
        );
        assert_eq!(
            exact_graph.feature_json_by_key.get(&libm_node),
            Some(&"[]".to_owned()),
        );
    }

    /// A package on both sides of the target/host split is two nodes: the
    /// wire carries `host_side` and each entry is keyed with it, so the
    /// same `(name, version)` no longer collides.
    #[test]
    fn exact_graph_keys_the_same_package_once_per_side() {
        let syn_key = key("syn", "2.0.0");
        let consumer_key = key("consumer", "1.0.0");
        let exact_graph = exact_graph_from_request(
            &[DependencyGraphEntry {
                crate_name: consumer_key.crate_name.clone(),
                version: consumer_key.version.clone(),
                features: Vec::new(),
            }],
            &[
                ResolvedDependencyGraphEntry {
                    crate_name: consumer_key.crate_name.clone(),
                    version: consumer_key.version.clone(),
                    features: Vec::new(),
                    host_side: false,
                    explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                    dependencies: vec![
                        ResolvedDependencyGraphDependency {
                            crate_name: syn_key.crate_name.clone(),
                            version: syn_key.version.clone(),
                            host_side: false,
                            profile: stow_types::node_profile::NodeProfile::Dev,
                        },
                        ResolvedDependencyGraphDependency {
                            crate_name: syn_key.crate_name.clone(),
                            version: syn_key.version.clone(),
                            host_side: true,
                            profile: stow_types::node_profile::NodeProfile::Dev,
                        },
                    ],
                    dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                    profile: stow_types::node_profile::NodeProfile::Dev,
                },
                ResolvedDependencyGraphEntry {
                    crate_name: syn_key.crate_name.clone(),
                    version: syn_key.version.clone(),
                    features: vec!["parsing".to_owned()],
                    host_side: false,
                    explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                    dependencies: Vec::new(),
                    dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                    profile: stow_types::node_profile::NodeProfile::Dev,
                },
                ResolvedDependencyGraphEntry {
                    crate_name: syn_key.crate_name.clone(),
                    version: syn_key.version.clone(),
                    features: vec!["full".to_owned(), "parsing".to_owned()],
                    host_side: true,
                    explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                    dependencies: Vec::new(),
                    dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                    profile: stow_types::node_profile::NodeProfile::Dev,
                },
            ],
        )
        .unwrap();

        let target_node = ExpandedNodeKey {
            package: syn_key.clone(),
            host_side: false,
            profile: stow_types::node_profile::NodeProfile::Dev,
        };
        let host_node = ExpandedNodeKey {
            package: syn_key,
            host_side: true,
            profile: stow_types::node_profile::NodeProfile::Dev,
        };
        assert_eq!(
            exact_graph.feature_json_by_key.get(&target_node),
            Some(&"[\"parsing\"]".to_owned()),
        );
        assert_eq!(
            exact_graph.feature_json_by_key.get(&host_node),
            Some(&"[\"full\",\"parsing\"]".to_owned()),
        );
        let consumer_node = ExpandedNodeKey {
            package: consumer_key,
            host_side: false,
            profile: stow_types::node_profile::NodeProfile::Dev,
        };
        assert_eq!(
            exact_graph.dependency_keys_by_key.get(&consumer_node),
            Some(&BTreeSet::from([target_node, host_node])),
        );
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
                crate::errors::ResolverError::CrateNotPublished {
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
            dependency_subgraph: stow_types::api::TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
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
            preserve_lockfile: false,
            host_side: false,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            profile: stow_types::node_profile::NodeProfile::Dev,
        }
    }

    /// Subgraphs minted off the exact graph the same way the wire
    /// carries them — each node's closure, covered nodes with their own
    /// feature set (stow#588).
    fn contexts(
        graph: &BTreeMap<ExpandedNodeKey, BTreeSet<ExpandedNodeKey>>,
        features: &BTreeMap<ExpandedNodeKey, String>,
    ) -> BTreeMap<ExpandedNodeKey, super::ExpandedNodeContext> {
        graph
            .keys()
            .map(|key| {
                let subgraph = subgraph_for(key, graph, features);
                (
                    key.clone(),
                    super::ExpandedNodeContext {
                        subgraph,
                        explicit_spelling: super::ExplicitSpelling::KeysAsNative,
                    },
                )
            })
            .collect()
    }

    fn subgraph_for(
        node_key: &ExpandedNodeKey,
        graph: &BTreeMap<ExpandedNodeKey, BTreeSet<ExpandedNodeKey>>,
        features: &BTreeMap<ExpandedNodeKey, String>,
    ) -> stow_types::api::TaskSubgraph {
        let mut closure = BTreeSet::new();
        let mut frontier: Vec<ExpandedNodeKey> =
            graph.get(node_key).into_iter().flatten().cloned().collect();
        while let Some(next) = frontier.pop() {
            if closure.insert(next.clone()) {
                frontier.extend(graph.get(&next).into_iter().flatten().cloned());
            }
        }
        let wire_index = |dep: &ExpandedNodeKey| {
            u32::try_from(
                closure
                    .iter()
                    .position(|key| key == dep)
                    .expect("dep in closure"),
            )
            .expect("wire index")
        };
        let nodes = closure
            .iter()
            .map(|member| stow_types::api::SubgraphNode {
                crate_name: member.package.crate_name.clone(),
                version: stow_types::identity::CrateVersion::new(member.package.version.clone()),
                features_json: features
                    .get(member)
                    .map(|raw| super::parse_canonical_features_json(raw).expect("features parse"))
                    .unwrap_or_default(),
                host_side: member.host_side,
                keys_apart: false,
                deps: graph
                    .get(member)
                    .into_iter()
                    .flatten()
                    .map(wire_index)
                    .collect(),
                profile: stow_types::node_profile::NodeProfile::Dev,
            })
            .collect();
        stow_types::api::TaskSubgraph {
            root_deps: graph
                .get(node_key)
                .into_iter()
                .flatten()
                .map(wire_index)
                .collect(),
            nodes,
        }
    }

    fn node(name: &str, host_side: bool) -> ExpandedNodeKey {
        ExpandedNodeKey {
            package: key(name, "1.0.0"),
            host_side,
            profile: stow_types::node_profile::NodeProfile::Dev,
        }
    }

    fn graph(
        edges: &[(&str, &[(&str, bool)])],
    ) -> BTreeMap<ExpandedNodeKey, BTreeSet<ExpandedNodeKey>> {
        edges
            .iter()
            .map(|(node_name, dependencies)| {
                (
                    node(node_name, false),
                    dependencies
                        .iter()
                        .map(|(dep, host_side)| node(dep, *host_side))
                        .collect(),
                )
            })
            .collect()
    }

    fn features(
        graph: &BTreeMap<ExpandedNodeKey, BTreeSet<ExpandedNodeKey>>,
    ) -> BTreeMap<ExpandedNodeKey, String> {
        graph
            .keys()
            .map(|key| (key.clone(), "[]".to_owned()))
            .collect()
    }

    fn covered(names: &[&str]) -> BTreeSet<(ExpandedNodeKey, String)> {
        names
            .iter()
            .map(|name| (node(name, false), "[]".to_owned()))
            .collect()
    }

    /// `depends_on` names the node's own task deps — the dependent
    /// dispatches only once every dep is servable — not the node that
    /// depends on it. Every candidate mints a request: the merge's
    /// born-published check is the coverage, so a dep already in the
    /// published slice resolves at merge time and never builds.
    #[test]
    fn enqueue_requests_depend_on_their_direct_dependencies() {
        let graph = graph(&[
            ("root", &[("a", false), ("b", false)]),
            ("a", &[("b", false)]),
            ("b", &[]),
        ]);
        let requests = build_enqueue_requests(
            &features(&graph),
            &graph,
            &contexts(&graph, &features(&graph)),
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
                        .depends_on()
                        .expect("deps")
                        .iter()
                        .map(|dependency| dependency.crate_name.as_str().to_owned())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            edges,
            [
                ("a".to_owned(), vec!["b".to_owned()]),
                ("b".to_owned(), Vec::new()),
                ("root".to_owned(), vec!["a".to_owned(), "b".to_owned()]),
            ]
        );
    }

    /// Host-side units mint on the consumer's runner-family host triple,
    /// and the edge a dependent carries into them names that same host
    /// platform — the issue-317 contract for the miss lane.
    #[test]
    fn enqueue_requests_key_host_units_on_the_family_host() {
        let mut graph = graph(&[("consumer", &[("macro-crate", true)])]);
        graph.insert(node("macro-crate", true), BTreeSet::new());
        let mut features = features(&graph);
        features.insert(node("macro-crate", true), "[]".to_owned());
        let requests = build_enqueue_requests(
            &features,
            &graph,
            &contexts(&graph, &features),
            &"wasm32-unknown-unknown".parse().expect("target"),
            &"1.98.0".parse().expect("rustc"),
            EnqueueSource::CacheMiss,
        )
        .expect("requests");

        let by_name = requests
            .iter()
            .map(|request| (request.crate_name.as_str(), request))
            .collect::<BTreeMap<_, _>>();
        let macro_request = by_name["macro-crate"];
        assert_eq!(
            macro_request.target.as_str(),
            "x86_64-unknown-linux-gnu",
            "host unit mints on the wasm32 family host"
        );
        assert!(
            macro_request.host_side,
            "the request carries the node's host side to the queue"
        );
        let consumer = by_name["consumer"];
        assert_eq!(consumer.target.as_str(), "wasm32-unknown-unknown");
        let consumer_deps = consumer.depends_on().expect("deps");
        assert_eq!(consumer_deps.len(), 1);
        assert_eq!(consumer_deps[0].crate_name.as_str(), "macro-crate");
        assert!(
            consumer_deps[0].host_side,
            "the edge names the side the dependent needs"
        );
        assert_eq!(
            consumer_deps[0].target.as_str(),
            "x86_64-unknown-linux-gnu",
            "the edge names the dep's own platform"
        );
    }

    /// The same rule on the Apple family: a host unit of an iOS consumer
    /// mints on `aarch64-apple-darwin`, not on the consumer's target.
    #[test]
    fn enqueue_requests_key_ios_host_units_on_macos() {
        let mut graph = graph(&[("consumer", &[("macro-crate", true)])]);
        graph.insert(node("macro-crate", true), BTreeSet::new());
        let mut features = features(&graph);
        features.insert(node("macro-crate", true), "[]".to_owned());
        let requests = build_enqueue_requests(
            &features,
            &graph,
            &contexts(&graph, &features),
            &"aarch64-apple-ios".parse().expect("target"),
            &"1.98.0".parse().expect("rustc"),
            EnqueueSource::CacheMiss,
        )
        .expect("requests");

        let by_name = requests
            .iter()
            .map(|request| (request.crate_name.as_str(), request))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            by_name["macro-crate"].target.as_str(),
            "aarch64-apple-darwin"
        );
        assert_eq!(
            by_name["consumer"].depends_on().expect("deps")[0]
                .target
                .as_str(),
            "aarch64-apple-darwin"
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
    use super::tests::{StubCache, StubCratesIo};

    use stow_types::api::{
        CrateRequestState, DependencyGraphEntry, QueueTaskStatus, RequestStatus,
        ResolvedDependencyGraphDependency, ResolvedDependencyGraphEntry, TaskLane,
    };
    use stow_types::identity::{
        CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
    };
    use stow_types::task_graph::TaskNodeIdentity;

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const WINDOWS_TARGET: &str = "x86_64-pc-windows-msvc";
    const RUSTC: &str = "1.85.0";

    fn wasm_target() -> TargetTriple {
        TargetTriple::parse("wasm32-unknown-unknown").expect("wasm triple")
    }

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
        let db = StubCache::default();
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
        let db = StubCache::default();
        let crates_io = closure_stub();

        let error = super::latest_published_version(&db, &crates_io, "never-published")
            .await
            .expect_err("an unpublished crate must error, not resolve to None");
        assert!(
            matches!(
                error,
                crate::errors::ResolverError::CrateNotPublished { ref crate_name }
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
            matches!(
                error,
                crate::errors::ResolverError::CrateNotPublished { .. }
            ),
            "expected CrateNotPublished, got {error:?}"
        );
    }

    /// A `graph_json` row written before `format_version` existed parses
    /// into nothing the resolver may serve: it is a cache miss and the
    /// crates.io data is fetched (and cached) fresh.
    #[tokio::test]
    async fn old_format_graph_cache_row_is_not_served() {
        let mut db = StubCache::default();
        // The v1 entry shape: no `format_version`, dependency entries the
        // current schema would reject — but none of that is reached,
        // because the tag is checked before the payload is trusted.
        db.stored.insert(
            super::version_graph_key("root", &semver::Version::parse("1.0.0").expect("version")),
            r#"{"features":{},"dependencies":[]}"#.as_bytes().to_vec(),
        );
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

    /// The issue-81/91 scenario, moved to the admissions lane: a fully
    /// uncovered `WaterUI`-scale request — 130 direct entries over an
    /// 830-node expanded graph — expands to one enqueue request per node.
    /// Misses go to the miss log as one Analytics Engine point per
    /// uncovered node.
    #[tokio::test]
    async fn admissions_uncovered_waterui_scale_graph_logs_misses() {
        const DIRECT: usize = 130;
        const EXPANDED: usize = 830;

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
                host_side: false,
                explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                dependencies: Vec::new(),
                dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                profile: stow_types::node_profile::NodeProfile::Dev,
            })
            .collect::<Vec<_>>();

        let outcome =
            expand_scheduler_requests(TARGET, RUSTC, &entries, &expanded).expect("expansion");

        assert_eq!(outcome.enqueue_requests.len(), EXPANDED);
        // Demand analytics are Analytics Engine points: the redemption
        // path writes one `graph` point per node the merge reports
        // unpublished — here every node is a miss.
        let miss_log = crate::miss_logger::RecordingMissLog::default();
        let tree = stow_types::api::SubmissionTree::from_enqueue_requests(
            stow_types::api::SubmissionSource::CacheMiss,
            &outcome.enqueue_requests,
        )
        .expect("miss tree");
        let unpublished: std::collections::BTreeSet<String> =
            tree.nodes.iter().map(|node| node.task_id.clone()).collect();
        crate::miss_logger::log_misses(
            &miss_log,
            crate::stats::AnalyticsConsent::ALLOWED,
            &tree,
            &unpublished,
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
                host_side: false,
                explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                dependencies: Vec::new(),
                dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                profile: stow_types::node_profile::NodeProfile::Dev,
            })
            .collect::<Vec<_>>();

        let error = super::exact_graph_from_request(&[], &expanded)
            .err()
            .expect("an over-limit graph must be rejected");
        match error {
            crate::errors::ResolverError::LimitExceeded { got, limit, .. } => {
                assert_eq!(got, over_limit);
                assert_eq!(limit, super::MAX_EXPANDED_TASKS);
            }
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    /// The Workers Cache contract is the `rust_channel` one: a rejected
    /// write is an error, never silently served — a broken cache entry
    /// means a bug, not a miss.
    #[tokio::test]
    async fn rejected_graph_cache_write_fails_the_request() {
        let db = StubCache {
            fail_put: true,
            ..StubCache::default()
        };
        let crates_io = StubCratesIo {
            versions: BTreeMap::from([("cfg-if".to_owned(), vec!["1.0.4".to_owned()])]),
            features: BTreeMap::from([(
                ("cfg-if".to_owned(), "1.0.4".to_owned()),
                BTreeMap::from([("rustc-dep-of-std".to_owned(), vec![])]),
            )]),
            dependencies: BTreeMap::new(),
            ..StubCratesIo::default()
        };

        let result = super::fetch_version_graph_cached(
            &db,
            &crates_io,
            "cfg-if",
            &semver::Version::parse("1.0.4").expect("version"),
        )
        .await;
        assert!(
            matches!(result, Err(crate::errors::ResolverError::Cache(_))),
            "a rejected cache write must fail the request, got {result:?}"
        );
    }

    /// A zed-shaped admissions request at the route's
    /// `MAX_EXPANDED_TASKS` cap: mostly leaves, a band of mid-size
    /// nodes, and a few broad hubs on both sides — so most entries
    /// carry small subgraphs and a minority carry real closures.
    /// Review measurement for stow#790: `node_contexts` derives every
    /// entry's dependency digest in one shared pass; the second timing
    /// re-runs the per-entry `TaskSubgraph::resolve` loop it replaced.
    /// Host CPU is an upper-bound proxy for the worker's CPU — the
    /// admission route's `WORKER_CPU_BUDGETS` row gates it relative to
    /// the Traffic cost test's reference workload.
    #[test]
    fn context_construction_at_max_admission_size() {
        const N: usize = super::MAX_EXPANDED_TASKS;
        let one_zero = || semver::Version::parse("1.0.0").expect("version");
        let identity = |index: usize, host_side: bool| TaskNodeIdentity {
            crate_name: CrateName::parse(format!("dep-{index}")).expect("name"),
            version: CrateVersion::new(one_zero()),
            features_json: FeaturesJson::canonicalize(
                index
                    .is_multiple_of(16)
                    .then(|| "std".to_owned())
                    .into_iter()
                    .collect(),
            )
            .expect("features"),
            target: if host_side {
                linux_target()
            } else {
                wasm_target()
            },
            rustc_version: rustc(),
            host_side,
            profile: stow_types::node_profile::NodeProfile::Dev,
        };
        // Deterministic zed-shaped out-degrees: ~60% leaves, ~30% light
        // (1-3 deps), ~8% mid (4-8), ~2% hubs (9-24). A tenth of nodes
        // compile host-side; every dep points strictly backward.
        let mut resolved_nodes = Vec::with_capacity(N);
        for index in 0..N {
            let width = match index % 50 {
                0..=29 => 0,
                30..=44 => 1 + index % 3,
                45..=48 => 4 + index % 5,
                _ => 9 + index % 16,
            };
            let deps = (0..width.min(index))
                .map(|d| index - 1 - (index + d) % index)
                .collect::<Vec<_>>();
            resolved_nodes.push(stow_types::task_graph::ResolvedTaskNode {
                identity: identity(index, index.is_multiple_of(10)),
                explicit_spelling: super::ExplicitSpelling::KeysAsNative,
                dependencies: deps,
            });
        }
        let resolved = stow_types::task_graph::ResolvedTaskGraph::resolve(resolved_nodes)
            .expect("fixture graph resolves");
        let entries = resolved
            .nodes()
            .iter()
            .enumerate()
            .map(|(index, node)| ResolvedDependencyGraphEntry {
                crate_name: node.identity.crate_name.clone(),
                version: node.identity.version.as_semver().clone(),
                features: node.identity.features_json.features().to_vec(),
                host_side: node.identity.host_side,
                dependencies: node
                    .dependencies
                    .iter()
                    .map(|&dep| ResolvedDependencyGraphDependency {
                        crate_name: resolved.nodes()[dep].identity.crate_name.clone(),
                        version: resolved.nodes()[dep].identity.version.as_semver().clone(),
                        host_side: resolved.nodes()[dep].identity.host_side,
                        profile: stow_types::node_profile::NodeProfile::Dev,
                    })
                    .collect(),
                dependency_subgraph: stow_types::api::TaskSubgraph::from_resolved(&resolved, index)
                    .expect("subgraph"),
                explicit_spelling: super::ExplicitSpelling::KeysAsNative,
                profile: stow_types::node_profile::NodeProfile::Dev,
            })
            .collect::<Vec<_>>();
        let wire_nodes = entries
            .iter()
            .map(|entry| entry.dependency_subgraph.nodes.len())
            .sum::<usize>();
        let roots = vec![DependencyGraphEntry {
            crate_name: CrateName::parse(format!("dep-{}", N - 1)).expect("name"),
            version: one_zero(),
            features: Vec::new(),
        }];
        let exact_graph = super::exact_graph_from_request(&roots, &entries).expect("exact graph");

        let start = std::time::Instant::now();
        let contexts = super::node_contexts(&exact_graph, &entries, &wasm_target(), &rustc())
            .expect("contexts");
        let shared = start.elapsed();
        assert_eq!(contexts.len(), N, "every expanded node gets a context");

        // The per-entry `TaskSubgraph::resolve` loop the shared pass
        // replaced — kept here so the review's cost comparison rides
        // the same fixture.
        let identities = (0..N)
            .map(|index| identity(index, index.is_multiple_of(10)))
            .collect::<Vec<_>>();
        let start = std::time::Instant::now();
        for (entry, node_identity) in entries.iter().zip(&identities) {
            std::hint::black_box(
                entry
                    .dependency_subgraph
                    .resolve(node_identity, entry.explicit_spelling)
                    .expect("resolve"),
            );
        }
        eprintln!(
            "admission context construction at {N} entries / {wire_nodes} wire nodes: \
             shared pass {shared:?}; per-entry resolve {:?}",
            start.elapsed()
        );
    }
}

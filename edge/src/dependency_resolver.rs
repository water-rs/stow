use std::collections::{BTreeMap, BTreeSet, VecDeque, btree_map::Entry};

use cargo_platform::{Cfg, Platform};
use futures_util::stream::StreamExt;
use semver::{Version, VersionReq};
use skyzen_cloudflare::{CfFetch, worker};
use skyzen_services::Db;
use stow_types::api::{
    BatchArtifactRequestEntry, DependencyGraphEntry, EnqueueDependency, EnqueueRequest,
    EnqueueSource, ResolvedDependencyGraphEntry,
};
use stow_types::public_cache::stable_c_metadata_for_compile_key;
use target_lexicon::{Endianness, Environment, OperatingSystem, Triple};

use crate::sql_batch;

const CRATES_IO_API_BASE: &str = "https://crates.io/api/v1/crates";
const CRATES_IO_USER_AGENT: &str = "stow-edge/graph-resolver";
const CACHE_TTL_SQL: &str = "-6 hours";
const MAX_EXPANDED_TASKS: usize = 4096;
const DEPENDENCY_RESOLUTION_CONCURRENCY: usize = 32;

pub struct ExpandedSchedulerPlan {
    pub enqueue_requests: Vec<EnqueueRequest>,
    pub expanded_cached: usize,
    pub expanded_total: usize,
    pub expanded_entries: Vec<DependencyGraphEntry>,
    pub prefetch_artifacts: Vec<BatchArtifactRequestEntry>,
}

pub(crate) async fn canonicalize_enqueue_requests(
    db: &Db,
    requests: Vec<EnqueueRequest>,
) -> Result<Vec<EnqueueRequest>, String> {
    let mut canonical = Vec::with_capacity(requests.len());
    for request in requests {
        canonical.push(canonicalize_enqueue_request(db, request).await?);
    }
    Ok(canonical)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PackageKey {
    crate_name: String,
    version: Version,
}

#[derive(Debug, Clone, Default)]
struct NodeState {
    features: BTreeSet<String>,
    dependencies: BTreeSet<PackageKey>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct VersionGraph {
    features: BTreeMap<String, Vec<String>>,
    dependencies: Vec<CratesIoDependency>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CratesIoDependency {
    crate_id: String,
    req: String,
    optional: bool,
    default_features: bool,
    features: Vec<String>,
    target: Option<String>,
    kind: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoVersionResponse {
    version: CratesIoVersionDetail,
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoVersionDetail {
    features: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoDependenciesResponse {
    dependencies: Vec<CratesIoDependency>,
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoCrateResponse {
    versions: Vec<CratesIoPublishedVersion>,
}

#[derive(Debug, serde::Deserialize)]
struct CratesIoPublishedVersion {
    num: String,
    yanked: bool,
}

#[derive(Debug, serde::Deserialize)]
struct VersionsCacheRow {
    versions_json: String,
}

#[derive(Debug, serde::Deserialize)]
struct GraphCacheRow {
    graph_json: String,
}

#[derive(Debug, serde::Deserialize)]
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

#[derive(Debug)]
struct DependencyRequest {
    crate_name: String,
    req: String,
    feature_seeds: BTreeSet<String>,
}

#[derive(Debug)]
struct ResolvedNode {
    local_features: BTreeSet<String>,
    dependency_requests: Vec<DependencyRequest>,
}

pub async fn expand_scheduler_requests(
    db: &Db,
    target: &str,
    rustc_version: &str,
    roots: &[DependencyGraphEntry],
    expanded_entries: &[ResolvedDependencyGraphEntry],
) -> Result<ExpandedSchedulerPlan, String> {
    let exact_graph = exact_graph_from_request(roots, expanded_entries)?;
    let cached = load_cached_artifacts(
        db,
        target,
        rustc_version,
        &exact_graph.dependency_keys_by_key,
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

    let mut requests = Vec::<EnqueueRequest>::new();
    for (node_key, dependency_keys) in exact_graph.dependency_keys_by_key {
        let features_json = exact_graph
            .feature_json_by_key
            .get(&node_key)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "missing serialized feature set for {} {}",
                    node_key.crate_name, node_key.version
                )
            })?;
        if cached
            .semantic_keys
            .contains(&(node_key.clone(), features_json.clone()))
        {
            continue;
        }
        let depends_on = dependency_keys
            .into_iter()
            .filter_map(|dependency_key| {
                let dependency_features_json = exact_graph
                    .feature_json_by_key
                    .get(&dependency_key)
                    .cloned()?;
                if cached
                    .semantic_keys
                    .contains(&(dependency_key.clone(), dependency_features_json.clone()))
                {
                    return None;
                }
                Some(EnqueueDependency {
                    crate_name: dependency_key.crate_name,
                    version: dependency_key.version.to_string(),
                    features_json: dependency_features_json,
                    target: target.to_owned(),
                    rustc_version: rustc_version.to_owned(),
                })
            })
            .collect::<Vec<_>>();
        requests.push(EnqueueRequest {
            crate_name: node_key.crate_name,
            version: node_key.version.to_string(),
            features_json,
            target: target.to_owned(),
            rustc_version: rustc_version.to_owned(),
            downloads: 0,
            source: EnqueueSource::CacheMiss,
            depends_on,
        });
    }
    Ok(ExpandedSchedulerPlan {
        enqueue_requests: requests,
        expanded_cached,
        expanded_total,
        expanded_entries: exact_graph.expanded_entries,
        prefetch_artifacts: cached.prefetch_artifacts,
    })
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
) -> Result<ExactExpandedGraph, String> {
    if expanded_entries.is_empty() {
        return Err("dependency graph request is missing expanded_entries".to_owned());
    }
    if expanded_entries.len() > MAX_EXPANDED_TASKS {
        return Err(format!(
            "expanded dependency task list exceeds limit {}",
            MAX_EXPANDED_TASKS
        ));
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
            return Err(format!(
                "duplicate expanded dependency graph entry for {} {}",
                key.crate_name, key.version
            ));
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
        normalized_entries.push(DependencyGraphEntry {
            crate_name: key.crate_name.clone(),
            version: key.version.clone(),
            features: features.into_iter().collect(),
        });
    }

    for (package_key, dependency_keys) in &dependency_keys_by_key {
        for dependency_key in dependency_keys {
            if feature_json_by_key.contains_key(dependency_key) {
                continue;
            }
            return Err(format!(
                "expanded dependency graph is missing {} {} required by {} {}",
                dependency_key.crate_name,
                dependency_key.version,
                package_key.crate_name,
                package_key.version
            ));
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
        return Err(format!(
            "expanded dependency graph is missing root {} {}",
            root_key.crate_name, root_key.version
        ));
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
    dependency_keys_by_key: &BTreeMap<PackageKey, BTreeSet<PackageKey>>,
    feature_json_by_key: &BTreeMap<PackageKey, String>,
    root_keys: &BTreeSet<PackageKey>,
) -> Result<CachedArtifacts, String> {
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

    let reachable_candidates =
        resolve_reachable_cached_rows(dependency_keys_by_key, &key_pairs, cached_rows)?;
    let semantic_keys = reachable_candidates
        .iter()
        .map(|candidate| candidate.semantic_key.clone())
        .collect::<BTreeSet<_>>();
    let selected_prefetch_rows = select_prefetch_candidates(
        dependency_keys_by_key,
        feature_json_by_key,
        root_keys,
        &reachable_candidates,
    )?;
    let mut prefetch_artifacts = BTreeSet::<(String, String)>::new();
    for index in selected_prefetch_rows {
        let row = &reachable_candidates[index].row;
        prefetch_artifacts.insert((row.crate_name.clone(), row.c_metadata.clone()));
    }
    Ok(CachedArtifacts {
        semantic_keys,
        prefetch_artifacts: prefetch_artifacts
            .into_iter()
            .map(|(crate_name, c_metadata)| BatchArtifactRequestEntry {
                crate_name,
                c_metadata,
            })
            .collect(),
    })
}

fn resolve_reachable_cached_rows(
    dependency_keys_by_key: &BTreeMap<PackageKey, BTreeSet<PackageKey>>,
    key_pairs: &BTreeSet<(PackageKey, String)>,
    rows: Vec<CachedArtifactRow>,
) -> Result<Vec<ReachableCandidateRow>, String> {
    let mut candidates = Vec::<ReachableCandidateRow>::new();
    let mut candidate_index = BTreeMap::<(String, String), usize>::new();

    for row in rows {
        if !cached_row_has_canonical_metadata(&row)? {
            continue;
        }
        let version = Version::parse(&row.version)
            .map_err(|error| format!("parse cached semver {}: {error}", row.version))?;
        let package_key = PackageKey {
            crate_name: row.crate_name.clone(),
            version,
        };
        let semantic_key = (package_key.clone(), row.features_json.clone());
        if !key_pairs.contains(&semantic_key) {
            continue;
        }
        let expected_dependency_names = dependency_keys_by_key
            .get(&package_key)
            .ok_or_else(|| {
                format!(
                    "missing resolved dependency names for {} {}",
                    package_key.crate_name, package_key.version
                )
            })?
            .iter()
            .map(|dependency_key| canonical_crate_name(&dependency_key.crate_name))
            .collect::<BTreeSet<_>>();
        let dependency_identities =
            serde_json::from_str::<Vec<DependencyIdentity>>(&row.dependency_c_metadata_json)
                .map_err(|error| {
                    format!(
                        "parse cached dependency_c_metadata_json for {} {} {}: {error}",
                        row.crate_name, row.version, row.c_metadata
                    )
                })?;
        let dependency_identities = canonicalize_dependency_identities(dependency_identities);
        let dependency_names = dependency_identities
            .iter()
            .map(|identity| canonical_crate_name(&identity.crate_name))
            .collect::<BTreeSet<_>>();
        if dependency_names != expected_dependency_names {
            continue;
        }
        let identity_key = (
            canonical_crate_name(&row.crate_name),
            row.c_metadata.clone(),
        );
        if let Some(existing_index) = candidate_index.get(&identity_key).copied() {
            if !deduplicate_cached_candidate(
                &mut candidates[existing_index],
                semantic_key,
                row,
                dependency_identities,
            ) {
                return Err(format!(
                    "conflicting cached artifact identity {} {}",
                    identity_key.0, identity_key.1
                ));
            }
            continue;
        }
        candidate_index.insert(identity_key, candidates.len());
        candidates.push(ReachableCandidateRow {
            semantic_key,
            row,
            dependency_identities,
        });
    }

    let mut reachable = BTreeSet::<usize>::new();
    let mut progressed = true;
    while progressed {
        progressed = false;
        for (index, candidate) in candidates.iter().enumerate() {
            if reachable.contains(&index) {
                continue;
            }
            let all_dependencies_reachable =
                candidate.dependency_identities.iter().all(|identity| {
                    candidate_index
                        .get(&(
                            canonical_crate_name(&identity.crate_name),
                            identity.c_metadata.clone(),
                        ))
                        .is_some_and(|dependency_index| reachable.contains(dependency_index))
                });
            if all_dependencies_reachable {
                reachable.insert(index);
                progressed = true;
            }
        }
    }

    Ok(candidates
        .into_iter()
        .enumerate()
        .filter_map(|(index, candidate)| reachable.contains(&index).then_some(candidate))
        .collect())
}

fn cached_row_has_canonical_metadata(row: &CachedArtifactRow) -> Result<bool, String> {
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
    existing: &mut ReachableCandidateRow,
    semantic_key: (PackageKey, String),
    row: CachedArtifactRow,
    dependency_identities: Vec<DependencyIdentity>,
) -> bool {
    if existing.semantic_key != semantic_key
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

fn select_prefetch_candidates(
    dependency_keys_by_key: &BTreeMap<PackageKey, BTreeSet<PackageKey>>,
    feature_json_by_key: &BTreeMap<PackageKey, String>,
    root_keys: &BTreeSet<PackageKey>,
    candidates: &[ReachableCandidateRow],
) -> Result<BTreeSet<usize>, String> {
    let mut candidates_by_semantic_key = BTreeMap::<(PackageKey, String), Vec<usize>>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        candidates_by_semantic_key
            .entry(candidate.semantic_key.clone())
            .or_default()
            .push(index);
    }
    for indices in candidates_by_semantic_key.values_mut() {
        indices.sort_by(|left, right| {
            candidates[*left]
                .row
                .c_metadata
                .cmp(&candidates[*right].row.c_metadata)
        });
    }

    let mut child_semantic_keys =
        BTreeMap::<(PackageKey, String), BTreeMap<String, (PackageKey, String)>>::new();
    for (package_key, dependency_keys) in dependency_keys_by_key {
        let semantic_key = (
            package_key.clone(),
            feature_json_by_key
                .get(package_key)
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "missing feature json for {} {}",
                        package_key.crate_name, package_key.version
                    )
                })?,
        );
        let mut child_map = BTreeMap::<String, (PackageKey, String)>::new();
        for dependency_key in dependency_keys {
            let child_semantic_key = (
                dependency_key.clone(),
                feature_json_by_key
                    .get(dependency_key)
                    .cloned()
                    .ok_or_else(|| {
                        format!(
                            "missing dependency feature json for {} {}",
                            dependency_key.crate_name, dependency_key.version
                        )
                    })?,
            );
            let canonical_name = canonical_crate_name(&dependency_key.crate_name);
            if child_map
                .insert(canonical_name.clone(), child_semantic_key)
                .is_some()
            {
                return Err(format!(
                    "ambiguous dependency semantic key for {} {} dependency {}",
                    package_key.crate_name, package_key.version, canonical_name
                ));
            }
        }
        child_semantic_keys.insert(semantic_key, child_map);
    }

    let root_semantic_keys = root_keys
        .iter()
        .map(|root_key| {
            Ok::<_, String>((
                root_key.clone(),
                feature_json_by_key.get(root_key).cloned().ok_or_else(|| {
                    format!(
                        "missing root feature json for {} {}",
                        root_key.crate_name, root_key.version
                    )
                })?,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let assignments = assign_prefetch_roots(
        &root_semantic_keys,
        0,
        &BTreeMap::new(),
        &candidates_by_semantic_key,
        &child_semantic_keys,
        candidates,
    )?;
    Ok(assignments
        .map(|assignments| assignments.into_values().collect())
        .unwrap_or_default())
}

fn assign_prefetch_roots(
    roots: &[(PackageKey, String)],
    index: usize,
    assignments: &BTreeMap<(PackageKey, String), usize>,
    candidates_by_semantic_key: &BTreeMap<(PackageKey, String), Vec<usize>>,
    child_semantic_keys: &BTreeMap<(PackageKey, String), BTreeMap<String, (PackageKey, String)>>,
    candidates: &[ReachableCandidateRow],
) -> Result<Option<BTreeMap<(PackageKey, String), usize>>, String> {
    if index == roots.len() {
        return Ok(Some(assignments.clone()));
    }
    for next_assignments in assign_prefetch_key(
        roots[index].clone(),
        None,
        assignments,
        candidates_by_semantic_key,
        child_semantic_keys,
        candidates,
    )? {
        if let Some(result) = assign_prefetch_roots(
            roots,
            index + 1,
            &next_assignments,
            candidates_by_semantic_key,
            child_semantic_keys,
            candidates,
        )? {
            return Ok(Some(result));
        }
    }
    Ok(None)
}

fn assign_prefetch_key(
    semantic_key: (PackageKey, String),
    required_identity: Option<&str>,
    assignments: &BTreeMap<(PackageKey, String), usize>,
    candidates_by_semantic_key: &BTreeMap<(PackageKey, String), Vec<usize>>,
    child_semantic_keys: &BTreeMap<(PackageKey, String), BTreeMap<String, (PackageKey, String)>>,
    candidates: &[ReachableCandidateRow],
) -> Result<Vec<BTreeMap<(PackageKey, String), usize>>, String> {
    if let Some(existing_index) = assignments.get(&semantic_key) {
        let existing = &candidates[*existing_index];
        let matches_identity =
            required_identity.is_none_or(|identity| existing.row.c_metadata == identity);
        return Ok(if matches_identity {
            vec![assignments.clone()]
        } else {
            Vec::new()
        });
    }

    let candidate_indices = candidates_by_semantic_key
        .get(&semantic_key)
        .cloned()
        .unwrap_or_default();
    let child_map = child_semantic_keys
        .get(&semantic_key)
        .cloned()
        .unwrap_or_default();
    let mut results = Vec::<BTreeMap<(PackageKey, String), usize>>::new();
    for candidate_index in candidate_indices {
        let candidate = &candidates[candidate_index];
        if required_identity.is_some_and(|identity| candidate.row.c_metadata != identity) {
            continue;
        }
        let mut branches = vec![{
            let mut next = assignments.clone();
            next.insert(semantic_key.clone(), candidate_index);
            next
        }];
        let mut failed = false;
        for dependency_identity in &candidate.dependency_identities {
            let dependency_name = canonical_crate_name(&dependency_identity.crate_name);
            let child_semantic_key = child_map.get(&dependency_name).ok_or_else(|| {
                format!(
                    "missing child semantic key for {} {} dependency {}",
                    semantic_key.0.crate_name, semantic_key.0.version, dependency_name
                )
            })?;
            let mut next_branches = Vec::<BTreeMap<(PackageKey, String), usize>>::new();
            for branch in std::mem::take(&mut branches) {
                let child_assignments = assign_prefetch_key(
                    child_semantic_key.clone(),
                    Some(dependency_identity.c_metadata.as_str()),
                    &branch,
                    candidates_by_semantic_key,
                    child_semantic_keys,
                    candidates,
                )?;
                next_branches.extend(child_assignments);
            }
            if next_branches.is_empty() {
                failed = true;
                break;
            }
            branches = next_branches;
        }
        if !failed {
            results.extend(branches.into_iter());
        }
    }
    Ok(results)
}

fn canonical_crate_name(crate_name: &str) -> String {
    crate_name.replace('-', "_")
}

async fn fetch_version_graph_cached(
    db: &Db,
    crate_name: &str,
    version: &Version,
) -> Result<VersionGraph, String> {
    let cache_row = db
        .query(
            "SELECT graph_json \
             FROM crate_version_graph_cache \
             WHERE crate_name = ? AND version = ? AND fetched_at >= datetime('now', ?)",
        )
        .bind(crate_name)
        .bind(version.to_string())
        .bind(CACHE_TTL_SQL)
        .fetch_optional::<GraphCacheRow>()
        .await
        .map_err(|error| {
            format!(
                "load crate_version_graph_cache {} {}: {error}",
                crate_name, version
            )
        })?;
    if let Some(row) = cache_row {
        return serde_json::from_str(&row.graph_json).map_err(|error| {
            format!(
                "parse cached version graph {} {}: {error}",
                crate_name, version
            )
        });
    }

    let graph = fetch_version_graph_live(crate_name, version).await?;
    let graph_json = serde_json::to_string(&graph).map_err(|error| {
        format!(
            "serialize version graph {} {}: {error}",
            crate_name, version
        )
    })?;
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
    .map_err(|error| format!("upsert crate_version_graph_cache {} {}: {error}", crate_name, version))?;
    Ok(graph)
}

async fn fetch_version_graph_live(
    crate_name: &str,
    version: &Version,
) -> Result<VersionGraph, String> {
    let url = format!("{CRATES_IO_API_BASE}/{crate_name}/{version}");
    let deps_url = format!("{CRATES_IO_API_BASE}/{crate_name}/{version}/dependencies");
    let version_request = build_get_request(&url)?;
    let dependencies_request = build_get_request(&deps_url)?;
    let version_response = CfFetch::default()
        .request_json::<CratesIoVersionResponse>(&version_request)
        .await
        .map_err(|error| {
            format!(
                "fetch crates.io version metadata {} {}: {}",
                crate_name, version, error
            )
        })?;
    let dependencies_response = CfFetch::default()
        .request_json::<CratesIoDependenciesResponse>(&dependencies_request)
        .await
        .map_err(|error| {
            format!(
                "fetch crates.io dependencies {} {}: {}",
                crate_name, version, error
            )
        })?;

    Ok(VersionGraph {
        features: version_response.version.features,
        dependencies: dependencies_response.dependencies,
    })
}

async fn resolve_dependency_version(
    db: &Db,
    crate_name: &str,
    requirement: &str,
) -> Result<Version, String> {
    let version_req = VersionReq::parse(requirement).map_err(|error| {
        format!("parse dependency requirement {crate_name} {requirement}: {error}")
    })?;
    let versions = fetch_versions_cached(db, crate_name).await?;
    versions
        .into_iter()
        .find(|version| version_req.matches(version))
        .ok_or_else(|| {
            format!("no crates.io version matched requirement {crate_name} {requirement}")
        })
}

async fn fetch_versions_cached(db: &Db, crate_name: &str) -> Result<Vec<Version>, String> {
    let cache_row = db
        .query(
            "SELECT versions_json \
             FROM crate_versions_cache \
             WHERE crate_name = ? AND fetched_at >= datetime('now', ?)",
        )
        .bind(crate_name)
        .bind(CACHE_TTL_SQL)
        .fetch_optional::<VersionsCacheRow>()
        .await
        .map_err(|error| format!("load crate_versions_cache {crate_name}: {error}"))?;
    if let Some(row) = cache_row {
        return parse_versions_json(crate_name, &row.versions_json);
    }

    let url = format!("{CRATES_IO_API_BASE}/{crate_name}");
    let request = build_get_request(&url)?;
    let response = CfFetch::default()
        .request_json::<CratesIoCrateResponse>(&request)
        .await
        .map_err(|error| format!("fetch crates.io crate metadata {crate_name}: {error}"))?;
    let versions = response
        .versions
        .into_iter()
        .filter(|version| !version.yanked)
        .map(|version| version.num)
        .collect::<Vec<_>>();
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

fn parse_versions_json(crate_name: &str, versions_json: &str) -> Result<Vec<Version>, String> {
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

fn resolve_node(
    graph: &VersionGraph,
    seed_features: &BTreeSet<String>,
    target: &str,
) -> Result<ResolvedNode, String> {
    let local_features = resolve_local_features(graph, seed_features)?;
    let optional_dependencies = graph
        .dependencies
        .iter()
        .filter(|dependency| dependency.optional)
        .map(|dependency| dependency.crate_id.clone())
        .collect::<BTreeSet<_>>();
    let mut activated_optional = local_features
        .iter()
        .filter(|feature| optional_dependencies.contains(*feature))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut dependency_feature_seeds = BTreeMap::<String, BTreeSet<String>>::new();

    for feature in &local_features {
        let Some(items) = graph.features.get(feature) else {
            continue;
        };
        for item in items {
            if let Some(dependency_name) = item.strip_prefix("dep:") {
                activated_optional.insert(dependency_name.to_owned());
                continue;
            }
            if let Some((dependency_name, dependency_feature)) = item.split_once('/') {
                let conditional = dependency_name.ends_with('?');
                let dependency_name = dependency_name.trim_end_matches('?');
                if conditional && !activated_optional.contains(dependency_name) {
                    continue;
                }
                activated_optional.insert(dependency_name.to_owned());
                dependency_feature_seeds
                    .entry(dependency_name.to_owned())
                    .or_default()
                    .insert(dependency_feature.to_owned());
            }
        }
    }

    let mut dependency_requests = Vec::<DependencyRequest>::new();
    for dependency in &graph.dependencies {
        if !dependency_matches_target(dependency, target)? {
            continue;
        }
        if dependency.kind.as_deref() == Some("dev") {
            continue;
        }
        if dependency.optional && !activated_optional.contains(&dependency.crate_id) {
            continue;
        }
        let mut feature_seeds = dependency.features.iter().cloned().collect::<BTreeSet<_>>();
        if dependency.default_features {
            feature_seeds.insert("default".to_owned());
        }
        if let Some(extra_features) = dependency_feature_seeds.get(&dependency.crate_id) {
            feature_seeds.extend(extra_features.iter().cloned());
        }
        dependency_requests.push(DependencyRequest {
            crate_name: dependency.crate_id.clone(),
            req: dependency.req.clone(),
            feature_seeds,
        });
    }

    Ok(ResolvedNode {
        local_features,
        dependency_requests,
    })
}

fn dependency_matches_target(
    dependency: &CratesIoDependency,
    target: &str,
) -> Result<bool, String> {
    let Some(target_expr) = dependency.target.as_deref() else {
        return Ok(true);
    };
    let platform = target_expr
        .parse::<Platform>()
        .map_err(|error| format!("parse crates.io target expression `{target_expr}`: {error}"))?;
    let triple = target
        .parse::<Triple>()
        .map_err(|error| format!("parse target triple `{target}`: {error}"))?;
    let cfgs = target_cfgs(&triple)?;
    Ok(platform.matches(target, &cfgs))
}

fn target_cfgs(triple: &Triple) -> Result<Vec<Cfg>, String> {
    let mut cfgs = Vec::<Cfg>::new();
    cfgs.push(Cfg::KeyPair(
        "target_arch".to_owned(),
        triple.architecture.to_string(),
    ));
    cfgs.push(Cfg::KeyPair(
        "target_vendor".to_owned(),
        triple.vendor.to_string(),
    ));
    cfgs.push(Cfg::KeyPair(
        "target_endian".to_owned(),
        match triple
            .endianness()
            .map_err(|_| "determine target endianness".to_owned())?
        {
            Endianness::Little => "little".to_owned(),
            Endianness::Big => "big".to_owned(),
        },
    ));
    cfgs.push(Cfg::KeyPair(
        "target_pointer_width".to_owned(),
        triple
            .pointer_width()
            .map_err(|_| "determine target pointer width".to_owned())?
            .bits()
            .to_string(),
    ));

    let target_os = match triple.operating_system {
        OperatingSystem::Darwin | OperatingSystem::MacOSX { .. } => "macos".to_owned(),
        os => os.to_string(),
    };
    cfgs.push(Cfg::KeyPair("target_os".to_owned(), target_os.clone()));

    match target_os.as_str() {
        "windows" => {
            cfgs.push(Cfg::Name("windows".to_owned()));
            cfgs.push(Cfg::KeyPair(
                "target_family".to_owned(),
                "windows".to_owned(),
            ));
        }
        "macos" | "ios" | "tvos" | "watchos" | "visionos" | "linux" | "android" | "freebsd"
        | "dragonfly" | "netbsd" | "openbsd" | "solaris" | "illumos" | "haiku" | "redox"
        | "hurd" | "aix" => {
            cfgs.push(Cfg::Name("unix".to_owned()));
            cfgs.push(Cfg::KeyPair("target_family".to_owned(), "unix".to_owned()));
        }
        "wasi" | "wasip1" | "wasip2" | "emscripten" => {
            cfgs.push(Cfg::KeyPair("target_family".to_owned(), "wasm".to_owned()));
        }
        _ => {}
    }

    if !matches!(triple.environment, Environment::Unknown) {
        cfgs.push(Cfg::KeyPair(
            "target_env".to_owned(),
            triple.environment.to_string(),
        ));
    }

    Ok(cfgs)
}

pub(crate) async fn resolve_root_features(
    db: &Db,
    crate_name: &str,
    version: &Version,
    seed_features: &BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    let graph = fetch_version_graph_cached(db, crate_name, version).await?;
    resolve_local_features(&graph, seed_features)
}

fn resolve_local_features(
    graph: &VersionGraph,
    seed_features: &BTreeSet<String>,
) -> Result<BTreeSet<String>, String> {
    let mut features = seed_features
        .iter()
        .filter(|feature| **feature != "default" || graph.features.contains_key("default"))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut queue = VecDeque::<String>::from_iter(features.iter().cloned());
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
    Ok(features)
}

async fn canonicalize_enqueue_request(
    db: &Db,
    request: EnqueueRequest,
) -> Result<EnqueueRequest, String> {
    let requested_version = Version::parse(&request.version).map_err(|error| {
        format!(
            "parse enqueue version {} {}: {error}",
            request.crate_name, request.version
        )
    })?;
    let canonical_version = resolve_dependency_version(
        db,
        request.crate_name.as_str(),
        compatible_requirement(&requested_version).as_str(),
    )
    .await?;
    let features =
        serde_json::from_str::<Vec<String>>(&request.features_json).map_err(|error| {
            format!(
                "parse enqueue features_json for {} {}: {error}",
                request.crate_name, request.version
            )
        })?;
    let features = normalize_feature_set(features)?;
    let features_json = serialize_feature_set(&features)?;
    let mut depends_on = Vec::with_capacity(request.depends_on.len());
    for dependency in request.depends_on {
        depends_on.push(canonicalize_enqueue_dependency(db, dependency).await?);
    }
    Ok(EnqueueRequest {
        version: canonical_version.to_string(),
        features_json,
        depends_on,
        ..request
    })
}

async fn canonicalize_enqueue_dependency(
    db: &Db,
    dependency: EnqueueDependency,
) -> Result<EnqueueDependency, String> {
    let requested_version = Version::parse(&dependency.version).map_err(|error| {
        format!(
            "parse enqueue dependency version {} {}: {error}",
            dependency.crate_name, dependency.version
        )
    })?;
    let canonical_version = resolve_dependency_version(
        db,
        dependency.crate_name.as_str(),
        compatible_requirement(&requested_version).as_str(),
    )
    .await?;
    let features =
        serde_json::from_str::<Vec<String>>(&dependency.features_json).map_err(|error| {
            format!(
                "parse enqueue dependency features_json for {} {}: {error}",
                dependency.crate_name, dependency.version
            )
        })?;
    let features = normalize_feature_set(features)?;
    Ok(EnqueueDependency {
        version: canonical_version.to_string(),
        features_json: serialize_feature_set(&features)?,
        ..dependency
    })
}

fn compatible_requirement(version: &Version) -> String {
    format!("^{version}")
}

fn normalize_feature_set(features: Vec<String>) -> Result<BTreeSet<String>, String> {
    let mut set = BTreeSet::<String>::new();
    for feature in features {
        validate_feature_name(feature.as_str())?;
        set.insert(feature);
    }
    Ok(set)
}

pub(crate) fn serialize_feature_set(features: &BTreeSet<String>) -> Result<String, String> {
    serde_json::to_string(&features.iter().cloned().collect::<Vec<_>>())
        .map_err(|error| format!("serialize feature set: {error}"))
}

fn merge_feature_sets(target: &mut BTreeSet<String>, incoming: &BTreeSet<String>) -> bool {
    let before = target.len();
    target.extend(incoming.iter().cloned());
    target.len() != before
}

fn upsert_node_features(
    states: &mut BTreeMap<PackageKey, NodeState>,
    key: &PackageKey,
    incoming: &BTreeSet<String>,
) -> bool {
    match states.entry(key.clone()) {
        Entry::Vacant(entry) => {
            let mut state = NodeState::default();
            state.features.extend(incoming.iter().cloned());
            entry.insert(state);
            true
        }
        Entry::Occupied(mut entry) => merge_feature_sets(&mut entry.get_mut().features, incoming),
    }
}

fn validate_feature_name(feature: &str) -> Result<(), String> {
    if feature.is_empty()
        || feature.len() > 128
        || !feature
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(format!("invalid feature name: {feature}"));
    }
    Ok(())
}

fn build_get_request(url: &str) -> Result<worker::Request, String> {
    let headers = worker::Headers::new();
    headers
        .set("User-Agent", CRATES_IO_USER_AGENT)
        .map_err(|error| error.to_string())?;

    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get);
    init.with_headers(headers);

    worker::Request::new_with_init(url, &init).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use semver::Version;
    use stow_types::api::{
        DependencyGraphEntry, ResolvedDependencyGraphDependency, ResolvedDependencyGraphEntry,
    };

    use super::{
        CachedArtifactRow, PackageKey, exact_graph_from_request, resolve_reachable_cached_rows,
    };

    #[test]
    fn exact_graph_preserves_client_resolved_lockfile_versions() {
        let humansize_key = PackageKey {
            crate_name: "humansize".to_owned(),
            version: Version::parse("2.1.3").unwrap(),
        };
        let libm_key = PackageKey {
            crate_name: "libm".to_owned(),
            version: Version::parse("0.2.8").unwrap(),
        };
        let unexpected_libm_key = PackageKey {
            crate_name: "libm".to_owned(),
            version: Version::parse("0.2.16").unwrap(),
        };
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
        let same_file_key = PackageKey {
            crate_name: "same-file".to_owned(),
            version: Version::parse("1.0.6").unwrap(),
        };
        let walkdir_key = PackageKey {
            crate_name: "walkdir".to_owned(),
            version: Version::parse("2.5.0").unwrap(),
        };
        let key_pairs = BTreeSet::from([
            (same_file_key.clone(), "[]".to_owned()),
            (walkdir_key.clone(), "[]".to_owned()),
        ]);
        let dependency_names_by_key = BTreeMap::from([
            (same_file_key, BTreeSet::new()),
            (
                walkdir_key,
                BTreeSet::from([PackageKey {
                    crate_name: "same-file".to_owned(),
                    version: Version::parse("1.0.6").unwrap(),
                }]),
            ),
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
                    r#"[{"crate_name":"same_file","c_metadata":"72e2ded9fa67e0a172e2ded9fa67e0a1"}]"#
                        .to_owned(),
            },
        ];

        let reachable =
            resolve_reachable_cached_rows(&dependency_names_by_key, &key_pairs, rows).unwrap();

        assert_eq!(reachable.len(), 2);
        assert_eq!(reachable[0].row.crate_name, "same-file");
        assert_eq!(reachable[1].row.crate_name, "walkdir");
    }

    #[test]
    fn duplicate_compile_key_rows_with_same_semantics_are_deduplicated() {
        let ignore_key = PackageKey {
            crate_name: "ignore".to_owned(),
            version: Version::parse("0.4.25").unwrap(),
        };
        let walkdir_key = PackageKey {
            crate_name: "walkdir".to_owned(),
            version: Version::parse("2.5.0").unwrap(),
        };
        let key_pairs = BTreeSet::from([(ignore_key.clone(), "[]".to_owned())]);
        let dependency_names_by_key = BTreeMap::from([(ignore_key, BTreeSet::from([walkdir_key]))]);
        let rows = vec![
            CachedArtifactRow {
                compile_key: "aaaaaaaaaaaaaaaaffffffffffffffff".to_owned(),
                crate_name: "ignore".to_owned(),
                version: "0.4.25".to_owned(),
                features_json: "[]".to_owned(),
                c_metadata: "bbbbbbbbbbbbbbbb".to_owned(),
                dependency_c_metadata_json:
                    r#"[{"crate_name":"walkdir","c_metadata":"9999999999999999eeeeeeeeeeeeeeee"}]"#
                        .to_owned(),
            },
            CachedArtifactRow {
                compile_key: "aaaaaaaaaaaaaaaaffffffffffffffff".to_owned(),
                crate_name: "ignore".to_owned(),
                version: "0.4.25".to_owned(),
                features_json: "[]".to_owned(),
                c_metadata: "aaaaaaaaaaaaaaaa".to_owned(),
                dependency_c_metadata_json:
                    r#"[{"crate_name":"walkdir","c_metadata":"9999999999999999eeeeeeeeeeeeeeee"}]"#
                        .to_owned(),
            },
        ];

        let reachable =
            resolve_reachable_cached_rows(&dependency_names_by_key, &key_pairs, rows).unwrap();

        assert_eq!(reachable.len(), 1);
        assert_eq!(reachable[0].row.crate_name, "ignore");
        assert_eq!(reachable[0].row.c_metadata, "aaaaaaaaaaaaaaaa");
    }
}

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use semver::{Version, VersionReq};
use skyzen_services::Db;
use stow_types::api::{
    BatchArtifactRequestEntry, DependencyGraphEntry, EnqueueDependency, EnqueueRequest,
    EnqueueSource, ResolvedDependencyGraphEntry,
};
use stow_types::identity::{
    CMetadata, CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::public_cache::stable_c_metadata_for_compile_key;

use crate::errors::ResolverError;
use crate::sql_batch;

const CACHE_TTL_SQL: &str = "-6 hours";
const MAX_EXPANDED_TASKS: usize = 4096;

/// Network boundary for crates.io metadata lookups.
///
/// Production passes the Cloudflare-fetch-backed client from
/// [`crate::crates_io`]; host-side tests can substitute a stub so every piece
/// of resolver logic stays testable off-wasm.
pub trait CratesIo {
    /// Feature map (`feature -> enabled items`) declared by one published
    /// crate version.
    async fn version_features(
        &self,
        crate_name: &str,
        version: &Version,
    ) -> Result<BTreeMap<String, Vec<String>>, ResolverError>;

    /// Non-yanked published version numbers for a crate, as listed by
    /// crates.io (unparsed).
    async fn published_version_nums(&self, crate_name: &str)
    -> Result<Vec<String>, ResolverError>;
}

pub struct ExpandedSchedulerPlan {
    pub enqueue_requests: Vec<EnqueueRequest>,
    pub expanded_cached: usize,
    pub expanded_total: usize,
    pub expanded_entries: Vec<DependencyGraphEntry>,
    pub prefetch_artifacts: Vec<BatchArtifactRequestEntry>,
}

pub async fn canonicalize_enqueue_requests(
    db: &Db,
    crates_io: &impl CratesIo,
    requests: Vec<EnqueueRequest>,
) -> Result<Vec<EnqueueRequest>, ResolverError> {
    let mut canonical = Vec::with_capacity(requests.len());
    for request in requests {
        canonical.push(canonicalize_enqueue_request(db, crates_io, request).await?);
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
/// Historic rows also carried a `dependencies` array for the abandoned
/// server-side full-graph expansion; serde ignores that legacy key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct VersionGraph {
    features: BTreeMap<String, Vec<String>>,
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
            source: EnqueueSource::CacheMiss,
            depends_on,
            preserve_lockfile: false,
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
        let crate_name = CrateName::parse(crate_name_raw.as_str()).map_err(|error| {
            format!("prefetch crate_name `{crate_name_raw}`: {error}")
        })?;
        let c_metadata = CMetadata::parse(c_metadata_raw.as_str()).map_err(|error| {
            format!("prefetch c_metadata `{c_metadata_raw}`: {error}")
        })?;
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
        let reach_check =
            |identity: &DependencyIdentity,
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
            if candidate.dependency_identities.iter().all(|identity| {
                reach_check(identity, &reachable_candidates, &reachable_chain)
            }) {
                reachable_candidates.insert(index);
                progressed = true;
            }
        }
        for (index, chain_row) in chain_rows.iter().enumerate() {
            if reachable_chain.contains(&index) {
                continue;
            }
            if chain_row.dependency_identities.iter().all(|identity| {
                reach_check(identity, &reachable_candidates, &reachable_chain)
            }) {
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
        let mut stack: Vec<(bool, usize)> = selected
            .iter()
            .map(|&index| (false, index))
            .collect();
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
                "load crate_version_graph_cache {crate_name} {version}: {error}"
            )
        })?;
    if let Some(row) = cache_row {
        return serde_json::from_str(&row.graph_json).map_err(|error| {
            ResolverError::Json(format!(
                "parse cached version graph {crate_name} {version}: {error}"
            ))
        });
    }

    let graph = VersionGraph {
        features: crates_io.version_features(crate_name, version).await?,
    };
    let graph_json = serde_json::to_string(&graph).map_err(|error| {
        format!(
            "serialize version graph {crate_name} {version}: {error}"
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
    .map_err(|error| format!("upsert crate_version_graph_cache {crate_name} {version}: {error}"))?;
    Ok(graph)
}

async fn resolve_dependency_version(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
    requirement: &str,
) -> Result<Version, ResolverError> {
    let version_req = VersionReq::parse(requirement).map_err(|error| {
        ResolverError::Invariant(format!(
            "parse dependency requirement {crate_name} {requirement}: {error}"
        ))
    })?;
    let versions = fetch_versions_cached(db, crates_io, crate_name).await?;
    versions
        .into_iter()
        .find(|version| version_req.matches(version))
        .ok_or_else(|| {
            ResolverError::Invariant(format!(
                "no crates.io version matched requirement {crate_name} {requirement}"
            ))
        })
}

async fn fetch_versions_cached(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
) -> Result<Vec<Version>, ResolverError> {
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

fn parse_versions_json(crate_name: &str, versions_json: &str) -> Result<Vec<Version>, ResolverError> {
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

fn resolve_local_features(graph: &VersionGraph, seed_features: &BTreeSet<String>) -> BTreeSet<String> {
    let mut features = seed_features
        .iter()
        .filter(|feature| **feature != "default" || graph.features.contains_key("default"))
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

async fn canonicalize_enqueue_request(
    db: &Db,
    crates_io: &impl CratesIo,
    request: EnqueueRequest,
) -> Result<EnqueueRequest, ResolverError> {
    let requested_version = request.version.as_semver().clone();
    let canonical_version = resolve_dependency_version(
        db,
        crates_io,
        request.crate_name.as_str(),
        compatible_requirement(&requested_version).as_str(),
    )
    .await?;
    let features = request.features_json.features().to_vec();
    let features = normalize_feature_set(features)?;
    let features_json = canonical_features_from_set(&features)?;
    let mut depends_on = Vec::with_capacity(request.depends_on.len());
    for dependency in request.depends_on {
        depends_on.push(canonicalize_enqueue_dependency(db, crates_io, dependency).await?);
    }
    Ok(EnqueueRequest {
        version: CrateVersion::new(canonical_version),
        features_json,
        depends_on,
        ..request
    })
}

async fn canonicalize_enqueue_dependency(
    db: &Db,
    crates_io: &impl CratesIo,
    dependency: EnqueueDependency,
) -> Result<EnqueueDependency, ResolverError> {
    let requested_version = dependency.version.as_semver().clone();
    let canonical_version = resolve_dependency_version(
        db,
        crates_io,
        dependency.crate_name.as_str(),
        compatible_requirement(&requested_version).as_str(),
    )
    .await?;
    let features = dependency.features_json.features().to_vec();
    let features = normalize_feature_set(features)?;
    Ok(EnqueueDependency {
        version: CrateVersion::new(canonical_version),
        features_json: canonical_features_from_set(&features)?,
        ..dependency
    })
}

/// Build a canonical `FeaturesJson` from a normalized feature set.
fn canonical_features_from_set(
    features: &BTreeSet<String>,
) -> Result<FeaturesJson, ResolverError> {
    FeaturesJson::from_sorted(features.iter().cloned().collect())
        .map_err(ResolverError::Identity)
}

fn compatible_requirement(version: &Version) -> String {
    format!("^{version}")
}

fn normalize_feature_set(features: Vec<String>) -> Result<BTreeSet<String>, ResolverError> {
    let mut set = BTreeSet::<String>::new();
    for feature in features {
        validate_feature_name(feature.as_str())?;
        set.insert(feature);
    }
    Ok(set)
}

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
}

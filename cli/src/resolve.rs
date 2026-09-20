//! Local dependency-graph analysis over a verified index slice
//! (stow#194).
//!
//! Ported from the edge's `db::analyze_dependency_graph` +
//! `dependency_resolver::expand_scheduler_requests`: where the edge read
//! candidate rows out of D1 and feature graphs out of crates.io, the CLI
//! walks the decoded [`ArtifactIndexRow`] slice and the feature tables
//! `cargo metadata` already reports — the dependency graph never leaves
//! the machine.
//!
//! The semantic split the edge ran stays: *candidates* are canonical rows
//! whose `(crate, version, features)` matches an expanded-graph node,
//! *chain rows* are every other canonical row a candidate's dep closure
//! may reference, and a node is covered only when its candidate's whole
//! dependency chain resolves inside the slice.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fixedbitset::FixedBitSet;
use semver::Version;
use stow_types::api::{
    BatchArtifactRequestEntry, DependencyGraphAnalysisEntry, DependencyGraphArtifact,
    DependencyGraphEntry, EnqueueDependency, EnqueueRequest, EnqueueSource,
    RecommendedDependencyVersion, ResolvedDependencyGraphEntry, SemanticArtifactRequest,
};
use stow_types::identity::{CrateName, CrateVersion, TargetTriple, WireRustcVersion};
use stow_types::index::ArtifactIndexRow;
use stow_types::public_cache::stable_c_metadata_for_compile_key;
use stow_types::versioning::is_semver_compatible_upgrade;

/// Upper bound on the client-supplied expanded graph — same limit the
/// edge enforced, so pathological graphs fail fast locally instead of
/// burning the resolver's budget.
const MAX_EXPANDED_TASKS: usize = 4096;

/// One package node in the exact dependency graph — crate name plus the
/// resolved version cargo pinned.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageKey {
    /// Crate name as published on crates.io.
    pub crate_name: CrateName,
    /// Exact resolved version.
    pub version: Version,
}

/// A package's feature surface as `cargo metadata` reports it — the
/// local stand-in for the crates.io `VersionGraph` the edge fetched.
///
/// Used to canonicalize a manifest's seed features the way the edge did:
/// seeds the package's real feature table does not declare are dropped,
/// and surviving seeds expand through the table's plain-name items.
#[derive(Debug, Clone, Default)]
pub struct PackageFeatureGraph {
    /// The package's declared `[features]` table.
    pub features: BTreeMap<String, Vec<String>>,
    /// Manifest-spelled names of optional dependencies — each grants an
    /// implicit selectable feature unless a declared feature references
    /// it through `dep:<name>`.
    pub optional_dependencies: BTreeSet<String>,
}

/// The local equivalent of the edge's `DependencyGraphAnalysisOutcome`:
/// the per-entry analysis plus the prefetch/enqueue plan, resolved
/// entirely from the verified index slice.
#[derive(Debug)]
pub struct GraphAnalysis {
    /// Per-entry analysis rows, one per requested [`DependencyGraphEntry`].
    pub entries: Vec<DependencyGraphAnalysisEntry>,
    /// Packages in the transitive expansion that have full cache coverage.
    pub expanded_cached: usize,
    /// Total packages the transitive expansion resolved.
    pub expanded_total: usize,
    /// The expanded graph normalized to [`DependencyGraphEntry`] form.
    pub expanded_entries: Vec<DependencyGraphEntry>,
    /// Exact artifacts the driver should fetch to satisfy the graph —
    /// `(crate_name, c_metadata)` identities resolved against the slice.
    pub prefetch_artifacts: Vec<BatchArtifactRequestEntry>,
    /// Cache-miss enqueue requests — the caller posts them to the edge's
    /// admissions endpoint, which returns the tickets to redeem through
    /// the proof-of-work gate.
    pub enqueue_requests: Vec<EnqueueRequest>,
}

/// Analyze the workspace's dependency graph against the verified index
/// slice: coverage and upgrade recommendations per direct dep, the
/// exact-artifact prefetch set, and the enqueue requests covering the
/// misses.
///
/// `feature_graphs` carries each expanded node's `[features]` table plus
/// optional-dependency names as `cargo metadata` reports them — the local
/// replacement for the crates.io version graphs the edge consulted to
/// canonicalize seed features.
///
/// # Errors
///
/// Returns an error when `expanded_entries` is missing or malformed
/// (duplicate node, dangling edge, missing root), when a root's feature
/// graph is absent from `feature_graphs`, or when an index row carries
/// a `compile_key` the canonical-metadata check cannot read.
pub fn analyze_dependency_graph(
    rows: &[ArtifactIndexRow],
    entries: &[DependencyGraphEntry],
    expanded_entries: &[ResolvedDependencyGraphEntry],
    feature_graphs: &BTreeMap<PackageKey, PackageFeatureGraph>,
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<GraphAnalysis> {
    if entries.is_empty() {
        return Ok(GraphAnalysis {
            entries: Vec::new(),
            expanded_cached: 0,
            expanded_total: 0,
            expanded_entries: Vec::new(),
            prefetch_artifacts: Vec::new(),
            enqueue_requests: Vec::new(),
        });
    }

    let exact_graph = exact_graph_from_request(entries, expanded_entries)?;

    // The analysis entries' feature key is the *requested* feature set
    // canonicalized through the crate's own feature table — the same
    // semantics the edge applied to manifest seeds — while coverage and
    // enqueue identity come from the expanded graph's resolved features.
    let mut crate_names = BTreeSet::<String>::new();
    let mut exact_entries = Vec::<ExactDependencyEntry>::with_capacity(entries.len());
    for entry in entries {
        let key = PackageKey {
            crate_name: entry.crate_name.clone(),
            version: entry.version.clone(),
        };
        let graph = feature_graphs.get(&key).ok_or_else(|| {
            stow_types::stow_error!(
                "feature graph missing for {} {}",
                key.crate_name,
                key.version
            )
        })?;
        let resolved = resolve_local_features(graph, &entry.features.iter().cloned().collect());
        crate_names.insert(entry.crate_name.as_str().to_owned());
        exact_entries.push(ExactDependencyEntry {
            dependency: entry.clone(),
            features_json: serialize_feature_set(&resolved)?,
        });
    }

    let catalog_rows = rows
        .iter()
        .filter(|row| crate_names.contains(row.crate_name.as_str()))
        .collect::<Vec<_>>();
    let semantic_catalog = build_semantic_catalog(&catalog_rows)?;
    let exact_artifacts = build_exact_artifact_catalog(&catalog_rows)?;
    let response_entries = exact_entries
        .iter()
        .map(|entry| {
            let semantic_key = semantic_key(
                entry.dependency.crate_name.as_str(),
                &entry.dependency.version,
                &entry.features_json,
            );
            let current_artifact_count = semantic_catalog
                .artifact_counts
                .get(&semantic_key)
                .copied()
                .unwrap_or(0);
            let current_artifacts = exact_artifacts
                .get(&semantic_key)
                .cloned()
                .unwrap_or_default();
            let recommended = best_upgrade_for(entry, &semantic_catalog);
            DependencyGraphAnalysisEntry {
                dependency: entry.dependency.clone(),
                current_artifact_count,
                current_artifacts,
                recommended,
            }
        })
        .collect::<Vec<_>>();

    let plan = expanded_scheduler_plan(&exact_graph, rows, target, rustc_version)?;

    Ok(GraphAnalysis {
        entries: response_entries,
        expanded_cached: plan.expanded_cached,
        expanded_total: plan.expanded_total,
        expanded_entries: plan.expanded_entries,
        prefetch_artifacts: plan.prefetch_artifacts,
        enqueue_requests: plan.enqueue_requests,
    })
}

/// The exact-graph expansion + coverage plan, resolved in memory.
/// `complete_chain_rows` — the edge's iterative D1 fetch of
/// chain-referenced rows — is subsumed: the slice already holds every
/// canonical row the target/rustc pair can serve, so a referenced
/// `c_metadata` that is absent here is simply absent.
fn expanded_scheduler_plan(
    exact_graph: &ExactExpandedGraph,
    rows: &[ArtifactIndexRow],
    target: &TargetTriple,
    rustc_version: &WireRustcVersion,
) -> stow_types::error::Result<ExpandedSchedulerPlan> {
    let cached = cached_artifacts(
        rows,
        &exact_graph.feature_json_by_key,
        &exact_graph.root_keys,
    )?;
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
        &exact_graph.dependency_keys_by_key,
        &cached.semantic_keys,
        target,
        rustc_version,
        EnqueueSource::CacheMiss,
    )?;
    Ok(ExpandedSchedulerPlan {
        enqueue_requests: requests,
        expanded_cached,
        expanded_total,
        expanded_entries: exact_graph.expanded_entries.clone(),
        prefetch_artifacts: cached.prefetch_artifacts,
    })
}

struct ExpandedSchedulerPlan {
    enqueue_requests: Vec<EnqueueRequest>,
    expanded_cached: usize,
    expanded_total: usize,
    expanded_entries: Vec<DependencyGraphEntry>,
    prefetch_artifacts: Vec<BatchArtifactRequestEntry>,
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
) -> stow_types::error::Result<ExactExpandedGraph> {
    if expanded_entries.is_empty() {
        return Err(stow_types::stow_error!(
            "dependency graph request is missing expanded_entries"
        ));
    }
    if expanded_entries.len() > MAX_EXPANDED_TASKS {
        return Err(stow_types::stow_error!(
            "expanded dependency graph entries: got {}, limit {MAX_EXPANDED_TASKS}",
            expanded_entries.len()
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
            return Err(stow_types::stow_error!(
                "duplicate expanded dependency graph entry for {} {}",
                key.crate_name,
                key.version
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
            return Err(stow_types::stow_error!(
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
        return Err(stow_types::stow_error!(
            "expanded dependency graph is missing root {} {}",
            root_key.crate_name,
            root_key.version
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

struct CachedArtifacts {
    semantic_keys: BTreeSet<(PackageKey, String)>,
    prefetch_artifacts: Vec<BatchArtifactRequestEntry>,
}

/// The in-memory equivalent of the edge's `load_cached_artifacts`: every
/// servable row for the slice is already resident, so the
/// crate-name-`IN` query and the chain-completion fetch collapse to one
/// pass over the slice.
fn cached_artifacts(
    rows: &[ArtifactIndexRow],
    feature_json_by_key: &BTreeMap<PackageKey, String>,
    root_keys: &BTreeSet<PackageKey>,
) -> stow_types::error::Result<CachedArtifacts> {
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

    let reachable = resolve_reachable_cached_rows(&key_pairs, rows)?;
    let semantic_keys = reachable
        .candidates
        .iter()
        .map(|candidate| candidate.semantic_key.clone())
        .collect::<BTreeSet<_>>();
    let selected_prefetch_rows =
        select_prefetch_candidates(feature_json_by_key, root_keys, &reachable)?;
    // Prefetch the full closure of every selected candidate: the CLI's
    // injection walk loads chain dependencies locally and pays a
    // per-artifact network round trip for each one missing from the batch.
    let prefetch_artifacts = reachable.closure_artifacts(&selected_prefetch_rows);
    let mut prefetch_entries = Vec::with_capacity(prefetch_artifacts.len());
    for (crate_name_raw, c_metadata_raw) in prefetch_artifacts {
        let crate_name = CrateName::parse(crate_name_raw.as_str()).map_err(|error| {
            stow_types::stow_error!("prefetch crate_name `{crate_name_raw}`: {error}")
        })?;
        let c_metadata =
            stow_types::identity::CMetadata::parse(c_metadata_raw.as_str()).map_err(|error| {
                stow_types::stow_error!("prefetch c_metadata `{c_metadata_raw}`: {error}")
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

fn resolve_reachable_cached_rows<'a>(
    key_pairs: &BTreeSet<(PackageKey, String)>,
    rows: &'a [ArtifactIndexRow],
) -> stow_types::error::Result<ReachableRows<'a>> {
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
                    canonical_crate_name(candidate.row.crate_name.as_str()),
                    candidate.row.c_metadata.as_str().to_owned(),
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
                    canonical_crate_name(chain_row.row.crate_name.as_str()),
                    chain_row.row.c_metadata.as_str().to_owned(),
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

/// Partition index rows by request match: rows whose (package, features)
/// pair is in `key_pairs` become candidates; every other canonical row is a
/// chain row another candidate's closure may reference. Rows failing the
/// canonical-metadata check are dropped.
fn partition_cached_rows<'a>(
    key_pairs: &BTreeSet<(PackageKey, String)>,
    rows: &'a [ArtifactIndexRow],
) -> stow_types::error::Result<IndexedRows<'a>> {
    let mut candidates = Vec::<ReachableCandidateRow<'a>>::new();
    let mut candidate_index = BTreeMap::<(String, String), usize>::new();
    let mut chain_rows = Vec::<ChainRow<'a>>::new();
    let mut chain_index = BTreeMap::<(String, String), usize>::new();

    for row in rows {
        if !cached_row_has_canonical_metadata(row)? {
            continue;
        }
        let dependency_identities = canonicalize_dependency_identities(
            row.dependency_c_metadata_json
                .entries()
                .iter()
                .map(|entry| DependencyIdentity {
                    crate_name: entry.crate_name.as_str().to_owned(),
                    c_metadata: entry.c_metadata.as_str().to_owned(),
                })
                .collect(),
        );
        let identity_key = (
            canonical_crate_name(row.crate_name.as_str()),
            row.c_metadata.as_str().to_owned(),
        );

        let package_key = PackageKey {
            crate_name: row.crate_name.clone(),
            version: row.version.as_semver().clone(),
        };
        let semantic_key = (package_key, row.features_json.raw());
        if key_pairs.contains(&semantic_key) {
            if let Some(existing_index) = candidate_index.get(&identity_key).copied() {
                if !deduplicate_cached_candidate(
                    &candidates[existing_index],
                    &semantic_key,
                    row,
                    &dependency_identities,
                ) {
                    return Err(stow_types::stow_error!(
                        "conflicting cached artifact identity {} {}",
                        identity_key.0,
                        identity_key.1
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

fn cached_row_has_canonical_metadata(row: &ArtifactIndexRow) -> stow_types::error::Result<bool> {
    let stable_c_metadata =
        stable_c_metadata_for_compile_key(&row.compile_key).map_err(|error| {
            stow_types::stow_error!(
                "compute stable c_metadata for {} {} {}: {error}",
                row.crate_name,
                row.version,
                row.compile_key
            )
        })?;
    Ok(stable_c_metadata == row.c_metadata.as_str())
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
    existing: &ReachableCandidateRow<'_>,
    semantic_key: &SemanticKey,
    row: &ArtifactIndexRow,
    dependency_identities: &[DependencyIdentity],
) -> bool {
    if existing.semantic_key != *semantic_key
        || existing.dependency_identities != dependency_identities
    {
        return false;
    }
    row.c_metadata.as_str() == existing.row.c_metadata.as_str()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DependencyIdentity {
    crate_name: String,
    c_metadata: String,
}

#[derive(Debug)]
struct ReachableCandidateRow<'a> {
    semantic_key: (PackageKey, String),
    row: &'a ArtifactIndexRow,
    dependency_identities: Vec<DependencyIdentity>,
}

/// A canonical row that is not a semantic match for the current request but
/// participates in candidates' dependency closures.
#[derive(Debug)]
struct ChainRow<'a> {
    row: &'a ArtifactIndexRow,
    dependency_identities: Vec<DependencyIdentity>,
}

/// Index rows partitioned by request match — semantic candidates and
/// chain-only rows, each indexed by (canonical crate name, `c_metadata`).
#[derive(Debug)]
struct IndexedRows<'a> {
    candidates: Vec<ReachableCandidateRow<'a>>,
    candidate_index: BTreeMap<(String, String), usize>,
    chain_rows: Vec<ChainRow<'a>>,
    chain_index: BTreeMap<(String, String), usize>,
}

/// Reachability result: semantic candidates plus the chain-only rows their
/// closures may traverse, both restricted to fully-resolvable nodes.
#[derive(Debug)]
struct ReachableRows<'a> {
    candidates: Vec<ReachableCandidateRow<'a>>,
    candidate_index: BTreeMap<(String, String), usize>,
    chain_rows: Vec<ChainRow<'a>>,
    chain_index: BTreeMap<(String, String), usize>,
}

impl ReachableRows<'_> {
    /// Every (`crate_name`, `c_metadata`) in the transitive closure of the
    /// selected candidate indices — the exact set the driver must fetch to
    /// inject those candidates without per-artifact round trips.
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
                (chain_row.row, &chain_row.dependency_identities)
            } else {
                if !visited_candidates.insert(index) {
                    continue;
                }
                let candidate = &self.candidates[index];
                (candidate.row, &candidate.dependency_identities)
            };
            artifacts.insert((
                row.crate_name.as_str().to_owned(),
                row.c_metadata.as_str().to_owned(),
            ));
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
    reachable: &ReachableRows<'_>,
) -> stow_types::error::Result<BTreeSet<usize>> {
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
                .as_str()
                .cmp(reachable.candidates[*right].row.c_metadata.as_str())
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
            stow_types::stow_error!(
                "missing root feature json for {} {}",
                root_key.crate_name,
                root_key.version
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

/// Turn an exact graph (`feature_json_by_key` + `dependency_keys_by_key`)
/// into one [`EnqueueRequest`] per node the cache does not already cover.
/// `source` decides the scheduler lane the tasks land in.
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
    target_typed: &TargetTriple,
    rustc_version_typed: &WireRustcVersion,
    source: EnqueueSource,
) -> stow_types::error::Result<Vec<EnqueueRequest>> {
    let dominators = immediate_dominators(
        feature_json_by_key,
        dependency_keys_by_key,
        cached_semantic_keys,
    )?;
    let mut requests = Vec::<EnqueueRequest>::new();
    for node_key in dependency_keys_by_key.keys() {
        let features_json = feature_json_by_key.get(node_key).cloned().ok_or_else(|| {
            stow_types::stow_error!(
                "missing serialized feature set for {} {}",
                node_key.crate_name,
                node_key.version
            )
        })?;
        if cached_semantic_keys.contains(&(node_key.clone(), features_json.clone())) {
            continue;
        }
        let depends_on = dominators
            .get(node_key)
            .map(|dominator| {
                let raw = feature_json_by_key.get(dominator).ok_or_else(|| {
                    stow_types::stow_error!(
                        "missing serialized feature set for dominator {} {}",
                        dominator.crate_name,
                        dominator.version
                    )
                })?;
                let dominator_features_json = parse_canonical_features_json(raw)?;
                Ok::<_, stow_types::error::Error>(EnqueueDependency {
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
            project_source: None,
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
) -> stow_types::error::Result<BTreeMap<PackageKey, PackageKey>> {
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
                stow_types::stow_error!(
                    "missing serialized feature set for {} {}",
                    key.crate_name,
                    key.version
                )
            })?;
            Ok(!cached_semantic_keys.contains(&((*key).clone(), features_json.clone())))
        })
        .collect::<Result<Vec<bool>, stow_types::error::Error>>()?;
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

/// The per-version feature surface for seed canonicalization: every
/// declared `[features]` key plus the implicit feature cargo grants each
/// optional dependency — unless a declared feature references that
/// dependency through `dep:<name>`, which hides the implicit feature.
fn selectable_features(graph: &PackageFeatureGraph) -> BTreeSet<String> {
    let dep_referenced = graph
        .features
        .values()
        .flat_map(|items| items.iter())
        .filter_map(|item| item.strip_prefix("dep:"))
        .collect::<BTreeSet<_>>();
    graph
        .features
        .keys()
        .cloned()
        .chain(
            graph
                .optional_dependencies
                .iter()
                .filter(|name| !dep_referenced.contains(name.as_str()))
                .cloned(),
        )
        .collect()
}

/// Canonicalize a manifest's seed features against the package's real
/// feature surface: seeds the table does not declare are dropped before
/// any task identity is minted, and surviving seeds expand through the
/// table's plain-name items (`dep:` and `name/feature` edges never name a
/// feature on this package).
fn resolve_local_features(
    graph: &PackageFeatureGraph,
    seed_features: &BTreeSet<String>,
) -> BTreeSet<String> {
    let selectable = selectable_features(graph);
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

/// Validate and deduplicate a requested feature list.
fn normalize_feature_set(features: Vec<String>) -> stow_types::error::Result<BTreeSet<String>> {
    let mut set = BTreeSet::<String>::new();
    for feature in features {
        validate_feature_name(feature.as_str())?;
        set.insert(feature);
    }
    Ok(set)
}

/// Canonical `features_json` for a resolved feature set: the sorted list
/// JSON-encoded — the same string [`stow_types::identity::FeaturesJson::raw`]
/// produces and the identity every task id hashes.
fn serialize_feature_set(features: &BTreeSet<String>) -> stow_types::error::Result<String> {
    serde_json::to_string(&features.iter().cloned().collect::<Vec<_>>())
        .map_err(|error| stow_types::stow_error!("serialize feature set: {error}"))
}

/// Decode a stored canonical features-json string into the structured wire type.
fn parse_canonical_features_json(
    raw: &str,
) -> stow_types::error::Result<stow_types::identity::FeaturesJson> {
    let parsed: Vec<String> = serde_json::from_str(raw)
        .map_err(|error| stow_types::stow_error!("parse features_json `{raw}`: {error}"))?;
    stow_types::identity::FeaturesJson::from_sorted(parsed)
        .map_err(|error| stow_types::stow_error!("canonical features_json `{raw}`: {error}"))
}

fn validate_feature_name(feature: &str) -> stow_types::error::Result<()> {
    if feature.is_empty()
        || feature.len() > 128
        || !feature
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(stow_types::stow_error!("invalid feature name: {feature}"));
    }
    Ok(())
}

/// Exact identity `(crate_name, version, features_json)` used as a catalog key.
type CatalogKey = (String, Version, String);
/// Exact artifacts grouped by semantic identity.
type ExactArtifactCatalog = BTreeMap<CatalogKey, Vec<DependencyGraphArtifact>>;

#[derive(Debug, Clone)]
struct ExactDependencyEntry {
    dependency: DependencyGraphEntry,
    features_json: String,
}

#[derive(Debug, Clone)]
struct CachedVersion {
    version: Version,
    artifact_count: u32,
}

#[derive(Debug, Clone)]
struct SemanticCatalog {
    artifact_counts: BTreeMap<(String, Version, String), u32>,
    feature_versions: BTreeMap<(String, String), Vec<CachedVersion>>,
}

fn semantic_key(crate_name: &str, version: &Version, features_json: &str) -> CatalogKey {
    (
        crate_name.to_owned(),
        version.clone(),
        features_json.to_owned(),
    )
}

/// Build the per-`(name, version, features)` artifact counts and the
/// `(name, features) → versions` upgrade index over the catalog rows —
/// canonical rows only, sorted by `(crate_name, version, features_json,
/// compile_key, c_metadata)` exactly as the edge's `ORDER BY` produced.
fn build_semantic_catalog(
    rows: &[&ArtifactIndexRow],
) -> stow_types::error::Result<SemanticCatalog> {
    let mut artifact_counts = BTreeMap::<(String, Version, String), u32>::new();
    let mut feature_versions = BTreeMap::<(String, String), Vec<CachedVersion>>::new();

    for row in sorted_catalog_rows(rows) {
        if !cached_row_has_canonical_metadata(row)? {
            continue;
        }
        let artifact_key = semantic_key(
            row.crate_name.as_str(),
            row.version.as_semver(),
            &row.features_json.raw(),
        );
        let artifact_count = artifact_counts.entry(artifact_key).or_insert(0);
        *artifact_count = artifact_count.saturating_add(1);
    }

    for ((crate_name, cached_version, features_json), artifact_count) in &artifact_counts {
        feature_versions
            .entry((crate_name.clone(), features_json.clone()))
            .or_default()
            .push(CachedVersion {
                version: cached_version.clone(),
                artifact_count: *artifact_count,
            });
    }

    for cached_versions in feature_versions.values_mut() {
        cached_versions.sort_by(|left, right| {
            right
                .artifact_count
                .cmp(&left.artifact_count)
                .then(right.version.cmp(&left.version))
        });
    }

    Ok(SemanticCatalog {
        artifact_counts,
        feature_versions,
    })
}

fn build_exact_artifact_catalog(
    rows: &[&ArtifactIndexRow],
) -> stow_types::error::Result<ExactArtifactCatalog> {
    let mut artifacts = ExactArtifactCatalog::new();

    for row in sorted_catalog_rows(rows) {
        if !cached_row_has_canonical_metadata(row)? {
            continue;
        }
        let key = semantic_key(
            row.crate_name.as_str(),
            row.version.as_semver(),
            &row.features_json.raw(),
        );
        let entry = artifacts.entry(key).or_default();
        if entry
            .last()
            .is_some_and(|last| last.c_metadata == row.c_metadata)
        {
            continue;
        }
        entry.push(DependencyGraphArtifact {
            c_metadata: row.c_metadata.clone(),
        });
    }

    Ok(artifacts)
}

/// Rows in the order the edge's `ORDER BY crate_name, version,
/// features_json, compile_key, c_metadata` produced — the exact-catalog
/// dedup relies on equal `c_metadata` rows landing adjacent.
fn sorted_catalog_rows<'a>(rows: &[&'a ArtifactIndexRow]) -> Vec<&'a ArtifactIndexRow> {
    let mut sorted = rows.to_vec();
    sorted.sort_by(|left, right| {
        left.crate_name
            .as_str()
            .cmp(right.crate_name.as_str())
            .then(left.version.to_string().cmp(&right.version.to_string()))
            .then(left.features_json.raw().cmp(&right.features_json.raw()))
            .then(left.compile_key.cmp(&right.compile_key))
            .then(left.c_metadata.as_str().cmp(right.c_metadata.as_str()))
    });
    sorted
}

fn best_upgrade_for(
    entry: &ExactDependencyEntry,
    catalog: &SemanticCatalog,
) -> Option<RecommendedDependencyVersion> {
    let current_key = semantic_key(
        entry.dependency.crate_name.as_str(),
        &entry.dependency.version,
        &entry.features_json,
    );
    let current_artifact_count = catalog
        .artifact_counts
        .get(&current_key)
        .copied()
        .unwrap_or(0);
    let candidates = catalog.feature_versions.get(&(
        entry.dependency.crate_name.as_str().to_owned(),
        entry.features_json.clone(),
    ));
    let candidates = candidates?;

    for candidate in candidates {
        if !is_semver_compatible_upgrade(&entry.dependency.version, &candidate.version) {
            continue;
        }
        if candidate.artifact_count <= current_artifact_count {
            continue;
        }
        return Some(RecommendedDependencyVersion {
            version: candidate.version.clone(),
            artifact_count: candidate.artifact_count,
        });
    }

    None
}

/// The wrapper's semantic lookup, resolved locally: the index row whose
/// full identity matches `request`, or the newest semver-compatible
/// upgrade the slice carries.
///
/// Mirrors the edge's `get_semantic_artifact_reference`: exact-identity
/// rows (crate, features, dep chain, profile, crate types, kind) first
/// pass a version/emit filter, then rank by version descending,
/// canonical metadata, narrowest emit set, and finally `bundle_digest`
/// descending — the slice's deterministic stand-in for the row's OCI
/// digest, which the index does not carry.
///
/// # Errors
///
/// Returns an error when `request.emit` is not sorted and deduplicated —
/// the canonical shape rustc-arg parsing produces.
#[expect(
    clippy::suspicious_operation_groupings,
    reason = "the request field is named `kind` while the row field is `artifact_kind`; the mismatch is the schema, not a bug"
)]
pub fn find_semantic_artifact<'a>(
    rows: &'a [ArtifactIndexRow],
    request: &SemanticArtifactRequest,
) -> stow_types::error::Result<Option<&'a ArtifactIndexRow>> {
    validate_emit_sorted(&request.emit)?;

    let mut candidates = rows
        .iter()
        .filter(|row| {
            row.crate_name == request.crate_name
                && row.features_json == request.features_json
                && row.dependency_c_metadata_json == request.dependency_c_metadata_json
                && row.artifact_kind == request.kind
                && row.crate_types == request.crate_types
                && row.profile == request.profile
        })
        .filter(|row| {
            let candidate_version = row.version.as_semver();
            let requested = request.version.as_semver();
            (candidate_version == requested
                || is_semver_compatible_upgrade(requested, candidate_version))
                && emit_covers_request(&row.emit, &request.emit)
        })
        .collect::<Vec<_>>();

    candidates.sort_by(|left, right| {
        right
            .version
            .as_semver()
            .cmp(left.version.as_semver())
            .then(row_has_canonical_metadata(right).cmp(&row_has_canonical_metadata(left)))
            .then(left.emit.len().cmp(&right.emit.len()))
            .then(right.bundle_digest.cmp(&left.bundle_digest))
    });

    Ok(candidates.into_iter().next())
}

/// The canonical-metadata check as a ranking predicate — a malformed
/// `compile_key` ranks non-canonical rather than failing the lookup.
fn row_has_canonical_metadata(row: &ArtifactIndexRow) -> bool {
    stable_c_metadata_for_compile_key(&row.compile_key)
        .is_ok_and(|stable| stable == row.c_metadata.as_str())
}

fn validate_emit_sorted(emit: &[String]) -> stow_types::error::Result<()> {
    let mut previous: Option<&str> = None;
    for value in emit {
        if previous.is_some_and(|last| last >= value.as_str()) {
            return Err(stow_types::stow_error!(
                "emit list must be strictly sorted and deduplicated"
            ));
        }
        previous = Some(value.as_str());
    }
    Ok(())
}

fn emit_covers_request(candidate_emit: &[String], requested_emit: &[String]) -> bool {
    let candidate_set = candidate_emit.iter().collect::<BTreeSet<_>>();
    requested_emit
        .iter()
        .all(|requested| candidate_set.contains(requested))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use semver::Version;
    use stow_types::api::{
        DependencyGraphEntry, EnqueueSource, ResolvedDependencyGraphDependency,
        ResolvedDependencyGraphEntry, SemanticArtifactRequest,
    };
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataIdentity, DependencyCMetadataJson,
        FeaturesJson, TargetTriple, WireRustcVersion,
    };
    use stow_types::index::ArtifactIndexRow;
    use stow_types::platform::{PanicStrategy, Profile, StripLevel};

    use super::{
        PackageFeatureGraph, PackageKey, analyze_dependency_graph, build_enqueue_requests,
        build_exact_artifact_catalog, build_semantic_catalog, exact_graph_from_request,
        find_semantic_artifact, immediate_dominators, resolve_local_features,
        resolve_reachable_cached_rows,
    };

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const RUSTC: &str = "1.91.1";

    fn target() -> TargetTriple {
        TargetTriple::parse(TARGET).expect("target")
    }

    fn rustc() -> WireRustcVersion {
        WireRustcVersion::parse(RUSTC).expect("rustc")
    }

    fn key(name: &str, version: &str) -> PackageKey {
        PackageKey {
            crate_name: CrateName::parse(name).unwrap(),
            version: Version::parse(version).unwrap(),
        }
    }

    /// An index row whose `compile_key[..16]` equals `c_metadata` — the
    /// canonical identity every analysis path requires.
    fn row(
        crate_name: &str,
        version: &str,
        c_metadata: &str,
        features: &[&str],
        deps: &[(&str, &str)],
    ) -> ArtifactIndexRow {
        row_with_compile_key(
            crate_name,
            version,
            c_metadata,
            &format!("{c_metadata}{c_metadata}"),
            features,
            deps,
        )
    }

    fn row_with_compile_key(
        crate_name: &str,
        version: &str,
        c_metadata: &str,
        compile_key: &str,
        features: &[&str],
        deps: &[(&str, &str)],
    ) -> ArtifactIndexRow {
        ArtifactIndexRow {
            crate_name: CrateName::parse(crate_name).expect("name"),
            version: CrateVersion::new(Version::parse(version).expect("version")),
            features_json: FeaturesJson::canonicalize(
                features
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
            )
            .expect("features"),
            dependency_c_metadata_json: DependencyCMetadataJson::canonicalize(
                deps.iter()
                    .map(|(name, meta)| DependencyCMetadataIdentity {
                        crate_name: CrateName::parse(*name).expect("dep name"),
                        c_metadata: CMetadata::parse(*meta).expect("dep c_metadata"),
                    })
                    .collect(),
            )
            .expect("deps"),
            c_metadata: CMetadata::parse(c_metadata).expect("c_metadata"),
            compile_key: compile_key.to_owned(),
            bundle_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            bundle_size: 1,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 0,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
                strip: StripLevel::None,
            },
            emit: vec!["link".to_owned()],
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
            row("same-file", "1.0.6", "72e2ded9fa67e0a1", &[], &[]),
            row(
                "walkdir",
                "2.5.0",
                "1c0d7420b566b7a2",
                &[],
                &[("same_file", "72e2ded9fa67e0a1")],
            ),
        ];

        let reachable = resolve_reachable_cached_rows(&key_pairs, &rows).unwrap();

        assert_eq!(reachable.candidates.len(), 2);
        assert_eq!(reachable.candidates[0].row.crate_name.as_str(), "same-file");
        assert_eq!(reachable.candidates[1].row.crate_name.as_str(), "walkdir");
        assert!(reachable.chain_rows.is_empty());
    }

    #[test]
    fn rows_with_uncached_dependency_identities_are_not_reachable() {
        let walkdir_key = key("walkdir", "2.5.0");
        let key_pairs = BTreeSet::from([(walkdir_key, "[]".to_owned())]);
        let rows = vec![row(
            "walkdir",
            "2.5.0",
            "1c0d7420b566b7a2",
            &[],
            &[("same_file", "72e2ded9fa67e0a1")],
        )];

        let reachable = resolve_reachable_cached_rows(&key_pairs, &rows).unwrap();

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
            row(
                "walkdir",
                "2.5.0",
                "1c0d7420b566b7a2",
                &[],
                &[("same_file", "72e2ded9fa67e0a1")],
            ),
            row("same-file", "1.0.6", "72e2ded9fa67e0a1", &["unstable"], &[]),
        ];

        let reachable = resolve_reachable_cached_rows(&key_pairs, &rows).unwrap();

        assert_eq!(reachable.candidates.len(), 1);
        assert_eq!(reachable.candidates[0].row.crate_name.as_str(), "walkdir");
        assert_eq!(reachable.chain_rows.len(), 1);
        assert_eq!(reachable.chain_rows[0].row.crate_name.as_str(), "same-file");

        let closure = reachable.closure_artifacts(&BTreeSet::from([0]));
        assert!(closure.contains(&("walkdir".to_owned(), "1c0d7420b566b7a2".to_owned())));
        assert!(closure.contains(&("same-file".to_owned(), "72e2ded9fa67e0a1".to_owned())));
    }

    #[test]
    fn duplicate_compile_key_rows_with_same_semantics_are_deduplicated() {
        let ignore_key = key("ignore", "0.4.25");
        let walkdir_key = key("walkdir", "2.5.0");
        let key_pairs = BTreeSet::from([
            (ignore_key, "[]".to_owned()),
            (walkdir_key, "[]".to_owned()),
        ]);
        let canonical_ignore_row = || {
            row(
                "ignore",
                "0.4.25",
                "aaaaaaaaaaaaaaaa",
                &[],
                &[("walkdir", "9999999999999999")],
            )
        };
        let rows = vec![
            // Row whose c_metadata does not match its compile_key's
            // stable prefix: filtered by the canonical-metadata check.
            ArtifactIndexRow {
                c_metadata: CMetadata::parse("bbbbbbbbbbbbbbbb").expect("c_metadata"),
                ..canonical_ignore_row()
            },
            canonical_ignore_row(),
            // Exact duplicate of the canonical row: deduplicated.
            canonical_ignore_row(),
            row("walkdir", "2.5.0", "9999999999999999", &[], &[]),
        ];

        let reachable = resolve_reachable_cached_rows(&key_pairs, &rows).unwrap();

        assert_eq!(reachable.candidates.len(), 2);
        assert_eq!(reachable.candidates[0].row.crate_name.as_str(), "ignore");
        assert_eq!(
            reachable.candidates[0].row.c_metadata.as_str(),
            "aaaaaaaaaaaaaaaa"
        );
        assert_eq!(reachable.candidates[1].row.crate_name.as_str(), "walkdir");
    }

    #[test]
    fn local_features_drop_seeds_the_crate_does_not_declare() {
        let graph = PackageFeatureGraph {
            features: BTreeMap::from([
                ("default".to_owned(), Vec::new()),
                ("derive".to_owned(), vec!["dep:serde_derive".to_owned()]),
                ("full".to_owned(), vec!["derive".to_owned()]),
            ]),
            optional_dependencies: BTreeSet::new(),
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
        let graph = PackageFeatureGraph {
            features: BTreeMap::from([("std".to_owned(), Vec::new())]),
            optional_dependencies: BTreeSet::new(),
        };
        // Every bogus-feature variant of a crate collapses onto the one
        // canonical empty-feature task identity.
        assert!(resolve_local_features(&graph, &BTreeSet::from(["bogus".to_owned()])).is_empty());
    }

    #[test]
    fn local_features_keep_implicit_optional_dependency_features() {
        // slab's real shape: `serde` is an optional dependency no declared
        // feature references through `dep:`, so cargo grants an implicit
        // `serde` feature that must survive validation.
        let graph = PackageFeatureGraph {
            features: BTreeMap::from([
                ("default".to_owned(), vec!["std".to_owned()]),
                ("std".to_owned(), Vec::new()),
            ]),
            optional_dependencies: BTreeSet::from(["serde".to_owned()]),
        };
        let resolved = resolve_local_features(
            &graph,
            &BTreeSet::from(["serde".to_owned(), "bogus".to_owned()]),
        );
        assert_eq!(resolved, BTreeSet::from(["serde".to_owned()]));
    }

    #[test]
    fn local_features_drop_dep_referenced_optional_dependencies() {
        // When a declared feature references `dep:foo`, cargo hides the
        // implicit `foo` feature — `foo` as a seed is bogus like any other
        // undeclared name.
        let graph = PackageFeatureGraph {
            features: BTreeMap::from([("full".to_owned(), vec!["dep:foo".to_owned()])]),
            optional_dependencies: BTreeSet::from(["foo".to_owned()]),
        };
        assert!(resolve_local_features(&graph, &BTreeSet::from(["foo".to_owned()])).is_empty());
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
        let dominators =
            immediate_dominators(&features(&graph), &graph, &BTreeSet::new()).expect("dominators");
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
        let dominators = immediate_dominators(&features(&graph), &graph, &covered(&["mid"]))
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
        let dominators =
            immediate_dominators(&features(&graph), &graph, &BTreeSet::new()).expect("dominators");
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
            &target(),
            &rustc(),
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

    #[test]
    fn dependency_graph_catalogs_ignore_noncanonical_duplicate_rows() {
        let rows = [
            row_with_compile_key(
                "proc-macro2",
                "1.0.106",
                "ffffffffffffffff",
                "1234567890abcdef1234567890abcdef",
                &["proc-macro"],
                &[],
            ),
            row_with_compile_key(
                "proc-macro2",
                "1.0.106",
                "1234567890abcdef",
                "1234567890abcdef1234567890abcdef",
                &["proc-macro"],
                &[],
            ),
        ];
        let catalog_rows = rows.iter().collect::<Vec<_>>();

        let semantic_catalog = build_semantic_catalog(&catalog_rows).unwrap();
        let semantic_key = (
            "proc-macro2".to_owned(),
            Version::parse("1.0.106").unwrap(),
            "[\"proc-macro\"]".to_owned(),
        );
        assert_eq!(
            semantic_catalog.artifact_counts.get(&semantic_key),
            Some(&1)
        );

        let exact_catalog = build_exact_artifact_catalog(&catalog_rows).unwrap();
        let artifacts = exact_catalog.get(&semantic_key).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].c_metadata.as_str(), "1234567890abcdef");
    }

    /// The full analyze path over an in-memory slice: the covered root
    /// reports its artifacts and the uncovered dep produces an enqueue
    /// request — all without a server round trip.
    #[test]
    fn analyze_covers_hits_and_reports_misses() {
        let dep_a = key("dep-a", "1.0.0");
        let dep_b = key("dep-b", "1.0.0");
        let missing = key("dep-c", "2.0.0");
        let rows = vec![
            row(
                "dep-a",
                "1.0.0",
                "aaaaaaaaaaaaaaaa",
                &[],
                &[("dep-b", "bbbbbbbbbbbbbbbb")],
            ),
            row("dep-b", "1.0.0", "bbbbbbbbbbbbbbbb", &[], &[]),
        ];
        let entries = vec![
            DependencyGraphEntry {
                crate_name: dep_a.crate_name.clone(),
                version: dep_a.version.clone(),
                features: Vec::new(),
            },
            DependencyGraphEntry {
                crate_name: missing.crate_name.clone(),
                version: missing.version.clone(),
                features: Vec::new(),
            },
        ];
        let expanded_entries = vec![
            ResolvedDependencyGraphEntry {
                crate_name: dep_a.crate_name.clone(),
                version: dep_a.version.clone(),
                features: Vec::new(),
                dependencies: vec![ResolvedDependencyGraphDependency {
                    crate_name: dep_b.crate_name.clone(),
                    version: dep_b.version.clone(),
                }],
            },
            ResolvedDependencyGraphEntry {
                crate_name: dep_b.crate_name.clone(),
                version: dep_b.version,
                features: Vec::new(),
                dependencies: Vec::new(),
            },
            ResolvedDependencyGraphEntry {
                crate_name: missing.crate_name.clone(),
                version: missing.version.clone(),
                features: Vec::new(),
                dependencies: Vec::new(),
            },
        ];
        let feature_graphs = BTreeMap::from([
            (dep_a, PackageFeatureGraph::default()),
            (missing, PackageFeatureGraph::default()),
        ]);

        let analysis = analyze_dependency_graph(
            &rows,
            &entries,
            &expanded_entries,
            &feature_graphs,
            &target(),
            &rustc(),
        )
        .expect("analyze");

        assert_eq!(analysis.expanded_total, 3);
        assert_eq!(analysis.expanded_cached, 2);
        assert_eq!(analysis.expanded_entries.len(), 3);
        assert_eq!(analysis.entries.len(), 2);
        assert_eq!(analysis.entries[0].current_artifact_count, 1);
        assert_eq!(analysis.entries[1].current_artifact_count, 0);
        let prefetch = analysis
            .prefetch_artifacts
            .iter()
            .map(|entry| (entry.crate_name.as_str(), entry.c_metadata.as_str()))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            prefetch,
            BTreeSet::from([("dep-a", "aaaaaaaaaaaaaaaa"), ("dep-b", "bbbbbbbbbbbbbbbb"),])
        );
        assert_eq!(analysis.enqueue_requests.len(), 1);
        assert_eq!(analysis.enqueue_requests[0].crate_name.as_str(), "dep-c");
        assert_eq!(analysis.enqueue_requests[0].version.to_string(), "2.0.0");
    }

    /// Semantic lookup: the newest compatible upgrade wins over an exact
    /// version match, and emit coverage gates the candidates.
    #[test]
    fn semantic_lookup_prefers_newest_compatible_version_and_covering_emit() {
        let rows = vec![
            row("serde", "1.4.9", "aaaaaaaaaaaaaaaa", &["default"], &[]),
            row("serde", "1.4.3", "bbbbbbbbbbbbbbbb", &["default"], &[]),
        ];
        let request = SemanticArtifactRequest {
            crate_name: CrateName::parse("serde").expect("name"),
            version: CrateVersion::new(Version::parse("1.4.3").expect("version")),
            features_json: FeaturesJson::canonicalize(vec!["default".to_owned()])
                .expect("features"),
            dependency_c_metadata_json: DependencyCMetadataJson::default(),
            target: target(),
            rustc_version: rustc(),
            profile: rows[0].profile.clone(),
            emit: vec!["link".to_owned()],
            kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
        };

        let found = find_semantic_artifact(&rows, &request)
            .expect("lookup")
            .expect("candidate");
        assert_eq!(found.version.as_semver(), &Version::parse("1.4.9").unwrap());

        let mut upgrade_only = request.clone();
        upgrade_only.version = CrateVersion::new(Version::parse("9.9.9").expect("version"));
        assert!(
            find_semantic_artifact(&rows, &upgrade_only)
                .expect("lookup")
                .is_none()
        );
    }
}

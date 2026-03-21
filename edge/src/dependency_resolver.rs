use std::collections::{BTreeMap, BTreeSet, VecDeque};

use cargo_platform::{Cfg, Platform};
use semver::{Version, VersionReq};
use skyzen_cloudflare::{CfFetch, worker};
use skyzen_services::Db;
use stow_types::api::{
    BatchArtifactRequestEntry, DependencyGraphEntry, EnqueueDependency, EnqueueRequest,
    EnqueueSource,
};
use target_lexicon::{Endianness, Environment, OperatingSystem, Triple};

use crate::sql_batch;

const CRATES_IO_API_BASE: &str = "https://crates.io/api/v1/crates";
const CRATES_IO_USER_AGENT: &str = "stow-edge/graph-resolver";
const CACHE_TTL_SQL: &str = "-6 hours";
const MAX_EXPANDED_TASKS: usize = 4096;

pub struct ExpandedSchedulerPlan {
    pub enqueue_requests: Vec<EnqueueRequest>,
    pub expanded_cached: usize,
    pub expanded_total: usize,
    pub prefetch_artifacts: Vec<BatchArtifactRequestEntry>,
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
    crate_name: String,
    version: String,
    features_json: String,
    c_metadata: String,
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
) -> Result<ExpandedSchedulerPlan, String> {
    let mut states = BTreeMap::<PackageKey, NodeState>::new();
    let mut queue = VecDeque::<PackageKey>::new();

    for root in roots {
        let key = PackageKey {
            crate_name: root.crate_name.clone(),
            version: root.version.clone(),
        };
        let seed_features = normalize_feature_set(root.features.clone())?;
        let features = resolve_root_features(db, &root.crate_name, &root.version, &seed_features)
            .await?;
        let state = states.entry(key.clone()).or_default();
        if merge_feature_sets(&mut state.features, &features) {
            queue.push_back(key);
        }
    }

    while let Some(node_key) = queue.pop_front() {
        if states.len() > MAX_EXPANDED_TASKS {
            return Err(format!(
                "expanded dependency task list exceeds limit {}",
                MAX_EXPANDED_TASKS
            ));
        }

        let current_features = states
            .get(&node_key)
            .map(|state| state.features.clone())
            .ok_or_else(|| {
                format!(
                    "missing node state for {} {}",
                    node_key.crate_name, node_key.version
                )
            })?;
        let graph =
            fetch_version_graph_cached(db, node_key.crate_name.as_str(), &node_key.version).await?;
        let resolved = resolve_node(&graph, &current_features, target)?;
        let mut resolved_dependency_keys = BTreeSet::<PackageKey>::new();
        let mut dependency_feature_updates = Vec::<(PackageKey, BTreeSet<String>)>::new();

        for dependency_request in resolved.dependency_requests {
            let dependency_version = resolve_dependency_version(
                db,
                dependency_request.crate_name.as_str(),
                dependency_request.req.as_str(),
            )
            .await?;
            let dependency_key = PackageKey {
                crate_name: dependency_request.crate_name,
                version: dependency_version.clone(),
            };
            resolved_dependency_keys.insert(dependency_key.clone());
            let dependency_graph = fetch_version_graph_cached(
                db,
                dependency_key.crate_name.as_str(),
                &dependency_version,
            )
            .await?;
            let dependency_features =
                resolve_local_features(&dependency_graph, &dependency_request.feature_seeds)?;
            dependency_feature_updates.push((dependency_key, dependency_features));
        }

        let state = states.get_mut(&node_key).ok_or_else(|| {
            format!(
                "missing mutable node state for {} {}",
                node_key.crate_name, node_key.version
            )
        })?;
        state.features = resolved.local_features.clone();
        state.dependencies = resolved_dependency_keys;

        for (dependency_key, dependency_features) in dependency_feature_updates {
            let dependency_state = states.entry(dependency_key.clone()).or_default();
            if merge_feature_sets(&mut dependency_state.features, &dependency_features) {
                queue.push_back(dependency_key);
            }
        }
    }

    let feature_json_by_key = states
        .iter()
        .map(|(key, state)| Ok::<_, String>((key.clone(), serialize_feature_set(&state.features)?)))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let cached = load_cached_artifacts(
        db,
        target,
        rustc_version,
        feature_json_by_key
            .iter()
            .map(|(key, features_json)| (key.clone(), features_json.clone())),
    )
    .await?;
    let expanded_total = feature_json_by_key.len();
    let expanded_cached = feature_json_by_key
        .iter()
        .filter(|(node_key, features_json)| {
            cached
                .semantic_keys
                .contains(&((*node_key).clone(), (*features_json).clone()))
        })
        .count();
    let mut requests = Vec::<EnqueueRequest>::new();
    for (node_key, state) in states {
        let features_json = feature_json_by_key.get(&node_key).cloned().ok_or_else(|| {
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
        let depends_on = state
            .dependencies
            .into_iter()
            .filter_map(|dependency_key| {
                let dependency_features_json = feature_json_by_key.get(&dependency_key).cloned()?;
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
                })
            })
            .collect::<Vec<_>>();
        requests.push(EnqueueRequest {
            crate_name: node_key.crate_name,
            version: node_key.version.to_string(),
            features_json,
            target: target.to_owned(),
            downloads: 0,
            source: EnqueueSource::CacheMiss,
            depends_on,
        });
    }
    Ok(ExpandedSchedulerPlan {
        enqueue_requests: requests,
        expanded_cached,
        expanded_total,
        prefetch_artifacts: cached.prefetch_artifacts,
    })
}

async fn load_cached_artifacts(
    db: &Db,
    target: &str,
    rustc_version: &str,
    keys: impl IntoIterator<Item = (PackageKey, String)>,
) -> Result<CachedArtifacts, String> {
    let key_pairs = keys.into_iter().collect::<BTreeSet<_>>();
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
    let mut semantic_keys = BTreeSet::<(PackageKey, String)>::new();
    let mut prefetch_artifacts = BTreeSet::<(String, String)>::new();
    for batch in crate_names.chunks(sql_batch::SQLITE_IN_CLAUSE_BATCH_SIZE) {
        let sql = format!(
            "SELECT crate_name, version, features_json, c_metadata \
             FROM artifacts \
             WHERE target = ? AND rustc_version = ? AND crate_name IN ({})",
            sql_batch::placeholders(batch.len())
        );
        let mut query = db.query(&sql).bind(target).bind(rustc_version);
        for crate_name in batch {
            query = query.bind(crate_name.as_str());
        }
        let rows = query
            .fetch_all::<CachedArtifactRow>()
            .await
            .map_err(|error| format!("load cached semantic keys: {error}"))?;
        for row in rows {
            let version = Version::parse(&row.version)
                .map_err(|error| format!("parse cached semver {}: {error}", row.version))?;
            let semantic_key = (
                PackageKey {
                    crate_name: row.crate_name.clone(),
                    version,
                },
                row.features_json,
            );
            if key_pairs.contains(&semantic_key) {
                semantic_keys.insert(semantic_key);
                prefetch_artifacts.insert((row.crate_name, row.c_metadata));
            }
        }
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

fn dependency_matches_target(dependency: &CratesIoDependency, target: &str) -> Result<bool, String> {
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
        "macos" | "ios" | "tvos" | "watchos" | "visionos" | "linux" | "android"
        | "freebsd" | "dragonfly" | "netbsd" | "openbsd" | "solaris" | "illumos"
        | "haiku" | "redox" | "hurd" | "aix" => {
            cfgs.push(Cfg::Name("unix".to_owned()));
            cfgs.push(Cfg::KeyPair(
                "target_family".to_owned(),
                "unix".to_owned(),
            ));
        }
        "wasi" | "wasip1" | "wasip2" | "emscripten" => {
            cfgs.push(Cfg::KeyPair(
                "target_family".to_owned(),
                "wasm".to_owned(),
            ));
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

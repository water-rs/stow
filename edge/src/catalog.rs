//! Crate catalog lookups: search, published versions, and selectable
//! features.
//!
//! These back the three controls on the request form — a crate search box, a
//! version picker, and feature checkboxes — so a submission is assembled
//! from what crates.io actually publishes instead of typed free-hand. Every
//! answer is derived from the same [`CratesIo`] boundary and the same
//! TTL-bounded D1 caches the dependency resolver uses, so a catalog lookup
//! and a later graph expansion of the same version share one round trip.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use semver::Version;
use skyzen_services::Db;
use stow_types::api::{
    CrateFeature, CrateFeaturesResponse, CrateSearchHit, CrateSearchResponse, CrateVersionsResponse,
};
use stow_types::identity::{CrateName, CrateVersion};

use crate::dependency_resolver::{
    CratesIo, published_versions, selectable_features, version_feature_graph,
};
use crate::errors::ResolverError;

/// Shortest query the search endpoint accepts. One character matches most of
/// the registry and tells the user nothing, so the form waits for two.
pub const MIN_SEARCH_QUERY_LEN: usize = 2;

/// Results returned when the caller names no `limit`.
pub const DEFAULT_SEARCH_LIMIT: u32 = 10;

/// Ceiling on `limit`: a larger value is clamped to this rather than
/// rejected, so one query can never fan out into an unbounded crates.io
/// page.
pub const MAX_SEARCH_LIMIT: u32 = 25;

/// The feature cargo enables when a build does not pass
/// `--no-default-features`.
const DEFAULT_FEATURE: &str = "default";

/// Search crates.io for `query`, most relevant first.
///
/// `limit` is clamped into <code>1..=[MAX_SEARCH_LIMIT]</code>. The query must be at
/// least [`MIN_SEARCH_QUERY_LEN`] characters after trimming; a shorter one is
/// the caller's error, not an empty result.
pub async fn search_crates(
    crates_io: &impl CratesIo,
    query: &str,
    limit: u32,
) -> Result<CrateSearchResponse, ResolverError> {
    let query = query.trim();
    if query.chars().count() < MIN_SEARCH_QUERY_LEN {
        return Err(ResolverError::BadRequest(format!(
            "search query must be at least {MIN_SEARCH_QUERY_LEN} characters"
        )));
    }
    let limit = limit.clamp(1, MAX_SEARCH_LIMIT);
    let hits = crates_io.search(query, limit).await?;
    let crates = hits
        .into_iter()
        .map(|hit| {
            // crates.io reports the newest prerelease as `max_version`; a
            // crate's stable line is what a build request should default to,
            // and only a crate that has never published a stable release
            // falls back to the prerelease.
            let displayed = hit.max_stable_version.unwrap_or(hit.max_version);
            Ok(CrateSearchHit {
                crate_name: hit.name.parse::<CrateName>()?,
                description: hit.description,
                max_version: CrateVersion(Version::parse(&displayed).map_err(|error| {
                    ResolverError::Json(format!(
                        "parse crates.io search version {} {displayed}: {error}",
                        hit.name
                    ))
                })?),
                downloads: hit.downloads,
            })
        })
        .collect::<Result<Vec<_>, ResolverError>>()?;
    Ok(CrateSearchResponse { crates })
}

/// Every published, non-yanked version of `crate_name`, newest first.
pub async fn crate_versions(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
) -> Result<CrateVersionsResponse, ResolverError> {
    let versions = published_versions(db, crates_io, crate_name)
        .await?
        .into_iter()
        .map(CrateVersion)
        .collect();
    Ok(CrateVersionsResponse { versions })
}

/// Every feature a caller may select on `crate_name@version`, `default`
/// first and the rest alphabetical.
pub async fn crate_features(
    db: &Db,
    crates_io: &impl CratesIo,
    crate_name: &str,
    version: &Version,
) -> Result<CrateFeaturesResponse, ResolverError> {
    let graph = version_feature_graph(db, crates_io, crate_name, version).await?;
    Ok(CrateFeaturesResponse {
        features: describe_features(&graph.features, &graph.dependencies),
    })
}

/// Turn a declared feature table and dependency list into the selectable
/// feature list the form renders.
fn describe_features(
    features: &BTreeMap<String, Vec<String>>,
    dependencies: &[crate::dependency_resolver::CratesIoDependency],
) -> Vec<CrateFeature> {
    let selectable = selectable_features(features, dependencies);
    let enabled_by_default = default_closure(features, &selectable);
    let mut described = selectable
        .into_iter()
        .map(|name| CrateFeature {
            // An optional dependency's implicit feature declares nothing;
            // enabling it just pulls the dependency in.
            implies: features.get(&name).cloned().unwrap_or_default(),
            default: enabled_by_default.contains(&name),
            name,
        })
        .collect::<Vec<_>>();
    // `default` is the one feature whose meaning is "everything the crate
    // ships with", so it leads; the rest stay in the alphabetical order
    // `selectable_features` produced.
    described.sort_by_key(|feature| feature.name != DEFAULT_FEATURE);
    described
}

/// The selectable features `default` turns on, transitively, including
/// `default` itself. Mirrors the traversal in
/// `dependency_resolver::resolve_local_features`: `dep:x` and `x/y` items
/// name a dependency, not a feature of this crate.
fn default_closure(
    features: &BTreeMap<String, Vec<String>>,
    selectable: &BTreeSet<String>,
) -> BTreeSet<String> {
    if !features.contains_key(DEFAULT_FEATURE) {
        return BTreeSet::new();
    }
    let mut enabled = BTreeSet::from([DEFAULT_FEATURE.to_owned()]);
    let mut queue = VecDeque::from([DEFAULT_FEATURE.to_owned()]);
    while let Some(feature) = queue.pop_front() {
        let Some(items) = features.get(&feature) else {
            continue;
        };
        for item in items {
            if item.starts_with("dep:") || item.contains('/') {
                continue;
            }
            if selectable.contains(item) && enabled.insert(item.clone()) {
                queue.push_back(item.clone());
            }
        }
    }
    enabled
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use semver::Version;
    use stow_types::api::CrateFeature;

    use super::{
        DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT, crate_features, crate_versions, describe_features,
        search_crates,
    };
    use crate::dependency_resolver::{CratesIo, CratesIoDependency, CratesIoSearchHit};
    use crate::errors::ResolverError;

    /// Canned crates.io: `search` and `package_metadata` read the same
    /// version map, so a test declares a crate once.
    struct StubCratesIo {
        versions: BTreeMap<String, Vec<String>>,
        features: BTreeMap<(String, String), BTreeMap<String, Vec<String>>>,
        dependencies: BTreeMap<(String, String), Vec<CratesIoDependency>>,
        /// Every `search` call the stub answered, for limit assertions.
        searched: std::sync::Mutex<Vec<(String, u32)>>,
    }

    impl StubCratesIo {
        fn new(versions: BTreeMap<String, Vec<String>>) -> Self {
            Self {
                versions,
                features: BTreeMap::new(),
                dependencies: BTreeMap::new(),
                searched: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl CratesIo for StubCratesIo {
        async fn package_metadata(
            &self,
            crate_name: &str,
        ) -> Result<Vec<crate::dependency_resolver::PublishedRelease>, ResolverError> {
            let versions =
                self.versions
                    .get(crate_name)
                    .ok_or_else(|| ResolverError::CrateNotPublished {
                        crate_name: crate_name.to_owned(),
                    })?;
            Ok(versions
                .iter()
                .map(|version| crate::dependency_resolver::PublishedRelease {
                    version: Version::parse(version).expect("stub semver"),
                    yanked: false,
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
        async fn search(
            &self,
            query: &str,
            limit: u32,
        ) -> Result<Vec<CratesIoSearchHit>, ResolverError> {
            self.searched
                .lock()
                .expect("stub search log")
                .push((query.to_owned(), limit));
            Ok(self
                .versions
                .iter()
                .filter(|(name, _)| name.contains(query))
                .take(limit as usize)
                .map(|(name, versions)| CratesIoSearchHit {
                    name: name.clone(),
                    description: Some(format!("{name} description")),
                    max_stable_version: versions.last().cloned(),
                    max_version: versions.last().cloned().unwrap_or_default(),
                    downloads: 7,
                })
                .collect())
        }
    }

    fn optional_dependency(name: &str) -> CratesIoDependency {
        CratesIoDependency {
            name: name.to_owned(),
            crate_id: name.to_owned(),
            optional: true,
            ..CratesIoDependency::default()
        }
    }

    /// `alias = { package = "real", optional = true }`: cargo grants the
    /// implicit feature `alias`, and `real` is only what gets built.
    fn renamed_optional_dependency(name: &str, package: &str) -> CratesIoDependency {
        CratesIoDependency {
            name: name.to_owned(),
            crate_id: package.to_owned(),
            optional: true,
            ..CratesIoDependency::default()
        }
    }

    async fn memory_db() -> skyzen_services::Db {
        let db = skyzen_services::Db::connect_sqlite_memory()
            .await
            .expect("memory db");
        crate::db::apply_migrations(&db).await;
        db
    }

    #[tokio::test]
    async fn search_rejects_a_one_character_query() {
        let crates_io = StubCratesIo::new(BTreeMap::new());
        let error = search_crates(&crates_io, " s ", DEFAULT_SEARCH_LIMIT)
            .await
            .expect_err("one character is below the floor");
        assert!(matches!(error, ResolverError::BadRequest(_)), "{error}");
    }

    #[tokio::test]
    async fn search_clamps_the_limit_and_trims_the_query() {
        let crates_io = StubCratesIo::new(BTreeMap::from([(
            "serde".to_owned(),
            vec!["1.0.0".to_owned(), "1.0.219".to_owned()],
        )]));

        let response = search_crates(&crates_io, "  serde  ", MAX_SEARCH_LIMIT + 500)
            .await
            .expect("search");

        assert_eq!(
            crates_io.searched.lock().expect("log").as_slice(),
            &[("serde".to_owned(), MAX_SEARCH_LIMIT)]
        );
        assert_eq!(response.crates.len(), 1);
        assert_eq!(response.crates[0].crate_name.as_str(), "serde");
        assert_eq!(response.crates[0].max_version.to_string(), "1.0.219");
    }

    #[tokio::test]
    async fn versions_come_back_newest_first() {
        let db = memory_db().await;
        let crates_io = StubCratesIo::new(BTreeMap::from([(
            "serde".to_owned(),
            vec![
                "1.0.0".to_owned(),
                "1.0.219".to_owned(),
                "1.0.100".to_owned(),
            ],
        )]));

        let response = crate_versions(&db, &crates_io, "serde")
            .await
            .expect("versions");

        let versions = response
            .versions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(versions, ["1.0.219", "1.0.100", "1.0.0"]);
    }

    #[tokio::test]
    async fn an_unpublished_crate_has_no_version_list() {
        let db = memory_db().await;
        let crates_io = StubCratesIo::new(BTreeMap::new());

        let error = crate_versions(&db, &crates_io, "definitely-not-a-crate")
            .await
            .expect_err("unpublished");

        assert!(
            matches!(error, ResolverError::CrateNotPublished { .. }),
            "{error}"
        );
    }

    #[tokio::test]
    async fn features_lead_with_default_and_mark_its_closure() {
        let db = memory_db().await;
        let mut crates_io = StubCratesIo::new(BTreeMap::from([(
            "serde".to_owned(),
            vec!["1.0.219".to_owned()],
        )]));
        crates_io.features = BTreeMap::from([(
            ("serde".to_owned(), "1.0.219".to_owned()),
            BTreeMap::from([
                ("default".to_owned(), vec!["std".to_owned()]),
                ("std".to_owned(), Vec::new()),
                ("derive".to_owned(), vec!["dep:serde_derive".to_owned()]),
                ("alloc".to_owned(), Vec::new()),
            ]),
        )]);

        let response = crate_features(&db, &crates_io, "serde", &Version::new(1, 0, 219))
            .await
            .expect("features");

        let names = response
            .features
            .iter()
            .map(|feature| feature.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["default", "alloc", "derive", "std"]);
        let by_name = |name: &str| -> &CrateFeature {
            response
                .features
                .iter()
                .find(|feature| feature.name == name)
                .expect("feature listed")
        };
        assert!(by_name("default").default);
        assert!(by_name("std").default);
        assert!(!by_name("derive").default);
        assert_eq!(by_name("derive").implies, ["dep:serde_derive"]);
    }

    #[test]
    fn an_optional_dependency_is_selectable_without_declaring_a_feature() {
        // slab's shape: `serde` is optional and no declared feature names it
        // through `dep:`, so cargo grants an implicit feature that a caller
        // may select even though `[features]` never mentions it.
        let described = describe_features(
            &BTreeMap::from([("default".to_owned(), vec!["std".to_owned()])]),
            &[optional_dependency("serde")],
        );

        let names = described
            .iter()
            .map(|feature| feature.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["default", "serde"]);
        let implicit = &described[1];
        assert!(implicit.implies.is_empty(), "{:?}", implicit.implies);
        assert!(!implicit.default);
    }

    #[test]
    fn a_dep_referenced_optional_dependency_is_not_selectable() {
        // A declared feature reaching the dependency through `dep:` hides
        // the implicit feature, so `foo` must not appear as a checkbox.
        let described = describe_features(
            &BTreeMap::from([("full".to_owned(), vec!["dep:foo".to_owned()])]),
            &[optional_dependency("foo")],
        );

        let names = described
            .iter()
            .map(|feature| feature.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["full"]);
    }

    #[test]
    fn a_renamed_optional_dependency_is_offered_under_its_declared_name() {
        // `cookie_crate = { package = "cookie", optional = true }` — the one
        // feature cargo accepts is `cookie_crate`. Offering `cookie` mints a
        // task whose build dies on "does not contain this feature".
        let described = describe_features(
            &BTreeMap::new(),
            &[renamed_optional_dependency("cookie_crate", "cookie")],
        );

        let names = described
            .iter()
            .map(|feature| feature.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["cookie_crate"]);
    }

    #[test]
    fn dep_hides_a_renamed_optional_dependency_by_its_declared_name() {
        // `dep:` spells the alias too, so the implicit feature it hides is
        // `cookie_crate` — matching on the package name would hide nothing.
        let described = describe_features(
            &BTreeMap::from([("cookies".to_owned(), vec!["dep:cookie_crate".to_owned()])]),
            &[renamed_optional_dependency("cookie_crate", "cookie")],
        );

        let names = described
            .iter()
            .map(|feature| feature.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["cookies"]);
    }

    #[test]
    fn default_marks_its_whole_closure_not_just_the_first_level() {
        // `default -> std -> alloc`: a traversal that stopped at depth one
        // would leave `alloc` unmarked and the form would show it unticked
        // while the build enables it.
        let described = describe_features(
            &BTreeMap::from([
                ("default".to_owned(), vec!["std".to_owned()]),
                ("std".to_owned(), vec!["alloc".to_owned()]),
                ("alloc".to_owned(), Vec::new()),
                ("unrelated".to_owned(), Vec::new()),
            ]),
            &[],
        );

        let marked = described
            .iter()
            .filter(|feature| feature.default)
            .map(|feature| feature.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(marked, ["default", "alloc", "std"]);
    }

    #[test]
    fn a_crate_without_a_default_feature_marks_nothing_default() {
        let described = describe_features(&BTreeMap::from([("std".to_owned(), Vec::new())]), &[]);

        assert_eq!(described.len(), 1);
        assert!(!described[0].default);
    }
}

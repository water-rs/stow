use crate::core::{Dependency, PackageId, SourceId};
use crate::util::CargoResult;
use crate::util::closest_msg;
use crate::util::interning::InternedString;
use anyhow::bail;
use cargo_util_schemas::manifest::FeatureName;
use cargo_util_schemas::manifest::RustVersion;
use semver::Version;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::mem;
use std::sync::Arc;

/// Subset of a `Manifest`. Contains only the most important information about
/// a package.
///
/// Summaries are cloned, and should not be mutated after creation
#[derive(Debug, Clone)]
pub struct Summary {
    inner: Arc<Inner>,
}

#[derive(Debug, Clone)]
struct Inner {
    package_id: PackageId,
    dependencies: Vec<Dependency>,
    features: Arc<FeatureMap>,
    checksum: Option<String>,
    links: Option<InternedString>,
    /// `Arc` so summaries carrying the same `rust_version` share it —
    /// interned like the feature map in [`Summary::share_parts`].
    rust_version: Option<Arc<RustVersion>>,
    pubtime: Option<jiff::Timestamp>,
}

/// Indicates the dependency inferred from the `dep` syntax that should exist,
/// but missing on the resolved dependencies tables.
#[derive(Debug)]
pub struct MissingDependencyError {
    pub dep_name: InternedString,
    pub feature: InternedString,
    pub feature_value: FeatureValue,
    /// Indicates the dependency inferred from the `dep?` syntax that is weak optional
    pub weak_optional: bool,
}

impl std::error::Error for MissingDependencyError {}

impl fmt::Display for MissingDependencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            dep_name,
            feature,
            feature_value: fv,
            ..
        } = self;

        write!(
            f,
            "feature `{feature}` includes `{fv}`, but `{dep_name}` is not a dependency",
        )
    }
}

impl Summary {
    #[tracing::instrument(skip_all)]
    pub fn new(
        pkg_id: PackageId,
        dependencies: Vec<Dependency>,
        features: &BTreeMap<InternedString, Vec<InternedString>>,
        links: Option<impl Into<InternedString>>,
        rust_version: Option<RustVersion>,
    ) -> CargoResult<Summary> {
        // ****CAUTION**** If you change anything here that may raise a new
        // error, be sure to coordinate that change with either the index
        // schema field or the SummariesCache version.
        Self::check_dependencies(&dependencies)?;
        let feature_map = build_feature_map(features, &dependencies)?;
        Ok(Summary {
            inner: Arc::new(Inner {
                package_id: pkg_id,
                dependencies,
                features: Arc::new(feature_map),
                checksum: None,
                links: links.map(|l| l.into()),
                rust_version: rust_version.map(Arc::new),
                pubtime: None,
            }),
        })
    }

    /// Rejects an optional dev-dependency — the check [`Summary::new`] runs
    /// before building its feature map. Exposed for [`new_shared`]'s callers
    /// so parse-path error precedence stays identical.
    ///
    /// [`new_shared`]: Summary::new_shared
    pub(crate) fn check_dependencies(dependencies: &[Dependency]) -> CargoResult<()> {
        for dep in dependencies.iter() {
            let dep_name = dep.name_in_toml();
            if dep.is_optional() && !dep.is_transitive() {
                bail!(
                    "dev-dependencies are not allowed to be optional: `{}`",
                    dep_name
                )
            }
        }
        Ok(())
    }

    /// A summary whose dependencies and feature map were already interned —
    /// the registry-index seam. Runs the same dev-dependency check as
    /// [`Summary::new`] but skips `build_feature_map`.
    pub(crate) fn new_shared(
        pkg_id: PackageId,
        dependencies: Vec<Dependency>,
        features: Arc<FeatureMap>,
        links: Option<impl Into<InternedString>>,
        rust_version: Option<Arc<RustVersion>>,
    ) -> CargoResult<Summary> {
        Self::check_dependencies(&dependencies)?;
        Ok(Summary {
            inner: Arc::new(Inner {
                package_id: pkg_id,
                dependencies,
                features,
                checksum: None,
                links: links.map(|l| l.into()),
                rust_version,
                pubtime: None,
            }),
        })
    }

    pub fn package_id(&self) -> PackageId {
        self.inner.package_id
    }
    pub fn name(&self) -> InternedString {
        self.package_id().name()
    }
    pub fn version(&self) -> &Version {
        self.package_id().version()
    }
    pub fn source_id(&self) -> SourceId {
        self.package_id().source_id()
    }
    pub fn dependencies(&self) -> &[Dependency] {
        &self.inner.dependencies
    }
    pub fn features(&self) -> &FeatureMap {
        &self.inner.features
    }

    #[cfg(test)]
    pub(crate) fn features_arc(&self) -> &Arc<FeatureMap> {
        &self.inner.features
    }

    pub(crate) fn share_parts(
        mut self,
        mut dep: impl FnMut(Dependency) -> Dependency,
        features: impl FnOnce(Arc<FeatureMap>) -> Arc<FeatureMap>,
        rust_version: impl FnOnce(Arc<RustVersion>) -> Arc<RustVersion>,
    ) -> Summary {
        let inner = Arc::make_mut(&mut self.inner);
        for dependency in &mut inner.dependencies {
            *dependency = dep(dependency.clone());
        }
        inner.dependencies.shrink_to_fit();
        inner.features = features(Arc::clone(&inner.features));
        if let Some(rv) = inner.rust_version.take() {
            inner.rust_version = Some(rust_version(rv));
        }
        self
    }

    pub fn checksum(&self) -> Option<&str> {
        self.inner.checksum.as_deref()
    }
    pub fn links(&self) -> Option<InternedString> {
        self.inner.links
    }

    pub fn rust_version(&self) -> Option<&RustVersion> {
        self.inner.rust_version.as_deref()
    }

    pub fn pubtime(&self) -> Option<jiff::Timestamp> {
        self.inner.pubtime
    }

    pub fn override_id(mut self, id: PackageId) -> Summary {
        Arc::make_mut(&mut self.inner).package_id = id;
        self
    }

    pub fn set_checksum(&mut self, cksum: String) {
        Arc::make_mut(&mut self.inner).checksum = Some(cksum);
    }

    pub fn set_pubtime(&mut self, pubtime: jiff::Timestamp) {
        Arc::make_mut(&mut self.inner).pubtime = Some(pubtime);
    }

    pub fn map_dependencies<F>(self, mut f: F) -> Summary
    where
        F: FnMut(Dependency) -> Dependency,
    {
        self.try_map_dependencies(|dep| Ok(f(dep))).unwrap()
    }

    /// Maps owned summaries in place and copies shared ones only when dependencies change.
    pub fn try_map_dependencies<F>(mut self, mut f: F) -> CargoResult<Summary>
    where
        F: FnMut(Dependency) -> CargoResult<Dependency>,
    {
        if let Some(inner) = Arc::get_mut(&mut self.inner) {
            inner.dependencies = mem::take(&mut inner.dependencies)
                .into_iter()
                .map(f)
                .collect::<CargoResult<_>>()?;
            return Ok(self);
        }

        let mut mapped: Option<Vec<Dependency>> = None;
        for (i, dep) in self.inner.dependencies.iter().enumerate() {
            let new = f(dep.clone())?;
            match &mut mapped {
                Some(deps) => deps.push(new),
                None if new.ptr_eq(dep) => {}
                None => {
                    let mut deps = Vec::with_capacity(self.inner.dependencies.len());
                    deps.extend(self.inner.dependencies[..i].iter().cloned());
                    deps.push(new);
                    mapped = Some(deps);
                }
            }
        }
        if let Some(deps) = mapped {
            Arc::make_mut(&mut self.inner).dependencies = deps;
        }
        Ok(self)
    }

    pub fn map_source(self, to_replace: SourceId, replace_with: SourceId) -> Summary {
        let me = if self.package_id().source_id() == to_replace {
            let new_id = self.package_id().with_source_id(replace_with);
            self.override_id(new_id)
        } else {
            self
        };
        me.map_dependencies(|dep| dep.map_source(to_replace, replace_with))
    }
}

impl PartialEq for Summary {
    fn eq(&self, other: &Summary) -> bool {
        self.inner.package_id == other.inner.package_id
    }
}

impl Eq for Summary {}

impl Hash for Summary {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.package_id.hash(state);
    }
}

// A check that only compiles if Summary is Sync
const _: fn() = || {
    fn is_sync<T: Sync>() {}
    is_sync::<Summary>();
};

/// Checks features for errors, bailing out a CargoResult:Err if invalid,
/// and creates `FeatureValues` for each feature.
pub(crate) fn build_feature_map(
    features: &BTreeMap<InternedString, Vec<InternedString>>,
    dependencies: &[Dependency],
) -> CargoResult<FeatureMap> {
    use self::FeatureValue::*;
    // A map of dependency names to whether there are any that are optional.
    let mut dep_map: HashMap<InternedString, bool> = HashMap::new();
    for dep in dependencies.iter() {
        *dep_map.entry(dep.name_in_toml()).or_insert(false) |= dep.is_optional();
    }
    let dep_map = dep_map; // We are done mutating this variable

    let mut map: BTreeMap<InternedString, Vec<FeatureValue>> = features
        .iter()
        .map(|(feature, list)| {
            let fvs: Vec<_> = list
                .iter()
                .map(|feat_value| FeatureValue::new(*feat_value))
                .collect();
            (*feature, fvs)
        })
        .collect();

    // Add implicit features for optional dependencies if they weren't
    // explicitly listed anywhere.
    let explicitly_listed: HashSet<_> = map
        .values()
        .flatten()
        .filter_map(|fv| fv.explicit_dep_name())
        .collect();

    for dep in dependencies {
        if !dep.is_optional() {
            continue;
        }
        let dep_name = dep.name_in_toml();
        if features.contains_key(&dep_name) || explicitly_listed.contains(&dep_name) {
            continue;
        }
        map.insert(dep_name, vec![Dep { dep_name }]);
    }
    let map = map; // We are done mutating this variable

    // Validate features are listed properly.
    for (feature, fvs) in &map {
        FeatureName::new(feature)?;
        for fv in fvs {
            // Find data for the referenced dependency...
            let dep_data = dep_map.get(&fv.feature_or_dep_name());
            let is_any_dep = dep_data.is_some();
            let is_optional_dep = dep_data.is_some_and(|&o| o);
            match fv {
                Feature(f) => {
                    if !features.contains_key(f) {
                        if !is_any_dep {
                            let closest = closest_msg(f, features.keys(), |k| k, "feature");
                            bail!(
                                "feature `{feature}` includes `{fv}` which is neither a dependency \
                                 nor another feature{closest}"
                            );
                        }
                        if is_optional_dep {
                            if !map.contains_key(f) {
                                bail!(
                                    "feature `{feature}` includes `{fv}`, but `{f}` is an \
                                     optional dependency without an implicit feature\n\
                                     Use `dep:{f}` to enable the dependency."
                                );
                            }
                        } else {
                            bail!(
                                "feature `{feature}` includes `{fv}`, but `{f}` is not an optional dependency\n\
                                A non-optional dependency of the same name is defined; \
                                consider adding `optional = true` to its definition."
                            );
                        }
                    }
                }
                Dep { dep_name } => {
                    if !is_any_dep {
                        bail!(
                            "feature `{feature}` includes `{fv}`, but `{dep_name}` is not listed as a dependency"
                        );
                    }
                    if !is_optional_dep {
                        bail!(
                            "feature `{feature}` includes `{fv}`, but `{dep_name}` is not an optional dependency\n\
                             A non-optional dependency of the same name is defined; \
                             consider adding `optional = true` to its definition."
                        );
                    }
                }
                DepFeature {
                    dep_name,
                    dep_feature,
                    weak,
                } => {
                    // Early check for some unlikely syntax.
                    if dep_feature.contains('/') {
                        bail!(
                            "multiple slashes in feature `{fv}` (included by feature `{feature}`) are not allowed"
                        );
                    }

                    // dep: cannot be combined with /
                    if let Some(stripped_dep) = dep_name.strip_prefix("dep:") {
                        let has_other_dep = explicitly_listed.contains(stripped_dep);
                        let is_optional = dep_map.get(stripped_dep).is_some_and(|&o| o);
                        let extra_help = if *weak || has_other_dep || !is_optional {
                            // In this case, the user should just remove dep:.
                            // Note that "hiding" an optional dependency
                            // wouldn't work with just a single `dep:foo?/bar`
                            // because there would not be any way to enable
                            // `foo`.
                            String::new()
                        } else {
                            format!(
                                "\nIf the intent is to avoid creating an implicit feature \
                                 `{stripped_dep}` for an optional dependency, \
                                 then consider replacing this with two values:\n    \
                                 \"dep:{stripped_dep}\", \"{stripped_dep}/{dep_feature}\""
                            )
                        };
                        bail!(
                            "feature `{feature}` includes `{fv}` with both `dep:` and `/`\n\
                            To fix this, remove the `dep:` prefix.{extra_help}"
                        )
                    }

                    // Validation of the feature name will be performed in the resolver.
                    if !is_any_dep {
                        bail!(MissingDependencyError {
                            feature: *feature,
                            feature_value: (*fv).clone(),
                            dep_name: *dep_name,
                            weak_optional: *weak,
                        })
                    }
                    if *weak && !is_optional_dep {
                        bail!(
                            "feature `{feature}` includes `{fv}` with a `?`, but `{dep_name}` is not an optional dependency\n\
                            A non-optional dependency of the same name is defined; \
                            consider removing the `?` or changing the dependency to be optional"
                        );
                    }
                }
            }
        }
    }

    // Make sure every optional dep is mentioned at least once.
    let used: HashSet<_> = map
        .values()
        .flatten()
        .filter_map(|fv| match fv {
            Dep { dep_name } | DepFeature { dep_name, .. } => Some(dep_name),
            _ => None,
        })
        .collect();
    if let Some((dep, _)) = dep_map
        .iter()
        .find(|&(dep, &is_optional)| is_optional && !used.contains(dep))
    {
        bail!(
            "optional dependency `{dep}` is not included in any feature\n\
            Make sure that `dep:{dep}` is included in one of features in the [features] table."
        );
    }

    Ok(FeatureMap::from(map))
}

/// `FeatureValue` represents the types of dependencies a feature can have.
#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum FeatureValue {
    /// A feature enabling another feature.
    Feature(InternedString),
    /// A feature enabling a dependency with `dep:dep_name` syntax.
    Dep { dep_name: InternedString },
    /// A feature enabling a feature on a dependency with `crate_name/feat_name` syntax.
    DepFeature {
        dep_name: InternedString,
        dep_feature: InternedString,
        /// If `true`, indicates the `?` syntax is used, which means this will
        /// not automatically enable the dependency unless the dependency is
        /// activated through some other means.
        weak: bool,
    },
}

impl FeatureValue {
    pub fn new(feature: InternedString) -> FeatureValue {
        match feature.split_once('/') {
            Some((dep, dep_feat)) => {
                let dep_name = dep.strip_suffix('?');
                FeatureValue::DepFeature {
                    dep_name: dep_name.unwrap_or(dep).into(),
                    dep_feature: dep_feat.into(),
                    weak: dep_name.is_some(),
                }
            }
            None => {
                if let Some(dep_name) = feature.strip_prefix("dep:") {
                    FeatureValue::Dep {
                        dep_name: dep_name.into(),
                    }
                } else {
                    FeatureValue::Feature(feature)
                }
            }
        }
    }

    /// Returns the name of the dependency if and only if it was explicitly named with the `dep:` syntax.
    fn explicit_dep_name(&self) -> Option<InternedString> {
        match self {
            FeatureValue::Dep { dep_name, .. } => Some(*dep_name),
            _ => None,
        }
    }

    fn feature_or_dep_name(&self) -> InternedString {
        match self {
            FeatureValue::Feature(dep_name)
            | FeatureValue::Dep { dep_name, .. }
            | FeatureValue::DepFeature { dep_name, .. } => *dep_name,
        }
    }
}

impl fmt::Display for FeatureValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::FeatureValue::*;
        match self {
            Feature(feat) => write!(f, "{feat}"),
            Dep { dep_name } => write!(f, "dep:{dep_name}"),
            DepFeature {
                dep_name,
                dep_feature,
                weak,
            } => {
                let weak = if *weak { "?" } else { "" };
                write!(f, "{dep_name}{weak}/{dep_feature}")
            }
        }
    }
}

/// The `[features]` table of a summary, kept sorted by feature name.
///
/// Stored as a single sorted slice rather than a `BTreeMap` — a map node
/// costs hundreds of bytes even for one or two features, and summaries are
/// read (get/contains/iterate), never mutated, after construction.
/// `InternedString`'s `Ord` is string order, so iteration order matches the
/// `BTreeMap` it replaces.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct FeatureMap {
    entries: Box<[(InternedString, Box<[FeatureValue]>)]>,
}

impl FeatureMap {
    /// Get the feature values for `key`.
    pub fn get(&self, key: &str) -> Option<&[FeatureValue]> {
        self.entries
            .binary_search_by(|(k, _)| k.as_str().cmp(key))
            .ok()
            .map(|i| &*self.entries[i].1)
    }

    /// Whether `key` is a defined feature.
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries
            .binary_search_by(|(k, _)| k.as_str().cmp(key))
            .is_ok()
    }

    /// Feature names in sorted order.
    pub fn keys(&self) -> impl Iterator<Item = &InternedString> + Clone + ExactSizeIterator {
        self.entries.iter().map(|(k, _)| k)
    }

    /// Feature value lists in key order.
    pub fn values(&self) -> impl Iterator<Item = &[FeatureValue]> + Clone + ExactSizeIterator {
        self.entries.iter().map(|(_, v)| &**v)
    }

    /// `(name, values)` pairs in key order.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = (&InternedString, &[FeatureValue])> + Clone + ExactSizeIterator {
        self.entries.iter().map(|(k, v)| (k, &**v))
    }

    /// Number of defined features.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no features are defined.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl From<BTreeMap<InternedString, Vec<FeatureValue>>> for FeatureMap {
    fn from(map: BTreeMap<InternedString, Vec<FeatureValue>>) -> FeatureMap {
        FeatureMap {
            entries: map
                .into_iter()
                .map(|(k, v)| (k, v.into_boxed_slice()))
                .collect(),
        }
    }
}

impl<'a> IntoIterator for &'a FeatureMap {
    type Item = (&'a InternedString, &'a [FeatureValue]);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (InternedString, Box<[FeatureValue]>)>,
        fn(&'a (InternedString, Box<[FeatureValue]>)) -> (&'a InternedString, &'a [FeatureValue]),
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter().map(|(k, v)| (k, &**v))
    }
}

#[cfg(test)]
mod tests {
    use super::Summary;
    use crate::core::{Dependency, FeatureMap, FeatureValue, PackageId, SourceId};
    use crate::util::interning::InternedString;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn summary_with_dependencies() -> Summary {
        let source_id =
            SourceId::from_url("registry+https://github.com/rust-lang/crates.io-index").unwrap();
        let dependencies = ["first", "second", "third"]
            .into_iter()
            .map(|name| Dependency::parse(name, Some("1"), source_id).unwrap())
            .collect();
        Summary::new(
            PackageId::try_new("summary-mapper", "1.0.0", source_id).unwrap(),
            dependencies,
            &BTreeMap::new(),
            None::<&String>,
            None,
        )
        .unwrap()
    }

    #[test]
    fn mapping_unchanged_dependencies_keeps_the_summary_arc() {
        let summary = summary_with_dependencies();
        let shared = summary.clone();

        let mapped = summary.map_dependencies(|dep| dep);

        assert!(Arc::ptr_eq(&mapped.inner, &shared.inner));
    }

    #[test]
    fn mapping_one_dependency_preserves_the_other_dependency_arcs() {
        let summary = summary_with_dependencies();
        let original = summary.clone();
        let original_deps = original.dependencies().to_vec();
        let mut index = 0;

        let mapped = summary.map_dependencies(|mut dep| {
            if index == 1 {
                dep.set_optional(true);
            }
            index += 1;
            dep
        });

        assert!(!Arc::ptr_eq(&mapped.inner, &original.inner));
        let mapped_deps = mapped.dependencies();
        assert!(mapped_deps[0].ptr_eq(&original_deps[0]));
        assert!(!mapped_deps[1].ptr_eq(&original_deps[1]));
        assert!(mapped_deps[2].ptr_eq(&original_deps[2]));
        assert!(!original.dependencies()[1].is_optional());
        assert!(original.dependencies()[1].ptr_eq(&original_deps[1]));
    }

    #[test]
    fn mapping_an_owned_summary_keeps_its_inner_allocation() {
        let summary = summary_with_dependencies();
        let inner_ptr = Arc::as_ptr(&summary.inner);
        let mut index = 0;

        let mapped = summary.map_dependencies(|mut dep| {
            if index == 1 {
                dep.set_optional(true);
            }
            index += 1;
            dep
        });

        assert_eq!(Arc::as_ptr(&mapped.inner), inner_ptr);
        assert!(mapped.dependencies()[1].is_optional());
    }

    #[test]
    fn feature_map_iterates_sorted_and_answers_by_str_key() {
        let mut map = BTreeMap::new();
        for (name, fvs) in [
            ("zebra", vec!["one"]),
            ("alpha", vec![]),
            ("mid", vec!["two", "three"]),
        ] {
            map.insert(
                InternedString::new(name),
                fvs.into_iter()
                    .map(InternedString::new)
                    .map(FeatureValue::new)
                    .collect(),
            );
        }
        let fm = FeatureMap::from(map);

        // Iteration order is BTreeMap order (string order), regardless of
        // how `InternedString` ids happen to be assigned.
        let keys: Vec<String> = fm.keys().map(|k| k.to_string()).collect();
        assert_eq!(keys, ["alpha", "mid", "zebra"]);
        let pairs: Vec<(String, usize)> =
            fm.iter().map(|(k, v)| (k.to_string(), v.len())).collect();
        assert_eq!(
            pairs,
            [
                ("alpha".to_string(), 0),
                ("mid".to_string(), 2),
                ("zebra".to_string(), 1)
            ]
        );

        // `&str` and `&InternedString` keys both work via deref.
        assert!(fm.contains_key("mid"));
        let mid = InternedString::new("mid");
        assert_eq!(fm.get(&mid).unwrap().len(), 2);
        assert!(fm.get("missing").is_none());
        assert!(!fm.contains_key("missing"));
        assert_eq!(fm.len(), 3);
        assert!(!fm.is_empty());
        assert!(FeatureMap::default().is_empty());
        // `values()` and `&FeatureMap` IntoIterator match `iter()`.
        assert_eq!(fm.values().count(), 3);
        assert_eq!((&fm).into_iter().count(), fm.iter().count());
    }
}

//! crates.io sparse-registry-index parsing, shared by the Worker-side
//! [`crate::crates_io`] fetch client and host tests.
//!
//! The index serves every published version of a crate — features,
//! dependencies, and yanked flags — in one static file, the same file cargo
//! itself fetches. The file format is stable and specified; parsing it here
//! keeps the network client free of format logic.

use std::collections::BTreeMap;

use crate::dependency_resolver::{CratesIoDependency, PublishedRelease};
use crate::errors::ResolverError;

/// The sparse-index URL for `crate_name`: `1/` and `2/` for the short
/// names, `3/<second>` for three letters, `<first-two>/<chars3-4>` beyond —
/// the same sharding cargo applies.
pub fn index_url(crate_name: &str) -> String {
    let name = crate_name.to_ascii_lowercase();
    let path = match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{name}", &name[1..2]),
        _ => format!("{}/{}/{name}", &name[0..2], &name[2..4]),
    };
    format!("{INDEX_BASE}/{path}")
}

/// The index host; a constant so tests and the client agree on the origin.
const INDEX_BASE: &str = "https://index.crates.io";

/// One line of a sparse-index file — one published release. Fields beyond
/// this set (`cksum`, `rust_version`, `links`, `v`, `pubtime`) carry no
/// resolver meaning and are ignored.
#[derive(Debug, serde::Deserialize)]
struct IndexLine {
    vers: String,
    #[serde(default)]
    yanked: bool,
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
    /// Second feature namespace for entries using `dep?/feat` syntax that
    /// older cargo cannot parse; merged into `features`.
    #[serde(default)]
    features2: BTreeMap<String, Vec<String>>,
    deps: Vec<IndexDependency>,
}

/// One dependency entry inside an [`IndexLine`].
#[derive(Debug, serde::Deserialize)]
struct IndexDependency {
    /// The name as declared in the manifest — the rename alias when
    /// `package` is present.
    name: String,
    /// Semver requirement string.
    req: String,
    /// Registry package name when the dependency is renamed; the resolver
    /// works in registry names, so this overrides `name` when present.
    package: Option<String>,
    #[serde(default)]
    features: Vec<String>,
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    default_features: bool,
    target: Option<String>,
    #[serde(default)]
    kind: crate::dependency_resolver::CratesIoDependencyKind,
}

/// Parse one index file into the release list
/// [`crate::dependency_resolver::CratesIo::package_metadata`] returns.
/// Every line must decode — a truncated or corrupt file is an error, not a
/// partial answer.
///
/// # Errors
/// Returns [`ResolverError::Json`] when any line fails to decode or a
/// `vers` field is not semver.
pub fn parse_index_file(
    crate_name: &str,
    body: &str,
) -> Result<Vec<PublishedRelease>, ResolverError> {
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let mut line: IndexLine = serde_json::from_str(line).map_err(|error| {
                ResolverError::Json(format!(
                    "decode crates.io index line for {crate_name}: {error}"
                ))
            })?;
            for (feature, extra) in std::mem::take(&mut line.features2) {
                let items = line.features.entry(feature).or_default();
                items.extend(extra);
                items.sort();
                items.dedup();
            }
            Ok(PublishedRelease {
                version: semver::Version::parse(&line.vers).map_err(|error| {
                    ResolverError::Json(format!(
                        "parse index semver {crate_name} {}: {error}",
                        line.vers
                    ))
                })?,
                yanked: line.yanked,
                features: line.features,
                dependencies: line
                    .deps
                    .into_iter()
                    .map(|dep| CratesIoDependency {
                        crate_id: dep.package.unwrap_or(dep.name),
                        optional: dep.optional,
                        req: dep.req,
                        kind: dep.kind,
                        features: dep.features,
                        default_features: dep.default_features,
                        target: dep.target,
                    })
                    .collect(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::dependency_resolver::CratesIoDependencyKind;

    use super::{index_url, parse_index_file};

    #[test]
    fn index_urls_shard_like_cargo() {
        assert_eq!(index_url("a"), "https://index.crates.io/1/a");
        assert_eq!(index_url("cc"), "https://index.crates.io/2/cc");
        assert_eq!(index_url("req"), "https://index.crates.io/3/e/req");
        assert_eq!(index_url("itoa"), "https://index.crates.io/it/oa/itoa");
        assert_eq!(
            index_url("serde_derive"),
            "https://index.crates.io/se/rd/serde_derive"
        );
        // Names are lowercased for the shard computation.
        assert_eq!(index_url("RwLock"), "https://index.crates.io/rw/lo/rwlock");
    }

    #[test]
    fn parses_real_index_lines_with_deps_features_and_kinds() {
        // Shaped like a real serde line: renamed dep, optional dep, dev and
        // build kinds, target-gated dep, features2 merge, a yanked release.
        let body = concat!(
            r#"{"name":"demo","vers":"1.0.0","deps":[{"name":"serde_alias","req":"^1.0","package":"serde","features":["derive"],"optional":true,"default_features":false,"target":null,"kind":"normal"},{"name":"criterion","req":"^0.5","features":[],"optional":false,"default_features":true,"target":null,"kind":"dev"},{"name":"cc","req":"^1.0","features":[],"optional":false,"default_features":true,"target":"cfg(unix)","kind":"build"}],"cksum":"00","features":{"default":["serde_alias"],"std":[]},"features2":{"serde_alias?/alloc":[]},"yanked":false}"#,
            "\n",
            r#"{"name":"demo","vers":"1.0.1","deps":[],"cksum":"00","features":{},"yanked":true}"#,
            "\n"
        );
        let releases = parse_index_file("demo", body).expect("index file parses");
        assert_eq!(releases.len(), 2);

        let first = &releases[0];
        assert_eq!(first.version.to_string(), "1.0.0");
        assert!(!first.yanked);
        assert_eq!(first.features["default"], vec!["serde_alias"]);
        assert!(first.features.contains_key("serde_alias?/alloc"));
        assert_eq!(first.dependencies.len(), 3);

        let renamed = &first.dependencies[0];
        assert_eq!(renamed.crate_id, "serde");
        assert!(renamed.optional);
        assert!(!renamed.default_features);
        assert_eq!(renamed.features, vec!["derive"]);
        assert_eq!(renamed.kind, CratesIoDependencyKind::Normal);

        let dev = &first.dependencies[1];
        assert_eq!(dev.kind, CratesIoDependencyKind::Dev);

        let build = &first.dependencies[2];
        assert_eq!(build.kind, CratesIoDependencyKind::Build);
        assert_eq!(build.target.as_deref(), Some("cfg(unix)"));

        assert!(releases[1].yanked);
    }

    #[test]
    fn rejects_a_corrupt_line() {
        let error = parse_index_file("demo", "{\"name\":\"demo\",\"vers\":").unwrap_err();
        assert!(error.to_string().contains("demo"), "{error}");
    }
}

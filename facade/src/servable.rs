//! The build's serve map: what its caches can serve.
//!
//! Answered once per build by the supervising `stow` run and handed to
//! every facade it spawns — as a complete env answer when the verified
//! index was already local, or as a file the driver's background fetch
//! keeps rewriting while it lands (stow#347).

use std::path::PathBuf;

/// The build's precomputed serve map in its facades' environment.
///
/// Written by the supervising `stow build`/`check`/`test`:
/// `[[crate_name, version], ...]` naming the units its caches can serve,
/// plus `[crate_name, "*"]` for crates a semantic fallback may cover.
/// A facade holding it answers the serve question locally — an exact
/// miss or an unlisted crate needs no supervisor round trip at all
/// (stow#347).
pub const STOW_SERVABLE_UNITS_ENV: &str = "STOW_SERVABLE_UNITS_JSON";

/// The file a facade reads while the build's serve map is still completing.
///
/// The verified index had not all reached disk before cargo started, so
/// the driver ships a partial map here and the background fetch rewrites
/// it in place (stow#347). Same JSON the env carries.
pub const STOW_SERVE_MAP_FILE_ENV: &str = "STOW_SERVE_MAP_FILE";

/// This build's serve-map JSON, from env or file.
///
/// The complete env answer when the index was already local, else the
/// file the driver's background fetch keeps rewriting (stow#347). A
/// file that cannot be read means "nothing known to serve yet" — an
/// empty map, never the ordinary path: cargo already paid for the fast
/// path and a facade should not pay the old one back.
#[must_use]
pub fn serve_map() -> Option<String> {
    if let Some(raw) = std::env::var_os(STOW_SERVABLE_UNITS_ENV)
        .and_then(|raw| raw.into_string().ok())
    {
        return Some(raw);
    }
    let path = std::env::var_os(STOW_SERVE_MAP_FILE_ENV).map(PathBuf::from)?;
    Some(std::fs::read_to_string(path).unwrap_or_else(|_| "[]".to_owned()))
}

/// The parsed servable map: exact `(name, version)` pairs and names the
/// semantic fallback may serve under any compatible version.
#[derive(Debug)]
pub struct ServableUnits {
    exact: std::collections::HashSet<(String, String)>,
    wildcard: std::collections::HashSet<String>,
}

impl ServableUnits {
    /// Parse the serve-map JSON a build handed down.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let entries = serde_json::from_str::<Vec<(String, String)>>(raw).ok()?;
        let mut units = Self {
            exact: std::collections::HashSet::new(),
            wildcard: std::collections::HashSet::new(),
        };
        for (name, version) in entries {
            let name = stow_types::public_cache::canonical_crate_name(&name);
            if version == "*" {
                units.wildcard.insert(name);
            } else {
                units.exact.insert((name, version));
            }
        }
        Some(units)
    }

    /// Whether the map allows a serve for this unit — an exact
    /// `(name, version)` entry when the version is known (registry
    /// units), or a wildcard on the name covering the semantic
    /// fallback, prefetch candidates, and name-scoped local hits.
    #[must_use]
    pub fn covers(&self, crate_name: &str, version: Option<&str>) -> bool {
        let name = stow_types::public_cache::canonical_crate_name(crate_name);
        if self.wildcard.contains(&name) {
            return true;
        }
        version.is_some_and(|version| self.exact.contains(&(name, version.to_owned())))
    }
}

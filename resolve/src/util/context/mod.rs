//! Global context, replacing cargo's `util/context/mod.rs`.
//!
//! Configuration information for cargo. This is not specific to a build,
//! it is information relating to cargo itself. The vendored sources call
//! `gctx.get::<T>(key)` through the vendored [`de`] machinery, so the
//! merge rules (`get_cv_with_env`, `has_key`, `get_env_list`) are ported
//! verbatim over a caller-supplied `values` map plus an [`Env`] snapshot.

use crate::util::time::Instant;
use std::cell::{Cell, OnceCell};
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, anyhow, bail};
use cargo_util_schemas::manifest::RegistryName;
use url::Url;

use crate::core::SourceId;
use crate::core::global_cache_tracker::DeferredGlobalLastUse;
use crate::core::{CliUnstable, WorkspaceRootConfig};
use crate::sources::{CRATES_IO_INDEX, CRATES_IO_REGISTRY};
use crate::util::cache_lock;
use crate::util::cache_lock::{CacheLockMode, CacheLocker};
use crate::util::context::config_value::is_nonmergeable_list;
use crate::util::errors::CargoResult;
use crate::util::network::http_async;
use crate::util::once::OnceExt;
use crate::util::rustc::Rustc;
use crate::util::shell::Shell;
use crate::util::{Filesystem, IntoUrl, IntoUrlWithBase};

pub mod config_value;
pub mod de;
pub mod environment;
pub mod error;
pub mod key;
pub mod path;
pub mod schema;
pub mod target;
pub mod value;

pub use config_value::ConfigValue;
pub use config_value::ConfigValue as CV;
pub use environment::Env;
pub use error::{ConfigError, MissingFieldError};
pub use key::{ArrayItemKeyPath, ConfigKey};
pub use path::{BracketType, ConfigRelativePath, PathAndArgs, ResolveTemplateError};
pub use schema::*;
pub use target::{TargetCfgConfig, TargetConfig};
pub use value::{Definition, OptValue, Value};

pub use crate::util::context::schema::BuildTargetConfig;

pub const TOP_LEVEL_CONFIG_KEYS: &[&str] = &[
    "paths",
    "alias",
    "build",
    "credential-alias",
    "doc",
    "env",
    "future-incompat-report",
    "cache",
    "cargo-new",
    "http",
    "install",
    "net",
    "patch",
    "profile",
    "resolver",
    "registries",
    "registry",
    "source",
    "target",
    "term",
];

/// Configuration information for cargo. This is not specific to a build,
/// it is information relating to cargo itself.
pub struct GlobalContext {
    /// The location of the user's Cargo home directory. OS-dependent.
    home_path: Filesystem,
    /// Information about how to write messages to the shell
    shell: Mutex<Shell>,
    /// The current working directory of cargo.
    ///
    /// This is a `OnceCell` because it is lazily set only once during
    /// `GlobalContext::new` and `reload_cwd` is a way to invalidate it.
    cwd: PathBuf,
    /// Information about cached credentials found in config files.
    values: OnceCell<HashMap<String, ConfigValue>>,
    /// Environment variables, snapped for this invocation.
    env: Env,
    /// Instant this context was created.
    invocation_instant: Instant,
    /// Cache of the `SourceId` for crates.io
    crates_io_source_id: OnceCell<SourceId>,
    /// Whether we are printing extra verbose messages
    extra_verbose: bool,
    /// `-Z` flags for use by the unstable features.
    unstable_flags: CliUnstable,
    /// Whether we are reading the package cache lock (mode). This should
    /// be accessed with the [`GlobalContext::acquire_package_cache_lock`]
    /// family of functions.
    package_cache_lock: CacheLocker,
    /// Whether the nightly features are activated
    pub(crate) nightly_features_allowed: bool,
    /// The global cache tracker used to track the last time files were used.
    deferred_global_last_use: Mutex<DeferredGlobalLastUse>,
    /// Cached query to ask if offline mode is active
    offline: bool,
    /// Whether the resolver may update Cargo.lock (never in metadata mode).
    locked: Cell<bool>,
    /// A place to keep `WorkspaceRootConfigs` that have been found
    ws_roots: Mutex<HashMap<PathBuf, WorkspaceRootConfig>>,
    /// The rustc the resolve runs against (injected; never probed).
    rustc: OnceCell<Rustc>,
    /// The http client used to fetch index/crate data.
    http: Option<http_async::Client>,
    /// Used for tracking which sources have been updated.
    updated_sources: Mutex<std::collections::HashSet<SourceId>>,
    /// Where config-file discovery stops (defaults to `/` via ancestors).
    search_stop_path: Option<PathBuf>,
    /// Cached `[build]` config table.
    build_config: OnceCell<CargoBuildConfig>,
    /// Cached `[net]` config table.
    net_config: OnceCell<CargoNetConfig>,
    /// Cached `http.*` config values.
    http_config: OnceCell<CargoHttpConfig>,
    /// Cached `[target]`/`[host]` config values.
    target_cfgs: OnceCell<Vec<(String, TargetCfgConfig)>>,
    /// Cached `term.progress` config.
    progress_config: OnceCell<ProgressConfig>,
}

impl std::fmt::Debug for GlobalContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalContext").finish_non_exhaustive()
    }
}

impl GlobalContext {
    /// Creates a context for a resolve invocation.
    ///
    /// * `cwd` — directory the resolve acts as if run in (usually the
    /// Creates a new instance, with all default settings.
    ///
    /// This does only minimal initialization. In particular, it does not load
    /// any config files from disk. Those will be loaded lazily as-needed.
    pub fn default() -> CargoResult<GlobalContext> {
        let shell = Shell::new();
        let cwd = crate::util::env::current_dir()
            .context("couldn't get the current directory of the process")?;
        let homedir = homedir(&cwd).ok_or_else(|| {
            anyhow::anyhow!(
                "Cargo couldn't find your home directory. \
                 This probably means that $HOME was not set."
            )
        })?;
        Self::new_for_resolve(cwd, homedir, shell, Env::new(), false)
    }

    ///   workspace root).
    /// * `homedir` — the cargo home (holds `registry/{index,cache,src}`).
    ///   Must match cargo's cargo home for `manifest_path` parity.
    /// * `shell` — output sink.
    /// * `env` — environment snapshot the config system reads.
    /// * `offline` — cargo's `--offline` flag.
    pub fn new_for_resolve(
        cwd: PathBuf,
        homedir: PathBuf,
        shell: Shell,
        env: Env,
        offline: bool,
    ) -> CargoResult<GlobalContext> {
        let home_path = Filesystem::new(homedir);
        Ok(GlobalContext {
            home_path,
            shell: Mutex::new(shell),
            cwd,
            values: OnceCell::new(),
            env,
            invocation_instant: Instant::now(),
            crates_io_source_id: OnceCell::new(),
            extra_verbose: false,
            unstable_flags: CliUnstable::default(),
            package_cache_lock: CacheLocker::new(),
            nightly_features_allowed: false,
            deferred_global_last_use: Mutex::new(DeferredGlobalLastUse::new()),
            offline,
            locked: Cell::new(false),
            ws_roots: Mutex::new(HashMap::new()),
            rustc: OnceCell::new(),
            http: None,
            updated_sources: Mutex::new(std::collections::HashSet::new()),
            search_stop_path: None,
            build_config: OnceCell::new(),
            net_config: OnceCell::new(),
            http_config: OnceCell::new(),
            target_cfgs: OnceCell::new(),
            progress_config: OnceCell::new(),
        })
    }

    /// Install the http client used by registry sources/downloads.
    pub fn set_http(&mut self, http: http_async::Client) {
        self.http = Some(http);
    }

    /// Install pre-parsed config `values` (contents of `.cargo/config.toml`
    /// as produced by [`crate::util::context::config_value`]).
    pub fn set_values(&self, values: HashMap<String, ConfigValue>) -> CargoResult<()> {
        self.values
            .set(values)
            .map_err(|_| anyhow!("config values were already set"))
    }

    /// Install the injected [`Rustc`] (version/host parsed from a captured
    /// `rustc -vV` output — no probe is run on this build).
    pub fn set_rustc(&self, rustc: Rustc) -> CargoResult<()> {
        self.rustc
            .set(rustc)
            .map_err(|_| anyhow!("rustc was already set"))
    }

    /// Sets the path where discovery of config files should stop.
    pub fn set_search_stop_path<P: Into<PathBuf>>(&mut self, path: P) {
        self.search_stop_path = Some(path.into());
    }

    /// Gets the directory of the cargo home (`~/.cargo` equivalent).
    pub fn home(&self) -> &Filesystem {
        &self.home_path
    }

    /// Returns the path for git database checkouts — part of cargo home.
    pub fn git_path(&self) -> Filesystem {
        self.home_path.join("git")
    }

    /// Returns the path for git checkouts — part of cargo home.
    pub fn git_checkouts_path(&self) -> Filesystem {
        self.home_path.join("git").join("checkouts")
    }

    /// Returns the path for git bare dbs — part of cargo home.
    pub fn git_db_path(&self) -> Filesystem {
        self.home_path.join("git").join("db")
    }

    /// Returns the path for registry state — part of cargo home.
    pub fn registry_base_path(&self) -> Filesystem {
        self.home_path.join("registry")
    }

    /// Returns the path for registry index — part of cargo home.
    pub fn registry_index_path(&self) -> Filesystem {
        self.registry_base_path().join("index")
    }

    /// Returns the path for registry .crate caches — part of cargo home.
    pub fn registry_cache_path(&self) -> Filesystem {
        self.registry_base_path().join("cache")
    }

    /// Returns the path for registry extracted sources — part of cargo home.
    pub fn registry_source_path(&self) -> Filesystem {
        self.registry_base_path().join("src")
    }

    /// The default registry name configured (`registry.default`), or None.
    pub fn default_registry(&self) -> CargoResult<Option<String>> {
        self.get::<Option<String>>("registry.default")
    }

    /// Gets a reference to the shell, e.g., for writing error messages.
    pub fn shell(&self) -> MutexGuard<'_, Shell> {
        self.shell.lock().unwrap()
    }

    #[cfg(debug_assertions)]
    pub fn debug_assert_shell_not_borrowed(&self) {
        debug_assert!(self.shell.try_lock().is_ok());
    }

    #[cfg(not(debug_assertions))]
    pub fn debug_assert_shell_not_borrowed(&self) {}

    /// The rustc the resolve runs against (injected via [`Self::set_rustc`]).
    /// Rebuilds an owned [`Rustc`] from the values injected via
    /// [`GlobalContext::set_rustc`]. Upstream cargo re-probes the rustc
    /// executable here; we derive it from the recorded `-vV` output instead,
    /// which carries identical information.
    pub fn load_global_rustc(
        &self,
        _ws: Option<&crate::core::Workspace<'_>>,
    ) -> CargoResult<Rustc> {
        let rustc = self.rustc.get().ok_or_else(|| {
            anyhow!("no rustc injected into this GlobalContext; call `set_rustc` first")
        })?;
        Rustc::new_from_verbose_version(rustc.path.clone(), rustc.verbose_version.clone())
    }

    /// Returns a path to `cargo` executable
    pub fn cargo_exe(&self) -> CargoResult<&Path> {
        // The path of the current executable does not exist in the VFS; the
        // only consumer (rustc probe env) never runs in this build.
        static CARGO_EXE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        Ok(CARGO_EXE.get_or_init(|| PathBuf::from("cargo")).as_path())
    }

    /// Path to the rustdoc executable — never spawned in this build.
    pub fn rustdoc(&self) -> CargoResult<&Path> {
        static RUSTDOC: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        Ok(RUSTDOC.get_or_init(|| PathBuf::from("rustdoc")).as_path())
    }

    /// Returns the path for downloads — part of cargo home.
    pub fn git_db_path_unused(&self) -> &Filesystem {
        &self.home_path
    }

    /// Tracks which sources have been updated in this invocation.
    pub fn updated_sources(&self) -> MutexGuard<'_, HashSet<SourceId>> {
        self.updated_sources.lock().unwrap()
    }

    /// Returns all values registries may have loaded.
    pub fn values(&self) -> CargoResult<&HashMap<String, ConfigValue>> {
        Ok(self.values.get_or_init(HashMap::new))
    }

    /// Returns the cwd cargo was invoked from
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    /// Returns the `target` directory for builds (unused for resolution,
    /// carried for vendored callers).
    pub fn target_dir(&self) -> CargoResult<Option<Filesystem>> {
        if let Some(dir) = self.get_env_os("CARGO_TARGET_DIR") {
            if dir.is_empty() {
                bail!(
                    "the target directory is set to an empty string in the \
                     `CARGO_TARGET_DIR` environment variable"
                )
            }
            Ok(Some(Filesystem::new(self.cwd.join(dir))))
        } else if let Some(val) = &self.build_config()?.target_dir {
            let path = val.resolve_path(self);
            if val.raw_value().is_empty() {
                bail!(
                    "the target directory is set to an empty string in {}",
                    val.value().definition
                )
            }
            Ok(Some(Filesystem::new(path)))
        } else {
            Ok(None)
        }
    }

    /// The directory to use for intermediate build artifacts (unused for
    /// resolution; carried for vendored callers).
    pub fn build_dir(&self, workspace_manifest_path: &Path) -> CargoResult<Option<Filesystem>> {
        let Some(val) = &self.build_config()?.build_dir else {
            return Ok(None);
        };
        self.custom_build_dir(val, workspace_manifest_path)
            .map(Some)
    }

    /// The directory to use for intermediate build artifacts.
    ///
    /// Callers should prefer `Workspace::build_dir` instead.
    pub fn custom_build_dir(
        &self,
        val: &ConfigRelativePath,
        workspace_manifest_path: &Path,
    ) -> CargoResult<Filesystem> {
        let replacements = [
            (
                "{workspace-root}",
                workspace_manifest_path
                    .parent()
                    .unwrap()
                    .to_str()
                    .context("workspace root was not valid utf-8")?
                    .to_string(),
            ),
            (
                "{cargo-cache-home}",
                self.home()
                    .as_path_unlocked()
                    .to_str()
                    .context("cargo home was not valid utf-8")?
                    .to_string(),
            ),
            ("{workspace-path-hash}", {
                let real_path = crate::util::fs::canonicalize(workspace_manifest_path)
                    .unwrap_or_else(|_err| workspace_manifest_path.to_owned());
                let hash = crate::util::hex::short_hash(&real_path);
                format!("{}{}{}", &hash[0..2], std::path::MAIN_SEPARATOR, &hash[2..])
            }),
        ];

        let template_variables = replacements
            .iter()
            .map(|(key, _)| key[1..key.len() - 1].to_string())
            .collect::<Vec<_>>();

        let mut out_dir = val.resolve_path(self);
        for (key, value) in replacements {
            let key_no_brackets = &key[1..key.len() - 1];
            if !template_variables.iter().any(|v| v == key_no_brackets) {
                continue;
            }
            let path = out_dir.to_string_lossy().replace(key, &value);
            out_dir = PathBuf::from(path);
        }
        Ok(Filesystem::new(out_dir))
    }

    // ------------------------------------------------------------------
    // Config accessors (ported verbatim semantics over `values` + `env`)
    // ------------------------------------------------------------------

    /// This is a low-level private method for getting a CV from a file only.
    fn get_cv(&self, key: &ConfigKey) -> CargoResult<Option<ConfigValue>> {
        self.get_cv_helper(key, self.values()?)
    }

    fn get_cv_helper(
        &self,
        key: &ConfigKey,
        vals: &HashMap<String, ConfigValue>,
    ) -> CargoResult<Option<ConfigValue>> {
        tracing::trace!("get cv {:?}", key);
        if key.is_root() {
            return Ok(Some(CV::Table(
                vals.clone(),
                Definition::Path(PathBuf::new()),
            )));
        }
        let mut parts = key.parts().enumerate();
        let Some(mut val) = vals.get(parts.next().unwrap().1) else {
            return Ok(None);
        };
        for (i, part) in parts {
            match val {
                CV::Table(map, _) => {
                    val = match map.get(part) {
                        Some(val) => val,
                        None => return Ok(None),
                    }
                }
                CV::Integer(_, def)
                | CV::String(_, def)
                | CV::List(_, def)
                | CV::Boolean(_, def) => {
                    let mut key_so_far = ConfigKey::new();
                    for part in key.parts().take(i) {
                        key_so_far.push(part);
                    }
                    bail!(
                        "expected table for configuration key `{}`, \
                         but found {} in {}",
                        key_so_far,
                        val.desc(),
                        def
                    )
                }
            }
        }
        Ok(Some(val.clone()))
    }

    /// This is a helper for getting a CV from a file or env var.
    pub(crate) fn get_cv_with_env(&self, key: &ConfigKey) -> CargoResult<Option<CV>> {
        let cv = self.get_cv(key)?;
        if key.is_root() {
            return Ok(cv);
        }
        let env = self.env.get_str(key.as_env_key());
        let env_def = Definition::Environment(key.as_env_key().to_string());
        let use_env = match (&cv, env) {
            // Lists are always merged.
            (Some(CV::List(..)), Some(_)) => true,
            (Some(cv), Some(_)) => env_def.is_higher_priority(cv.definition()),
            (None, Some(_)) => true,
            _ => false,
        };

        if !use_env {
            return Ok(cv);
        }

        let env = env.unwrap();
        if env == "true" {
            Ok(Some(CV::Boolean(true, env_def)))
        } else if env == "false" {
            Ok(Some(CV::Boolean(false, env_def)))
        } else if let Ok(i) = env.parse::<i64>() {
            Ok(Some(CV::Integer(i, env_def)))
        } else if self.cli_unstable().advanced_env && env.starts_with('[') && env.ends_with(']') {
            match cv {
                Some(CV::List(mut cv_list, cv_def)) => {
                    self.get_env_list(key, &mut cv_list)?;
                    Ok(Some(CV::List(cv_list, cv_def)))
                }
                Some(cv) => {
                    bail!(
                        "unable to merge array env for config `{}`\n\
                        file: {:?}\n\
                        env: {}",
                        key,
                        cv,
                        env
                    );
                }
                None => {
                    let mut cv_list = Vec::new();
                    self.get_env_list(key, &mut cv_list)?;
                    Ok(Some(CV::List(cv_list, env_def)))
                }
            }
        } else {
            match cv {
                Some(CV::List(mut cv_list, cv_def)) => {
                    self.get_env_list(key, &mut cv_list)?;
                    Ok(Some(CV::List(cv_list, cv_def)))
                }
                _ => Ok(Some(CV::String(env.to_string(), env_def))),
            }
        }
    }

    /// Helper primarily for testing — replace env.
    pub fn set_env(&mut self, env: HashMap<String, String>) {
        self.env = Env::from_map(env);
    }

    /// Returns all environment variables as an iterator.
    pub(crate) fn env(&self) -> impl Iterator<Item = (&str, &str)> {
        self.env.iter_str()
    }

    /// Returns all environment variable keys.
    pub(crate) fn env_keys(&self) -> impl Iterator<Item = &str> {
        self.env.keys_str()
    }

    /// Get the value of environment variable `key` through the snapshot in
    /// [`GlobalContext`].
    pub fn get_env(&self, key: impl AsRef<OsStr>) -> CargoResult<&str> {
        self.env.get_env(key)
    }

    /// Get the value of environment variable `key` through the snapshot in
    /// [`GlobalContext`].
    pub fn get_env_os(&self, key: impl AsRef<OsStr>) -> Option<&OsStr> {
        self.env.get_env_os(key)
    }

    /// Check if the [`GlobalContext`] contains a given [`ConfigKey`].
    pub(crate) fn has_key(&self, key: &ConfigKey, env_prefix_ok: bool) -> CargoResult<bool> {
        if self.env.contains_key(key.as_env_key()) {
            return Ok(true);
        }
        if env_prefix_ok {
            let env_prefix = format!("{}_", key.as_env_key());
            if self.env_keys().any(|k| k.starts_with(&env_prefix)) {
                return Ok(true);
            }
        }
        if self.get_cv(key)?.is_some() {
            return Ok(true);
        }
        self.check_environment_key_case_mismatch(key);
        Ok(false)
    }

    fn check_environment_key_case_mismatch(&self, key: &ConfigKey) {
        if let Some(env_key) = self.env.get_normalized(key.as_env_key()) {
            let _ = self.shell().warn(format!(
                "environment variables are expected to use uppercase letters and underscores, \
                the variable `{env_key}` will be ignored and have no effect"
            ));
        }
    }

    /// Get a string config value.
    pub fn get_string(&self, key: &str) -> CargoResult<OptValue<String>> {
        self.get::<OptValue<String>>(key)
    }

    /// Internal method for getting an environment variable as a list.
    pub(crate) fn get_env_list(
        &self,
        key: &ConfigKey,
        output: &mut Vec<ConfigValue>,
    ) -> CargoResult<()> {
        let Some(env_val) = self.env.get_str(key.as_env_key()) else {
            self.check_environment_key_case_mismatch(key);
            return Ok(());
        };

        let env_def = Definition::Environment(key.as_env_key().to_string());

        if is_nonmergeable_list(key) {
            assert!(
                output
                    .windows(2)
                    .all(|cvs| cvs[0].definition() == cvs[1].definition()),
                "non-mergeable list must have only one definition: {output:?}",
            );
            if output
                .first()
                .map(|o| o.definition() > &env_def)
                .unwrap_or_default()
            {
                return Ok(());
            } else {
                output.clear();
            }
        }

        if self.cli_unstable().advanced_env && env_val.starts_with('[') && env_val.ends_with(']') {
            let toml_v = env_val.parse::<toml::Value>().map_err(|e| {
                ConfigError::new(format!("could not parse TOML list: {}", e), env_def.clone())
            })?;
            let values = toml_v.as_array().expect("env var was not array");
            for value in values {
                let s = value.as_str().ok_or_else(|| {
                    ConfigError::new(
                        format!("expected string, found {}", value.type_str()),
                        env_def.clone(),
                    )
                })?;
                output.push(CV::String(s.to_string(), env_def.clone()))
            }
        } else {
            output.extend(
                env_val
                    .split_whitespace()
                    .map(|s| CV::String(s.to_string(), env_def.clone())),
            );
        }
        output.sort_by(|a, b| a.definition().cmp(b.definition()));
        Ok(())
    }

    /// Low-level method for getting a config value as an `OptValue<HashMap<String, CV>>`.
    pub(crate) fn get_table(&self, key: &ConfigKey) -> CargoResult<OptValue<HashMap<String, CV>>> {
        match self.get_cv(key)? {
            Some(CV::Table(val, definition)) => Ok(Some(Value { val, definition })),
            Some(val) => self.expected("table", key, &val),
            None => Ok(None),
        }
    }

    /// Generate an error when the given value is the wrong type.
    pub(crate) fn expected<T>(&self, ty: &str, key: &ConfigKey, val: &CV) -> CargoResult<T> {
        val.expected(ty, &key.to_string())
            .map_err(|e| anyhow!("invalid configuration for key `{key}`\n{e}"))
    }

    // ------------------------------------------------------------------
    // Command-line / mode accessors
    // ------------------------------------------------------------------

    /// The unstable flags requested on the command line.
    pub fn cli_unstable(&self) -> &CliUnstable {
        &self.unstable_flags
    }

    /// Whether `-Z` flags/nightly features may be enabled.
    pub fn nightly_features_allowed(&self) -> bool {
        self.nightly_features_allowed
    }

    /// If we are printing extra verbose messages
    pub fn extra_verbose(&self) -> bool {
        self.extra_verbose
    }

    /// Whether we are allowed network access
    pub fn network_allowed(&self) -> bool {
        !self.offline
    }

    /// Returns a displayable message for --offline flag
    pub fn offline_flag(&self) -> Option<&'static str> {
        self.offline.then_some("--offline")
    }

    /// Whether Cargo.lock updates are allowed (never in metadata mode).
    pub fn lock_update_allowed(&self) -> bool {
        !self.locked.get()
    }

    /// Returns a displayable message for --locked/--frozen flags
    pub fn locked_flag(&self) -> Option<&'static str> {
        self.locked.get().then_some("--locked")
    }

    /// Returns the http client the registry sources use for fetching.
    pub fn http_async(&self) -> CargoResult<&http_async::Client> {
        self.http
            .as_ref()
            .ok_or_else(|| anyhow!("no http client installed on this context"))
    }

    /// The `http.*` config values (proxy/timeout/cainfo checks).
    pub fn http_config(&self) -> CargoResult<&CargoHttpConfig> {
        self.http_config
            .try_borrow_with(|| self.get::<CargoHttpConfig>("http"))
    }

    /// The `net.*` config values.
    pub fn net_config(&self) -> CargoResult<&CargoNetConfig> {
        self.net_config
            .try_borrow_with(|| self.get::<CargoNetConfig>("net"))
    }

    /// The `build.*` config values.
    pub fn build_config(&self) -> CargoResult<&CargoBuildConfig> {
        self.build_config
            .try_borrow_with(|| self.get::<CargoBuildConfig>("build"))
    }

    /// Returns the `env.*` config table.
    pub fn env_config(&self) -> CargoResult<&Arc<HashMap<String, OsString>>> {
        static ENV_CONFIG: std::sync::OnceLock<Arc<HashMap<String, OsString>>> =
            std::sync::OnceLock::new();
        Ok(ENV_CONFIG.get_or_init(|| Arc::new(HashMap::new())))
    }

    /// Returns `term.progress` configuration.
    pub fn progress_config(&self) -> &ProgressConfig {
        self.progress_config.get_or_init(|| {
            self.get::<ProgressConfig>("term.progress")
                .unwrap_or_default()
        })
    }

    /// Returns `target.*`/`target.cfg(...)` config tables.
    pub fn target_cfgs(&self) -> CargoResult<&Vec<(String, TargetCfgConfig)>> {
        self.target_cfgs
            .try_borrow_with(|| target::load_target_cfgs(self))
    }

    /// The `doc.extern-map.*` values for rustdoc — unused in resolution.
    pub fn doc_extern_map(&self) -> CargoResult<&crate::core::compiler::rustdoc::RustdocExternMap> {
        static MAP: std::sync::OnceLock<crate::core::compiler::rustdoc::RustdocExternMap> =
            std::sync::OnceLock::new();
        Ok(MAP.get_or_init(crate::core::compiler::rustdoc::RustdocExternMap::default))
    }

    /// Whether target applies to host platform.
    pub fn target_applies_to_host(&self) -> CargoResult<bool> {
        Ok(self.build_config()?.target.is_none())
    }

    /// Returns the `host.*` target config for the given `cfg` triple.
    pub fn host_cfg_triple(&self, target: &str) -> CargoResult<TargetConfig> {
        target::load_host_triple(self, target)
    }

    /// Returns the `target.*` config for the given triple.
    pub fn target_cfg_triple(&self, target: &str) -> CargoResult<TargetConfig> {
        target::load_target_triple(self, target)
    }

    /// Returns the `[source]` path overrides.
    pub fn paths_overrides(&self) -> CargoResult<OptValue<Vec<(String, Definition)>>> {
        let key = ConfigKey::from_str("paths");
        // paths overrides cannot be set via env config, so use get_cv here.
        match self.get_cv(&key)? {
            Some(CV::List(val, definition)) => {
                let val = val
                    .into_iter()
                    .map(|cv| match cv {
                        CV::String(s, def) => Ok((s, def)),
                        other => self.expected("string", &key, &other),
                    })
                    .collect::<CargoResult<Vec<_>>>()?;
                Ok(Some(Value { val, definition }))
            }
            Some(val) => self.expected("list", &key, &val),
            None => Ok(None),
        }
    }

    /// Returns the URL to use for the registry index for the given registry
    /// name, if overridden by `registries.NAME.index`.
    pub fn get_registry_index(&self, registry: &str) -> CargoResult<Url> {
        RegistryName::new(registry)?;
        if let Some(index) = self.get_string(&format!("registries.{registry}.index"))? {
            self.resolve_registry_index(&index).with_context(|| {
                format!(
                    "invalid index URL for registry `{}` defined in {}",
                    registry, index.definition
                )
            })
        } else {
            bail!("registry index was not found in any configuration: `{registry}`");
        }
    }

    /// Returns an error if `registry.index` is set.
    pub fn check_registry_index_not_set(&self) -> CargoResult<()> {
        if self.get_string("registry.index")?.is_some() {
            bail!(
                "the `registry.index` config value is no longer supported\n\
                Use `[source]` replacement to alter the default index for crates.io."
            );
        }
        Ok(())
    }

    fn resolve_registry_index(&self, index: &Value<String>) -> CargoResult<Url> {
        let base = index
            .definition
            .root(self.cwd())
            .join("truncated-by-url_with_base");
        let _parsed = index.val.into_url()?;
        let url = index.val.into_url_with_base(Some(&*base))?;
        if url.password().is_some() {
            bail!("registry URLs may not contain passwords");
        }
        Ok(url)
    }

    /// Returns the `SourceId` for crates.io (respecting `[source]`-replacement
    /// is handled at the SourceConfigMap layer).
    pub fn crates_io_source_id(&self) -> CargoResult<SourceId> {
        let source_id = self.crates_io_source_id.try_borrow_with(|| {
            self.check_registry_index_not_set()?;
            let url = CRATES_IO_INDEX.into_url().unwrap();
            SourceId::for_alt_registry(&url, CRATES_IO_REGISTRY)
        })?;
        Ok(*source_id)
    }

    /// Returns the time this invocation started
    pub fn invocation_instant(&self) -> Instant {
        self.invocation_instant
    }

    /// Returns the wall-clock time of this cargo invocation.
    pub fn invocation_time(&self) -> jiff::Timestamp {
        jiff::Timestamp::now()
    }

    /// Gets a path config value used as a directory path.
    fn string_to_path(&self, value: &str, definition: &Definition) -> PathBuf {
        let is_path = value.contains('/') || (cfg!(windows) && value.contains('\\'));
        if is_path {
            definition.root(self.cwd()).join(value)
        } else {
            // A pathless name.
            PathBuf::from(value)
        }
    }

    /// Return the path to the first existing cargo config file used for
    /// diagnostic messages (the `config`/`config.toml` beside `cargo_home`).
    pub fn diagnostic_home_config(&self) -> String {
        let home = self.home_path.as_path_unlocked();
        let path = match self.get_file_path(home, "config", false) {
            Ok(Some(existing_path)) => existing_path,
            _ => home.join("config.toml"),
        };
        path.to_string_lossy().to_string()
    }

    /// Check for `key`.'+'toml' file, falling back to `key` (without
    /// extension) if `also'` is set.
    fn get_file_path(
        &self,
        dir: &std::path::Path,
        key: &str,
        also_extensionless: bool,
    ) -> CargoResult<Option<PathBuf>> {
        let possible = dir.join(format!("{key}.toml"));
        if crate::util::fs::exists(&possible) {
            Ok(Some(possible))
        } else if also_extensionless {
            let possible = dir.join(key);
            if crate::util::fs::exists(&possible) {
                Ok(Some(possible))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    fn get_config_env<T>(&self, key: &ConfigKey) -> Result<OptValue<T>, ConfigError>
    where
        T: FromStr,
        <T as FromStr>::Err: std::fmt::Display,
    {
        match self.env.get_str(key.as_env_key()) {
            Some(value) => {
                let definition = Definition::Environment(key.as_env_key().to_string());
                Ok(Some(Value {
                    val: value
                        .parse()
                        .map_err(|e| ConfigError::new(format!("{}", e), definition.clone()))?,
                    definition,
                }))
            }
            None => {
                self.check_environment_key_case_mismatch(key);
                Ok(None)
            }
        }
    }

    fn get_integer(&self, key: &ConfigKey) -> Result<OptValue<i64>, ConfigError> {
        let cv = self.get_cv(key)?;
        let env = self.get_config_env::<i64>(key)?;
        match (cv, env) {
            (Some(CV::Integer(val, definition)), Some(env)) => {
                if definition.is_higher_priority(&env.definition) {
                    Ok(Some(Value { val, definition }))
                } else {
                    Ok(Some(env))
                }
            }
            (Some(CV::Integer(val, definition)), None) => Ok(Some(Value { val, definition })),
            (Some(cv), _) => Err(ConfigError::expected(key, "an integer", &cv)),
            (None, env) => Ok(env),
        }
    }

    fn get_bool(&self, key: &ConfigKey) -> Result<OptValue<bool>, ConfigError> {
        let cv = self.get_cv(key)?;
        let env = self.get_config_env::<bool>(key)?;
        match (cv, env) {
            (Some(CV::Boolean(val, definition)), Some(env)) => {
                if definition.is_higher_priority(&env.definition) {
                    Ok(Some(Value { val, definition }))
                } else {
                    Ok(Some(env))
                }
            }
            (Some(CV::Boolean(val, definition)), None) => Ok(Some(Value { val, definition })),
            (Some(cv), _) => Err(ConfigError::expected(key, "true/false", &cv)),
            (None, env) => Ok(env),
        }
    }

    fn get_string_priv(&self, key: &ConfigKey) -> Result<OptValue<String>, ConfigError> {
        let cv = self.get_cv(key)?;
        let env = self.get_config_env::<String>(key)?;
        match (cv, env) {
            (Some(CV::String(val, definition)), Some(env)) => {
                if definition.is_higher_priority(&env.definition) {
                    Ok(Some(Value { val, definition }))
                } else {
                    Ok(Some(env))
                }
            }
            (Some(CV::String(val, definition)), None) => Ok(Some(Value { val, definition })),
            (Some(cv), _) => Err(ConfigError::expected(key, "a string", &cv)),
            (None, env) => Ok(env),
        }
    }

    /// Get a configuration value by key.

    ///
    /// This does NOT look at environment variables, they are merged via
    /// [`GlobalContext::get_cv_with_env`] inside the deserializer.
    pub fn get<'de, T: serde::de::Deserialize<'de>>(&self, key: &str) -> CargoResult<T> {
        let d = de::Deserializer {
            gctx: self,
            key: ConfigKey::from_str(key),
            env_prefix_ok: true,
        };
        T::deserialize(d).map_err(|e| e.into())
    }

    // ------------------------------------------------------------------
    // Package cache locking (advisory; VFS-backed)
    // ------------------------------------------------------------------

    /// Asserts the package cache is locked in `mode`, returning the path.
    ///
    /// See [`crate::util::cache_lock`] for more details.
    pub fn assert_package_cache_locked<'a>(
        &self,
        mode: CacheLockMode,
        path: &'a Filesystem,
    ) -> &'a Path {
        assert!(
            self.package_cache_lock.is_locked(mode),
            "package cache lock is not currently held in mode {mode:?}",
        );
        path.as_path_unlocked()
    }

    /// Acquires the package cache lock — succeeds immediately in this build
    /// (one resolve owns its own VFS).
    pub fn acquire_package_cache_lock(
        &self,
        mode: CacheLockMode,
    ) -> CargoResult<cache_lock::CacheLock<'_>> {
        self.package_cache_lock.lock(self, mode)
    }

    /// Attempts to acquire the package cache lock without blocking.
    pub fn try_acquire_package_cache_lock(
        &self,
        mode: CacheLockMode,
    ) -> CargoResult<Option<cache_lock::CacheLock<'_>>> {
        self.package_cache_lock.try_lock(self, mode)
    }

    /// Returns the deferred last-use tracker.
    pub fn deferred_global_last_use(&self) -> CargoResult<MutexGuard<'_, DeferredGlobalLastUse>> {
        Ok(self.deferred_global_last_use.lock().unwrap())
    }

    /// Get the global warning-handling configuration.
    pub fn warning_handling(&self) -> CargoResult<WarningHandling> {
        Ok(self.build_config()?.warnings.unwrap_or_default())
    }

    /// Whether source overrides via `[patch]`/`[source]` should affect the
    /// resolver — mirrors cargo's `[patch]` handling, kept for compat.
    pub fn warn_odd_forced_incompatible_source(&self) -> bool {
        true
    }

    /// Returns a cache of `WorkspaceRootConfig`s discovered during manifest
    /// parsing (populated by `util::toml::read_manifest`).
    pub fn ws_roots(&self) -> MutexGuard<'_, HashMap<PathBuf, WorkspaceRootConfig>> {
        self.ws_roots.lock().unwrap()
    }
}

/// Returns the home directory for cargo to use (see [`GlobalContext::home`]).
///
/// `CARGO_HOME` env var if set, otherwise the provided default.
pub fn homedir(cwd: &Path) -> Option<PathBuf> {
    if let Ok(home) = crate::util::env::var("CARGO_HOME") {
        return Some(cwd.join(home));
    }
    None
}

#[macro_export]
macro_rules! __shell_print {
    ($config:expr, $which:ident, $newline:literal, $($arg:tt)*) => ({
        let mut shell = $config.shell();
        let out = shell.$which();
        drop(out.write_fmt(format_args!($($arg)*)));
        if $newline {
            drop(out.write_all(b"\n"));
        }
    });
}

#[macro_export]
macro_rules! drop_println {
    ($config:expr) => ( $crate::drop_print!($config, "\n") );
    ($config:expr, $($arg:tt)*) => (
        $crate::__shell_print!($config, out, true, $($arg)*)
    );
}

#[macro_export]
macro_rules! drop_eprintln {
    ($config:expr) => ( $crate::drop_eprint!($config, "\n") );
    ($config:expr, $($arg:tt)*) => (
        $crate::__shell_print!($config, err, true, $($arg)*)
    );
}

#[macro_export]
macro_rules! drop_print {
    ($config:expr, $($arg:tt)*) => (
        $crate::__shell_print!($config, out, false, $($arg)*)
    );
}

#[macro_export]
macro_rules! drop_eprint {
    ($config:expr, $($arg:tt)*) => (
        $crate::__shell_print!($config, err, false, $($arg)*)
    );
}

/// A list of strings.
///
/// This supports the `shell` or `list` syntax, where the `shell` syntax is
/// split on whitespace:
///
/// ```toml
/// a = 'a b c'
/// b = ['a', 'b', 'c']
/// ```
/// Both of these are equivalent to `['a', 'b', 'c']`.
#[derive(Debug, serde::Deserialize, Clone)]
pub struct StringList(Vec<String>);

impl StringList {
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

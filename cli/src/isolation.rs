//! Build isolation levels (stow#1000).
//!
//! Every dependency, path dependencies included, is untrusted code: its build
//! script and proc macros run on the developer's machine, and the most common
//! supply-chain attack steals the credentials they find there. The sandbox
//! wraps the whole cargo process tree, rustc's proc-macro expansion included,
//! at one of four levels:
//!
//! | level | files | environment | network |
//! |---|---|---|---|
//! | `protect` (default except on Windows) | denylist: credential stores unreadable, persistence locations unwritable, everything else as usual | credential variables stripped | allowed through heel's proxy, destinations recorded |
//! | `strict` (default on Windows) | allowlist: workspace, target dir, toolchain, cargo registry and stow's shims; home never granted | allowlist | allowed through the proxy, recorded |
//! | `offline` | as `strict` | as `strict` | denied; the supervisor's IPC socket is the only channel |
//! | `off` | no isolation | untouched | unrestricted |
//!
//! The level is one option in the global config, `[isolation] level`, overridden
//! for one run by `--isolation <level>`. It is independent of the cache mode: a
//! build with the cache off still runs at the configured level. A level the
//! platform cannot enforce fails the build; nothing is ever downgraded.
//!
//! `strict` and `offline` take per-crate grants, `[[isolation.grant]]`, that name
//! a crate and only widen what the level gives the build while that crate is in
//! its dependency graph.

use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// How much of the machine a build's cargo process tree can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Credential stores unreadable, persistence locations unwritable, the
    /// network open through heel's proxy and recorded. The default everywhere
    /// but Windows.
    Protect,
    /// An allowlist of files and environment; the network open through the
    /// proxy and recorded. The default on Windows.
    Strict,
    /// `strict`, with the network denied.
    Offline,
    /// No isolation.
    Off,
}

impl Default for Level {
    /// `protect`, except on Windows: heel cannot enforce `protect` there, and
    /// `strict` reads and writes only the granted paths, so credentials stay
    /// unreachable. An explicit `protect` on Windows fails; it is never
    /// replaced.
    fn default() -> Self {
        if cfg!(windows) {
            Self::Strict
        } else {
            Self::Protect
        }
    }
}

impl Level {
    /// The name the config file and `--isolation` spell.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Protect => "protect",
            Self::Strict => "strict",
            Self::Offline => "offline",
            Self::Off => "off",
        }
    }

    /// The sandboxed form of this level, `None` for `off`.
    pub const fn confinement(self) -> Option<Confinement> {
        match self {
            Self::Protect => Some(Confinement::Protect),
            Self::Strict => Some(Confinement::Strict),
            Self::Offline => Some(Confinement::Offline),
            Self::Off => None,
        }
    }
}

/// A level that runs the build in a sandbox: the type a sandbox is created for,
/// so no code path can ask for a sandbox at `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confinement {
    /// See [`Level::Protect`].
    Protect,
    /// See [`Level::Strict`].
    Strict,
    /// See [`Level::Offline`].
    Offline,
}

impl Confinement {
    /// Whether the build's files are an allowlist rather than a denylist.
    pub const fn is_allowlist(self) -> bool {
        matches!(self, Self::Strict | Self::Offline)
    }

    /// Whether the build may reach the network, through heel's proxy.
    pub const fn network_allowed(self) -> bool {
        !matches!(self, Self::Offline)
    }
}

/// The `[isolation]` table of the global config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IsolationConfig {
    /// The level builds run at unless `--isolation` says otherwise.
    pub level: Level,
    /// How many daily audit files of each kind are kept before the oldest is
    /// removed.
    pub audit_files: usize,
    /// Per-crate widening for `strict` and `offline`.
    #[serde(rename = "grant")]
    pub grants: Vec<CrateGrant>,
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            level: Level::default(),
            audit_files: 30,
            grants: Vec::new(),
        }
    }
}

/// What the sandbox adds while one crate is in the build's dependency graph.
///
/// A grant only widens: the level's own boundary has no entry a grant could
/// narrow, and a grant cannot reopen a `protect` denylist entry, which heel
/// enforces after every grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrateGrant {
    /// The crate the grant is for, as named in `Cargo.lock`.
    #[serde(rename = "crate")]
    pub crate_name: String,
    /// Absolute paths the build may read.
    #[serde(default)]
    pub read: Vec<PathBuf>,
    /// Absolute paths the build may read and write.
    #[serde(default)]
    pub write: Vec<PathBuf>,
    /// Absolute paths the build may read and execute.
    #[serde(default)]
    pub exec: Vec<PathBuf>,
    /// Environment variables passed through to the build.
    #[serde(default)]
    pub env: Vec<String>,
}

impl CrateGrant {
    /// Check the grant is well formed: it names a crate and only absolute
    /// paths and valid variable names.
    ///
    /// # Errors
    ///
    /// The first malformed entry.
    pub fn validate(&self) -> stow_types::error::Result<()> {
        if self.crate_name.trim().is_empty() {
            return Err(stow_types::stow_error!(
                "an [[isolation.grant]] entry names no crate"
            ));
        }
        for path in self.read.iter().chain(&self.write).chain(&self.exec) {
            if !path.is_absolute() {
                return Err(stow_types::stow_error!(
                    "the isolation grant for `{}` names {}, which is not an absolute path",
                    self.crate_name,
                    path.display()
                ));
            }
        }
        for name in &self.env {
            if name.is_empty() || name.contains('=') || name.contains('\0') {
                return Err(stow_types::stow_error!(
                    "the isolation grant for `{}` names the invalid variable `{name}`",
                    self.crate_name
                ));
            }
        }
        Ok(())
    }
}

/// The level a run resolved to, and the config its grants and audit settings
/// come from.
#[derive(Debug, Clone)]
pub struct Isolation {
    /// The level the build runs at.
    pub level: Level,
    /// The `[isolation]` table the level was resolved against.
    pub config: IsolationConfig,
}

impl Isolation {
    /// Resolve the level of one run: `flag` is `--isolation`, and the config's
    /// level applies when it is absent.
    ///
    /// # Errors
    ///
    /// A malformed grant, or a level this platform cannot enforce.
    pub fn resolve(
        flag: Option<Level>,
        config: IsolationConfig,
    ) -> stow_types::error::Result<Self> {
        let level = resolve(flag, &config)?;
        Ok(Self { level, config })
    }

    /// No isolation, for the commands that compile nothing.
    pub fn off() -> Self {
        Self {
            level: Level::Off,
            config: IsolationConfig::default(),
        }
    }
}

/// The level a run resolves to, with the platform check applied.
///
/// `flag` is `--isolation`; the config's level applies when it is absent.
///
/// # Errors
///
/// A malformed grant, or a level this platform cannot enforce.
pub fn resolve(flag: Option<Level>, config: &IsolationConfig) -> stow_types::error::Result<Level> {
    for grant in &config.grants {
        grant.validate()?;
    }
    let level = flag.unwrap_or(config.level);
    ensure_supported(level)?;
    Ok(level)
}

/// Fail when this platform has no sandbox backend for `level`.
///
/// Whether a backend can enforce the level on this host (kernel version,
/// `ptrace_scope`, a setting the platform refuses) is heel's answer when the
/// sandbox is created, which fails the build; nothing here falls back to a
/// weaker level.
fn ensure_supported(level: Level) -> stow_types::error::Result<()> {
    if level == Level::Off
        || cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows"
        ))
    {
        Ok(())
    } else {
        Err(stow_types::stow_error!(
            "isolation level `{}` is not supported on {}: heel has a sandbox backend for Linux, macOS and Windows only; use `--isolation off`",
            level.as_str(),
            std::env::consts::OS
        ))
    }
}

/// The names of the crates in the build's lockfile, which decide which
/// per-crate grants apply.
///
/// # Errors
///
/// A lockfile that exists and cannot be read. A missing one names no crates.
pub fn locked_crates(
    workspace_root: &Path,
) -> stow_types::error::Result<std::collections::BTreeSet<String>> {
    let path = workspace_root.join("Cargo.lock");
    if !path.is_file() {
        return Ok(std::collections::BTreeSet::new());
    }
    let lockfile = cargo_lock::Lockfile::load(&path)
        .map_err(|error| stow_types::stow_error!("read {}: {error}", path.display()))?;
    Ok(lockfile
        .packages
        .iter()
        .map(|package| package.name.as_str().to_owned())
        .collect())
}

/// The grants of `config` whose crate is in `crates`.
pub fn applicable_grants<'a>(
    config: &'a IsolationConfig,
    crates: &std::collections::BTreeSet<String>,
) -> impl Iterator<Item = &'a CrateGrant> {
    config
        .grants
        .iter()
        .filter(|grant| crates.contains(&grant.crate_name))
}

/// Variable-name fragments that mark a credential, matched without regard to
/// case anywhere in the name.
const SECRET_FRAGMENTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "CREDENTIAL",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
];

/// Variables that name an agent a build must not be able to reach, whatever
/// they are called.
const AGENT_VARIABLES: &[&str] = &[
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "DOCKER_AUTH_CONFIG",
];

/// Whether `protect` strips the environment variable `name`.
///
/// Token, secret and password patterns, registry tokens
/// (`CARGO_REGISTRY_TOKEN`, `CARGO_REGISTRIES_<NAME>_TOKEN`) and the agent
/// socket variables. Everything else reaches the build unchanged.
pub fn is_credential_variable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    AGENT_VARIABLES.contains(&upper.as_str())
        || SECRET_FRAGMENTS
            .iter()
            .any(|fragment| upper.contains(fragment))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_level_is_strict_on_windows_and_protect_elsewhere() {
        let expected = if cfg!(windows) {
            Level::Strict
        } else {
            Level::Protect
        };
        assert_eq!(Level::default(), expected);
        assert_eq!(IsolationConfig::default().level, expected);
    }

    #[test]
    fn the_levels_parse_from_the_config_and_reject_anything_else() {
        for (name, level) in [
            ("protect", Level::Protect),
            ("strict", Level::Strict),
            ("offline", Level::Offline),
            ("off", Level::Off),
        ] {
            let config: IsolationConfig = toml::from_str(&format!("level = \"{name}\"")).unwrap();
            assert_eq!(config.level, level);
            assert_eq!(level.as_str(), name);
        }
        assert!(toml::from_str::<IsolationConfig>("level = \"paranoid\"").is_err());
        assert!(toml::from_str::<IsolationConfig>("unknown = 1").is_err());
    }

    #[test]
    fn grants_parse_and_validate() {
        // A TOML literal string (single quotes) keeps Windows backslashes
        // unescaped; the path is absolute on the platform under test.
        let openssl = if cfg!(windows) {
            r"C:\opt\openssl"
        } else {
            "/opt/homebrew/opt/openssl"
        };
        let config: IsolationConfig = toml::from_str(&format!(
            r#"
            level = "strict"

            [[grant]]
            crate = "openssl-sys"
            read = ['{openssl}']
            env = ["OPENSSL_DIR"]
            "#,
        ))
        .unwrap();
        assert_eq!(config.grants[0].read, [PathBuf::from(openssl)]);
        assert_eq!(config.grants[0].crate_name, "openssl-sys");
        config.grants[0].validate().unwrap();
    }

    #[test]
    fn a_malformed_grant_fails_the_resolution() {
        let relative = IsolationConfig {
            grants: vec![CrateGrant {
                crate_name: "x".into(),
                read: vec![PathBuf::from("relative/path")],
                write: vec![],
                exec: vec![],
                env: vec![],
            }],
            ..IsolationConfig::default()
        };
        assert!(resolve(Some(Level::Off), &relative).is_err());

        let nameless = IsolationConfig {
            grants: vec![CrateGrant {
                crate_name: " ".into(),
                read: vec![],
                write: vec![],
                exec: vec![],
                env: vec![],
            }],
            ..IsolationConfig::default()
        };
        assert!(resolve(Some(Level::Off), &nameless).is_err());
    }

    #[test]
    fn the_flag_overrides_the_config() {
        let config = IsolationConfig {
            level: Level::Strict,
            ..IsolationConfig::default()
        };
        assert_eq!(resolve(Some(Level::Off), &config).unwrap(), Level::Off);
        assert_eq!(resolve(None, &config).unwrap(), Level::Strict);
    }

    #[test]
    fn every_level_resolves_on_a_platform_with_a_backend() {
        for level in [Level::Protect, Level::Strict, Level::Offline, Level::Off] {
            assert_eq!(
                resolve(Some(level), &IsolationConfig::default()).unwrap(),
                level
            );
        }
    }

    #[test]
    fn only_the_crates_in_the_lockfile_widen_the_build() {
        let config = IsolationConfig {
            grants: vec![
                CrateGrant {
                    crate_name: "present".into(),
                    read: vec![],
                    write: vec![],
                    exec: vec![],
                    env: vec![],
                },
                CrateGrant {
                    crate_name: "absent".into(),
                    read: vec![],
                    write: vec![],
                    exec: vec![],
                    env: vec![],
                },
            ],
            ..IsolationConfig::default()
        };
        let crates = std::collections::BTreeSet::from(["present".to_owned()]);
        let applied: Vec<_> = applicable_grants(&config, &crates)
            .map(|grant| grant.crate_name.as_str())
            .collect();
        assert_eq!(applied, ["present"]);
    }

    #[test]
    fn credential_variables_are_recognised_and_toolchain_variables_are_not() {
        for name in [
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "NPM_TOKEN",
            "CARGO_REGISTRY_TOKEN",
            "CARGO_REGISTRIES_PRIVATE_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "DB_PASSWORD",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "OPENAI_API_KEY",
            "SSH_AUTH_SOCK",
            "SSH_AGENT_PID",
            "GPG_AGENT_INFO",
            "github_token",
        ] {
            assert!(is_credential_variable(name), "{name} should be stripped");
        }
        for name in [
            "PATH",
            "HOME",
            "CARGO_HOME",
            "RUSTFLAGS",
            "CC",
            "LANG",
            "TERM",
            "SDKROOT",
            "GIT_AUTHOR_NAME",
            "SSL_CERT_FILE",
            "RUST_BACKTRACE",
        ] {
            assert!(!is_credential_variable(name), "{name} should pass");
        }
    }
}

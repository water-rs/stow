use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "stow", version, disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Check(CargoCommandArgs),
    Build(CargoCommandArgs),
    Test(CargoCommandArgs),
    /// Report this workspace's cache coverage. Read-only: nothing is
    /// posted and nothing is enqueued.
    Predict(CargoCommandArgs),
    Setup(SetupArgs),
    /// Update this install to the latest stow-cli release.
    Update,
    Status,
    Stats(StatsArgs),
    Clean,
    CheckArtifact(CheckArtifactArgs),
    FetchArtifact(FetchArtifactArgs),
    /// Manage the signed local artifact index this toolchain resolves
    /// against.
    Index(IndexArgs),
    #[command(name = "rustc", hide = true)]
    Rustc(WrapperCommandArgs),
    #[command(name = "cc", hide = true)]
    Cc(WrapperCommandArgs),
    #[command(name = "__purge-cache-dir", hide = true)]
    PurgeCacheDir(PurgeCacheDirArgs),
    /// `stow __drain-misses <target_dir>`: post the miss admissions a
    /// finished build's rustc wrappers journaled. Internal — the driver
    /// or a later wrapper spawns it detached; it is never for users.
    #[command(name = "__drain-misses", hide = true)]
    DrainMisses(DrainMissesArgs),
}

#[derive(Debug, Clone, Args)]
pub struct DrainMissesArgs {
    /// The cargo target dir holding the `stow-misses.*.jsonl` journals.
    pub target_dir: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct CargoCommandArgs {
    #[arg(long)]
    pub silent_compatible_upgrades: bool,
    /// Disable the default-on stow resolver. By default stow asks the edge
    /// to synthesize a cache-optimized `Cargo.lock` for this workspace,
    /// then runs `cargo metadata --locked` as a dry-run gate — cargo
    /// rejects any synthesis that violates the user's semver/feature
    /// requirements, in which case stow deletes the swap and falls back
    /// to cargo's own resolver. Pass this flag to skip the takeover
    /// entirely.
    #[arg(long)]
    pub no_stow_resolver: bool,
    #[command(flatten)]
    pub isolation: IsolationArgs,
    #[command(flatten)]
    pub cache: CacheSwitchArgs,
    #[arg(
        value_name = "CARGO_ARGS",
        num_args = 0..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub cargo_args: Vec<OsString>,
}

/// The build isolation switch, flattened into the commands that run cargo
/// (stow#1000).
#[derive(Debug, Clone, Args)]
pub struct IsolationArgs {
    /// How much of the machine the build's cargo, build scripts and proc
    /// macros can reach, for this run: `protect` (the default, except on
    /// Windows, where heel cannot enforce it and the default is `strict`)
    /// keeps credential stores unreadable and persistence locations
    /// unwritable and strips credential variables, `strict` grants only the workspace, the
    /// target directory and the toolchain, `offline` is `strict` without the
    /// network, and `off` is no isolation. Overrides `[isolation] level` in the
    /// stow config.
    #[arg(long, value_enum, value_name = "LEVEL")]
    pub isolation: Option<crate::isolation::Level>,
}

/// The cache layer switches, flattened into the commands that run cargo
/// (stow#1007). Each flag turns its layer off for this run, over the
/// `[cache]` table of the stow config.
#[derive(Debug, Clone, Copy, Default, Args)]
pub struct CacheSwitchArgs {
    /// Turn the remote cache off for this run: no edge or registry request,
    /// no miss journal, no inexact report, and no entry downloaded earlier is
    /// served; those units compile locally and are stored as local entries.
    /// Overrides `[cache] remote` in the stow config.
    #[arg(long)]
    pub no_remote_cache: bool,
    /// Turn the local cache of crates.io units off for this run: none is
    /// looked up or stored. Overrides `[cache] local_crates_io`.
    #[arg(long)]
    pub no_local_crates_io_cache: bool,
    /// Turn the local cache of git units off for this run: none is looked up
    /// or stored. Overrides `[cache] local_git`.
    #[arg(long)]
    pub no_local_git_cache: bool,
}

impl CacheSwitchArgs {
    /// The config's layers with this run's flags applied: a flag only turns a
    /// layer off.
    #[must_use]
    pub const fn over(self, layers: crate::config::CacheLayers) -> crate::config::CacheLayers {
        crate::config::CacheLayers {
            remote: layers.remote && !self.no_remote_cache,
            local_crates_io: layers.local_crates_io && !self.no_local_crates_io_cache,
            local_git: layers.local_git && !self.no_local_git_cache,
        }
    }
}

#[derive(Debug, Clone, Args)]
pub struct SetupArgs {
    /// Print the wrapper wiring as `KEY=VALUE` lines on stdout instead of
    /// writing the global cargo config, for CI systems that configure the
    /// job environment (`stow setup --github-env >> "$GITHUB_ENV"`).
    #[arg(long)]
    pub github_env: bool,
}

/// `stow stats`: print this install's own cache statistics — hits,
/// CPU time saved, bytes downloaded — kept in `stats.json` next to the
/// cache. Local-only: nothing leaves the machine.
#[derive(Debug, Clone, Args)]
pub struct StatsArgs {
    /// Print the counters as JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Args)]
pub struct CheckArtifactArgs {
    pub target: String,
    pub rustc_version: String,
    pub c_metadata: String,
}

#[derive(Debug, Clone, Args)]
pub struct FetchArtifactArgs {
    pub target: String,
    pub rustc_version: String,
    pub c_metadata: String,
    pub output_path: PathBuf,
    pub crate_name: String,
}

#[derive(Debug, Clone, Args)]
pub struct WrapperCommandArgs {
    pub executable: OsString,
    #[arg(
        value_name = "WRAPPED_ARGS",
        num_args = 0..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub wrapped_args: Vec<OsString>,
}

#[derive(Debug, Clone, Args)]
pub struct PurgeCacheDirArgs {
    #[arg(value_name = "PATH", num_args = 1..)]
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct IndexArgs {
    #[command(subcommand)]
    pub command: IndexCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum IndexCommand {
    /// Download, verify, and cache the index slice for a toolchain, even
    /// when the cached pointer is still fresh.
    Refresh(IndexRefreshArgs),
    /// Print every cached index slice: target, `rustc_version`, row count,
    /// `fetched_at`, manifest digest.
    Status,
}

#[derive(Debug, Clone, Args)]
pub struct IndexRefreshArgs {
    /// Target triple; defaults to the `rustc -vV` host target.
    #[arg(long)]
    pub target: Option<String>,
    /// Stable rustc version (e.g. `1.91.1`); defaults to `rustc --version`.
    #[arg(long)]
    pub rustc_version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_check_command_with_passthrough_cargo_args() {
        let cli = Cli::try_parse_from([
            "stow",
            "check",
            "--silent-compatible-upgrades",
            "--target",
            "aarch64-apple-darwin",
            "--manifest-path",
            "Cargo.toml",
        ])
        .expect("parse check command");

        let Command::Check(args) = cli.command else {
            panic!("expected check command");
        };
        assert!(args.silent_compatible_upgrades);
        assert_eq!(
            args.cargo_args,
            vec![
                OsString::from("--target"),
                OsString::from("aarch64-apple-darwin"),
                OsString::from("--manifest-path"),
                OsString::from("Cargo.toml"),
            ]
        );
    }

    #[test]
    fn each_cache_flag_turns_off_its_own_layer_over_the_config() {
        use crate::config::CacheLayers;
        let parse = |flag: &str| {
            let cli = Cli::try_parse_from(["stow", "build", flag]).expect("parse build command");
            let Command::Build(args) = cli.command else {
                panic!("expected build command");
            };
            args.cache
        };
        let on = CacheLayers::default();
        assert_eq!(
            parse("--no-remote-cache").over(on),
            CacheLayers {
                remote: false,
                ..on
            }
        );
        assert_eq!(
            parse("--no-local-crates-io-cache").over(on),
            CacheLayers {
                local_crates_io: false,
                ..on
            }
        );
        assert_eq!(
            parse("--no-local-git-cache").over(on),
            CacheLayers {
                local_git: false,
                ..on
            }
        );
        // A flag never turns a layer the config switched off back on.
        let all_off = CacheLayers {
            remote: false,
            local_crates_io: false,
            local_git: false,
        };
        assert_eq!(CacheSwitchArgs::default().over(all_off), all_off);
        assert_eq!(parse("--no-local-git-cache").over(all_off), all_off);
    }

    #[test]
    fn every_cargo_running_command_takes_the_cache_flags() {
        for command in ["check", "build", "test", "predict"] {
            Cli::try_parse_from([
                "stow",
                command,
                "--no-remote-cache",
                "--no-local-crates-io-cache",
                "--no-local-git-cache",
            ])
            .unwrap_or_else(|error| panic!("{command} rejects a cache flag: {error}"));
        }
    }

    #[test]
    fn parses_fetch_artifact_command() {
        let cli = Cli::try_parse_from([
            "stow",
            "fetch-artifact",
            "aarch64-apple-darwin",
            "1.91.1",
            "abc123",
            "/tmp/out.tar",
            "aho-corasick",
        ])
        .expect("parse fetch-artifact command");

        let Command::FetchArtifact(args) = cli.command else {
            panic!("expected fetch-artifact command");
        };
        assert_eq!(args.target, "aarch64-apple-darwin");
        assert_eq!(args.rustc_version, "1.91.1");
        assert_eq!(args.c_metadata, "abc123");
        assert_eq!(args.output_path, PathBuf::from("/tmp/out.tar"));
        assert_eq!(args.crate_name, "aho-corasick");
    }

    #[test]
    fn parses_setup_command_with_github_env_flag() {
        let cli =
            Cli::try_parse_from(["stow", "setup", "--github-env"]).expect("parse setup command");

        let Command::Setup(args) = cli.command else {
            panic!("expected setup command");
        };
        assert!(args.github_env);
    }

    #[test]
    fn parses_index_refresh_command() {
        let cli =
            Cli::try_parse_from(["stow", "index", "refresh"]).expect("parse index refresh command");

        let Command::Index(args) = cli.command else {
            panic!("expected index command");
        };
        let IndexCommand::Refresh(args) = args.command else {
            panic!("expected index refresh");
        };
        assert!(args.target.is_none());
        assert!(args.rustc_version.is_none());
    }

    #[test]
    fn parses_index_refresh_with_toolchain_overrides() {
        let cli = Cli::try_parse_from([
            "stow",
            "index",
            "refresh",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--rustc-version",
            "1.91.1",
        ])
        .expect("parse index refresh command");

        let Command::Index(args) = cli.command else {
            panic!("expected index command");
        };
        let IndexCommand::Refresh(args) = args.command else {
            panic!("expected index refresh");
        };
        assert_eq!(args.target.as_deref(), Some("x86_64-unknown-linux-gnu"));
        assert_eq!(args.rustc_version.as_deref(), Some("1.91.1"));
    }

    #[test]
    fn parses_index_status_command() {
        let cli =
            Cli::try_parse_from(["stow", "index", "status"]).expect("parse index status command");

        let Command::Index(args) = cli.command else {
            panic!("expected index command");
        };
        assert!(matches!(args.command, IndexCommand::Status));
    }

    #[test]
    fn parses_hidden_rustc_wrapper_command() {
        let cli = Cli::try_parse_from(["stow", "rustc", "/usr/bin/rustc", "--crate-name", "itoa"])
            .expect("parse rustc wrapper command");

        let Command::Rustc(args) = cli.command else {
            panic!("expected rustc command");
        };
        assert_eq!(args.executable, OsString::from("/usr/bin/rustc"));
        assert_eq!(
            args.wrapped_args,
            vec![OsString::from("--crate-name"), OsString::from("itoa")]
        );
    }
}

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
    #[arg(
        value_name = "CARGO_ARGS",
        num_args = 0..,
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub cargo_args: Vec<OsString>,
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

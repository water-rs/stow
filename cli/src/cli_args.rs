use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// A prebuilt cache for Rust dependencies, and a local compilation
/// cache that replaces sccache.
#[derive(Debug, Parser)]
#[command(name = "stow", version, disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Parse `args` while recognizing `CargoCommandArgs` flags anywhere before
    /// `--` on `check`, `build`, `test`, and `predict`, even after Cargo flags
    /// such as `-p foo` or `--workspace`.
    ///
    /// # Errors
    ///
    /// Returns clap's parse error when any `stow` flag or subcommand is
    /// malformed.
    pub fn try_parse_normalized<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let raw: Vec<OsString> = args.into_iter().map(Into::into).collect();
        Self::try_parse_from(hoist_cargo_command_flags(&raw))
    }
}

fn hoist_cargo_command_flags(args: &[OsString]) -> Vec<OsString> {
    let Some(subcommand) = args.get(1).and_then(|s| s.to_str()) else {
        return args.to_vec();
    };
    if !matches!(subcommand, "check" | "build" | "test" | "predict") {
        return args.to_vec();
    }

    let mut hoisted = Vec::new();
    let mut passthrough = Vec::new();
    let tail = &args[2..];
    let mut index = 0;
    while index < tail.len() {
        let arg = &tail[index];
        if arg == "--" {
            passthrough.extend_from_slice(&tail[index..]);
            break;
        }
        match arg.to_str() {
            Some(
                "--silent-compatible-upgrades"
                | "--no-stow-resolver"
                | "--no-remote-cache"
                | "--no-local-crates-io-cache"
                | "--no-local-git-cache",
            ) => {
                hoisted.push(arg.clone());
            }
            Some(flag) if flag.starts_with("--isolation=") => {
                hoisted.push(arg.clone());
            }
            Some("--isolation") => {
                hoisted.push(arg.clone());
                if let Some(next) = tail.get(index + 1)
                    && next != "--"
                {
                    hoisted.push(next.clone());
                    index += 1;
                }
            }
            _ => passthrough.push(arg.clone()),
        }
        index += 1;
    }

    let mut out = Vec::with_capacity(args.len());
    out.extend_from_slice(&args[..2]);
    out.extend(hoisted);
    out.extend(passthrough);
    out
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Drop-in replacement for `cargo check`: units the caches cover
    /// are served, the rest compile.
    Check(CargoCommandArgs),
    /// Drop-in replacement for `cargo build`: units the caches cover
    /// are served, the rest compile.
    Build(CargoCommandArgs),
    /// Drop-in replacement for `cargo test`: units the caches cover
    /// are served, the rest compile.
    Test(CargoCommandArgs),
    /// Drop-in replacement for `cargo run`: the binary and its
    /// dependencies are the units `cargo build` compiles; argv after
    /// `--` passes to the program.
    Run(CargoCommandArgs),
    /// Drop-in replacement for `cargo clippy`: dependencies the caches
    /// cover are served; workspace members lint through clippy-driver
    /// and are never cached.
    Clippy(CargoCommandArgs),
    /// Drop-in replacement for `cargo bench`: units the caches cover
    /// are served, the rest compile.
    Bench(CargoCommandArgs),
    /// Drop-in replacement for `cargo doc`: dependencies the caches
    /// cover are served; the rustdoc output itself is not cached.
    Doc(CargoCommandArgs),
    /// Drop-in replacement for `cargo nextest`: the build compiles the
    /// units `cargo test` compiles, serving whatever the caches cover.
    /// cargo-nextest is the user's own tool; stow does not install it.
    Nextest(CargoCommandArgs),
    /// Report this workspace's cache coverage. Read-only: nothing is
    /// posted and nothing is enqueued.
    Predict(CargoCommandArgs),
    /// Write stow's wrapper wiring into the global cargo config, so
    /// every `cargo` invocation routes through the wrappers.
    Setup(SetupArgs),
    /// Update this install to the latest stow-cli release.
    Update,
    /// Print Cargo wrapper wiring, remote and daemon state, stale per-project
    /// wiring, and cache performance counters.
    Status,
    /// Print this install's own cache statistics — hits, CPU time
    /// saved, bytes downloaded — kept in `stats.json` next to the
    /// cache. Local-only: nothing leaves the machine.
    Stats(StatsArgs),
    /// Reclaim unlocked build directories (deleted workspaces, idle age, or
    /// least-recently-used under size and free-space bounds) without touching
    /// cached artifacts.
    Gc(GcArgs),
    /// Remove cached artifacts and build directories, keeping index
    /// slices and local stats; `--all` removes the whole cache dir.
    Clean(CleanArgs),
    /// Resolve a `c_metadata` against the verified index slice and
    /// report the bundle digest it pins.
    CheckArtifact(CheckArtifactArgs),
    /// Download the artifact bundle a `c_metadata` resolves to,
    /// digest-checked against the index.
    FetchArtifact(FetchArtifactArgs),
    /// Manage the signed local artifact index this toolchain resolves
    /// against.
    Index(IndexArgs),
    /// Run the per-user stow daemon in the foreground, or with `status`
    /// report the running one. Clients start the daemon themselves; this
    /// is what they run.
    Daemon(DaemonArgs),
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

/// The spelling of [`DaemonArgs::run_dir`]. A daemon starts its successor
/// with these three flags, and an older image starts a newer one, so they
/// never change.
#[cfg(unix)]
pub const RUN_DIR_FLAG: &str = "--run-dir";
/// The spelling of [`DaemonArgs::inherit_lock`].
#[cfg(unix)]
pub const INHERIT_LOCK_FLAG: &str = "--inherit-lock";
/// The spelling of [`DaemonArgs::inherit_listener`].
#[cfg(unix)]
pub const INHERIT_LISTENER_FLAG: &str = "--inherit-listener";

#[derive(Debug, Clone, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct DaemonArgs {
    /// The endpoint to report readiness to — how the client that spawned
    /// this daemon learns it is serving. Internal to the start path.
    #[arg(long, value_name = "ENDPOINT", hide = true)]
    pub ready: Option<PathBuf>,
    /// The runtime directory to serve, instead of `STOW_DAEMON_DIR` or the
    /// default. The Windows scheduled task names it, because a daemon the
    /// Task Scheduler starts has none of its starter's environment.
    /// Internal to the scheduled task.
    #[arg(long, value_name = "DIR", hide = true)]
    pub run_dir: Option<PathBuf>,
    /// The descriptor of `daemon.lock`, locked by the daemon this one
    /// replaces: adopt it instead of locking the file. Internal to the
    /// replacement of a running daemon.
    #[cfg(unix)]
    #[arg(long, value_name = "FD", hide = true, requires = "inherit_listener")]
    pub inherit_lock: Option<std::os::fd::RawFd>,
    /// The descriptor of the listening socket of the daemon this one
    /// replaces: serve on it instead of binding. Internal to the
    /// replacement of a running daemon.
    #[cfg(unix)]
    #[arg(long, value_name = "FD", hide = true, requires = "inherit_lock")]
    pub inherit_listener: Option<std::os::fd::RawFd>,
    #[command(subcommand)]
    pub command: Option<DaemonCommand>,
}

#[derive(Debug, Clone, Subcommand)]
pub enum DaemonCommand {
    /// Print the running daemon's stow version and protocol, starting the
    /// daemon first when it is not running.
    Status,
    /// Drain the running daemon if any, checkpoint and truncate every cache
    /// catalog's WAL, and exit with no daemon holding files open.
    Stop(DaemonStopArgs),
}

#[derive(Debug, Clone, Default, Args)]
pub struct DaemonStopArgs {
    /// Evict `local-crates-io/` down to at most this many reclaimable bytes
    /// before checkpointing the catalogs.
    #[arg(long)]
    pub local_crates_io_max_bytes: Option<u64>,
}

#[derive(Debug, Clone, Args)]
pub struct DrainMissesArgs {
    /// The cargo target dir holding the `stow-misses.*.jsonl` journals.
    pub target_dir: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct CargoCommandArgs {
    /// Apply the index's semver-compatible dependency-upgrade
    /// suggestions without prompting.
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

// The build isolation switch, flattened into the commands that run cargo
// (stow#1000). Not a doc comment: a doc comment on a flattened `Args`
// struct becomes the `about` of every command it is flattened into.
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

// The cache layer switches, flattened into the commands that run cargo
// (stow#1007). Each flag turns its layer off for this run, over the
// `[cache]` table of the stow config. Not a doc comment: a doc comment
// on a flattened `Args` struct becomes the `about` of every command it
// is flattened into.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillInstallPolicy {
    PromptIfDetected,
    Install,
    Skip,
}

#[derive(Debug, Clone, Copy, Args, Default)]
pub struct SkillSetupArgs {
    /// Install the bundled `stow` agent skill into detected `~/.agents` /
    /// `~/.claude` directories without prompting.
    #[arg(long, conflicts_with = "no_install_skill")]
    pub install_skill: bool,
    /// Skip offering or installing the `stow` agent skill.
    #[arg(long, conflicts_with = "install_skill")]
    pub no_install_skill: bool,
}

impl SkillSetupArgs {
    #[must_use]
    pub const fn policy(self) -> SkillInstallPolicy {
        if self.no_install_skill {
            SkillInstallPolicy::Skip
        } else if self.install_skill {
            SkillInstallPolicy::Install
        } else {
            SkillInstallPolicy::PromptIfDetected
        }
    }
}

#[derive(Debug, Clone, Args, Default)]
pub struct SetupArgs {
    /// Print the wrapper wiring as `KEY=VALUE` lines on stdout instead of
    /// writing the global cargo config, for CI systems that configure the
    /// job environment (`stow setup --github-env >> "$GITHUB_ENV"`).
    #[arg(long)]
    pub github_env: bool,
    /// Leave Cargo's standard `target/` build directory untouched instead of
    /// placing `build.build-dir` under `$STOW_CACHE_DIR/build-dir/` (removing
    /// any previously stow-placed `build.build-dir`), for ephemeral CI
    /// runners.
    #[arg(long)]
    pub no_build_dir: bool,
    /// Apply the setup plan without prompting for confirmation on an
    /// interactive terminal.
    #[arg(short = 'y', long)]
    pub yes: bool,
    #[command(flatten)]
    pub skill: SkillSetupArgs,
}

#[derive(Debug, Clone, Args)]
pub struct StatsArgs {
    /// Print the counters as JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Args, Default)]
pub struct GcArgs {
    /// Reclaim only the build directories belonging to these workspace or
    /// git worktree paths (before or after the directory is deleted).
    #[arg(long = "worktree", value_name = "PATH")]
    pub worktrees: Vec<PathBuf>,
    /// Override `build_dir_max_bytes` for this run (`0` evicts every unlocked
    /// idle build directory).
    #[arg(long, value_name = "BYTES")]
    pub max_bytes: Option<u64>,
    /// Override `build_dir_min_free_bytes` for this run.
    #[arg(long, value_name = "BYTES")]
    pub min_free_bytes: Option<u64>,
}

#[derive(Debug, Clone, Args, Default)]
pub struct CleanArgs {
    /// Remove the entire `$STOW_CACHE_DIR` including cached index slices and
    /// local usage stats.
    #[arg(long)]
    pub all: bool,
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

    /// Every visible command and subcommand describes itself, and no
    /// description is an internal note: a `///` doc comment on a
    /// flattened `Args` struct becomes the `about` of every command it
    /// is flattened into, which is how the `CacheSwitchArgs` note leaked
    /// onto `check`/`build`/`test` (stow#1659).
    #[test]
    fn every_visible_command_describes_itself_without_internal_notes() {
        fn walk(command: &clap::Command) {
            for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
                let about = sub.get_about().map_or_else(
                    || panic!("`{}` has no description", sub.get_name()),
                    ToString::to_string,
                );
                let long = sub
                    .get_long_about()
                    .map_or_else(String::new, ToString::to_string);
                assert!(
                    !about.contains("stow#") && !long.contains("stow#"),
                    "`{}` leaks an internal reference into help: {about}",
                    sub.get_name()
                );
                walk(sub);
            }
        }
        walk(&<Cli as clap::CommandFactory>::command());
    }

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

    /// A daemon starts its successor with this command line, and an older
    /// image starts a newer one, so what it names must keep parsing.
    #[cfg(unix)]
    #[test]
    fn a_daemons_successor_command_line_parses() {
        let cli = Cli::try_parse_from([
            "stow",
            "daemon",
            RUN_DIR_FLAG,
            "/run",
            INHERIT_LOCK_FLAG,
            "5",
            INHERIT_LISTENER_FLAG,
            "6",
        ])
        .expect("parse the successor command line");
        let Command::Daemon(args) = cli.command else {
            panic!("expected the daemon command");
        };
        assert_eq!(args.run_dir, Some(PathBuf::from("/run")));
        assert_eq!(
            (args.inherit_lock, args.inherit_listener),
            (Some(5), Some(6))
        );
        assert!(
            Cli::try_parse_from(["stow", "daemon", INHERIT_LOCK_FLAG, "5"]).is_err(),
            "the two descriptors come together"
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
        for command in [
            "check", "build", "test", "run", "clippy", "bench", "doc", "nextest", "predict",
        ] {
            Cli::try_parse_normalized([
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
    fn stow_flags_parse_after_cargo_flags_and_stay_verbatim_after_double_dash() {
        for command in ["check", "build", "test", "predict"] {
            let cli = Cli::try_parse_normalized([
                "stow",
                command,
                "-p",
                "demo",
                "--release",
                "--no-remote-cache",
                "--silent-compatible-upgrades",
                "--no-stow-resolver",
                "--isolation",
                "strict",
                "--no-local-crates-io-cache",
                "--no-local-git-cache",
                "--",
                "--no-remote-cache",
                "--isolation",
                "bogus",
            ])
            .unwrap_or_else(|error| panic!("{command} failed to parse interleaved flags: {error}"));

            let args = match cli.command {
                Command::Check(a) | Command::Build(a) | Command::Test(a) | Command::Predict(a) => a,
                other => panic!("unexpected command {other:?}"),
            };
            assert!(args.silent_compatible_upgrades);
            assert!(args.no_stow_resolver);
            assert!(args.cache.no_remote_cache);
            assert!(args.cache.no_local_crates_io_cache);
            assert!(args.cache.no_local_git_cache);
            assert_eq!(
                args.isolation.isolation,
                Some(crate::isolation::Level::Strict)
            );
            assert_eq!(
                args.cargo_args,
                vec![
                    OsString::from("-p"),
                    OsString::from("demo"),
                    OsString::from("--release"),
                    OsString::from("--"),
                    OsString::from("--no-remote-cache"),
                    OsString::from("--isolation"),
                    OsString::from("bogus"),
                ]
            );
        }

        let eq = Cli::try_parse_normalized(["stow", "check", "--workspace", "--isolation=offline"])
            .expect("parse --isolation=<LEVEL> after cargo flag");
        let Command::Check(eq_args) = eq.command else {
            panic!("expected check command");
        };
        assert_eq!(
            eq_args.isolation.isolation,
            Some(crate::isolation::Level::Offline)
        );
        assert_eq!(eq_args.cargo_args, vec![OsString::from("--workspace")]);

        assert!(
            Cli::try_parse_normalized(["stow", "check", "-p", "demo", "--isolation", "bogus"])
                .is_err()
        );
        assert!(Cli::try_parse_normalized(["stow", "check", "-p", "demo", "--isolation"]).is_err());
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
        assert!(!args.yes);
    }

    #[test]
    fn parses_setup_command_with_yes_flags() {
        for flag in ["-y", "--yes"] {
            let cli = Cli::try_parse_from(["stow", "setup", flag])
                .unwrap_or_else(|error| panic!("parse `stow setup {flag}`: {error}"));
            let Command::Setup(args) = cli.command else {
                panic!("expected setup command");
            };
            assert!(args.yes, "{flag} must set args.yes");
        }
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
    fn parses_the_daemon_and_its_status_command() {
        let cli = Cli::try_parse_from(["stow", "daemon", "--ready", "/run/ready.sock"])
            .expect("parse daemon command");
        let Command::Daemon(args) = cli.command else {
            panic!("expected daemon command");
        };
        assert_eq!(args.ready, Some(PathBuf::from("/run/ready.sock")));
        assert!(args.command.is_none());

        let cli = Cli::try_parse_from(["stow", "daemon", "--run-dir", "/run/stow"])
            .expect("parse daemon command with a run directory");
        let Command::Daemon(args) = cli.command else {
            panic!("expected daemon command");
        };
        assert_eq!(args.run_dir, Some(PathBuf::from("/run/stow")));
        assert!(args.ready.is_none());

        let cli = Cli::try_parse_from(["stow", "daemon", "status"]).expect("parse status");
        let Command::Daemon(args) = cli.command else {
            panic!("expected daemon command");
        };
        assert!(matches!(args.command, Some(DaemonCommand::Status)));
        assert!(Cli::try_parse_from(["stow", "daemon", "--ready", "x", "status"]).is_err());
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

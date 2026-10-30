//! Stow CLI: rustc-wrapper that intercepts every compilation unit, looks up a
//! prebuilt artifact via the edge worker, and either injects the cached output
//! into Cargo's target directory or falls through to a normal `rustc` build.
//!
//! Public binaries:
//!
//! * `stow-cli` — the canonical entrypoint installed on user machines.
//! * `cargo-stow` — same binary exposed as a `cargo` subcommand.
//! * `stow` — short alias.
//!
//! All three resolve to [`run`].

// The wrapper's nested async serve chain overflows the default auto-trait
// evaluation depth when rustc proves `Send` for `async_main`'s future.
#![recursion_limit = "256"]

mod admission;
mod artifact_cache;
mod budget;
/// The verified cache-consumption chain `stow-build` reuses (stow#299).
///
/// Signed index fetch, digest-checked bundle download, cosign verification
/// and artifact injection — one implementation for the user CLI and the
/// trusted builder alike.
pub mod build_consume;
mod cache_policy;
mod cargo_cmd;
mod cc;
mod circuit;
mod cli_args;
mod commands;
mod config;
mod derive_gate;
mod edge_client;
mod facade;
mod fetch;
mod file_lock;
mod index;
mod inject;
mod isolation;
mod lockfile_graph_cache;
mod lockfile_resolver;
mod miss_journal;
mod mold;
#[cfg(test)]
mod network_gate;
mod prefetch;
mod profile_guard;
mod provenance;
mod report;
mod resolve;
mod rustc_args;
mod sandbox;
mod state_db;
mod stats;
mod supervisor;
#[cfg(test)]
mod test_edge;
mod unit_node;
mod verify;
mod workspace_deps;

use stow_shim as wrapper_shim;
/// `cargo --unit-graph` reads — the build stage computes its consumable
/// set from the workspace's own unit graphs (stow#589).
pub use workspace_deps::{
    ExpandedDependencyGraph, expanded_dependency_graph, resolve_exact_dependency_graph,
};

/// What a supervisor exports beside its endpoint so a wrapper can tell
/// it was started by its own build — the stub supervisors export it the
/// way the real one does (stow#645).
pub use supervisor::BinaryIdentity;
/// The supervisor wire protocol, so a peer decoding frames — a stub
/// supervisor standing in for the real one in integration tests — uses
/// the product's own types instead of reimplementing the format.
pub use supervisor::protocol;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use async_process::Command;
use clap::Parser;
use stow_types::error::Context;
use stow_types::identity::DependencyCompileKeyIdentity;
use stow_types::public_cache::{
    Reach, UnitSource, detect_git_checkout,
    detect_registry_crate_version as shared_detect_registry_crate_version,
    normalized_cache_profile, stable_unit_identity,
};
use stow_types::rustc::{UncachedReason, UnitClass};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer as _};

use crate::artifact_cache::{
    DependencyCMetadataResolution, DependencyInstanceIdentity, load_cached_bundle,
    load_cached_bundle_by_compile_key, load_semantic_cached_bundle, prepare_local_cache,
    record_materialized_bundle_outputs, record_materialized_local_build_outputs,
    remove_cached_bundle, remove_loaded_bundle_entry, resolve_dependency_c_metadata_json,
};
use crate::cli_args::{Cli, Command as CliCommand, WrapperCommandArgs};
use crate::config::StowConfig;
use crate::fetch::FetchRequest;
use crate::state_db::StateDb;
use crate::supervisor::protocol::ArtifactNotifications;

const STOW_EXPANDED_GRAPH_PATH_ENV: &str = "STOW_EXPANDED_GRAPH_PATH";
pub(crate) const STOW_PREFETCH_ARTIFACTS_PATH_ENV: &str = "STOW_PREFETCH_ARTIFACTS_PATH";
pub(crate) const STOW_ENABLE_SEMANTIC_FALLBACK_ENV: &str = "STOW_ENABLE_SEMANTIC_FALLBACK";
pub(crate) const STOW_TRACE_WRAPPED_COMPILERS_ENV: &str = "STOW_TRACE_WRAPPED_COMPILERS";
/// When set to a path, stow writes a Chrome-trace JSON to that file describing
/// every instrumented span (`stow.startup`, `stow.project.context`,
/// `stow.edge.graph.query`, `stow.wrapper.invoke`, ...). The trace records
/// every span and event of stow's own crates regardless of `RUST_LOG`. Open
/// the file with <chrome://tracing> or perfetto.dev for a flame waterfall.
const STOW_TRACE_FILE_ENV: &str = "STOW_TRACE_FILE";

/// Holds the tracing-chrome flush guard, if a Chrome trace was requested.
///
/// The guard must outlive `block_on` so the trace file is fully flushed.
struct TracingGuard {
    _chrome: Option<tracing_chrome::FlushGuard>,
}

/// Entry point for all three stow binaries: runs the fast paths that
/// need no runtime, then [`run_command`].
///
/// # Errors
///
/// Returns an error when the selected subcommand fails before it can
/// produce an exit status.
pub fn run() -> stow_types::error::Result<()> {
    if let Some(status) = delegate_to_capture()? {
        std::process::exit(status);
    }
    // An uncovered rustc invocation needs no runtime: the serve map the
    // driver built answers the decision, and the compile's bookkeeping is
    // two one-way frames. Everything the runtime would buy — the provider
    // install, tracing, the tokio stack — is the per-invocation cost this
    // build pays hundreds of times.
    if let facade::FastPath::Handled(status) = facade::try_invocation()? {
        std::process::exit(status);
    }
    let status = run_command()?;
    // The one place a command's failure ends the process — `run_command`
    // has returned, so everything the command owned — its mirror, its
    // scratch directory, the runtime, the tracing guard — has been
    // dropped before the exit (stow#652). The state database was closed
    // before that: `async_main` closes it ahead of returning (stow#682).
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

/// Installs tracing when the invocation allows it, builds a tokio
/// runtime sized to the invocation kind, runs [`async_main`] on the
/// `stow-main` thread, and returns the command's exit status.
///
/// Wrapper invocations (`stow rustc`, `stow cc`) get a `current_thread`
/// runtime — they run hundreds of times per build with at most one
/// concurrent network task, so worker-pool spin-up is wasted overhead.
/// User-facing commands that can fan out get the multi-threaded runtime.
fn run_command() -> stow_types::error::Result<std::process::ExitStatus> {
    // `sigstore`'s `sigstore-trust-root` feature pulls `tough`, which depends
    // on `rustls` with default features — that compiles in `aws_lc_rs`
    // alongside the `ring` provider selected by `zenwave`, `sqlx`, and
    // reqwest 0.12. `tough`'s rustls dep cannot be reconfigured, so rustls
    // cannot auto-select a provider; install `ring` explicitly before any
    // TLS client is built.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| stow_types::error::Error::msg("install ring CryptoProvider"))?;
    let _tracing_guard = should_install_tracing().then(install_tracing);
    let runtime = if is_wrapper_invocation() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .wrap_err("create tokio runtime for stow rustc wrapper")?
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .wrap_err("create tokio runtime for stow cli")?
    };
    // `block_on` drives the whole command on the thread that calls it, and
    // the main thread's stack is whatever the executable's headers reserve
    // — a megabyte on Windows. stow's command futures nest deeply (resolve,
    // mirror build, prefetch, verification, each holding the config and its
    // graphs), so that megabyte is a ceiling the call graph can grow into
    // rather than a bound anyone chose. Run it on a thread whose stack size
    // is stated instead.
    std::thread::Builder::new()
        .name("stow-main".to_owned())
        .stack_size(MAIN_STACK_BYTES)
        .spawn(move || {
            let result = runtime.block_on(async_main());
            // The command returns when its main future does. Dropping the
            // runtime instead waits for whatever is still running on it —
            // a build sat out a trust-store scan that way (stow#624) — so
            // what a command owes, its main future awaits, the way the
            // supervisor's drain does (stow#618).
            runtime.shutdown_background();
            result
        })
        .wrap_err("spawn the stow main thread")?
        .join()
        .map_err(|_| stow_types::error::Error::msg("the stow main thread panicked"))?
}

/// Stack for the thread every command runs on.
///
/// Sixteen megabytes: large enough that the nesting depth of a command is
/// not a platform-dependent cliff, small enough to be a rounding error
/// against the process this tool exists to make faster.
const MAIN_STACK_BYTES: usize = 16 * 1024 * 1024;

/// The process arguments as the CLI parser sees them.
///
/// Cargo runs an external subcommand as `cargo-stow stow <args>`, repeating
/// the subcommand name as `argv[1]`; that word is dropped so `cargo stow
/// check` and `stow check` parse identically. A binary started under one of
/// the wrapper names (the shims are this executable, symlinked on Unix and
/// copied on Windows) parses the `rustc`/`cc` subcommand line that name
/// stands for.
pub(crate) fn process_args() -> Vec<OsString> {
    expand_wrapper_role(strip_cargo_subcommand_word(std::env::args_os().collect()))
}

fn expand_wrapper_role(args: Vec<OsString>) -> Vec<OsString> {
    let Some((program, wrapped)) = args.split_first() else {
        return args;
    };
    // An internal `__`-namespaced subcommand is the runtime addressing
    // itself, not a wrapped compiler call — the detached miss drain
    // respawns current_exe, which is the shim's own name on platforms
    // where current_exe does not resolve through the shim (stow#317).
    if wrapped
        .first()
        .and_then(|arg| arg.to_str())
        .is_some_and(|arg| arg.starts_with("__"))
    {
        return args;
    }
    let Some(role) = wrapper_shim::WrapperRole::from_program(Path::new(program)) else {
        return args;
    };
    let mut expanded = Vec::with_capacity(args.len() + 2);
    expanded.push(program.clone());
    expanded.extend(role.runtime_args(wrapped));
    expanded
}

/// Inside a trusted build sandbox the rustc wrapper belongs to the capture
/// executable, not this runtime. The wrapper is this runtime under another
/// name, so it runs `stow-capture` from its own directory with the same
/// arguments and returns that exit status.
fn delegate_to_capture() -> stow_types::error::Result<Option<i32>> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let Some((program, wrapped)) = args.split_first() else {
        return Ok(None);
    };
    let program = Path::new(program);
    let delegates = wrapper_shim::WrapperRole::from_program(program)
        .is_some_and(wrapper_shim::WrapperRole::delegates_to_capture);
    if !delegates {
        return Ok(None);
    }
    let capture = wrapper_shim::capture_executable_beside(program);
    let status = std::process::Command::new(&capture)
        .arg("rustc")
        .args(wrapped)
        .status()
        .wrap_err_with(|| format!("run capture wrapper {}", capture.display()))?;
    Ok(Some(status.code().unwrap_or(1)))
}

fn strip_cargo_subcommand_word(mut args: Vec<OsString>) -> Vec<OsString> {
    let invoked_as_cargo_subcommand = args
        .first()
        .and_then(|program| Path::new(program).file_stem())
        .is_some_and(|stem| stem == "cargo-stow")
        && args.get(1).is_some_and(|word| word == "stow");
    if invoked_as_cargo_subcommand {
        args.remove(1);
    }
    args
}

fn is_wrapper_invocation() -> bool {
    matches!(
        process_args().get(1).map(OsString::as_os_str),
        Some(arg) if arg == "rustc" || arg == "cc"
    )
}

fn should_install_tracing() -> bool {
    let args = process_args();
    should_install_tracing_for_args(
        &args,
        std::env::var_os("RUST_LOG").as_deref(),
        std::env::var_os(STOW_TRACE_WRAPPED_COMPILERS_ENV),
    )
}

fn should_install_tracing_for_args(
    args: &[OsString],
    rust_log: Option<&OsStr>,
    trace_wrapped_compilers: Option<OsString>,
) -> bool {
    let is_wrapper_subcommand = matches!(
        args.get(1).map(OsString::as_os_str),
        Some(command) if command == "rustc" || command == "cc"
    );
    if is_wrapper_subcommand {
        return trace_wrapped_compilers.is_some_and(|value| value != "0");
    }
    rust_log.is_some() || !is_wrapper_subcommand
}

#[tracing::instrument(name = "stow.startup", skip_all, fields(subcommand))]
async fn async_main() -> stow_types::error::Result<std::process::ExitStatus> {
    let args = process_args();
    let cli = parse_cli_or_exit(&args)?;
    let span = tracing::Span::current();
    span.record("subcommand", subcommand_name(&cli.command));
    // The process's one handle on the state database: every config the
    // command loads shares it, so this is the only place that has to
    // know what is open.
    let state_db = StateDb::default();
    let result = Box::pin(run_cli(cli, &state_db)).await;
    // Closed on every path, before the runtime goes away (stow#682).
    state_db.close().await;
    result
}

/// Run the parsed command and return the exit status the process owes
/// its caller. Nothing below here ends the process: every path returns,
/// so [`async_main`] closes the state database behind it (stow#682).
async fn run_cli(
    cli: Cli,
    state_db: &StateDb,
) -> stow_types::error::Result<std::process::ExitStatus> {
    // The cargo commands end with cargo's own exit status and the
    // wrapper roles with their compiler's; every other command either
    // fails or ends with success.
    let done = match cli.command {
        CliCommand::Check(command) => {
            return Box::pin(cargo_cmd::run("check", command, state_db)).await;
        }
        CliCommand::Build(command) => {
            return Box::pin(cargo_cmd::run("build", command, state_db)).await;
        }
        CliCommand::Test(command) => {
            return Box::pin(cargo_cmd::run("test", command, state_db)).await;
        }
        CliCommand::Rustc(command) => return run_rustc_wrapper(command, state_db).await,
        CliCommand::Cc(command) => return run_cc_wrapper(command, state_db).await,
        CliCommand::Predict(command) => Box::pin(cargo_cmd::predict(command, state_db)).await,
        CliCommand::Setup(args) => commands::setup_project(args, state_db).await,
        CliCommand::Update => commands::update_self().await,
        CliCommand::Status => commands::status_project(state_db).await,
        CliCommand::Stats(args) => commands::stats_command(args, state_db).await,
        CliCommand::Clean => commands::clean_project().await,
        CliCommand::CheckArtifact(command) => commands::check_artifact(command, state_db).await,
        CliCommand::FetchArtifact(command) => commands::fetch_artifact(command, state_db).await,
        CliCommand::Index(args) => match args.command {
            cli_args::IndexCommand::Refresh(args) => commands::index_refresh(args, state_db).await,
            cli_args::IndexCommand::Status => commands::index_status(state_db).await,
        },
        CliCommand::PurgeCacheDir(command) => commands::purge_cache_dirs(command).await,
        CliCommand::DrainMisses(args) => miss_journal::drain(&args.target_dir, state_db).await,
    };
    done.map(|()| std::process::ExitStatus::default())
}

const fn subcommand_name(command: &CliCommand) -> &'static str {
    match command {
        CliCommand::Check(_) => "check",
        CliCommand::Build(_) => "build",
        CliCommand::Test(_) => "test",
        CliCommand::Predict(_) => "predict",
        CliCommand::Setup(_) => "setup",
        CliCommand::Update => "update",
        CliCommand::Status => "status",
        CliCommand::Stats(_) => "stats",
        CliCommand::Clean => "clean",
        CliCommand::CheckArtifact(_) => "check-artifact",
        CliCommand::FetchArtifact(_) => "fetch-artifact",
        CliCommand::Index(_) => "index",
        CliCommand::Rustc(_) => "rustc",
        CliCommand::Cc(_) => "cc",
        CliCommand::PurgeCacheDir(_) => "purge-cache-dir",
        CliCommand::DrainMisses(_) => "drain-misses",
    }
}

async fn run_passthrough_status(
    executable: &OsString,
    env: &[(OsString, OsString)],
    wrapped_args: &[std::ffi::OsString],
) -> stow_types::error::Result<async_process::ExitStatus> {
    Command::new(executable)
        .args(wrapped_args)
        .envs(env.iter().cloned())
        .status()
        .await
        .wrap_err("failed to spawn wrapped compiler")
}

/// Whether this unit has to be compiled locally because one of the
/// dependencies cargo hands it on the command line was compiled locally
/// in this build.
///
/// Every cache path would otherwise serve an artifact compiled against
/// CI's copy of that dependency while cargo passes the local copy, and
/// rustc rejects the pair outright (E0460/E0463) — the build fails rather
/// than merely running slower.
fn must_build_locally(
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    policy_dir: Option<&Path>,
) -> bool {
    let Some(dependency) =
        provenance::locally_built_dependency(policy_dir, target, &parsed.extern_crates)
    else {
        return false;
    };
    tracing::debug!(
        crate_name = %parsed.crate_name,
        %dependency,
        target,
        "dependency was compiled locally in this build; compiling this unit locally too"
    );
    true
}

/// The decision one rustc invocation gets, with nothing done yet: the
/// facade has not exited and rustc has not run.
///
/// Splitting the decision from its execution is what lets the same code
/// answer a facade over the supervisor socket and run standalone under a
/// plain `cargo build`.
enum Outcome {
    /// The unit's outputs are in the target directory. The payload is
    /// the artifact-notification lines the deciding process computed —
    /// written to stderr only by the process cargo spawned, at the
    /// `exit(0)` it earns (stow#633).
    Served(supervisor::protocol::ArtifactNotifications),
    /// Nothing serves this unit; the real rustc has to run, and
    /// [`finish_rustc_compile`] finishes the work afterwards.
    Compile(Box<PostCompile>),
}

/// The bookkeeping that only exists once a real rustc has run: the stable
/// aliases, the output metadata, and the local cache entry this build's
/// own outputs become for the next one.
struct PostCompile {
    executable: OsString,
    /// `None` for an invocation stow could not parse — a probe, or a rustc
    /// command line it does not understand. There is nothing to record.
    parsed: Option<rustc_args::ParsedRustcArgs>,
    /// The invocation's environment as the deciding process learned it —
    /// the `Plan`/`Observed` frame's values under a supervised build, this
    /// process's own under a standalone one.
    env: supervisor::protocol::InvocationEnv,
    /// How long the real rustc ran, set once it has: the compile time a later
    /// local hit on the stored unit reports as saved.
    compile_time: std::time::Duration,
}

impl PostCompile {
    /// A compile with no bookkeeping at all.
    fn raw(executable: &OsString) -> Self {
        Self {
            executable: executable.clone(),
            parsed: None,
            env: supervisor::protocol::InvocationEnv::default(),
            compile_time: std::time::Duration::ZERO,
        }
    }
}

/// Decide to compile, recording the local-build marker first.
///
/// The marker is recorded before the compile, not after it. Cargo
/// pipelines: it starts a consumer as soon as this unit emits its
/// metadata, which happens while rustc is still finishing, so a marker
/// written afterwards arrives too late to stop the consumer from taking a
/// cached artifact that was compiled against a different copy.
///
/// The marker's target key — the unit's own compile target: the spelled
/// `--target`, else the host triple this build's rustc compiles for. A
/// dependent checks under its own target the same way, so a host-side
/// unit on a `--target` build marks and is found under the host triple.
async fn compile(
    executable: &OsString,
    parsed: &rustc_args::ParsedRustcArgs,
    mark_target: Option<&str>,
    policy_dir: Option<&Path>,
    invocation_env: &supervisor::protocol::InvocationEnv,
) -> Outcome {
    if let Some(target) = mark_target {
        log_nonfatal_result(
            "failed to record a locally built crate for this build",
            provenance::record_local_build(
                policy_dir,
                target,
                &parsed.crate_name,
                &parsed.extra_filename,
            )
            .await,
        );
    }
    Outcome::Compile(Box::new(PostCompile {
        executable: executable.clone(),
        parsed: Some(parsed.clone()),
        env: invocation_env.clone(),
        compile_time: std::time::Duration::ZERO,
    }))
}

/// Finish the work a real compile leaves behind, and return the identity
/// it resolved to — `None` when the invocation was unparseable or the
/// artifact's identity could not be worked out (already warned). Callers
/// minting misses from compile observations treat `None` as "not
/// observed": a unit whose extern resolution failed is never minted
/// (stow#317).
///
/// # Errors
///
/// Only the build-script output check — it cannot write what it checks,
/// because cargo owns `build-script-build`: stow copying onto a path
/// cargo may already have hardlinked to the source turns `fs::copy`'s
/// truncate into a zeroed shared inode (stow#347). Everything else is
/// best effort and logged.
async fn finish_rustc_compile(
    post: &PostCompile,
    success: bool,
    local_base: Option<&WrapperEnvBase>,
    env_cache: &WrapperEnvCache,
    ctx: &BuildContext,
) -> stow_types::error::Result<Option<artifact_cache::LocalBuildArtifact>> {
    let Some(parsed) = post.parsed.as_ref() else {
        return Ok(None);
    };
    let mut artifact = None;
    if success {
        if let Some(base) = local_base {
            match resolve_local_build_artifact(
                base,
                parsed,
                &ctx.in_flight,
                ctx.unit_nodes(),
                env_cache,
                ctx,
                &post.env,
            )
            .await
            {
                Ok(LocalBuildResolution::Resolved(build)) => {
                    let mut build = *build;
                    build.compile_millis = duration_millis(post.compile_time);
                    log_nonfatal_result(
                        "failed to materialize stable local build aliases after successful rustc build",
                        inject::materialize_local_build_stable_aliases(
                            parsed,
                            &build.identity,
                            &base.host_target,
                            inject::OutputDirWriters::StowOnly,
                        )
                        .await,
                    );
                    log_nonfatal_result(
                        "failed to record materialized stow output metadata after local rustc build",
                        record_materialized_local_build_outputs(
                            &base.config,
                            parsed,
                            &build,
                            &base.host_target,
                        )
                        .await,
                    );
                    // A resolved unit is keyed by construction — the
                    // classification inside `resolve_local_build_artifact`
                    // already excluded every uncached shape.
                    if base.config.cache.local(&build.identity.source) {
                        log_nonfatal_result(
                            "failed to store locally built artifact in the stow cache",
                            artifact_cache::store_local_build_outputs(
                                &base.config,
                                parsed,
                                &build,
                                &base.host_target,
                            )
                            .await
                            .map(|_| ()),
                        );
                    }
                    artifact = Some(build);
                }
                // A dependency whose bookkeeping genuinely never landed —
                // a path or git dependency, or a store this build skipped.
                // This used to be a silent drop, which is how stow#618
                // stayed hidden; the debug line names the crate and the
                // extern that has no row.
                Ok(LocalBuildResolution::UnrecordedExtern { extern_path }) => {
                    tracing::debug!(
                        crate_name = %parsed.crate_name,
                        extern_path,
                        "not storing locally built unit: an extern's bookkeeping was never recorded"
                    );
                }
                Ok(LocalBuildResolution::NotAnArtifactUnit) => {}
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        crate_name = %parsed.crate_name,
                        "failed to resolve local artifact identity after successful rustc build"
                    );
                }
            }
        }
        if parsed.is_build_script() && parsed.out_dir.is_some() {
            // The binary and its alias are named for the host the
            // compiling rustc reports — the build's memoized probe of
            // that executable, one source whether an env base loaded or
            // not.
            let host = env_cache
                .rustc_host_target(&post.executable)
                .await
                .map_err(stow_types::error::Error::msg)?;
            check_build_script_output(parsed, &host)?;
        }
    }
    Ok(artifact)
}

/// A compiled build script must leave its binary behind for cargo's run
/// phase to link as `build-script-build`. Cargo creates that alias
/// itself before it execs the script — stow must not write the alias
/// too: two writers racing a path that may already be hardlinked to the
/// source turns `fs::copy`'s truncate into a zeroed shared inode
/// (stow#347).
fn check_build_script_output(
    parsed: &rustc_args::ParsedRustcArgs,
    host: &str,
) -> stow_types::error::Result<()> {
    let Some(source_path) = parsed
        .output_binary_path(host)
        .map_err(stow_types::error::Error::msg)?
    else {
        return Ok(());
    };
    if parsed
        .build_script_alias_path(host)
        .map_err(stow_types::error::Error::msg)?
        .is_none()
    {
        return Ok(());
    }
    if !source_path.exists() {
        return Err(stow_types::stow_error!(
            "build script output {} does not exist after successful rustc passthrough",
            source_path.display()
        ));
    }
    Ok(())
}

/// How the wrapper disposes of an argv `ParsedRustcArgs` rejected.
///
/// The wrapper accelerates builds; it must never break one, so an argument
/// list stow cannot model still reaches the real compiler — both variants
/// run a transparent passthrough and differ only in how loudly they are
/// logged.
enum UnparseableInvocation {
    /// cargo's `--crate-name`-less probe of the compiler; quiet bypass.
    Probe(String),
    /// A unit whose arguments failed to parse. One warn names the error —
    /// and the crate, when `--crate-name` is still readable — before the
    /// untouched argv goes to rustc.
    Passthrough(String),
}

fn classify_invocation(
    args: &[OsString],
) -> Result<rustc_args::ParsedRustcArgs, UnparseableInvocation> {
    match rustc_args::ParsedRustcArgs::parse(args) {
        Ok(parsed) => Ok(parsed),
        Err(error) if error.contains("missing --crate-name") => {
            Err(UnparseableInvocation::Probe(error))
        }
        Err(error) => Err(UnparseableInvocation::Passthrough(error)),
    }
}

/// The parsed invocation, or `None` after logging what the rejected
/// argv was: a cargo probe at debug — expected, not a defect — and a
/// unit whose arguments failed to parse at warn, with the crate name
/// when `--crate-name` is still readable. `None` means run rustc and
/// take its answer; each caller supplies its own way to do that.
fn classify_or_log(
    classified: Result<rustc_args::ParsedRustcArgs, UnparseableInvocation>,
    args: &[OsString],
) -> Option<rustc_args::ParsedRustcArgs> {
    match classified {
        Ok(parsed) => Some(parsed),
        Err(UnparseableInvocation::Probe(error)) => {
            tracing::debug!(error = %error, "rustc probe invocation detected, bypassing cache");
            None
        }
        Err(UnparseableInvocation::Passthrough(error)) => {
            tracing::warn!(
                error = %error,
                crate_name = wrapped_crate_name(args)
                    .as_deref()
                    .unwrap_or("<unknown>"),
                "rustc arguments failed to parse; passing the invocation through to rustc"
            );
            None
        }
    }
}

/// Best-effort `--crate-name` scrape for the warn emitted on an invocation
/// the parser rejected — the name is usually present even when some other
/// argument failed.
fn wrapped_crate_name(args: &[OsString]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(value) = arg.to_str() else {
            continue;
        };
        if let Some(name) = value.strip_prefix("--crate-name=") {
            return Some(name.to_owned());
        }
        if value == "--crate-name" {
            return iter
                .next()
                .and_then(|name| name.to_str())
                .map(str::to_owned);
        }
    }
    None
}

/// The build-scoped facts a supervisor cannot read from its own
/// environment: every `STOW_*` variable `run_cargo` sets travels on
/// cargo's environment to the facades, while the deciding process — the
/// `stow` that spawned cargo — has only its own. The driver passes them
/// in by construction; the standalone wrapper rebuilds the same view
/// from the environment it actually inherits.
#[derive(Debug, Default)]
pub(crate) struct BuildContext {
    /// `STOW_CACHE_POLICY_PATH`: the per-build directory the allow markers
    /// and the local-build provenance markers live under.
    pub(crate) policy_dir: Option<PathBuf>,
    /// `STOW_PUBLIC_CACHE_TARGET`: the consumer target the driver told
    /// its wrappers they build for — a fallback for invocations that do
    /// not spell `--target`.
    pub(crate) public_cache_target: Option<String>,
    /// The public cache is off — the remote cache layer being off, or a gate
    /// the driver decided (an unsupported toolchain, a profile the cache
    /// cannot key): local lookups still run.
    pub(crate) public_cache_disabled: bool,
    /// The resolved cache layers (config, then flags). With every layer off
    /// each unit compiles and nothing is recorded; a single layer off gates
    /// its own lookups and stores where they happen.
    pub(crate) cache: crate::config::CacheLayers,
    /// The facts the full graph analysis contributes once it lands. A
    /// supervised build starts the cell empty — the driver's analysis
    /// runs while cargo builds and commits it — while the standalone
    /// wrapper's cell is already filled from the environment that
    /// invoked it (stow#347). Until it is set, the plan path answers as
    /// though the build carried no expanded graph and no prefetch
    /// ledger: semantic fallback off, no candidates.
    pub(crate) analysis: std::sync::Arc<std::sync::OnceLock<AnalysisFacts>>,
    /// The "the serve map is final" signal `AwaitServeMap` frames wait
    /// on — and the "the build's slice fetch has settled" signal the
    /// slice memo's missing-slice read (stow#735) and pending-slice
    /// miss retry (stow#797) wait on: `run_cargo` shares the
    /// enrichment's with the supervisor and completes it itself when no
    /// fetch is in flight; the standalone wrapper's settles by
    /// construction — a driver with no pending map answers at once
    /// (stow#347).
    pub(crate) serve_map_ready: std::sync::Arc<crate::facade::ServeMapSignal>,
    /// The "the cache policy's allow set is committed" signal the plan
    /// path waits on when an invocation's marker is absent
    /// (stow#788): armed pending only while a supervised build's
    /// deferred enrichment still owes the policy directory its coarse
    /// commit, released by the commit itself or by the guard that
    /// drops with a failed or aborted enrichment. The standalone
    /// wrapper's settles by construction — no commit is coming.
    pub(crate) policy_ready: std::sync::Arc<crate::facade::ServeMapSignal>,
    /// The build's in-flight local compiles, shared with the supervisor:
    /// a post-compile waits on the ones its `--extern` set names before
    /// reading their `materialized_outputs` rows (stow#618). The
    /// standalone wrapper's is empty — its invocations have no other
    /// connections to order against.
    pub(crate) in_flight: crate::supervisor::server::InFlightUnits,
    /// How this build tells a crates.io package from another registry's —
    /// the workspace's `Cargo.lock` for a supervised build, the cargo
    /// config's source table for the standalone wrapper (stow#1006).
    /// Lazily resolved for the standalone wrapper: the cargo-config load
    /// only runs when a registry slot is actually classified, never for
    /// a path or git unit. A supervised build seeds it with the
    /// lockfile's answer.
    pub(crate) registry_sources: std::sync::OnceLock<RegistrySources>,
}

impl BuildContext {
    /// The source map this build classifies registry slots against: the
    /// map the cell was seeded with — the lockfile's for a supervised
    /// build — else the cargo-config host rule the standalone wrapper
    /// lives on.
    ///
    /// # Errors
    ///
    /// The cargo config the standalone rule reads does not load or names
    /// a source chain cargo itself would reject.
    pub(crate) fn registry_sources(&self) -> stow_types::error::Result<&RegistrySources> {
        if let Some(sources) = self.registry_sources.get() {
            return Ok(sources);
        }
        let sources = RegistrySources::from_cargo_config()?;
        Ok(self.registry_sources.get_or_init(|| sources))
    }
}

/// The source map a build classifies registry slots against (stow#1006):
/// only crates.io packages may carry a crates.io identity — every other
/// registry's package is [`UncachedReason::NonCratesIoRegistry`].
#[derive(Debug)]
pub(crate) enum RegistrySources {
    /// The `(package, version)` → registry-source map `Cargo.lock`
    /// records — a supervised build's authoritative answer, but read
    /// before cargo runs: a build that rewrites the lockfile can leave
    /// it stale, so the extraction slot's index directory against
    /// `crates_io_hosts` is always checked too. A replaced crates.io
    /// still records the crates.io source, so a mirror's extraction
    /// directory classifies correctly.
    Lockfile {
        /// `(package, version)` → the registry `SourceId`s the lockfile
        /// records for it.
        sources: std::collections::BTreeMap<
            (String, String),
            std::collections::BTreeSet<cargo_lock::package::SourceId>,
        >,
        /// The index-dir hosts a crates.io or replace-with slot extracts
        /// under — the cargo-config source chain, resolved once.
        crates_io_hosts: std::collections::BTreeSet<String>,
    },
    /// The registry index-dir hosts a standalone wrapper accepts as
    /// crates.io: `index.crates.io` plus every host the
    /// `source.crates-io.replace-with` chain resolves to, matched by the
    /// URL host against the `<host>-<hash>` directory name.
    CargoConfig(std::collections::BTreeSet<String>),
}

impl RegistrySources {
    /// The map a supervised build's `Cargo.lock` at `workspace_root`
    /// carries. A missing lockfile degrades to the cargo-config rule —
    /// cargo writes it during this very build, so absence is a defined
    /// state, same answer `lockfile_registry_packages` gives. A
    /// lockfile that exists but does not parse is an error: degraded
    /// source classification is exactly the D1 defect this map exists
    /// to close.
    ///
    /// # Errors
    ///
    /// The lockfile is unreadable or unparseable.
    pub(crate) async fn from_lockfile(workspace_root: &Path) -> stow_types::error::Result<Self> {
        let lockfile_path = workspace_root.join("Cargo.lock");
        let contents = match async_fs::read(&lockfile_path).await {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Self::from_cargo_config();
            }
            Err(error) => {
                return Err(stow_types::stow_error!(
                    "read lockfile {}: {error}",
                    lockfile_path.display()
                ));
            }
        };
        let contents = String::from_utf8(contents).map_err(|error| {
            stow_types::stow_error!("lockfile {} is not UTF-8: {error}", lockfile_path.display())
        })?;
        Self::parse_lockfile(&contents, &cargo_config_hosts()?).map_err(|error| {
            stow_types::stow_error!("parse lockfile {}: {error}", lockfile_path.display())
        })
    }

    /// The `(package, version)` → source map one `Cargo.lock` records,
    /// classified against `crates_io_hosts` when several registries ship
    /// the same pair.
    fn parse_lockfile(
        contents: &str,
        crates_io_hosts: &std::collections::BTreeSet<String>,
    ) -> Result<Self, cargo_lock::Error> {
        let lockfile = contents.parse::<cargo_lock::Lockfile>()?;
        let mut sources: std::collections::BTreeMap<
            (String, String),
            std::collections::BTreeSet<cargo_lock::package::SourceId>,
        > = std::collections::BTreeMap::new();
        for package in &lockfile.packages {
            let Some(source) = package.source.as_ref() else {
                continue;
            };
            if !source.is_registry() {
                continue;
            }
            sources
                .entry((package.name.to_string(), package.version.to_string()))
                .or_default()
                .insert(source.clone());
        }
        Ok(Self::Lockfile {
            sources,
            crates_io_hosts: crates_io_hosts.clone(),
        })
    }

    /// The index-dir hosts a standalone wrapper accepts as crates.io:
    /// the cargo-config source chain's answer.
    ///
    /// # Errors
    ///
    /// See [`cargo_config_hosts`].
    pub(crate) fn from_cargo_config() -> stow_types::error::Result<Self> {
        Ok(Self::CargoConfig(cargo_config_hosts()?))
    }

    /// Whether the registry slot's `(package, version)` at `index_dir`
    /// (`<host>-<hash>` or `index.crates.io-<hash>`) is a crates.io
    /// package.
    pub(crate) fn is_crates_io(&self, package: &str, version: &str, index_dir: &str) -> bool {
        match self {
            Self::Lockfile {
                sources,
                crates_io_hosts,
            } => {
                let Some(set) = sources.get(&(package.to_owned(), version.to_owned())) else {
                    return false;
                };
                // The lockfile was read before cargo ran and can be a
                // build stale — the extraction slot's index dir must
                // also name a crates.io host. One recorded source is no
                // shortcut: a lockfile written before this build's
                // resolution still says crates.io for the alternative-
                // registry package cargo just extracted elsewhere.
                set.iter()
                    .any(cargo_lock::package::SourceId::is_default_registry)
                    && index_dir_in_hosts(index_dir, crates_io_hosts)
            }
            Self::CargoConfig(hosts) => index_dir_in_hosts(index_dir, hosts),
        }
    }
}

/// The `<index>` directory's `<host>` half against a host allowlist.
fn index_dir_in_hosts(index_dir: &str, hosts: &std::collections::BTreeSet<String>) -> bool {
    index_dir
        .rsplit_once('-')
        .is_some_and(|(host, _)| hosts.contains(host))
}

/// The index-dir hosts a crates.io slot or its replacement chain can
/// extract under: `index.crates.io`, plus every host the
/// `source.crates-io.replace-with` chain resolves through.
///
/// # Errors
///
/// The cargo config does not load, or its chain names an undefined
/// source, loops, or carries a registry URL without a host — configs
/// cargo itself rejects, so no classification is guessed from them.
fn cargo_config_hosts() -> stow_types::error::Result<std::collections::BTreeSet<String>> {
    let mut hosts = std::collections::BTreeSet::from(["index.crates.io".to_owned()]);
    let config = cargo_config2::Config::load()
        .map_err(|error| stow_types::stow_error!("load the cargo config: {error}"))?;
    let mut source = Some("crates-io".to_owned());
    let mut seen = std::collections::BTreeSet::new();
    while let Some(name) = source.as_deref() {
        if !seen.insert(name.to_owned()) {
            return Err(stow_types::stow_error!(
                "cargo config `source.{name}` closes a replace-with cycle"
            ));
        }
        let Some(table) = config.source.get(name) else {
            if name == "crates-io" {
                break;
            }
            return Err(stow_types::stow_error!(
                "cargo config replace-with names `{name}`, which no `source.{name}` defines"
            ));
        };
        if let Some(registry) = table.registry.as_deref() {
            let host = url::Url::parse(registry)
                .ok()
                .and_then(|url| url.host_str().map(str::to_owned))
                .ok_or_else(|| {
                    stow_types::stow_error!(
                        "cargo config `source.{name}.registry` `{registry}` has no host"
                    )
                })?;
            hosts.insert(host);
        }
        source.clone_from(&table.replace_with);
    }
    Ok(hosts)
}

/// The one-shot latch every build-scoped "it happened" signal shares —
/// a `watch` cell `complete` flips once, awaited by subscribers whether
/// they armed before or after the flip (stow#608). `send_replace`, not
/// `send`: the state must be stored even while no waiter is subscribed
/// yet, or a signal that completes before its first waiter is parked
/// forever.
#[derive(Debug, Clone)]
pub(crate) struct Latch {
    done: tokio::sync::watch::Sender<bool>,
    /// Test observation (stow#810): how many waits have found the latch
    /// pending and parked on it. A test reaches the point where a
    /// decision is provably held by the latch through this, rather than
    /// sleeping and asserting the decision has not finished — which
    /// passes just as well when it never started.
    #[cfg(test)]
    parked: tokio::sync::watch::Sender<usize>,
}

impl Latch {
    /// A latch that has not fired.
    #[must_use]
    pub(crate) fn pending() -> Self {
        Self {
            done: tokio::sync::watch::channel(false).0,
            #[cfg(test)]
            parked: tokio::sync::watch::channel(0).0,
        }
    }

    /// Resolve once `waits` waits have parked on this latch — each
    /// subscribed while it was pending, so a [`Self::complete`] from here
    /// on is what releases them.
    #[cfg(test)]
    pub(crate) async fn parked(&self, waits: usize) {
        let mut parked = self.parked.subscribe();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            parked.wait_for(|count| *count >= waits),
        )
        .await
        .expect("no wait parked on the latch")
        .expect("the latch outlives its observation");
    }

    /// Fire it: release every waiter, present and late alike.
    /// Idempotent — the second fire states the same truth.
    pub(crate) fn complete(&self) {
        self.done.send_replace(true);
    }

    /// Whether it has fired yet.
    #[must_use]
    pub(crate) fn has_completed(&self) -> bool {
        *self.done.borrow()
    }

    /// Resolve on [`Self::complete`]. A latch that is never completed
    /// resolves nothing: its waiters stay parked until the task or
    /// process holding them ends.
    pub(crate) async fn wait(&self) {
        let mut receiver = self.done.subscribe();
        if !*receiver.borrow() {
            #[cfg(test)]
            self.parked.send_modify(|count| *count += 1);
            let _ = receiver.changed().await;
        }
    }
}

impl Default for Latch {
    /// A latch nobody armed has not fired.
    fn default() -> Self {
        Self::pending()
    }
}

/// The build's "cargo's resolution is over" signal.
///
/// The supervisor completes it on the first facade frame that
/// describes a real compile unit — by then cargo holds only the shared
/// package-cache lock, so the in-build enrichment's own `--unit-graph`
/// cargo may take the exclusive one without queuing the user's build
/// behind it. A build whose cargo compiles nothing never fires it; the
/// waiter then ends with the process, as it already does when cargo
/// exits first — no second trigger on cargo's exit (stow#608).
pub(crate) type ResolutionDone = Latch;

/// The `--crate-name` cargo's target-info probe gives its throwaway
/// crate — a probe spelling, never a unit of the build (stow#608).
const PROBE_CRATE_NAME: &str = "___";

/// Whether a parsed invocation compiles a real unit — cargo's
/// `--crate-name ___` probe crate is not one (stow#608).
fn is_compile_unit(parsed: &rustc_args::ParsedRustcArgs) -> bool {
    parsed.crate_name != PROBE_CRATE_NAME
}

/// Whether a facade's frame describes a real compile unit — the moment
/// cargo's resolution is over. Cargo's own probes pass through the
/// wrapper before resolution (`rustc -vV`, the `--crate-name ___
/// --print=file-names` target-info query): the classifier's probe set
/// and the `___` probe crate are not units. An invocation the parser
/// rejects is a compile headed to rustc all the same — cargo does not
/// spawn unparseable probes (stow#608).
fn describes_compile_unit(
    classified: &Result<rustc_args::ParsedRustcArgs, UnparseableInvocation>,
) -> bool {
    match classified {
        Ok(parsed) => is_compile_unit(parsed),
        Err(UnparseableInvocation::Passthrough(_)) => true,
        Err(UnparseableInvocation::Probe(_)) => false,
    }
}

/// What the graph analysis adds to the plan path when it commits: the
/// build's unit node table the semantic identity derivation consults,
/// the prefetch ledger, and whether semantic fallback applies.
#[derive(Debug)]
pub(crate) struct AnalysisFacts {
    /// Whether the expanded graph found a semver-upgrade the plan path
    /// may serve for — the `STOW_ENABLE_SEMANTIC_FALLBACK` fact.
    pub(crate) semantic_fallback_enabled: bool,
    /// The `STOW_EXPANDED_GRAPH_PATH` file parsed: the build's unit
    /// graph as a per-side node table — each lib node's `(crate,
    /// version, side, cargo-resolved feature set)` plus whether the
    /// graph's cargo invocation spelled `--target`. `None` means the
    /// environment carried no graph at all — the distinction a semantic
    /// gate needs between "unset" and "empty".
    pub(crate) unit_nodes: Option<unit_node::UnitNodeTable>,
    /// The `STOW_PREFETCH_ARTIFACTS_PATH` file parsed and indexed:
    /// canonical crate name to the `c_metadata` values the driver
    /// already fetched.
    pub(crate) prefetch_candidates: BTreeMap<String, BTreeSet<String>>,
}

impl BuildContext {
    /// Rebuild the driver's view from this process's own environment —
    /// the standalone wrapper's shape, where the caller that would set
    /// the variables is also the process reading them.
    ///
    /// # Errors
    ///
    /// A set-but-unreadable or malformed table file is a wiring bug and
    /// fails loudly, as a malformed inline payload did.
    fn from_env() -> stow_types::error::Result<Self> {
        let cache = crate::config::load_cache_layers()?;
        let unit_nodes =
            read_build_json_table_env::<unit_node::UnitNodeTable>(STOW_EXPANDED_GRAPH_PATH_ENV)?;
        let prefetch_candidates = read_build_json_table_env::<Vec<resolve::PrefetchArtifactRow>>(
            STOW_PREFETCH_ARTIFACTS_PATH_ENV,
        )?
        .map_or_else(BTreeMap::new, |rows| {
            prefetch_candidate_c_metadatas(
                rows.into_iter()
                    .map(|row| (row.crate_name.into_inner(), row.c_metadata.into_inner())),
            )
        });
        Ok(Self {
            policy_dir: cache_policy::policy_dir(),
            public_cache_target: std::env::var(rustc_args::STOW_PUBLIC_CACHE_TARGET_ENV)
                .ok()
                .filter(|target| !target.trim().is_empty()),
            public_cache_disabled: !cache.reaches_network(),
            cache,
            analysis: std::sync::Arc::new(std::sync::OnceLock::from(AnalysisFacts {
                semantic_fallback_enabled: std::env::var_os(STOW_ENABLE_SEMANTIC_FALLBACK_ENV)
                    .is_some_and(|value| value != "0"),
                unit_nodes,
                prefetch_candidates,
            })),
            serve_map_ready: std::sync::Arc::new(crate::facade::ServeMapSignal::settled()),
            policy_ready: std::sync::Arc::new(crate::facade::ServeMapSignal::settled()),
            // No supervisor shares a standalone invocation's registry —
            // the wait finds nothing and returns at once.
            in_flight: crate::supervisor::server::InFlightUnits::default(),
            registry_sources: std::sync::OnceLock::new(),
        })
    }

    /// The build's per-side unit node table, once analysis committed
    /// it.
    pub(crate) fn unit_nodes(&self) -> Option<&unit_node::UnitNodeTable> {
        self.analysis
            .get()
            .and_then(|facts| facts.unit_nodes.as_ref())
    }

    /// Whether semantic fallback may serve an upgrade for this build.
    pub(crate) fn semantic_fallback_enabled(&self) -> bool {
        self.analysis
            .get()
            .is_some_and(|facts| facts.semantic_fallback_enabled)
    }

    /// The prefetch ledger keyed by canonical crate name.
    pub(crate) fn prefetch_candidates(&self) -> Option<&BTreeMap<String, BTreeSet<String>>> {
        self.analysis.get().map(|facts| &facts.prefetch_candidates)
    }
}

/// One build-scoped JSON table the driver left behind `env` — a file
/// path since stow#625, when the payloads outgrew what one environment
/// string can carry past `execve` (Linux fails it at `MAX_ARG_STRLEN`,
/// which a workspace-sized table clears). Unset reads as no table, as
/// the inline payload did.
///
/// # Errors
///
/// A set variable whose file is missing or malformed is a wiring bug —
/// the same loud failure a malformed inline payload was — naming the
/// path.
fn read_build_json_table_env<T: serde::de::DeserializeOwned>(
    env: &str,
) -> stow_types::error::Result<Option<T>> {
    let Some(path) = std::env::var_os(env) else {
        return Ok(None);
    };
    read_build_json_table(Path::new(&path), env).map(Some)
}

/// Read `path` as the JSON table `env` named; the variable names the
/// wiring in the error.
fn read_build_json_table<T: serde::de::DeserializeOwned>(
    path: &Path,
    env: &str,
) -> stow_types::error::Result<T> {
    let bytes = std::fs::read(path)
        .map_err(|error| stow_types::stow_error!("read {env} {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| stow_types::stow_error!("parse {env} {}: {error}", path.display()))
}

/// The `STOW_PREFETCH_ARTIFACTS_PATH` ledger, indexed once for the
/// per-invocation candidate lookups: canonical crate name to the
/// `c_metadata` values the driver prefetched.
pub(crate) fn prefetch_candidate_c_metadatas(
    rows: impl IntoIterator<Item = (String, String)>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut candidates = BTreeMap::<String, BTreeSet<String>>::new();
    for (crate_name, c_metadata) in rows {
        candidates
            .entry(canonical_crate_name(&crate_name))
            .or_default()
            .insert(c_metadata);
    }
    candidates
}

/// The build's supervisor: it answers every facade this build spawns.
///
/// It holds no state of its own yet — the decision path reads the config
/// from the environment blob the parent already resolved — but it is the
/// process boundary that matters: every edge request for the whole build
/// now happens here, over one pooled connection.
/// The build's supervisor, plus the compile observations it collects:
/// every locally-compiled registry unit lands here at the identity its
/// rustc invocation actually used. `run_cargo` mints the build's misses
/// from this list once cargo finishes — the observations are the build's
/// own, in memory, and die with it (stow#317).
#[derive(Debug)]
pub(crate) struct BuildSupervisor {
    /// The build-scoped wrapper environment memo — one config load,
    /// rustc probe pair and cache lease for the whole build.
    env_cache: WrapperEnvCache,
    /// The build facts `run_cargo` resolved before cargo started — the
    /// policy dir, the expanded graph, the prefetch candidates — which
    /// this process's environment never carried.
    ctx: BuildContext,
    /// Completed by the first facade frame that describes a real
    /// compile unit — the boundary after which the enrichment's own
    /// cargo may take the package-cache lock without holding the real
    /// cargo back (stow#608).
    resolution_done: ResolutionDone,
    observations: std::sync::Mutex<Vec<artifact_cache::ObservedUnit>>,
}

impl BuildSupervisor {
    /// A supervisor that owns the build's resolved context rather than
    /// rediscovering it per invocation. `base` is the wrapper environment
    /// the driver computed before cargo spawned — the facts the lazy
    /// loader would have probed on the first facade's critical path —
    /// seeded into the env cache so `compiled` answers immediately
    /// (stow#608). `state_db` is the process's handle: a base the cache
    /// has to load for a spelling the seed does not cover opens the same
    /// database the driver's own config does (stow#682).
    pub(crate) fn new(
        ctx: BuildContext,
        base: Option<std::sync::Arc<WrapperEnvBase>>,
        resolution_done: ResolutionDone,
        state_db: StateDb,
    ) -> Self {
        let supervisor = Self {
            env_cache: WrapperEnvCache::new(state_db),
            ctx,
            resolution_done,
            observations: std::sync::Mutex::default(),
        };
        if let Some(base) = base {
            supervisor.env_cache.seed(base);
        }
        supervisor
    }

    /// The build's circuit handle — shared with the enrichment so its
    /// index-fetch outage trips the breaker the plan path reads and the
    /// broadcast in-flight downloads abandon on (stow#977).
    pub(crate) fn circuit(&self) -> circuit::BuildCircuit {
        self.env_cache.circuit.clone()
    }

    /// Every unit this build compiled locally, in compile order.
    pub(crate) fn observations(&self) -> Vec<artifact_cache::ObservedUnit> {
        self.observations
            .lock()
            .expect("observations mutex")
            .clone()
    }

    /// `compiled` and the observed report finish the same way: resolve the
    /// build's own outputs, then mint its miss observation.
    async fn finish_and_observe(
        &self,
        post: &PostCompile,
        success: bool,
        local_base: Option<&WrapperEnvBase>,
    ) {
        if let Ok(Some(build)) =
            finish_rustc_compile(post, success, local_base, &self.env_cache, &self.ctx).await
            && let Some(parsed) = post.parsed.as_ref()
            && let Some(unit) = miss_journal::observed_unit(parsed, &build)
        {
            // The unit compiled locally: it is a cache miss by
            // definition, so the build records it for the post-build
            // admissions post (stow#317).
            self.observations
                .lock()
                .expect("observations mutex")
                .push(unit);
        }
    }
}

impl supervisor::server::Handler for BuildSupervisor {
    type Pending = Box<PostCompile>;

    async fn plan(
        self: &std::sync::Arc<Self>,
        executable: OsString,
        args: Vec<OsString>,
        invocation_env: supervisor::protocol::InvocationEnv,
    ) -> supervisor::server::Decision<Self::Pending> {
        let classified = classify_invocation(&args);
        if !self.resolution_done.has_completed() && describes_compile_unit(&classified) {
            self.resolution_done.complete();
        }
        let Some(parsed) = classify_or_log(classified, &args) else {
            return supervisor::server::Decision::Compile(Box::new(PostCompile::raw(&executable)));
        };
        match decide_rustc_invocation(
            &executable,
            parsed,
            &self.env_cache,
            &self.ctx,
            &invocation_env,
        )
        .await
        {
            Outcome::Served(notifications) => supervisor::server::Decision::Served(notifications),
            Outcome::Compile(post) => supervisor::server::Decision::Compile(post),
        }
    }

    async fn compiled(
        self: &std::sync::Arc<Self>,
        mut pending: Self::Pending,
        success: bool,
        compile_time: std::time::Duration,
    ) {
        pending.compile_time = compile_time;
        let local_base = self.env_cache.local_base(&pending.executable).await;
        self.finish_and_observe(&pending, success, local_base.as_deref())
            .await;
    }

    async fn await_serve_map(self: &std::sync::Arc<Self>) {
        self.ctx.serve_map_ready.wait().await;
    }

    async fn rustc_host_target(
        self: &std::sync::Arc<Self>,
        executable: &std::ffi::OsStr,
    ) -> Result<String, String> {
        self.env_cache.rustc_host_target(executable).await
    }

    async fn observed(self: &std::sync::Arc<Self>, observation: supervisor::server::Observation) {
        let Ok(parsed) = classify_invocation(&observation.args) else {
            // The facade only sends invocations it parsed — one that
            // fails here is a wiring bug, not a compile.
            tracing::warn!("supervisor observation carried an unparseable invocation; dropped");
            return;
        };
        if is_compile_unit(&parsed) {
            self.resolution_done.complete();
        }
        if self.ctx.cache.is_off() {
            return;
        }
        let Some(local_base) = self.env_cache.local_base(&observation.executable).await else {
            return;
        };
        // The mark's key is the target decide computes: the unit's own
        // spelled `--target`, else this build's rustc host triple — the
        // key a dependent's `must_build_locally` checks under.
        let target = parsed
            .target
            .clone()
            .unwrap_or_else(|| local_base.host_target.clone());
        let Some(success) = observation.success else {
            log_nonfatal_result(
                "failed to record a locally built crate for this build",
                provenance::record_local_build(
                    self.ctx.policy_dir.as_deref(),
                    &target,
                    &parsed.crate_name,
                    &parsed.extra_filename,
                )
                .await,
            );
            return;
        };
        let mut parsed = parsed;
        resolve_native_target_cpu(&observation.executable, &mut parsed, &self.env_cache).await;
        let source = match observation.env.manifest_dir() {
            Ok(manifest_dir) => {
                detect_unit_source(&parsed, manifest_dir.as_deref(), &self.env_cache, &self.ctx)
                    .await
                    .map_err(|error| error.to_string())
            }
            Err(error) => Err(error),
        };
        match source {
            Ok(source) => {
                let class = parsed.unit_class(source, observation.env.primary_package, &target);
                // Only a publicly-missable unit counts: a git source or
                // extra codegen could never have been served remotely,
                // so its local compile is not a cache miss (stow#1006).
                record_unit_outcome(
                    &local_base.config,
                    &parsed,
                    &target,
                    &local_base.rustc_version,
                    UnitOutcome::Miss,
                    class.remote_missable(),
                )
                .await;
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    "failed to detect an observed unit's source; miss outcome skipped"
                );
            }
        }
        let post = PostCompile {
            executable: observation.executable,
            parsed: Some(parsed),
            env: observation.env,
            compile_time: observation.compile_time,
        };
        self.finish_and_observe(&post, success, Some(&local_base))
            .await;
    }
}

/// A duration in whole milliseconds, the unit the cache records compile time
/// in.
pub(crate) fn duration_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).expect("a compile's milliseconds fit in u64")
}

/// The rustc facade.
///
/// Parses the command line, asks the build's supervisor what to do with
/// the invocation, and either answers success or runs the real rustc.
/// When there is no supervisor — a plain `cargo build` through the
/// `RUSTC_WRAPPER` that `stow setup` writes — it decides in this process
/// instead. Returns the status this process owes cargo: a served unit's
/// success, or the real rustc's own.
#[tracing::instrument(name = "stow.wrapper.invoke", skip_all, fields(crate_name, cache_hit))]
async fn run_rustc_wrapper(
    mut command: WrapperCommandArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<std::process::ExitStatus> {
    // The supervising run's extra rustc arguments (workspace path remap and
    // any flags it selected) arrive appended to the argv so the user's own
    // rustflags sources — env or config — keep their cargo semantics.
    command
        .wrapped_args
        .extend(rustc_args::extra_args_from_env()?);
    // An endpoint that is set but unusable fails the build. A wrapper that
    // quietly compiled everything itself would leave a build that is
    // merely slow, which is the failure mode that hides.
    match supervisor::from_env().map_err(|error| stow_types::stow_error!("{error}"))? {
        Some((endpoint, token)) => delegate_to_supervisor(&endpoint, token, &command).await,
        None => run_rustc_standalone(&command, state_db).await,
    }
}

/// Ask the supervisor, then do what it says.
async fn delegate_to_supervisor(
    endpoint: &supervisor::Endpoint,
    token: String,
    command: &WrapperCommandArgs,
) -> stow_types::error::Result<std::process::ExitStatus> {
    let mut connection = supervisor::client::Connection::open(endpoint, token)
        .await
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    let decision = connection
        .plan(&command.executable, &command.wrapped_args)
        .await
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    tracing::debug!(
        served = matches!(decision, supervisor::client::Decision::Served(_)),
        "the build supervisor answered this invocation"
    );
    let ticket = match decision {
        supervisor::client::Decision::Served(notifications) => {
            connection
                .close()
                .await
                .map_err(|error| stow_types::stow_error!("{error}"))?;
            write_served_artifact_notifications(&notifications)?;
            return Ok(std::process::ExitStatus::default());
        }
        supervisor::client::Decision::Compile(ticket) => ticket,
    };
    let started = std::time::Instant::now();
    let status = run_passthrough_status(&command.executable, &[], &command.wrapped_args).await?;
    let compile_time = started.elapsed();
    connection
        .report(&ticket, status.success(), compile_time)
        .await
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    connection
        .close()
        .await
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    Ok(status)
}

/// Decide and execute in this process: the configuration that has no
/// supervisor to ask.
async fn run_rustc_standalone(
    command: &WrapperCommandArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<std::process::ExitStatus> {
    // Parse the argv once: the probe gate, the journal and the decision
    // all read the one `ParsedRustcArgs` (stow#608). A non-compile
    // invocation has nothing for the cache to decide and nothing to
    // record — the classifier's probe set covers `-vV`, `-V`,
    // `--version` and every `--print` query (none carry a
    // `--crate-name`), and cargo's `___` probe crate is no real unit:
    // run rustc and return its result rather than loading the wrapper
    // base and opening the state DB for an answer that is never used.
    let classified = classify_invocation(&command.wrapped_args);
    let parsed = match classify_or_log(classified, &command.wrapped_args) {
        Some(parsed) if is_compile_unit(&parsed) => parsed,
        _ => {
            return run_passthrough_status(&command.executable, &[], &command.wrapped_args).await;
        }
    };
    let ctx = match BuildContext::from_env() {
        Ok(ctx) => ctx,
        Err(error) => {
            // Malformed driver wiring must not cost a compile: the same
            // parse failure used to bypass the identity step per call.
            tracing::warn!(error = %error, "failed to read the build context, compiling the unit as-is");
            return run_passthrough_status(&command.executable, &[], &command.wrapped_args).await;
        }
    };
    // No supervising stow owns this build's misses: the wrappers
    // journal them, and the first invocation after the journaling cargo
    // exits kicks the detached drain (stow#317). Checked before the
    // decision so a fully-served build drains too. Misses exist only to
    // reach the network, so the local-only and off modes keep none.
    if !ctx.public_cache_disabled
        && let Some(out_dir) = parsed.out_dir.as_deref()
    {
        miss_journal::drain_finished_builds(out_dir);
        miss_journal::note_consumer_context(out_dir);
    }
    let env_cache = WrapperEnvCache::new(state_db.clone());
    match decide_rustc_invocation(
        &command.executable,
        parsed,
        &env_cache,
        &ctx,
        &supervisor::protocol::InvocationEnv::current(),
    )
    .await
    {
        Outcome::Served(notifications) => {
            write_served_artifact_notifications(&notifications)?;
            Ok(std::process::ExitStatus::default())
        }
        Outcome::Compile(mut post) => {
            let started = std::time::Instant::now();
            let status =
                run_passthrough_status(&command.executable, &[], &command.wrapped_args).await?;
            post.compile_time = started.elapsed();
            let local_base = env_cache.local_base(&command.executable).await;
            if let Ok(Some(build)) = finish_rustc_compile(
                &post,
                status.success(),
                local_base.as_deref(),
                &env_cache,
                &ctx,
            )
            .await
                && !ctx.public_cache_disabled
                && let (Some(parsed), Some(base)) = (post.parsed.as_ref(), local_base.as_deref())
            {
                miss_journal::record_observation(
                    &command.executable,
                    parsed,
                    &build,
                    &base.host_target,
                );
            }
            Ok(status)
        }
    }
}

/// Decide one rustc invocation: serve it from the cache, or say it has to
/// be compiled.
///
/// Runs in the supervisor when there is one, and in the wrapper process
/// itself under a plain `cargo build`. Nothing here exits the process or
/// runs rustc.
async fn decide_rustc_invocation(
    rustc: &OsString,
    mut parsed: rustc_args::ParsedRustcArgs,
    env_cache: &WrapperEnvCache,
    ctx: &BuildContext,
    invocation_env: &supervisor::protocol::InvocationEnv,
) -> Outcome {
    if ctx.cache.is_off() {
        // Every cache layer is off: nothing is looked up, recorded or stored, so
        // the unit compiles and owes no bookkeeping.
        return Outcome::Compile(Box::new(PostCompile::raw(rustc)));
    }
    let class = match classify_unit_invocation(rustc, &mut parsed, env_cache, ctx, invocation_env)
        .await
    {
        Ok(class) => class,
        Err(error) => {
            tracing::warn!(error = %error, crate_name = %parsed.crate_name, "failed to detect the unit's source, bypassing the cache");
            return compile(
                rustc,
                &parsed,
                parsed
                    .target
                    .as_deref()
                    .or(ctx.public_cache_target.as_deref()),
                ctx.policy_dir.as_deref(),
                invocation_env,
            )
            .await;
        }
    };

    if let UnitClass::Uncached(reason) = &class {
        tracing::debug!(
            crate_name = %parsed.crate_name,
            reason = ?reason,
            "unit is not a cache unit; compiling"
        );
        return compile(
            rustc,
            &parsed,
            parsed
                .target
                .as_deref()
                .or(ctx.public_cache_target.as_deref()),
            ctx.policy_dir.as_deref(),
            invocation_env,
        )
        .await;
    }

    let Some(prepared) = prepare_unit_environment(rustc, &parsed, &class, env_cache, ctx).await
    else {
        return compile(
            rustc,
            &parsed,
            parsed
                .target
                .as_deref()
                .or(ctx.public_cache_target.as_deref()),
            ctx.policy_dir.as_deref(),
            invocation_env,
        )
        .await;
    };
    match prepared {
        UnitPreparation::LocalOnly(prep) => {
            tracing::debug!(
                crate_name = %parsed.crate_name,
                "serving local lookups only for this invocation"
            );
            decide_local_only(rustc, &parsed, &class, prep, ctx, invocation_env).await
        }
        UnitPreparation::Public(env) => {
            // The policy wait only exists for a public lookup — a
            // local-only unit was diverted before it (stow#788).
            let exact_public_cache_allowed = exact_public_cache_allowed(&parsed, ctx).await;
            if must_build_locally(&parsed, &env.target, ctx.policy_dir.as_deref()) {
                record_unit_outcome(
                    &env.env_base.config,
                    &parsed,
                    &env.target,
                    &env.rustc_version,
                    UnitOutcome::LocalDependencyBuild,
                    true,
                )
                .await;
                return compile(
                    rustc,
                    &parsed,
                    Some(env.target.as_str()),
                    ctx.policy_dir.as_deref(),
                    invocation_env,
                )
                .await;
            }
            serve_or_compile(
                rustc,
                &parsed,
                &env,
                ctx,
                exact_public_cache_allowed,
                invocation_env,
            )
            .await
        }
    }
}

/// Classify one invocation (stow#1006): the invocation's own
/// `CARGO_MANIFEST_DIR` and `CARGO_PRIMARY_PACKAGE` facts, the
/// `native`-CPU resolution, and
/// the source detection the identity needs, folded into the unit's
/// `UnitClass`. An `Err` means the source could not be *read* — a harder
/// failure than an uncached classification, which is `Ok(Uncached(..))`.
async fn classify_unit_invocation(
    rustc: &OsString,
    parsed: &mut rustc_args::ParsedRustcArgs,
    env_cache: &WrapperEnvCache,
    ctx: &BuildContext,
    invocation_env: &supervisor::protocol::InvocationEnv,
) -> stow_types::error::Result<UnitClass> {
    // The invocation's own `CARGO_MANIFEST_DIR`, not this process's:
    // under a supervised build the supervisor's environment is the
    // driver's. A frame that cannot decode it is a wiring bug, not a
    // missing value.
    let manifest_dir = invocation_env
        .manifest_dir()
        .map_err(stow_types::error::Error::msg)?;
    parsed.build_script_out_dir = invocation_env
        .out_dir()
        .map_err(stow_types::error::Error::msg)?;
    // `target-cpu=native` resolves to the host's concrete CPU before
    // classification; a `native` that survives is unfoldable.
    resolve_native_target_cpu(rustc, parsed, env_cache).await;
    let source = detect_unit_source(parsed, manifest_dir.as_deref(), env_cache, ctx).await?;
    // The triple the unit is keyed under: its own `--target`, else the
    // compiling rustc's host.
    let target = match parsed.target.clone() {
        Some(target) => target,
        None => env_cache
            .rustc_host_target(rustc)
            .await
            .map_err(stow_types::error::Error::msg)?,
    };
    let class = parsed.unit_class(source, invocation_env.primary_package, &target);
    tracing::Span::current().record("crate_name", parsed.crate_name.as_str());
    tracing::debug!(
        crate_name = %parsed.crate_name,
        crate_types = ?parsed.crate_types,
        target = ?parsed.target,
        c_metadata = ?parsed.c_metadata,
        out_dir = ?parsed.out_dir,
        proc_macro = parsed.is_proc_macro(),
        output_rlib = ?parsed.output_rlib_path(),
        output_rmeta = ?parsed.output_rmeta_path(),
        class = ?class,
        "observed rustc wrapper invocation"
    );
    Ok(class)
}

/// Whether the cache policy permits an exact public lookup for this
/// unit — a missing allow marker while the enrichment still owes the
/// policy directory its commit is "undecided", not "denied": wait out
/// the commit — bounded — and take the marker once more before ruling
/// (stow#788). A completed or absent latch is the old path: deny on
/// absence at once.
async fn exact_public_cache_allowed(
    parsed: &rustc_args::ParsedRustcArgs,
    ctx: &BuildContext,
) -> bool {
    let mut policy_answer = cache_policy::public_cache_allowed(
        ctx.policy_dir.as_deref(),
        parsed,
        ctx.public_cache_target.as_deref(),
    );
    if policy_answer == Some(false) && !ctx.policy_ready.has_completed() {
        let _ = tokio::time::timeout(
            crate::facade::SERVE_MAP_WAIT_TIMEOUT,
            ctx.policy_ready.wait(),
        )
        .await;
        policy_answer = cache_policy::public_cache_allowed(
            ctx.policy_dir.as_deref(),
            parsed,
            ctx.public_cache_target.as_deref(),
        );
    }
    match policy_answer {
        Some(false) => {
            tracing::debug!(
                crate_name = %parsed.crate_name,
                "public exact rust cache disabled by stow cache policy for this invocation"
            );
            false
        }
        Some(true) | None => true,
    }
}

/// The serve-and-compile tail of the decision: the lookup chain, the one
/// outcome it comes to, and on anything but a serve the compile the build
/// records.
async fn serve_or_compile(
    rustc: &OsString,
    parsed: &rustc_args::ParsedRustcArgs,
    env: &WrapperEnvironment<'_>,
    ctx: &BuildContext,
    exact_public_cache_allowed: bool,
    invocation_env: &supervisor::protocol::InvocationEnv,
) -> Outcome {
    // The stages only note what they saw; the one outcome the invocation
    // contributes is recorded here, where the chain ends (stow#696).
    let mut tally = LookupTally::default();
    let (served, refused) =
        match lookup_chain(parsed, env, ctx, exact_public_cache_allowed, &mut tally).await {
            RemoteServe::Served(notifications) => (Some(notifications), false),
            RemoteServe::Refused => (None, true),
            RemoteServe::Bypass | RemoteServe::Miss => (None, false),
        };
    record_unit_outcome(
        &env.env_base.config,
        parsed,
        &env.target,
        &env.rustc_version,
        UnitOutcome::of(served.is_some(), &tally, refused),
        true,
    )
    .await;
    match served {
        Some(notifications) => Outcome::Served(notifications),
        None => {
            compile(
                rustc,
                parsed,
                Some(env.target.as_str()),
                ctx.policy_dir.as_deref(),
                invocation_env,
            )
            .await
        }
    }
}

/// The lookup chain for one invocation: local entries, then the remote
/// serves a keyed or semantic request could hit. A local serve ends it
/// the way a remote one does.
async fn lookup_chain(
    parsed: &rustc_args::ParsedRustcArgs,
    env: &WrapperEnvironment<'_>,
    ctx: &BuildContext,
    exact_public_cache_allowed: bool,
    tally: &mut LookupTally,
) -> RemoteServe {
    let request = FetchRequest {
        target: &env.target,
        rustc_version: &env.rustc_version,
        c_metadata: env.request_c_metadata.as_str(),
    };
    if let Some(notifications) =
        try_serve_local_cached_bundle(&env.env_base.config, parsed, &env.source, &request, tally)
            .await
    {
        return RemoteServe::Served(notifications);
    }
    if let Some(notifications) = try_serve_local_prefetched_graph_bundle(
        &env.env_base.config,
        parsed,
        &env.source,
        &env.target,
        &env.rustc_version,
        ctx,
        tally,
    )
    .await
    {
        return RemoteServe::Served(notifications);
    }
    if let Some(semantic_request) = env.semantic_request.as_ref()
        && let Some(notifications) = try_serve_local_semantic_cached_bundle(
            &env.env_base.config,
            parsed,
            &env.source,
            semantic_request,
            tally,
        )
        .await
    {
        return RemoteServe::Served(notifications);
    }
    try_remote_serves(
        env,
        parsed,
        &request,
        ctx,
        exact_public_cache_allowed,
        tally,
    )
    .await
}

/// Everything the cache path needs once every bypass-capable preparation
/// step has succeeded: the loaded config, the circuit state, the resolved
/// invocation identity, and the lease that keeps this rustc version's local
/// cache dir alive for the rest of the invocation.
struct WrapperEnvironment<'a> {
    /// The build-scoped base this invocation's identity was resolved over
    /// — carried so the lease and pooled state-db handle stay alive.
    env_base: std::sync::Arc<WrapperEnvBase>,
    /// The build-scoped memo the slice lookup and the circuit recorders
    /// share — a state this build loads once, refreshed by its own writes.
    env_cache: &'a WrapperEnvCache,
    /// The breaker guards the *network*: remote fetches stop while tripped,
    /// but a local entry still serves — a self-produced hit never touches
    /// the edge, so it keeps paying off through the very outage that tripped
    /// the breaker. Read once per build and kept in step by this build's
    /// own recordings (stow#347).
    circuit_tripped: bool,
    /// The unit's source, which decides the local cache layer its lookups
    /// and stores belong to.
    source: UnitSource,
    target: String,
    rustc_version: String,
    /// `target/rustc_version/c_metadata`, the negative-cache key.
    cache_key: String,
    /// The `c_metadata` to query with: the stable identity's when the
    /// invocation's own was rewritten, else the raw cargo one.
    request_c_metadata: String,
    /// Semantic fallback request, only built when
    /// `STOW_ENABLE_SEMANTIC_FALLBACK` opts in.
    semantic_request: Option<Box<fetch::SemanticFetchRequest>>,
    /// The host's glibc release, read once and passed to every lookup —
    /// no global. `None` on musl and non-Linux hosts, where the index
    /// row's `min_glibc` is not applicable.
    host_glibc: Option<stow_types::glibc::GlibcVersion>,
}

/// One decoded index slice plus the lookup table the per-invocation
/// exact match needs — the row scan of every call rebuilt into a map
/// once, when the driver first reads the slice.
#[derive(Debug)]
struct SliceIndex {
    /// The decoded slice rows.
    slice: index::IndexSlice,
    /// `c_metadata` → row position inside `slice.index.rows`.
    exact: std::collections::HashMap<String, usize>,
}

impl SliceIndex {
    fn new(slice: index::IndexSlice) -> Self {
        let exact = slice
            .index
            .rows
            .iter()
            .enumerate()
            .map(|(position, row)| (row.c_metadata.to_string(), position))
            .collect();
        Self { slice, exact }
    }

    /// The row at `c_metadata`, if the slice carries one.
    fn exact_row(&self, c_metadata: &str) -> Option<&stow_types::index::ArtifactIndexRow> {
        self.exact
            .get(c_metadata)
            .map(|position| &self.slice.index.rows[*position])
    }
}

/// The pieces of a wrapper environment that cannot change inside one
/// build — the loaded config (whose pooled state-db handle makes every
/// later query cheap), the compiling rustc's own probes, and the lease
/// keeping its local cache dir alive. The build's supervisor holds one
/// for the whole build instead of rediscovering it per rustc invocation.
#[derive(Debug)]
pub(crate) struct WrapperEnvBase {
    /// The rustc executable this base was prepared for — a build uses
    /// one, but a cached base must never answer for another.
    rustc: OsString,
    pub(crate) config: StowConfig,
    /// The compiling rustc's real `host:` triple — where a unit with no
    /// `--target` compiles, which is not the consumer target under a
    /// `--target` build (stow#317).
    pub(crate) host_target: String,
    pub(crate) rustc_version: String,
    _version_lease: artifact_cache::RustcVersionLease,
}

/// Build-scoped memo for the wrapper environment: a base computed once
/// per distinct rustc *spelling* rather than per invocation (stow#608).
/// The supervisor owns one for the whole build; a standalone invocation
/// builds a fresh one and gets exactly the one-shot behavior it always
/// had.
#[derive(Debug)]
pub(crate) struct WrapperEnvCache {
    /// The base the driver computed before cargo started. Any spelling
    /// that resolves to the same file adopts it — cargo reports
    /// `<sysroot>/bin/rustc` only in its rustup bypass, the bare `rustc`
    /// or a symlinked path otherwise, and all of them can name the one
    /// toolchain file the seed probed.
    seeded: std::sync::Mutex<Option<std::sync::Arc<WrapperEnvBase>>>,
    /// The remote path's bases (`StowConfig::load`), one memoized cell
    /// per executable spelling the facades report.
    env_bases: MemoizedBaseMap,
    /// The local path's bases (`StowConfig::load_local`), shared by
    /// `decide_local_only` and the post-compile finish.
    local_bases: MemoizedBaseMap,
    /// Each spelling's `rustc -vV` host triple — config-independent, so
    /// the in-flight marks a dependent's bookkeeping waits on never
    /// depend on an env base that can legitimately be absent (stow#618);
    /// the env bases' own `host_target` reads the same cells.
    host_targets: MemoizedHostMap,
    /// The `PATH` bare spellings resolve through, captured at
    /// construction so the cache reads the environment the build
    /// invoked the wrapper with.
    path: OsString,
    /// The verified index slices this build's lookups read — the driver's
    /// fetch can still be in flight when cargo starts, so a miss waits
    /// on `serve_map_ready` before its answer is memoized (stow#735),
    /// and a stale-but-readable slice memoizes with a `fetch_pending`
    /// flag that lets a later miss wait, refresh, and retry once
    /// (stow#797); each slice is decoded and keyed once per
    /// `(target, rustc)` instead of once per rustc invocation (stow#347).
    slices: MemoizedSliceMap,
    /// The circuit's tripped state, read once for the build and kept in
    /// step by the build's own recordings — plus the open broadcast an
    /// in-flight download abandons on (stow#977).
    circuit: circuit::BuildCircuit,
    /// The process's state-database handle, given to every config the
    /// base loaders read (stow#682).
    state_db: StateDb,
    /// The resolved commit of each cargo git checkout a git-sourced unit
    /// named — one `gix` read per checkout per build (stow#1006).
    git_commits: std::sync::Mutex<std::collections::HashMap<PathBuf, Option<String>>>,
    /// The concrete CPU each rustc's `--print target-cpus` reports as
    /// `native` — one probe per executable spelling per build.
    native_cpus: std::sync::Mutex<std::collections::HashMap<OsString, Option<String>>>,
}

/// One memoized env-base cell per executable spelling a facade reports:
/// each distinct spelling is probed at most once per build, whichever
/// loader answers (stow#608).
type MemoizedBaseMap = std::sync::Mutex<
    std::collections::HashMap<
        OsString,
        std::sync::Arc<tokio::sync::OnceCell<Option<std::sync::Arc<WrapperEnvBase>>>>,
    >,
>;

/// One memoized `rustc -vV` host answer per executable spelling: the
/// probe runs at most once per spelling per build, and its answer —
/// the triple or the failure — is what every consumer shares.
type MemoizedHostMap = std::sync::Mutex<
    std::collections::HashMap<
        OsString,
        std::sync::Arc<tokio::sync::OnceCell<Result<String, String>>>,
    >,
>;

/// The slice memoization key and cell shape: `(target, rustc)` to a
/// shared cell each wrapper task awaits.
type MemoizedSliceMap = std::sync::Mutex<
    std::collections::HashMap<
        (String, String),
        std::sync::Arc<tokio::sync::OnceCell<std::sync::Arc<SliceMemo>>>,
    >,
>;

/// One build's memoized answer for an index slice: the freshest decoded
/// slice the cache has handed it plus whether the build's own fetch
/// could still replace it — `slice_fetch_pending` decided once, when
/// the memo is filled, so no invocation pays a pointer read (stow#797).
/// A lookup that misses on a pending slice waits out `serve_map_ready`,
/// [`SliceMemo::refresh`] swaps in what the fetch landed — every later
/// invocation sees it — and the serves retry once; a hit never waits,
/// and a miss on a settled slice never does either.
#[derive(Debug)]
struct SliceMemo {
    inner: std::sync::Mutex<SliceMemoState>,
}

#[derive(Debug)]
struct SliceMemoState {
    /// The freshest decoded slice this build has read; `refresh`
    /// replaces it with what the settled fetch landed.
    slice: Option<std::sync::Arc<SliceIndex>>,
    /// `slice_fetch_pending` at fill: `true` while the build's fetch may
    /// still land rows this slice lacks. `false` once the memo was
    /// filled from the settled answer or a miss's `refresh` took it — a
    /// fetch that has already landed cannot be waited out twice.
    fetch_pending: bool,
}

impl SliceMemo {
    fn new(slice: Option<SliceIndex>, fetch_pending: bool) -> Self {
        Self {
            inner: std::sync::Mutex::new(SliceMemoState {
                slice: slice.map(std::sync::Arc::new),
                fetch_pending,
            }),
        }
    }

    /// The memo's answer as one pair under one lock — the slice and its
    /// pending flag can never describe different generations, which is
    /// what a racing `refresh` would otherwise allow (stow#797).
    fn read(&self) -> (Option<std::sync::Arc<SliceIndex>>, bool) {
        let state = self.inner.lock().expect("slice memo mutex");
        (state.slice.clone(), state.fetch_pending)
    }

    /// A pending miss's second answer: the fetch `serve_map_ready`
    /// gated has settled, so read the cache once more and make its
    /// answer the build's — every later lookup sees this slice. The
    /// flag clears with the swap: a settled fetch cannot be waited out
    /// again, and a sibling that already refreshed short-circuits the
    /// re-read.
    async fn refresh(
        &self,
        config: &StowConfig,
        target: &str,
        rustc_version: &str,
    ) -> stow_types::error::Result<Option<std::sync::Arc<SliceIndex>>> {
        {
            let state = self.inner.lock().expect("slice memo mutex");
            if !state.fetch_pending {
                return Ok(state.slice.clone());
            }
        }
        let slice = match index::cached_slice(config, target, rustc_version).await? {
            Some(slice) => Some(smol::unblock(move || SliceIndex::new(slice)).await),
            None => None,
        };
        let mut state = self.inner.lock().expect("slice memo mutex");
        state.slice = slice.map(std::sync::Arc::new);
        state.fetch_pending = false;
        Ok(state.slice.clone())
    }
}

/// Whether the facade's `spelling` and the seeded base's `target` rustc
/// are the same file — bare names resolved through `path`, the
/// wrapper's inherited `PATH`, with the platform's own rules for
/// separators and executable suffixes (`PATHEXT` on Windows), and the
/// two files compared by identity rather than by canonicalized string
/// (stow#608). Runs off the runtime workers: the `PATH` walk and the
/// comparison both stat the file system.
async fn resolves_to_same_file(spelling: &OsStr, target: &OsStr, path: &OsStr) -> bool {
    let spelling = spelling.to_os_string();
    let target = PathBuf::from(target);
    let path = path.to_os_string();
    tokio::task::spawn_blocking(move || {
        let cwd = std::env::current_dir().ok()?;
        let resolved = which::which_in(&spelling, Some(&path), &cwd).ok()?;
        same_file::is_same_file(&resolved, &target).ok()
    })
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

impl WrapperEnvCache {
    /// An empty memo reading this process's `PATH`, whose loaders hand
    /// `state_db` to every config they read.
    fn new(state_db: StateDb) -> Self {
        Self {
            seeded: std::sync::Mutex::new(None),
            env_bases: MemoizedBaseMap::default(),
            local_bases: MemoizedBaseMap::default(),
            host_targets: MemoizedHostMap::default(),
            path: std::env::var_os("PATH").unwrap_or_default(),
            slices: MemoizedSliceMap::default(),
            circuit: circuit::BuildCircuit::new(),
            state_db,
            git_commits: std::sync::Mutex::new(std::collections::HashMap::new()),
            native_cpus: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Seed the build's base: the base the driver computed before cargo
    /// started, adopted by every spelling that resolves to the same file
    /// (stow#608).
    fn seed(&self, base: std::sync::Arc<WrapperEnvBase>) {
        *self.seeded.lock().expect("seeded env base mutex") = Some(base);
    }

    /// The commit a cargo `git/checkouts/` checkout is reset to — read
    /// once per checkout per build (stow#1006). `None` when the checkout
    /// cannot be opened or its `HEAD` cannot be resolved: the unit's
    /// git identity fails and it compiles uncached.
    async fn git_commit(&self, checkout_root: &Path) -> Option<String> {
        if let Some(commit) = self
            .git_commits
            .lock()
            .expect("git commits mutex")
            .get(checkout_root)
        {
            return commit.clone();
        }
        let root = checkout_root.to_path_buf();
        let commit = match tokio::task::spawn_blocking(move || {
            let repository = gix::open(&root).map_err(|error| error.to_string())?;
            let commit = repository.head_id().map_err(|error| error.to_string())?;
            Ok::<_, String>(commit.to_string())
        })
        .await
        {
            Ok(Ok(commit)) => Some(commit),
            Ok(Err(error)) => {
                tracing::debug!(error = %error, "git checkout commit resolution failed");
                None
            }
            Err(error) => {
                tracing::debug!(error = %error, "git checkout commit task failed");
                None
            }
        };
        self.git_commits
            .lock()
            .expect("git commits mutex")
            .insert(checkout_root.to_path_buf(), commit.clone());
        commit
    }

    /// The concrete CPU `rustc --print target-cpus` reports for `native`
    /// — one probe per executable spelling per build. `None` when the
    /// probe or its parse fails: `target-cpu=native` then classifies as
    /// unfoldable and the unit compiles uncached.
    async fn native_cpu(&self, rustc: &OsStr) -> Option<String> {
        if let Some(cpu) = self
            .native_cpus
            .lock()
            .expect("native cpus mutex")
            .get(rustc)
        {
            return cpu.clone();
        }
        let cpu = Command::new(rustc)
            .arg("--print")
            .arg("target-cpus")
            .output()
            .await
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|stdout| {
                // The `native` line names the detected CPU:
                // `    native          - Select the CPU of the current
                //  host (currently apple-m2).`
                stdout.lines().find_map(|line| {
                    let rest = line.trim_start().strip_prefix("native")?;
                    rest.split("currently ")
                        .nth(1)?
                        .split(')')
                        .next()
                        .map(str::to_owned)
                })
            });
        self.native_cpus
            .lock()
            .expect("native cpus mutex")
            .insert(rustc.to_os_string(), cpu.clone());
        cpu
    }

    /// The base `load` prepares for the executable `rustc` as the
    /// facade spelled it — memoized per spelling, so no spelling is
    /// probed twice in one build. A spelling that resolves to the seeded
    /// base's file adopts it; one that resolves elsewhere is probed
    /// once. A `None` means every invocation bypasses — the wrapper
    /// exists to accelerate builds, never to break them.
    async fn base(
        &self,
        map: &MemoizedBaseMap,
        rustc: &OsStr,
        load: impl Fn(StateDb) -> stow_types::error::Result<StowConfig> + Send + Sync,
    ) -> Option<std::sync::Arc<WrapperEnvBase>> {
        let cell = map
            .lock()
            .expect("env base map mutex")
            .entry(rustc.to_os_string())
            .or_default()
            .clone();
        cell.get_or_init(|| async {
            let seed = self.seeded.lock().expect("seeded env base mutex").clone();
            if let Some(seed) = seed
                && resolves_to_same_file(rustc, &seed.rustc, &self.path).await
            {
                return Some(seed);
            }
            let config = match load(self.state_db.clone()) {
                Ok(config) => config,
                Err(error) => {
                    tracing::warn!(error = %error, "stow config unavailable, bypassing rust cache");
                    return None;
                }
            };
            load_wrapper_env_base(rustc, config, self.rustc_host_target(rustc))
                .await
                .map(std::sync::Arc::new)
        })
        .await
        .clone()
    }

    async fn env_base(&self, rustc: &OsStr) -> Option<std::sync::Arc<WrapperEnvBase>> {
        self.base(&self.env_bases, rustc, StowConfig::load).await
    }

    pub(crate) async fn local_base(&self, rustc: &OsStr) -> Option<std::sync::Arc<WrapperEnvBase>> {
        self.base(&self.local_bases, rustc, StowConfig::load_local)
            .await
    }

    /// The host triple `rustc` compiles target-less units for — one
    /// `rustc -vV` probe per executable spelling per build, independent
    /// of the config the env bases load: the marks dependents block on
    /// must not vanish because a base that can legitimately be absent
    /// did not load (stow#618). A spelling that resolves to the seeded
    /// base's file adopts its host answer rather than probing again.
    pub(crate) async fn rustc_host_target(&self, rustc: &OsStr) -> Result<String, String> {
        let cell = self
            .host_targets
            .lock()
            .expect("host target map mutex")
            .entry(rustc.to_os_string())
            .or_default()
            .clone();
        cell.get_or_init(|| async {
            let seed = self.seeded.lock().expect("seeded env base mutex").clone();
            if let Some(seed) = seed
                && resolves_to_same_file(rustc, &seed.rustc, &self.path).await
            {
                return Ok(seed.host_target.clone());
            }
            rustc_args::rustc_host_target(rustc).await
        })
        .await
        .clone()
    }

    /// The decoded index slice for `(target, rustc)` — read, decompressed
    /// and keyed by `c_metadata` once per build rather than per
    /// invocation. A missing slice may still be in flight — the driver's
    /// fetch runs beside cargo's build, not before it — so absence is
    /// memoized only after `serve_map_ready` says the build's fetch has
    /// settled (stow#735); a stale-but-readable slice memoizes at once
    /// but flagged `fetch_pending`, so a lookup that misses on it waits
    /// the fetch out and retries once against what it landed (stow#797).
    /// An error is not memoized — it keeps today's retry-and-warn
    /// semantics for a transient read failure.
    async fn slice(
        &self,
        config: &StowConfig,
        target: &str,
        rustc_version: &str,
        serve_map_ready: &crate::facade::ServeMapSignal,
    ) -> stow_types::error::Result<std::sync::Arc<SliceMemo>> {
        let key = (target.to_owned(), rustc_version.to_owned());
        let cell = self
            .slices
            .lock()
            .expect("slice cache mutex")
            .entry(key)
            .or_default()
            .clone();
        cell.get_or_try_init(|| async {
            // Pending is decided once, here, and read *before* the
            // slice: a fetch landing between the two answers then flags
            // a fresh memo pending — one redundant retry a miss pays —
            // where the other order can flag a stale memo settled,
            // which is the stow#797 miss this flag exists to catch.
            let fetch_pending = index::slice_fetch_pending(config, target, rustc_version).await?;
            if let Some(slice) = index::cached_slice(config, target, rustc_version).await? {
                let index = smol::unblock(move || SliceIndex::new(slice)).await;
                return Ok(std::sync::Arc::new(SliceMemo::new(
                    Some(index),
                    fetch_pending,
                )));
            }
            // The fetch can still be in flight when cargo starts: wait
            // out the build's `serve_map_ready`, then let the cache's
            // second answer be the memoized one — only then is absence
            // final for this build (stow#735). Its flag is settled: the
            // fetch this signal gated has already been waited out.
            let waited = std::time::Instant::now();
            serve_map_ready.wait().await;
            tracing::debug!(
                target = %target,
                rustc_version = %rustc_version,
                waited_ms = waited.elapsed().as_millis(),
                "index slice lookup waited for the build's fetch to settle"
            );
            let index = match index::cached_slice(config, target, rustc_version).await? {
                // The lookup table is one entry per row the slice
                // publishes, so it is built on a blocking thread like
                // the decode behind it (stow#624).
                Some(slice) => Some(smol::unblock(move || SliceIndex::new(slice)).await),
                None => None,
            };
            Ok::<_, stow_types::error::Error>(std::sync::Arc::new(SliceMemo::new(index, false)))
        })
        .await
        .cloned()
    }

    /// The circuit's tripped state for this build, read once — the
    /// per-invocation state-db query was the supervisor's busiest query,
    /// and the breaker guards transport that has already been decided
    /// once the driver laid the build's coverage down (stow#347).
    async fn circuit_tripped(&self, config: &StowConfig) -> stow_types::error::Result<bool> {
        self.circuit.tripped(config).await
    }

    /// Count a remote-cache failure against the circuit breaker, then
    /// refresh the memo so the rest of the build sees its own recording.
    async fn record_circuit_failure(&self, config: &StowConfig) {
        self.circuit.record_failure(config).await;
    }

    /// Count a remote-cache success toward resetting the circuit breaker;
    /// a success resets it outright, so the memo just clears.
    async fn record_circuit_success(&self, config: &StowConfig) {
        self.circuit.record_success(config).await;
    }
}

/// Load the config, probe the rustc and take the version lease — once
/// for the whole build. Every step can legitimately be unavailable, so
/// `None` means "run the real rustc". `host_target` is the build's
/// memoized per-spelling lookup — the source the supervisor's mark
/// bookkeeping answers from too, not a second probe.
async fn load_wrapper_env_base(
    rustc: &OsStr,
    config: StowConfig,
    host_target: impl std::future::Future<Output = Result<String, String>>,
) -> Option<WrapperEnvBase> {
    if let Err(error) = config.ensure_dirs().await {
        tracing::warn!(error = %error, "failed to prepare stow cache directories, bypassing rust cache");
        return None;
    }
    // The host triple and the version probe are independent answers from
    // the same rustc — await them together (stow#608).
    let (host_target, rustc_version) =
        tokio::join!(host_target, rustc_args::detect_rustc_version(rustc));
    let host_target = match host_target {
        Ok(target) => target,
        Err(error) => {
            tracing::warn!(error = %error, "failed to detect rustc host target, bypassing rust cache");
            return None;
        }
    };
    let rustc_version = match rustc_version {
        Ok(version) => version,
        Err(error) => {
            tracing::warn!(error = %error, "failed to detect rustc version, bypassing rust cache");
            return None;
        }
    };
    let version_lease = match prepare_local_cache(&config, &rustc_version).await {
        Ok(lease) => lease,
        Err(error) => {
            tracing::warn!(error = %error, "failed to prepare local stow artifact cache, bypassing rust cache");
            return None;
        }
    };
    Some(WrapperEnvBase {
        rustc: rustc.to_os_string(),
        config,
        host_target,
        rustc_version,
        _version_lease: version_lease,
    })
}

/// The wrapper environment base the supervisor seeds from, built on the
/// driver's own timeline before cargo spawns rather than inside the
/// first facade's `compiled` (stow#608). The facts are the ones the lazy
/// path computes — the driver's `config` (whose state-DB pool `prepare`
/// reuses, so no second `StowConfig`/pool), the host triple and release
/// from the shared `rustc -vV` of the build's rustc, and the build's
/// [`artifact_cache::RustcVersionLease`].
///
/// `build_rustc` is the one rustc the driver resolved for this build —
/// the configured `RUSTC`/`build.rustc` when set, else the toolchain's
/// `rustc` — so the shared `-vV` the driver spawned, the sysroot probe
/// and the link key all read the same executable. A failed rustc probe
/// fails the build (plain cargo fails there too); a cache-side failure —
/// `ensure_dirs`, the version lease — costs the base, never the build,
/// so `None` seeds nothing and the facades bypass (stow#608).
pub(crate) async fn supervisor_env_base(
    config: &StowConfig,
    shared_vv: &rustc_args::SharedRustcVv,
    build_rustc: &rustc_args::BuildRustc,
) -> stow_types::error::Result<Option<WrapperEnvBase>> {
    // The executable as the facades will report it — the configured
    // `RUSTC`/`build.rustc` spelling verbatim when one names the build's
    // compiler, else the toolchain's own `rustc` — so the seeded cell
    // matches the spelling the first facade carries.
    let (executable, vv) = tokio::join!(build_rustc.facade_spelling(), async {
        shared_vv.clone().await.map(|vv| (*vv).clone())
    },);
    let rustc = executable.map_err(|error| {
        stow_types::stow_error!("probe the rustc executable for the supervisor base: {error}")
    })?;
    let vv = vv.map_err(|error| {
        stow_types::stow_error!("probe rustc -vV for the supervisor base: {error}")
    })?;
    let host_target = rustc_args::vv_host(&vv).map_err(|error| {
        stow_types::stow_error!("probe rustc -vV for the supervisor base: {error}")
    })?;
    let rustc_version = rustc_args::vv_release(&vv).map_err(|error| {
        stow_types::stow_error!("probe rustc -vV for the supervisor base: {error}")
    })?;
    if let Err(error) = config.ensure_dirs().await {
        tracing::warn!(error = %error, "failed to prepare stow cache directories, seeding no env base");
        return Ok(None);
    }
    let version_lease = match prepare_local_cache(config, &rustc_version).await {
        Ok(lease) => lease,
        Err(error) => {
            tracing::warn!(error = %error, "failed to prepare the local cache, seeding no env base");
            return Ok(None);
        }
    };
    Ok(Some(WrapperEnvBase {
        rustc,
        config: config.clone(),
        host_target,
        rustc_version,
        _version_lease: version_lease,
    }))
}

/// What the remote-fetch phase decided for an invocation.
enum RemoteServe {
    /// An artifact was written into the target dir; the wrapper exits 0
    /// after writing the artifact notifications the serve computed
    /// (stow#633).
    Served(supervisor::protocol::ArtifactNotifications),
    /// No remote artifact applies; fall through to the miss path.
    Miss,
    /// The cache path failed or the artifact could not be used; run the
    /// real rustc immediately.
    Bypass,
    /// The index names an artifact whose `min_glibc` exceeds the host's:
    /// it exists, so it is not a miss and no build is enqueued — but it
    /// cannot be `dlopen`'d here, so the unit compiles locally, counted
    /// as a refusal rather than a miss.
    Refused,
}

/// Load the config and resolve everything the cache path needs for this
/// invocation. Every step can legitimately be unavailable — the wrapper
/// exists to accelerate builds, never to break them — so `None` means "run
/// the real rustc".
/// What the preparation concluded about a keyed invocation: the full
/// remote-capable environment when the unit's identity may travel, or
/// the local identity work when it may not. The match on this type is
/// the one place the public/local-only split is decided — a
/// `LocalOnly` variant carries exactly what `decide_local_only` needs,
/// so no caller recomputes the identity or re-reads the reach
/// (stow#1006).
enum UnitPreparation<'a> {
    /// Remote-capable: the identity folded to `Public`.
    Public(WrapperEnvironment<'a>),
    /// Local-only by construction — the public cache being off, a git source,
    /// extra codegen, or a `LocalOnly` dependency.
    LocalOnly(LocalOnlyPreparation),
}

/// The local path's resolved inputs: the local base, the unit's target,
/// and the stable identity (and reach) `build_stable_exact_identity`
/// already computed once.
struct LocalOnlyPreparation {
    env_base: std::sync::Arc<WrapperEnvBase>,
    target: String,
    identity: Option<(stow_types::public_cache::StableUnitIdentity, Reach)>,
}

/// The preparation half of the decision: which cache shape the unit's
/// identity takes, with the identity resolved exactly once whichever
/// branch it lands on. `None` bypasses the cache entirely.
async fn prepare_unit_environment<'a>(
    rustc: &OsString,
    parsed: &rustc_args::ParsedRustcArgs,
    class: &UnitClass,
    env_cache: &'a WrapperEnvCache,
    ctx: &'a BuildContext,
) -> Option<UnitPreparation<'a>> {
    let UnitClass::Keyed { source, .. } = class else {
        unreachable!("prepare_unit_environment only runs for a keyed unit");
    };
    if ctx.public_cache_disabled || class.source_local_only() {
        // An off public cache disables the *public* cache; a self-produced
        // local entry is not public. A git source or extra codegen is
        // local-only by construction — it can never be looked up
        // remotely or reported (stow#1006).
        return prepare_local_only(rustc, parsed, source, class.source_local_only(), env_cache)
            .await
            .map(UnitPreparation::LocalOnly);
    }
    let env_base = env_cache.env_base(rustc).await?;
    let target = parsed
        .target
        .clone()
        .unwrap_or_else(|| env_base.host_target.clone());
    let stable_exact_identity = match build_stable_exact_identity(
        &env_base.config,
        parsed,
        source,
        class.source_local_only(),
        &target,
        &env_base.rustc_version,
    )
    .await
    {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(error = %error, "failed to resolve local artifact identity, bypassing rust cache");
            return None;
        }
    };
    let reach = stable_exact_identity
        .as_ref()
        .map_or(Reach::Public, |(_, reach)| *reach);
    if reach == Reach::LocalOnly {
        // A crates.io unit over a local-only dependency is local-only
        // itself: local lookups only, no remote, no miss (stow#1006).
        let local_base = env_cache.local_base(rustc).await?;
        return Some(UnitPreparation::LocalOnly(LocalOnlyPreparation {
            env_base: local_base,
            target,
            identity: stable_exact_identity,
        }));
    }

    let circuit_tripped = match env_cache.circuit_tripped(&env_base.config).await {
        Ok(tripped) => tripped,
        Err(error) => {
            tracing::warn!(error = %error, "failed to read stow circuit state, bypassing rust cache");
            return None;
        }
    };
    if circuit_tripped {
        tracing::debug!("circuit breaker tripped, serving local lookups only");
    }
    let Some(c_metadata) = parsed.c_metadata.as_deref() else {
        tracing::warn!("cacheable rustc invocation is missing -C metadata, bypassing rust cache");
        return None;
    };
    let rustc_version = env_base.rustc_version.clone();
    let cache_key = format!("{target}/{rustc_version}/{c_metadata}");
    let request_c_metadata = stable_exact_identity
        .as_ref()
        .map_or(c_metadata, |(identity, _)| identity.c_metadata.as_str())
        .to_owned();
    let semantic_request = if ctx.semantic_fallback_enabled() {
        match build_semantic_fetch_request(
            &env_base.config,
            parsed,
            &target,
            &rustc_version,
            ctx.unit_nodes(),
        )
        .await
        {
            Ok(request) => request.map(Box::new),
            Err(error) => {
                tracing::warn!(error = %error, "failed to build semantic fetch request, continuing without semantic fallback");
                None
            }
        }
    } else {
        None
    };
    Some(UnitPreparation::Public(WrapperEnvironment {
        env_base,
        env_cache,
        circuit_tripped,
        source: source.clone(),
        target,
        rustc_version,
        cache_key,
        request_c_metadata,
        semantic_request,
        host_glibc: resolve::host_glibc(),
    }))
}

/// The local-only preparation: the local base plus the stable identity
/// — resolved against the same `materialized_outputs` table either
/// config reads — for the local serve and store the decision runs.
/// `source_local_only` is the identity's own reach input — a public-cache-off
/// detour passes `false`, since the recorded reach must reflect the
/// identity, not this build's cache policy.
async fn prepare_local_only(
    rustc: &OsString,
    parsed: &rustc_args::ParsedRustcArgs,
    source: &UnitSource,
    source_local_only: bool,
    env_cache: &WrapperEnvCache,
) -> Option<LocalOnlyPreparation> {
    let local_base = env_cache.local_base(rustc).await?;
    let target = parsed
        .target
        .clone()
        .unwrap_or_else(|| local_base.host_target.clone());
    let identity = match build_stable_exact_identity(
        &local_base.config,
        parsed,
        source,
        source_local_only,
        &target,
        &local_base.rustc_version,
    )
    .await
    {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(error = %error, "failed to resolve local artifact identity, bypassing local artifact cache");
            return None;
        }
    };
    Some(LocalOnlyPreparation {
        env_base: local_base,
        target,
        identity,
    })
}

/// Try the registry for this invocation: resolve the artifact identity
/// against the locally cached, verified index slice, then pull the bundle
/// blob it names straight from the OCI registry. The exact lookup runs
/// first, then the semantic fallback when it is enabled and the exact path
/// did not serve or disqualify the cache outright.
async fn try_remote_serves(
    env: &WrapperEnvironment<'_>,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    ctx: &BuildContext,
    exact_public_cache_allowed: bool,
    tally: &mut LookupTally,
) -> RemoteServe {
    if env.circuit_tripped {
        return RemoteServe::Miss;
    }
    // The slice read is cache-only: the driver's `ensure_slice` owns
    // freshness, and a registry round trip on every rustc invocation is
    // exactly the cost the local index exists to remove. Absence is a
    // miss — but only once `serve_map_ready` says the build's fetch has
    // settled (stow#735); a readable-but-stale slice whose fetch is
    // still in flight serves at once, flagged pending.
    let memo = match env
        .env_cache
        .slice(
            &env.env_base.config,
            &env.target,
            &env.rustc_version,
            &ctx.serve_map_ready,
        )
        .await
    {
        Ok(memo) => memo,
        Err(error) => {
            tracing::debug!(
                error = %error,
                target = %env.target,
                rustc_version = %env.rustc_version,
                "failed to read cached index slice, skipping registry serves"
            );
            return RemoteServe::Miss;
        }
    };
    let (slice, fetch_pending) = memo.read();
    let Some(slice) = slice else {
        tracing::debug!(
            target = %env.target,
            rustc_version = %env.rustc_version,
            "no cached index slice, skipping registry serves"
        );
        return RemoteServe::Miss;
    };
    let outcome = serves_against_slice(
        env,
        parsed,
        request,
        &slice,
        exact_public_cache_allowed,
        fetch_pending,
        tally,
    )
    .await;
    // A miss on a pending slice is provisional: the fetch the memo's
    // flag saw still in flight can carry the row this lookup lacked.
    // Wait it out, make its answer the build's memo — every later
    // invocation reads it — and retry once. A hit never waits, and a
    // miss on a settled slice never does either (stow#797).
    if !matches!(outcome, RemoteServe::Miss) || !fetch_pending {
        return outcome;
    }
    let waited = std::time::Instant::now();
    ctx.serve_map_ready.wait().await;
    tracing::debug!(
        target = %env.target,
        rustc_version = %env.rustc_version,
        waited_ms = waited.elapsed().as_millis(),
        "index slice miss waited for the build's fetch, retrying on its answer"
    );
    match memo
        .refresh(&env.env_base.config, &env.target, &env.rustc_version)
        .await
    {
        Ok(Some(slice)) => {
            serves_against_slice(
                env,
                parsed,
                request,
                &slice,
                exact_public_cache_allowed,
                false,
                tally,
            )
            .await
        }
        Ok(None) => RemoteServe::Miss,
        Err(error) => {
            tracing::debug!(
                error = %error,
                target = %env.target,
                rustc_version = %env.rustc_version,
                "failed to re-read the index slice after the fetch settled"
            );
            RemoteServe::Miss
        }
    }
}

/// The two registry serves over one decoded slice: exact first, then
/// the semantic fallback when it is enabled and the exact path did not
/// serve or disqualify the cache outright. `fetch_pending` marks the
/// slice provisional — a miss on it records no negative-cache entry,
/// the settled retry's does (stow#797).
async fn serves_against_slice(
    env: &WrapperEnvironment<'_>,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    slice: &SliceIndex,
    exact_public_cache_allowed: bool,
    fetch_pending: bool,
    tally: &mut LookupTally,
) -> RemoteServe {
    // A refusal does not end the lookup: the exact row may be unservable
    // while a differently-shaped semantic candidate still loads. Either
    // way, one refusal anywhere means no build should be enqueued —
    // `Refused` outranks `Miss` in the merge.
    let mut refused = false;
    if exact_public_cache_allowed {
        match try_remote_exact_serve(env, parsed, request, slice, fetch_pending, tally).await {
            RemoteServe::Miss => {}
            RemoteServe::Refused => refused = true,
            outcome => return outcome,
        }
    }
    if let Some(semantic_request) = env.semantic_request.as_ref() {
        return match try_remote_semantic_serve(env, parsed, semantic_request, &slice.slice, tally)
            .await
        {
            RemoteServe::Miss | RemoteServe::Refused if refused => RemoteServe::Refused,
            outcome => outcome,
        };
    }
    if refused {
        RemoteServe::Refused
    } else {
        RemoteServe::Miss
    }
}

/// Resolve the exact artifact identity against the index slice, stream its
/// bundle through the edge byte path, and serve it. `Miss` means the index
/// carries no such artifact (or the negative cache already says so);
/// `Bypass` means the artifact arrived but could not be used. While
/// `fetch_pending` marks the slice provisional the miss records nothing:
/// the negative cache asserts a settled absence (stow#797).
/// Download a bundle, abandoning the request the moment the build's
/// circuit opens rather than waiting out `request_timeout`: the edge is
/// already known unreachable (stow#977).
async fn download_unless_circuit_opens(
    env: &WrapperEnvironment<'_>,
    bundle_ref: &fetch::BundleRef<'_>,
) -> Result<fetch::ArtifactBundle, fetch::FetchError> {
    tokio::select! {
        outcome = fetch::download_bundle(&env.env_base.config, bundle_ref) => outcome,
        () = env.env_cache.circuit.opened(&env.env_base.config) => {
            Err(fetch::FetchError::CircuitOpen)
        }
    }
}

async fn try_remote_exact_serve(
    env: &WrapperEnvironment<'_>,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    slice: &SliceIndex,
    fetch_pending: bool,
    tally: &mut LookupTally,
) -> RemoteServe {
    let negative_cache_hit = match circuit::negative_cache_contains(
        &env.env_base.config,
        &env.cache_key,
    )
    .await
    {
        Ok(hit) => hit,
        Err(error) => {
            tracing::warn!(error = %error, cache_key = %env.cache_key, "failed to read stow negative cache");
            false
        }
    };
    if negative_cache_hit {
        tracing::debug!(cache_key = %env.cache_key, "negative cache hit, bypassing exact edge fetch");
        return RemoteServe::Miss;
    }
    let Some(row) = slice.exact_row(request.c_metadata) else {
        // While the slice's fetch is in flight this absence is
        // provisional — the fetched slice can carry the row — so the
        // negative-cache write waits for the settled retry (stow#797).
        if !fetch_pending {
            log_nonfatal_result(
                "failed to record stow negative cache entry",
                circuit::record_negative_cache(&env.env_base.config, &env.cache_key).await,
            );
        }
        return RemoteServe::Miss;
    };
    if !resolve::row_servable_on_host(row, env.host_glibc) {
        tracing::info!(
            crate_name = %parsed.crate_name,
            c_metadata = %row.c_metadata,
            min_glibc = ?row.min_glibc,
            host_glibc = ?env.host_glibc,
            "stow artifact needs a newer glibc than this host; compiling locally"
        );
        return RemoteServe::Refused;
    }
    let bundle_ref = fetch::BundleRef::from_index_row(&env.target, &env.rustc_version, row);
    let outcome = download_unless_circuit_opens(env, &bundle_ref).await;
    match outcome {
        Ok(bundle) => try_serve_downloaded_bundle(env, parsed, request, &bundle, tally)
            .await
            .map_or(RemoteServe::Bypass, RemoteServe::Served),
        // The circuit opened mid-download: the breaker is already
        // tripped, so nothing more is counted — the unit compiles.
        Err(fetch::FetchError::CircuitOpen) => {
            tally.failed = true;
            tracing::debug!(
                crate_name = %parsed.crate_name,
                target = %env.target,
                rustc_version = %env.rustc_version,
                bundle_digest = %row.bundle_digest,
                "stow exact bundle fetch abandoned: circuit opened mid-download"
            );
            RemoteServe::Miss
        }
        // The index is ahead of the catalog: the edge pruned the row (a
        // stale registry blob) after the slice was published. Remember the
        // miss locally until the next slice; the circuit stays closed.
        Err(fetch::FetchError::NotFound) => {
            if !fetch_pending {
                log_nonfatal_result(
                    "failed to record stow negative cache entry",
                    circuit::record_negative_cache(&env.env_base.config, &env.cache_key).await,
                );
            }
            RemoteServe::Miss
        }
        Err(error) => {
            env.env_cache
                .record_circuit_failure(&env.env_base.config)
                .await;
            tally.failed = true;
            tracing::debug!(
                crate_name = %parsed.crate_name,
                target = %env.target,
                rustc_version = %env.rustc_version,
                bundle_digest = %row.bundle_digest,
                error = %error,
                "stow exact bundle fetch failed, falling back to semantic or rustc"
            );
            RemoteServe::Miss
        }
    }
}

/// Resolve the semantic fallback request against the index slice, stream
/// the winning bundle through the edge byte path, and serve it.
async fn try_remote_semantic_serve(
    env: &WrapperEnvironment<'_>,
    parsed: &rustc_args::ParsedRustcArgs,
    semantic_request: &fetch::SemanticFetchRequest,
    slice: &index::IndexSlice,
    tally: &mut LookupTally,
) -> RemoteServe {
    // Published nodes are built without a consumer's cfgs, extra codegen or
    // `embed-metadata`, so none can answer a request that carries them; the
    // download-and-reject round trip is skipped (stow#1047).
    if !semantic_request.consumer.is_publishable_shape() {
        tracing::debug!(
            crate_name = %parsed.crate_name,
            "request carries cfgs, extra codegen or embed-metadata no published node has; compiling locally"
        );
        return RemoteServe::Miss;
    }
    let row = match resolve::find_semantic_artifact(
        &slice.index.rows,
        semantic_request,
        env.host_glibc,
    ) {
        Ok(row) => row,
        Err(error) => {
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                semantic_crate_name = %semantic_request.crate_name,
                "semantic index lookup failed, falling back to rustc"
            );
            return RemoteServe::Miss;
        }
    };
    let Some(row) = row else {
        // No servable candidate — but if an identity-matching row was
        // filtered out only for its glibc floor, this is a refusal, not
        // a miss: the artifact exists and no rebuild can serve it here.
        let refused = slice.index.rows.iter().any(|row| {
            resolve::semantic_identity_match(row, semantic_request)
                && !resolve::row_servable_on_host(row, env.host_glibc)
        });
        return if refused {
            tracing::info!(
                crate_name = %parsed.crate_name,
                semantic_crate_name = %semantic_request.crate_name,
                host_glibc = ?env.host_glibc,
                "stow artifact needs a newer glibc than this host; compiling locally"
            );
            RemoteServe::Refused
        } else {
            RemoteServe::Miss
        };
    };
    let bundle_ref = fetch::BundleRef::from_index_row(&env.target, &env.rustc_version, row);
    let outcome = download_unless_circuit_opens(env, &bundle_ref).await;
    match outcome {
        Ok(bundle) => {
            try_serve_semantic_downloaded_bundle(env, parsed, semantic_request, &bundle, tally)
                .await
                .map_or(RemoteServe::Bypass, RemoteServe::Served)
        }
        Err(fetch::FetchError::CircuitOpen) => {
            tally.failed = true;
            tracing::debug!(
                crate_name = %parsed.crate_name,
                semantic_crate_name = %semantic_request.crate_name,
                semantic_version = %semantic_request.version,
                target = %env.target,
                rustc_version = %env.rustc_version,
                bundle_digest = %row.bundle_digest,
                "stow semantic bundle fetch abandoned: circuit opened mid-download"
            );
            RemoteServe::Bypass
        }
        Err(fetch::FetchError::NotFound) => RemoteServe::Miss,
        Err(error) => {
            env.env_cache
                .record_circuit_failure(&env.env_base.config)
                .await;
            tally.failed = true;
            tracing::debug!(
                crate_name = %parsed.crate_name,
                semantic_crate_name = %semantic_request.crate_name,
                semantic_version = %semantic_request.version,
                target = %env.target,
                rustc_version = %env.rustc_version,
                bundle_digest = %row.bundle_digest,
                error = %error,
                "stow semantic bundle fetch failed, falling back to rustc"
            );
            RemoteServe::Bypass
        }
    }
}

/// What the lookup chain saw for one rustc invocation. The stages only
/// note it here; the outcome is counted once, when the chain has ended
/// (stow#696).
#[derive(Debug, Default)]
struct LookupTally {
    /// A stage that should have worked did not: an entry that could not
    /// be read, verified or materialized, or a fetch that failed.
    failed: bool,
}

/// The one outcome an invocation contributes to the build's counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitOutcome {
    Hit,
    Error,
    GlibcRefusal,
    Miss,
    /// The unit never reached a lookup: a dependency cargo hands it was
    /// compiled locally in this build, so its cached copy — compiled
    /// against CI's copy of that dependency — could not serve it
    /// (stow#734).
    LocalDependencyBuild,
}

impl UnitOutcome {
    /// Served wins: a unit that was served is a hit whatever failed on
    /// the way. Otherwise a failure outranks a refusal, and a refusal a
    /// miss.
    const fn of(served: bool, tally: &LookupTally, refused: bool) -> Self {
        if served {
            Self::Hit
        } else if tally.failed {
            Self::Error
        } else if refused {
            Self::GlibcRefusal
        } else {
            Self::Miss
        }
    }
}

/// Write the one outcome a rustc invocation contributes to the build's
/// counts. The lookup chain's stages report into a [`LookupTally`] and
/// only the end of the chain calls this, so an invocation whose lookup
/// visited several stages is still counted exactly once (stow#696). A
/// stats write never fails the invocation — it is not worth a missed
/// compile.
///
/// Only a registry package can be a miss: a workspace member is
/// first-party code the public cache never carries, so counting it
/// would report the project's own crates as failures and make a healthy
/// build look broken in the post-build summary. A glibc refusal is not
/// a miss either: the artifact exists, so counting it as one would
/// enqueue a build whose product cannot serve this host either. The
/// registry gate covers the local-dependency outcome the same way: a
/// non-registry unit could never have been served, so it joins no count.
async fn record_unit_outcome(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
    outcome: UnitOutcome,
    missable: bool,
) {
    match outcome {
        UnitOutcome::Hit => log_nonfatal_result(
            "failed to record rust cache hit stats",
            stats::record_hit(config, &parsed.crate_name).await,
        ),
        UnitOutcome::Error => log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
        ),
        UnitOutcome::GlibcRefusal => log_nonfatal_result(
            "failed to record rust glibc refusal stats",
            stats::record_glibc_refusal(config, &parsed.crate_name).await,
        ),
        UnitOutcome::Miss => {
            if missable {
                log_nonfatal_result(
                    "failed to record rust cache miss stats",
                    stats::record_miss(config, &parsed.crate_name).await,
                );
                tracing::debug!(
                    crate_name = %parsed.crate_name,
                    target,
                    rustc_version,
                    "stow cache miss, falling back to rustc"
                );
            }
        }
        UnitOutcome::LocalDependencyBuild => {
            if missable {
                log_nonfatal_result(
                    "failed to record rust local-dependency build stats",
                    stats::record_local_dependency_build(config, &parsed.crate_name).await,
                );
            }
        }
    }
}

/// Remember a profile divergence so the build summary can explain a build
/// that downloaded artifacts it was never able to use. Nothing else in the
/// wrapper's output survives to the parent process.
async fn record_profile_divergence(config: &StowConfig, mismatch: &BundleMismatch) {
    let BundleMismatch::Profile { cached, wanted } = mismatch else {
        return;
    };
    log_nonfatal_result(
        "failed to record the cache profile divergence",
        stats::record_profile_divergence(config, cached, wanted).await,
    );
}

/// Evict a local cache entry that can no longer be trusted to serve this
/// invocation, warning with the invocation identity when eviction itself
/// fails. `context` is the warning text for that failure.
async fn evict_cached_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    context: &'static str,
) {
    if let Err(error) = remove_cached_bundle(config, request).await {
        tracing::debug!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "{context}"
        );
    }
}

/// Wrapper path for invocations the remote cache does not cover — chiefly
/// release-profile crates, which `is_cacheable` restricts to the canonical
/// dev profile. A self-produced local entry covers dev *and* release builds,
/// so look the identity up locally before compiling; on a miss the
/// passthrough stores this build's outputs for the next worktree.
async fn decide_local_only(
    rustc: &OsString,
    parsed: &rustc_args::ParsedRustcArgs,
    class: &UnitClass,
    prep: LocalOnlyPreparation,
    ctx: &BuildContext,
    invocation_env: &supervisor::protocol::InvocationEnv,
) -> Outcome {
    let UnitClass::Keyed { source, .. } = class else {
        unreachable!("decide_local_only only runs for a keyed unit");
    };
    let target = prep.target;
    if must_build_locally(parsed, &target, ctx.policy_dir.as_deref()) {
        // A remote-missable unit records the build against stats; a
        // local-only-by-source one is never reported (stow#1006).
        record_unit_outcome(
            &prep.env_base.config,
            parsed,
            &target,
            &prep.env_base.rustc_version,
            UnitOutcome::LocalDependencyBuild,
            class.remote_missable(),
        )
        .await;
        return compile(
            rustc,
            parsed,
            Some(target.as_str()),
            ctx.policy_dir.as_deref(),
            invocation_env,
        )
        .await;
    }
    if let Some((identity, _reach)) = prep.identity {
        let request = FetchRequest {
            target: &target,
            rustc_version: &prep.env_base.rustc_version,
            c_metadata: identity.c_metadata.as_str(),
        };
        let mut tally = LookupTally::default();
        let served = try_serve_local_cached_bundle(
            &prep.env_base.config,
            parsed,
            source,
            &request,
            &mut tally,
        )
        .await;
        // A miss is never counted here: this path serves units the
        // public cache does not carry, so an unmet local lookup means
        // nothing was promised. A serve and a failed lookup are the
        // only outcomes.
        if served.is_some() || tally.failed {
            record_unit_outcome(
                &prep.env_base.config,
                parsed,
                &target,
                &prep.env_base.rustc_version,
                UnitOutcome::of(served.is_some(), &tally, false),
                false,
            )
            .await;
        }
        if let Some(notifications) = served {
            return Outcome::Served(notifications);
        }
    }
    compile(
        rustc,
        parsed,
        Some(target.as_str()),
        ctx.policy_dir.as_deref(),
        invocation_env,
    )
    .await
}

/// What `stow cc`'s executable argument asks for: an explicitly recorded
/// compiler execed verbatim, or the platform toolchain resolved per
/// invocation for the compilation's `TARGET`.
enum CcResolution {
    Explicit(OsString),
    Resolve(cc::CcKind),
}

/// Classify `stow cc`'s executable argument. The compiler shims emit the
/// resolve markers when no `STOW_REAL_CC`/`STOW_REAL_CXX` was recorded.
/// A bare `cl`/`clang-cl` also resolves rather than execing verbatim: the
/// `CMake` launcher role hands the compiler cmake picked as argv[1], and
/// `cl.exe` cannot run without the toolchain env `find_msvc_tools`
/// computes.
fn classify_cc_executable(executable: &OsString, target: Option<&str>) -> CcResolution {
    let msvc_target = target.map_or(cfg!(all(windows, target_env = "msvc")), |t| {
        t.contains("msvc")
    });
    let stem = || {
        Path::new(executable)
            .file_stem()
            .and_then(std::ffi::OsStr::to_str)
    };
    match executable.to_str() {
        Some(wrapper_shim::RESOLVE_CC) => CcResolution::Resolve(cc::CcKind::C),
        Some(wrapper_shim::RESOLVE_CXX) => CcResolution::Resolve(cc::CcKind::Cxx),
        _ if msvc_target
            && stem().is_some_and(|stem| {
                stem.eq_ignore_ascii_case("cl") || stem.contains("clang-cl")
            }) =>
        {
            CcResolution::Resolve(cc::CcKind::C)
        }
        _ => CcResolution::Explicit(executable.clone()),
    }
}

/// The compiler a `stow cc` invocation execs — see
/// [`classify_cc_executable`] and `cc::resolve_compiler`.
#[cfg(windows)]
fn resolve_cc_compiler(executable: &OsString) -> stow_types::error::Result<cc::ResolvedCompiler> {
    let target = std::env::var("TARGET").ok();
    match classify_cc_executable(executable, target.as_deref()) {
        CcResolution::Resolve(kind) => cc::resolve_compiler(kind, target.as_deref()),
        CcResolution::Explicit(program) => Ok(cc::ResolvedCompiler::explicit(program)),
    }
}

/// The POSIX form: infallible, because resolution is always the `cc`/`c++`
/// driver name.
#[cfg(not(windows))]
fn resolve_cc_compiler(executable: &OsString) -> cc::ResolvedCompiler {
    match classify_cc_executable(executable, std::env::var("TARGET").ok().as_deref()) {
        CcResolution::Resolve(kind) => cc::resolve_compiler(kind, None),
        CcResolution::Explicit(program) => cc::ResolvedCompiler::explicit(program),
    }
}

/// The C/C++ compiler facade. Returns the status this process owes its
/// caller: success for a served object, else the real compiler's own.
#[tracing::instrument(name = "stow.wrapper.cc_invoke", skip_all)]
async fn run_cc_wrapper(
    command: WrapperCommandArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<std::process::ExitStatus> {
    #[cfg(not(windows))]
    let compiler = resolve_cc_compiler(&command.executable);
    #[cfg(windows)]
    let compiler = resolve_cc_compiler(&command.executable)?;
    let compiler_args = &command.wrapped_args;
    let config = match StowConfig::load_local(state_db.clone()) {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(error = %error, "stow local config unavailable, bypassing C/C++ cache");
            return run_passthrough_status(&compiler.program, &compiler.env, compiler_args).await;
        }
    };
    if !config.cache.uses_cc_cache() {
        return run_passthrough_status(&compiler.program, &compiler.env, compiler_args).await;
    }
    if let Err(error) = config.ensure_dirs().await {
        tracing::warn!(error = %error, "failed to prepare stow cache directories, bypassing C/C++ cache");
        return run_passthrough_status(&compiler.program, &compiler.env, compiler_args).await;
    }

    let outcome = match cc::try_compile(&config, &compiler, compiler_args).await {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(error = %error, "stow C/C++ cache failed, bypassing cache");
            return run_passthrough_status(&compiler.program, &compiler.env, compiler_args).await;
        }
    };

    match outcome {
        cc::CcOutcome::Passthrough => {
            run_passthrough_status(&compiler.program, &compiler.env, compiler_args).await
        }
        cc::CcOutcome::Hit {
            cache_key,
            output_path,
        } => {
            log_nonfatal_result(
                "failed to record C/C++ cache hit stats",
                stats::record_hit(&config, &format!("cc:{cache_key}")).await,
            );
            tracing::info!(
                cache_key = %cache_key,
                output_path = %output_path.display(),
                "served C/C++ compilation from local stow cache"
            );
            Ok(std::process::ExitStatus::default())
        }
        cc::CcOutcome::Miss {
            cache_key,
            cache_path,
            output_path,
        } => {
            let compiler_status = Command::new(&compiler.program)
                .args(compiler_args)
                .envs(compiler.env.iter().cloned())
                .status()
                .await
                .wrap_err("failed to spawn wrapped C/C++ compiler")?;
            if !compiler_status.success() {
                log_nonfatal_result(
                    "failed to record C/C++ cache error stats",
                    stats::record_error(&config, &format!("cc:{cache_key}")).await,
                );
                return Ok(compiler_status);
            }

            if let Err(error) = cc::store_compiled_object(&config, &cache_path, &output_path).await
            {
                tracing::warn!(
                    error = %error,
                    cache_key = %cache_key,
                    output_path = %output_path.display(),
                    "failed to store C/C++ compilation in local stow cache"
                );
                log_nonfatal_result(
                    "failed to record C/C++ cache error stats",
                    stats::record_error(&config, &format!("cc:{cache_key}")).await,
                );
                return Ok(std::process::ExitStatus::default());
            }
            log_nonfatal_result(
                "failed to record C/C++ cache miss stats",
                stats::record_miss(&config, &format!("cc:{cache_key}")).await,
            );
            tracing::info!(
                cache_key = %cache_key,
                output_path = %output_path.display(),
                "stored C/C++ compilation in local stow cache"
            );
            Ok(std::process::ExitStatus::default())
        }
    }
}

async fn try_serve_local_cached_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    source: &UnitSource,
    request: &FetchRequest<'_>,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    let cached_bundle = match load_cached_bundle(config, request).await {
        Ok(bundle) => bundle,
        Err(error) => {
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to read local stow artifact cache entry"
            );
            tally.failed = true;
            return None;
        }
    };
    let cached_bundle = cached_bundle?;
    try_serve_loaded_local_cached_bundle(
        config,
        parsed,
        source,
        request,
        EntryOrigin::ExactKey,
        cached_bundle,
        tally,
    )
    .await
}

async fn try_serve_local_prefetched_graph_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    source: &UnitSource,
    target: &str,
    rustc_version: &str,
    ctx: &BuildContext,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    // `Ok(None)` is the non-registry case, which can match no published
    // bundle.
    let (crate_name, version) = registry_unit_identity(parsed)?;
    // The bundle's features are the unit's cargo feature set — the unit
    // graph's node — never the argv scan (stow#615).
    let table = ctx.unit_nodes()?;
    let expected_features_json =
        resolved_unit_features_json(table, &crate_name, &version, parsed, target, rustc_version)?;
    let expected_dependency_c_metadata_json =
        match resolve_dependency_c_metadata_json(config, parsed).await {
            Ok(DependencyCMetadataResolution::Resolved(resolved)) => resolved.c_metadata_json,
            Ok(DependencyCMetadataResolution::Unrecorded(..)) => return None,
            Err(error) => {
                tracing::debug!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    target,
                    rustc_version,
                    "failed to resolve prefetched graph dependency identities"
                );
                return None;
            }
        };
    // The driver indexed its prefetch payload by canonical PACKAGE name
    // before cargo started; a crate name's candidates are one map lookup.
    // The registry path's name, never `parsed.crate_name` — `[lib] name`
    // lets the two differ (stow#578).
    let candidate_c_metadatas = ctx
        .prefetch_candidates()
        .and_then(|candidates| candidates.get(&canonical_crate_name(&crate_name)))?;

    for c_metadata in candidate_c_metadatas {
        let request = FetchRequest {
            target,
            rustc_version,
            c_metadata: c_metadata.as_str(),
        };
        let cached_bundle = match load_cached_bundle(config, &request).await {
            Ok(Some(bundle)) => bundle,
            Ok(None) => continue,
            Err(error) => {
                tracing::debug!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    target,
                    rustc_version,
                    candidate_c_metadata = %c_metadata,
                    "failed to read prefetched graph bundle from local cache"
                );
                return None;
            }
        };
        if let Err(error) = validate_prefetched_graph_bundle(
            &crate_name,
            &version,
            &expected_features_json,
            &expected_dependency_c_metadata_json,
            &cached_bundle,
        ) {
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                target,
                rustc_version,
                candidate_c_metadata = %c_metadata,
                "skipping prefetched graph bundle that does not match current invocation"
            );
            continue;
        }
        if let Some(notifications) = try_serve_loaded_local_cached_bundle(
            config,
            parsed,
            source,
            &request,
            EntryOrigin::GraphCandidate,
            cached_bundle,
            tally,
        )
        .await
        {
            return Some(notifications);
        }
    }
    None
}

/// Where a cache entry came from, which decides what a semantic mismatch
/// means.
#[derive(Clone, Copy)]
enum EntryOrigin {
    /// Looked up under this invocation's own compile key. That key encodes
    /// the profile and the emit set, so a bundle stored there that does not
    /// describe this invocation is a poisoned row: evict it.
    ExactKey,
    /// One of several bundles the prefetch warmed for this crate. The rest
    /// are legitimate artifacts for a different compile variant — the check
    /// phase, another profile — so a divergence means "not this candidate",
    /// never "throw it away". Evicting them deleted bytes the same build had
    /// just downloaded, and counted each one as a cache error.
    GraphCandidate,
}

async fn try_serve_loaded_local_cached_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    source: &UnitSource,
    request: &FetchRequest<'_>,
    origin: EntryOrigin,
    cached_bundle: artifact_cache::CachedArtifactBundle,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    if !config.cache.serves(cached_bundle.provenance, source) {
        tracing::debug!(
            crate_name = %parsed.crate_name,
            provenance = cached_bundle.provenance.as_column(),
            "cache layer off for this entry, compiling the unit locally"
        );
        return None;
    }
    if let Some(mismatch) = bundle_mismatch(
        parsed,
        &cached_bundle.profile,
        &cached_bundle.emit,
        &cached_bundle.kind,
        &cached_bundle.crate_types,
        &cached_bundle.crate_version,
    ) {
        record_profile_divergence(config, &mismatch).await;
        match origin {
            EntryOrigin::GraphCandidate => {
                tracing::debug!(
                    error = %mismatch,
                    crate_name = %parsed.crate_name,
                    target = %request.target,
                    rustc_version = %request.rustc_version,
                    "prefetched candidate describes a different compile, trying the next one"
                );
                return None;
            }
            EntryOrigin::ExactKey => {}
        }
        tracing::debug!(
            error = %mismatch,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "local stow artifact cache entry semantic mismatch, evicting and falling back to rustc"
        );
        drop(cached_bundle);
        evict_cached_bundle(
            config,
            parsed,
            request,
            "failed to evict local stow artifact cache entry with semantic mismatch",
        )
        .await;
        tally.failed = true;
        return None;
    }

    if let Err(error) = verify::verify_cached_bundle_signature(config, &cached_bundle).await {
        tracing::debug!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "local stow artifact cache entry failed verification, evicting and falling back to rustc"
        );
        drop(cached_bundle);
        evict_cached_bundle(
            config,
            parsed,
            request,
            "failed to evict untrusted local stow artifact cache entry",
        )
        .await;
        tally.failed = true;
        return None;
    }

    let cached_bundle = match prune_materialized_aliases_for_cached_closure(
        config,
        parsed,
        request,
        cached_bundle,
    )
    .await
    {
        Ok(Some(bundle)) => bundle,
        // The binding no longer holds — a miss, not a path failure.
        Ok(None) => return None,
        Err(error) => {
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to materialize dependency closure aliases for local stow artifact cache entry"
            );
            tally.failed = true;
            return None;
        }
    };

    materialize_local_cached_bundle(config, parsed, request, cached_bundle, tally).await
}

/// Write a verified local cache entry's artifacts into the target dir.
/// `false` means the entry could not be materialized — it is evicted so the
/// next lookup does not trip over it again.
async fn materialize_local_cached_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: artifact_cache::CachedArtifactBundle,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    match inject::write_artifacts(
        parsed,
        &cached_bundle,
        request.target,
        inject::OutputDirWriters::StowOnly,
    )
    .await
    {
        Ok(()) => finish_local_serve(config, parsed, request, cached_bundle, tally).await,
        Err(error) => {
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to materialize local stow artifact cache entry, evicting and falling back to rustc"
            );
            drop(cached_bundle);
            evict_cached_bundle(
                config,
                parsed,
                request,
                "failed to evict broken local stow artifact cache entry",
            )
            .await;
            tally.failed = true;
            None
        }
    }
}

/// The bookkeeping that turns written artifacts into a served hit: record
/// what was materialized, compute the artifact notifications the unit
/// owes cargo — the process cargo spawned prints them at its `exit(0)`
/// (stow#633). The chain's end counts the hit itself (stow#696).
async fn finish_local_serve(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: artifact_cache::CachedArtifactBundle,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    if let Err(error) =
        record_materialized_bundle_outputs(config, parsed, &cached_bundle, request.target).await
    {
        tracing::debug!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "failed to record materialized local stow artifact outputs"
        );
        tally.failed = true;
        return None;
    }
    let notifications = match cached_rustc_artifact_notifications(parsed, request.target) {
        Ok(notifications) => notifications,
        Err(error) => {
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to compute rustc artifact notifications for local stow artifact cache entry"
            );
            drop(cached_bundle);
            evict_cached_bundle(
                config,
                parsed,
                request,
                "failed to evict local stow artifact cache entry missing rustc artifact notifications",
            )
            .await;
            tally.failed = true;
            return None;
        }
    };
    log_nonfatal_result(
        "failed to record local usage statistics",
        stats::record_served_bundle(
            config,
            cached_bundle.compile_millis,
            cached_bundle.size_bytes,
            stats::HitSource::Local,
        )
        .await,
    );
    tracing::info!(
        crate_name = %parsed.crate_name,
        target = %request.target,
        rustc_version = %request.rustc_version,
        "served rustc invocation from local stow artifact cache"
    );
    Some(notifications)
}

/// Materialize the dependency closure of the cached bundle a serve path is
/// about to hand rustc — and first verify every entry the serve would hand
/// out is still bound to the exact dependency instances it was compiled
/// against (stow#836).
///
/// `Ok(Some(bundle))` serves; `Ok(None)` is a binding that no longer
/// holds — this invocation compiles — with every stale local entry already
/// evicted so a later local compile can store a consistent replacement;
/// `Err` is a failure of the cache path itself.
pub(crate) async fn prune_materialized_aliases_for_cached_closure(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: artifact_cache::CachedArtifactBundle,
) -> stow_types::error::Result<Option<artifact_cache::CachedArtifactBundle>> {
    let Some(out_dir) = parsed.out_dir.as_ref() else {
        return Ok(Some(cached_bundle));
    };

    // The instances this build's --extern files carry — what the served
    // entry's binding is checked against. An unrecorded extern makes the
    // binding unverifiable: a miss, never a serve.
    let externs = match resolve_dependency_c_metadata_json(config, parsed).await? {
        DependencyCMetadataResolution::Resolved(resolved) => resolved.externs,
        DependencyCMetadataResolution::Unrecorded(extern_path) => {
            tracing::debug!(
                crate_name = %parsed.crate_name,
                extern_path,
                "not serving stow artifact cache entry: an extern has no recorded instance"
            );
            return Ok(None);
        }
    };

    let mut bundles_by_compile_key = BTreeMap::new();
    let mut pending = serde_json::from_str::<Vec<DependencyCompileKeyIdentity>>(
        &cached_bundle.dependency_compile_keys_json,
    )?;
    let mut visited = BTreeSet::new();
    while let Some(dependency) = pending.pop() {
        if !visited.insert(dependency.compile_key.clone()) {
            continue;
        }
        let dependency_bundle = match load_cached_bundle_by_compile_key(
            config,
            request.rustc_version,
            &dependency.compile_key,
        )
        .await?
        {
            Some(bundle) => bundle,
            None => {
                download_closure_dependency_bundle(
                    config,
                    request.target,
                    request.rustc_version,
                    &dependency,
                )
                .await?
            }
        };
        let nested = serde_json::from_str::<Vec<DependencyCompileKeyIdentity>>(
            &dependency_bundle.dependency_compile_keys_json,
        )?;
        pending.extend(nested);
        bundles_by_compile_key.insert(dependency.compile_key, dependency_bundle);
    }

    let binding =
        check_served_closure_binding(parsed, &cached_bundle, &externs, &bundles_by_compile_key)?;
    if binding.unbound || !binding.stale.is_empty() {
        evict_closure_entries(
            config,
            cached_bundle,
            bundles_by_compile_key,
            &binding.stale,
        )
        .await;
        return Ok(None);
    }

    let mut keep_original_file_names = BTreeSet::new();
    let mut closure_compile_keys = BTreeSet::new();
    let mut closure_crates = BTreeSet::from([canonical_crate_name(&cached_bundle.crate_name)]);
    let mut closure_visited = BTreeSet::new();
    collect_dependency_closure_file_names(
        &cached_bundle,
        &bundles_by_compile_key,
        &mut closure_visited,
        &mut keep_original_file_names,
        &mut closure_crates,
        &mut closure_compile_keys,
    )?;

    for compile_key in &closure_compile_keys {
        let dependency_bundle = bundles_by_compile_key.get(compile_key).ok_or_else(|| {
            stow_types::stow_error!(
                "missing prefetched cached bundle for compile key {compile_key}"
            )
        })?;
        inject::materialize_original_outputs(
            out_dir,
            dependency_bundle,
            inject::OutputDirWriters::StowOnly,
        )
        .await?;
        // The closure materialization wrote dep outputs without a row
        // before; a dependent compiled against these paths resolves its
        // externs — and their instances — through them (stow#836).
        artifact_cache::record_materialized_closure_outputs(config, out_dir, dependency_bundle)
            .await?;
    }

    Ok(Some(cached_bundle))
}

/// Evict the closure entries a binding check marked (stow#836). A loaded
/// bundle holds its entry's shared lease, so each marked bundle is dropped
/// before the removal takes the entry's exclusive lock; a removal that
/// fails — the entry is in use by another process — is retried by a later
/// invocation that finds the same binding.
async fn evict_closure_entries(
    config: &StowConfig,
    cached_bundle: artifact_cache::CachedArtifactBundle,
    mut bundles_by_compile_key: BTreeMap<String, artifact_cache::CachedArtifactBundle>,
    stale: &[String],
) {
    let mut served = Some(cached_bundle);
    for cache_key in stale {
        let bundle = if served
            .as_ref()
            .is_some_and(|bundle| bundle.cache_key == *cache_key)
        {
            served.take().expect("the served bundle is evicted once")
        } else if let Some(compile_key) = bundles_by_compile_key
            .iter()
            .find(|(_, bundle)| bundle.cache_key == *cache_key)
            .map(|(compile_key, _)| compile_key.clone())
        {
            bundles_by_compile_key
                .remove(&compile_key)
                .expect("the found key is present")
        } else {
            continue;
        };
        if let Err(error) = remove_loaded_bundle_entry(config, bundle).await {
            tracing::debug!(
                error = %error,
                cache_key = %cache_key,
                "failed to evict stale stow artifact cache entry"
            );
        }
    }
}

/// What comparing the served closure's bindings against the instances at
/// hand found (stow#836). Either field alone makes the invocation a miss.
struct ClosureBinding {
    /// Cache keys of local entries to evict: entries bound to dependency
    /// instances the cache no longer holds, and local dependency entries a
    /// remote entry sits on. Evicting the first lets a later local compile
    /// store a consistent replacement under the freed key; evicting the
    /// second lets the next build download the published instance, so the
    /// remote pair serves instead of missing for as long as the local
    /// entry lives.
    stale: Vec<String>,
    /// The serve is impossible: a remote entry sitting on a
    /// local-provenance dependency entry, or a served entry whose binding
    /// does not match this build's `--extern` files.
    unbound: bool,
}

/// The hard error a dep identity absent from the walked bundle map means —
/// the walk loads every key it will be asked for.
fn missing_closure_dep(dep: &DependencyCompileKeyIdentity) -> stow_types::error::Error {
    stow_types::stow_error!(
        "missing prefetched cached bundle for compile key {} ({})",
        dep.compile_key,
        dep.crate_name
    )
}

/// Verify every entry a serve would hand rustc — the served unit's entry
/// and each closure entry the walk loaded — is still bound to the exact
/// dependency instances it was compiled against (stow#836):
///
/// - a local entry's `dependency_instances_json` must equal, per dep, the
///   `instance()` of the dep's currently cached entry — a dep evicted and
///   re-stored from another build leaves the entry stale;
/// - a remote entry (binding `'[]'`) is bound to the published dep
///   instance by construction, so each dep's entry must be
///   remote-provenance — a local dep entry blocks the serve and is
///   evicted, since the published instance supersedes it: kept, it would
///   make the remote dependent miss on every build.
///
/// The served entry is additionally checked against this build's own
/// `--extern` files: the instances `resolve_dependency_c_metadata_json`
/// resolved are the only bytes this invocation can pair with it.
fn check_served_closure_binding(
    parsed: &rustc_args::ParsedRustcArgs,
    cached_bundle: &artifact_cache::CachedArtifactBundle,
    externs: &[artifact_cache::MaterializedDependency],
    bundles_by_compile_key: &BTreeMap<String, artifact_cache::CachedArtifactBundle>,
) -> stow_types::error::Result<ClosureBinding> {
    let mut stale = Vec::new();
    let mut unbound = false;
    for entry in std::iter::once(cached_bundle).chain(bundles_by_compile_key.values()) {
        let deps = serde_json::from_str::<Vec<DependencyCompileKeyIdentity>>(
            &entry.dependency_compile_keys_json,
        )?;
        match entry.provenance {
            artifact_cache::ArtifactProvenance::Local => {
                let bound = serde_json::from_str::<Vec<DependencyInstanceIdentity>>(
                    &entry.dependency_instances_json,
                )?;
                let bound_by_key: BTreeMap<&str, &str> = bound
                    .iter()
                    .map(|identity| (identity.compile_key.as_str(), identity.instance.as_str()))
                    .collect();
                // The binding names exactly the dep set the entry was
                // compiled against; a gap or an extra is a stale row.
                let mut entry_stale = bound_by_key.len() != deps.len();
                for dep in &deps {
                    if entry_stale {
                        break;
                    }
                    let dep_bundle = bundles_by_compile_key
                        .get(&dep.compile_key)
                        .ok_or_else(|| missing_closure_dep(dep))?;
                    let recorded = bound_by_key.get(dep.compile_key.as_str()).copied();
                    let current = dep_bundle.instance();
                    if recorded != Some(current.as_str()) {
                        tracing::debug!(
                            crate_name = %entry.crate_name,
                            dependency = %dep.crate_name,
                            bound_instance = recorded.unwrap_or("<unbound>"),
                            entry_instance = %current,
                            "cached entry is bound to a dependency instance the cache no longer holds; evicting"
                        );
                        entry_stale = true;
                    }
                }
                if entry_stale {
                    stale.push(entry.cache_key.clone());
                }
            }
            artifact_cache::ArtifactProvenance::Remote => {
                for dep in &deps {
                    let dep_bundle = bundles_by_compile_key
                        .get(&dep.compile_key)
                        .ok_or_else(|| missing_closure_dep(dep))?;
                    if dep_bundle.provenance != artifact_cache::ArtifactProvenance::Remote {
                        tracing::debug!(
                            crate_name = %entry.crate_name,
                            dependency = %dep.crate_name,
                            dep_instance = %dep_bundle.instance(),
                            dep_provenance = dep_bundle.provenance.as_column(),
                            "not serving remote cached entry: a dependency's cache entry is a local instance; evicting it"
                        );
                        stale.push(dep_bundle.cache_key.clone());
                        unbound = true;
                    }
                }
            }
        }
    }

    if !served_binding_matches_externs(parsed, cached_bundle, externs, bundles_by_compile_key)? {
        unbound = true;
    }

    Ok(ClosureBinding { stale, unbound })
}

/// Whether the served entry's binding matches the instances this build's
/// `--extern` files carry (stow#836) — the dep entries can be consistent
/// among themselves while the files cargo handed this invocation are
/// another instance. The dep a build extern resolved to is identified by
/// the dep entry's stable `c_metadata`: the crate name is not a join key —
/// a rename or a `[lib] name` rewrites it.
fn served_binding_matches_externs(
    parsed: &rustc_args::ParsedRustcArgs,
    cached_bundle: &artifact_cache::CachedArtifactBundle,
    externs: &[artifact_cache::MaterializedDependency],
    bundles_by_compile_key: &BTreeMap<String, artifact_cache::CachedArtifactBundle>,
) -> stow_types::error::Result<bool> {
    let mut matches = true;
    let served_deps = serde_json::from_str::<Vec<DependencyCompileKeyIdentity>>(
        &cached_bundle.dependency_compile_keys_json,
    )?;
    let mut served_dep_bundles = Vec::with_capacity(served_deps.len());
    for dep in &served_deps {
        served_dep_bundles.push(
            bundles_by_compile_key
                .get(&dep.compile_key)
                .ok_or_else(|| missing_closure_dep(dep))?,
        );
    }
    let served_bound: BTreeMap<String, String> = match cached_bundle.provenance {
        artifact_cache::ArtifactProvenance::Local => {
            serde_json::from_str::<Vec<DependencyInstanceIdentity>>(
                &cached_bundle.dependency_instances_json,
            )?
            .into_iter()
            .map(|identity| (identity.compile_key, identity.instance))
            .collect()
        }
        artifact_cache::ArtifactProvenance::Remote => BTreeMap::new(),
    };
    for extern_dep in externs {
        let Some(dep_bundle) = served_dep_bundles
            .iter()
            .find(|bundle| bundle.c_metadata == extern_dep.c_metadata)
        else {
            tracing::debug!(
                crate_name = %parsed.crate_name,
                dependency = %extern_dep.crate_name,
                c_metadata = %extern_dep.c_metadata,
                "not serving cached entry: an extern is not a direct dependency of the entry"
            );
            matches = false;
            continue;
        };
        match cached_bundle.provenance {
            artifact_cache::ArtifactProvenance::Local => {
                let bound_instance = served_bound
                    .get(dep_bundle.compile_key.as_str())
                    .map(String::as_str);
                if bound_instance != Some(extern_dep.instance.as_str()) {
                    tracing::debug!(
                        crate_name = %parsed.crate_name,
                        dependency = %extern_dep.crate_name,
                        bound_instance = bound_instance.unwrap_or("<unbound>"),
                        extern_instance = %extern_dep.instance,
                        "not serving cached entry: it is bound to a different dependency instance than the extern carries"
                    );
                    matches = false;
                }
            }
            artifact_cache::ArtifactProvenance::Remote => {
                let entry_instance = dep_bundle.instance();
                if dep_bundle.provenance != artifact_cache::ArtifactProvenance::Remote
                    || entry_instance != extern_dep.instance
                {
                    tracing::debug!(
                        crate_name = %parsed.crate_name,
                        dependency = %extern_dep.crate_name,
                        extern_instance = %extern_dep.instance,
                        entry_instance = %entry_instance,
                        dep_provenance = dep_bundle.provenance.as_column(),
                        "not serving remote cached entry: a direct dependency's instance is not the published one"
                    );
                    matches = false;
                }
            }
        }
    }

    Ok(matches)
}

async fn download_closure_dependency_bundle(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
    dependency: &DependencyCompileKeyIdentity,
) -> stow_types::error::Result<artifact_cache::CachedArtifactBundle> {
    let slice = index::cached_slice(config, target, rustc_version)
        .await?
        .ok_or_else(|| {
            stow_types::stow_error!(
                "no cached index slice for {target} {rustc_version} to resolve closure dependency {}",
                dependency.compile_key
            )
        })?;
    let row = slice
        .index
        .rows
        .iter()
        .find(|row| row.compile_key == dependency.compile_key)
        .ok_or_else(|| {
            stow_types::stow_error!(
                "index slice carries no row for closure dependency {} ({})",
                dependency.compile_key,
                dependency.crate_name
            )
        })?;
    let bundle_ref = fetch::BundleRef::from_index_row(target, rustc_version, row);
    let bundle = fetch::download_bundle(config, &bundle_ref)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "download closure dependency bundle {} ({}) failed: {error}",
                dependency.compile_key,
                dependency.crate_name
            )
        })?;
    let request = bundle_ref.fetch_request();
    let cached_bundle = cache_verified_downloaded_bundle(config, &request, &bundle).await?;
    if cached_bundle.compile_key != dependency.compile_key {
        return Err(stow_types::stow_error!(
            "downloaded closure dependency compile key mismatch for {}: expected {}, got {}",
            dependency.crate_name,
            dependency.compile_key,
            cached_bundle.compile_key
        ));
    }
    Ok(cached_bundle)
}

async fn cache_verified_downloaded_bundle(
    config: &StowConfig,
    request: &FetchRequest<'_>,
    bundle: &fetch::ArtifactBundle,
) -> stow_types::error::Result<artifact_cache::CachedArtifactBundle> {
    verify::verify_bundle_signature(config, bundle).await?;
    verify::store_downloaded_bundle_with_trust_marker(config, request, bundle).await
}

fn collect_dependency_closure_file_names(
    bundle: &artifact_cache::CachedArtifactBundle,
    bundles_by_compile_key: &BTreeMap<String, artifact_cache::CachedArtifactBundle>,
    visited: &mut BTreeSet<String>,
    keep_original_file_names: &mut BTreeSet<String>,
    closure_crates: &mut BTreeSet<String>,
    closure_compile_keys: &mut BTreeSet<String>,
) -> stow_types::error::Result<()> {
    let dependencies = serde_json::from_str::<Vec<DependencyCompileKeyIdentity>>(
        &bundle.dependency_compile_keys_json,
    )?;
    for dependency in dependencies {
        if !visited.insert(dependency.compile_key.clone()) {
            continue;
        }
        closure_compile_keys.insert(dependency.compile_key.clone());
        let dependency_bundle = bundles_by_compile_key
            .get(&dependency.compile_key)
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "missing prefetched cached bundle for compile key {} ({})",
                    dependency.compile_key,
                    dependency.crate_name
                )
            })?;
        closure_crates.insert(canonical_crate_name(&dependency_bundle.crate_name));
        for output in &dependency_bundle.outputs {
            keep_original_file_names.insert(output.file_name.clone());
        }
        collect_dependency_closure_file_names(
            dependency_bundle,
            bundles_by_compile_key,
            visited,
            keep_original_file_names,
            closure_crates,
            closure_compile_keys,
        )?;
    }
    Ok(())
}

/// The name a downloaded bundle's `crate_name` must match: the package
/// name the invocation's registry source path carries. A bundle's
/// `crate_name` is the package, while `parsed.crate_name` is the lib
/// target `[lib] name` may rename (stow#578) — `None` for an invocation
/// with no registry identity, which has nothing a published bundle can
/// legitimately serve.
fn expected_bundle_crate_name(parsed: &rustc_args::ParsedRustcArgs) -> Option<String> {
    registry_unit_identity(parsed).map(|(name, _version)| name)
}

/// The `(package name, version)` an invocation's registry source path
/// carries — the package identity, where `parsed.crate_name` is the lib
/// target `[lib] name` may rename (stow#578). `None` for an invocation
/// with no registry identity, which no published artifact can serve.
///
/// The serve paths calling this return `bool` — no error channel — so a
/// probe error is logged and lands on the same miss as a mismatch.
fn registry_unit_identity(parsed: &rustc_args::ParsedRustcArgs) -> Option<(String, String)> {
    match shared_detect_registry_crate_version(parsed) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                "registry identity probe failed; the invocation cannot match a published artifact"
            );
            None
        }
    }
}

fn validate_prefetched_graph_bundle(
    crate_name: &str,
    expected_version: &str,
    expected_features_json: &str,
    expected_dependency_c_metadata_json: &str,
    cached_bundle: &artifact_cache::CachedArtifactBundle,
) -> stow_types::error::Result<()> {
    // `crate_name` is the package name the invocation's registry path
    // carries — what a bundle's `crate_name` records — never the lib
    // target's name `[lib] name` may have changed (stow#578).
    if canonical_crate_name(&cached_bundle.crate_name) != canonical_crate_name(crate_name) {
        return Err(stow_types::stow_error!(
            "prefetched graph bundle crate name mismatch"
        ));
    }
    if cached_bundle.crate_version != expected_version {
        return Err(stow_types::stow_error!(
            "prefetched graph bundle crate version mismatch"
        ));
    }
    if cached_bundle.features_json != expected_features_json {
        return Err(stow_types::stow_error!(
            "prefetched graph bundle features mismatch"
        ));
    }
    if cached_bundle.dependency_c_metadata_json != expected_dependency_c_metadata_json {
        return Err(stow_types::stow_error!(
            "prefetched graph bundle dependency identities mismatch"
        ));
    }
    Ok(())
}

async fn try_serve_downloaded_bundle(
    env: &WrapperEnvironment<'_>,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    bundle: &fetch::ArtifactBundle,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    let config = &env.env_base.config;
    // The bundle's `crate_name` is the package name — compare against the
    // registry path's name, not `parsed.crate_name`, which `[lib] name`
    // may have renamed (stow#578).
    let package_name = expected_bundle_crate_name(parsed)?;
    if let Err(error) = fetch::validate_bundle_identity(
        bundle,
        &package_name,
        request.c_metadata,
        request.target,
        request.rustc_version,
    ) {
        tracing::debug!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "downloaded stow bundle identity mismatch"
        );
        // A miss, not an outage: the artifact arrived intact, it just does
        // not describe this invocation. Counting identity divergence toward
        // the circuit breaker meant a handful of legitimately-unmatched units
        // (the proc-macro host graph, typically) tripped it five invocations
        // in, and every remaining crate in the build then bypassed the cache
        // for the full reset window. Only transport and materialization
        // failures say the cache path itself is unhealthy.
        return None;
    }
    if let Some(mismatch) = bundle_mismatch(
        parsed,
        &bundle.manifest.config.profile,
        &bundle.manifest.config.emit,
        &bundle.manifest.config.kind,
        &bundle.manifest.config.crate_types,
        &bundle.manifest.config.crate_version.to_string(),
    ) {
        record_profile_divergence(config, &mismatch).await;
        tracing::debug!(
            error = %mismatch,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "downloaded stow bundle semantic mismatch"
        );
        // A miss, not an outage: the artifact arrived intact, it just does
        // not describe this invocation. Counting identity divergence toward
        // the circuit breaker meant a handful of legitimately-unmatched units
        // (the proc-macro host graph, typically) tripped it five invocations
        // in, and every remaining crate in the build then bypassed the cache
        // for the full reset window. Only transport and materialization
        // failures say the cache path itself is unhealthy.
        return None;
    }
    try_serve_verified_downloaded_bundle(env, parsed, request, bundle, tally).await
}

async fn try_serve_local_semantic_cached_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    source: &UnitSource,
    semantic_request: &fetch::SemanticFetchRequest,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    let cached_bundle = match load_semantic_cached_bundle(config, semantic_request).await {
        Ok(bundle) => bundle,
        Err(error) => {
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                semantic_crate_name = %semantic_request.crate_name,
                semantic_version = %semantic_request.version,
                target = %semantic_request.target,
                rustc_version = %semantic_request.rustc_version,
                "failed to read local semantic stow artifact cache entry"
            );
            tally.failed = true;
            return None;
        }
    };
    let cached_bundle = cached_bundle?;
    if !config.cache.serves(cached_bundle.provenance, source) {
        return None;
    }
    if let Some(mismatch) = bundle_mismatch(
        parsed,
        &cached_bundle.profile,
        &cached_bundle.emit,
        &cached_bundle.kind,
        &cached_bundle.crate_types,
        &cached_bundle.crate_version,
    ) {
        record_profile_divergence(config, &mismatch).await;
        tracing::debug!(
            error = %mismatch,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "local semantic stow artifact cache entry semantic mismatch"
        );
        return None;
    }
    if let Err(error) = verify::verify_cached_bundle_signature(config, &cached_bundle).await {
        tracing::debug!(
            error = %error,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "local semantic stow artifact cache entry failed verification"
        );
        tally.failed = true;
        return None;
    }
    let cached_c_metadata = cached_bundle.c_metadata.clone();
    let request = FetchRequest {
        target: &semantic_request.target,
        rustc_version: &semantic_request.rustc_version,
        c_metadata: &cached_c_metadata,
    };
    let cached_bundle = match prune_materialized_aliases_for_cached_closure(
        config,
        parsed,
        &request,
        cached_bundle,
    )
    .await
    {
        Ok(Some(bundle)) => bundle,
        // The binding no longer holds — a miss, not a path failure.
        Ok(None) => return None,
        Err(error) => {
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                semantic_crate_name = %semantic_request.crate_name,
                semantic_version = %semantic_request.version,
                target = %semantic_request.target,
                rustc_version = %semantic_request.rustc_version,
                cached_c_metadata = %request.c_metadata,
                "failed to materialize dependency closure aliases for local semantic stow artifact cache entry"
            );
            tally.failed = true;
            return None;
        }
    };

    materialize_semantic_cached_bundle(config, parsed, semantic_request, cached_bundle, tally).await
}

/// Write a verified semantic cache entry's artifacts into the target dir and
/// finish the bookkeeping that makes it a served hit. Unlike the exact-local
/// path the entry is not evicted on failure: the semantic lookup is
/// best-effort, so a broken entry just misses again next time.
async fn materialize_semantic_cached_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    semantic_request: &fetch::SemanticFetchRequest,
    cached_bundle: artifact_cache::CachedArtifactBundle,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    if let Err(error) = inject::write_artifacts(
        parsed,
        &cached_bundle,
        &semantic_request.target,
        inject::OutputDirWriters::StowOnly,
    )
    .await
    {
        tracing::debug!(
            error = %error,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "failed to materialize local semantic stow artifact cache entry"
        );
        tally.failed = true;
        return None;
    }
    if let Err(error) =
        record_materialized_bundle_outputs(config, parsed, &cached_bundle, &semantic_request.target)
            .await
    {
        tracing::debug!(
            error = %error,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "failed to record materialized local semantic stow artifact outputs"
        );
        tally.failed = true;
        return None;
    }
    let notifications = match cached_rustc_artifact_notifications(parsed, &semantic_request.target)
    {
        Ok(notifications) => notifications,
        Err(error) => {
            tracing::debug!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    semantic_crate_name = %semantic_request.crate_name,
                semantic_version = %semantic_request.version,
                target = %semantic_request.target,
                rustc_version = %semantic_request.rustc_version,
                cached_c_metadata = %cached_bundle.c_metadata,
                "failed to compute rustc artifact notifications for local semantic stow artifact cache entry"
            );
            tally.failed = true;
            return None;
        }
    };
    log_nonfatal_result(
        "failed to record local usage statistics",
        stats::record_served_bundle(
            config,
            cached_bundle.compile_millis,
            cached_bundle.size_bytes,
            stats::HitSource::Local,
        )
        .await,
    );
    tracing::info!(
        crate_name = %parsed.crate_name,
        semantic_crate_name = %semantic_request.crate_name,
        semantic_version = %semantic_request.version,
        target = %semantic_request.target,
        rustc_version = %semantic_request.rustc_version,
        cached_c_metadata = %cached_bundle.c_metadata,
        "served rustc invocation from local semantic stow artifact cache"
    );
    Some(notifications)
}

async fn try_serve_semantic_downloaded_bundle(
    env: &WrapperEnvironment<'_>,
    parsed: &rustc_args::ParsedRustcArgs,
    semantic_request: &fetch::SemanticFetchRequest,
    bundle: &fetch::ArtifactBundle,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    if let Err(error) = fetch::validate_semantic_bundle_identity(bundle, semantic_request) {
        tracing::debug!(
            error = %error,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            "downloaded stow semantic bundle identity mismatch"
        );
        // A miss, not an outage: the artifact arrived intact, it just does
        // not describe this invocation. Counting identity divergence toward
        // the circuit breaker meant a handful of legitimately-unmatched units
        // (the proc-macro host graph, typically) tripped it five invocations
        // in, and every remaining crate in the build then bypassed the cache
        // for the full reset window. Only transport failures say the cache
        // path itself is unhealthy (stow#1044).
        return None;
    }

    let request = FetchRequest {
        target: bundle.manifest.config.target.as_str(),
        rustc_version: bundle.manifest.config.rustc_version.as_str(),
        c_metadata: bundle.manifest.config.c_metadata.as_str(),
    };
    try_serve_verified_downloaded_bundle(env, parsed, &request, bundle, tally).await
}

async fn try_serve_verified_downloaded_bundle(
    env: &WrapperEnvironment<'_>,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    bundle: &fetch::ArtifactBundle,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    let config = &env.env_base.config;
    let cached_bundle = match cache_verified_downloaded_bundle(config, request, bundle).await {
        Ok(cached_bundle) => cached_bundle,
        Err(error) => {
            // A local store or verification failure — the transport worked,
            // so the circuit counts nothing for it (stow#1044).
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to cache verified stow bundle"
            );
            tally.failed = true;
            return None;
        }
    };

    let cached_bundle =
        match prune_materialized_aliases_for_cached_closure(config, parsed, request, cached_bundle)
            .await
        {
            Ok(Some(bundle)) => bundle,
            // The binding no longer holds — a miss, not a path failure: the
            // freshly stored remote entry stays cached and the circuit
            // records nothing (stow#836).
            Ok(None) => return None,
            Err(error) => {
                tracing::debug!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    target = %request.target,
                    rustc_version = %request.rustc_version,
                    "failed to materialize dependency closure aliases for downloaded stow bundle"
                );
                evict_cached_bundle(
                config,
                parsed,
                request,
                "failed to evict downloaded stow bundle with incomplete dependency closure aliases",
            )
            .await;
                // A local materialization failure — the transport worked,
                // so the circuit counts nothing for it (stow#1044).
                tally.failed = true;
                return None;
            }
        };

    materialize_downloaded_bundle(env, parsed, request, cached_bundle, tally).await
}

/// Write a verified downloaded bundle's artifacts into the target dir.
/// `false` means the freshly cached entry could not be materialized — it is
/// evicted; a local failure like this never opens the circuit (stow#1044).
async fn materialize_downloaded_bundle(
    env: &WrapperEnvironment<'_>,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: artifact_cache::CachedArtifactBundle,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    let config = &env.env_base.config;
    match inject::write_artifacts(
        parsed,
        &cached_bundle,
        request.target,
        inject::OutputDirWriters::StowOnly,
    )
    .await
    {
        Ok(()) => finish_downloaded_serve(env, parsed, request, cached_bundle, tally).await,
        Err(error) => {
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to materialize verified stow bundle, evicting local cache entry"
            );
            drop(cached_bundle);
            evict_cached_bundle(
                config,
                parsed,
                request,
                "failed to evict verified-but-unusable stow cache entry",
            )
            .await;
            // A local materialization failure — the transport worked, so
            // the circuit counts nothing for it (stow#1044).
            tally.failed = true;
            None
        }
    }
}

/// The bookkeeping that turns a materialized downloaded bundle into a served
/// hit: record outputs, compute the artifact notifications the unit owes
/// cargo — the process cargo spawned prints them at its `exit(0)`
/// (stow#633) — then count the circuit success. The chain's end counts the
/// hit itself (stow#696).
async fn finish_downloaded_serve(
    env: &WrapperEnvironment<'_>,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: artifact_cache::CachedArtifactBundle,
    tally: &mut LookupTally,
) -> Option<ArtifactNotifications> {
    let config = &env.env_base.config;
    if let Err(error) =
        record_materialized_bundle_outputs(config, parsed, &cached_bundle, request.target).await
    {
        tracing::debug!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "failed to record materialized downloaded stow artifact outputs"
        );
        drop(cached_bundle);
        evict_cached_bundle(
            config,
            parsed,
            request,
            "failed to evict downloaded stow bundle missing materialized output metadata",
        )
        .await;
        // A local bookkeeping failure — the transport worked, so the
        // circuit counts nothing for it (stow#1044).
        tally.failed = true;
        return None;
    }
    let notifications = match cached_rustc_artifact_notifications(parsed, request.target) {
        Ok(notifications) => notifications,
        Err(error) => {
            tracing::debug!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to compute rustc artifact notifications for downloaded stow bundle"
            );
            drop(cached_bundle);
            evict_cached_bundle(
                config,
                parsed,
                request,
                "failed to evict downloaded stow bundle missing rustc artifact notifications",
            )
            .await;
            // A local bookkeeping failure — the transport worked, so the
            // circuit counts nothing for it (stow#1044).
            tally.failed = true;
            return None;
        }
    };
    env.env_cache.record_circuit_success(config).await;
    log_nonfatal_result(
        "failed to record local usage statistics",
        stats::record_served_bundle(
            config,
            cached_bundle.compile_millis,
            cached_bundle.size_bytes,
            stats::HitSource::Downloaded,
        )
        .await,
    );
    tracing::info!(
        crate_name = %parsed.crate_name,
        target = %request.target,
        rustc_version = %request.rustc_version,
        "served rustc invocation from downloaded stow artifact cache"
    );
    Some(notifications)
}

async fn build_semantic_fetch_request(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
    unit_nodes: Option<&unit_node::UnitNodeTable>,
) -> stow_types::error::Result<Option<fetch::SemanticFetchRequest>> {
    let Some((crate_name, version)) = shared_detect_registry_crate_version(parsed)? else {
        return Ok(None);
    };
    // The request's feature set is the unit's cargo feature set — the
    // build's own unit graph's node — never the argv `--cfg feature="…"`
    // scan, which a build script's `cargo:rustc-cfg=feature="…"` lines
    // inflate. No table (the analysis has not landed, or a standalone
    // wrapper with no graph) means no semantic request; a table that
    // does not hold the unit warns and compiles (stow#615).
    let Some(table) = unit_nodes else {
        return Ok(None);
    };
    let Some(features_json) =
        resolved_unit_features_json(table, &crate_name, &version, parsed, target, rustc_version)
    else {
        return Ok(None);
    };
    let dependency_c_metadata_json =
        match resolve_dependency_c_metadata_json(config, parsed).await? {
            DependencyCMetadataResolution::Resolved(resolved) => resolved.c_metadata_json,
            DependencyCMetadataResolution::Unrecorded(..) => return Ok(None),
        };
    let emit = parsed.emit.iter().cloned().collect::<Vec<_>>();
    let profile = semantic_request_profile(parsed)?;
    let kind = parsed_artifact_kind(parsed)?;
    let crate_types = parsed_crate_types(parsed)?;
    let build_script = stow_types::upload_plan::BuildScriptInputs::of_out_dir(
        &parsed.crate_name,
        parsed.build_script_out_dir.as_deref(),
    )?;
    let consumer = stow_types::upload_plan::ConsumerInputs::of(parsed, &build_script, target);
    tracing::debug!(
        crate_name = %crate_name,
        version = %version,
        features_json = %features_json,
        dependency_c_metadata_json = %dependency_c_metadata_json,
        target = %target,
        rustc_version = %rustc_version,
        profile = ?profile,
        emit = ?emit,
        kind = %kind.as_str(),
        crate_types = ?crate_types,
        "constructed semantic fetch request"
    );
    Ok(Some(fetch::SemanticFetchRequest {
        crate_name,
        version,
        features_json,
        dependency_c_metadata_json,
        target: target.to_owned(),
        rustc_version: rustc_version.to_owned(),
        profile,
        emit,
        kind,
        crate_types,
        consumer,
        build_script,
    }))
}

async fn build_stable_exact_identity(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    source: &UnitSource,
    source_local_only: bool,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<Option<(stow_types::public_cache::StableUnitIdentity, Reach)>> {
    let dependencies = match resolve_dependency_c_metadata_json(config, parsed).await? {
        DependencyCMetadataResolution::Resolved(resolved) => resolved,
        DependencyCMetadataResolution::Unrecorded(..) => {
            trace_identity_inputs(
                parsed,
                target,
                rustc_version,
                None,
                None,
                "dependency-identities-unresolved",
            )
            .await;
            return Ok(None);
        }
    };
    // The source's own reach — a git unit or extra codegen is local-only
    // — folded with the reaches the externs' `materialized_outputs` rows
    // recorded: a unit over a local-only dependency is local-only itself
    // (stow#1006).
    let reach = if source_local_only {
        Reach::LocalOnly
    } else {
        Reach::Public
    }
    .fold(dependencies.reach);
    // The compile key is the command line's: the feature cfgs are the
    // argv scan exactly as the builder's capture serializes them
    // (`ci/src/capture.rs` feeds `stable_unit_identity_for_package`
    // the same bytes) — a build script's `cargo:rustc-cfg=feature="…"`
    // output is part of the invocation's identity, and the graph's
    // resolved set never enters the key (stow#615).
    let features_json = command_line_features_json(parsed)?;
    let identity = stable_unit_identity(
        parsed,
        source,
        reach,
        target,
        rustc_version,
        &features_json,
        &dependencies.c_metadata_json,
    )?;
    trace_identity_inputs(
        parsed,
        target,
        rustc_version,
        Some(IdentityTraceInputs {
            crate_name: &identity.crate_name,
            version: &identity.version,
            features_json: &features_json,
            dependency_c_metadata_json: &dependencies.c_metadata_json,
        }),
        Some(&identity),
        "computed",
    )
    .await;
    Ok(Some((identity, reach)))
}

/// Identity inputs captured by [`trace_identity_inputs`].
#[derive(serde::Serialize)]
struct IdentityTraceInputs<'a> {
    crate_name: &'a str,
    version: &'a str,
    features_json: &'a str,
    dependency_c_metadata_json: &'a str,
}

#[derive(serde::Serialize)]
struct IdentityTraceRecord<'a> {
    outcome: &'a str,
    parsed_crate_name: &'a str,
    cargo_c_metadata: Option<&'a str>,
    target: &'a str,
    rustc_version: &'a str,
    emit: Vec<&'a str>,
    crate_types: &'a [String],
    profile: Option<stow_types::platform::Profile>,
    inputs: Option<IdentityTraceInputs<'a>>,
    computed_compile_key: Option<&'a str>,
    computed_c_metadata: Option<&'a str>,
}

/// Debugging probe: when `STOW_IDENTITY_TRACE` names a directory, write one
/// JSON file per rustc invocation capturing every input that feeds the
/// stable compile key, so client-side keys can be diffed against D1 rows
/// field by field. Inert when the env var is unset.
async fn trace_identity_inputs(
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
    inputs: Option<IdentityTraceInputs<'_>>,
    identity: Option<&stow_types::public_cache::StableUnitIdentity>,
    outcome: &str,
) {
    let Some(trace_dir) = std::env::var_os("STOW_IDENTITY_TRACE") else {
        return;
    };
    let record = IdentityTraceRecord {
        outcome,
        parsed_crate_name: &parsed.crate_name,
        cargo_c_metadata: parsed.c_metadata.as_deref(),
        target,
        rustc_version,
        emit: parsed.emit.iter().map(String::as_str).collect(),
        crate_types: &parsed.crate_types,
        profile: normalized_cache_profile(parsed).ok(),
        inputs,
        computed_compile_key: identity.map(|identity| identity.compile_key.as_str()),
        computed_c_metadata: identity.map(|identity| identity.c_metadata.as_str()),
    };
    let trace_dir = PathBuf::from(trace_dir);
    let file_name = format!(
        "{}-{}-{}.json",
        parsed.crate_name,
        parsed.c_metadata.as_deref().unwrap_or("none"),
        std::process::id()
    );
    let Ok(payload) = serde_json::to_vec(&record) else {
        return;
    };
    let _ = async_fs::create_dir_all(&trace_dir).await;
    let _ = async_fs::write(trace_dir.join(file_name), payload).await;
}

/// What [`resolve_local_build_artifact`] concluded about a finished
/// compile — the store inputs, or why there are none worth warning about
/// (stow#618).
enum LocalBuildResolution {
    /// The unit's stable identity and the inputs `store_local_build_outputs`
    /// persists.
    Resolved(Box<artifact_cache::LocalBuildArtifact>),
    /// The invocation is not a unit the cache can hold — no restorable
    /// artifact shape, not a registry crate, or no stable identity —
    /// nothing was owed (stow#619).
    NotAnArtifactUnit,
    /// An `--extern` dependency's `materialized_outputs` row is absent
    /// after every in-flight unit completed: a dependency whose
    /// bookkeeping genuinely never landed — a path or git dependency, or
    /// a store that was skipped.
    UnrecordedExtern {
        /// The first extern path with no row, for the debug log.
        extern_path: String,
    },
}

/// Resolve the stable identity a finished local build would carry as a cache
/// entry, plus the identity inputs `store_local_build_outputs` persists with
/// it.
async fn resolve_local_build_artifact(
    base: &WrapperEnvBase,
    parsed: &rustc_args::ParsedRustcArgs,
    in_flight: &crate::supervisor::server::InFlightUnits,
    unit_nodes: Option<&unit_node::UnitNodeTable>,
    env_cache: &WrapperEnvCache,
    ctx: &BuildContext,
    invocation_env: &supervisor::protocol::InvocationEnv,
) -> stow_types::error::Result<LocalBuildResolution> {
    // Whether the cache can hold this unit at all — the same predicate
    // `artifact_cache::materialized_output_paths` gates on — comes first:
    // a `bin` unit like `build_script_build` is never a cache unit, so it
    // never waits on another unit's bookkeeping, never reads
    // `materialized_outputs`, and never reaches an identity function,
    // which would only fail on its crate type (stow#619).
    if !parsed.is_restorable_artifact() {
        return Ok(LocalBuildResolution::NotAnArtifactUnit);
    }
    // The identity resolution reads each `--extern` dependency's
    // `materialized_outputs` row, which that dependency's own
    // post-compile writes on another connection. A dependency
    // still in flight — rustc running or bookkeeping unfinished
    // — has not written its rows yet, so wait for it rather than
    // misread a pending write as a missing one (stow#618). The
    // waits follow dependency edges, and those form a DAG: a
    // unit can only block on units it was compiled against, which
    // can never transitively be waiting on it, so no cycle can
    // form.
    in_flight.wait_for_externs(parsed).await;
    let config = &base.config;
    // The unit's own platform — the compiling rustc's real host triple
    // when cargo passed no `--target`, never the
    // `STOW_PUBLIC_CACHE_TARGET` consumer shortcut (stow#317).
    let target = parsed
        .target
        .clone()
        .unwrap_or_else(|| base.host_target.clone());
    let rustc_version = base.rustc_version.clone();
    let dependencies = match resolve_dependency_c_metadata_json(config, parsed).await? {
        DependencyCMetadataResolution::Resolved(dependencies) => dependencies,
        DependencyCMetadataResolution::Unrecorded(extern_path) => {
            return Ok(LocalBuildResolution::UnrecordedExtern { extern_path });
        }
    };
    let manifest_dir = invocation_env
        .manifest_dir()
        .map_err(stow_types::error::Error::msg)?;
    let source = detect_unit_source(parsed, manifest_dir.as_deref(), env_cache, ctx).await?;
    let class = parsed.unit_class(source, invocation_env.primary_package, &target);
    let local_only = class.source_local_only();
    let UnitClass::Keyed { ref source, .. } = class else {
        if let UnitClass::Uncached(reason) = &class {
            tracing::debug!(
                crate_name = %parsed.crate_name,
                reason = ?reason,
                "not storing locally built unit"
            );
        }
        return Ok(LocalBuildResolution::NotAnArtifactUnit);
    };
    let reach = if local_only {
        Reach::LocalOnly
    } else {
        Reach::Public
    }
    .fold(dependencies.reach);
    // The compile key is the command line's scan, always — a build
    // script's `cargo:rustc-cfg=feature="…"` output is part of the
    // invocation's identity (stow#615).
    let scan_features_json = command_line_features_json(parsed)?;
    let identity = stable_unit_identity(
        parsed,
        source,
        reach,
        &target,
        &rustc_version,
        &scan_features_json,
        &dependencies.c_metadata_json,
    )?;
    let crate_name = identity.crate_name.clone();
    let version = identity.version.clone();
    // The stored row's label is the unit's cargo feature set when the
    // build's unit graph names the unit, the scan otherwise — a unit
    // that finished before the analysis landed, or a standalone wrapper
    // with no graph, has no other answer. Both are sound labels for a
    // local row: two units of one crate whose scans agree compiled with
    // the same feature cfgs, so a scan-labelled row still serves exact
    // lookups. The scan only costs semantic matches for a crate whose
    // build script adds feature cfgs when its unit finished before the
    // analysis landed.
    let features_json = unit_nodes
        .and_then(|table| {
            resolved_unit_features_json(
                table,
                &crate_name,
                &version,
                parsed,
                &target,
                &rustc_version,
            )
        })
        .unwrap_or(scan_features_json);
    // Hash the unit's outputs once here — the materialized-output rows
    // record the instance digest, and the local store reuses the per-file
    // sha256s instead of re-reading the staged copy (stow#836).
    let stable_parsed =
        inject::parsed_with_stable_identity(parsed, &identity.c_metadata, &identity.extra_filename);
    let outputs =
        artifact_cache::local_build_output_specs(parsed, &stable_parsed, &base.host_target)?;
    let outputs = artifact_cache::hash_local_build_outputs(outputs).await?;
    Ok(LocalBuildResolution::Resolved(Box::new(
        artifact_cache::LocalBuildArtifact {
            compile_millis: 0,
            target,
            rustc_version,
            identity,
            reach,
            features_json,
            dependencies,
            outputs,
        },
    )))
}

fn semantic_request_profile(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<stow_types::platform::Profile> {
    normalized_requested_profile(parsed)
}

/// The argv `--cfg feature="…"` scan serialized for the compile key —
/// exactly the bytes the builder's capture serializes
/// (`ci/src/capture.rs` hands `stable_unit_identity_for_package`
/// the same string). The scan is a fact about the command line: it may
/// carry a build script's `cargo:rustc-cfg=feature="…"` additions, which
/// is why it is a compile-key input and never a semantic label (stow#615).
fn command_line_features_json(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<String> {
    serde_json::to_string(&parsed.features.iter().cloned().collect::<Vec<_>>())
        .wrap_err("serialize the command line's feature cfgs")
}

/// The unit's cargo feature set serialized, resolved against the build's
/// unit node table — the label published rows and miss nodes carry
/// (stow#615). `None` — with a warning naming the crate — when the table
/// does not hold the unit; the caller compiles on without a semantic
/// request or graph label for it.
fn resolved_unit_features_json(
    table: &unit_node::UnitNodeTable,
    crate_name: &str,
    version: &str,
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
) -> Option<String> {
    let evidence =
        match crate::unit_node::UnitEvidence::from_invocation(crate_name, version, parsed) {
            Ok(evidence) => evidence,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    crate_name = %crate_name,
                    version = %version,
                    target,
                    rustc_version,
                    "compiled unit's profile did not parse"
                );
                return None;
            }
        };
    match crate::unit_node::resolve_unit_node(
        table.coordinates(),
        table.consumer_spelled_target,
        &evidence,
    ) {
        Ok(node) => match serde_json::to_string(node.features) {
            Ok(features_json) => Some(features_json),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    crate_name = %crate_name,
                    version = %version,
                    target,
                    rustc_version,
                    "failed to serialize the unit's resolved feature set"
                );
                None
            }
        },
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %crate_name,
                version = %version,
                target,
                rustc_version,
                "compiled unit does not resolve against the build's unit graph"
            );
            None
        }
    }
}

/// The unit's immutable source identity, or the reason its source is
/// uncached (stow#1006): a registry slot that is not crates.io, a git
/// checkout whose commit could not be verified, or a path under neither
/// slot.
async fn detect_unit_source(
    parsed: &rustc_args::ParsedRustcArgs,
    manifest_dir: Option<&Path>,
    env_cache: &WrapperEnvCache,
    ctx: &BuildContext,
) -> stow_types::error::Result<Result<UnitSource, UncachedReason>> {
    if let Some(slot) = stow_types::public_cache::detect_registry_package_slot(parsed)? {
        return Ok(
            if ctx
                .registry_sources()?
                .is_crates_io(&slot.package, &slot.version, &slot.index_dir)
            {
                Ok(UnitSource::CratesIo {
                    package: slot.package,
                    version: slot.version,
                })
            } else {
                Err(UncachedReason::NonCratesIoRegistry)
            },
        );
    }
    if let Some(checkout) = detect_git_checkout(parsed) {
        // The manifest path inside the repository is cargo's own
        // `CARGO_MANIFEST_DIR` — the package root inside the checkout —
        // relative to the checkout root (`""` for a root package). One
        // that escapes the root, or an absent manifest dir, is a git
        // identity that cannot be verified.
        let manifest_path_in_repo = manifest_dir
            .and_then(|dir| dir.strip_prefix(&checkout.root).ok())
            .and_then(|path| path.to_str())
            .map(str::to_owned);
        let Some(manifest_path_in_repo) = manifest_path_in_repo else {
            tracing::debug!(
                crate_name = %parsed.crate_name,
                checkout = %checkout.root.display(),
                manifest_dir = ?manifest_dir,
                "git checkout's manifest dir is not inside the checkout; unit compiles uncached"
            );
            return Ok(Err(UncachedReason::GitIdentityFailed));
        };
        return Ok(match env_cache.git_commit(&checkout.root).await {
            // The checkout's `<short id>` directory is a prefix of the
            // resolved commit — cargo hashes the source id for the name,
            // so the check both proves the read landed on the right
            // checkout and pins the commit the identity keys under.
            Some(commit) if commit.starts_with(&checkout.short_id) => Ok(UnitSource::Git {
                commit,
                manifest_path_in_repo,
            }),
            Some(commit) => {
                tracing::debug!(
                    crate_name = %parsed.crate_name,
                    checkout = %checkout.root.display(),
                    resolved = %commit,
                    short_id = %checkout.short_id,
                    "git checkout's short id is not a prefix of its resolved commit; unit compiles uncached"
                );
                Err(UncachedReason::GitIdentityFailed)
            }
            None => {
                tracing::debug!(
                    crate_name = %parsed.crate_name,
                    checkout = %checkout.root.display(),
                    "could not resolve the git checkout's commit; unit compiles uncached"
                );
                Err(UncachedReason::GitIdentityFailed)
            }
        });
    }
    Ok(Err(UncachedReason::PathSource))
}

/// Resolve `-C target-cpu=native` to the concrete CPU the host rustc
/// reports — the only value that makes the option deterministic across
/// machines (stow#1006). An unresolved `native` survives in the option
/// set and classifies unfoldable.
async fn resolve_native_target_cpu(
    rustc: &OsStr,
    parsed: &mut rustc_args::ParsedRustcArgs,
    env_cache: &WrapperEnvCache,
) {
    if !parsed
        .extra_codegen
        .iter()
        .any(|option| option == "-C target-cpu=native")
    {
        return;
    }
    if let Some(cpu) = env_cache.native_cpu(rustc).await {
        // Replaced where it stood: option order is compile identity.
        for option in &mut parsed.extra_codegen {
            if option == "-C target-cpu=native" {
                *option = format!("-C target-cpu={cpu}");
            }
        }
    }
}

pub(crate) fn canonical_crate_name(name: &str) -> String {
    stow_types::public_cache::canonical_crate_name(name)
}

/// Why a cached bundle cannot serve the invocation in hand.
#[derive(Debug)]
enum BundleMismatch {
    /// The artifact was compiled under a different profile. Dev profiles
    /// are configurable per machine, so this one is routine, systematic
    /// when it happens, and the only mismatch a user can act on — it is
    /// carried separately so the build summary can name it.
    Profile {
        /// The cached artifact's diverging fields, as `k=v`.
        cached: String,
        /// The same fields as this compile requests them.
        wanted: String,
    },
    /// Anything else: crate version, emit set, artifact kind, crate types,
    /// or a failure to classify the invocation at all.
    Other(stow_types::error::Error),
}

impl std::fmt::Display for BundleMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Profile { cached, wanted } => write!(
                formatter,
                "exact bundle profile mismatch: cached {cached}, invocation wants {wanted}"
            ),
            Self::Other(error) => write!(formatter, "{error}"),
        }
    }
}

/// Classify a cached bundle against this invocation, folding a failure to
/// classify into the mismatch itself: either way the bundle cannot serve.
fn bundle_mismatch(
    parsed: &rustc_args::ParsedRustcArgs,
    profile: &stow_types::platform::Profile,
    emit: &[String],
    kind: &stow_types::artifact::ArtifactKind,
    crate_types: &[stow_types::artifact::RustCrateType],
    crate_version: &str,
) -> Option<BundleMismatch> {
    match validate_exact_bundle_semantics(parsed, profile, emit, kind, crate_types, crate_version) {
        Ok(mismatch) => mismatch,
        Err(error) => Some(BundleMismatch::Other(error)),
    }
}

fn validate_exact_bundle_semantics(
    parsed: &rustc_args::ParsedRustcArgs,
    profile: &stow_types::platform::Profile,
    emit: &[String],
    kind: &stow_types::artifact::ArtifactKind,
    crate_types: &[stow_types::artifact::RustCrateType],
    crate_version: &str,
) -> stow_types::error::Result<Option<BundleMismatch>> {
    // Version first, and unconditionally. The exact lookup is keyed on
    // `c_metadata`, which is supposed to encode the crate version — but
    // "supposed to" is not a check, and a collision serves one version's
    // compiled code for another's. That is how bitflags 2.5.0 came to be
    // injected into a bitflags 1.3.2 unit on dust, breaking the build with 126
    // conflicting-impl errors inside `nix`. Nothing downstream can detect it,
    // so it has to fail closed here.
    if let Some((_, requested_version)) = shared_detect_registry_crate_version(parsed)?
        && requested_version != crate_version
    {
        return Ok(Some(BundleMismatch::Other(stow_types::stow_error!(
            "exact bundle version mismatch: cached {crate_version}, invocation wants {requested_version}"
        ))));
    }
    let expected_profile = normalized_requested_profile(parsed)?;
    if let Some((cached, wanted)) = profile.divergence(&expected_profile) {
        // Name the diverging field. A profile mismatch is systematic — one
        // `[profile.dev]` line in the user's cargo config rejects every
        // artifact the public cache holds — so "which knob" is the whole
        // diagnosis, and the build summary repeats it.
        return Ok(Some(BundleMismatch::Profile { cached, wanted }));
    }
    let expected_emit = parsed
        .emit
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let actual_emit = emit
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if !expected_emit.iter().all(|emit| actual_emit.contains(emit)) {
        return Ok(Some(BundleMismatch::Other(stow_types::stow_error!(
            "exact bundle emit mismatch"
        ))));
    }
    let expected_kind = parsed_artifact_kind(parsed)?;
    if kind != &expected_kind {
        return Ok(Some(BundleMismatch::Other(stow_types::stow_error!(
            "exact bundle artifact kind mismatch: expected {}, got {}",
            expected_kind.as_str(),
            kind.as_str()
        ))));
    }
    let expected_crate_types = parsed_crate_types(parsed)?;
    if crate_types != expected_crate_types.as_slice() {
        return Ok(Some(BundleMismatch::Other(stow_types::stow_error!(
            "exact bundle crate types mismatch"
        ))));
    }
    Ok(None)
}

fn normalized_requested_profile(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<stow_types::platform::Profile> {
    normalized_cache_profile(parsed)
}

pub(crate) fn parsed_artifact_kind(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<stow_types::artifact::ArtifactKind> {
    let crate_types = parsed_crate_types(parsed)?;
    if crate_types
        .iter()
        .any(|crate_type| matches!(crate_type, stow_types::artifact::RustCrateType::ProcMacro))
    {
        return Ok(stow_types::artifact::ArtifactKind::ProcMacro);
    }
    if crate_types
        .iter()
        .any(|crate_type| matches!(crate_type, stow_types::artifact::RustCrateType::Dylib))
    {
        return Ok(stow_types::artifact::ArtifactKind::Dylib);
    }
    if crate_types.iter().any(|crate_type| {
        matches!(
            crate_type,
            stow_types::artifact::RustCrateType::Lib | stow_types::artifact::RustCrateType::Rlib
        )
    }) {
        return Ok(stow_types::artifact::ArtifactKind::Rlib);
    }
    Err(stow_types::stow_error!(
        "unsupported semantic artifact kind for crate types {:?}",
        parsed.crate_types
    ))
}

pub(crate) fn parsed_crate_types(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<Vec<stow_types::artifact::RustCrateType>> {
    let mut crate_types = parsed
        .crate_types
        .iter()
        .map(|crate_type| match crate_type.as_str() {
            "lib" => Ok(stow_types::artifact::RustCrateType::Lib),
            "rlib" => Ok(stow_types::artifact::RustCrateType::Rlib),
            "dylib" => Ok(stow_types::artifact::RustCrateType::Dylib),
            "cdylib" => Ok(stow_types::artifact::RustCrateType::Cdylib),
            "staticlib" => Ok(stow_types::artifact::RustCrateType::Staticlib),
            "proc-macro" => Ok(stow_types::artifact::RustCrateType::ProcMacro),
            other => Err(stow_types::stow_error!(
                "unsupported rust crate type `{other}`"
            )),
        })
        .collect::<stow_types::error::Result<std::collections::BTreeSet<_>>>()?
        .into_iter()
        .collect::<Vec<_>>();
    crate_types.sort();
    Ok(crate_types)
}

pub(crate) fn log_nonfatal_result(context: &'static str, result: stow_types::error::Result<()>) {
    if let Err(error) = result {
        tracing::warn!(error = %error, "{context}");
    }
}

fn parse_cli_or_exit(args: &[std::ffi::OsString]) -> stow_types::error::Result<Cli> {
    match Cli::try_parse_from(args.iter().cloned()) {
        Ok(cli) => Ok(cli),
        Err(error) => {
            let kind = error.kind();
            error.print()?;
            if matches!(
                kind,
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                std::process::exit(0);
            }
            std::process::exit(2);
        }
    }
}

pub(crate) use commands::detect_wrapper_commands;

/// One artifact notification exactly as rustc prints it under
/// `--json=…artifacts…` — the field order in this struct is the byte
/// order of the line, and a rename of `$message_type` fails the build
/// rather than the consumer (stow#633).
#[derive(Debug, PartialEq, Eq, serde::Serialize)]
struct RustcArtifactNotification {
    #[serde(rename = "$message_type")]
    message_type: &'static str,
    artifact: PathBuf,
    emit: &'static str,
}

/// The artifact-notification lines a served invocation owes cargo, in
/// rustc's emission order — empty when the invocation's `--json` set did
/// not ask for `artifacts`.
fn cached_rustc_artifact_notifications(
    parsed: &rustc_args::ParsedRustcArgs,
    host: &str,
) -> stow_types::error::Result<ArtifactNotifications> {
    if !parsed.requests_json_artifact_notifications() {
        return Ok(ArtifactNotifications::default());
    }

    let mut notifications = Vec::new();
    if parsed.emit.contains("dep-info") {
        notifications.push(RustcArtifactNotification {
            message_type: "artifact",
            artifact: parsed.output_dep_info_path().ok_or_else(|| {
                stow_types::stow_error!("cached rustc invocation is missing dep-info path")
            })?,
            emit: "dep-info",
        });
    }
    if parsed.emit.contains("metadata") {
        notifications.push(RustcArtifactNotification {
            message_type: "artifact",
            artifact: parsed.output_rmeta_path().ok_or_else(|| {
                stow_types::stow_error!(
                    "cached rustc invocation cannot emit metadata for crate types {:?}",
                    parsed.crate_types
                )
            })?,
            emit: "metadata",
        });
    }
    if parsed.emit.contains("link") {
        let artifact = parsed
            .output_link_path(host)
            .map_err(stow_types::error::Error::msg)?
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "cached rustc invocation cannot emit link artifact for crate types {:?}",
                    parsed.crate_types
                )
            })?;
        notifications.push(RustcArtifactNotification {
            message_type: "artifact",
            artifact,
            emit: "link",
        });
    }
    notifications
        .iter()
        .map(|notification| {
            serde_json::to_string(notification).wrap_err("serialize rustc artifact notification")
        })
        .collect::<stow_types::error::Result<Vec<_>>>()
        .map(ArtifactNotifications)
}

/// Write the artifact notifications a served decision carried to this
/// process's own stderr, each line `\n`-terminated and flushed — this is
/// the process cargo spawned, and the supervisor's notifications travel
/// here in the answer because cargo reads them from its child, not from
/// the build's terminal (stow#633).
///
/// # Errors
///
/// A write or flush failure is an error: cargo is owed these lines, and
/// exiting 0 without them leaves it blind to the artifacts it was told
/// were emitted.
pub(crate) fn write_served_artifact_notifications(
    notifications: &ArtifactNotifications,
) -> stow_types::error::Result<()> {
    let mut stderr = io::stderr().lock();
    for line in notifications.lines() {
        stderr
            .write_all(line.as_bytes())
            .and_then(|()| stderr.write_all(b"\n"))
            .wrap_err("write rustc artifact notification")?;
    }
    stderr
        .flush()
        .wrap_err("flush rustc artifact notifications")
}

pub(crate) fn write_stdout(message: &str) -> stow_types::error::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(message.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

/// The subscriber [`install_tracing`] installs, built from the values the
/// environment supplied.
fn tracing_subscriber_for<W>(
    rust_log: Option<&str>,
    trace_file: Option<PathBuf>,
    terminal: W,
) -> (
    impl tracing::Subscriber + Send + Sync + 'static,
    TracingGuard,
)
where
    W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    // `warn` by default: what reaches the terminal without `RUST_LOG` is
    // a once-per-condition signal — the per-unit and per-attempt detail
    // lives at `debug` (stow#633).
    let terminal_filter = rust_log
        .and_then(|value| EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| EnvFilter::new("warn"));
    // stderr, never stdout: `run()` also serves the `rustc` / `cc` wrapper
    // subcommands, whose stdout must stay byte-identical to the wrapped
    // compiler's. Cargo hashes `rustc -vV` stdout into every unit's
    // `-C metadata`, so a single log line there changes the cache key of
    // every crate in the build on every invocation.
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(terminal)
        .with_filter(terminal_filter);

    // The trace is an explicit request for stow's own spans, most of
    // them recorded at `debug`; one filter for both outputs wrote an
    // empty trace (stow#698), and a filter `RUST_LOG` could narrow
    // would do it again. The layer sees stow's crates at `trace` and
    // nothing else.
    let (chrome_layer, chrome_guard) = trace_file
        .map(|path| {
            let (layer, guard) = tracing_chrome::ChromeLayerBuilder::new()
                .file(path)
                .include_args(true)
                .build();
            (
                Some(
                    layer.with_filter(
                        tracing_subscriber::filter::Targets::new()
                            .with_target("stow_", tracing::Level::TRACE),
                    ),
                ),
                Some(guard),
            )
        })
        .unwrap_or_default();

    (
        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(chrome_layer),
        TracingGuard {
            _chrome: chrome_guard,
        },
    )
}

fn install_tracing() -> TracingGuard {
    let rust_log = std::env::var("RUST_LOG").ok();
    let trace_file = std::env::var_os(STOW_TRACE_FILE_ENV).map(PathBuf::from);
    let (subscriber, guard) =
        tracing_subscriber_for(rust_log.as_deref(), trace_file, std::io::stderr);
    // `try_init` installs the global default and — `tracing-subscriber`'s
    // `tracing-log` feature is on — the `LogTracer` bridge routing `log`
    // records into tracing; the already-set error stays ignored.
    let _ = subscriber.try_init();
    guard
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{
        UnparseableInvocation, cached_rustc_artifact_notifications, classify_invocation,
        expand_wrapper_role, should_install_tracing_for_args, strip_cargo_subcommand_word,
        tracing_subscriber_for,
    };
    use crate::rustc_args::ParsedRustcArgs;

    fn args(parts: &[&str]) -> Vec<std::ffi::OsString> {
        parts.iter().map(std::ffi::OsString::from).collect()
    }

    fn env_value(value: Option<&str>) -> Option<OsString> {
        value.map(OsString::from)
    }

    /// A one-commit git repository at `<root>/git/checkouts/demo-9f9f/<name>`
    /// — `name` is the commit's 7-hex prefix when `None`, else the given
    /// (wrong) directory name — and the commit it resolves to.
    fn git_checkout_slot(root: &std::path::Path, name: Option<&str>) -> (PathBuf, String) {
        let work = root.join("work");
        std::fs::create_dir_all(work.join("src")).expect("create work tree");
        std::fs::write(work.join("src").join("lib.rs"), "pub fn leaf() {}\n").expect("write lib");
        let git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .args(args)
                .current_dir(&work)
                .output()
                .expect("run git");
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).expect("utf8 git output")
        };
        git(&["init", "--quiet"]);
        git(&["add", "--all"]);
        git(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--message=m",
        ]);
        let commit = git(&["rev-parse", "HEAD"]).trim().to_owned();
        let slot_name = name.unwrap_or(&commit[..7]);
        let slot = root.join("git/checkouts/demo-9f9f").join(slot_name);
        std::fs::create_dir_all(slot.parent().expect("slot parent")).expect("create slot parent");
        std::fs::rename(&work, &slot).expect("move the checkout into its slot");
        (slot, commit)
    }

    /// The identity of a git unit is the commit its checkout resolves
    /// to: a `<short id>` directory that is a prefix of it keys the
    /// unit, one that is not fails the identity (stow#1006).
    #[tokio::test]
    async fn a_git_checkout_keys_by_its_resolved_commit() {
        let signal = std::sync::Arc::new(crate::facade::ServeMapSignal::settled());
        let ctx = serve_ctx(&signal);
        let cache = test_cache(std::ffi::OsStr::new(""));
        let parse = |slot: &std::path::Path| {
            ParsedRustcArgs::parse(&args(&[
                "--crate-name",
                "demo",
                "--crate-type",
                "lib",
                slot.join("src/lib.rs").to_str().expect("utf8 path"),
            ]))
            .expect("parse")
        };

        let matching = tempfile::tempdir().expect("tempdir");
        let (slot, commit) = git_checkout_slot(matching.path(), None);
        let source = super::detect_unit_source(&parse(&slot), Some(&slot), &cache, &ctx)
            .await
            .expect("detection reads the checkout");
        assert_eq!(
            source,
            Ok(stow_types::public_cache::UnitSource::Git {
                commit,
                manifest_path_in_repo: String::new(),
            })
        );

        // A manifest dir below the root names its path inside the repo.
        let nested = slot.join("tools/demo");
        let source = super::detect_unit_source(&parse(&slot), Some(&nested), &cache, &ctx)
            .await
            .expect("detection reads the checkout");
        assert!(
            matches!(
                source,
                Ok(stow_types::public_cache::UnitSource::Git { ref manifest_path_in_repo, .. })
                    if manifest_path_in_repo == "tools/demo"
            ),
            "{source:?}"
        );

        let mismatched = tempfile::tempdir().expect("tempdir");
        let (slot, _) = git_checkout_slot(mismatched.path(), Some("0000000"));
        let source = super::detect_unit_source(&parse(&slot), Some(&slot), &cache, &ctx)
            .await
            .expect("detection reads the checkout");
        assert_eq!(
            source,
            Err(stow_types::rustc::UncachedReason::GitIdentityFailed)
        );
    }

    #[test]
    fn registry_sources_classify_only_crates_io() {
        // The lockfile map is authoritative: a package whose source is a
        // crates.io entry classifies; the same `(name, version)` under
        // another registry does not (stow#1006).
        let hosts_set = std::iter::once("index.crates.io".to_owned()).collect();
        let lockfile = super::RegistrySources::parse_lockfile(
            r#"
            [[package]]
            name = "itoa"
            version = "1.0.15"
            source = "registry+https://github.com/rust-lang/crates.io-index"

            [[package]]
            name = "mycrate"
            version = "0.2.0"
            source = "sparse+https://index.crates.io/"

            [[package]]
            name = "mirrored"
            version = "0.3.0"
            source = "registry+https://my-mirror.example.com/index"

            [[package]]
            name = "patched"
            version = "0.4.0"
            "#,
            &hosts_set,
        )
        .expect("lockfile parses");
        assert!(lockfile.is_crates_io("itoa", "1.0.15", "index.crates.io-0123abcd"));
        assert!(lockfile.is_crates_io("mycrate", "0.2.0", "index.crates.io-0123abcd"));
        assert!(!lockfile.is_crates_io("mirrored", "0.3.0", "my-mirror.example.com-deadbeef"));
        assert!(!lockfile.is_crates_io("patched", "0.4.0", "index.crates.io-0123abcd"));
        assert!(!lockfile.is_crates_io("itoa", "9.9.9", "index.crates.io-0123abcd"));

        // An unparseable lockfile is an error, never a degraded map.
        assert!(
            super::RegistrySources::parse_lockfile("not [toml", &hosts_set).is_err(),
            "an unparseable lockfile must fail, not degrade"
        );

        // Two registries shipping the same `(name, version)`: the slot's
        // index dir settles which source this unit came from — a
        // crates.io answer under the crates.io slot, a non-crates.io
        // answer under the mirror's (the D1 case).
        let shared = super::RegistrySources::parse_lockfile(
            r#"
            [[package]]
            name = "shared"
            version = "1.0.0"
            source = "registry+https://github.com/rust-lang/crates.io-index"

            [[package]]
            name = "shared"
            version = "1.0.0"
            source = "sparse+https://my-alt.example.com/index"
            "#,
            &hosts_set,
        )
        .expect("shared-source lockfile parses");
        assert!(shared.is_crates_io("shared", "1.0.0", "index.crates.io-0123abcd"));
        assert!(!shared.is_crates_io("shared", "1.0.0", "my-alt.example.com-deadbeef"));

        // A stale lockfile: `foo` records crates.io alone, but the slot
        // this build extracted it into sits under the alternative
        // registry's index dir. The single recorded source is no answer
        // — the dir must name a crates.io host too.
        let stale = super::RegistrySources::parse_lockfile(
            r#"
            [[package]]
            name = "foo"
            version = "1.0.0"
            source = "registry+https://github.com/rust-lang/crates.io-index"
            "#,
            &hosts_set,
        )
        .expect("stale lockfile parses");
        assert!(stale.is_crates_io("foo", "1.0.0", "index.crates.io-0123abcd"));
        assert!(!stale.is_crates_io("foo", "1.0.0", "my-alt.example.com-deadbeef"));

        // The cargo-config map matches on the slot's host component:
        // crates.io's own slot, plus every host the replace-with chain
        // resolved to, counts as crates.io.
        let hosts = super::RegistrySources::CargoConfig(
            [
                "index.crates.io".to_owned(),
                "my-mirror.example.com".to_owned(),
            ]
            .into_iter()
            .collect(),
        );
        assert!(hosts.is_crates_io("itoa", "1.0.15", "index.crates.io-0123abcd"));
        assert!(hosts.is_crates_io("mirrored", "0.3.0", "my-mirror.example.com-deadbeef"));
        assert!(!hosts.is_crates_io("other", "1.0.0", "other.example.com-abcdef12"));
    }

    #[test]
    fn cargo_subcommand_invocation_drops_the_repeated_subcommand_word() {
        assert_eq!(
            strip_cargo_subcommand_word(args(&["/usr/bin/cargo-stow", "stow", "check"])),
            args(&["/usr/bin/cargo-stow", "check"])
        );
        assert_eq!(
            strip_cargo_subcommand_word(args(&["cargo-stow.exe", "stow", "check"])),
            args(&["cargo-stow.exe", "check"])
        );
        // Only cargo repeats the word; a direct `stow stow` is a user error
        // clap reports, and `cargo-stow check` stays as typed.
        assert_eq!(
            strip_cargo_subcommand_word(args(&["stow", "stow", "check"])),
            args(&["stow", "stow", "check"])
        );
        assert_eq!(
            strip_cargo_subcommand_word(args(&["cargo-stow", "check"])),
            args(&["cargo-stow", "check"])
        );
    }

    #[test]
    fn wrapper_role_names_expand_to_runtime_subcommands() {
        assert_eq!(
            expand_wrapper_role(args(&[
                "C:/Users/ci/AppData/Local/stow/tools/stow-rustc-wrapper.exe",
                "C:/rustc.exe",
                "-vV"
            ])),
            args(&[
                "C:/Users/ci/AppData/Local/stow/tools/stow-rustc-wrapper.exe",
                "rustc",
                "C:/rustc.exe",
                "-vV"
            ])
        );
        assert_eq!(
            expand_wrapper_role(args(&[
                "/home/ci/.local/share/stow/tools/stow-cc-launcher",
                "cl.exe",
                "/c"
            ])),
            args(&[
                "/home/ci/.local/share/stow/tools/stow-cc-launcher",
                "cc",
                "cl.exe",
                "/c"
            ])
        );
        assert_eq!(
            expand_wrapper_role(args(&["stow", "check"])),
            args(&["stow", "check"]),
            "an ordinary invocation is untouched"
        );
        assert_eq!(
            expand_wrapper_role(args(&[
                "/home/ci/.local/share/stow/tools/stow-rustc-wrapper",
                "__drain-misses",
                "/ws/target"
            ])),
            args(&[
                "/home/ci/.local/share/stow/tools/stow-rustc-wrapper",
                "__drain-misses",
                "/ws/target"
            ]),
            "an internal subcommand under a shim's name stays the runtime"
        );
    }

    #[test]
    fn wrapper_tracing_stays_disabled_under_rust_log_by_default() {
        assert!(!should_install_tracing_for_args(
            &args(&["stow", "rustc"]),
            env_value(Some("debug")).as_deref(),
            env_value(None),
        ));
        assert!(!should_install_tracing_for_args(
            &args(&["stow", "cc"]),
            env_value(Some("debug")).as_deref(),
            env_value(None),
        ));
    }

    #[test]
    fn wrapper_tracing_requires_explicit_opt_in() {
        assert!(should_install_tracing_for_args(
            &args(&["stow", "rustc"]),
            env_value(None).as_deref(),
            env_value(Some("1")),
        ));
        assert!(!should_install_tracing_for_args(
            &args(&["stow", "rustc"]),
            env_value(None).as_deref(),
            env_value(Some("0")),
        ));
    }

    #[test]
    fn top_level_commands_keep_tracing_behavior() {
        assert!(should_install_tracing_for_args(
            &args(&["stow", "check"]),
            env_value(None).as_deref(),
            env_value(None),
        ));
        assert!(should_install_tracing_for_args(
            &args(&["stow", "check"]),
            env_value(Some("debug")).as_deref(),
            env_value(None),
        ));
    }

    #[test]
    fn unparseable_rustc_invocation_passes_through_instead_of_failing() {
        // A flag stow does not model must never fail the unit: the
        // invocation goes to the real rustc verbatim.
        let invocation = classify_invocation(&args(&[
            "--crate-name",
            "itoa",
            "-Z",
            "embed-metadata=banana",
        ]));

        assert!(
            matches!(invocation, Err(UnparseableInvocation::Passthrough(_))),
            "an unsupported flag is a passthrough, not a build failure"
        );
    }

    #[test]
    fn crate_name_less_probe_stays_a_quiet_passthrough() {
        assert!(matches!(
            classify_invocation(&args(&["-vV"])),
            Err(UnparseableInvocation::Probe(_))
        ));
    }

    /// Cargo's probes reach the supervisor as `Plan` frames — `rustc -vV`
    /// and the `--crate-name ___ --print=file-names` target-info query —
    /// but they run before resolution and must not complete
    /// `ResolutionDone`; only a real compile unit's frame may (stow#608).
    #[tokio::test]
    async fn resolution_done_fires_only_on_a_compile_unit_plan() {
        let resolution_done = super::ResolutionDone::pending();
        let handler = std::sync::Arc::new(super::BuildSupervisor::new(
            super::BuildContext::default(),
            None,
            resolution_done.clone(),
            crate::state_db::StateDb::default(),
        ));

        let _ = crate::supervisor::server::Handler::plan(
            &handler,
            OsString::from("rustc"),
            args(&["-vV"]),
            crate::supervisor::protocol::InvocationEnv::default(),
        )
        .await;
        assert!(!resolution_done.has_completed());

        let _ = crate::supervisor::server::Handler::plan(
            &handler,
            OsString::from("rustc"),
            args(&[
                "--crate-name",
                "___",
                "--crate-type",
                "lib",
                "--print",
                "file-names",
            ]),
            crate::supervisor::protocol::InvocationEnv::default(),
        )
        .await;
        assert!(!resolution_done.has_completed());

        let _ = crate::supervisor::server::Handler::plan(
            &handler,
            OsString::from("rustc"),
            args(&[
                "--crate-name",
                "demo",
                "--crate-type",
                "lib",
                "--out-dir",
                "/tmp/out",
                "--emit",
                "metadata",
                "-C",
                "metadata=abc123",
            ]),
            crate::supervisor::protocol::InvocationEnv::default(),
        )
        .await;
        assert!(resolution_done.has_completed());
        // A waiter armed after completion resolves at once.
        resolution_done.wait().await;
    }

    /// The uncovered fast path's `Observed` frames describe real compile
    /// units by construction — the same signal fires on them, while a
    /// probe that somehow arrived is dropped by the classifier before it
    /// can complete the signal (stow#608).
    #[tokio::test]
    async fn resolution_done_fires_on_a_compile_unit_observed() {
        let resolution_done = super::ResolutionDone::pending();
        let handler = std::sync::Arc::new(super::BuildSupervisor::new(
            super::BuildContext::default(),
            None,
            resolution_done.clone(),
            crate::state_db::StateDb::default(),
        ));

        crate::supervisor::server::Handler::observed(
            &handler,
            crate::supervisor::server::Observation {
                executable: OsString::from("rustc"),
                args: args(&["-vV"]),
                success: None,
                compile_time: std::time::Duration::ZERO,
                env: crate::supervisor::protocol::InvocationEnv::default(),
            },
        )
        .await;
        assert!(!resolution_done.has_completed());

        crate::supervisor::server::Handler::observed(
            &handler,
            crate::supervisor::server::Observation {
                executable: OsString::from("rustc"),
                args: args(&[
                    "--crate-name",
                    "demo",
                    "--crate-type",
                    "lib",
                    "--out-dir",
                    "/tmp/out",
                    "--emit",
                    "metadata",
                    "-C",
                    "metadata=abc123",
                ]),
                success: None,
                compile_time: std::time::Duration::ZERO,
                env: crate::supervisor::protocol::InvocationEnv::default(),
            },
        )
        .await;
        assert!(resolution_done.has_completed());
    }

    /// The line rustc prints for `file` under the fixtures' `/tmp/out`
    /// out-dir: the path is spelled the way this platform joins it and
    /// escaped as JSON, everything around it is the literal protocol.
    fn notification_line(file: &str, emit: &str) -> String {
        let artifact = serde_json::to_string(&PathBuf::from("/tmp/out").join(file))
            .expect("a UTF-8 path serializes");
        format!(r#"{{"$message_type":"artifact","artifact":{artifact},"emit":"{emit}"}}"#)
    }

    #[test]
    fn cached_rlib_notifications_match_rustc_protocol() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "autocfg",
            "--crate-type",
            "lib",
            "--out-dir",
            "/tmp/out",
            "--emit",
            "dep-info,metadata,link",
            "--json",
            "diagnostic-rendered-ansi,artifacts,future-incompat",
            "-C",
            "metadata=abc123",
            "-C",
            "extra-filename=-xyz789",
        ]))
        .expect("parse rustc args");

        let notifications = cached_rustc_artifact_notifications(&parsed, "aarch64-apple-darwin")
            .expect("build artifact notifications");

        // Byte-identical to the lines rustc itself prints: field order
        // and the `$message_type` tag included (stow#633).
        assert_eq!(
            notifications,
            crate::supervisor::protocol::ArtifactNotifications(vec![
                notification_line("autocfg-xyz789.d", "dep-info"),
                notification_line("libautocfg-xyz789.rmeta", "metadata"),
                notification_line("libautocfg-xyz789.rlib", "link"),
            ])
        );
        assert!(parsed.requests_json_artifact_notifications());
    }

    #[test]
    fn cached_proc_macro_notifications_use_dylib_output() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "serde_derive",
            "--crate-type",
            "proc-macro",
            "--target",
            "aarch64-apple-darwin",
            "--out-dir",
            "/tmp/out",
            "--emit",
            "dep-info,link",
            "--json",
            "artifacts",
            "-C",
            "metadata=pm123",
            "-C",
            "extra-filename=-xyz789",
        ]))
        .expect("parse rustc args");

        let notifications = cached_rustc_artifact_notifications(&parsed, "aarch64-apple-darwin")
            .expect("build artifact notifications");

        assert_eq!(
            notifications,
            crate::supervisor::protocol::ArtifactNotifications(vec![
                notification_line("serde_derive-xyz789.d", "dep-info"),
                notification_line("libserde_derive-xyz789.dylib", "link"),
            ])
        );
    }

    /// Cargo only reads artifact notifications from a unit whose `--json`
    /// asks for them — a served invocation that never asked owes nothing
    /// (stow#633).
    #[test]
    fn an_invocation_without_artifacts_requests_no_notifications() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "autocfg",
            "--crate-type",
            "lib",
            "--out-dir",
            "/tmp/out",
            "--emit",
            "dep-info,metadata,link",
            "--json",
            "diagnostic-rendered-ansi,future-incompat",
            "-C",
            "metadata=abc123",
        ]))
        .expect("parse rustc args");

        let notifications = cached_rustc_artifact_notifications(&parsed, "aarch64-apple-darwin")
            .expect("build artifact notifications");

        assert_eq!(
            notifications,
            crate::supervisor::protocol::ArtifactNotifications::default()
        );
    }

    /// stow#578: the name a bundle's `crate_name` is checked against is
    /// the package name the registry source path carries — the lib
    /// target's name a `[lib] name` rename changes is never it.
    #[test]
    fn the_expected_bundle_name_is_the_registry_package_name() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "debug_unreachable",
            "--crate-type",
            "lib",
            "/root/.cargo/registry/src/index.crates.io-0123abcd/new_debug_unreachable-1.0.6/src/lib.rs",
        ]))
        .expect("parse rustc args");
        assert_eq!(parsed.crate_name, "debug_unreachable");
        assert_eq!(
            super::expected_bundle_crate_name(&parsed).as_deref(),
            Some("new_debug_unreachable")
        );
    }

    /// An invocation with no registry source path is the non-registry
    /// case: `Ok(None)`, no bundle name to match — the miss path.
    #[test]
    fn the_expected_bundle_name_is_none_for_a_non_registry_unit() {
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "mycrate",
            "--crate-type",
            "lib",
            "src/lib.rs",
        ]))
        .expect("parse rustc args");
        assert_eq!(super::expected_bundle_crate_name(&parsed), None);
    }

    /// stow#696: a unit that was served is a hit even when a stage
    /// failed earlier in the chain — the tally never turns a serve
    /// into an error.
    #[test]
    fn a_served_unit_is_a_hit_whatever_failed_on_the_way() {
        let mut tally = super::LookupTally::default();
        assert_eq!(
            super::UnitOutcome::of(true, &tally, false),
            super::UnitOutcome::Hit
        );
        tally.failed = true;
        assert_eq!(
            super::UnitOutcome::of(true, &tally, true),
            super::UnitOutcome::Hit
        );
    }

    /// stow#696: an unserved unit whose chain saw a failure is an error
    /// — outranking both the refusal and the plain miss.
    #[test]
    fn a_failure_outranks_a_refusal_and_a_miss() {
        let tally = super::LookupTally { failed: true };
        assert_eq!(
            super::UnitOutcome::of(false, &tally, false),
            super::UnitOutcome::Error
        );
        assert_eq!(
            super::UnitOutcome::of(false, &tally, true),
            super::UnitOutcome::Error
        );
    }

    /// stow#696: a glibc refusal is still a refusal, not a miss — the
    /// artifact exists, no build can change it.
    #[test]
    fn a_refusal_outranks_a_miss() {
        let tally = super::LookupTally::default();
        assert_eq!(
            super::UnitOutcome::of(false, &tally, true),
            super::UnitOutcome::GlibcRefusal
        );
    }

    /// stow#696: a chain that served nothing and failed nothing is the
    /// plain miss the build enqueues.
    #[test]
    fn nothing_seen_is_a_miss() {
        let tally = super::LookupTally::default();
        assert_eq!(
            super::UnitOutcome::of(false, &tally, false),
            super::UnitOutcome::Miss
        );
    }

    /// stow#696: a semantic lookup that returns the entry of another
    /// version has found no entry for this invocation — it is not a
    /// failure, and nothing is counted. The regression counted it an
    /// error, after which a later stage's serve counted the same
    /// invocation a hit: one invocation, two outcomes.
    #[tokio::test]
    async fn a_semantic_entry_of_another_version_is_not_a_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = env_base_test_config(&dir);
        config.artifact_cache_max_bytes = u64::MAX;
        let mut bundle = crate::artifact_cache::tests::sample_bundle(
            "aaaabbbbccccdddd",
            "libanyhow-aaaabbbbccccdddd.rmeta",
        );
        bundle.manifest.config.crate_name =
            stow_types::identity::CrateName::parse("anyhow").unwrap();
        bundle.manifest.config.crate_version =
            stow_types::identity::CrateVersion::new(semver::Version::parse("1.0.104").unwrap());

        crate::artifact_cache::prepare_local_cache(&config, "1.91.1")
            .await
            .expect("prepare cache");
        let request = crate::fetch::FetchRequest {
            target: "aarch64-apple-darwin",
            rustc_version: "1.91.1",
            c_metadata: "aaaabbbbccccdddd",
        };
        let stored = crate::artifact_cache::store_downloaded_bundle(&config, &request, &bundle)
            .await
            .expect("store bundle");
        drop(stored);

        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "anyhow",
            "--crate-type",
            "lib",
            "--emit",
            "metadata",
            "-C",
            "metadata=bbbbccccddddeeee",
            "/root/.cargo/registry/src/index.crates.io-0123abcd/anyhow-1.0.103/src/lib.rs",
        ]))
        .expect("parse rustc args");
        let semantic_request = crate::fetch::SemanticFetchRequest {
            crate_name: "anyhow".to_owned(),
            version: "1.0.103".to_owned(),
            features_json: bundle.manifest.config.features_json.raw(),
            dependency_c_metadata_json: bundle.manifest.config.dependency_c_metadata_json.raw(),
            target: "aarch64-apple-darwin".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            profile: bundle.manifest.config.profile.clone(),
            emit: bundle.manifest.config.emit.clone(),
            kind: bundle.manifest.config.kind.clone(),
            crate_types: bundle.manifest.config.crate_types.clone(),
            consumer: stow_types::upload_plan::ConsumerInputs::stock(),
            build_script: stow_types::upload_plan::BuildScriptInputs::default(),
        };

        let mut tally = super::LookupTally::default();
        let served = super::try_serve_local_semantic_cached_bundle(
            &config,
            &parsed,
            &super::UnitSource::CratesIo {
                package: "anyhow".to_owned(),
                version: "1.0.103".to_owned(),
            },
            &semantic_request,
            &mut tally,
        )
        .await;
        assert!(served.is_none(), "another version's entry cannot serve");
        assert!(
            !tally.failed,
            "finding no entry for this invocation is not a failure"
        );

        let summary = crate::stats::read_summary(&config)
            .await
            .expect("read the stats summary");
        assert_eq!(
            summary.rust_lookups(),
            0,
            "an entry of another version records no outcome for the crate"
        );
    }

    /// A `StowConfig` whose every path and endpoint is a throwaway — the
    /// env-base tests' shared fixture. Its windows outlast any test, so a
    /// slice written fresh stays fresh and a negative-cache entry stays
    /// recorded however slow the runner; a test that wants either expired
    /// sets it to zero (stow#806).
    fn env_base_test_config(dir: &tempfile::TempDir) -> crate::config::StowConfig {
        crate::config::StowConfig {
            cache: crate::config::CacheLayers::default(),
            edge_url: "http://127.0.0.1:9".to_owned(),
            registry_base_url: "http://127.0.0.1:9".to_owned(),
            cache_dir: dir.path().join("cache"),
            request_timeout: std::time::Duration::from_millis(50),
            negative_cache_ttl: std::time::Duration::from_mins(10),
            circuit_reset_after: std::time::Duration::from_mins(10),
            circuit_trip_threshold: 1,
            artifact_cache_max_bytes: 1,
            index_refresh_interval: std::time::Duration::from_mins(10),
            verify_mode: crate::config::VerifyMode::GithubCi,
            state_db: crate::state_db::StateDb::default(),
            trust_material: std::sync::Arc::default(),
            registry_http: std::sync::Arc::default(),
            artifact_cache_staging: std::sync::Arc::default(),
        }
    }

    /// The shared `rustc -vV` the driver hands these tests.
    fn test_shared_vv() -> crate::rustc_args::SharedRustcVv {
        crate::rustc_args::shared_rustc_vv(std::ffi::OsString::from("rustc"))
    }

    /// The real rustc's path — `PATH` order and the platform's own
    /// executable rules, as the OS resolves cargo's bare spelling —
    /// used as the seeded base's executable.
    fn real_rustc_path() -> std::path::PathBuf {
        which::which("rustc").expect("the test machine has rustc on PATH")
    }

    /// A `WrapperEnvCache` whose `PATH` is the test's injected value.
    fn test_cache(path: &std::ffi::OsStr) -> super::WrapperEnvCache {
        super::WrapperEnvCache {
            seeded: std::sync::Mutex::new(None),
            env_bases: super::MemoizedBaseMap::default(),
            local_bases: super::MemoizedBaseMap::default(),
            host_targets: super::MemoizedHostMap::default(),
            path: path.to_os_string(),
            slices: super::MemoizedSliceMap::default(),
            circuit: crate::circuit::BuildCircuit::new(),
            state_db: crate::state_db::StateDb::default(),
            git_commits: std::sync::Mutex::new(std::collections::HashMap::new()),
            native_cpus: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// stow#608 A1: a seeded base computed from the driver's rustc and a
    /// lazily resolved one for the same spelling are the same base. The
    /// seeded base must carry exactly the facts the lazy path computes —
    /// the same executable spelling, the machine's own host triple
    /// (never the consumer target a `--target` build compiles for) and
    /// the same release string.
    #[tokio::test]
    async fn the_seeded_env_base_matches_the_lazy_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = env_base_test_config(&dir);
        let shared_vv = test_shared_vv();
        let rustc = real_rustc_path();
        let build_rustc = crate::rustc_args::BuildRustc::Configured(rustc.clone().into_os_string());
        let Some(seeded) = super::supervisor_env_base(&config, &shared_vv, &build_rustc)
            .await
            .expect("the seeded env base must build on a machine with rustc")
        else {
            panic!("the seeded env base must exist on a machine with rustc");
        };
        let Some(lazy) = super::load_wrapper_env_base(
            rustc.as_os_str(),
            config,
            crate::rustc_args::rustc_host_target(rustc.as_os_str()),
        )
        .await
        else {
            panic!("the lazy env base must build on the same rustc");
        };
        assert_eq!(seeded.rustc, lazy.rustc);
        assert_eq!(seeded.host_target, lazy.host_target);
        assert_eq!(seeded.rustc_version, lazy.rustc_version);
    }

    /// A spelling that does not resolve to the seeded file is probed —
    /// but exactly once, however many frames carry it (stow#608 A1).
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unseeded_spelling_loads_its_base_exactly_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = env_base_test_config(&dir);
        let shared_vv = test_shared_vv();
        let rustc = real_rustc_path();
        let build_rustc = crate::rustc_args::BuildRustc::Configured(rustc.clone().into_os_string());
        let Some(seeded) = super::supervisor_env_base(&config, &shared_vv, &build_rustc)
            .await
            .expect("seeded env base")
        else {
            panic!("the seeded env base must exist");
        };
        // A second spelling naming a different file that still answers
        // `rustc -vV` — a thin script in a directory of its own.
        let tools = tempfile::tempdir().expect("tools");
        let fake = tools.path().join("other-rustc");
        std::fs::write(&fake, "#!/bin/sh\nexec rustc \"$@\"\n").expect("write fake rustc");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755))
                .expect("chmod fake rustc");
        }

        let cache = test_cache(std::ffi::OsStr::new(""));
        cache.seed(std::sync::Arc::new(seeded));
        let loads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = {
            let loads = loads.clone();
            let config = config.clone();
            move |_state_db| {
                loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(config.clone())
            }
        };
        for _ in 0..4 {
            let base = cache
                .base(&cache.env_bases, fake.as_os_str(), &counted)
                .await;
            assert!(
                base.is_some(),
                "the unseeded spelling still resolves a base"
            );
        }
        assert_eq!(
            loads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "four frames loaded the unseeded spelling's base exactly once"
        );
    }

    /// A spelling that reaches the seed's file through a symlinked
    /// directory adopts the seed — zero loads (stow#608 A1).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_spelling_through_a_symlinked_dir_adopts_the_seed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = env_base_test_config(&dir);
        let shared_vv = test_shared_vv();
        let rustc = real_rustc_path();
        let build_rustc = crate::rustc_args::BuildRustc::Configured(rustc.clone().into_os_string());
        let Some(seeded) = super::supervisor_env_base(&config, &shared_vv, &build_rustc)
            .await
            .expect("seeded env base")
        else {
            panic!("the seeded env base must exist");
        };
        let seeded = std::sync::Arc::new(seeded);

        let link_dir = tempfile::tempdir().expect("link dir");
        std::os::unix::fs::symlink(
            rustc.parent().expect("rustc has a parent"),
            link_dir.path().join("bin"),
        )
        .expect("symlink bin dir");
        let spelling = link_dir.path().join("bin").join("rustc");

        let cache = test_cache(std::ffi::OsStr::new(""));
        cache.seed(seeded.clone());
        let loads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = {
            let loads = loads.clone();
            move |_state_db| {
                loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                unreachable!("the adopted seed never loads")
            }
        };
        let base = cache
            .base(&cache.env_bases, spelling.as_os_str(), &counted)
            .await
            .expect("the symlinked spelling adopts the seed");
        assert!(
            std::sync::Arc::ptr_eq(&base, &seeded),
            "the adopted base IS the seeded base"
        );
        assert_eq!(loads.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// A bare `rustc` found on the injected `PATH` adopts the seed —
    /// cargo's spelling on any non-rustup toolchain (stow#608 A1).
    #[tokio::test]
    async fn a_bare_spelling_on_the_injected_path_adopts_the_seed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = env_base_test_config(&dir);
        let shared_vv = test_shared_vv();
        let rustc = real_rustc_path();
        let build_rustc = crate::rustc_args::BuildRustc::Configured(rustc.clone().into_os_string());
        let Some(seeded) = super::supervisor_env_base(&config, &shared_vv, &build_rustc)
            .await
            .expect("seeded env base")
        else {
            panic!("the seeded env base must exist");
        };
        let seeded = std::sync::Arc::new(seeded);

        let path =
            std::env::join_paths([rustc.parent().expect("rustc has a parent")]).expect("join PATH");
        let cache = test_cache(&path);
        cache.seed(seeded.clone());
        let loads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = {
            let loads = loads.clone();
            move |_state_db| {
                loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                unreachable!("the adopted seed never loads")
            }
        };
        let base = cache
            .base(&cache.env_bases, std::ffi::OsStr::new("rustc"), &counted)
            .await
            .expect("the bare spelling adopts the seed");
        assert!(std::sync::Arc::ptr_eq(&base, &seeded));
        assert_eq!(loads.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// An empty index under the fixture header — the slice-memo tests
    /// need a cached slice's presence, not its rows (stow#735).
    fn empty_test_index(target: &str, rustc: &str) -> stow_types::index::ArtifactIndex {
        stow_types::index::ArtifactIndex {
            header: stow_types::index::ArtifactIndexHeader {
                format_version: stow_types::index::ARTIFACT_INDEX_FORMAT_VERSION,
                target: stow_types::identity::TargetTriple::parse(target).expect("target"),
                rustc_version: stow_types::identity::WireRustcVersion::parse(rustc)
                    .expect("rustc version"),
                generated_at: "2026-10-14T00:00:00Z".to_owned(),
                generation: 1,
                row_count: 0,
            },
            rows: Vec::new(),
        }
    }

    /// stow#735: a slice the build is still fetching is not "absent"
    /// yet — the first lookup parks on `serve_map_ready`, reads the
    /// cache once more when the fetch settles, and that second answer
    /// is what the memo keeps.
    #[tokio::test]
    async fn a_missing_slice_waits_for_the_builds_fetch() {
        const TARGET: &str = "x86_64-unknown-linux-gnu";
        const RUSTC: &str = "1.91.1";
        let dir = tempfile::tempdir().expect("tempdir");
        let config = env_base_test_config(&dir);
        let cache = test_cache(std::ffi::OsStr::new(""));
        let signal = std::sync::Arc::new(crate::facade::ServeMapSignal::pending());

        // The lookup starts while the slice is still absent: it must
        // not answer before the build's fetch has settled — it parks on
        // the signal, and from there only the settle answers it.
        let mut lookup = std::pin::pin!(cache.slice(&config, TARGET, RUSTC, &signal));
        tokio::select! {
            biased;
            _ = &mut lookup => {
                panic!("the lookup answered while the build's fetch was still in flight")
            }
            () = signal.parked(1) => {}
        }
        let digest = crate::index::write_cached_test_slice(
            &config,
            TARGET,
            RUSTC,
            &empty_test_index(TARGET, RUSTC),
        )
        .await
        .expect("write the slice the fetch landed");
        signal.complete();
        let memo = lookup.await.expect("read the cached slice");
        let (slice, fetch_pending) = memo.read();
        assert_eq!(
            slice
                .expect("the slice the fetch landed is served")
                .slice
                .manifest_digest
                .as_deref(),
            Some(digest.as_str())
        );
        assert!(
            !fetch_pending,
            "the fetch the fill-time wait covered has settled"
        );
    }

    /// stow#735: once the build's fetch has settled, absence is final —
    /// the memoized `None` answers every later lookup for the build,
    /// even after a slice lands.
    #[tokio::test]
    async fn a_settled_absence_is_memoized_for_the_build() {
        const TARGET: &str = "x86_64-unknown-linux-gnu";
        const RUSTC: &str = "1.91.1";
        let dir = tempfile::tempdir().expect("tempdir");
        let config = env_base_test_config(&dir);
        let cache = test_cache(std::ffi::OsStr::new(""));
        let signal = std::sync::Arc::new(crate::facade::ServeMapSignal::settled());

        assert!(
            cache
                .slice(&config, TARGET, RUSTC, &signal)
                .await
                .expect("read the cached slice")
                .read()
                .0
                .is_none(),
            "no slice once the fetch has settled reads as absent"
        );
        crate::index::write_cached_test_slice(
            &config,
            TARGET,
            RUSTC,
            &empty_test_index(TARGET, RUSTC),
        )
        .await
        .expect("write a slice after the settled answer");
        assert!(
            cache
                .slice(&config, TARGET, RUSTC, &signal)
                .await
                .expect("read the cached slice")
                .read()
                .0
                .is_none(),
            "the settled absence is memoized for the rest of the build"
        );
    }

    /// stow#797: a stale-but-readable slice memoizes at once — a hit on
    /// it never waits for the in-flight fetch — and the memo carries the
    /// pending flag the miss path reads.
    #[tokio::test]
    async fn a_pending_slice_memoizes_at_once_flagged() {
        const TARGET: &str = "x86_64-unknown-linux-gnu";
        const RUSTC: &str = "1.91.1";
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = env_base_test_config(&dir);
        // A zero interval keeps every cached slice's fetch pending —
        // the rule `fetch_slice` itself applies (stow#788).
        config.index_refresh_interval = std::time::Duration::ZERO;
        let digest = crate::index::write_cached_test_slice(
            &config,
            TARGET,
            RUSTC,
            &empty_test_index(TARGET, RUSTC),
        )
        .await
        .expect("write the stale slice");
        let cache = test_cache(std::ffi::OsStr::new(""));
        let signal = std::sync::Arc::new(crate::facade::ServeMapSignal::pending());

        // The signal stays pending for the whole test: if the fill
        // waited on it, this read could never answer.
        let memo = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            cache.slice(&config, TARGET, RUSTC, &signal),
        )
        .await
        .expect("a readable slice answers without waiting on the fetch")
        .expect("read the cached slice");
        let (slice, fetch_pending) = memo.read();
        assert_eq!(
            slice
                .expect("the stale slice serves")
                .slice
                .manifest_digest
                .as_deref(),
            Some(digest.as_str())
        );
        assert!(
            fetch_pending,
            "a slice whose fetch is in flight memoizes flagged pending"
        );
    }

    /// The wrapper environment a remote-serve test needs: a real env
    /// base over `config`, the build's `env_cache`, and an exact-only
    /// request keyed by `c_metadata` — the dead test registry stands in
    /// for the edge (stow#797).
    async fn serve_env<'a>(
        config: &crate::config::StowConfig,
        env_cache: &'a super::WrapperEnvCache,
        target: &str,
        rustc_version: &str,
        c_metadata: &str,
    ) -> super::WrapperEnvironment<'a> {
        config.ensure_dirs().await.expect("ensure cache dirs");
        let env_base = std::sync::Arc::new(super::WrapperEnvBase {
            rustc: OsString::from("rustc"),
            config: config.clone(),
            host_target: target.to_owned(),
            rustc_version: rustc_version.to_owned(),
            _version_lease: crate::prepare_local_cache(config, rustc_version)
                .await
                .expect("prepare local cache"),
        });
        super::WrapperEnvironment {
            env_base,
            env_cache,
            circuit_tripped: false,
            target: target.to_owned(),
            rustc_version: rustc_version.to_owned(),
            cache_key: format!("{target}/{rustc_version}/{c_metadata}"),
            request_c_metadata: c_metadata.to_owned(),
            semantic_request: None,
            host_glibc: None,
            source: super::UnitSource::CratesIo {
                package: "anyhow".to_owned(),
                version: "1.0.104".to_owned(),
            },
        }
    }

    /// The `BuildContext` the serve tests drive — no policy, no
    /// analysis facts, `serve_map_ready` under the test's control.
    fn serve_ctx(
        serve_map_ready: &std::sync::Arc<crate::facade::ServeMapSignal>,
    ) -> super::BuildContext {
        super::BuildContext {
            policy_dir: None,
            public_cache_target: None,
            public_cache_disabled: false,
            cache: crate::config::CacheLayers::default(),
            analysis: std::sync::Arc::new(std::sync::OnceLock::from(super::AnalysisFacts {
                semantic_fallback_enabled: false,
                unit_nodes: None,
                prefetch_candidates: std::collections::BTreeMap::new(),
            })),
            serve_map_ready: std::sync::Arc::clone(serve_map_ready),
            policy_ready: std::sync::Arc::new(crate::facade::ServeMapSignal::settled()),
            in_flight: crate::supervisor::server::InFlightUnits::default(),
            registry_sources: std::sync::OnceLock::from(crate::RegistrySources::CargoConfig(
                std::iter::once("index.crates.io".to_owned()).collect(),
            )),
        }
    }

    /// The argv of one registry lib unit — enough for the parser; the
    /// serves themselves key on `request.c_metadata`.
    fn serve_args(target: &str, c_metadata: &str) -> Vec<OsString> {
        vec![
            OsString::from("--crate-name"),
            OsString::from("demo"),
            OsString::from("--crate-type"),
            OsString::from("lib"),
            OsString::from("--emit"),
            OsString::from("dep-info,metadata,link"),
            OsString::from("-C"),
            OsString::from(format!("metadata={c_metadata}")),
            OsString::from("--target"),
            OsString::from(target),
            OsString::from("lib.rs"),
        ]
    }

    /// stow#1044: a downloaded bundle that cannot be materialized locally
    /// is a local failure — the transport worked — so it is reported and
    /// evicted but never counted against the circuit breaker (threshold 1
    /// here, so a single recorded failure would trip it).
    #[tokio::test]
    async fn a_local_materialization_failure_leaves_the_circuit_closed() {
        const TARGET: &str = "aarch64-apple-darwin";
        const RUSTC: &str = "1.91.1";
        const C_METADATA: &str = "aabbccddeeff0011";
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = env_base_test_config(&dir);
        config.artifact_cache_max_bytes = u64::MAX;
        let env_cache = test_cache(std::ffi::OsStr::new(""));
        let env = serve_env(&config, &env_cache, TARGET, RUSTC, C_METADATA).await;
        let request = crate::fetch::FetchRequest {
            target: TARGET,
            rustc_version: RUSTC,
            c_metadata: C_METADATA,
        };
        let bundle = crate::artifact_cache::tests::sample_bundle(
            C_METADATA,
            "libdemo-aabbccddeeff0011.rmeta",
        );
        let cached = crate::artifact_cache::store_downloaded_bundle(&config, &request, &bundle)
            .await
            .expect("store the bundle");
        // The argv carries no `--out-dir`, so materializing must fail.
        let parsed =
            ParsedRustcArgs::parse(&serve_args(TARGET, C_METADATA)).expect("parse the unit args");
        let mut tally = super::LookupTally::default();

        let served =
            super::materialize_downloaded_bundle(&env, &parsed, &request, cached, &mut tally).await;

        assert!(served.is_none());
        assert!(tally.failed, "the failure is still reported");
        assert!(
            !crate::circuit::is_tripped(&config)
                .await
                .expect("read the circuit"),
            "a local materialization failure opened the circuit"
        );
    }

    /// stow#797: a lookup that misses on a stale slice whose fetch is
    /// still in flight parks on `serve_map_ready`, writes no
    /// negative-cache entry while parked, and retries once on the
    /// fetched slice. Here the retry reaches the row's bundle fetch —
    /// which the dead test registry refuses (`tally.failed`) — and the
    /// memo serves the fresh row to every later invocation.
    #[tokio::test]
    async fn a_miss_on_a_pending_slice_retries_the_fetched_answer() {
        const TARGET: &str = "x86_64-unknown-linux-gnu";
        const RUSTC: &str = "1.91.1";
        const C_METADATA: &str = "cd800a14379e5df9";
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = env_base_test_config(&dir);
        // A zero interval keeps the cached slice's fetch pending — the
        // stale-slice miss this test drives (stow#788).
        config.index_refresh_interval = std::time::Duration::ZERO;
        crate::index::write_cached_test_slice(
            &config,
            TARGET,
            RUSTC,
            &empty_test_index(TARGET, RUSTC),
        )
        .await
        .expect("write the stale slice the build starts with");
        let signal = std::sync::Arc::new(crate::facade::ServeMapSignal::pending());
        let env_cache = test_cache(std::ffi::OsStr::new(""));
        let env = serve_env(&config, &env_cache, TARGET, RUSTC, C_METADATA).await;
        let ctx = serve_ctx(&signal);
        let parsed =
            ParsedRustcArgs::parse(&serve_args(TARGET, C_METADATA)).expect("parse the unit args");
        let request = crate::fetch::FetchRequest {
            target: TARGET,
            rustc_version: RUSTC,
            c_metadata: C_METADATA,
        };
        let mut tally = super::LookupTally::default();

        // The stale slice lacks the row, but its fetch is still in
        // flight — the miss must wait for it, not answer. The block
        // scopes the pinned future so its `tally` borrow ends before
        // the tally is checked.
        let outcome = {
            let mut serve = std::pin::pin!(super::try_remote_serves(
                &env, &parsed, &request, &ctx, true, &mut tally,
            ));
            tokio::select! {
                biased;
                _ = &mut serve => {
                    panic!("the lookup missed on a pending slice without waiting for the fetch")
                }
                () = signal.parked(1) => {}
            }
            assert!(
                !crate::circuit::negative_cache_contains(&config, &env.cache_key)
                    .await
                    .expect("read the negative cache"),
                "a pending miss wrote a negative-cache entry"
            );

            // The fetch lands the row the stale slice lacked, then the
            // map settles — the order the enrichment writes it.
            let mut index = empty_test_index(TARGET, RUSTC);
            index.rows.push(crate::index::index_test_row(C_METADATA));
            index.header.row_count = 1;
            crate::index::write_cached_test_slice(&config, TARGET, RUSTC, &index)
                .await
                .expect("write the slice the fetch landed");
            signal.complete();
            serve.await
        };

        // The retry finds the row: the bundle fetch it then pays fails
        // on the dead test registry, which `tally.failed` records.
        assert!(matches!(outcome, super::RemoteServe::Miss));
        assert!(
            tally.failed,
            "the retry must reach the fetched row's bundle fetch"
        );

        // And the memo now serves the fetched slice to the whole build.
        let (slice, fetch_pending) = env_cache
            .slice(&config, TARGET, RUSTC, &signal)
            .await
            .expect("read the memoized slice")
            .read();
        assert!(!fetch_pending, "the settled fetch is no longer pending");
        assert!(
            slice
                .expect("the fetched slice")
                .exact_row(C_METADATA)
                .is_some(),
            "later invocations see the row the fetch landed"
        );
    }

    /// stow#797: a miss on a slice whose fetch is not pending is the old
    /// answer — immediate, `serve_map_ready` never awaited, and the
    /// negative cache records it as it always has.
    #[tokio::test]
    async fn a_miss_on_a_settled_slice_never_waits() {
        const TARGET: &str = "x86_64-unknown-linux-gnu";
        const RUSTC: &str = "1.91.1";
        const C_METADATA: &str = "cd800a14379e5df9";
        let dir = tempfile::tempdir().expect("tempdir");
        let config = env_base_test_config(&dir);
        crate::index::write_cached_test_slice(
            &config,
            TARGET,
            RUSTC,
            &empty_test_index(TARGET, RUSTC),
        )
        .await
        .expect("write the fresh slice");
        // The signal stays pending for the whole test — a wait on it
        // would hang, so the timeout *is* the assertion.
        let signal = std::sync::Arc::new(crate::facade::ServeMapSignal::pending());
        let env_cache = test_cache(std::ffi::OsStr::new(""));
        let env = serve_env(&config, &env_cache, TARGET, RUSTC, C_METADATA).await;
        let ctx = serve_ctx(&signal);
        let parsed =
            ParsedRustcArgs::parse(&serve_args(TARGET, C_METADATA)).expect("parse the unit args");
        let request = crate::fetch::FetchRequest {
            target: TARGET,
            rustc_version: RUSTC,
            c_metadata: C_METADATA,
        };
        let mut tally = super::LookupTally::default();

        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            super::try_remote_serves(&env, &parsed, &request, &ctx, true, &mut tally),
        )
        .await
        .expect("a miss on a settled slice must not wait on serve_map_ready");
        assert!(matches!(outcome, super::RemoteServe::Miss));
        assert!(!tally.failed);
        assert!(
            crate::circuit::negative_cache_contains(&config, &env.cache_key)
                .await
                .expect("read the negative cache"),
            "a settled miss records its negative-cache entry"
        );
    }

    /// stow#615: the consumer's compile key is computed over the command
    /// line's `--cfg feature="…"` scan — the same bytes the builder's
    /// capture hands
    /// `stable_unit_identity_for_package` — whatever the
    /// unit graph's resolved set says. A build script's
    /// `cargo:rustc-cfg=feature="…"` output rides the scan and lands in
    /// the key; the graph never enters the identity at all.
    #[tokio::test]
    async fn the_compile_key_is_the_command_lines_scan() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let config = crate::config::StowConfig {
            cache: crate::config::CacheLayers::default(),
            edge_url: "http://127.0.0.1:9".to_owned(),
            registry_base_url: "http://127.0.0.1:9".to_owned(),
            cache_dir: tempdir.path().to_path_buf(),
            request_timeout: std::time::Duration::from_millis(200),
            negative_cache_ttl: std::time::Duration::ZERO,
            circuit_reset_after: std::time::Duration::ZERO,
            circuit_trip_threshold: 1,
            artifact_cache_max_bytes: 0,
            index_refresh_interval: std::time::Duration::ZERO,
            verify_mode: crate::config::VerifyMode::GithubCi,
            state_db: crate::state_db::StateDb::default(),
            trust_material: std::sync::Arc::default(),
            registry_http: std::sync::Arc::default(),
            artifact_cache_staging: std::sync::Arc::default(),
        };
        // A scan shaped like a build-script crate's: `default` resolved
        // plus `probe_from_build_script` the script printed itself.
        let parsed = ParsedRustcArgs::parse(&args(&[
            "--crate-name",
            "lexicon",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "--cfg",
            "feature=\"default\"",
            "--cfg",
            "feature=\"probe_from_build_script\"",
            "-C",
            "metadata=abc123",
            "-C",
            "extra-filename=-xyz789",
            "/root/.cargo/registry/src/index.crates.io-0123abcd/lexicon-0.9.6/src/lib.rs",
        ]))
        .expect("parse rustc args");

        let (identity, _reach) = super::build_stable_exact_identity(
            &config,
            &parsed,
            &stow_types::public_cache::UnitSource::CratesIo {
                package: "lexicon".to_owned(),
                version: "0.9.6".to_owned(),
            },
            false,
            "x86_64-unknown-linux-gnu",
            "1.99.0",
        )
        .await
        .expect("identity resolves")
        .expect("registry unit");

        // The builder's key for the same command line: the capture path
        // serializes the scan and hashes it into the compile key
        // verbatim.
        let scan_features_json =
            serde_json::to_string(&parsed.features.iter().cloned().collect::<Vec<_>>())
                .expect("serialize the scan");
        let builder_identity = stow_types::public_cache::stable_unit_identity_for_package(
            &parsed,
            "lexicon",
            "0.9.6",
            "x86_64-unknown-linux-gnu",
            "1.99.0",
            &scan_features_json,
            "[]",
        )
        .expect("builder identity");
        assert_eq!(identity.compile_key, builder_identity.compile_key);
        assert_eq!(identity.c_metadata, builder_identity.c_metadata);
        assert_eq!(
            scan_features_json, "[\"default\",\"probe_from_build_script\"]",
            "the scan, not the resolved set, is what the key covers"
        );
    }

    /// The process environment is global and the harness runs tests on
    /// several threads, so every test that touches the table variables
    /// holds this for its whole body — one test's `set_var` must never
    /// land inside another's assertion.
    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static GUARD: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        GUARD
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// stow#625: unset table variables read as no table, exactly as the
    /// inline payloads did.
    #[test]
    fn unset_table_variables_carry_no_table() {
        let _guard = env_guard();
        unsafe {
            std::env::remove_var(super::STOW_EXPANDED_GRAPH_PATH_ENV);
            std::env::remove_var(super::STOW_PREFETCH_ARTIFACTS_PATH_ENV);
        }
        let ctx = super::BuildContext::from_env().expect("unset reads as no table");
        assert!(ctx.unit_nodes().is_none());
        assert!(
            ctx.prefetch_candidates()
                .expect("the facts cell is filled")
                .is_empty()
        );
    }

    /// stow#625: a set variable whose file is missing is a wiring bug —
    /// the same loud failure a malformed inline payload was — naming the
    /// path.
    #[test]
    fn a_missing_table_file_fails_loudly_naming_the_path() {
        let _guard = env_guard();
        let missing = PathBuf::from("/definitely/missing/table.json");
        let missing_display = missing.display().to_string();
        for env in [
            super::STOW_EXPANDED_GRAPH_PATH_ENV,
            super::STOW_PREFETCH_ARTIFACTS_PATH_ENV,
        ] {
            unsafe { std::env::set_var(env, &missing) };
            let error = super::BuildContext::from_env()
                .expect_err("a set variable whose file is missing fails loudly");
            unsafe { std::env::remove_var(env) };
            let message = error.to_string();
            assert!(
                message.contains(env) && message.contains(&missing_display),
                "the error names the variable and the path: {message}"
            );
        }
    }

    /// stow#625: a set variable whose file is not the table's JSON is the
    /// same wiring bug, naming the path.
    #[test]
    fn a_malformed_table_file_fails_loudly_naming_the_path() {
        let _guard = env_guard();
        let dir = tempfile::tempdir().expect("tempdir");
        let malformed = dir.path().join("malformed.json");
        let malformed_display = malformed.display().to_string();
        std::fs::write(&malformed, "not a json table").expect("write malformed file");
        for env in [
            super::STOW_EXPANDED_GRAPH_PATH_ENV,
            super::STOW_PREFETCH_ARTIFACTS_PATH_ENV,
        ] {
            unsafe { std::env::set_var(env, &malformed) };
            let error =
                super::BuildContext::from_env().expect_err("a malformed table file fails loudly");
            unsafe { std::env::remove_var(env) };
            let message = error.to_string();
            assert!(
                message.contains(env) && message.contains(&malformed_display),
                "the error names the variable and the path: {message}"
            );
        }
    }

    /// stow#618: a dependent's post-compile bookkeeping must wait for the
    /// bookkeeping of the dependencies it was built against — an
    /// `--extern` whose rows are still being written is a pending write,
    /// not a missing one. These tests drive the real supervisor over the
    /// real socket with `Observed` frames, a real `BuildSupervisor`, and
    /// a temp-dir cache — cargo-free end to end.
    mod in_flight_ordering {
        use std::ffi::{OsStr, OsString};
        use std::path::Path;
        use std::sync::Arc;
        use std::time::Duration;

        use crate::supervisor::protocol::{Observed, Request, write_frame};
        use crate::supervisor::{Endpoint, server, server::Handler as _};
        use crate::{AnalysisFacts, BuildContext, BuildSupervisor, WrapperEnvBase};

        /// A `tracing` writer whose buffer the test can inspect — the
        /// assertions on what the post-compile logged read it back.
        #[derive(Clone)]
        struct SharedLog(Arc<std::sync::Mutex<Vec<u8>>>);

        impl SharedLog {
            fn text(&self) -> String {
                String::from_utf8_lossy(&self.0.lock().expect("log buffer")).into_owned()
            }
        }

        impl std::io::Write for SharedLog {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().expect("log buffer").extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        /// The global default under every capture: it enables nothing and
        /// answers every callsite "sometimes", so each event asks the
        /// dispatcher current on its own thread.
        ///
        /// tracing-core caches a callsite's interest process-wide when the
        /// callsite is first reached. While a single dispatcher is
        /// registered it takes that interest from whichever thread got
        /// there first: a concurrent test thread with no subscriber caches
        /// `never` for a production callsite a capture on another thread is
        /// waiting for, and the capture never sees the event. With this
        /// subscriber as the global default no thread answers `never`.
        struct UndecidedInterest;

        impl tracing::Subscriber for UndecidedInterest {
            fn register_callsite(
                &self,
                _: &'static tracing::Metadata<'static>,
            ) -> tracing::subscriber::Interest {
                tracing::subscriber::Interest::sometimes()
            }
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                false
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, _: &tracing::Event<'_>) {}
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }

        /// Capture this thread's events at `level` and above until the
        /// guard drops, immune to other tests reaching the same callsites
        /// first (see [`UndecidedInterest`]).
        fn capture_logs(level: tracing::Level) -> (SharedLog, tracing::subscriber::DefaultGuard) {
            // The first capture installs it and every later one finds it
            // in place: nothing else in the lib tests sets a global
            // default, so a refusal only means it is already there.
            let _ = tracing::subscriber::set_global_default(UndecidedInterest);
            let log = SharedLog(Arc::new(std::sync::Mutex::new(Vec::new())));
            let writer = log.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(level)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            (log, tracing::subscriber::set_default(subscriber))
        }

        /// The shared `--out-dir` both fixture units compile into, cargo's
        /// deps-dir shape.
        const HOST_TARGET: &str = "aarch64-apple-darwin";
        const RUSTC_VERSION: &str = "1.91.1";

        fn test_config(root: &Path) -> crate::config::StowConfig {
            crate::config::StowConfig {
                cache: crate::config::CacheLayers::default(),
                edge_url: "http://127.0.0.1:9".to_owned(),
                registry_base_url: "http://127.0.0.1:9".to_owned(),
                cache_dir: root.join(".stow"),
                request_timeout: Duration::from_millis(200),
                // Long enough that a recorded miss is still there when a
                // test reads it back.
                negative_cache_ttl: Duration::from_mins(10),
                circuit_reset_after: Duration::ZERO,
                circuit_trip_threshold: 1,
                artifact_cache_max_bytes: u64::MAX,
                index_refresh_interval: Duration::ZERO,
                verify_mode: crate::config::VerifyMode::GithubCi,
                state_db: crate::state_db::StateDb::default(),
                trust_material: std::sync::Arc::default(),
                registry_http: std::sync::Arc::default(),
                artifact_cache_staging: std::sync::Arc::default(),
            }
        }

        /// The argv a rustc-wrapper frame carries for one registry lib
        /// unit; `metadata` is cargo's `-C metadata`, which names the
        /// output files and the externs that point at them.
        fn unit_args(
            registry_src: &Path,
            out_dir: &Path,
            package: &str,
            version: &str,
            metadata: &str,
            externs: &[(&str, &Path)],
        ) -> Vec<OsString> {
            let mut argv = vec![
                OsString::from("--crate-name"),
                OsString::from(package.replace('-', "_")),
                OsString::from("--crate-type"),
                OsString::from("lib"),
                OsString::from("--emit"),
                OsString::from("dep-info,metadata,link"),
                OsString::from("--out-dir"),
                out_dir.as_os_str().to_os_string(),
                OsString::from("-C"),
                OsString::from(format!("metadata={metadata}")),
                OsString::from("-C"),
                OsString::from(format!("extra-filename=-{metadata}")),
                OsString::from("--target"),
                OsString::from(HOST_TARGET),
                registry_src
                    .join(format!(
                        "index.crates.io-0123abcd/{package}-{version}/src/lib.rs"
                    ))
                    .into_os_string(),
            ];
            for (name, path) in externs {
                argv.push(OsString::from(format!(
                    "--extern={name}={}",
                    path.display()
                )));
            }
            argv
        }

        /// The output files a successful rustc would have left behind.
        fn write_outputs(out_dir: &Path, package: &str, metadata: &str) {
            let stem = package.replace('-', "_");
            std::fs::write(
                out_dir.join(format!("lib{stem}-{metadata}.rlib")),
                b"rlib-bytes",
            )
            .expect("write rlib");
            std::fs::write(
                out_dir.join(format!("lib{stem}-{metadata}.rmeta")),
                b"rmeta-bytes",
            )
            .expect("write rmeta");
        }

        /// A `BuildSupervisor` whose bases for the `rustc` spelling the
        /// fixture's frames carry are already memoized with a temp-dir
        /// config — the cells are set, so `observed` and `plan` never
        /// touch the process environment or probe a toolchain.
        async fn fixture(
            root: &Path,
        ) -> (
            crate::config::StowConfig,
            server::InFlightUnits,
            Arc<BuildSupervisor>,
        ) {
            fixture_ctx(root, |in_flight| BuildContext {
                policy_dir: None,
                public_cache_target: Some(HOST_TARGET.to_owned()),
                public_cache_disabled: false,
                cache: crate::config::CacheLayers::default(),
                analysis: std::sync::Arc::new(std::sync::OnceLock::from(AnalysisFacts {
                    semantic_fallback_enabled: false,
                    unit_nodes: None,
                    prefetch_candidates: std::collections::BTreeMap::new(),
                })),
                serve_map_ready: std::sync::Arc::new(crate::facade::ServeMapSignal::settled()),
                policy_ready: std::sync::Arc::new(crate::facade::ServeMapSignal::settled()),
                in_flight: in_flight.clone(),
                registry_sources: std::sync::OnceLock::from(crate::RegistrySources::CargoConfig(
                    std::iter::once("index.crates.io".to_owned()).collect(),
                )),
            })
            .await
        }

        /// [`fixture`] with the caller's `BuildContext` — the
        /// policy-race tests drive `policy_dir`/`policy_ready`
        /// (stow#788).
        async fn fixture_ctx(
            root: &Path,
            ctx: impl FnOnce(&server::InFlightUnits) -> BuildContext,
        ) -> (
            crate::config::StowConfig,
            server::InFlightUnits,
            Arc<BuildSupervisor>,
        ) {
            let config = test_config(root);
            config.ensure_dirs().await.expect("ensure cache dirs");
            let base = Arc::new(WrapperEnvBase {
                rustc: OsString::from("rustc"),
                config: config.clone(),
                host_target: HOST_TARGET.to_owned(),
                rustc_version: RUSTC_VERSION.to_owned(),
                _version_lease: crate::prepare_local_cache(&config, RUSTC_VERSION)
                    .await
                    .expect("prepare local cache"),
            });
            let in_flight = server::InFlightUnits::default();
            let env_cache = crate::WrapperEnvCache::new(config.state_db.clone());
            // Both base maps get the fixture's cell: an unset cell loads
            // through `StowConfig::load`, which reads the developer's
            // `~/.stow` — a real index slice for the host there would
            // serve the fixture's units from state the test never wrote
            // (stow#800).
            let cell = Arc::new(tokio::sync::OnceCell::from(Some(base)));
            for map in [&env_cache.local_bases, &env_cache.env_bases] {
                map.lock()
                    .expect("env base map mutex")
                    .insert(OsString::from("rustc"), Arc::clone(&cell));
            }
            let handler = Arc::new(BuildSupervisor {
                env_cache,
                ctx: ctx(&in_flight),
                observations: std::sync::Mutex::new(Vec::new()),
                resolution_done: crate::ResolutionDone::pending(),
            });
            (config, in_flight, handler)
        }

        /// The raw facade transport: `Observed` frames are one-way, so
        /// the test writes them itself rather than going through the
        /// client connection.
        #[cfg(unix)]
        async fn connect_raw(endpoint: &Endpoint) -> tokio::net::UnixStream {
            let Endpoint::Unix(path) = endpoint else {
                panic!("the unix transport is the only one this platform starts");
            };
            tokio::net::UnixStream::connect(path)
                .await
                .expect("connect to the supervisor")
        }

        /// The raw facade transport on the loopback listener.
        #[cfg(not(unix))]
        async fn connect_raw(endpoint: &Endpoint) -> tokio::net::TcpStream {
            let Endpoint::Loopback(port) = endpoint else {
                panic!("the loopback transport is the only one this platform starts");
            };
            tokio::net::TcpStream::connect(("127.0.0.1", *port))
                .await
                .expect("connect to the supervisor")
        }

        async fn send_observed<S>(
            stream: &mut S,
            token: &str,
            args: &[OsString],
            success: Option<bool>,
        ) where
            S: tokio::io::AsyncWrite + Unpin + Send,
        {
            let frame = Observed::new(
                token.to_owned(),
                OsStr::new("rustc"),
                args,
                success,
                0,
                crate::supervisor::protocol::InvocationEnv::default(),
            );
            write_frame(&mut *stream, &Request::Observed(frame))
                .await
                .expect("write the observation frame");
        }

        /// Guarantee the frames already written on `stream` have been
        /// handled: the frames are sequential, so an answered
        /// `AwaitServeMap` proves everything before it was processed.
        async fn flush_frames<S>(stream: &mut S, token: &str)
        where
            S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
        {
            use crate::supervisor::protocol::read_frame;
            write_frame(
                &mut *stream,
                &Request::AwaitServeMap(crate::supervisor::protocol::AwaitServeMap {
                    token: token.to_owned(),
                }),
            )
            .await
            .expect("write the flush frame");
            let answer: crate::supervisor::protocol::Answer = read_frame(&mut *stream)
                .await
                .expect("read the flush answer")
                .expect("the supervisor answers the wait");
            assert!(
                matches!(answer, crate::supervisor::protocol::Answer::ServeMapReady),
                "the flush answered with {answer:?}"
            );
        }

        async fn stored_crates(config: &crate::config::StowConfig) -> Vec<String> {
            let connection = config.state_db_pool().await.expect("state db pool");
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(
                "SELECT crate_name FROM artifact_cache_entries ORDER BY crate_name".to_owned(),
            ))
            .fetch_all(&connection)
            .await
            .expect("list stored crates")
        }

        /// The `BuildContext` a deferred build hands its supervisor when
        /// the policy directory is seeded empty and the enrichment still
        /// owes it the coarse allow commit (stow#788).
        fn pending_policy_ctx(
            policy_dir: std::path::PathBuf,
            ready: &Arc<crate::facade::ServeMapSignal>,
            in_flight: &server::InFlightUnits,
        ) -> BuildContext {
            BuildContext {
                policy_dir: Some(policy_dir),
                public_cache_target: Some(HOST_TARGET.to_owned()),
                public_cache_disabled: false,
                cache: crate::config::CacheLayers::default(),
                analysis: std::sync::Arc::new(std::sync::OnceLock::from(AnalysisFacts {
                    semantic_fallback_enabled: false,
                    unit_nodes: None,
                    prefetch_candidates: std::collections::BTreeMap::new(),
                })),
                serve_map_ready: std::sync::Arc::new(crate::facade::ServeMapSignal::settled()),
                policy_ready: std::sync::Arc::clone(ready),
                in_flight: in_flight.clone(),
                registry_sources: std::sync::OnceLock::from(crate::RegistrySources::CargoConfig(
                    std::iter::once("index.crates.io".to_owned()).collect(),
                )),
            }
        }

        /// stow#788: a covered unit that reaches the policy check before
        /// its allow marker lands waits out the commit instead of being
        /// denied by timing — the marker lands mid-wait, and the unit
        /// takes the allowed path: its exact registry lookup runs against
        /// the build's index slice.
        #[tokio::test]
        async fn a_unit_before_its_allow_marker_waits_and_serves() {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("deps");
            std::fs::create_dir_all(&out_dir).expect("create deps dir");
            let registry_src = tempdir.path().join("cargo_home/registry/src");
            let policy_dir = tempdir.path().join("policy");
            std::fs::create_dir_all(&policy_dir).expect("create policy dir");
            let policy_ready = Arc::new(crate::facade::ServeMapSignal::pending());
            let (config, _in_flight, handler) = fixture_ctx(tempdir.path(), |in_flight| {
                pending_policy_ctx(policy_dir.clone(), &policy_ready, in_flight)
            })
            .await;
            // The build's slice carries no row for the unit: the exact
            // lookup — which only the allowed path runs — misses on it and
            // records that miss in the negative cache. A denied unit never
            // asks the slice, so it records nothing.
            crate::index::write_cached_test_slice(
                &config,
                HOST_TARGET,
                RUSTC_VERSION,
                &super::empty_test_index(HOST_TARGET, RUSTC_VERSION),
            )
            .await
            .expect("write the build's index slice");

            let args = unit_args(&registry_src, &out_dir, "demo", "1.0.0", "demometa", &[]);

            let deciding = {
                let handler = Arc::clone(&handler);
                let args = args.clone();
                tokio::spawn(async move {
                    handler
                        .plan(
                            OsString::from("rustc"),
                            args,
                            crate::supervisor::protocol::InvocationEnv::default(),
                        )
                        .await
                })
            };
            // The decision found no marker and parked on the owed
            // commit: from here only the commit can answer it.
            policy_ready.parked(1).await;

            // The enrichment's commit: the marker lands, then the latch
            // releases — the order `run_build_enrichment` writes it.
            crate::cache_policy::write_policy_entries(
                &policy_dir,
                &[crate::cache_policy::CachePolicyEntry {
                    target: HOST_TARGET.to_owned(),
                    crate_name: "demo".to_owned(),
                }],
            )
            .await
            .expect("write the allow marker");
            policy_ready.complete();

            let decision = deciding.await.expect("join the plan");
            drop(decision);
            // The marker was honored: the unit's exact lookup asked the
            // slice — rather than being denied by timing. With no row it
            // still compiles, but the allow it waited for was real.
            assert!(
                crate::circuit::negative_cache_contains(
                    &config,
                    &format!("{HOST_TARGET}/{RUSTC_VERSION}/demometa"),
                )
                .await
                .expect("read the negative cache"),
                "the waited unit must take the allowed path to its exact lookup"
            );

            // A served leaf mints no local-build marker: a dependent
            // carrying its rlib is not forced to compile behind it.
            let dependent_args = unit_args(
                &registry_src,
                &out_dir,
                "consumer",
                "2.0.0",
                "consmeta",
                &[("demo", &out_dir.join("libdemo-demometa.rlib"))],
            );
            let dependent = crate::rustc_args::ParsedRustcArgs::parse(&dependent_args)
                .expect("parse dependent");
            assert!(
                !crate::must_build_locally(&dependent, HOST_TARGET, Some(&policy_dir)),
                "a served dependency must not start the local-build cascade"
            );
        }

        /// stow#788: once the commit lands without the unit's marker the
        /// deny is final and immediate — an all-miss build's answer is
        /// the old path's: one `exists()`, no wait.
        #[tokio::test]
        async fn a_marker_absent_after_the_commit_denies_without_waiting() {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("deps");
            std::fs::create_dir_all(&out_dir).expect("create deps dir");
            let registry_src = tempdir.path().join("cargo_home/registry/src");
            let policy_dir = tempdir.path().join("policy");
            std::fs::create_dir_all(&policy_dir).expect("create policy dir");
            let policy_ready = Arc::new(crate::facade::ServeMapSignal::pending());
            let (_config, _in_flight, handler) = fixture_ctx(tempdir.path(), |in_flight| {
                pending_policy_ctx(policy_dir.clone(), &policy_ready, in_flight)
            })
            .await;
            let args = unit_args(&registry_src, &out_dir, "demo", "1.0.0", "demometa", &[]);

            // While the commit is owed, the decision parks on it.
            let deciding = {
                let handler = Arc::clone(&handler);
                let args = args.clone();
                tokio::spawn(async move {
                    handler
                        .plan(
                            OsString::from("rustc"),
                            args,
                            crate::supervisor::protocol::InvocationEnv::default(),
                        )
                        .await
                })
            };
            policy_ready.parked(1).await;
            policy_ready.complete();
            let decision = deciding.await.expect("join the plan");
            assert!(
                matches!(decision, server::Decision::Compile(_)),
                "no marker after the commit is a real deny"
            );

            // Once the latch is settled the same question costs one
            // marker check — an all-miss build waits on nothing.
            let started = std::time::Instant::now();
            let decision = handler
                .plan(
                    OsString::from("rustc"),
                    args,
                    crate::supervisor::protocol::InvocationEnv::default(),
                )
                .await;
            assert!(
                matches!(decision, server::Decision::Compile(_)),
                "the settled deny still compiles"
            );
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "a settled latch is not a wait: {:?}",
                started.elapsed()
            );
        }

        /// A dependent whose report the supervisor handles while its
        /// dependency is still in flight is stored only once the
        /// dependency's bookkeeping has landed (stow#618).
        #[tokio::test]
        async fn a_dependent_waits_for_its_dependencys_bookkeeping() {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("deps");
            std::fs::create_dir_all(&out_dir).expect("create deps dir");
            let registry_src = tempdir.path().join("cargo_home/registry/src");

            let (config, in_flight, handler) = fixture(tempdir.path()).await;
            let supervisor = server::start(
                handler,
                in_flight.clone(),
                &std::env::current_exe().expect("current exe"),
            )
            .expect("start supervisor");
            let [(_, endpoint), (_, token), _] = supervisor.env();
            let endpoint = Endpoint::parse(&endpoint).expect("endpoint");

            let dep_args = unit_args(&registry_src, &out_dir, "dep", "1.0.0", "depmeta", &[]);
            write_outputs(&out_dir, "dep", "depmeta");
            let consumer_args = unit_args(
                &registry_src,
                &out_dir,
                "consumer",
                "2.0.0",
                "consmeta",
                &[("dep", &out_dir.join("libdep-depmeta.rlib"))],
            );
            write_outputs(&out_dir, "consumer", "consmeta");

            // The dependency's mark lands first: the flush guarantees the
            // registration before the dependent's frames are written.
            let mut dep_conn = connect_raw(&endpoint).await;
            send_observed(&mut dep_conn, &token, &dep_args, None).await;
            flush_frames(&mut dep_conn, &token).await;

            let mut consumer_conn = connect_raw(&endpoint).await;
            send_observed(&mut consumer_conn, &token, &consumer_args, None).await;
            send_observed(&mut consumer_conn, &token, &consumer_args, Some(true)).await;

            // No flush here — the report's bookkeeping is what waits, so
            // the connection's next frame cannot be answered yet. The
            // dependent's bookkeeping parks on the dependency's flight;
            // from there nothing may be stored while it is in flight.
            let dep_rlib =
                crate::artifact_cache::path_to_string(&out_dir.join("libdep-depmeta.rlib"))
                    .expect("utf-8 extern path");
            in_flight.parked_on(&dep_rlib, 1).await;
            assert!(
                stored_crates(&config).await.is_empty(),
                "nothing may be stored while the dependency is in flight"
            );

            send_observed(&mut dep_conn, &token, &dep_args, Some(true)).await;
            // The flush answers only after the dependency's bookkeeping —
            // store included — has run to its end.
            flush_frames(&mut dep_conn, &token).await;

            // The dependent's wait releases now; its connection's flush
            // answers only once that bookkeeping — store included — ran.
            flush_frames(&mut consumer_conn, &token).await;
            assert_eq!(stored_crates(&config).await, vec!["consumer", "dep"]);
        }

        /// A facade whose connection ends between the mark and the report
        /// completes the unit's flight anyway — the dependent is
        /// released, finds the bookkeeping genuinely absent, and the
        /// debug line says which extern was never recorded (stow#618).
        #[tokio::test]
        async fn a_dead_connection_releases_the_dependent() {
            let (log, _capture) = capture_logs(tracing::Level::DEBUG);

            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("deps");
            std::fs::create_dir_all(&out_dir).expect("create deps dir");
            let registry_src = tempdir.path().join("cargo_home/registry/src");

            let (config, in_flight, handler) = fixture(tempdir.path()).await;
            let supervisor = server::start(
                handler,
                in_flight,
                &std::env::current_exe().expect("current exe"),
            )
            .expect("start supervisor");
            let [(_, endpoint), (_, token), _] = supervisor.env();
            let endpoint = Endpoint::parse(&endpoint).expect("endpoint");

            let dep_args = unit_args(&registry_src, &out_dir, "dep2", "1.0.0", "dep2meta", &[]);
            write_outputs(&out_dir, "dep2", "dep2meta");
            let consumer_args = unit_args(
                &registry_src,
                &out_dir,
                "consumer2",
                "2.0.0",
                "cons2meta",
                &[("dep2", &out_dir.join("libdep2-dep2meta.rlib"))],
            );
            write_outputs(&out_dir, "consumer2", "cons2meta");

            // The dependency's mark lands — the flush proves it — then
            // the facade's connection dies with no report ever coming.
            let mut dep_conn = connect_raw(&endpoint).await;
            send_observed(&mut dep_conn, &token, &dep_args, None).await;
            flush_frames(&mut dep_conn, &token).await;
            drop(dep_conn);

            let mut consumer_conn = connect_raw(&endpoint).await;
            send_observed(&mut consumer_conn, &token, &consumer_args, None).await;
            send_observed(&mut consumer_conn, &token, &consumer_args, Some(true)).await;
            // The dependent's bookkeeping waits only until the dead
            // connection's flight completes — then the flush answers, and
            // the bookkeeping that logs the skip has run to its end.
            flush_frames(&mut consumer_conn, &token).await;

            let captured = log.text();
            assert!(
                captured.contains("bookkeeping was never recorded"),
                "the unrecorded-dependency debug line:\n{captured}"
            );
            assert!(
                captured.contains("consumer2"),
                "the debug line names the skipped unit:\n{captured}"
            );
            assert!(
                stored_crates(&config).await.is_empty(),
                "a dependent whose dependency never recorded is not stored"
            );
        }

        /// stow#619: a build script's `bin` unit is never an artifact
        /// unit — its post-compile owes no wait on an in-flight extern,
        /// no `materialized_outputs` read, no identity resolution, and
        /// therefore no store and no warn. The dependency's flight stays
        /// open for the whole test: a post-compile that waited on it
        /// would never let the flush answer.
        #[tokio::test]
        async fn a_build_script_units_post_compile_owes_nothing() {
            let (log, _capture) = capture_logs(tracing::Level::WARN);

            let tempdir = tempfile::tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("deps");
            std::fs::create_dir_all(&out_dir).expect("create deps dir");
            let registry_src = tempdir.path().join("cargo_home/registry/src");

            let (config, in_flight, handler) = fixture(tempdir.path()).await;
            let supervisor = server::start(
                handler,
                in_flight,
                &std::env::current_exe().expect("current exe"),
            )
            .expect("start supervisor");
            let [(_, endpoint), (_, token), _] = supervisor.env();
            let endpoint = Endpoint::parse(&endpoint).expect("endpoint");

            // The extern the build-script unit was compiled against is
            // in flight for the whole test: its mark lands — the flush
            // proves the registration — and its report never does.
            let dep_args = unit_args(&registry_src, &out_dir, "dep3", "1.0.0", "dep3meta", &[]);
            write_outputs(&out_dir, "dep3", "dep3meta");
            let mut dep_conn = connect_raw(&endpoint).await;
            send_observed(&mut dep_conn, &token, &dep_args, None).await;
            flush_frames(&mut dep_conn, &token).await;

            // The invocation cargo runs for a registry crate's build
            // script: `--crate-type bin`, the `build.rs` source, the
            // deps dir, and the build-dependencies as `--extern`s.
            let build_script_args = vec![
                OsString::from("--crate-name"),
                OsString::from("build_script_build"),
                OsString::from("--crate-type"),
                OsString::from("bin"),
                OsString::from("--emit"),
                OsString::from("link"),
                OsString::from("--out-dir"),
                out_dir.as_os_str().to_os_string(),
                OsString::from("-C"),
                OsString::from("metadata=bsmeta"),
                OsString::from("-C"),
                OsString::from("extra-filename=-bsmeta"),
                OsString::from("--target"),
                OsString::from(HOST_TARGET),
                OsString::from(format!(
                    "--extern=dep3={}",
                    out_dir.join("libdep3-dep3meta.rlib").display()
                )),
                registry_src
                    .join("index.crates.io-0123abcd/proc-macro2-1.0.0/build.rs")
                    .into_os_string(),
            ];
            // rustc succeeded: its binary is where the post-compile's
            // build-script check looks for it.
            std::fs::write(out_dir.join("build_script_build-bsmeta"), b"bin-bytes")
                .expect("write build script binary");

            let mut script_conn = connect_raw(&endpoint).await;
            send_observed(&mut script_conn, &token, &build_script_args, None).await;
            send_observed(&mut script_conn, &token, &build_script_args, Some(true)).await;
            // The flush answers only once the report's bookkeeping has
            // run to its end — a post-compile that waited on the
            // in-flight extern would hold it forever.
            tokio::time::timeout(
                Duration::from_secs(10),
                flush_frames(&mut script_conn, &token),
            )
            .await
            .expect("the build-script unit's post-compile returned while its extern was in flight");

            assert!(
                stored_crates(&config).await.is_empty(),
                "a unit the cache cannot hold stores nothing"
            );
            let captured = log.text();
            assert!(
                captured.is_empty(),
                "a never-cacheable unit logs no warn:\n{captured}"
            );
        }
    }

    /// An in-memory stderr for the `tracing_subscriber_for` tests — a
    /// shared byte buffer the fmt layer writes through `MakeWriter`.
    #[derive(Clone, Default)]
    struct Terminal(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl Terminal {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("terminal buffer").clone())
                .expect("fmt output is UTF-8")
        }
    }

    impl std::io::Write for Terminal {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("terminal buffer").write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.lock().expect("terminal buffer").flush()
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for Terminal {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// The two outputs are filtered separately: the terminal keeps the
    /// `warn` default (stow#633) while the trace — an explicit request —
    /// records every span and event of stow's own crates, including the
    /// `debug` spans it exists to show (stow#698).
    #[test]
    fn the_trace_file_records_what_the_terminal_does_not_print() {
        let dir = tempfile::tempdir().expect("tempdir");
        let trace = dir.path().join("trace.json");
        let terminal = Terminal::default();
        let (subscriber, guard) =
            tracing_subscriber_for(None, Some(trace.clone()), terminal.clone());

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::debug_span!("stow.test.span");
            let _entered = span.enter();
            tracing::info!("an info line");
            tracing::warn!("a warn line");
            tracing::warn!(target: "hyper", "a foreign line");
        });
        // Dropping the guard flushes the trace writer's queue to disk.
        drop(guard);

        let trace_text = std::fs::read_to_string(&trace).expect("read the trace file");
        assert!(
            trace_text.contains("stow.test.span"),
            "the trace records the debug span: {trace_text}"
        );
        assert!(
            trace_text.contains("an info line"),
            "the trace records stow's own events below warn: {trace_text}"
        );
        assert!(
            !trace_text.contains("a foreign line"),
            "the trace ignores non-stow targets: {trace_text}"
        );

        let terminal_text = terminal.text();
        assert!(
            terminal_text.contains("a warn line"),
            "the terminal prints warn events: {terminal_text}"
        );
        assert!(
            terminal_text.contains("a foreign line"),
            "the terminal's warn default covers foreign targets: {terminal_text}"
        );
        assert!(
            !terminal_text.contains("an info line"),
            "the terminal does not print info: {terminal_text}"
        );
    }

    /// `RUST_LOG` selects the terminal's level only — a restrictive
    /// value must not write an empty trace (stow#698).
    #[test]
    fn rust_log_does_not_narrow_the_trace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let trace = dir.path().join("trace.json");
        let terminal = Terminal::default();
        let (subscriber, guard) =
            tracing_subscriber_for(Some("error"), Some(trace.clone()), terminal.clone());

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::debug_span!("stow.test.span");
            let _entered = span.enter();
            tracing::info!("an info line");
            tracing::warn!("a warn line");
            tracing::warn!(target: "hyper", "a foreign line");
        });
        drop(guard);

        let trace_text = std::fs::read_to_string(&trace).expect("read the trace file");
        assert!(
            trace_text.contains("stow.test.span"),
            "RUST_LOG does not narrow the trace: {trace_text}"
        );
        assert!(
            !trace_text.contains("a foreign line"),
            "the trace ignores non-stow targets: {trace_text}"
        );

        let terminal_text = terminal.text();
        assert!(
            !terminal_text.contains("a warn line"),
            "RUST_LOG=error hides warn on the terminal: {terminal_text}"
        );
        assert!(
            !terminal_text.contains("an info line"),
            "RUST_LOG=error hides info on the terminal: {terminal_text}"
        );
    }
}

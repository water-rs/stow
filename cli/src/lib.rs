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
mod build_state;
mod cache_policy;
mod cargo_cmd;
mod cc;
mod circuit;
mod cli_args;
mod commands;
mod config;
mod edge_client;
mod fetch;
mod index;
mod inject;
mod lockfile_graph_cache;
mod lockfile_resolver;
mod miss_journal;
mod mold;
mod prefetch;
mod profile_guard;
mod provenance;
mod resolve;
mod rustc_args;
mod state_db;
mod stats;
mod supervisor;
mod verify;
mod workspace_deps;
use stow_shim as wrapper_shim;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use async_process::Command;
use clap::Parser;
use stow_types::error::Context;
use stow_types::identity::DependencyCompileKeyIdentity;
use stow_types::public_cache::{
    detect_registry_crate_version as shared_detect_registry_crate_version,
    normalized_cache_profile, stable_registry_artifact_identity,
};
use tokio::io::AsyncWriteExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::artifact_cache::{
    load_cached_bundle, load_cached_bundle_by_compile_key, load_semantic_cached_bundle,
    prepare_local_cache, record_materialized_bundle_outputs,
    record_materialized_local_build_outputs, remove_cached_bundle,
    resolve_dependency_c_metadata_json,
};
use crate::build_state::BuildState;
use crate::cli_args::{Cli, Command as CliCommand, WrapperCommandArgs};
use crate::config::StowConfig;
use crate::fetch::FetchRequest;
use stow_types::api::DependencyGraphEntry;

const STOW_EXPANDED_GRAPH_ENV: &str = "STOW_EXPANDED_GRAPH_JSON";
pub(crate) const STOW_PREFETCH_ARTIFACTS_ENV: &str = "STOW_PREFETCH_ARTIFACTS_JSON";
pub(crate) const STOW_ENABLE_SEMANTIC_FALLBACK_ENV: &str = "STOW_ENABLE_SEMANTIC_FALLBACK";
/// The build's precomputed serve map, written by the supervising
/// `stow build`/`check`/`test` for its wrapper facades:
/// `[[crate_name, version], ...]` naming the units its caches can serve,
/// plus `[crate_name, "*"]` for crates a semantic fallback may cover.
/// A facade holding it answers the serve question locally — an exact
/// miss or an unlisted crate needs no supervisor round trip at all
/// (stow#347).
pub(crate) const STOW_SERVABLE_UNITS_ENV: &str = "STOW_SERVABLE_UNITS_JSON";
const STOW_TRACE_WRAPPED_COMPILERS_ENV: &str = "STOW_TRACE_WRAPPED_COMPILERS";
/// When set to a path, stow writes a Chrome-trace JSON to that file describing
/// every instrumented span (`stow.startup`, `stow.project.context`,
/// `stow.edge.graph.query`, `stow.wrapper.invoke`, ...). Open the file with
/// <chrome://tracing> or perfetto.dev for a flame waterfall. Used to drive P1
/// performance work — see plan P0.1.
const STOW_TRACE_FILE_ENV: &str = "STOW_TRACE_FILE";

/// Holds the tracing-chrome flush guard, if a Chrome trace was requested.
///
/// The guard must outlive `block_on` so the trace file is fully flushed.
struct TracingGuard {
    _chrome: Option<tracing_chrome::FlushGuard>,
}

/// Entry point for all three stow binaries: installs tracing when the
/// invocation allows it, builds a tokio runtime sized to the invocation
/// kind, and runs [`async_main`].
///
/// Wrapper invocations (`stow rustc`, `stow cc`) get a `current_thread`
/// runtime — they run hundreds of times per build with at most one
/// concurrent network task, so worker-pool spin-up is wasted overhead.
/// User-facing commands that can fan out get the multi-threaded runtime.
///
/// # Errors
///
/// Returns an error when the tokio runtime cannot be built or when the
/// selected subcommand fails.
pub fn run() -> stow_types::error::Result<()> {
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
    if let Some(status) = delegate_to_capture()? {
        std::process::exit(status);
    }
    // A facade the build's own serve map already answers compiles without
    // paying a runtime, a connection or a plan round trip (stow#347).
    if let Some(status) = try_fast_wrapper_path()? {
        std::process::exit(status);
    }
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
        .spawn(move || runtime.block_on(async_main()))
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
fn process_args() -> Vec<OsString> {
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

/// The serve question, answered from the map the supervising build
/// computed: `(crate_name, version)` pairs it can serve, plus
/// `crate_name → *` wildcard entries a semantic fallback may cover.
///
/// Every unit outside the map compiles — no plan round trip asks again
/// (stow#347). Returns `None` when the fast path does not apply and the
/// invocation should take the ordinary wrapper path.
fn try_fast_wrapper_path() -> stow_types::error::Result<Option<i32>> {
    let args = process_args();
    // The fast path is rustc-only — `stow cc` goes through the supervisor
    // for the toolchain bookkeeping that is already cheap.
    if args.get(1).map(OsString::as_os_str) != Some(OsStr::new("rustc")) {
        return Ok(None);
    }
    // Both envs must be live: the supervisor endpoint (set by every
    // supervised run) and the servable map (set only by a run that
    // computed it). Without the map this is an older supervisor — the
    // ordinary path keeps working.
    let Some((endpoint, token)) =
        supervisor::from_env().map_err(|error| stow_types::stow_error!("{error}"))?
    else {
        return Ok(None);
    };
    let Some(units) = std::env::var_os(STOW_SERVABLE_UNITS_ENV)
        .and_then(|raw| raw.into_string().ok())
        .and_then(|raw| ServableUnits::parse(&raw))
    else {
        return Ok(None);
    };
    let Some(executable) = args.get(2).cloned() else {
        return Ok(None);
    };
    let mut wrapped_args: Vec<OsString> = args.get(3..).unwrap_or_default().to_vec();
    // The supervising run's extra rustc arguments arrive appended, the
    // same merge `run_rustc_wrapper` performs before planning.
    if let Some(encoded) = std::env::var_os(rustc_args::STOW_RUSTC_EXTRA_ARGS_ENV)
        .and_then(|encoded| encoded.into_string().ok())
    {
        wrapped_args.extend(
            encoded
                .split('\x1f')
                .filter(|arg| !arg.is_empty())
                .map(OsString::from),
        );
    }
    let mut connection = supervisor::client::SyncConnection::open(&endpoint, token)
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    let parsed = classify_invocation(&wrapped_args).ok();
    let servable = parsed.as_ref().is_some_and(|parsed| {
        let detected_version = detect_registry_crate_version(parsed)
            .ok()
            .flatten()
            .map(|(_, version)| version);
        units.covers(&parsed.crate_name, detected_version.as_deref())
    });
    if parsed.is_none() || servable {
        // A serve is possible, or the invocation is not a unit at all
        // (a probe): the plan round trip decides — the only frame that
        // may block rustc's start, and only where it can pay (stow#347).
        return run_planned_invocation(connection, &executable, &wrapped_args).map(Some);
    }

    // Nothing in this build can serve this unit: compile it here and
    // report the outcome so the supervisor's bookkeeping still lands —
    // the provenance mark before rustc starts, the rest off the wire.
    connection
        .mark(&executable, &wrapped_args)
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    let status = std::process::Command::new(&executable)
        .args(&wrapped_args)
        .status()
        .wrap_err("failed to spawn wrapped compiler")?;
    connection
        .report_observed(&executable, &wrapped_args, status.success())
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    Ok(Some(status.code().unwrap_or(1)))
}

/// The plan half of the facade, synchronous: ask the supervisor what to
/// do, run rustc only when nothing serves it, then report — the same
/// exchange [`delegate_to_supervisor`] runs over the async transport.
fn run_planned_invocation(
    mut connection: supervisor::client::SyncConnection,
    executable: &OsString,
    args: &[OsString],
) -> stow_types::error::Result<i32> {
    let decision = connection
        .plan(executable, args)
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    let ticket = match decision {
        supervisor::client::Decision::Served => return Ok(0),
        supervisor::client::Decision::Compile(ticket) => ticket,
    };
    let status = std::process::Command::new(executable)
        .args(args)
        .status()
        .wrap_err("failed to spawn wrapped compiler")?;
    connection
        .report(&ticket, status.success())
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    Ok(status.code().unwrap_or(1))
}

/// The parsed servable map: exact `(name, version)` pairs and names the
/// semantic fallback may serve under any compatible version.
struct ServableUnits {
    exact: std::collections::HashSet<(String, String)>,
    wildcard: std::collections::HashSet<String>,
}

impl ServableUnits {
    fn parse(raw: &str) -> Option<Self> {
        let entries = serde_json::from_str::<Vec<(String, String)>>(raw).ok()?;
        let mut units = Self {
            exact: std::collections::HashSet::new(),
            wildcard: std::collections::HashSet::new(),
        };
        for (name, version) in entries {
            let name = canonical_crate_name(&name);
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
    fn covers(&self, crate_name: &str, version: Option<&str>) -> bool {
        let name = canonical_crate_name(crate_name);
        if self.wildcard.contains(&name) {
            return true;
        }
        version.is_some_and(|version| self.exact.contains(&(name, version.to_owned())))
    }
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
async fn async_main() -> stow_types::error::Result<()> {
    let args = process_args();
    let cli = parse_cli_or_exit(&args)?;
    let span = tracing::Span::current();
    span.record("subcommand", subcommand_name(&cli.command));
    match cli.command {
        CliCommand::Check(command) => cargo_cmd::run("check", command).await,
        CliCommand::Build(command) => cargo_cmd::run("build", command).await,
        CliCommand::Test(command) => cargo_cmd::run("test", command).await,
        CliCommand::Predict(command) => cargo_cmd::predict(command).await,
        CliCommand::Setup(args) => commands::setup_project(args).await,
        CliCommand::Update => commands::update_self().await,
        CliCommand::Status => commands::status_project().await,
        CliCommand::Stats(args) => commands::stats_command(args).await,
        CliCommand::Clean => commands::clean_project().await,
        CliCommand::CheckArtifact(command) => commands::check_artifact(command).await,
        CliCommand::FetchArtifact(command) => commands::fetch_artifact(command).await,
        CliCommand::Index(args) => match args.command {
            cli_args::IndexCommand::Refresh(args) => commands::index_refresh(args).await,
            cli_args::IndexCommand::Status => commands::index_status().await,
        },
        CliCommand::Rustc(command) => run_rustc_wrapper(command).await,
        CliCommand::Cc(command) => run_cc_wrapper(command).await,
        CliCommand::PurgeCacheDir(command) => commands::purge_cache_dirs(command).await,
        CliCommand::DrainMisses(args) => miss_journal::drain(&args.target_dir).await,
    }
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

async fn run_passthrough(
    executable: &OsString,
    env: &[(OsString, OsString)],
    wrapped_args: &[std::ffi::OsString],
) -> stow_types::error::Result<()> {
    let status = run_passthrough_status(executable, env, wrapped_args).await?;

    std::process::exit(status.code().unwrap_or(1));
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
    build: Option<&BuildState>,
) -> bool {
    let dependency = build.map_or_else(
        || provenance::locally_built_dependency(target, &parsed.extern_crates),
        |build| build.locally_built_dependency(target, &parsed.extern_crates),
    );
    let Some(dependency) = dependency else {
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
    /// The unit's outputs are in the target directory.
    Served,
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
}

impl PostCompile {
    /// A compile with no bookkeeping at all.
    fn raw(executable: &OsString) -> Self {
        Self {
            executable: executable.clone(),
            parsed: None,
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
/// The marker lands in the build state when there is one — under the
/// same target key the dependents' [`must_build_locally`] checks — and
/// in the policy-dir marker file otherwise, the shape standalone
/// wrappers have always used.
async fn compile(
    executable: &OsString,
    parsed: &rustc_args::ParsedRustcArgs,
    build: Option<&std::sync::Arc<BuildState>>,
    target: Option<&str>,
) -> Outcome {
    let target = target
        .map(str::to_owned)
        .or_else(|| cache_policy::effective_target(parsed));
    if let Some(target) = target {
        match build {
            Some(build) => build.mark_locally_built(target, parsed.crate_name.clone()),
            None => {
                log_nonfatal_result(
                    "failed to record a locally built crate for this build",
                    provenance::record_local_build(&target, &parsed.crate_name).await,
                );
            }
        }
    }
    Outcome::Compile(Box::new(PostCompile {
        executable: executable.clone(),
        parsed: Some(parsed.clone()),
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
/// Only the build-script alias materialization, which is load-bearing for
/// cargo; everything else is best effort and logged.
async fn finish_rustc_compile(
    post: &PostCompile,
    success: bool,
    local_base: Option<&WrapperEnvBase>,
) -> stow_types::error::Result<Option<artifact_cache::LocalBuildArtifact>> {
    let Some(parsed) = post.parsed.as_ref() else {
        return Ok(None);
    };
    let mut artifact = None;
    if success {
        if let Some(base) = local_base {
            match resolve_local_build_artifact(base, parsed).await {
                Ok(Some(build)) => {
                    log_nonfatal_result(
                        "failed to materialize stable local build aliases after successful rustc build",
                        inject::materialize_local_build_stable_aliases(
                            parsed,
                            &build.identity,
                            inject::OutputDirWriters::StowOnly,
                        )
                        .await,
                    );
                    log_nonfatal_result(
                        "failed to record materialized stow output metadata after local rustc build",
                        record_materialized_local_build_outputs(
                            &base.config,
                            parsed,
                            &build.identity,
                        )
                        .await,
                    );
                    if parsed.is_locally_cacheable() {
                        log_nonfatal_result(
                            "failed to store locally built artifact in the stow cache",
                            artifact_cache::store_local_build_outputs(&base.config, parsed, &build)
                                .await
                                .map(|_| ()),
                        );
                    }
                    artifact = Some(build);
                }
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        crate_name = %parsed.crate_name,
                        "failed to resolve local artifact identity after successful rustc build"
                    );
                }
            }
        }
        materialize_build_script_alias(parsed).await?;
    }
    Ok(artifact)
}

async fn materialize_build_script_alias(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<()> {
    let Some(source_path) = parsed.output_binary_path() else {
        return Ok(());
    };
    let Some(alias_path) = parsed.build_script_alias_path() else {
        return Ok(());
    };
    if alias_path.exists() {
        return Ok(());
    }
    if !source_path.exists() {
        return Err(stow_types::stow_error!(
            "build script output {} does not exist after successful rustc passthrough",
            source_path.display()
        ));
    }

    let source_for_copy = source_path.clone();
    let alias_for_copy = alias_path.clone();
    smol::unblock(move || {
        reflink::reflink_or_copy(&source_for_copy, &alias_for_copy).wrap_err_with(|| {
            format!(
                "materialize cargo build script alias {} from {}",
                alias_for_copy.display(),
                source_for_copy.display()
            )
        })
    })
    .await?;

    tracing::debug!(
        source = %source_path.display(),
        alias = %alias_path.display(),
        "materialized cargo build script alias after rustc passthrough"
    );
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
#[derive(Debug, Default)]
pub(crate) struct BuildSupervisor {
    /// The build-scoped wrapper environment memo — one config load,
    /// rustc probe pair and cache lease for the whole build.
    env_cache: WrapperEnvCache,
    observations: std::sync::Mutex<Vec<artifact_cache::ObservedUnit>>,
}

impl BuildSupervisor {
    /// Every unit this build compiled locally, in compile order.
    pub(crate) fn observations(&self) -> Vec<artifact_cache::ObservedUnit> {
        self.observations
            .lock()
            .expect("observations mutex")
            .clone()
    }
}

impl BuildSupervisor {
    /// The supervisor one build actually runs: its env memo answers from
    /// the build state the launching `stow` computed once.
    pub(crate) fn with_build_state(build: std::sync::Arc<BuildState>) -> Self {
        let mut env_cache = WrapperEnvCache::default();
        env_cache.set_build_state(build);
        Self {
            env_cache,
            observations: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Finish one compile's bookkeeping — the stable aliases, the local
    /// store and the miss observation — whether the facade reported over
    /// a ticket or the fast-path `Observed` frame.
    async fn finish_and_observe(
        self: &std::sync::Arc<Self>,
        pending: Box<PostCompile>,
        success: bool,
    ) {
        let local_base = self.env_cache.local_base(&pending.executable).await;
        if let Ok(Some(build)) =
            finish_rustc_compile(&pending, success, local_base.as_deref()).await
            && let Some(parsed) = pending.parsed.as_ref()
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

    /// The target this invocation's mark belongs under — the same key
    /// dependents' [`must_build_locally`] checks look up.
    async fn mark_target(
        &self,
        executable: &OsStr,
        parsed: &rustc_args::ParsedRustcArgs,
    ) -> Option<String> {
        match parsed.target.clone() {
            Some(target) => Some(target),
            None => self
                .env_cache
                .local_base(executable)
                .await
                .map(|base| base.host_target.clone()),
        }
    }
}

impl supervisor::server::Handler for BuildSupervisor {
    type Pending = Box<PostCompile>;

    async fn plan(
        self: &std::sync::Arc<Self>,
        executable: OsString,
        args: Vec<OsString>,
    ) -> supervisor::server::Decision<Self::Pending> {
        match decide_rustc_invocation(&executable, &args, &self.env_cache).await {
            Outcome::Served => supervisor::server::Decision::Served,
            Outcome::Compile(post) => supervisor::server::Decision::Compile(post),
        }
    }

    async fn compiled(self: &std::sync::Arc<Self>, pending: Self::Pending, success: bool) {
        // A build-script unit's alias is load-bearing for cargo's very
        // next step, so its bookkeeping waits on the ticket path the way
        // it always did; every other unit's finishes off the request
        // path, drained when cargo exits (stow#347).
        let is_build_script = pending
            .parsed
            .as_ref()
            .is_some_and(rustc_args::ParsedRustcArgs::is_build_script);
        match self.env_cache.build_state() {
            Some(build) if !is_build_script => {
                let this = std::sync::Arc::clone(self);
                let build = std::sync::Arc::clone(build);
                build.enqueue(async move {
                    this.finish_and_observe(pending, success).await;
                });
            }
            _ => self.finish_and_observe(pending, success).await,
        }
    }

    async fn observed(
        self: &std::sync::Arc<Self>,
        executable: OsString,
        args: Vec<OsString>,
        success: Option<bool>,
    ) {
        let Ok(parsed) = classify_invocation(&args) else {
            return;
        };
        let Some(build) = self.env_cache.build_state().cloned() else {
            return;
        };
        // The provenance mark must land before the facade's compile is
        // visible to a dependent's plan — the mark-half of the frame is
        // sent ahead of rustc for exactly that reason.
        let Some(target) = self.mark_target(&executable, &parsed).await else {
            return;
        };
        build.mark_locally_built(target.clone(), parsed.crate_name.clone());
        let Some(success) = success else {
            return;
        };
        // The same accounting the plan path's `record_miss` produced for
        // a unit that finished the lookup unserved — the map already told
        // this facade nothing could serve it.
        if success
            && parsed.is_cacheable()
            && build.public_cache_enabled()
            && detect_registry_crate_version(&parsed).is_ok_and(|version| version.is_some())
            && build
                .locally_built_dependency(&target, &parsed.extern_crates)
                .is_none()
        {
            build.stats_miss(&parsed.crate_name);
            tracing::debug!(
                crate_name = %parsed.crate_name,
                target,
                "stow cache miss, falling back to rustc"
            );
        }
        let is_build_script = parsed.is_build_script();
        let post = Box::new(PostCompile {
            executable,
            parsed: Some(parsed),
        });
        if is_build_script {
            self.finish_and_observe(post, success).await;
        } else {
            let this = std::sync::Arc::clone(self);
            build.enqueue(async move {
                this.finish_and_observe(post, success).await;
            });
        }
    }
}

/// The rustc facade.
///
/// Parses the command line, asks the build's supervisor what to do with
/// the invocation, and either exits or runs the real rustc. When there is
/// no supervisor — a plain `cargo build` through the `RUSTC_WRAPPER` that
/// `stow setup` writes — it decides in this process instead.
#[tracing::instrument(name = "stow.wrapper.invoke", skip_all, fields(crate_name, cache_hit))]
async fn run_rustc_wrapper(mut command: WrapperCommandArgs) -> stow_types::error::Result<()> {
    // The supervising run's extra rustc arguments (workspace path remap and
    // any flags it selected) arrive appended to the argv so the user's own
    // rustflags sources — env or config — keep their cargo semantics.
    if let Some(encoded) = std::env::var_os(rustc_args::STOW_RUSTC_EXTRA_ARGS_ENV)
        && let Ok(encoded) = encoded.into_string()
    {
        command.wrapped_args.extend(
            encoded
                .split('\x1f')
                .filter(|arg| !arg.is_empty())
                .map(std::ffi::OsString::from),
        );
    }
    // An endpoint that is set but unusable fails the build. A wrapper that
    // quietly compiled everything itself would leave a build that is
    // merely slow, which is the failure mode that hides.
    match supervisor::from_env().map_err(|error| stow_types::stow_error!("{error}"))? {
        Some((endpoint, token)) => delegate_to_supervisor(&endpoint, token, &command).await,
        None => run_rustc_standalone(&command).await,
    }
}

/// Ask the supervisor, then do what it says.
async fn delegate_to_supervisor(
    endpoint: &supervisor::Endpoint,
    token: String,
    command: &WrapperCommandArgs,
) -> stow_types::error::Result<()> {
    let mut connection = supervisor::client::Connection::open(endpoint, token)
        .await
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    let decision = connection
        .plan(&command.executable, &command.wrapped_args)
        .await
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    tracing::debug!(
        served = matches!(decision, supervisor::client::Decision::Served),
        "the build supervisor answered this invocation"
    );
    let ticket = match decision {
        supervisor::client::Decision::Served => std::process::exit(0),
        supervisor::client::Decision::Compile(ticket) => ticket,
    };
    let status = run_passthrough_status(&command.executable, &[], &command.wrapped_args).await?;
    connection
        .report(&ticket, status.success())
        .await
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    std::process::exit(status.code().unwrap_or(1));
}

/// Decide and execute in this process: the configuration that has no
/// supervisor to ask.
async fn run_rustc_standalone(command: &WrapperCommandArgs) -> stow_types::error::Result<()> {
    let env_cache = WrapperEnvCache::default();
    match decide_rustc_invocation(&command.executable, &command.wrapped_args, &env_cache).await {
        Outcome::Served => std::process::exit(0),
        Outcome::Compile(post) => {
            if let Some(out_dir) = post
                .parsed
                .as_ref()
                .and_then(|parsed| parsed.out_dir.as_deref())
            {
                // No supervising stow owns this build's misses: the
                // wrappers journal them, and the first invocation after
                // the journaling cargo exits kicks the detached drain
                // (stow#317).
                miss_journal::drain_finished_builds(out_dir);
            }
            let status =
                run_passthrough_status(&command.executable, &[], &command.wrapped_args).await?;
            let local_base = env_cache.local_base(&command.executable).await;
            if let Ok(Some(build)) =
                finish_rustc_compile(&post, status.success(), local_base.as_deref()).await
                && let Some(parsed) = post.parsed.as_ref()
            {
                miss_journal::record_observation(&command.executable, parsed, &build);
            }
            std::process::exit(status.code().unwrap_or(1));
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
    wrapped_args: &[std::ffi::OsString],
    env_cache: &WrapperEnvCache,
) -> Outcome {
    let parsed = match classify_invocation(wrapped_args) {
        Ok(parsed) => parsed,
        Err(UnparseableInvocation::Probe(error)) => {
            tracing::debug!(error = %error, "rustc probe invocation detected, bypassing cache");
            return Outcome::Compile(Box::new(PostCompile::raw(rustc)));
        }
        Err(UnparseableInvocation::Passthrough(error)) => {
            tracing::warn!(
                error = %error,
                crate_name = wrapped_crate_name(wrapped_args)
                    .as_deref()
                    .unwrap_or("<unknown>"),
                "rustc arguments failed to parse; passing the invocation through to rustc"
            );
            return Outcome::Compile(Box::new(PostCompile::raw(rustc)));
        }
    };

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
        cacheable = parsed.is_cacheable(),
        "observed rustc wrapper invocation"
    );

    if !parsed.is_cacheable() {
        return decide_local_only(rustc, &parsed, env_cache).await;
    }

    let build = env_cache.build_state();
    // The kill switch disables the *public* cache; a self-produced local
    // entry is not public, so lookups still run against it.
    if !build.map_or_else(
        || std::env::var_os("STOW_DISABLE_PUBLIC_CACHE").is_none(),
        |build| build.public_cache_enabled(),
    ) {
        tracing::debug!(
            "public rust cache disabled for this cargo invocation, serving local lookups only"
        );
        return decide_local_only(rustc, &parsed, env_cache).await;
    }

    let Some(env) = prepare_wrapper_environment(rustc, &parsed, env_cache).await else {
        return compile(rustc, &parsed, build, None).await;
    };
    let exact_public_cache_allowed = build.map_or_else(
        || cache_policy::public_cache_allowed(&parsed),
        |build| build.public_cache_allowed(Some(env.target.clone()), &parsed.crate_name),
    ) != Some(false);
    if !exact_public_cache_allowed {
        tracing::debug!(
            crate_name = %parsed.crate_name,
            "public exact rust cache disabled by stow cache policy for this invocation"
        );
    }
    if must_build_locally(&parsed, &env.target, build.map(AsRef::as_ref)) {
        return compile(rustc, &parsed, build, Some(&env.target)).await;
    }
    let request = FetchRequest {
        target: &env.target,
        rustc_version: &env.rustc_version,
        c_metadata: env.request_c_metadata.as_str(),
    };
    if try_serve_local_cached_bundle(&env.env_base.config, &parsed, &request).await {
        return Outcome::Served;
    }
    if try_serve_local_prefetched_graph_bundle(
        &env.env_base.config,
        &parsed,
        &env.target,
        &env.rustc_version,
    )
    .await
    {
        return Outcome::Served;
    }
    if let Some(semantic_request) = env.semantic_request.as_ref()
        && try_serve_local_semantic_cached_bundle(&env.env_base.config, &parsed, semantic_request)
            .await
    {
        return Outcome::Served;
    }

    match try_remote_serves(&env, &parsed, &request, exact_public_cache_allowed).await {
        RemoteServe::Served => return Outcome::Served,
        RemoteServe::Bypass => return compile(rustc, &parsed, build, Some(&env.target)).await,
        RemoteServe::Miss => {}
    }

    record_miss(
        &env.env_base.config,
        &parsed,
        &env.target,
        &env.rustc_version,
    )
    .await;
    compile(rustc, &parsed, build, Some(&env.target)).await
}

/// Everything the cache path needs once every bypass-capable preparation
/// step has succeeded: the loaded config, the circuit state, the resolved
/// invocation identity, and the lease that keeps this rustc version's local
/// cache dir alive for the rest of the invocation.
struct WrapperEnvironment {
    /// The build-scoped base this invocation's identity was resolved over
    /// — carried so the lease and pooled state-db handle stay alive.
    env_base: std::sync::Arc<WrapperEnvBase>,
    /// The breaker guards the *network*: remote fetches stop while tripped,
    /// but a local entry still serves — a self-produced hit never touches
    /// the edge, so it keeps paying off through the very outage that tripped
    /// the breaker. Read per invocation so the kill switch acts live.
    circuit_tripped: bool,
    target: String,
    rustc_version: String,
    /// `target/rustc_version/c_metadata`, the negative-cache key.
    cache_key: String,
    /// The `c_metadata` to query with: the stable identity's when the
    /// invocation's own was rewritten, else the raw cargo one.
    request_c_metadata: String,
    /// Semantic fallback request, only built when
    /// `STOW_ENABLE_SEMANTIC_FALLBACK` opts in.
    semantic_request: Option<fetch::SemanticFetchRequest>,
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
/// per build rather than per invocation. The supervisor owns one for the
/// whole build; a standalone invocation builds a fresh one and gets
/// exactly the one-shot behavior it always had.
#[derive(Debug, Default)]
pub(crate) struct WrapperEnvCache {
    /// The remote path's base (`StowConfig::load`).
    env_base: tokio::sync::OnceCell<Option<std::sync::Arc<WrapperEnvBase>>>,
    /// The local path's base (`StowConfig::load_local`), shared by
    /// `decide_local_only` and the post-compile finish.
    local_base: tokio::sync::OnceCell<Option<std::sync::Arc<WrapperEnvBase>>>,
    /// The build's shared serve state, attached to every base's config —
    /// present exactly when a `stow`-driven build supervises these
    /// wrappers (stow#347).
    build_state: Option<std::sync::Arc<BuildState>>,
}

impl WrapperEnvCache {
    /// Attach the build's shared serve state; every base this cache
    /// produces afterwards carries it on its config.
    pub(crate) fn set_build_state(&mut self, build: std::sync::Arc<BuildState>) {
        self.build_state = Some(build);
    }

    /// The attached build state, when this cache runs inside a
    /// supervising build.
    pub(crate) const fn build_state(&self) -> Option<&std::sync::Arc<BuildState>> {
        self.build_state.as_ref()
    }

    /// The base `load` prepares for `rustc`, computed once per build. A
    /// `None` means every invocation bypasses — the wrapper exists to
    /// accelerate builds, never to break them.
    async fn base(
        cell: &tokio::sync::OnceCell<Option<std::sync::Arc<WrapperEnvBase>>>,
        rustc: &OsStr,
        load: fn() -> stow_types::error::Result<StowConfig>,
        build_state: Option<&std::sync::Arc<BuildState>>,
    ) -> Option<std::sync::Arc<WrapperEnvBase>> {
        if let Some(base) = cell
            .get_or_init(|| async {
                load_wrapper_env_base(rustc, load).await.map(|mut base| {
                    base.config.build_state = build_state.cloned();
                    std::sync::Arc::new(base)
                })
            })
            .await
            && base.rustc == rustc
        {
            return Some(base.clone());
        }
        // A second rustc in one build never caches — it is a probe, not
        // the build's toolchain.
        load_wrapper_env_base(rustc, load).await.map(|mut base| {
            base.config.build_state = build_state.cloned();
            std::sync::Arc::new(base)
        })
    }

    async fn env_base(&self, rustc: &OsStr) -> Option<std::sync::Arc<WrapperEnvBase>> {
        Self::base(
            &self.env_base,
            rustc,
            StowConfig::load,
            self.build_state.as_ref(),
        )
        .await
    }

    pub(crate) async fn local_base(&self, rustc: &OsStr) -> Option<std::sync::Arc<WrapperEnvBase>> {
        Self::base(
            &self.local_base,
            rustc,
            StowConfig::load_local,
            self.build_state.as_ref(),
        )
        .await
    }
}

/// Load the config, probe the rustc and take the version lease — once
/// for the whole build. Every step can legitimately be unavailable, so
/// `None` means "run the real rustc".
async fn load_wrapper_env_base(
    rustc: &OsStr,
    load: fn() -> stow_types::error::Result<StowConfig>,
) -> Option<WrapperEnvBase> {
    let config = match load() {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(error = %error, "stow config unavailable, bypassing rust cache");
            return None;
        }
    };
    if let Err(error) = config.ensure_dirs().await {
        tracing::warn!(error = %error, "failed to prepare stow cache directories, bypassing rust cache");
        return None;
    }
    let host_target = match rustc_args::rustc_host_target(rustc).await {
        Ok(target) => target,
        Err(error) => {
            tracing::warn!(error = %error, "failed to detect rustc host target, bypassing rust cache");
            return None;
        }
    };
    let rustc_version = match rustc_args::detect_rustc_version(rustc).await {
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

/// What the remote-fetch phase decided for an invocation.
enum RemoteServe {
    /// An artifact was written into the target dir; the wrapper exits 0.
    Served,
    /// No remote artifact applies; fall through to the miss path.
    Miss,
    /// The cache path failed or the artifact could not be used; run the
    /// real rustc immediately.
    Bypass,
}

/// Load the config and resolve everything the cache path needs for this
/// invocation. Every step can legitimately be unavailable — the wrapper
/// exists to accelerate builds, never to break them — so `None` means "run
/// the real rustc".
async fn prepare_wrapper_environment(
    rustc: &OsString,
    parsed: &rustc_args::ParsedRustcArgs,
    env_cache: &WrapperEnvCache,
) -> Option<WrapperEnvironment> {
    let env_base = env_cache.env_base(rustc).await?;
    let circuit_tripped = match circuit::is_tripped(&env_base.config).await {
        Ok(tripped) => tripped,
        Err(error) => {
            tracing::warn!(error = %error, "failed to read stow circuit state, bypassing rust cache");
            return None;
        }
    };
    if circuit_tripped {
        tracing::debug!("circuit breaker tripped, serving local lookups only");
    }

    let target = parsed
        .target
        .clone()
        .unwrap_or_else(|| env_base.host_target.clone());
    let Some(c_metadata) = parsed.c_metadata.as_deref() else {
        tracing::warn!("cacheable rustc invocation is missing -C metadata, bypassing rust cache");
        return None;
    };
    let rustc_version = env_base.rustc_version.clone();
    let cache_key = format!("{target}/{rustc_version}/{c_metadata}");

    let stable_exact_identity = match build_stable_exact_identity(
        &env_base.config,
        parsed,
        &target,
        &rustc_version,
    )
    .await
    {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(error = %error, "failed to resolve local artifact identity, bypassing rust cache");
            return None;
        }
    };
    let request_c_metadata = stable_exact_identity
        .as_ref()
        .map_or(c_metadata, |identity| identity.c_metadata.as_str())
        .to_owned();
    let semantic_fallback_enabled = env_base.config.build_state().map_or_else(
        || std::env::var_os(STOW_ENABLE_SEMANTIC_FALLBACK_ENV).is_some_and(|value| value != "0"),
        |build| build.semantic_fallback_enabled(),
    );
    let semantic_request = if semantic_fallback_enabled {
        match build_semantic_fetch_request(&env_base.config, parsed, &target, &rustc_version).await
        {
            Ok(request) => request,
            Err(error) => {
                tracing::warn!(error = %error, "failed to build semantic fetch request, continuing without semantic fallback");
                None
            }
        }
    } else {
        None
    };
    Some(WrapperEnvironment {
        env_base,
        circuit_tripped,
        target,
        rustc_version,
        cache_key,
        request_c_metadata,
        semantic_request,
    })
}

/// Try the registry for this invocation: resolve the artifact identity
/// against the locally cached, verified index slice, then pull the bundle
/// blob it names straight from the OCI registry. The exact lookup runs
/// first, then the semantic fallback when it is enabled and the exact path
/// did not serve or disqualify the cache outright.
async fn try_remote_serves(
    env: &WrapperEnvironment,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    exact_public_cache_allowed: bool,
) -> RemoteServe {
    if env.circuit_tripped {
        return RemoteServe::Miss;
    }
    // The slice read is cache-only: the driver's `ensure_slice` owns
    // freshness, and a registry round trip on every rustc invocation is
    // exactly the cost the local index exists to remove. Absence is a miss,
    // not an outage.
    let slice =
        match index::cached_slice(&env.env_base.config, &env.target, &env.rustc_version).await {
            Ok(Some(slice)) => slice,
            Ok(None) => {
                tracing::debug!(
                    target = %env.target,
                    rustc_version = %env.rustc_version,
                    "no cached index slice, skipping registry serves"
                );
                return RemoteServe::Miss;
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    target = %env.target,
                    rustc_version = %env.rustc_version,
                    "failed to read cached index slice, skipping registry serves"
                );
                return RemoteServe::Miss;
            }
        };
    if exact_public_cache_allowed {
        match try_remote_exact_serve(env, parsed, request, &slice).await {
            RemoteServe::Miss => {}
            outcome => return outcome,
        }
    }
    if let Some(semantic_request) = env.semantic_request.as_ref() {
        return try_remote_semantic_serve(env, parsed, semantic_request, &slice).await;
    }
    RemoteServe::Miss
}

/// Resolve the exact artifact identity against the index slice, stream its
/// bundle through the edge byte path, and serve it. `Miss` means the index
/// carries no such artifact (or the negative cache already says so);
/// `Bypass` means the artifact arrived but could not be used.
async fn try_remote_exact_serve(
    env: &WrapperEnvironment,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    slice: &index::IndexSlice,
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
    let Some(row) = resolve::find_exact_artifact(&slice.index.rows, request.c_metadata) else {
        log_nonfatal_result(
            "failed to record stow negative cache entry",
            circuit::record_negative_cache(&env.env_base.config, &env.cache_key).await,
        );
        return RemoteServe::Miss;
    };
    let bundle_ref = fetch::BundleRef::from_index_row(&env.target, &env.rustc_version, row);
    match fetch::download_bundle(&env.env_base.config, &bundle_ref).await {
        Ok(bundle) => {
            if try_serve_downloaded_bundle(&env.env_base.config, parsed, request, &bundle).await {
                RemoteServe::Served
            } else {
                RemoteServe::Bypass
            }
        }
        // The index is ahead of the catalog: the edge pruned the row (a
        // stale registry blob) after the slice was published. Remember the
        // miss locally until the next slice; the circuit stays closed.
        Err(fetch::FetchError::NotFound) => {
            log_nonfatal_result(
                "failed to record stow negative cache entry",
                circuit::record_negative_cache(&env.env_base.config, &env.cache_key).await,
            );
            RemoteServe::Miss
        }
        Err(error) => {
            record_circuit_failure(&env.env_base.config).await;
            record_lookup_error(&env.env_base.config, parsed).await;
            tracing::warn!(
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
    env: &WrapperEnvironment,
    parsed: &rustc_args::ParsedRustcArgs,
    semantic_request: &fetch::SemanticFetchRequest,
    slice: &index::IndexSlice,
) -> RemoteServe {
    let row = match resolve::find_semantic_artifact(&slice.index.rows, semantic_request) {
        Ok(row) => row,
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                semantic_crate_name = %semantic_request.crate_name,
                "semantic index lookup failed, falling back to rustc"
            );
            return RemoteServe::Miss;
        }
    };
    let Some(row) = row else {
        return RemoteServe::Miss;
    };
    let bundle_ref = fetch::BundleRef::from_index_row(&env.target, &env.rustc_version, row);
    match fetch::download_bundle(&env.env_base.config, &bundle_ref).await {
        Ok(bundle) => {
            if try_serve_semantic_downloaded_bundle(
                &env.env_base.config,
                parsed,
                semantic_request,
                &bundle,
            )
            .await
            {
                RemoteServe::Served
            } else {
                RemoteServe::Bypass
            }
        }
        Err(fetch::FetchError::NotFound) => RemoteServe::Miss,
        Err(error) => {
            record_circuit_failure(&env.env_base.config).await;
            record_lookup_error(&env.env_base.config, parsed).await;
            tracing::warn!(
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

/// Record a public-cache miss for a registry crate, then run the real rustc.
/// Only a registry package can be a miss: a workspace member is first-party
/// code the public cache never carries, so counting it would report the
/// project's own crates as failures and make a healthy build look broken in
/// the post-build summary.
async fn record_miss(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
) {
    if detect_registry_crate_version(parsed).is_ok_and(|version| version.is_some()) {
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

/// Count a remote-cache failure against the circuit breaker; the record
/// itself must never fail the invocation.
async fn record_circuit_failure(config: &StowConfig) {
    log_nonfatal_result(
        "failed to record stow circuit failure",
        circuit::record_failure(config).await,
    );
}

/// Count a remote-cache success toward resetting the circuit breaker.
async fn record_circuit_success(config: &StowConfig) {
    log_nonfatal_result(
        "failed to record stow circuit success",
        circuit::record_success(config).await,
    );
}

/// Count a failed rust cache lookup as an error stat without failing the
/// invocation — a stats write is not worth a missed compile.
async fn record_lookup_error(config: &StowConfig, parsed: &rustc_args::ParsedRustcArgs) {
    log_nonfatal_result(
        "failed to record rust cache error stats",
        stats::record_error(config, &parsed.crate_name).await,
    );
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

/// Count a served rust cache lookup as a hit stat.
async fn record_lookup_hit(config: &StowConfig, parsed: &rustc_args::ParsedRustcArgs) {
    log_nonfatal_result(
        "failed to record rust cache hit stats",
        stats::record_hit(config, &parsed.crate_name).await,
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
        tracing::warn!(
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
    env_cache: &WrapperEnvCache,
) -> Outcome {
    let build = env_cache.build_state();
    if !parsed.is_locally_cacheable() {
        return compile(rustc, parsed, build, None).await;
    }
    let Some(local_base) = env_cache.local_base(rustc).await else {
        return compile(rustc, parsed, build, None).await;
    };
    let target = parsed
        .target
        .clone()
        .unwrap_or_else(|| local_base.host_target.clone());
    let identity = match build_stable_exact_identity(
        &local_base.config,
        parsed,
        &target,
        &local_base.rustc_version,
    )
    .await
    {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(error = %error, "failed to resolve local artifact identity, bypassing local artifact cache");
            return compile(rustc, parsed, build, Some(&target)).await;
        }
    };
    if must_build_locally(parsed, &target, build.map(AsRef::as_ref)) {
        return compile(rustc, parsed, build, Some(&target)).await;
    }
    if let Some(identity) = identity {
        let request = FetchRequest {
            target: &target,
            rustc_version: &local_base.rustc_version,
            c_metadata: identity.c_metadata.as_str(),
        };
        if try_serve_local_cached_bundle(&local_base.config, parsed, &request).await {
            return Outcome::Served;
        }
    }
    compile(rustc, parsed, build, Some(&target)).await
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

#[tracing::instrument(name = "stow.wrapper.cc_invoke", skip_all)]
async fn run_cc_wrapper(command: WrapperCommandArgs) -> stow_types::error::Result<()> {
    #[cfg(not(windows))]
    let compiler = resolve_cc_compiler(&command.executable);
    #[cfg(windows)]
    let compiler = resolve_cc_compiler(&command.executable)?;
    let compiler_args = &command.wrapped_args;
    let config = match StowConfig::load_local() {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(error = %error, "stow local config unavailable, bypassing C/C++ cache");
            return run_passthrough(&compiler.program, &compiler.env, compiler_args).await;
        }
    };
    if let Err(error) = config.ensure_dirs().await {
        tracing::warn!(error = %error, "failed to prepare stow cache directories, bypassing C/C++ cache");
        return run_passthrough(&compiler.program, &compiler.env, compiler_args).await;
    }

    let outcome = match cc::try_compile(&config, &compiler, compiler_args).await {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(error = %error, "stow C/C++ cache failed, bypassing cache");
            return run_passthrough(&compiler.program, &compiler.env, compiler_args).await;
        }
    };

    match outcome {
        cc::CcOutcome::Passthrough => {
            run_passthrough(&compiler.program, &compiler.env, compiler_args).await
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
            std::process::exit(0);
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
                std::process::exit(compiler_status.code().unwrap_or(1));
            }

            if let Err(error) = cc::store_compiled_object(&cache_path, &output_path).await {
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
                std::process::exit(0);
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
            std::process::exit(0);
        }
    }
}

async fn try_serve_local_cached_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
) -> bool {
    let cached_bundle = match load_cached_bundle(config, request).await {
        Ok(bundle) => bundle,
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to read local stow artifact cache entry"
            );
            log_nonfatal_result(
                "failed to record rust cache error stats",
                stats::record_error(config, &parsed.crate_name).await,
            );
            return false;
        }
    };
    let Some(cached_bundle) = cached_bundle else {
        return false;
    };
    try_serve_loaded_local_cached_bundle(
        config,
        parsed,
        request,
        EntryOrigin::ExactKey,
        cached_bundle,
    )
    .await
}

async fn try_serve_local_prefetched_graph_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
) -> bool {
    let Some((expected_features_json, expected_dependency_c_metadata_json, candidates)) =
        prefetched_graph_expectations(config, parsed, target, rustc_version).await
    else {
        return false;
    };
    let Some((_, version)) = detect_registry_crate_version(parsed).ok().flatten() else {
        return false;
    };

    for c_metadata in candidates {
        let request = FetchRequest {
            target,
            rustc_version,
            c_metadata: c_metadata.as_str(),
        };
        let cached_bundle = match load_cached_bundle(config, &request).await {
            Ok(Some(bundle)) => bundle,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    target,
                    rustc_version,
                    candidate_c_metadata = %c_metadata,
                    "failed to read prefetched graph bundle from local cache"
                );
                return false;
            }
        };
        if let Err(error) = validate_prefetched_graph_bundle(
            parsed,
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
        if try_serve_loaded_local_cached_bundle(
            config,
            parsed,
            &request,
            EntryOrigin::GraphCandidate,
            cached_bundle,
        )
        .await
        {
            return true;
        }
    }
    false
}

/// The expectations a prefetched graph candidate is checked against:
/// this invocation's semantic features, its dependencies' identities,
/// and the candidates the plan staged — `None` whenever any of the
/// three cannot be resolved (already warned).
async fn prefetched_graph_expectations(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
) -> Option<(String, String, Vec<String>)> {
    let (crate_name, version) = detect_registry_crate_version(parsed).ok().flatten()?;
    let features_json = resolve_semantic_features_json(config, &crate_name, &version, parsed)
        .map_err(|error| {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                target,
                rustc_version,
                "failed to resolve semantic features for prefetched graph bundle lookup"
            );
        })
        .ok()?;
    let dependency_c_metadata_json = resolve_dependency_c_metadata_json(config, parsed)
        .await
        .map_err(|error| {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                target,
                rustc_version,
                "failed to resolve prefetched graph dependency identities"
            );
        })
        .ok()?
        .or_else(|| parsed.extern_crates.is_empty().then(|| "[]".to_owned()))?;
    let candidates = load_prefetched_graph_candidate_c_metadatas(config, &parsed.crate_name)
        .map_err(|error| {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                target,
                rustc_version,
                "failed to parse prefetched graph artifact candidates"
            );
        })
        .ok()?;
    Some((features_json, dependency_c_metadata_json, candidates))
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
    request: &FetchRequest<'_>,
    origin: EntryOrigin,
    cached_bundle: artifact_cache::CachedArtifactBundle,
) -> bool {
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
                return false;
            }
            EntryOrigin::ExactKey => {}
        }
        tracing::warn!(
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
        record_lookup_error(config, parsed).await;
        return false;
    }

    if let Err(error) = verify::verify_cached_bundle_signature(config, &cached_bundle).await {
        tracing::warn!(
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
        record_lookup_error(config, parsed).await;
        return false;
    }

    if let Err(error) =
        prune_materialized_aliases_for_cached_closure(config, parsed, request, &cached_bundle).await
    {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "failed to materialize dependency closure aliases for local stow artifact cache entry"
        );
        record_lookup_error(config, parsed).await;
        return false;
    }

    materialize_local_cached_bundle(config, parsed, request, cached_bundle).await
}

/// Write a verified local cache entry's artifacts into the target dir.
/// `false` means the entry could not be materialized — it is evicted so the
/// next lookup does not trip over it again.
async fn materialize_local_cached_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: artifact_cache::CachedArtifactBundle,
) -> bool {
    match inject::write_artifacts(parsed, &cached_bundle, inject::OutputDirWriters::StowOnly).await
    {
        Ok(()) => finish_local_serve(config, parsed, request, cached_bundle).await,
        Err(error) => {
            tracing::warn!(
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
            record_lookup_error(config, parsed).await;
            false
        }
    }
}

/// The bookkeeping that turns written artifacts into a served hit: record
/// what was materialized, replay rustc's artifact notifications so cargo
/// sees a normal compile, then count the hit.
async fn finish_local_serve(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: artifact_cache::CachedArtifactBundle,
) -> bool {
    if let Err(error) = record_materialized_bundle_outputs(config, parsed, &cached_bundle).await {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "failed to record materialized local stow artifact outputs"
        );
        record_lookup_error(config, parsed).await;
        return false;
    }
    if let Err(error) = emit_cached_rustc_artifact_notifications(parsed).await {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "failed to replay rustc artifact notifications for local stow artifact cache entry"
        );
        drop(cached_bundle);
        evict_cached_bundle(
            config,
            parsed,
            request,
            "failed to evict local stow artifact cache entry missing rustc artifact notifications",
        )
        .await;
        record_lookup_error(config, parsed).await;
        return false;
    }
    record_lookup_hit(config, parsed).await;
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
    true
}

fn load_prefetched_graph_candidate_c_metadatas(
    config: &StowConfig,
    crate_name: &str,
) -> stow_types::error::Result<Vec<String>> {
    if let Some(build) = config.build_state() {
        return Ok(build.prefetch_candidate_c_metadatas(crate_name));
    }
    Ok(load_prefetched_graph_artifacts()?
        .into_iter()
        .filter(|entry| {
            canonical_crate_name(entry.crate_name.as_str()) == canonical_crate_name(crate_name)
        })
        .map(|entry| entry.c_metadata.into_inner())
        .collect())
}

fn load_prefetched_graph_artifacts() -> stow_types::error::Result<Vec<resolve::PrefetchArtifactRow>>
{
    let Some(raw) = std::env::var_os(STOW_PREFETCH_ARTIFACTS_ENV) else {
        return Ok(Vec::new());
    };
    let raw = raw.into_string().map_err(|_| {
        stow_types::stow_error!("{STOW_PREFETCH_ARTIFACTS_ENV} must be valid UTF-8")
    })?;
    serde_json::from_str::<Vec<resolve::PrefetchArtifactRow>>(&raw)
        .wrap_err_with(|| format!("parse {STOW_PREFETCH_ARTIFACTS_ENV}"))
}

async fn prune_materialized_aliases_for_cached_closure(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: &artifact_cache::CachedArtifactBundle,
) -> stow_types::error::Result<()> {
    let Some(out_dir) = parsed.out_dir.as_ref() else {
        return Ok(());
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

    let mut keep_original_file_names = BTreeSet::new();
    let mut closure_compile_keys = BTreeSet::new();
    let mut closure_crates = BTreeSet::from([canonical_crate_name(&cached_bundle.crate_name)]);
    let mut closure_visited = BTreeSet::new();
    collect_dependency_closure_file_names(
        cached_bundle,
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
    }

    Ok(())
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

fn validate_prefetched_graph_bundle(
    parsed: &rustc_args::ParsedRustcArgs,
    expected_version: &str,
    expected_features_json: &str,
    expected_dependency_c_metadata_json: &str,
    cached_bundle: &artifact_cache::CachedArtifactBundle,
) -> stow_types::error::Result<()> {
    if canonical_crate_name(&cached_bundle.crate_name) != canonical_crate_name(&parsed.crate_name) {
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
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    bundle: &fetch::ArtifactBundle,
) -> bool {
    if let Err(error) = fetch::validate_bundle_identity(
        bundle,
        &parsed.crate_name,
        request.c_metadata,
        request.target,
        request.rustc_version,
    ) {
        tracing::warn!(
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
        log_nonfatal_result(
            "failed to record rust cache miss stats",
            stats::record_miss(config, &parsed.crate_name).await,
        );
        return false;
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
        tracing::warn!(
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
        log_nonfatal_result(
            "failed to record rust cache miss stats",
            stats::record_miss(config, &parsed.crate_name).await,
        );
        return false;
    }
    try_serve_verified_downloaded_bundle(config, parsed, request, bundle).await
}

async fn try_serve_local_semantic_cached_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    semantic_request: &fetch::SemanticFetchRequest,
) -> bool {
    let cached_bundle = match load_semantic_cached_bundle(config, semantic_request).await {
        Ok(bundle) => bundle,
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                semantic_crate_name = %semantic_request.crate_name,
                semantic_version = %semantic_request.version,
                target = %semantic_request.target,
                rustc_version = %semantic_request.rustc_version,
                "failed to read local semantic stow artifact cache entry"
            );
            record_lookup_error(config, parsed).await;
            return false;
        }
    };
    let Some(cached_bundle) = cached_bundle else {
        return false;
    };
    if let Some(mismatch) = bundle_mismatch(
        parsed,
        &cached_bundle.profile,
        &cached_bundle.emit,
        &cached_bundle.kind,
        &cached_bundle.crate_types,
        &cached_bundle.crate_version,
    ) {
        record_profile_divergence(config, &mismatch).await;
        tracing::warn!(
            error = %mismatch,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "local semantic stow artifact cache entry semantic mismatch"
        );
        record_lookup_error(config, parsed).await;
        return false;
    }
    if let Err(error) = verify::verify_cached_bundle_signature(config, &cached_bundle).await {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "local semantic stow artifact cache entry failed verification"
        );
        record_lookup_error(config, parsed).await;
        return false;
    }
    let request = FetchRequest {
        target: &semantic_request.target,
        rustc_version: &semantic_request.rustc_version,
        c_metadata: &cached_bundle.c_metadata,
    };
    if let Err(error) =
        prune_materialized_aliases_for_cached_closure(config, parsed, &request, &cached_bundle)
            .await
    {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "failed to materialize dependency closure aliases for local semantic stow artifact cache entry"
        );
        record_lookup_error(config, parsed).await;
        return false;
    }

    materialize_semantic_cached_bundle(config, parsed, semantic_request, cached_bundle).await
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
) -> bool {
    if let Err(error) =
        inject::write_artifacts(parsed, &cached_bundle, inject::OutputDirWriters::StowOnly).await
    {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "failed to materialize local semantic stow artifact cache entry"
        );
        record_lookup_error(config, parsed).await;
        return false;
    }
    if let Err(error) = record_materialized_bundle_outputs(config, parsed, &cached_bundle).await {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "failed to record materialized local semantic stow artifact outputs"
        );
        record_lookup_error(config, parsed).await;
        return false;
    }
    if let Err(error) = emit_cached_rustc_artifact_notifications(parsed).await {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "failed to replay rustc artifact notifications for local semantic stow artifact cache entry"
        );
        record_lookup_error(config, parsed).await;
        return false;
    }
    record_lookup_hit(config, parsed).await;
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
    true
}

async fn try_serve_semantic_downloaded_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    semantic_request: &fetch::SemanticFetchRequest,
    bundle: &fetch::ArtifactBundle,
) -> bool {
    if let Err(error) = fetch::validate_semantic_bundle_identity(bundle, semantic_request) {
        tracing::warn!(
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
        // for the full reset window. Only transport and materialization
        // failures say the cache path itself is unhealthy.
        log_nonfatal_result(
            "failed to record rust cache miss stats",
            stats::record_miss(config, &parsed.crate_name).await,
        );
        return false;
    }
    match semantic_request_allowed_by_expanded_graph(semantic_request) {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                crate_name = %parsed.crate_name,
                semantic_crate_name = %semantic_request.crate_name,
                semantic_version = %semantic_request.version,
                target = %semantic_request.target,
                rustc_version = %semantic_request.rustc_version,
                semantic_c_metadata = %bundle.manifest.config.c_metadata,
                "rejecting semantic bundle outside expanded dependency graph"
            );
            return false;
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                semantic_crate_name = %semantic_request.crate_name,
                semantic_version = %semantic_request.version,
                target = %semantic_request.target,
                rustc_version = %semantic_request.rustc_version,
                "failed to validate semantic bundle against expanded dependency graph"
            );
            return false;
        }
    }

    let request = FetchRequest {
        target: bundle.manifest.config.target.as_str(),
        rustc_version: bundle.manifest.config.rustc_version.as_str(),
        c_metadata: bundle.manifest.config.c_metadata.as_str(),
    };
    try_serve_verified_downloaded_bundle(config, parsed, &request, bundle).await
}

async fn try_serve_verified_downloaded_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    bundle: &fetch::ArtifactBundle,
) -> bool {
    let cached_bundle = match cache_verified_downloaded_bundle(config, request, bundle).await {
        Ok(cached_bundle) => cached_bundle,
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to cache verified stow bundle"
            );
            record_circuit_failure(config).await;
            record_lookup_error(config, parsed).await;
            return false;
        }
    };

    if let Err(error) =
        prune_materialized_aliases_for_cached_closure(config, parsed, request, &cached_bundle).await
    {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "failed to materialize dependency closure aliases for downloaded stow bundle"
        );
        drop(cached_bundle);
        evict_cached_bundle(
            config,
            parsed,
            request,
            "failed to evict downloaded stow bundle with incomplete dependency closure aliases",
        )
        .await;
        record_circuit_failure(config).await;
        record_lookup_error(config, parsed).await;
        return false;
    }

    materialize_downloaded_bundle(config, parsed, request, cached_bundle).await
}

/// Write a verified downloaded bundle's artifacts into the target dir.
/// `false` means the freshly cached entry could not be materialized — it is
/// evicted and counted against the circuit breaker.
async fn materialize_downloaded_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: artifact_cache::CachedArtifactBundle,
) -> bool {
    match inject::write_artifacts(parsed, &cached_bundle, inject::OutputDirWriters::StowOnly).await
    {
        Ok(()) => finish_downloaded_serve(config, parsed, request, cached_bundle).await,
        Err(error) => {
            tracing::warn!(
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
            record_circuit_failure(config).await;
            record_lookup_error(config, parsed).await;
            false
        }
    }
}

/// The bookkeeping that turns a materialized downloaded bundle into a served
/// hit: record outputs, replay rustc's artifact notifications, then count
/// the circuit success and the lookup hit.
async fn finish_downloaded_serve(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: artifact_cache::CachedArtifactBundle,
) -> bool {
    if let Err(error) = record_materialized_bundle_outputs(config, parsed, &cached_bundle).await {
        tracing::warn!(
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
        record_circuit_failure(config).await;
        record_lookup_error(config, parsed).await;
        return false;
    }
    if let Err(error) = emit_cached_rustc_artifact_notifications(parsed).await {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "failed to replay rustc artifact notifications for downloaded stow bundle"
        );
        drop(cached_bundle);
        evict_cached_bundle(
            config,
            parsed,
            request,
            "failed to evict downloaded stow bundle missing rustc artifact notifications",
        )
        .await;
        record_circuit_failure(config).await;
        record_lookup_error(config, parsed).await;
        return false;
    }
    record_circuit_success(config).await;
    record_lookup_hit(config, parsed).await;
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
    true
}

async fn build_semantic_fetch_request(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<Option<fetch::SemanticFetchRequest>> {
    let Some((crate_name, version)) = detect_registry_crate_version(parsed)? else {
        return Ok(None);
    };
    let dependency_c_metadata_json =
        match resolve_dependency_c_metadata_json(config, parsed).await? {
            Some(value) => value,
            None if parsed.extern_crates.is_empty() => "[]".to_owned(),
            None => return Ok(None),
        };
    let emit = parsed.emit.iter().cloned().collect::<Vec<_>>();
    let profile = semantic_request_profile(parsed)?;
    let kind = parsed_artifact_kind(parsed)?;
    let crate_types = parsed_crate_types(parsed)?;
    let features_json = resolve_semantic_features_json(config, &crate_name, &version, parsed)?;
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
    }))
}

async fn build_stable_exact_identity(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
) -> stow_types::error::Result<Option<stow_types::public_cache::StableRegistryArtifactIdentity>> {
    let Some((crate_name, version)) = detect_registry_crate_version(parsed)? else {
        trace_identity_inputs(
            parsed,
            target,
            rustc_version,
            None,
            None,
            "not-a-registry-crate",
        )
        .await;
        return Ok(None);
    };
    let dependency_c_metadata_json =
        match resolve_dependency_c_metadata_json(config, parsed).await? {
            Some(value) => value,
            None if parsed.extern_crates.is_empty() => "[]".to_owned(),
            None => {
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
    let features_json = resolve_semantic_features_json(config, &crate_name, &version, parsed)?;
    let identity = stable_registry_artifact_identity(
        parsed,
        target,
        rustc_version,
        &features_json,
        &dependency_c_metadata_json,
    )?;
    trace_identity_inputs(
        parsed,
        target,
        rustc_version,
        Some(IdentityTraceInputs {
            crate_name: &crate_name,
            version: &version,
            features_json: &features_json,
            dependency_c_metadata_json: &dependency_c_metadata_json,
        }),
        identity.as_ref(),
        "computed",
    )
    .await;
    Ok(identity)
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
    identity: Option<&stow_types::public_cache::StableRegistryArtifactIdentity>,
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

/// Resolve the stable identity a finished local build would carry as a cache
/// entry, plus the identity inputs `store_local_build_outputs` persists with
/// it. `None` means the invocation is not a registry crate or its dependency
/// identities have not been recorded yet.
async fn resolve_local_build_artifact(
    base: &WrapperEnvBase,
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<Option<artifact_cache::LocalBuildArtifact>> {
    let config = &base.config;
    // The unit's own platform — the compiling rustc's real host triple
    // when cargo passed no `--target`, never the
    // `STOW_PUBLIC_CACHE_TARGET` consumer shortcut (stow#317).
    let target = parsed
        .target
        .clone()
        .unwrap_or_else(|| base.host_target.clone());
    let rustc_version = base.rustc_version.clone();
    let dependency_c_metadata_json =
        match resolve_dependency_c_metadata_json(config, parsed).await? {
            Some(value) => value,
            None if parsed.extern_crates.is_empty() => "[]".to_owned(),
            None => return Ok(None),
        };
    let Some((crate_name, version)) = detect_registry_crate_version(parsed)? else {
        return Ok(None);
    };
    let features_json = resolve_semantic_features_json(config, &crate_name, &version, parsed)?;
    let Some(identity) = stable_registry_artifact_identity(
        parsed,
        &target,
        &rustc_version,
        &features_json,
        &dependency_c_metadata_json,
    )?
    else {
        return Ok(None);
    };
    Ok(Some(artifact_cache::LocalBuildArtifact {
        target,
        rustc_version,
        identity,
        features_json,
        dependency_c_metadata_json,
        build_script_out_dir: std::env::var_os("OUT_DIR").map(PathBuf::from),
    }))
}

fn semantic_request_profile(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<stow_types::platform::Profile> {
    normalized_requested_profile(parsed)
}

fn resolve_semantic_features_json(
    config: &StowConfig,
    crate_name: &str,
    version: &str,
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<String> {
    if let Some(features_json) =
        lookup_expanded_graph_features_json(config, crate_name, version, &parsed.features)?
    {
        return Ok(features_json);
    }
    serde_json::to_string(&parsed.features.iter().cloned().collect::<Vec<_>>())
        .wrap_err("serialize semantic rustc features")
}

fn lookup_expanded_graph_features_json(
    config: &StowConfig,
    crate_name: &str,
    version: &str,
    parsed_features: &std::collections::BTreeSet<String>,
) -> stow_types::error::Result<Option<String>> {
    if let Some(build) = config.build_state() {
        return build.expanded_features_json(crate_name, version, parsed_features);
    }
    let Some(raw) = std::env::var_os(STOW_EXPANDED_GRAPH_ENV) else {
        return Ok(None);
    };
    let raw = raw
        .into_string()
        .map_err(|_| stow_types::stow_error!("{STOW_EXPANDED_GRAPH_ENV} must be valid UTF-8"))?;
    let entries = serde_json::from_str::<Vec<DependencyGraphEntry>>(&raw)
        .wrap_err_with(|| format!("parse {STOW_EXPANDED_GRAPH_ENV}"))?;
    let requested_version = semver::Version::parse(version)
        .wrap_err_with(|| format!("parse semantic request version `{version}`"))?;
    let canonical_name = canonical_crate_name(crate_name);
    let mut matches = entries
        .into_iter()
        .filter(|entry| {
            if canonical_crate_name(entry.crate_name.as_str()) != canonical_name
                || entry.version != requested_version
            {
                return false;
            }
            let expanded_features = entry
                .features
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            parsed_features
                .iter()
                .all(|feature| expanded_features.contains(feature))
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        left.features
            .len()
            .cmp(&right.features.len())
            .then(left.features.cmp(&right.features))
    });
    if let Some(best) = matches.first() {
        let best_len = best.features.len();
        matches.retain(|entry| entry.features.len() == best_len);
    }
    matches.dedup_by(|left, right| left.features == right.features);
    match matches.as_slice() {
        [] => Ok(None),
        [entry] => serde_json::to_string(&entry.features)
            .wrap_err("serialize expanded graph semantic features")
            .map(Some),
        _ => Err(stow_types::stow_error!(
            "{STOW_EXPANDED_GRAPH_ENV} contains duplicate exact feature sets for {} {}",
            crate_name,
            version
        )),
    }
}

fn detect_registry_crate_version(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<Option<(String, String)>> {
    shared_detect_registry_crate_version(parsed)
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
    if let Some((_, requested_version)) = detect_registry_crate_version(parsed)?
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

fn semantic_request_allowed_by_expanded_graph(
    semantic_request: &fetch::SemanticFetchRequest,
) -> stow_types::error::Result<bool> {
    let Some(raw) = std::env::var_os(STOW_EXPANDED_GRAPH_ENV) else {
        return Ok(true);
    };
    let raw = raw
        .into_string()
        .map_err(|_| stow_types::stow_error!("{STOW_EXPANDED_GRAPH_ENV} must be valid UTF-8"))?;
    let entries = serde_json::from_str::<Vec<DependencyGraphEntry>>(&raw)
        .wrap_err_with(|| format!("parse {STOW_EXPANDED_GRAPH_ENV}"))?;
    Ok(entries.iter().any(|entry| {
        canonical_crate_name(entry.crate_name.as_str())
            == canonical_crate_name(&semantic_request.crate_name)
            && entry.version.to_string() == semantic_request.version
            && serde_json::to_string(&entry.features)
                .is_ok_and(|features_json| features_json == semantic_request.features_json)
    }))
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

#[derive(Debug, PartialEq, Eq)]
struct RustcArtifactNotification {
    artifact: PathBuf,
    emit: &'static str,
}

fn cached_rustc_artifact_notifications(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<Vec<RustcArtifactNotification>> {
    let mut notifications = Vec::new();
    if parsed.emit.contains("dep-info") {
        notifications.push(RustcArtifactNotification {
            artifact: parsed.output_dep_info_path().ok_or_else(|| {
                stow_types::stow_error!("cached rustc invocation is missing dep-info path")
            })?,
            emit: "dep-info",
        });
    }
    if parsed.emit.contains("metadata") {
        notifications.push(RustcArtifactNotification {
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
            .output_link_path()
            .map_err(stow_types::error::Error::msg)?
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "cached rustc invocation cannot emit link artifact for crate types {:?}",
                    parsed.crate_types
                )
            })?;
        notifications.push(RustcArtifactNotification {
            artifact,
            emit: "link",
        });
    }
    Ok(notifications)
}

async fn emit_cached_rustc_artifact_notifications(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<()> {
    if !parsed.requests_json_artifact_notifications() {
        return Ok(());
    }

    let notifications = cached_rustc_artifact_notifications(parsed)?;
    let mut stderr = tokio::io::stderr();
    for notification in notifications {
        let message = serde_json::json!({
            "$message_type": "artifact",
            "artifact": notification.artifact,
            "emit": notification.emit,
        });
        let line = message.to_string();
        stderr
            .write_all(line.as_bytes())
            .await
            .wrap_err("write rustc artifact notification")?;
        stderr
            .write_all(b"\n")
            .await
            .wrap_err("terminate rustc artifact notification")?;
    }
    stderr
        .flush()
        .await
        .wrap_err("flush rustc artifact notifications")
}

pub(crate) fn write_stdout(message: &str) -> stow_types::error::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(message.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn install_tracing() -> TracingGuard {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    // stderr, never stdout: `run()` also serves the `rustc` / `cc` wrapper
    // subcommands, whose stdout must stay byte-identical to the wrapped
    // compiler's. Cargo hashes `rustc -vV` stdout into every unit's
    // `-C metadata`, so a single log line there changes the cache key of
    // every crate in the build on every invocation.
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr);

    let chrome = std::env::var_os(STOW_TRACE_FILE_ENV).map(|path| {
        tracing_chrome::ChromeLayerBuilder::new()
            .file(PathBuf::from(path))
            .include_args(true)
            .build()
    });

    if let Some((chrome_layer, chrome_guard)) = chrome {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .with(chrome_layer)
            .try_init();
        TracingGuard {
            _chrome: Some(chrome_guard),
        }
    } else {
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init();
        TracingGuard { _chrome: None }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{
        UnparseableInvocation, cached_rustc_artifact_notifications, classify_invocation,
        expand_wrapper_role, should_install_tracing_for_args, strip_cargo_subcommand_word,
    };
    use crate::rustc_args::ParsedRustcArgs;

    fn args(parts: &[&str]) -> Vec<std::ffi::OsString> {
        parts.iter().map(std::ffi::OsString::from).collect()
    }

    fn env_value(value: Option<&str>) -> Option<OsString> {
        value.map(OsString::from)
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

        let notifications =
            cached_rustc_artifact_notifications(&parsed).expect("build artifact notifications");

        assert_eq!(
            notifications,
            vec![
                super::RustcArtifactNotification {
                    artifact: PathBuf::from("/tmp/out/autocfg-xyz789.d"),
                    emit: "dep-info",
                },
                super::RustcArtifactNotification {
                    artifact: PathBuf::from("/tmp/out/libautocfg-xyz789.rmeta"),
                    emit: "metadata",
                },
                super::RustcArtifactNotification {
                    artifact: PathBuf::from("/tmp/out/libautocfg-xyz789.rlib"),
                    emit: "link",
                },
            ]
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

        let notifications =
            cached_rustc_artifact_notifications(&parsed).expect("build artifact notifications");

        assert_eq!(
            notifications,
            vec![
                super::RustcArtifactNotification {
                    artifact: PathBuf::from("/tmp/out/serde_derive-xyz789.d"),
                    emit: "dep-info",
                },
                super::RustcArtifactNotification {
                    artifact: PathBuf::from("/tmp/out/libserde_derive-xyz789.dylib"),
                    emit: "link",
                },
            ]
        );
    }
}

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

mod artifact_cache;
mod cache_policy;
mod commands;
mod lockfile_graph_cache;
mod cargo_cmd;
mod cc;
mod circuit;
mod cli_args;
mod config;
mod fetch;
mod graph_cache;
mod inject;
mod prefetch;
mod profile_guard;
mod rustc_args;
mod state_db;
mod stats;
mod verify;
mod workspace_deps;
use stow_shim as wrapper_shim;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::PathBuf;

use async_process::Command;
use clap::Parser;
use stow_types::error::Context;
use stow_types::identity::DependencyCompileKeyIdentity;
use stow_types::public_cache::{
    StableRegistryArtifactIdentity,
    detect_registry_crate_version as shared_detect_registry_crate_version,
    normalized_cache_profile, stable_c_metadata_for_compile_key, stable_registry_artifact_identity,
};
use tokio::io::AsyncWriteExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::artifact_cache::{
    load_cached_bundle, load_cached_bundle_by_compile_key, load_semantic_cached_bundle,
    prepare_local_cache, record_materialized_bundle_outputs,
    record_materialized_local_build_outputs, remove_cached_bundle,
    resolve_dependency_c_metadata_json, store_downloaded_bundle,
};
use crate::cli_args::{Cli, Command as CliCommand, WrapperCommandArgs};
use crate::config::StowConfig;
use crate::fetch::FetchRequest;
use stow_types::api::{BatchArtifactRequestEntry, DependencyGraphEntry};

const STOW_EXPANDED_GRAPH_ENV: &str = "STOW_EXPANDED_GRAPH_JSON";
pub(crate) const STOW_PREFETCH_ARTIFACTS_ENV: &str = "STOW_PREFETCH_ARTIFACTS_JSON";
pub(crate) const STOW_ENABLE_SEMANTIC_FALLBACK_ENV: &str = "STOW_ENABLE_SEMANTIC_FALLBACK";
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

pub fn run() -> stow_types::error::Result<()> {
    let _tracing_guard = should_install_tracing().then(install_tracing);
    // The rustc wrapper subcommand has at most one concurrent network task per
    // invocation and is called hundreds of times per `cargo build`, so the
    // multi-threaded runtime's worker-pool spin-up is wasted overhead. Use
    // `current_thread` for wrapper invocations and the multi-threaded runtime
    // for user-facing commands that can fan out (prefetch, batch fetch, etc.).
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
    runtime.block_on(async_main())
}

fn is_wrapper_invocation() -> bool {
    matches!(
        std::env::args_os().nth(1).as_deref(),
        Some(arg) if arg == "rustc" || arg == "cc"
    )
}

fn should_install_tracing() -> bool {
    let args = std::env::args_os().collect::<Vec<_>>();
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
    let args = std::env::args_os().collect::<Vec<_>>();
    let cli = parse_cli_or_exit(&args)?;
    let span = tracing::Span::current();
    span.record("subcommand", subcommand_name(&cli.command));
    match cli.command {
        CliCommand::Check(command) => cargo_cmd::run("check", command).await,
        CliCommand::Build(command) => cargo_cmd::run("build", command).await,
        CliCommand::Test(command) => cargo_cmd::run("test", command).await,
        CliCommand::Predict(command) => cargo_cmd::predict(command).await,
        CliCommand::Setup => commands::setup_project().await,
        CliCommand::Status => commands::status_project().await,
        CliCommand::Clean => commands::clean_project().await,
        CliCommand::CheckArtifact(command) => commands::check_artifact(command).await,
        CliCommand::FetchArtifact(command) => commands::fetch_artifact(command).await,
        CliCommand::Rustc(command) => run_rustc_wrapper(command).await,
        CliCommand::Cc(command) => run_cc_wrapper(command).await,
        CliCommand::PurgeCacheDir(command) => commands::purge_cache_dirs(command).await,
    }
}

const fn subcommand_name(command: &CliCommand) -> &'static str {
    match command {
        CliCommand::Check(_) => "check",
        CliCommand::Build(_) => "build",
        CliCommand::Test(_) => "test",
        CliCommand::Predict(_) => "predict",
        CliCommand::Setup => "setup",
        CliCommand::Status => "status",
        CliCommand::Clean => "clean",
        CliCommand::CheckArtifact(_) => "check-artifact",
        CliCommand::FetchArtifact(_) => "fetch-artifact",
        CliCommand::Rustc(_) => "rustc",
        CliCommand::Cc(_) => "cc",
        CliCommand::PurgeCacheDir(_) => "purge-cache-dir",
    }
}

async fn run_passthrough(
    executable: &OsString,
    wrapped_args: &[std::ffi::OsString],
) -> stow_types::error::Result<()> {
    let status = run_passthrough_status(executable, wrapped_args).await?;

    std::process::exit(status.code().unwrap_or(1));
}

async fn run_passthrough_status(
    executable: &OsString,
    wrapped_args: &[std::ffi::OsString],
) -> stow_types::error::Result<async_process::ExitStatus> {
    Command::new(executable)
        .args(wrapped_args)
        .status()
        .await
        .wrap_err("failed to spawn wrapped compiler")
}

async fn run_rustc_passthrough(
    executable: &OsString,
    wrapped_args: &[std::ffi::OsString],
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<()> {
    let status = run_passthrough_status(executable, wrapped_args).await?;
    if status.success() {
        if let Ok(config) = StowConfig::load() {
            match resolve_local_artifact_identity(&config, executable, parsed).await {
                Ok(Some(identity)) => {
                    log_nonfatal_result(
                        "failed to materialize stable local build aliases after successful rustc build",
                        inject::materialize_local_build_stable_aliases(parsed, &identity).await,
                    );
                    log_nonfatal_result(
                        "failed to record materialized stow output metadata after local rustc build",
                        record_materialized_local_build_outputs(&config, parsed, &identity).await,
                    );
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
    std::process::exit(status.code().unwrap_or(1));
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

#[tracing::instrument(name = "stow.wrapper.invoke", skip_all, fields(crate_name, cache_hit))]
async fn run_rustc_wrapper(command: WrapperCommandArgs) -> stow_types::error::Result<()> {
    let rustc = &command.executable;
    let parsed = match rustc_args::ParsedRustcArgs::parse(&command.wrapped_args) {
        Ok(parsed) => parsed,
        Err(error) if error.contains("missing --crate-name") => {
            tracing::debug!(error = %error, "rustc probe invocation detected, bypassing cache");
            return run_passthrough(rustc, &command.wrapped_args).await;
        }
        Err(error) => {
            return Err(stow_types::stow_error!(
                "parse rustc wrapper arguments: {error}"
            ));
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
        return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
    }

    if std::env::var_os("STOW_DISABLE_PUBLIC_CACHE").is_some() {
        tracing::debug!("public rust cache disabled for this cargo invocation");
        return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
    }
    let exact_public_cache_allowed = match cache_policy::public_cache_allowed(&parsed) {
        Some(false) => {
            tracing::debug!(
                crate_name = %parsed.crate_name,
                "public exact rust cache disabled by stow cache policy for this invocation"
            );
            false
        }
        Some(true) | None => true,
    };

    let config = match StowConfig::load() {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(error = %error, "stow edge config unavailable, bypassing rust cache");
            return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
        }
    };
    if let Err(error) = config.ensure_dirs().await {
        tracing::warn!(error = %error, "failed to prepare stow cache directories, bypassing rust cache");
        return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
    }
    let circuit_tripped = match circuit::is_tripped(&config).await {
        Ok(tripped) => tripped,
        Err(error) => {
            tracing::warn!(error = %error, "failed to read stow circuit state, bypassing rust cache");
            return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
        }
    };
    if circuit_tripped {
        tracing::debug!("circuit breaker tripped, bypassing cache");
        return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
    }

    let target = match parsed.target.as_deref() {
        Some(target) => target.to_owned(),
        None => match rustc_args::detect_rustc_host_target(rustc).await {
            Ok(target) => target,
            Err(error) => {
                tracing::warn!(error = %error, "failed to detect rustc host target, bypassing rust cache");
                return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
            }
        },
    };
    let Some(c_metadata) = parsed.c_metadata.as_deref() else {
        tracing::warn!("cacheable rustc invocation is missing -C metadata, bypassing rust cache");
        return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
    };
    let rustc_version = match rustc_args::detect_rustc_version(rustc).await {
        Ok(version) => version,
        Err(error) => {
            tracing::warn!(error = %error, "failed to detect rustc version, bypassing rust cache");
            return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
        }
    };
    let cache_key = format!("{target}/{rustc_version}/{c_metadata}");
    let _version_cache_lease = match prepare_local_cache(&config, &rustc_version).await {
        Ok(lease) => lease,
        Err(error) => {
            tracing::warn!(error = %error, "failed to prepare local stow artifact cache, bypassing rust cache");
            return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
        }
    };

    let stable_exact_identity =
        build_stable_exact_identity(&config, &parsed, &target, &rustc_version).await?;
    let request_c_metadata = stable_exact_identity
        .as_ref()
        .map_or(c_metadata, |identity| identity.c_metadata.as_str());
    let request = FetchRequest {
        target: &target,
        rustc_version: &rustc_version,
        c_metadata: request_c_metadata,
        crate_name: &parsed.crate_name,
    };
    let semantic_fallback_enabled =
        std::env::var_os(STOW_ENABLE_SEMANTIC_FALLBACK_ENV).is_some_and(|value| value != "0");
    let semantic_request = if semantic_fallback_enabled {
        build_semantic_fetch_request(&config, &parsed, &target, &rustc_version).await?
    } else {
        None
    };
    if try_serve_local_cached_bundle(&config, &parsed, &request).await {
        std::process::exit(0);
    }
    if try_serve_local_prefetched_graph_bundle(&config, &parsed, &target, &rustc_version).await {
        std::process::exit(0);
    }
    if let Some(semantic_request) = semantic_request.as_ref()
        && try_serve_local_semantic_cached_bundle(&config, &parsed, semantic_request).await
    {
        std::process::exit(0);
    }

    if exact_public_cache_allowed {
        let negative_cache_hit = match circuit::negative_cache_contains(&config, &cache_key).await {
            Ok(hit) => hit,
            Err(error) => {
                tracing::warn!(error = %error, cache_key = %cache_key, "failed to read stow negative cache");
                false
            }
        };
        if negative_cache_hit {
            tracing::debug!(cache_key = %cache_key, "negative cache hit, bypassing exact edge fetch");
        } else {
            let fetch_result = fetch::download_bundle(&config, &request).await;

            match fetch_result {
                Ok(bundle) => {
                    if try_serve_downloaded_bundle(&config, &parsed, &request, &bundle).await {
                        std::process::exit(0);
                    }
                    return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
                }
                Err(fetch::FetchError::NotFound) => {
                    log_nonfatal_result(
                        "failed to record stow negative cache entry",
                        circuit::record_negative_cache(&config, &cache_key).await,
                    );
                }
                Err(error) => {
                    log_nonfatal_result(
                        "failed to record stow circuit failure",
                        circuit::record_failure(&config).await,
                    );
                    log_nonfatal_result(
                        "failed to record rust cache error stats",
                        stats::record_error(&config, &parsed.crate_name).await,
                    );
                    tracing::warn!(
                        crate_name = %parsed.crate_name,
                        target = %target,
                        rustc_version = %rustc_version,
                        error = %error,
                        "stow exact fetch failed, falling back to semantic or rustc"
                    );
                }
            }
        }
    }

    if let Some(semantic_request) = semantic_request.as_ref() {
        match fetch::download_semantic_bundle(&config, semantic_request).await {
            Ok(bundle) => {
                if try_serve_semantic_downloaded_bundle(&config, &parsed, semantic_request, &bundle)
                    .await
                {
                    std::process::exit(0);
                }
                return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
            }
            Err(fetch::FetchError::NotFound) => {}
            Err(error) => {
                log_nonfatal_result(
                    "failed to record stow circuit failure",
                    circuit::record_failure(&config).await,
                );
                log_nonfatal_result(
                    "failed to record rust cache error stats",
                    stats::record_error(&config, &parsed.crate_name).await,
                );
                tracing::warn!(
                    crate_name = %parsed.crate_name,
                    semantic_crate_name = %semantic_request.crate_name,
                    semantic_version = %semantic_request.version,
                    target = %target,
                    rustc_version = %rustc_version,
                    error = %error,
                    "stow semantic fetch failed, falling back to rustc"
                );
                return run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await;
            }
        }
    }

    log_nonfatal_result(
        "failed to record rust cache miss stats",
        stats::record_miss(&config, &parsed.crate_name).await,
    );
    tracing::debug!(
        crate_name = %parsed.crate_name,
        target = %target,
        rustc_version = %rustc_version,
        "stow cache miss, falling back to rustc"
    );
    run_rustc_passthrough(rustc, &command.wrapped_args, &parsed).await
}

#[tracing::instrument(name = "stow.wrapper.cc_invoke", skip_all)]
async fn run_cc_wrapper(command: WrapperCommandArgs) -> stow_types::error::Result<()> {
    let compiler = &command.executable;
    let compiler_args = &command.wrapped_args;
    let config = match StowConfig::load_local() {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(error = %error, "stow local config unavailable, bypassing C/C++ cache");
            return run_passthrough(compiler, compiler_args).await;
        }
    };
    if let Err(error) = config.ensure_dirs().await {
        tracing::warn!(error = %error, "failed to prepare stow cache directories, bypassing C/C++ cache");
        return run_passthrough(compiler, compiler_args).await;
    }

    let outcome = match cc::try_compile(&config, compiler, compiler_args).await {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(error = %error, "stow C/C++ cache failed, bypassing cache");
            return run_passthrough(compiler, compiler_args).await;
        }
    };

    match outcome {
        cc::CcOutcome::Passthrough => run_passthrough(compiler, compiler_args).await,
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
            let compiler_status = Command::new(compiler)
                .args(compiler_args)
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
    try_serve_loaded_local_cached_bundle(config, parsed, request, cached_bundle).await
}

async fn try_serve_local_prefetched_graph_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    target: &str,
    rustc_version: &str,
) -> bool {
    let Some((crate_name, version)) = detect_registry_crate_version(parsed).ok().flatten() else {
        return false;
    };
    let expected_features_json = match resolve_semantic_features_json(&crate_name, &version, parsed)
    {
        Ok(features_json) => features_json,
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                target,
                rustc_version,
                "failed to resolve semantic features for prefetched graph bundle lookup"
            );
            return false;
        }
    };
    let expected_dependency_c_metadata_json =
        match resolve_dependency_c_metadata_json(config, parsed).await {
            Ok(Some(value)) => value,
            Ok(None) if parsed.extern_crates.is_empty() => "[]".to_owned(),
            Ok(None) => return false,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    target,
                    rustc_version,
                    "failed to resolve prefetched graph dependency identities"
                );
                return false;
            }
        };
    let candidate_c_metadatas =
        match load_prefetched_graph_candidate_c_metadatas(&parsed.crate_name) {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    target,
                    rustc_version,
                    "failed to parse prefetched graph artifact candidates"
                );
                return false;
            }
        };

    for c_metadata in candidate_c_metadatas {
        let request = FetchRequest {
            target,
            rustc_version,
            c_metadata: c_metadata.as_str(),
            crate_name: &parsed.crate_name,
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
        if try_serve_loaded_local_cached_bundle(config, parsed, &request, cached_bundle).await {
            return true;
        }
    }
    false
}

async fn try_serve_loaded_local_cached_bundle(
    config: &StowConfig,
    parsed: &rustc_args::ParsedRustcArgs,
    request: &FetchRequest<'_>,
    cached_bundle: artifact_cache::CachedArtifactBundle,
) -> bool {
    if let Err(error) = validate_exact_bundle_semantics(
        parsed,
        &cached_bundle.profile,
        &cached_bundle.emit,
        &cached_bundle.kind,
        &cached_bundle.crate_types,
    ) {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "local stow artifact cache entry semantic mismatch, evicting and falling back to rustc"
        );
        drop(cached_bundle);
        if let Err(evict_error) = remove_cached_bundle(config, request).await {
            tracing::warn!(
                error = %evict_error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to evict local stow artifact cache entry with semantic mismatch"
            );
        }
        log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
        );
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
        if let Err(evict_error) = remove_cached_bundle(config, request).await {
            tracing::warn!(
                error = %evict_error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to evict untrusted local stow artifact cache entry"
            );
        }
        log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
        );
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
        log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
        );
        return false;
    }

    match inject::write_artifacts(parsed, &cached_bundle).await {
        Ok(()) => {
            if let Err(error) =
                record_materialized_bundle_outputs(config, parsed, &cached_bundle).await
            {
                tracing::warn!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    target = %request.target,
                    rustc_version = %request.rustc_version,
                    "failed to record materialized local stow artifact outputs"
                );
                log_nonfatal_result(
                    "failed to record rust cache error stats",
                    stats::record_error(config, &parsed.crate_name).await,
                );
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
                if let Err(evict_error) = remove_cached_bundle(config, request).await {
                    tracing::warn!(
                        error = %evict_error,
                        crate_name = %parsed.crate_name,
                        target = %request.target,
                        rustc_version = %request.rustc_version,
                        "failed to evict local stow artifact cache entry missing rustc artifact notifications"
                    );
                }
                log_nonfatal_result(
                    "failed to record rust cache error stats",
                    stats::record_error(config, &parsed.crate_name).await,
                );
                return false;
            }
            log_nonfatal_result(
                "failed to record rust cache hit stats",
                stats::record_hit(config, &parsed.crate_name).await,
            );
            tracing::info!(
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "served rustc invocation from local stow artifact cache"
            );
            true
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to materialize local stow artifact cache entry, evicting and falling back to rustc"
            );
            drop(cached_bundle);
            if let Err(evict_error) = remove_cached_bundle(config, request).await {
                tracing::warn!(
                    error = %evict_error,
                    crate_name = %parsed.crate_name,
                    target = %request.target,
                    rustc_version = %request.rustc_version,
                    "failed to evict broken local stow artifact cache entry"
                );
            }
            log_nonfatal_result(
                "failed to record rust cache error stats",
                stats::record_error(config, &parsed.crate_name).await,
            );
            false
        }
    }
}

fn load_prefetched_graph_candidate_c_metadatas(
    crate_name: &str,
) -> stow_types::error::Result<Vec<String>> {
    Ok(load_prefetched_graph_artifacts()?
        .into_iter()
        .filter(|entry| canonical_crate_name(entry.crate_name.as_str()) == canonical_crate_name(crate_name))
        .map(|entry| entry.c_metadata.into_inner())
        .collect())
}

fn load_prefetched_graph_artifacts() -> stow_types::error::Result<Vec<BatchArtifactRequestEntry>> {
    let Some(raw) = std::env::var_os(STOW_PREFETCH_ARTIFACTS_ENV) else {
        return Ok(Vec::new());
    };
    let raw = raw.into_string().map_err(|_| {
        stow_types::stow_error!("{STOW_PREFETCH_ARTIFACTS_ENV} must be valid UTF-8")
    })?;
    serde_json::from_str::<Vec<BatchArtifactRequestEntry>>(&raw)
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
        inject::materialize_original_outputs(out_dir, dependency_bundle).await?;
    }

    Ok(())
}

async fn download_closure_dependency_bundle(
    config: &StowConfig,
    target: &str,
    rustc_version: &str,
    dependency: &DependencyCompileKeyIdentity,
) -> stow_types::error::Result<artifact_cache::CachedArtifactBundle> {
    let c_metadata = stable_c_metadata_for_compile_key(&dependency.compile_key)?;
    let request = fetch::FetchRequest {
        target,
        rustc_version,
        c_metadata: &c_metadata,
        crate_name: dependency.crate_name.as_str(),
    };
    let bundle = fetch::download_bundle(config, &request)
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "download closure dependency bundle {} ({}) failed: {error}",
                dependency.compile_key,
                dependency.crate_name
            )
        })?;
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
    let cached_bundle = store_downloaded_bundle(config, request, bundle).await?;
    if let Err(error) = verify::persist_cached_bundle_trust_marker(config, &cached_bundle).await {
        drop(cached_bundle);
        remove_cached_bundle(config, request)
            .await
            .wrap_err("evict cache entry missing trust marker")?;
        return Err(error.wrap_err("persist local stow cache trust marker"));
    }
    Ok(cached_bundle)
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
        log_nonfatal_result(
            "failed to record stow circuit failure",
            circuit::record_failure(config).await,
        );
        log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
        );
        return false;
    }
    if let Err(error) = validate_exact_bundle_semantics(
        parsed,
        &bundle.manifest.config.profile,
        &bundle.manifest.config.emit,
        &bundle.manifest.config.kind,
        &bundle.manifest.config.crate_types,
    ) {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "downloaded stow bundle semantic mismatch"
        );
        log_nonfatal_result(
            "failed to record stow circuit failure",
            circuit::record_failure(config).await,
        );
        log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
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
    if let Err(error) = validate_exact_bundle_semantics(
        parsed,
        &cached_bundle.profile,
        &cached_bundle.emit,
        &cached_bundle.kind,
        &cached_bundle.crate_types,
    ) {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            semantic_crate_name = %semantic_request.crate_name,
            semantic_version = %semantic_request.version,
            target = %semantic_request.target,
            rustc_version = %semantic_request.rustc_version,
            cached_c_metadata = %cached_bundle.c_metadata,
            "local semantic stow artifact cache entry semantic mismatch"
        );
        log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
        );
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
        log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
        );
        return false;
    }
    let request = FetchRequest {
        target: &semantic_request.target,
        rustc_version: &semantic_request.rustc_version,
        c_metadata: &cached_bundle.c_metadata,
        crate_name: &cached_bundle.crate_name,
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
        log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
        );
        return false;
    }

    match inject::write_artifacts(parsed, &cached_bundle).await {
        Ok(()) => {
            if let Err(error) =
                record_materialized_bundle_outputs(config, parsed, &cached_bundle).await
            {
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
                log_nonfatal_result(
                    "failed to record rust cache error stats",
                    stats::record_error(config, &parsed.crate_name).await,
                );
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
                log_nonfatal_result(
                    "failed to record rust cache error stats",
                    stats::record_error(config, &parsed.crate_name).await,
                );
                return false;
            }
            log_nonfatal_result(
                "failed to record rust cache hit stats",
                stats::record_hit(config, &parsed.crate_name).await,
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
        Err(error) => {
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
            log_nonfatal_result(
                "failed to record rust cache error stats",
                stats::record_error(config, &parsed.crate_name).await,
            );
            false
        }
    }
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
        log_nonfatal_result(
            "failed to record stow circuit failure",
            circuit::record_failure(config).await,
        );
        log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
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
        crate_name: bundle.manifest.config.crate_name.as_str(),
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
            log_nonfatal_result(
                "failed to record stow circuit failure",
                circuit::record_failure(config).await,
            );
            log_nonfatal_result(
                "failed to record rust cache error stats",
                stats::record_error(config, &parsed.crate_name).await,
            );
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
        if let Err(evict_error) = remove_cached_bundle(config, request).await {
            tracing::warn!(
                error = %evict_error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to evict downloaded stow bundle with incomplete dependency closure aliases"
            );
        }
        log_nonfatal_result(
            "failed to record stow circuit failure",
            circuit::record_failure(config).await,
        );
        log_nonfatal_result(
            "failed to record rust cache error stats",
            stats::record_error(config, &parsed.crate_name).await,
        );
        return false;
    }

    match inject::write_artifacts(parsed, &cached_bundle).await {
        Ok(()) => {
            if let Err(error) =
                record_materialized_bundle_outputs(config, parsed, &cached_bundle).await
            {
                tracing::warn!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    target = %request.target,
                    rustc_version = %request.rustc_version,
                    "failed to record materialized downloaded stow artifact outputs"
                );
                drop(cached_bundle);
                if let Err(evict_error) = remove_cached_bundle(config, request).await {
                    tracing::warn!(
                        error = %evict_error,
                        crate_name = %parsed.crate_name,
                        target = %request.target,
                        rustc_version = %request.rustc_version,
                        "failed to evict downloaded stow bundle missing materialized output metadata"
                    );
                }
                log_nonfatal_result(
                    "failed to record stow circuit failure",
                    circuit::record_failure(config).await,
                );
                log_nonfatal_result(
                    "failed to record rust cache error stats",
                    stats::record_error(config, &parsed.crate_name).await,
                );
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
                if let Err(evict_error) = remove_cached_bundle(config, request).await {
                    tracing::warn!(
                        error = %evict_error,
                        crate_name = %parsed.crate_name,
                        target = %request.target,
                        rustc_version = %request.rustc_version,
                        "failed to evict downloaded stow bundle missing rustc artifact notifications"
                    );
                }
                log_nonfatal_result(
                    "failed to record stow circuit failure",
                    circuit::record_failure(config).await,
                );
                log_nonfatal_result(
                    "failed to record rust cache error stats",
                    stats::record_error(config, &parsed.crate_name).await,
                );
                return false;
            }
            log_nonfatal_result(
                "failed to record stow circuit success",
                circuit::record_success(config).await,
            );
            log_nonfatal_result(
                "failed to record rust cache hit stats",
                stats::record_hit(config, &parsed.crate_name).await,
            );
            tracing::info!(
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "served rustc invocation from downloaded stow artifact cache"
            );
            true
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to materialize verified stow bundle, evicting local cache entry"
            );
            drop(cached_bundle);
            if let Err(evict_error) = remove_cached_bundle(config, request).await {
                tracing::warn!(
                    error = %evict_error,
                    crate_name = %parsed.crate_name,
                    target = %request.target,
                    rustc_version = %request.rustc_version,
                    "failed to evict verified-but-unusable stow cache entry"
                );
            }
            log_nonfatal_result(
                "failed to record stow circuit failure",
                circuit::record_failure(config).await,
            );
            log_nonfatal_result(
                "failed to record rust cache error stats",
                stats::record_error(config, &parsed.crate_name).await,
            );
            false
        }
    }
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
    let features_json = resolve_semantic_features_json(&crate_name, &version, parsed)?;
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
        trace_identity_inputs(parsed, target, rustc_version, None, None, "not-a-registry-crate")
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
    let features_json = resolve_semantic_features_json(&crate_name, &version, parsed)?;
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

async fn resolve_local_artifact_identity(
    config: &StowConfig,
    executable: &OsString,
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<Option<StableRegistryArtifactIdentity>> {
    let target = match parsed.target.as_deref() {
        Some(target) => target.to_owned(),
        None => rustc_args::detect_rustc_host_target(executable)
            .await
            .map_err(stow_types::error::Error::msg)?,
    };
    let rustc_version = rustc_args::detect_rustc_version(executable)
        .await
        .map_err(stow_types::error::Error::msg)?;
    let dependency_c_metadata_json =
        match resolve_dependency_c_metadata_json(config, parsed).await? {
            Some(value) => value,
            None if parsed.extern_crates.is_empty() => "[]".to_owned(),
            None => return Ok(None),
        };
    let Some((crate_name, version)) = detect_registry_crate_version(parsed)? else {
        return Ok(None);
    };
    let features_json = resolve_semantic_features_json(&crate_name, &version, parsed)?;
    stable_registry_artifact_identity(
        parsed,
        &target,
        &rustc_version,
        &features_json,
        &dependency_c_metadata_json,
    )
}

fn semantic_request_profile(
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<stow_types::platform::Profile> {
    normalized_requested_profile(parsed)
}

fn resolve_semantic_features_json(
    crate_name: &str,
    version: &str,
    parsed: &rustc_args::ParsedRustcArgs,
) -> stow_types::error::Result<String> {
    if let Some(features_json) =
        lookup_expanded_graph_features_json(crate_name, version, &parsed.features)?
    {
        return Ok(features_json);
    }
    serde_json::to_string(&parsed.features.iter().cloned().collect::<Vec<_>>())
        .wrap_err("serialize semantic rustc features")
}

fn lookup_expanded_graph_features_json(
    crate_name: &str,
    version: &str,
    parsed_features: &std::collections::BTreeSet<String>,
) -> stow_types::error::Result<Option<String>> {
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

fn canonical_crate_name(name: &str) -> String {
    stow_types::public_cache::canonical_crate_name(name)
}

fn validate_exact_bundle_semantics(
    parsed: &rustc_args::ParsedRustcArgs,
    profile: &stow_types::platform::Profile,
    emit: &[String],
    kind: &stow_types::artifact::ArtifactKind,
    crate_types: &[stow_types::artifact::RustCrateType],
) -> stow_types::error::Result<()> {
    let expected_profile = normalized_requested_profile(parsed)?;
    if profile != &expected_profile {
        return Err(stow_types::stow_error!("exact bundle profile mismatch"));
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
        return Err(stow_types::stow_error!("exact bundle emit mismatch"));
    }
    let expected_kind = parsed_artifact_kind(parsed)?;
    if kind != &expected_kind {
        return Err(stow_types::stow_error!(
            "exact bundle artifact kind mismatch: expected {}, got {}",
            expected_kind.as_str(),
            kind.as_str()
        ));
    }
    let expected_crate_types = parsed_crate_types(parsed)?;
    if crate_types != expected_crate_types.as_slice() {
        return Err(stow_types::stow_error!("exact bundle crate types mismatch"));
    }
    Ok(())
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

fn parsed_artifact_kind(
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

fn parsed_crate_types(
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
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);

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

    use super::{cached_rustc_artifact_notifications, should_install_tracing_for_args};
    use crate::rustc_args::ParsedRustcArgs;

    fn args(parts: &[&str]) -> Vec<std::ffi::OsString> {
        parts.iter().map(std::ffi::OsString::from).collect()
    }

    fn env_value(value: Option<&str>) -> Option<OsString> {
        value.map(OsString::from)
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

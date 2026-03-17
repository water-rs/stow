mod artifact_cache;
mod cache_policy;
mod cargo_cmd;
mod cc;
mod circuit;
mod cli_args;
mod config;
mod fetch;
mod graph_cache;
mod inject;
mod prefetch;
mod rustc_args;
mod state_file;
mod stats;
mod verify;
#[path = "../../shared/workspace_mirror.rs"]
mod workspace_mirror;
#[path = "../../shared/wrapper_shim.rs"]
mod wrapper_shim;

use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use async_process::Command;
use clap::Parser;
use eyre::Context;
use toml_edit::{DocumentMut, Item, Table, Value};
use tracing_subscriber::EnvFilter;
use zenwave::Client;

use crate::artifact_cache::{
    load_cached_bundle, prepare_local_cache, remove_cached_bundle, store_downloaded_bundle,
};
use crate::cli_args::{
    CheckArtifactArgs, Cli, Command as CliCommand, FetchArtifactArgs, PurgeCacheDirArgs,
};
use crate::config::StowConfig;
use crate::fetch::FetchRequest;

pub fn run() -> eyre::Result<()> {
    install_tracing();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .wrap_err("create tokio runtime for stow cli")?
        .block_on(async_main())
}

async fn async_main() -> eyre::Result<()> {
    let args = std::env::args_os().collect::<Vec<_>>();
    match detect_mode(&args) {
        Mode::RustcWrapper => run_rustc_wrapper(&args).await,
        Mode::CcWrapper => run_cc_wrapper(&args).await,
        Mode::CargoSubcommand => handle_subcommand(&args).await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    RustcWrapper,
    CcWrapper,
    CargoSubcommand,
}

fn detect_mode(args: &[std::ffi::OsString]) -> Mode {
    let Some(argv1) = args.get(1) else {
        return Mode::CargoSubcommand;
    };

    if is_rustc_path(argv1) {
        return Mode::RustcWrapper;
    }
    if is_c_compiler(argv1) {
        return Mode::CcWrapper;
    }

    Mode::CargoSubcommand
}

async fn run_passthrough(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let executable = args
        .get(1)
        .ok_or_else(|| eyre::eyre!("wrapper mode requires the real compiler path as argv[1]"))?;
    let status = Command::new(executable)
        .args(&args[2..])
        .status()
        .await
        .wrap_err("failed to spawn wrapped compiler")?;

    std::process::exit(status.code().unwrap_or(1));
}

async fn run_rustc_wrapper(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let rustc = args
        .get(1)
        .ok_or_else(|| eyre::eyre!("rustc wrapper mode requires rustc path as argv[1]"))?;
    let parsed = match rustc_args::ParsedRustcArgs::parse(&args[2..]) {
        Ok(parsed) => parsed,
        Err(error) if error.contains("missing --crate-name") => {
            tracing::debug!(error = %error, "rustc probe invocation detected, bypassing cache");
            return run_passthrough(args).await;
        }
        Err(error) => {
            return Err(eyre::eyre!("parse rustc wrapper arguments: {error}"));
        }
    };

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
        return run_passthrough(args).await;
    }

    if std::env::var_os("STOW_DISABLE_PUBLIC_CACHE").is_some() {
        tracing::debug!("public rust cache disabled for this cargo invocation");
        return run_passthrough(args).await;
    }
    match cache_policy::public_cache_allowed(&parsed).await {
        Ok(Some(false)) => {
            tracing::debug!(
                crate_name = %parsed.crate_name,
                "public rust cache disabled by stow cache policy for this semantic dependency"
            );
            return run_passthrough(args).await;
        }
        Ok(Some(true) | None) => {}
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                "failed to read stow cache policy, bypassing rust cache"
            );
            return run_passthrough(args).await;
        }
    }

    let config = match StowConfig::load() {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(error = %error, "stow edge config unavailable, bypassing rust cache");
            return run_passthrough(args).await;
        }
    };
    if let Err(error) = config.ensure_dirs().await {
        tracing::warn!(error = %error, "failed to prepare stow cache directories, bypassing rust cache");
        return run_passthrough(args).await;
    }
    let circuit_tripped = match circuit::is_tripped(&config).await {
        Ok(tripped) => tripped,
        Err(error) => {
            tracing::warn!(error = %error, "failed to read stow circuit state, bypassing rust cache");
            return run_passthrough(args).await;
        }
    };
    if circuit_tripped {
        tracing::debug!("circuit breaker tripped, bypassing cache");
        return run_passthrough(args).await;
    }

    let target = match parsed.target.as_deref() {
        Some(target) => target.to_owned(),
        None => match rustc_args::detect_rustc_host_target(rustc).await {
            Ok(target) => target,
            Err(error) => {
                tracing::warn!(error = %error, "failed to detect rustc host target, bypassing rust cache");
                return run_passthrough(args).await;
            }
        },
    };
    let Some(c_metadata) = parsed.c_metadata.as_deref() else {
        tracing::warn!("cacheable rustc invocation is missing -C metadata, bypassing rust cache");
        return run_passthrough(args).await;
    };
    let rustc_version = match rustc_args::detect_rustc_version(rustc).await {
        Ok(version) => version,
        Err(error) => {
            tracing::warn!(error = %error, "failed to detect rustc version, bypassing rust cache");
            return run_passthrough(args).await;
        }
    };
    let cache_key = format!("{target}/{rustc_version}/{c_metadata}");
    let _version_cache_lease = match prepare_local_cache(&config, &rustc_version).await {
        Ok(lease) => lease,
        Err(error) => {
            tracing::warn!(error = %error, "failed to prepare local stow artifact cache, bypassing rust cache");
            return run_passthrough(args).await;
        }
    };

    let request = FetchRequest {
        target: &target,
        rustc_version: &rustc_version,
        c_metadata,
        crate_name: &parsed.crate_name,
    };

    if try_serve_local_cached_bundle(&config, &parsed, &request).await {
        std::process::exit(0);
    }

    let negative_cache_hit = match circuit::negative_cache_contains(&config, &cache_key).await {
        Ok(hit) => hit,
        Err(error) => {
            tracing::warn!(error = %error, cache_key = %cache_key, "failed to read stow negative cache");
            false
        }
    };
    if negative_cache_hit {
        tracing::debug!(cache_key = %cache_key, "negative cache hit, bypassing edge fetch");
        return run_passthrough(args).await;
    }

    let fetch_result = fetch::download_bundle(&config, &request).await;

    match fetch_result {
        Ok(bundle) => {
            if try_serve_downloaded_bundle(&config, &parsed, &request, &bundle).await {
                std::process::exit(0);
            }
            run_passthrough(args).await
        }
        Err(fetch::FetchError::NotFound) => {
            log_nonfatal_result(
                "failed to record stow negative cache entry",
                circuit::record_negative_cache(&config, &cache_key).await,
            );
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
            run_passthrough(args).await
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
                "stow fetch failed, falling back to rustc"
            );
            run_passthrough(args).await
        }
    }
}

async fn run_cc_wrapper(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let compiler = args
        .get(1)
        .ok_or_else(|| eyre::eyre!("cc wrapper mode requires compiler path as argv[1]"))?;
    let compiler_args = &args[2..];
    let config = match StowConfig::load_local() {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(error = %error, "stow local config unavailable, bypassing C/C++ cache");
            return run_passthrough(args).await;
        }
    };
    if let Err(error) = config.ensure_dirs().await {
        tracing::warn!(error = %error, "failed to prepare stow cache directories, bypassing C/C++ cache");
        return run_passthrough(args).await;
    }

    let outcome = match cc::try_compile(&config, compiler, compiler_args).await {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(error = %error, "stow C/C++ cache failed, bypassing cache");
            return run_passthrough(args).await;
        }
    };

    match outcome {
        cc::CcOutcome::Passthrough => run_passthrough(args).await,
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

    match inject::write_artifacts(parsed, &cached_bundle).await {
        Ok(()) => {
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

    if let Err(error) = verify::verify_bundle_signature(config, bundle).await {
        tracing::warn!(
            error = %error,
            crate_name = %parsed.crate_name,
            target = %request.target,
            rustc_version = %request.rustc_version,
            "downloaded stow bundle failed verification"
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

    let cached_bundle = match store_downloaded_bundle(config, request, bundle).await {
        Ok(cached_bundle) => cached_bundle,
        Err(error) => {
            tracing::warn!(
                error = %error,
                crate_name = %parsed.crate_name,
                target = %request.target,
                rustc_version = %request.rustc_version,
                "failed to persist verified stow bundle into local artifact cache"
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

    match inject::write_artifacts(parsed, &cached_bundle).await {
        Ok(()) => {
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

fn log_nonfatal_result(context: &'static str, result: eyre::Result<()>) {
    if let Err(error) = result {
        tracing::warn!(error = %error, "{context}");
    }
}

async fn handle_subcommand(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let cli = parse_cli_or_exit(args)?;

    match cli.command {
        CliCommand::Check(command) => cargo_cmd::run("check", command).await,
        CliCommand::Build(command) => cargo_cmd::run("build", command).await,
        CliCommand::Test(command) => cargo_cmd::run("test", command).await,
        CliCommand::Predict(command) => cargo_cmd::predict(command).await,
        CliCommand::Setup => setup_project().await,
        CliCommand::Status => status_project().await,
        CliCommand::Clean => clean_project().await,
        CliCommand::CheckArtifact(command) => check_artifact(command).await,
        CliCommand::FetchArtifact(command) => fetch_artifact(command).await,
        CliCommand::PurgeCacheDir(command) => purge_cache_dirs(command).await,
    }
}

fn parse_cli_or_exit(args: &[std::ffi::OsString]) -> eyre::Result<Cli> {
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

async fn setup_project() -> eyre::Result<()> {
    let current_dir = std::env::current_dir().wrap_err("resolve current directory")?;
    let cargo_dir = current_dir.join(".cargo");
    let config_path = cargo_dir.join("config.toml");
    let wrapper_command = detect_wrapper_command()?;

    std::fs::create_dir_all(&cargo_dir).wrap_err("create .cargo directory")?;

    let mut document = if config_path.exists() {
        std::fs::read_to_string(&config_path)
            .wrap_err("read existing .cargo/config.toml")?
            .parse::<DocumentMut>()
            .wrap_err("parse existing .cargo/config.toml")?
    } else {
        DocumentMut::new()
    };

    set_build_wrapper(&mut document, &wrapper_command);
    set_env_wrapper(&mut document, "CC", &format!("{wrapper_command} cc"));
    set_env_wrapper(&mut document, "CXX", &format!("{wrapper_command} c++"));
    set_env_wrapper(&mut document, "CMAKE_C_COMPILER_LAUNCHER", &wrapper_command);
    set_env_wrapper(
        &mut document,
        "CMAKE_CXX_COMPILER_LAUNCHER",
        &wrapper_command,
    );

    std::fs::write(&config_path, document.to_string()).wrap_err("write .cargo/config.toml")?;

    tracing::info!(path = %config_path.display(), wrapper = %wrapper_command, "configured project for stow");
    write_stdout(&format!(
        "configured {}\nwrapper: {}\n",
        config_path.display(),
        wrapper_command
    ))?;

    Ok(())
}

async fn status_project() -> eyre::Result<()> {
    let current_dir = std::env::current_dir().wrap_err("resolve current directory")?;
    let config_path = current_dir.join(".cargo").join("config.toml");

    if !config_path.exists() {
        write_stdout("not configured: .cargo/config.toml is missing\n")?;
        return Ok(());
    }

    let document = std::fs::read_to_string(&config_path)
        .wrap_err("read .cargo/config.toml")?
        .parse::<DocumentMut>()
        .wrap_err("parse .cargo/config.toml")?;

    let rustc_wrapper = document
        .get("build")
        .and_then(Item::as_table)
        .and_then(|table| table.get("rustc-wrapper"))
        .and_then(Item::as_str)
        .unwrap_or("<missing>");

    let cc = env_value(&document, "CC").unwrap_or("<missing>");
    let cxx = env_value(&document, "CXX").unwrap_or("<missing>");
    let (edge_url, stats_summary) = match StowConfig::load() {
        Ok(config) => {
            let edge_url = config.edge_url.clone();
            (
                edge_url,
                stats::read_summary(&config).await.unwrap_or_default(),
            )
        }
        Err(_) => ("<missing>".to_owned(), stats::StatsSummary::default()),
    };

    write_stdout(&format!(
        "config: {}\nrustc-wrapper: {}\nCC: {}\nCXX: {}\nedge-url: {}\nrust-cache: hits={} misses={} errors={}\ncc-cache: hits={} misses={} errors={}\n",
        config_path.display(),
        rustc_wrapper,
        cc,
        cxx,
        edge_url,
        stats_summary.rust_hits,
        stats_summary.rust_misses,
        stats_summary.rust_errors,
        stats_summary.cc_hits,
        stats_summary.cc_misses,
        stats_summary.cc_errors,
    ))?;

    Ok(())
}

async fn clean_project() -> eyre::Result<()> {
    let cache_dir = config::cache_dir()?;
    if cache_dir.exists() {
        async_fs::remove_dir_all(&cache_dir)
            .await
            .wrap_err_with(|| format!("remove cache dir {}", cache_dir.display()))?;
        write_stdout(&format!("removed {}\n", cache_dir.display()))?;
    } else {
        write_stdout(&format!("cache dir missing: {}\n", cache_dir.display()))?;
    }
    Ok(())
}

async fn check_artifact(args: CheckArtifactArgs) -> eyre::Result<()> {
    let config = StowConfig::load()?;

    let url = format!(
        "{}/api/v1/artifacts/{}/{}/{}",
        config.edge_url.trim_end_matches('/'),
        args.target,
        args.rustc_version,
        args.c_metadata
    );

    let mut client = zenwave::client();
    let response = client.method(zenwave::Method::HEAD, &url)?.await?;

    write_stdout(&format!("status: {}\nurl: {}\n", response.status(), url))?;
    Ok(())
}

async fn fetch_artifact(args: FetchArtifactArgs) -> eyre::Result<()> {
    let config = StowConfig::load()?;
    let bytes = fetch::download_raw_bundle(
        &config,
        &FetchRequest {
            target: &args.target,
            rustc_version: &args.rustc_version,
            c_metadata: &args.c_metadata,
            crate_name: &args.crate_name,
        },
    )
    .await
    .map_err(|error| eyre::eyre!("download artifact bundle: {error}"))?;

    if let Some(parent) = args.output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create parent directory {}", parent.display()))?;
    }
    std::fs::write(&args.output_path, &bytes)
        .wrap_err_with(|| format!("write artifact to {}", args.output_path.display()))?;

    write_stdout(&format!(
        "downloaded {}\nbytes: {}\n",
        args.output_path.display(),
        bytes.len()
    ))?;
    Ok(())
}

async fn purge_cache_dirs(args: PurgeCacheDirArgs) -> eyre::Result<()> {
    smol::unblock(move || {
        for path in args.paths {
            if !path.exists() {
                continue;
            }
            std::fs::remove_dir_all(&path)
                .wrap_err_with(|| format!("purge stale cache directory {}", path.display()))?;
        }
        Ok(())
    })
    .await
}

fn set_build_wrapper(document: &mut DocumentMut, wrapper_command: &str) {
    let build = ensure_table(document, "build");
    build["rustc-wrapper"] = Item::Value(Value::from(wrapper_command));
}

fn set_env_wrapper(document: &mut DocumentMut, key: &str, value: &str) {
    let env = ensure_table(document, "env");
    let mut table = Table::new();
    table["value"] = Item::Value(Value::from(value));
    table["force"] = Item::Value(Value::from(true));
    env[key] = Item::Table(table);
}

fn ensure_table<'a>(document: &'a mut DocumentMut, key: &str) -> &'a mut Table {
    if !document.get(key).is_some_and(Item::is_table) {
        document.insert(key, Item::Table(Table::new()));
    }
    document
        .get_mut(key)
        .expect("table inserted above must exist")
        .as_table_mut()
        .expect("table inserted above must exist")
}

fn env_value<'a>(document: &'a DocumentMut, key: &str) -> Option<&'a str> {
    document
        .get("env")
        .and_then(Item::as_table)
        .and_then(|table| table.get(key))
        .and_then(Item::as_table_like)
        .and_then(|entry| entry.get("value"))
        .and_then(Item::as_str)
}

pub(crate) fn detect_wrapper_command() -> eyre::Result<String> {
    if let Ok(wrapper) = std::env::var("STOW_WRAPPER_PATH") {
        return Ok(wrapper);
    }

    let current_exe = std::env::current_exe().wrap_err("resolve current executable")?;
    let capture_exe = sibling_binary(&current_exe, "stow-build");
    let capture_exe = if capture_exe.exists() {
        capture_exe
    } else {
        current_exe.clone()
    };
    let shim = wrapper_shim::materialize_wrapper_shim(&current_exe, &capture_exe)?;
    let shim_string = shim
        .to_str()
        .ok_or_else(|| eyre::eyre!("wrapper shim path {} is not UTF-8", shim.display()))?
        .to_owned();
    let file_name = current_exe
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    if matches!(file_name, "stow-cli" | "stow" | "cargo-stow") {
        return Ok(shim_string);
    }

    let sibling = sibling_binary(&current_exe, "stow-cli");
    if sibling.exists() {
        let sibling_capture = sibling_binary(&current_exe, "stow-build");
        let sibling_capture = if sibling_capture.exists() {
            sibling_capture
        } else {
            sibling.clone()
        };
        let shim = wrapper_shim::materialize_wrapper_shim(&sibling, &sibling_capture)?;
        return shim
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| eyre::eyre!("wrapper shim path {} is not UTF-8", shim.display()));
    }

    Ok(shim_string)
}

fn sibling_binary(current_exe: &Path, name: &str) -> PathBuf {
    current_exe
        .parent()
        .map(|parent| parent.join(name))
        .unwrap_or_else(|| PathBuf::from(name))
}

fn is_rustc_path(path: &OsStr) -> bool {
    file_name(path).is_some_and(|name| name.starts_with("rustc"))
}

fn is_c_compiler(path: &OsStr) -> bool {
    matches!(
        file_name(path),
        Some("cc" | "c++" | "gcc" | "g++" | "clang" | "clang++" | "cl" | "cl.exe")
    )
}

fn file_name(path: &OsStr) -> Option<&str> {
    Path::new(path).file_name().and_then(OsStr::to_str)
}

pub(crate) fn write_stdout(message: &str) -> eyre::Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(message.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

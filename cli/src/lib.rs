mod cc;
mod circuit;
mod config;
mod fetch;
mod inject;
mod rustc_args;
mod stats;
mod verify;

use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use async_process::Command;
use eyre::Context;
use toml_edit::{DocumentMut, Item, Table, Value};
use tracing_subscriber::EnvFilter;
use zenwave::Client;

use crate::config::StowConfig;
use crate::fetch::FetchRequest;

pub fn run() -> eyre::Result<()> {
    install_tracing();
    smol::block_on(async_main())
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
    let parsed = rustc_args::ParsedRustcArgs::parse(&args[2..])
        .map_err(|error| eyre::eyre!("parse rustc wrapper arguments: {error}"))?;

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

    let config = match StowConfig::load() {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(error = %error, "stow edge config unavailable, bypassing rust cache");
            return run_passthrough(args).await;
        }
    };
    config.ensure_dirs().await?;
    if circuit::is_tripped(&config).await? {
        tracing::debug!("circuit breaker tripped, bypassing cache");
        return run_passthrough(args).await;
    }

    let target = parsed
        .target
        .as_deref()
        .ok_or_else(|| eyre::eyre!("cacheable rustc invocation is missing --target"))?;
    let c_metadata = parsed
        .c_metadata
        .as_deref()
        .ok_or_else(|| eyre::eyre!("cacheable rustc invocation is missing -C metadata"))?;
    let cache_key = format!("{target}/{c_metadata}");

    if circuit::negative_cache_contains(&config, &cache_key).await? {
        tracing::debug!(cache_key = %cache_key, "negative cache hit, bypassing edge fetch");
        return run_passthrough(args).await;
    }

    let rustc_version = rustc_args::detect_rustc_version(rustc)
        .await
        .map_err(|error| eyre::eyre!("detect rustc version: {error}"))?;
    let request = FetchRequest {
        target,
        rustc_version: &rustc_version,
        c_metadata,
        crate_name: &parsed.crate_name,
    };

    match fetch::try_download(&config, &request).await {
        Ok(bundle) => {
            verify::verify_bundle_signature(&config, &bundle).await?;
            inject::write_artifacts(&parsed, &bundle).await?;
            circuit::record_success(&config).await?;
            stats::record_hit(&config, &parsed.crate_name).await?;
            tracing::info!(
                crate_name = %parsed.crate_name,
                target,
                rustc_version = %rustc_version,
                "served rustc invocation from stow cache"
            );
            std::process::exit(0);
        }
        Err(fetch::FetchError::NotFound) => {
            circuit::record_negative_cache(&config, &cache_key).await?;
            stats::record_miss(&config, &parsed.crate_name).await?;
            tracing::debug!(
                crate_name = %parsed.crate_name,
                target,
                rustc_version = %rustc_version,
                "stow cache miss, falling back to rustc"
            );
            run_passthrough(args).await
        }
        Err(error) => {
            circuit::record_failure(&config).await?;
            stats::record_error(&config, &parsed.crate_name).await?;
            tracing::warn!(
                crate_name = %parsed.crate_name,
                target,
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
    let config = StowConfig::load_local()?;
    config.ensure_dirs().await?;

    match cc::try_compile(&config, compiler, compiler_args).await? {
        cc::CcOutcome::Passthrough => run_passthrough(args).await,
        cc::CcOutcome::Hit {
            cache_key,
            output_path,
        } => {
            stats::record_hit(&config, &format!("cc:{cache_key}")).await?;
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
                stats::record_error(&config, &format!("cc:{cache_key}")).await?;
                std::process::exit(compiler_status.code().unwrap_or(1));
            }

            cc::store_compiled_object(&cache_path, &output_path).await?;
            stats::record_miss(&config, &format!("cc:{cache_key}")).await?;
            tracing::info!(
                cache_key = %cache_key,
                output_path = %output_path.display(),
                "stored C/C++ compilation in local stow cache"
            );
            std::process::exit(0);
        }
    }
}

async fn handle_subcommand(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let Some(command) = args.get(1).and_then(|arg| arg.to_str()) else {
        return Err(eyre::eyre!("missing subcommand: expected `setup` or `status`"));
    };

    match command {
        "setup" => setup_project().await,
        "status" => status_project().await,
        "clean" => clean_project().await,
        "check-artifact" => check_artifact(args).await,
        "fetch-artifact" => fetch_artifact(args).await,
        other => Err(eyre::eyre!("unsupported subcommand `{other}`")),
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
    set_env_wrapper(&mut document, "CMAKE_CXX_COMPILER_LAUNCHER", &wrapper_command);

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

async fn check_artifact(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let target = args
        .get(2)
        .and_then(|value| value.to_str())
        .ok_or_else(|| eyre::eyre!("missing <target> for check-artifact"))?;
    let rustc_version = args
        .get(3)
        .and_then(|value| value.to_str())
        .ok_or_else(|| eyre::eyre!("missing <rustc_version> for check-artifact"))?;
    let c_metadata = args
        .get(4)
        .and_then(|value| value.to_str())
        .ok_or_else(|| eyre::eyre!("missing <c_metadata> for check-artifact"))?;
    let config = StowConfig::load()?;

    let url = format!(
        "{}/api/v1/artifacts/{}/{}/{}",
        config.edge_url.trim_end_matches('/'),
        target,
        rustc_version,
        c_metadata
    );

    let mut client = zenwave::client();
    let response = client
        .method(zenwave::Method::HEAD, &url)
        .await?;

    write_stdout(&format!("status: {}\nurl: {}\n", response.status(), url))?;
    Ok(())
}

async fn fetch_artifact(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let target = args
        .get(2)
        .and_then(|value| value.to_str())
        .ok_or_else(|| eyre::eyre!("missing <target> for fetch-artifact"))?;
    let rustc_version = args
        .get(3)
        .and_then(|value| value.to_str())
        .ok_or_else(|| eyre::eyre!("missing <rustc_version> for fetch-artifact"))?;
    let c_metadata = args
        .get(4)
        .and_then(|value| value.to_str())
        .ok_or_else(|| eyre::eyre!("missing <c_metadata> for fetch-artifact"))?;
    let output_path = args
        .get(5)
        .map(PathBuf::from)
        .ok_or_else(|| eyre::eyre!("missing <output_path> for fetch-artifact"))?;
    let crate_name = args
        .get(6)
        .and_then(|value| value.to_str())
        .ok_or_else(|| eyre::eyre!("missing <crate_name> for fetch-artifact"))?;
    let config = StowConfig::load()?;
    let bytes = fetch::download_raw_bundle(
        &config,
        &FetchRequest {
            target,
            rustc_version,
            c_metadata,
            crate_name,
        },
    )
    .await
    .map_err(|error| eyre::eyre!("download artifact bundle: {error}"))?;

    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create parent directory {}", parent.display()))?;
    }
    std::fs::write(&output_path, &bytes)
        .wrap_err_with(|| format!("write artifact to {}", output_path.display()))?;

    write_stdout(&format!(
        "downloaded {}\nbytes: {}\n",
        output_path.display(),
        bytes.len()
    ))?;
    Ok(())
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

fn detect_wrapper_command() -> eyre::Result<String> {
    if let Ok(wrapper) = std::env::var("STOW_WRAPPER_PATH") {
        return Ok(wrapper);
    }

    let current_exe = std::env::current_exe().wrap_err("resolve current executable")?;
    let file_name = current_exe.file_name().and_then(OsStr::to_str).unwrap_or_default();
    if file_name == "stow-cli" {
        return Ok(current_exe.display().to_string());
    }

    let sibling = sibling_binary(&current_exe, "stow-cli");
    if sibling.exists() {
        return Ok(sibling.display().to_string());
    }

    Ok("stow-cli".to_owned())
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
    Path::new(path)
        .file_name()
        .and_then(OsStr::to_str)
}

fn write_stdout(message: &str) -> eyre::Result<()> {
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

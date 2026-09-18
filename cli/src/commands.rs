//! User-facing top-level subcommands: `stow setup`, `status`, `clean`,
//! `check-artifact`, `fetch-artifact`, `purge-cache-dir`.
//!
//! The runtime command (`stow run`/`stow rustc`/`stow cc`) and the cargo
//! drivers (`stow check`/`stow build`/`stow test`) live elsewhere; this
//! module is the dev/maintenance surface.

use std::path::{Path, PathBuf};

use stow_types::error::Context;
use toml_edit::{DocumentMut, Item, Table, Value};
use zenwave::Client;

use crate::cli_args::{CheckArtifactArgs, FetchArtifactArgs, PurgeCacheDirArgs, SetupArgs};
use crate::config::{self, StowConfig};
use crate::fetch::{self, FetchRequest};
use crate::stats;
use crate::wrapper_shim;
use crate::write_stdout;

/// `stow setup`: write a `.cargo/config.toml` that points cargo at the stow
/// rustc/cc wrappers in the current directory — or, with `--github-env`,
/// print the equivalent `KEY=VALUE` job-environment wiring on stdout.
pub async fn setup_project(args: SetupArgs) -> stow_types::error::Result<()> {
    if args.github_env {
        return print_setup_env();
    }
    let current_dir = std::env::current_dir().wrap_err("resolve current directory")?;
    let cargo_dir = current_dir.join(".cargo");
    let config_path = cargo_dir.join("config.toml");
    let wrappers = detect_wrapper_commands()?;

    async_fs::create_dir_all(&cargo_dir)
        .await
        .wrap_err("create .cargo directory")?;

    let mut document = if async_fs::metadata(&config_path).await.is_ok() {
        async_fs::read_to_string(&config_path)
            .await
            .wrap_err("read existing .cargo/config.toml")?
            .parse::<DocumentMut>()
            .wrap_err("parse existing .cargo/config.toml")?
    } else {
        DocumentMut::new()
    };

    set_build_wrapper(&mut document, &wrappers.rustc);
    // Record the toolchain the caller already had before pointing CC/CXX at
    // the shims, so an explicit compiler survives setup: the shims exec
    // `$STOW_REAL_CC` / `$STOW_REAL_CXX`.
    set_env_wrapper(&mut document, "STOW_REAL_CC", &real_c_compiler());
    set_env_wrapper(&mut document, "STOW_REAL_CXX", &real_cxx_compiler());
    set_env_wrapper(&mut document, "CC", &wrappers.cc_compiler);
    set_env_wrapper(&mut document, "CXX", &wrappers.cxx_compiler);
    set_env_wrapper(
        &mut document,
        "CMAKE_C_COMPILER_LAUNCHER",
        &wrappers.cc_launcher,
    );
    set_env_wrapper(
        &mut document,
        "CMAKE_CXX_COMPILER_LAUNCHER",
        &wrappers.cc_launcher,
    );

    async_fs::write(&config_path, document.to_string())
        .await
        .wrap_err("write .cargo/config.toml")?;

    tracing::info!(
        path = %config_path.display(),
        rustc_wrapper = %wrappers.rustc,
        cc_compiler = %wrappers.cc_compiler,
        cxx_compiler = %wrappers.cxx_compiler,
        cc_launcher = %wrappers.cc_launcher,
        "configured project for stow"
    );
    write_stdout(&format!(
        "configured {}\nrustc-wrapper: {}\ncc: {}\ncxx: {}\ncc-launcher: {}\n",
        config_path.display(),
        wrappers.rustc,
        wrappers.cc_compiler,
        wrappers.cxx_compiler,
        wrappers.cc_launcher,
    ))?;

    Ok(())
}

/// `stow setup --github-env`: emit the job-environment equivalent of what
/// `stow setup` writes into `.cargo/config.toml`, plus the resolved edge
/// configuration, as `KEY=VALUE` lines. Consumers append it to `$GITHUB_ENV`
/// so the wiring applies to the whole job instead of one project.
fn print_setup_env() -> stow_types::error::Result<()> {
    let wrappers = detect_wrapper_commands()?;
    let config = StowConfig::load()?;
    write_stdout(&setup_env_output(
        &wrappers,
        &real_c_compiler(),
        &real_cxx_compiler(),
        &config,
    ))
}

/// The job-environment variables `stow setup` wires, in a fixed order so the
/// output is stable for consumers that diff it.
fn setup_env_output(
    wrappers: &WrapperCommands,
    real_cc: &str,
    real_cxx: &str,
    config: &StowConfig,
) -> String {
    let entries: [(&str, &str); 9] = [
        ("RUSTC_WRAPPER", &wrappers.rustc),
        ("STOW_REAL_CC", real_cc),
        ("STOW_REAL_CXX", real_cxx),
        ("CC", &wrappers.cc_compiler),
        ("CXX", &wrappers.cxx_compiler),
        ("CMAKE_C_COMPILER_LAUNCHER", &wrappers.cc_launcher),
        ("CMAKE_CXX_COMPILER_LAUNCHER", &wrappers.cc_launcher),
        ("STOW_EDGE_URL", &config.edge_url),
        ("STOW_VERIFY_MODE", config.verify_mode.as_str()),
    ];
    entries
        .into_iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect()
}

/// `stow status`: print the current project's wrapper configuration and
/// rolling cache-hit stats.
pub async fn status_project() -> stow_types::error::Result<()> {
    let current_dir = std::env::current_dir().wrap_err("resolve current directory")?;
    let config_path = current_dir.join(".cargo").join("config.toml");

    if async_fs::metadata(&config_path).await.is_err() {
        write_stdout("not configured: .cargo/config.toml is missing\n")?;
        return Ok(());
    }

    let document = async_fs::read_to_string(&config_path)
        .await
        .wrap_err("read .cargo/config.toml")?
        .parse::<DocumentMut>()
        .wrap_err("parse .cargo/config.toml")?;

    let rustc_wrapper = document
        .get("build")
        .and_then(Item::as_table)
        .and_then(|table| table.get("rustc-wrapper"))
        .and_then(Item::as_str)
        .unwrap_or("<missing>");

    let cc_compiler = env_value(&document, "CC").unwrap_or("<missing>");
    let cxx_compiler = env_value(&document, "CXX").unwrap_or("<missing>");
    let cc_launcher = env_value(&document, "CMAKE_C_COMPILER_LAUNCHER").unwrap_or("<missing>");
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
        "config: {}\nrustc-wrapper: {}\ncc: {}\ncxx: {}\ncc-launcher: {}\nedge-url: {}\nrust-cache: hits={} misses={} errors={}\ncc-cache: hits={} misses={} errors={}\n",
        config_path.display(),
        rustc_wrapper,
        cc_compiler,
        cxx_compiler,
        cc_launcher,
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

/// `stow clean`: remove the local stow cache directory.
pub async fn clean_project() -> stow_types::error::Result<()> {
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

/// `stow check-artifact`: HEAD the edge artifact endpoint and print the result.
pub async fn check_artifact(args: CheckArtifactArgs) -> stow_types::error::Result<()> {
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

/// `stow fetch-artifact`: GET an artifact bundle from the edge and write it
/// to disk.
pub async fn fetch_artifact(args: FetchArtifactArgs) -> stow_types::error::Result<()> {
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
    .map_err(|error| stow_types::stow_error!("download artifact bundle: {error}"))?;

    if let Some(parent) = args.output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create parent directory {}", parent.display()))?;
    }
    async_fs::write(&args.output_path, &bytes)
        .await
        .wrap_err_with(|| format!("write artifact to {}", args.output_path.display()))?;

    write_stdout(&format!(
        "downloaded {}\nbytes: {}\n",
        args.output_path.display(),
        bytes.len()
    ))?;
    Ok(())
}

/// `stow purge-cache-dir`: remove a list of cache directories.
pub async fn purge_cache_dirs(args: PurgeCacheDirArgs) -> stow_types::error::Result<()> {
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

pub struct WrapperCommands {
    pub(crate) rustc: String,
    /// Launcher-shaped; the program to run arrives as the first argument.
    pub(crate) cc_launcher: String,
    /// Compiler-shaped; invoked with compiler arguments only.
    pub(crate) cc_compiler: String,
    /// Compiler-shaped, for C++.
    pub(crate) cxx_compiler: String,
}

pub fn detect_wrapper_commands() -> stow_types::error::Result<WrapperCommands> {
    let current_exe = std::env::current_exe().wrap_err("resolve current executable")?;
    let runtime_executable =
        std::env::var_os("STOW_WRAPPER_PATH").map_or_else(|| current_exe.clone(), PathBuf::from);
    let runtime_executable = if runtime_executable.exists() {
        runtime_executable
    } else {
        current_exe
    };
    let capture_exe = sibling_binary(&runtime_executable, "stow-build");
    let capture_exe = if capture_exe.exists() {
        capture_exe
    } else {
        runtime_executable.clone()
    };
    let file_name = runtime_executable
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    let runtime_executable = if matches!(file_name, "stow-cli" | "stow" | "cargo-stow") {
        runtime_executable
    } else {
        let sibling = sibling_binary(&runtime_executable, "stow-cli");
        if sibling.exists() {
            sibling
        } else {
            runtime_executable
        }
    };
    let capture_executable = {
        let sibling_capture = sibling_binary(&runtime_executable, "stow-build");
        if sibling_capture.exists() {
            sibling_capture
        } else {
            capture_exe
        }
    };
    let shims = wrapper_shim::materialize_wrapper_shims(&runtime_executable, &capture_executable)?;
    Ok(WrapperCommands {
        rustc: shim_path(&shims.rustc_wrapper, "rustc wrapper")?,
        cc_launcher: shim_path(&shims.cc_launcher, "cc launcher")?,
        cc_compiler: shim_path(&shims.cc_compiler, "cc compiler")?,
        cxx_compiler: shim_path(&shims.cxx_compiler, "cxx compiler")?,
    })
}

fn shim_path(path: &std::path::Path, what: &str) -> stow_types::error::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| stow_types::stow_error!("{what} path {} is not UTF-8", path.display()))
}

fn sibling_binary(current_exe: &Path, name: &str) -> PathBuf {
    current_exe
        .parent()
        .map_or_else(|| PathBuf::from(name), |parent| parent.join(name))
}

/// The C compiler the caller had configured, or the platform default.
pub(crate) fn real_c_compiler() -> String {
    std::env::var("STOW_REAL_CC")
        .or_else(|_| std::env::var("CC"))
        .unwrap_or_else(|_| "cc".to_owned())
}

/// The C++ compiler the caller had configured, or the platform default.
pub(crate) fn real_cxx_compiler() -> String {
    std::env::var("STOW_REAL_CXX")
        .or_else(|_| std::env::var("CXX"))
        .unwrap_or_else(|_| "c++".to_owned())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{WrapperCommands, setup_env_output};
    use crate::config::{StowConfig, VerifyMode};

    fn test_config(verify_mode: VerifyMode) -> StowConfig {
        StowConfig {
            edge_url: "https://stow.waterui.dev".to_owned(),
            cache_dir: PathBuf::from("/tmp/stow-cache"),
            request_timeout: Duration::from_secs(300),
            negative_cache_ttl: Duration::from_secs(300),
            graph_cache_ttl: Duration::from_secs(300),
            circuit_reset_after: Duration::from_secs(60),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: 1024,
            verify_mode,
            mock_public_key_path: None,
            state_db_pool: StowConfig::default_state_db_pool(),
        }
    }

    fn test_wrappers() -> WrapperCommands {
        WrapperCommands {
            rustc: "/tmp/stow-tools/stow-rustc-wrapper".to_owned(),
            cc_launcher: "/tmp/stow-tools/stow-cc-launcher".to_owned(),
            cc_compiler: "/tmp/stow-tools/stow-cc".to_owned(),
            cxx_compiler: "/tmp/stow-tools/stow-cxx".to_owned(),
        }
    }

    #[test]
    fn github_env_output_emits_every_wrapper_key() {
        let output = setup_env_output(
            &test_wrappers(),
            "clang",
            "clang++",
            &test_config(VerifyMode::GithubCi),
        );
        assert_eq!(
            output,
            "RUSTC_WRAPPER=/tmp/stow-tools/stow-rustc-wrapper\n\
             STOW_REAL_CC=clang\n\
             STOW_REAL_CXX=clang++\n\
             CC=/tmp/stow-tools/stow-cc\n\
             CXX=/tmp/stow-tools/stow-cxx\n\
             CMAKE_C_COMPILER_LAUNCHER=/tmp/stow-tools/stow-cc-launcher\n\
             CMAKE_CXX_COMPILER_LAUNCHER=/tmp/stow-tools/stow-cc-launcher\n\
             STOW_EDGE_URL=https://stow.waterui.dev\n\
             STOW_VERIFY_MODE=github-ci\n"
        );
    }

    #[test]
    fn github_env_output_serializes_verify_mode_as_wire_string() {
        let output = setup_env_output(
            &test_wrappers(),
            "cc",
            "c++",
            &test_config(VerifyMode::MockKey),
        );
        assert!(output.contains("STOW_VERIFY_MODE=mock-key\n"));
    }
}

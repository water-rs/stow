//! User-facing top-level subcommands: `stow setup`, `status`, `clean`,
//! `check-artifact`, `fetch-artifact`, `purge-cache-dir`.
//!
//! The runtime command (`stow run`/`stow rustc`/`stow cc`) and the cargo
//! drivers (`stow check`/`stow build`/`stow test`) live elsewhere; this
//! module is the dev/maintenance surface.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use stow_types::error::Context;
use toml_edit::{DocumentMut, Item, Table, Value};

use crate::cli_args::{
    CheckArtifactArgs, FetchArtifactArgs, IndexRefreshArgs, PurgeCacheDirArgs, SetupArgs, StatsArgs,
};
use crate::config::{self, StowConfig};
use crate::fetch;
use crate::index;
use crate::mold;
use crate::resolve;
use crate::rustc_args::{detect_rustc_host_target, detect_rustc_version};
use crate::stats;
use crate::wrapper_shim;
use crate::write_stdout;

/// `stow setup`: write the stow wiring into the user's global cargo
/// configuration — `$CARGO_HOME/config.toml` — so every cargo invocation
/// on the machine routes through the stow rustc/cc wrappers; or, with
/// `--github-env`, print the equivalent `KEY=VALUE` job-environment
/// wiring on stdout.
pub async fn setup_project(args: SetupArgs) -> stow_types::error::Result<()> {
    if args.github_env {
        return print_setup_env();
    }
    let current_dir = std::env::current_dir().wrap_err("resolve current directory")?;
    let cargo_home = config::cargo_home().ok_or_else(|| {
        stow_types::stow_error!(
            "resolve the cargo home — neither $CARGO_HOME nor a home directory is available"
        )
    })?;
    let mold_bin_dir = mold::prepare(&current_dir).await?;
    let wrappers = detect_wrapper_commands()?;
    let config_path = write_cargo_config(
        &cargo_home,
        &wrappers,
        &real_c_compiler(),
        &real_cxx_compiler(),
        mold_bin_dir.as_deref(),
    )
    .await?;

    tracing::info!(
        path = %config_path.display(),
        rustc_wrapper = %wrappers.rustc,
        cc_compiler = %wrappers.cc_compiler,
        cxx_compiler = %wrappers.cxx_compiler,
        cc_launcher = %wrappers.cc_launcher,
        mold_bin_dir = ?mold_bin_dir,
        "configured cargo for stow"
    );
    let linker_line = match &mold_bin_dir {
        Some(dir) => format!("\nlinker: mold ({})", dir.join("mold").display()),
        None if cfg!(target_os = "linux") => "\nlinker: mold (already configured)".to_owned(),
        None => String::new(),
    };
    write_stdout(&format!(
        "configured {}\nrustc-wrapper: {}\ncc: {}\ncxx: {}\ncc-launcher: {}{}\n",
        config_path.display(),
        wrappers.rustc,
        wrappers.cc_compiler,
        wrappers.cxx_compiler,
        wrappers.cc_launcher,
        linker_line,
    ))?;

    Ok(())
}

/// Write `cargo_dir/config.toml` pointing cargo at `wrappers` and — when
/// `mold_bin_dir` carries a managed install — selecting mold for every
/// Linux target, with the install dir reaching the linker through the
/// `[env]` table rather than a rustflag so it stays out of the compile
/// key. An existing document keeps every unrelated setting: the
/// `build.rustc-wrapper`, `[env]` compiler keys and stow's linker wiring
/// are replaced in place, so re-running `setup` — including over a stale
/// `/tmp/stow-tools` entry left by an older stow — rewrites the same keys
/// instead of appending duplicates.
async fn write_cargo_config(
    cargo_dir: &Path,
    wrappers: &WrapperCommands,
    real_cc: &str,
    real_cxx: &str,
    mold_bin_dir: Option<&Path>,
) -> stow_types::error::Result<PathBuf> {
    let config_path = cargo_dir.join("config.toml");
    async_fs::create_dir_all(cargo_dir)
        .await
        .wrap_err_with(|| format!("create {}", cargo_dir.display()))?;

    let mut document = if async_fs::metadata(&config_path).await.is_ok() {
        async_fs::read_to_string(&config_path)
            .await
            .wrap_err_with(|| format!("read {}", config_path.display()))?
            .parse::<DocumentMut>()
            .wrap_err_with(|| format!("parse {}", config_path.display()))?
    } else {
        DocumentMut::new()
    };

    configure_document(&mut document, wrappers, real_cc, real_cxx, mold_bin_dir)?;

    async_fs::write(&config_path, document.to_string())
        .await
        .wrap_err_with(|| format!("write {}", config_path.display()))?;
    Ok(config_path)
}

/// Point `document` at `wrappers` and `mold_bin_dir`: `build.rustc-wrapper`,
/// the `[env]` compiler entries, and the mold linker selection when setup
/// provisioned one. Replacement is by key, so the operation is idempotent.
fn configure_document(
    document: &mut DocumentMut,
    wrappers: &WrapperCommands,
    real_cc: &str,
    real_cxx: &str,
    mold_bin_dir: Option<&Path>,
) -> stow_types::error::Result<()> {
    set_build_wrapper(document, &wrappers.rustc);
    for (key, value) in compiler_env_entries(wrappers, real_cc, real_cxx) {
        set_env_wrapper(document, &key, &value);
    }
    if let Some(bin_dir) = mold_bin_dir {
        mold::write_linker_selection(document, bin_dir)?;
    }
    Ok(())
}

/// `stow setup --github-env`: emit the job-environment equivalent of what
/// `stow setup` writes into the cargo configuration, plus the resolved edge
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

/// The C/C++ environment `stow setup` wires, shared by the `.cargo/config.toml`
/// `[env]` table and the `--github-env` output so the two can never drift.
///
/// `STOW_REAL_CC` / `STOW_REAL_CXX` record the toolchain the caller already
/// had before CC/CXX are pointed at the shims, so an explicit compiler
/// survives setup: the shims exec those variables.
fn compiler_env_entries(
    wrappers: &WrapperCommands,
    real_cc: &str,
    real_cxx: &str,
) -> Vec<(String, String)> {
    let mut entries = vec![
        ("STOW_REAL_CC", real_cc.to_owned()),
        ("STOW_REAL_CXX", real_cxx.to_owned()),
        ("CC", wrappers.cc_compiler.clone()),
        ("CXX", wrappers.cxx_compiler.clone()),
        ("CMAKE_C_COMPILER_LAUNCHER", wrappers.cc_launcher.clone()),
        ("CMAKE_CXX_COMPILER_LAUNCHER", wrappers.cc_launcher.clone()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect::<Vec<_>>();
    entries.extend(msvc_toolchain_env());
    entries
}

/// The job-environment variables `stow setup` wires, in a fixed order so the
/// output is stable for consumers that diff it.
fn setup_env_output(
    wrappers: &WrapperCommands,
    real_cc: &str,
    real_cxx: &str,
    config: &StowConfig,
) -> String {
    let rustc_wrapper = [("RUSTC_WRAPPER".to_owned(), wrappers.rustc.clone())];
    let edge = [
        ("STOW_EDGE_URL".to_owned(), config.edge_url.clone()),
        (
            "STOW_VERIFY_MODE".to_owned(),
            config.verify_mode.as_str().to_owned(),
        ),
    ];
    rustc_wrapper
        .into_iter()
        .chain(compiler_env_entries(wrappers, real_cc, real_cxx))
        .chain(edge)
        .fold(String::new(), |mut output, (key, value)| {
            // Writing to a String cannot fail.
            let _ = writeln!(output, "{key}={value}");
            output
        })
}

/// `stow status`: print the wrapper configuration `stow setup` wrote into
/// the global cargo config, plus rolling cache-hit stats.
pub async fn status_project() -> stow_types::error::Result<()> {
    let cargo_home = config::cargo_home().ok_or_else(|| {
        stow_types::stow_error!(
            "resolve the cargo home — neither $CARGO_HOME nor a home directory is available"
        )
    })?;
    let config_path = cargo_home.join("config.toml");

    if async_fs::metadata(&config_path).await.is_err() {
        write_stdout(&format!(
            "not configured: {} is missing — run `stow setup`\n",
            config_path.display()
        ))?;
        return Ok(());
    }

    let document = async_fs::read_to_string(&config_path)
        .await
        .wrap_err_with(|| format!("read {}", config_path.display()))?
        .parse::<DocumentMut>()
        .wrap_err_with(|| format!("parse {}", config_path.display()))?;

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

/// `stow update`: replace this install with the latest stow-cli release.
/// The cargo-dist install receipt — `stow-cli-receipt.json`, written by
/// the shell and powershell installers — records the install prefix and
/// the GitHub repository, and axoupdater downloads that release's own
/// installer and runs it against the recorded prefix, so a `cargo
/// install` or source build cannot clobber itself (the receipt check
/// fails first, with the reason). Afterwards the wrapper shims under the
/// tools dir are re-materialized so they keep resolving to the fresh
/// binary.
pub async fn update_self() -> stow_types::error::Result<()> {
    let mut updater = axoupdater::AxoUpdater::new_for("stow-cli");
    if let Ok(token) = std::env::var("STOW_CLI_GITHUB_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .or_else(|_| std::env::var("GH_TOKEN"))
    {
        updater.set_github_token(&token);
    }
    updater.load_receipt().map_err(|error| {
        stow_types::stow_error!(
            "no install receipt — this binary was not installed by the stow \
             installer, so it cannot update itself ({error})"
        )
    })?;
    let result = updater
        .run()
        .await
        .map_err(|error| stow_types::stow_error!("update stow-cli: {error}"))?;
    match &result {
        Some(update) => write_stdout(&format!(
            "updated stow-cli to {} ({})\n",
            update.new_version, update.new_version_tag
        ))?,
        None => write_stdout("stow-cli is already up to date\n")?,
    }
    let wrappers = detect_wrapper_commands()?;
    tracing::info!(
        rustc_wrapper = %wrappers.rustc,
        cc_compiler = %wrappers.cc_compiler,
        "refreshed wrapper shims"
    );
    Ok(())
}

/// `stow stats`: print this install's own cache counters — served hits,
/// misses, errors, CPU time saved, bytes served and bytes downloaded —
/// from `stats.json`
/// and the per-crate counters in the cache directory. Local-only: the
/// command sends nothing.
pub async fn stats_command(args: StatsArgs) -> stow_types::error::Result<()> {
    let config = StowConfig::load()?;
    let report = stats_report(&config).await?;
    if args.json {
        let body = serde_json::to_string(&report).wrap_err("serialize local stats")?;
        write_stdout(&format!("{body}\n"))
    } else {
        write_stdout(&local_stats_table(&report))
    }
}

/// The counters `stow stats` reports: the bundle-level totals from
/// `stats.json` plus the per-crate lookup counters from `crate_stats`.
#[derive(Debug, serde::Serialize)]
struct StatsReport {
    /// Served cache hits.
    hits: u64,
    /// Lookups the edge had no artifact for.
    misses: u64,
    /// Lookups that failed without producing a miss.
    errors: u64,
    /// Sum of the served bundles' recorded compile times.
    cpu_millis_saved: u64,
    /// Sum of every served cache entry's byte size.
    bytes_served: u64,
    /// The part of `bytes_served` that crossed the network.
    bytes_downloaded: u64,
}

async fn stats_report(config: &StowConfig) -> stow_types::error::Result<StatsReport> {
    let local = stats::read_local_stats(config).await?;
    let summary = stats::read_summary(config).await?;
    Ok(StatsReport {
        hits: local.hits,
        misses: summary.rust_misses.saturating_add(summary.cc_misses),
        errors: summary.rust_errors.saturating_add(summary.cc_errors),
        cpu_millis_saved: local.cpu_millis_saved,
        bytes_served: local.bytes_served,
        bytes_downloaded: local.bytes_downloaded,
    })
}

/// `12_345_678` → `"12,345,678"`.
fn grouped_count(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Compile milliseconds for the table: seconds under a minute, minutes
/// under an hour, hours above.
#[expect(
    clippy::cast_precision_loss,
    reason = "saved CPU time is far below 2^53 milliseconds"
)]
fn format_cpu_millis(millis: u64) -> String {
    if millis >= 3_600_000 {
        format!("{:.1} h", millis as f64 / 3_600_000.0)
    } else if millis >= 60_000 {
        format!("{:.1} min", millis as f64 / 60_000.0)
    } else {
        format!("{:.1} s", millis as f64 / 1_000.0)
    }
}

/// Byte counts for the table, in binary units.
#[expect(
    clippy::cast_precision_loss,
    reason = "downloaded bytes are far below 2^53"
)]
fn format_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// The short table `stow stats` prints.
fn local_stats_table(report: &StatsReport) -> String {
    format!(
        "cache hits          {}\ncache misses        {}\ncache errors        {}\nCPU time saved      {}\nbytes served        {}\nbytes downloaded    {}\n",
        grouped_count(report.hits),
        grouped_count(report.misses),
        grouped_count(report.errors),
        format_cpu_millis(report.cpu_millis_saved),
        format_bytes(report.bytes_served),
        format_bytes(report.bytes_downloaded),
    )
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

/// `stow check-artifact`: resolve `c_metadata` against the verified index
/// slice and report the bundle digest the index pins for it.
pub async fn check_artifact(args: CheckArtifactArgs) -> stow_types::error::Result<()> {
    let config = StowConfig::load()?;
    let slice = index::ensure_slice(&config, &args.target, &args.rustc_version).await?;

    match resolve::find_exact_artifact(&slice.index.rows, &args.c_metadata) {
        Some(row) => {
            write_stdout(&format!(
                "status: present\ncrate: {} {}\nbundle-digest: {}\nindex-manifest: {}\n",
                row.crate_name.as_str(),
                row.version.as_semver(),
                row.bundle_digest,
                slice.manifest_digest,
            ))?;
        }
        None => {
            write_stdout(&format!(
                "status: absent\nc-metadata: {}\nindex-manifest: {}\n",
                args.c_metadata, slice.manifest_digest,
            ))?;
        }
    }
    Ok(())
}

/// `stow fetch-artifact`: resolve `c_metadata` against the index slice,
/// stream the bundle through the edge byte path (digest-checked against
/// the index), and write it to disk.
pub async fn fetch_artifact(args: FetchArtifactArgs) -> stow_types::error::Result<()> {
    let config = StowConfig::load()?;
    let slice = index::ensure_slice(&config, &args.target, &args.rustc_version).await?;
    let row =
        resolve::find_exact_artifact(&slice.index.rows, &args.c_metadata).ok_or_else(|| {
            stow_types::stow_error!(
                "index slice for {} {} carries no artifact {}",
                args.target,
                args.rustc_version,
                args.c_metadata
            )
        })?;
    let bundle_ref = fetch::BundleRef::from_index_row(&args.target, &args.rustc_version, row);
    let bytes = fetch::download_bundle_bytes(&config, &bundle_ref)
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

/// `stow index refresh`: force-fetch and verify the index slice for one
/// toolchain — `--target`/`--rustc-version` override the `rustc` probe.
pub async fn index_refresh(args: IndexRefreshArgs) -> stow_types::error::Result<()> {
    let config = StowConfig::load()?;
    let target = resolve_index_target(args.target).await?;
    let rustc_version = resolve_index_rustc_version(args.rustc_version).await?;
    let slice = index::refresh_slice(&config, &target, &rustc_version).await?;
    write_stdout(&format!(
        "index: {}\ntarget: {}\nrustc-version: {}\nrows: {}\nmanifest-digest: {}\n",
        stow_types::index::index_tag(&target, &rustc_version),
        target,
        rustc_version,
        slice.index.rows.len(),
        slice.manifest_digest,
    ))?;
    Ok(())
}

/// `stow index status`: every verified index slice in the local cache.
pub async fn index_status() -> stow_types::error::Result<()> {
    let config = StowConfig::load()?;
    let slices = index::cached_slices(&config).await?;
    if slices.is_empty() {
        write_stdout("no cached index slices\n")?;
        return Ok(());
    }
    let mut output = String::new();
    for slice in slices {
        let _ = writeln!(
            output,
            "index: {}\ntarget: {}\nrustc-version: {}\nrows: {}\nfetched-at: {}\nmanifest-digest: {}\n",
            stow_types::index::index_tag(&slice.target, &slice.rustc_version),
            slice.target,
            slice.rustc_version,
            slice.row_count,
            slice.fetched_at,
            slice.manifest_digest,
        );
    }
    write_stdout(&output)?;
    Ok(())
}

async fn resolve_index_target(overridden: Option<String>) -> stow_types::error::Result<String> {
    match overridden {
        Some(target) => Ok(target),
        None => detect_rustc_host_target(std::ffi::OsStr::new("rustc"))
            .await
            .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}")),
    }
}

async fn resolve_index_rustc_version(
    overridden: Option<String>,
) -> stow_types::error::Result<String> {
    match overridden {
        Some(rustc_version) => Ok(rustc_version),
        None => detect_rustc_version(std::ffi::OsStr::new("rustc"))
            .await
            .map_err(|error| stow_types::stow_error!("detect rustc version: {error}")),
    }
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
    let shims = wrapper_shim::materialize_wrapper_shims(
        &config::tools_dir()?,
        &runtime_executable,
        &capture_executable,
    )?;
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
pub fn real_c_compiler() -> String {
    std::env::var("STOW_REAL_CC")
        .or_else(|_| std::env::var("CC"))
        .unwrap_or_else(|_| platform_c_compiler())
}

/// The C++ compiler the caller had configured, or the platform default.
pub fn real_cxx_compiler() -> String {
    std::env::var("STOW_REAL_CXX")
        .or_else(|_| std::env::var("CXX"))
        .unwrap_or_else(|_| platform_cxx_compiler())
}

/// The platform's default C compiler. `cc` is the POSIX entry point; on
/// Windows the default is the resolved `cl.exe`, because the bare `cc` on
/// PATH there is a MinGW compiler whose objects `link.exe` cannot link
/// into an MSVC binary — the same resolution the `cc` crate performs for
/// an msvc target.
fn platform_c_compiler() -> String {
    #[cfg(not(windows))]
    return "cc".to_owned();
    #[cfg(windows)]
    return resolved_msvc_compiler();
}

/// The platform's default C++ compiler. `cl.exe` covers both languages on
/// Windows — it is also what the `cc` crate invokes for C++ on an msvc
/// target.
fn platform_cxx_compiler() -> String {
    #[cfg(not(windows))]
    return "c++".to_owned();
    #[cfg(windows)]
    return resolved_msvc_compiler();
}

/// The `cl.exe` of the installed MSVC toolchain, resolved the way the
/// `cc` crate resolves it; the bare name when no installation is found,
/// where the build fails on its own terms.
#[cfg(windows)]
fn resolved_msvc_compiler() -> String {
    find_msvc_tools::find_tool(std::env::consts::ARCH, "cl.exe")
        .map(|tool| tool.path().to_string_lossy().into_owned())
        .unwrap_or_else(|| {
            tracing::warn!("no MSVC installation found; wiring `cl` as the real compiler");
            "cl".to_owned()
        })
}

/// The PATH/LIB/INCLUDE of the resolved MSVC toolchain — the same
/// environment the `cc` crate composes around `cl.exe`, captured so the
/// compiler shims work outside a developer prompt too. Empty on
/// non-Windows hosts and on Windows hosts with no MSVC installation.
#[cfg(not(windows))]
pub const fn msvc_toolchain_env() -> Vec<(String, String)> {
    Vec::new()
}

/// See the non-Windows variant above.
#[cfg(windows)]
pub fn msvc_toolchain_env() -> Vec<(String, String)> {
    find_msvc_tools::find_tool(std::env::consts::ARCH, "cl.exe")
        .map(|tool| {
            tool.env()
                .iter()
                .map(|(key, value)| {
                    (
                        key.to_string_lossy().into_owned(),
                        value.to_string_lossy().into_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
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
            registry_base_url: stow_types::registry::GHCR_V2_BASE_URL.to_owned(),
            cache_dir: PathBuf::from("/tmp/stow-cache"),
            request_timeout: Duration::from_mins(5),
            negative_cache_ttl: Duration::from_mins(5),
            circuit_reset_after: Duration::from_mins(1),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: 1024,
            index_refresh_interval: Duration::from_mins(5),
            verify_mode,
            state_db_pool: StowConfig::default_state_db_pool(),
            trust_material: std::sync::Arc::default(),
        }
    }

    /// A tools-dir-shaped prefix for the wrapper fixtures; contents matter,
    /// not the platform spelling.
    const TEST_TOOLS_DIR: &str = "/home/user/.local/share/stow/tools";

    fn test_wrappers() -> WrapperCommands {
        WrapperCommands {
            rustc: format!("{TEST_TOOLS_DIR}/stow-rustc-wrapper"),
            cc_launcher: format!("{TEST_TOOLS_DIR}/stow-cc-launcher"),
            cc_compiler: format!("{TEST_TOOLS_DIR}/stow-cc"),
            cxx_compiler: format!("{TEST_TOOLS_DIR}/stow-cxx"),
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
            "RUSTC_WRAPPER=/home/user/.local/share/stow/tools/stow-rustc-wrapper\n\
             STOW_REAL_CC=clang\n\
             STOW_REAL_CXX=clang++\n\
             CC=/home/user/.local/share/stow/tools/stow-cc\n\
             CXX=/home/user/.local/share/stow/tools/stow-cxx\n\
             CMAKE_C_COMPILER_LAUNCHER=/home/user/.local/share/stow/tools/stow-cc-launcher\n\
             CMAKE_CXX_COMPILER_LAUNCHER=/home/user/.local/share/stow/tools/stow-cc-launcher\n\
             STOW_EDGE_URL=https://stow.waterui.dev\n\
             STOW_VERIFY_MODE=github-ci\n"
        );
    }

    #[tokio::test]
    async fn setup_rewrites_stale_wrapper_entries_without_duplicating() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let cargo_dir = tempdir.path().join(".cargo");
        std::fs::create_dir_all(&cargo_dir).expect("create .cargo");
        std::fs::write(
            cargo_dir.join("config.toml"),
            "[build]\nrustc-wrapper = \"/tmp/stow-tools/stow-rustc-wrapper\"\n\
             \n[env]\n\
             CC = { value = \"/tmp/stow-tools/stow-cc\", force = true }\n",
        )
        .expect("seed stale cargo config");

        let wrappers = test_wrappers();
        let config_path =
            super::write_cargo_config(&cargo_dir, &wrappers, "clang", "clang++", None)
                .await
                .expect("first setup");
        let once = std::fs::read_to_string(&config_path).expect("read written config");

        super::write_cargo_config(&cargo_dir, &wrappers, "clang", "clang++", None)
            .await
            .expect("second setup");
        let twice = std::fs::read_to_string(&config_path).expect("read rewritten config");

        assert_eq!(once, twice, "re-running setup changed the file");
        assert!(
            !once.contains("/tmp/stow-tools"),
            "stale /tmp/stow-tools entry survived:\n{once}"
        );
        assert!(
            once.contains(&wrappers.rustc),
            "config does not point at {}:\n{once}",
            wrappers.rustc
        );
        assert_eq!(once.matches("rustc-wrapper =").count(), 1);
    }

    #[cfg(feature = "mock-verify")]
    #[test]
    fn github_env_output_serializes_verify_mode_as_wire_string() {
        let output = setup_env_output(
            &test_wrappers(),
            "cc",
            "c++",
            &test_config(VerifyMode::MockKey {
                public_key_path: std::path::PathBuf::from("/keys/mock.pub"),
                public_key_sha256: "00".repeat(32),
            }),
        );
        assert!(output.contains("STOW_VERIFY_MODE=mock-key\n"));
    }
}

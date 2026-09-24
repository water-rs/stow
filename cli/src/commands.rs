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
        return print_setup_env().await;
    }
    let current_dir = std::env::current_dir().wrap_err("resolve current directory")?;
    let cargo_home = config::cargo_home().ok_or_else(|| {
        stow_types::stow_error!(
            "resolve the cargo home — neither $CARGO_HOME nor a home directory is available"
        )
    })?;
    let host_target = detect_rustc_host_target(std::ffi::OsStr::new("rustc"))
        .await
        .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
    // A global setup answers only from the global configuration — the
    // directory it runs in must not change the result.
    let mold_bin_dir = mold::prepare_global().await?;
    let wrappers = detect_wrapper_commands()?;
    let cleaned = clean_stale_project_configs(&current_dir, &cargo_home.join("config.toml"))?;
    let config_path = write_cargo_config(
        &cargo_home,
        &wrappers,
        &host_target,
        configured_c_compiler(&host_target).as_deref(),
        configured_cxx_compiler(&host_target).as_deref(),
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
    for path in cleaned {
        write_stdout(&format!(
            "cleaned stale stow wiring from {}\n",
            path.display()
        ))?;
    }

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
    host_target: &str,
    real_cc: Option<&str>,
    real_cxx: Option<&str>,
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

    // A compiler recorded by an earlier setup lives in this document, not
    // in the environment — carry it forward so re-running setup never
    // forgets the toolchain the caller configured the first time.
    let recorded = |key: &str| -> Option<String> {
        document
            .get("env")
            .and_then(Item::as_table)
            .and_then(|env| env.get(key))
            .and_then(env_item_value)
            .map(str::to_owned)
            .filter(|value| !is_stow_owned_value(value))
    };
    let real_cc = real_cc
        .map(str::to_owned)
        .or_else(|| recorded("STOW_REAL_CC"));
    let real_cxx = real_cxx
        .map(str::to_owned)
        .or_else(|| recorded("STOW_REAL_CXX"));

    configure_document(
        &mut document,
        wrappers,
        compiler_env_entries(
            wrappers,
            host_target,
            real_cc.as_deref(),
            real_cxx.as_deref(),
        ),
        mold_bin_dir,
    )?;

    async_fs::write(&config_path, document.to_string())
        .await
        .wrap_err_with(|| format!("write {}", config_path.display()))?;
    Ok(config_path)
}

/// Point `document` at `wrappers` and `mold_bin_dir`: `build.rustc-wrapper`,
/// the `[env]` compiler entries, and the mold linker selection when setup
/// provisioned one. Entries an earlier stow wrote and this revision no
/// longer emits are removed first — by value, never by key name alone —
/// and replacement of the rest is by key, so the operation is idempotent.
fn configure_document(
    document: &mut DocumentMut,
    wrappers: &WrapperCommands,
    env_entries: Vec<(String, String)>,
    mold_bin_dir: Option<&Path>,
) -> stow_types::error::Result<()> {
    clean_stow_owned_entries(document);
    set_build_wrapper(document, &wrappers.rustc);
    for (key, value) in env_entries {
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
async fn print_setup_env() -> stow_types::error::Result<()> {
    let wrappers = detect_wrapper_commands()?;
    let config = StowConfig::load()?;
    let host_target = detect_rustc_host_target(std::ffi::OsStr::new("rustc"))
        .await
        .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
    write_stdout(&setup_env_output(
        &wrappers,
        &host_target,
        configured_c_compiler(&host_target).as_deref(),
        configured_cxx_compiler(&host_target).as_deref(),
        &config,
    ))
}

/// The C/C++ environment `stow setup` wires, shared by the `.cargo/config.toml`
/// `[env]` table and the `--github-env` output so the two can never drift.
///
/// The shims are wired through the `cc` crate's own target-scoped keys —
/// `CC_<triple>` / `CXX_<triple>` for the host target — rather than bare
/// `CC`/`CXX`, so other targets (`*-windows-gnu`, `wasm32`, cross builds)
/// keep the toolchain `cc`-rs resolves for them instead of being forced
/// onto the host compiler. The `CMAKE_*_COMPILER_LAUNCHER` variables have
/// no target-scoped form; they stay bare — the launcher wraps whichever
/// compiler `CMake` picked, so it is correct on every target.
///
/// `STOW_REAL_CC` / `STOW_REAL_CXX` are written only when the caller had
/// an explicit toolchain configured; without them the shims resolve the
/// platform's compiler per invocation, the way the `cc` crate does.
fn compiler_env_entries(
    wrappers: &WrapperCommands,
    host_target: &str,
    real_cc: Option<&str>,
    real_cxx: Option<&str>,
) -> Vec<(String, String)> {
    let scoped = host_target.replace(['-', '.'], "_");
    let mut entries = Vec::with_capacity(6);
    if let Some(real_cc) = real_cc {
        entries.push(("STOW_REAL_CC".to_owned(), real_cc.to_owned()));
    }
    if let Some(real_cxx) = real_cxx {
        entries.push(("STOW_REAL_CXX".to_owned(), real_cxx.to_owned()));
    }
    entries.extend([
        (format!("CC_{scoped}"), wrappers.cc_compiler.clone()),
        (format!("CXX_{scoped}"), wrappers.cxx_compiler.clone()),
        (
            "CMAKE_C_COMPILER_LAUNCHER".to_owned(),
            wrappers.cc_launcher.clone(),
        ),
        (
            "CMAKE_CXX_COMPILER_LAUNCHER".to_owned(),
            wrappers.cc_launcher.clone(),
        ),
    ]);
    entries
}

/// The job-environment variables `stow setup` wires, in a fixed order so the
/// output is stable for consumers that diff it.
fn setup_env_output(
    wrappers: &WrapperCommands,
    host_target: &str,
    real_cc: Option<&str>,
    real_cxx: Option<&str>,
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
        .chain(compiler_env_entries(
            wrappers,
            host_target,
            real_cc,
            real_cxx,
        ))
        .chain(edge)
        .fold(String::new(), |mut output, (key, value)| {
            // Writing to a String cannot fail.
            let _ = writeln!(output, "{key}={value}");
            output
        })
}

/// `stow status`: print the wrapper configuration `stow setup` wrote into
/// the global cargo config, any stale per-project wiring an older stow
/// left in the ancestor `.cargo/config.toml` files, plus rolling
/// cache-hit stats.
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

    // The shims are wired under the `cc` crate's target-scoped keys for the
    // host triple; an unrecognized answer still reports whatever scoped
    // keys are present rather than pretending nothing is wired.
    let scoped = |base: &str| -> Option<String> {
        document
            .get("env")
            .and_then(Item::as_table)
            .map(|env| {
                env.iter()
                    .filter(|(key, _)| key.starts_with(&format!("{base}_")) || *key == base)
                    .filter_map(|(_, item)| env_item_value(item).map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .filter(|values| !values.is_empty())
            .map(|values| values.join(", "))
    };
    let cc_compiler = scoped("CC").unwrap_or_else(|| "<missing>".to_owned());
    let cxx_compiler = scoped("CXX").unwrap_or_else(|| "<missing>".to_owned());
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

    if let Ok(current_dir) = std::env::current_dir() {
        for path in stale_project_configs(&current_dir, &config_path) {
            write_stdout(&format!(
                "stale stow wiring: {} — left by an older stow; `stow setup` removes it\n",
                path.display()
            ))?;
        }
    }

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
    if !updater
        .check_receipt_is_for_this_executable()
        .map_err(|error| stow_types::stow_error!("check the install receipt: {error}"))?
    {
        let prefix = updater
            .install_prefix_root()
            .map_or_else(|_| "<unknown>".to_owned(), |root| root.to_string());
        return Err(stow_types::stow_error!(
            "the install receipt records a different install prefix ({prefix}) — \
             this stow was not installed by the installer and cannot update itself"
        ));
    }
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

/// The compiler the caller configured for `target`, in the order the `cc`
/// crate consults the same variables: `STOW_REAL_*` (the value setup
/// recorded), then `<base>_<target>`, `<base>_<target_underscored>`,
/// `TARGET_<base>`, `HOST_<base>`, `<base>`. `None` means no toolchain was
/// configured — the shim then resolves the platform's compiler itself.
fn configured_compiler(real_env: &str, base_env: &str, target: &str) -> Option<String> {
    let scoped = target.replace(['-', '.'], "_");
    std::env::var(real_env)
        .ok()
        .or_else(|| std::env::var(format!("{base_env}_{target}")).ok())
        .or_else(|| std::env::var(format!("{base_env}_{scoped}")).ok())
        .or_else(|| std::env::var(format!("TARGET_{base_env}")).ok())
        .or_else(|| std::env::var(format!("HOST_{base_env}")).ok())
        .or_else(|| std::env::var(base_env).ok())
        .filter(|value| !value.trim().is_empty())
}

/// The C compiler the caller configured for `target`, or `None` when none
/// is — setup records it as `STOW_REAL_CC`; with no entry the shim
/// resolves per invocation the way the `cc` crate does.
pub fn configured_c_compiler(target: &str) -> Option<String> {
    configured_compiler("STOW_REAL_CC", "CC", target)
}

/// The C++ compiler the caller configured for `target`; see
/// [`configured_c_compiler`].
pub fn configured_cxx_compiler(target: &str) -> Option<String> {
    configured_compiler("STOW_REAL_CXX", "CXX", target)
}

/// `.cargo/config.toml` files in `dir`'s ancestors that still carry stow's
/// old per-project wiring — they shadow the global config. `exclude` is the
/// global config path itself (it belongs to the write target, not this
/// walk). Returns every file holding a stow-owned value.
fn stale_project_configs(dir: &Path, exclude: &Path) -> Vec<PathBuf> {
    let mut stale = Vec::new();
    for ancestor in dir.ancestors() {
        let path = ancestor.join(".cargo").join("config.toml");
        if path == exclude || !path.is_file() {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(document) = contents.parse::<DocumentMut>() else {
            continue;
        };
        if document_is_stow_wired(&document) {
            stale.push(path);
        }
    }
    stale
}

/// Remove stow's old per-project wiring from every ancestor
/// `.cargo/config.toml` of `dir`, returning the cleaned paths. Keys are
/// removed by value — only entries pointing at stow's shims or tools dir —
/// so a user's own `CC`, `COMPILER_PATH` or `rustc-wrapper` survives.
fn clean_stale_project_configs(
    dir: &Path,
    exclude: &Path,
) -> stow_types::error::Result<Vec<PathBuf>> {
    let mut cleaned = Vec::new();
    for path in stale_project_configs(dir, exclude) {
        let contents =
            std::fs::read_to_string(&path).wrap_err_with(|| format!("read {}", path.display()))?;
        let mut document = contents
            .parse::<DocumentMut>()
            .wrap_err_with(|| format!("parse {}", path.display()))?;
        clean_stow_owned_entries(&mut document);
        std::fs::write(&path, document.to_string())
            .wrap_err_with(|| format!("write {}", path.display()))?;
        cleaned.push(path);
    }
    Ok(cleaned)
}

/// Whether `document` holds any value stow's wiring owns — a
/// `rustc-wrapper` or an `[env]` entry pointing at a stow shim or the
/// tools dir.
fn document_is_stow_wired(document: &DocumentMut) -> bool {
    let rustc_wrapper_is_stow = document
        .get("build")
        .and_then(Item::as_table)
        .and_then(|build| build.get("rustc-wrapper"))
        .and_then(Item::as_str)
        .is_some_and(is_stow_owned_value);
    let env_has_stow_value = document
        .get("env")
        .and_then(Item::as_table)
        .is_some_and(|env| {
            env.iter()
                .any(|(_, item)| env_item_value(item).is_some_and(is_stow_owned_value))
        });
    rustc_wrapper_is_stow || env_has_stow_value
}

/// Remove the entries older stow versions wrote into `document`, by value:
/// any `build.rustc-wrapper` or `[env]` entry pointing at a stow shim or
/// the tools dir, the `STOW_REAL_*` companion variables once the document
/// is proven stow-wired, the `PATH`/`LIB`/`LIBPATH`/`INCLUDE` MSVC
/// toolchain snapshot an earlier revision persisted, and stow's mold
/// rustflags inside `target` tables. Returns whether anything changed.
fn clean_stow_owned_entries(document: &mut DocumentMut) -> bool {
    let mut changed = false;
    let wired = document_is_stow_wired(document);

    if wired
        && let Some(build) = document.get_mut("build").and_then(Item::as_table_mut)
        && build
            .get("rustc-wrapper")
            .is_some_and(|item| item.as_str().is_some_and(is_stow_owned_value))
    {
        build.remove("rustc-wrapper");
        changed = true;
    }

    if let Some(env) = document.get_mut("env").and_then(Item::as_table_like_mut) {
        let keys: Vec<String> = env.iter().map(|(key, _)| key.to_owned()).collect();
        for key in keys {
            let remove = match env.get(&key).and_then(env_item_value) {
                Some(value) if is_stow_owned_value(value) => true,
                Some(value)
                    if matches!(key.as_str(), "PATH" | "LIB" | "LIBPATH" | "INCLUDE")
                        && is_msvc_snapshot_value(value) =>
                {
                    true
                }
                Some(_) if wired && key.starts_with("STOW_REAL_") => true,
                _ => false,
            };
            if remove {
                env.remove(&key);
                changed = true;
            }
        }
    }

    // Stow's linker selection lives in `target` rustflags — strip it only
    // where the document already proved stow-wired by value.
    if wired && let Some(target) = document.get_mut("target").and_then(Item::as_table_mut) {
        for (_, table) in target.iter_mut() {
            let Some(table) = table.as_table_like_mut() else {
                continue;
            };
            let flags = match table.get("rustflags") {
                Some(item) if item.is_array() || item.is_str() => mold::rustflags_value(item),
                _ => continue,
            };
            let flag_count = flags.len();
            let kept = mold::strip_stow_linker_flags(flags);
            if kept.len() != flag_count {
                changed = true;
                if kept.is_empty() {
                    table.remove("rustflags");
                } else {
                    let mut array = toml_edit::Array::new();
                    array.extend(kept);
                    *table.get_mut("rustflags").expect("rustflags exists") =
                        Item::Value(Value::Array(array));
                }
            }
        }
    }
    changed
}

/// A value stow's wiring owns: a path to one of its shims, or anything
/// inside a stow tools dir — the shims' home (`<data>/stow/tools`) and the
/// tools dir older releases used (`/tmp/stow-tools`). The key holding a
/// value never decides, so a user's own `CC` or `COMPILER_PATH` survives.
fn is_stow_owned_value(value: &str) -> bool {
    const SHIM_STEMS: &[&str] = &[
        "stow-rustc-wrapper",
        "stow-cc",
        "stow-cxx",
        "stow-cc-launcher",
        "stow-runtime",
        "stow-capture",
    ];
    let path = Path::new(value.trim());
    if path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|stem| SHIM_STEMS.contains(&stem))
    {
        return true;
    }
    // tools-dir segment pairs: "…/stow/tools/…" or "…/stow-tools/…".
    let mut previous_was_stow = false;
    for component in path.components() {
        let name = component.as_os_str().to_string_lossy();
        if name == "stow-tools" || (previous_was_stow && name == "tools") {
            return true;
        }
        previous_was_stow = name == "stow";
    }
    false
}

/// Whether an `[env]` value carries the MSVC toolchain snapshot an earlier
/// revision persisted under `PATH`/`LIB`/`LIBPATH`/`INCLUDE` — Visual
/// Studio's `MSVC` toolset or the Windows Kits SDK paths it recorded.
/// Identification is by content, so a user's own `PATH` entry survives.
fn is_msvc_snapshot_value(value: &str) -> bool {
    value.contains("MSVC") || value.contains("Windows Kits")
}

/// The string an `env` entry holds, accepting both cargo shapes —
/// `KEY = "…"` and `KEY = { value = "…", force = … }`.
fn env_item_value(item: &Item) -> Option<&str> {
    if let Some(value) = item.as_str() {
        return Some(value);
    }
    item.as_table_like()
        .and_then(|entry| entry.get("value"))
        .and_then(Item::as_str)
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
            build_state: None,
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
            "x86_64-unknown-linux-gnu",
            Some("clang"),
            Some("clang++"),
            &test_config(VerifyMode::GithubCi),
        );
        let expected = String::from(
            "RUSTC_WRAPPER=/home/user/.local/share/stow/tools/stow-rustc-wrapper\n\
             STOW_REAL_CC=clang\n\
             STOW_REAL_CXX=clang++\n\
             CC_x86_64_unknown_linux_gnu=/home/user/.local/share/stow/tools/stow-cc\n\
             CXX_x86_64_unknown_linux_gnu=/home/user/.local/share/stow/tools/stow-cxx\n\
             CMAKE_C_COMPILER_LAUNCHER=/home/user/.local/share/stow/tools/stow-cc-launcher\n\
             CMAKE_CXX_COMPILER_LAUNCHER=/home/user/.local/share/stow/tools/stow-cc-launcher\n\
             STOW_EDGE_URL=https://stow.waterui.dev\n\
             STOW_VERIFY_MODE=github-ci\n",
        );
        assert_eq!(output, expected);
    }

    /// The shims ride the `cc` crate's target-scoped keys so other targets
    /// keep their own toolchain — no bare `CC`/`CXX` anywhere.
    #[test]
    fn env_entries_scope_the_shims_to_the_host_target() {
        let entries =
            super::compiler_env_entries(&test_wrappers(), "aarch64-pc-windows-msvc", None, None);
        let keys: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "CC_aarch64_pc_windows_msvc",
                "CXX_aarch64_pc_windows_msvc",
                "CMAKE_C_COMPILER_LAUNCHER",
                "CMAKE_CXX_COMPILER_LAUNCHER",
            ],
            "entries: {entries:?}"
        );
        // No unconfigured-toolchain variables, and nothing unscoped.
        for (key, _) in &entries {
            assert!(!key.starts_with("STOW_REAL_"), "{key} leaked");
            assert_ne!(key, "CC");
            assert_ne!(key, "CXX");
        }
    }

    /// An explicit toolchain the caller configured is recorded, in the
    /// same precedence order the `cc` crate resolves it.
    #[test]
    fn configured_compiler_prefers_the_scoped_key() {
        // SAFETY: nextest runs every test in its own process.
        unsafe {
            std::env::set_var("CC_armv7_unknown_linux_gnueabihf", "arm-gcc");
            std::env::set_var("CC", "cc");
        }
        let resolved = super::configured_c_compiler("armv7-unknown-linux-gnueabihf");
        unsafe {
            std::env::remove_var("CC_armv7_unknown_linux_gnueabihf");
            std::env::remove_var("CC");
        }
        assert_eq!(resolved.as_deref(), Some("arm-gcc"));
    }

    /// With nothing configured the answer is `None` — the shim resolves
    /// the platform toolchain per invocation instead of a stale snapshot.
    #[test]
    fn configured_compiler_is_none_without_any_cc_env() {
        // SAFETY: nextest runs every test in its own process.
        unsafe {
            for key in [
                "STOW_REAL_CC",
                "CC_riscv64gc_unknown_linux_gnu",
                "TARGET_CC",
                "HOST_CC",
                "CC",
            ] {
                std::env::remove_var(key);
            }
        }
        assert_eq!(
            super::configured_c_compiler("riscv64gc-unknown-linux-gnu"),
            None
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
        let config_path = super::write_cargo_config(
            &cargo_dir,
            &wrappers,
            "x86_64-unknown-linux-gnu",
            Some("clang"),
            Some("clang++"),
            None,
        )
        .await
        .expect("first setup");
        let once = std::fs::read_to_string(&config_path).expect("read written config");

        super::write_cargo_config(
            &cargo_dir,
            &wrappers,
            "x86_64-unknown-linux-gnu",
            Some("clang"),
            Some("clang++"),
            None,
        )
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

    /// The cleanup identifies stow's wiring by value: a config whose `CC`
    /// points at the user's own compiler is untouched, while every entry
    /// pointing at a stow shim or the old tools dir goes.
    #[test]
    fn stale_cleanup_removes_only_stow_owned_values() {
        let mut document: toml_edit::DocumentMut = "[build]\n\
             rustc-wrapper = \"/tmp/stow-tools/stow-rustc-wrapper\"\n\
             \n[env]\n\
             CC = { value = \"/tmp/stow-tools/stow-cc\", force = true }\n\
             CXX = \"/tmp/stow-tools/stow-cxx\"\n\
             STOW_REAL_CC = \"cc\"\n\
             STOW_REAL_CXX = \"c++\"\n\
             PATH = { value = \"C:\\\\Program Files\\\\Microsoft Visual Studio\\\\2022\\\\VC\\\\Tools\\\\MSVC\\\\14.4\\\\bin\\\\HostX64\\\\x64\", force = true }\n\
             INCLUDE = \"C:\\\\Program Files (x86)\\\\Windows Kits\\\\10\\\\Include\"\n\
             CMAKE_C_COMPILER_LAUNCHER = \"/home/u/.local/share/stow/tools/stow-cc-launcher\"\n\
             OBJC = \"/usr/bin/clang\"\n\
             \n[target.'cfg(target_os = \"linux\")']\n\
             rustflags = [\"-C\", \"link-arg=-fuse-ld=mold\", \"-C\", \"debuginfo=2\", \"-C\", \"link-arg=-B/home/u/.local/share/stow/tools/mold/bin\"]\n\
             \n[target.'cfg(target_os = \"macos\")']\n\
             rustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n"
            .parse()
            .expect("parse fixture");

        assert!(super::clean_stow_owned_entries(&mut document));
        let text = document.to_string();

        for gone in [
            "/tmp/stow-tools",
            "stow-cc-launcher",
            "STOW_REAL_CC",
            "STOW_REAL_CXX",
            "MSVC",
            "Windows Kits",
            "rustc-wrapper",
            "-fuse-ld=mold",
            "mold/bin",
        ] {
            assert!(!text.contains(gone), "{gone} survived:\n{text}");
        }
        // The user's own compiler and their non-stow rustflag stay.
        assert!(text.contains("OBJC"), "user env dropped:\n{text}");
        assert!(text.contains("debuginfo=2"), "user flag dropped:\n{text}");
    }

    /// Value-based identification means a project config the user wrote
    /// themselves — same keys, their own values — reports clean.
    #[test]
    fn user_wired_config_is_not_stale() {
        let mut document: toml_edit::DocumentMut = "[build]\n\
             rustc-wrapper = \"/usr/bin/sccache\"\n\
             \n[env]\n\
             CC = \"/usr/bin/clang\"\n\
             STOW_REAL_CC = \"not-a-path\"\n"
            .parse()
            .expect("parse fixture");
        assert!(!super::clean_stow_owned_entries(&mut document));
    }

    /// Setup walking ancestors removes the stale project file and reports
    /// it; a config that is stow-wired by value in `cwd` is rewritten even
    /// though the global config is elsewhere.
    #[tokio::test]
    async fn clean_stale_project_configs_removes_only_stow_wiring() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let project = tempdir.path().join("proj");
        let cargo_dir = project.join(".cargo");
        std::fs::create_dir_all(&cargo_dir).expect("create .cargo");
        let stale = cargo_dir.join("config.toml");
        std::fs::write(
            &stale,
            "[env]\nCC = \"/tmp/stow-tools/stow-cc\"\nOBJC = \"/usr/bin/clang\"\n",
        )
        .expect("seed stale config");
        let untouched_dir = project.join("nested/.cargo");
        std::fs::create_dir_all(&untouched_dir).expect("create nested .cargo");
        let untouched = untouched_dir.join("config.toml");
        std::fs::write(&untouched, "[env]\nCC = \"/usr/bin/clang\"\n").expect("seed user config");

        let cleaned = super::clean_stale_project_configs(
            &project,
            &tempdir.path().join("elsewhere/config.toml"),
        )
        .expect("clean");
        assert_eq!(cleaned, vec![stale.clone()]);
        let text = std::fs::read_to_string(&stale).expect("read cleaned");
        assert!(!text.contains("stow-cc"), "stow entry survived:\n{text}");
        assert!(text.contains("OBJC"), "user entry dropped:\n{text}");
        assert_eq!(
            std::fs::read_to_string(&untouched).expect("read user config"),
            "[env]\nCC = \"/usr/bin/clang\"\n"
        );
    }

    /// `stow update` refuses a receipt recorded for a different install
    /// prefix instead of reporting "already up to date".
    #[tokio::test]
    async fn update_refuses_a_receipt_from_another_prefix() {
        let receipt_dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            receipt_dir.path().join("stow-cli-receipt.json"),
            r#"{"binaries":["stow","stow-cc","stow-cxx","stow-cc-launcher","stow-rustc-wrapper","stow-runtime","stow-capture"],"cdylibs":[],"install_prefix":"/elsewhere/bin","provider":{"source":"cargo-dist","version":"0.30.2"},"source":{"app_name":"stow-cli","name":"stow","owner":"water-rs","release_type":"github"},"version":"0.5.0","modify_path":false}"#,
        )
        .expect("write receipt");
        // SAFETY: nextest runs every test in its own process.
        unsafe {
            std::env::set_var("AXOUPDATER_CONFIG_PATH", receipt_dir.path());
        }
        let error = super::update_self().await.expect_err("must refuse");
        assert!(
            format!("{error}").contains("different install prefix"),
            "unexpected error: {error}"
        );
    }

    #[cfg(feature = "mock-verify")]
    #[test]
    fn github_env_output_serializes_verify_mode_as_wire_string() {
        let output = setup_env_output(
            &test_wrappers(),
            "x86_64-unknown-linux-gnu",
            None,
            None,
            &test_config(VerifyMode::MockKey {
                public_key_path: std::path::PathBuf::from("/keys/mock.pub"),
                public_key_sha256: "00".repeat(32),
            }),
        );
        assert!(output.contains("STOW_VERIFY_MODE=mock-key\n"));
    }
}

//! mold is the linker on Linux, and it is mandatory.
//!
//! stow links with mold on both sides of the cache, and the published
//! artifacts exist only in the mold variant of units that invoke the
//! linker. `stow setup` therefore makes mold available on the machine when
//! the configuration does not already select a reachable one, and writes
//! the selection into the global `$CARGO_HOME/config.toml`; a `stow` build
//! on Linux that finds no selection provisions the managed install and
//! selects it for that invocation only — falling back to another linker
//! produces artifacts keyed for a linker the cache does not publish, a
//! slower build and a colder cache at once.
//!
//! Both questions — "does the configuration select mold" and "can the
//! linker reach a mold binary" — are answered from what cargo and the
//! compiler driver actually resolve, never guessed from a missing
//! variable. The second question comes in two shapes: a configured
//! `linker = "…mold"` must itself name a resolvable executable, while
//! `-C link-arg=-fuse-ld=mold` asks the compiler driver to find an
//! `ld.mold`.
//!
//! How `ld.mold` becomes findable is the part that cannot be a rustc
//! flag: every `link-arg` reaches the compile key verbatim, and the cache
//! publishes linked units keyed on exactly `["link-arg=-fuse-ld=mold"]` —
//! a `-B` prefix or `-C linker=` line in the config would put the
//! machine's paths inside the identity and miss every published artifact.
//! The resolution therefore lives in the environment, not the argv: the
//! config's `[env]` table sets `COMPILER_PATH` to the managed install's
//! `bin`, cargo applies it to every process the build spawns, and a
//! gcc- or clang-shaped driver — native or cross — searches it for
//! subprograms. `PATH` is not a substitute: a cross-prefixed gcc does not
//! consult it for `ld.mold`, so only `COMPILER_PATH` survives both shapes.

use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use sha2::Digest as _;
use stow_types::error::Context;
use tracing::Instrument as _;

use crate::rustc_args::detect_rustc_host_target;

/// The mold release stow installs: a version and a per-arch sha256 of the
/// tarball GitHub serves for it, so the install does not have to trust the
/// download.
const MOLD_VERSION: &str = "2.42.1";

/// The `-C` link option selecting mold through the compiler driver —
/// `rustc` passes `link-arg` values through to the driver's command line.
const FUSE_LD_MOLD: &str = "link-arg=-fuse-ld=mold";

/// The `target` table `stow setup` writes the selection into: every Linux
/// triple matches `target_os = "linux"` (Android triples do not), so one
/// table covers native and cross builds alike.
const LINUX_TARGET_TABLE: &str = "cfg(target_os = \"linux\")";

/// Seconds before a mold release download is given up.
const DOWNLOAD_TIMEOUT_SECS: u64 = 300;

/// The cargo `--config` overrides a `stow` build without `stow setup`
/// needs so its Linux units link with mold — the same two keys
/// [`write_linker_selection`] puts into the config, carried on the command
/// line so nothing touches the user's files: `link-arg=-fuse-ld=mold` in
/// the `cfg(target_os = "linux")` table's rustflags, and `COMPILER_PATH`
/// at the managed install's `bin` so the driver finds `ld.mold`.
///
/// An empty list means nothing is needed: a non-Linux build, or a
/// configuration that already selects mold and can reach a mold binary —
/// in which case the existing selection stands untouched. A build whose
/// own selection exists but cannot resolve — the selection without the
/// binary — is provisioned too, exactly as `stow setup` provisions it.
///
/// # Errors
///
/// Fails when the mold install fails — the error says which step.
pub async fn provision(target: &str, cargo_dir: &Path) -> stow_types::error::Result<Vec<String>> {
    if !cfg!(target_os = "linux") || !linux_target(target) {
        return Ok(Vec::new());
    }
    // The cfg probe and the availability probe are both process spawns,
    // and they are independent unless a `cfg()` target table changes the
    // probe's inputs: the conservative read — every cfg table a
    // candidate, the same read `matching_target_tables` gives an
    // unanswered cfg probe — launches the probe the config asks for while
    // rustc is still answering. When the answered cfgs leave the probe
    // inputs untouched the speculative answer stands; when they change
    // it the probe reruns on the real inputs.
    let cfgs = tokio::spawn({
        let target = target.to_owned();
        async move {
            rustc_target_cfgs(&target)
                .instrument(tracing::debug_span!("stow.precargo.mold_cfg_probe"))
                .await
        }
    });
    let config = CargoConfig::load(cargo_dir, &process_env).await;
    let candidate = resolve_link_from(&config, target, None, &process_env);
    let speculative = match (candidate.selects_mold, candidate.probe()) {
        (true, probe @ MoldProbe::Driver { .. }) => {
            let task = tokio::spawn({
                let probe = probe.clone();
                async move {
                    probe_unavailable_reason(&probe)
                        .instrument(tracing::debug_span!("stow.precargo.mold_probe"))
                        .await
                }
            });
            Some((probe, task))
        }
        _ => None,
    };
    let cfgs = cfgs.await.unwrap_or_default();
    let link = resolve_link_from(&config, target, cfgs.as_ref(), &process_env);
    if link.selects_mold {
        let real = link.probe();
        let reason = match speculative {
            Some((probe, task)) if probe == real => task
                .await
                .map_err(|error| stow_types::stow_error!("join mold probe task: {error}"))?,
            Some((_, task)) => {
                task.abort();
                probe_unavailable_reason(&real)
                    .instrument(tracing::debug_span!("stow.precargo.mold_probe"))
                    .await
            }
            None => {
                probe_unavailable_reason(&real)
                    .instrument(tracing::debug_span!("stow.precargo.mold_probe"))
                    .await
            }
        };
        if reason.is_none() {
            return Ok(Vec::new());
        }
    } else if let Some((_, task)) = speculative {
        task.abort();
    }
    let bin_dir = ensure_mold_install()
        .instrument(tracing::debug_span!("stow.precargo.mold_install"))
        .await?;
    selection_args(&bin_dir)
}

/// The linker selection as cargo `--config` values — the same TOML
/// [`write_linker_selection`] produces, expressed as dotted keys for the
/// command line.
fn selection_args(bin_dir: &Path) -> stow_types::error::Result<Vec<String>> {
    let bin = compiler_path_value(bin_dir)?;
    // `--config` values are `KEY=VALUE` where the value is scalar TOML —
    // an inline table is rejected, so the `env` entry's `value` and
    // `force` fields arrive as two dotted keys cargo merges into the same
    // table the file write produces. The cfg key segment is a TOML
    // literal-string (`'…'`) because its inner quotes would need escaping
    // inside a `"…"` key.
    Ok(vec![
        format!("target.'{LINUX_TARGET_TABLE}'.rustflags=[\"-C\",\"{FUSE_LD_MOLD}\"]"),
        format!("env.COMPILER_PATH.value=\"{bin}\""),
        "env.COMPILER_PATH.force=true".to_owned(),
    ])
}

/// The `COMPILER_PATH` string a `bin_dir` becomes, or why it cannot be
/// one: non-UTF-8, containing the `:` list separator, or containing a
/// `'`/`"` quote, which would break the config TOML the path is written
/// into.
fn compiler_path_value(bin_dir: &Path) -> stow_types::error::Result<&str> {
    let bin = bin_dir.to_str().ok_or_else(|| {
        stow_types::stow_error!("mold install path {} is not UTF-8", bin_dir.display())
    })?;
    if bin.contains(':') {
        return Err(stow_types::stow_error!(
            "mold install path {bin} cannot be a COMPILER_PATH entry — `:` splits the list"
        ));
    }
    if bin.contains('"') || bin.contains('\'') {
        return Err(stow_types::stow_error!(
            "mold install path {bin} cannot embed in the cargo configuration — it contains a quote"
        ));
    }
    Ok(bin)
}

/// `stow setup`'s half of the contract: what the user's global cargo
/// configuration needs so every build links with mold — read the way a
/// global setup must read it, from `$CARGO_HOME/config.toml` plus the
/// environment, so the answer never depends on the directory setup ran
/// in. The project-level walk belongs to `stow` builds, which run inside
/// a project and resolve through [`resolve_link_from`] instead.
///
/// `None` means the config needs no linker selection written — not a
/// Linux host, or the configuration already selects mold *and can reach a
/// mold binary*, in which case nothing is installed and nothing written.
/// Every other Linux machine gets the managed install's `bin` dir back,
/// which the caller passes to [`write_linker_selection`]. A configuration
/// whose own selection exists but cannot resolve — the selection without
/// the binary — is provisioned too: the config gains the `COMPILER_PATH`
/// env entry that makes the managed install findable.
///
/// # Errors
///
/// Fails when the rustc host target cannot be detected or the mold install
/// fails — the error says which.
pub async fn prepare_global() -> stow_types::error::Result<Option<PathBuf>> {
    if !cfg!(target_os = "linux") {
        return Ok(None);
    }
    let host = detect_rustc_host_target(OsStr::new("rustc"))
        .await
        .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
    let (config, cfgs) = futures_util::future::join(
        CargoConfig::load_global(&process_env),
        rustc_target_cfgs(&host),
    )
    .await;
    let link = resolve_link_from(&config, &host, cfgs.as_ref(), &process_env);
    if link.selects_mold && link.unavailable_reason().await.is_none() {
        return Ok(None);
    }
    Ok(Some(ensure_mold_install().await?))
}

/// Merge stow's mold selection into `document`: the `cfg(target_os =
/// "linux")` table's rustflags gain `-C link-arg=-fuse-ld=mold` — the only
/// link option the cache keys on — while `env.COMPILER_PATH` gains the
/// managed install's `bin` dir, the environment search path where the
/// compiler driver finds `ld.mold`. The dir is env precisely so that it
/// never reaches a rustc flag and therefore never enters the compile key.
///
/// Rustflags the project already had stay; entries stow itself wrote —
/// `-fuse-ld=mold` and `-B` prefixes pointing at a `mold/bin` from an
/// earlier wiring — are replaced in place, so re-running `setup` rewrites
/// the same keys rather than appending duplicates.
///
/// # Errors
///
/// Fails when `bin_dir` is not usable inside `COMPILER_PATH` (non-UTF-8,
/// or containing the `:` list separator) or the existing `target` shape is
/// not a table cargo could have written.
pub fn write_linker_selection(
    document: &mut toml_edit::DocumentMut,
    bin_dir: &Path,
) -> stow_types::error::Result<()> {
    let bin = compiler_path_value(bin_dir)?;
    // `build.rustflags` the table being written would shadow, carried
    // into it so the user's flags still reach every Linux link — cargo
    // uses `build.rustflags` only when no matching `target.*` table
    // carries flags (cargo/src/cargo/util/context/target.rs). A
    // `build.rustflags` in a shape cargo could not have written is a hard
    // error: dropping it silently is the failure this rule exists to
    // prevent. Read before the `target` table is borrowed below.
    let carried = match document
        .get("build")
        .and_then(toml_edit::Item::as_table)
        .and_then(|build| build.get("rustflags"))
    {
        None => Vec::new(),
        Some(item) if item.is_array() || item.is_str() => rustflags_value(item),
        Some(_) => {
            return Err(stow_types::stow_error!(
                ".cargo/config.toml `build.rustflags` is not a string or array — \
                 it cannot be carried into the `target` rustflags stow writes"
            ));
        }
    };
    let target = document["target"].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let target = target.as_table_mut().ok_or_else(|| {
        stow_types::stow_error!(".cargo/config.toml `target` exists but is not a table")
    })?;
    let table =
        target[LINUX_TARGET_TABLE].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let table = table.as_table_mut().ok_or_else(|| {
        stow_types::stow_error!(
            ".cargo/config.toml `target.{LINUX_TARGET_TABLE}` exists but is not a table"
        )
    })?;
    let existing = match table.get("rustflags") {
        None => Vec::new(),
        Some(item) if item.is_array() || item.is_str() => rustflags_value(item),
        Some(_) => {
            return Err(stow_types::stow_error!(
                ".cargo/config.toml `target.{LINUX_TARGET_TABLE}.rustflags` is not a string or array"
            ));
        }
    };
    let mut flags = Vec::with_capacity(carried.len() + existing.len() + 2);
    flags.extend(carried);
    flags.extend(strip_stow_linker_flags(existing));
    flags.extend(["-C".to_owned(), FUSE_LD_MOLD.to_owned()]);
    let mut rustflags = toml_edit::Array::new();
    rustflags.extend(flags);
    table["rustflags"] = toml_edit::Item::Value(toml_edit::Value::Array(rustflags));

    let env = document["env"].or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
    let env = env.as_table_mut().ok_or_else(|| {
        stow_types::stow_error!(".cargo/config.toml `env` exists but is not a table")
    })?;
    let mut entry = toml_edit::Table::new();
    entry["value"] = toml_edit::Item::Value(toml_edit::Value::from(bin));
    entry["force"] = toml_edit::Item::Value(toml_edit::Value::from(true));
    env["COMPILER_PATH"] = toml_edit::Item::Table(entry);
    Ok(())
}

/// A rustflag entry `write_linker_selection` owns: the mold selection
/// itself, or a `-B` prefix into any `mold/bin` — the tail of every
/// managed install path, so a stale entry from a different tools dir is
/// also replaced.
fn is_stow_linker_flag(flag: &str) -> bool {
    flag == FUSE_LD_MOLD || (flag.starts_with("link-arg=-B") && flag.ends_with("/mold/bin"))
}

/// A target the Linux build gate covers: every Linux triple. Android
/// triples contain `linux` but their toolchain is the NDK's, and the cache
/// does not publish their mold variants — they are not stow's Linux link.
fn linux_target(target: &str) -> bool {
    target.contains("linux") && !target.contains("android")
}

/// What the cargo configuration for `target` actually resolves to: the
/// effective rustflags, the linker they name, and whether either selects
/// mold.
#[derive(Debug)]
struct LinkResolution {
    /// The linker rustc invokes for the link: a `-C linker=` codegen
    /// option wins over a configured `linker` key, per rustc's last-wins
    /// option precedence.
    linker: Option<String>,
    /// The effective rustflags — env sources ahead of the config chain.
    rustflags: Vec<String>,
    /// Whether either half selects mold.
    selects_mold: bool,
    /// The `COMPILER_PATH` the build would run under — a forced config
    /// `env` entry wins over the ambient value, a plain one loses to it —
    /// which is where `stow setup` puts the managed install's `bin`.
    compiler_path: Option<std::ffi::OsString>,
}

/// The environment a link resolution reads — `std::env::var_os` on a
/// real build, a fixture's map in tests, so a test never mutates the
/// process's shared environment.
type EnvLookup<'a> = &'a (dyn Fn(&str) -> Option<OsString> + Sync);

/// The process's environment — the [`EnvLookup`] real code reads.
fn process_env(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

/// Resolve `target`'s link configuration over an already-loaded config
/// chain: which `target.*` tables match (cfg tables only when `cfgs` was
/// answered — `None` keeps them all candidates), the effective rustflags
/// and linker they resolve to, and whether the selection picks mold.
fn resolve_link_from(
    config: &CargoConfig,
    target: &str,
    cfgs: Option<&HashSet<String>>,
    env: EnvLookup<'_>,
) -> LinkResolution {
    let tables = config.matching_target_tables(target, cfgs);
    let rustflags = effective_rustflags(config, &tables, env);
    let linker = rustflags_linker(&rustflags).or_else(|| effective_linker(target, &tables, env));
    let selects_mold = linker
        .as_deref()
        .is_some_and(|linker| linker.contains("mold"))
        || rustflags.iter().any(|flag| flag_mentions_mold(flag));
    LinkResolution {
        linker,
        rustflags,
        selects_mold,
        compiler_path: effective_compiler_path(config, env),
    }
}

/// The `COMPILER_PATH` a build at this config would run under, per
/// cargo's `env` precedence: `force` entries beat the ambient variable,
/// plain entries lose to it and apply only when it is unset.
fn effective_compiler_path(config: &CargoConfig, env: EnvLookup<'_>) -> Option<OsString> {
    let ambient = env("COMPILER_PATH");
    match config.env_setting("COMPILER_PATH") {
        Some((value, true)) => Some(value.into()),
        Some((value, false)) => ambient.or_else(|| Some(value.into())),
        None => ambient,
    }
}

/// What asking the machine "is this link's mold reachable" looks like:
/// a configured `linker` naming mold must itself resolve to an
/// executable, while `-fuse-ld=mold` asks the compiler driver to find an
/// `ld.mold`. The value is everything the probe reads — driver, `-B`
/// prefixes, `COMPILER_PATH` — so two resolutions with the same probe
/// answer the same question.
#[derive(Clone, Debug, PartialEq, Eq)]
enum MoldProbe {
    /// The configured linker resolves to an executable itself.
    Linker(String),
    /// A `-fuse-ld=mold` link probe through a compiler driver.
    Driver {
        driver: String,
        b_dirs: Vec<PathBuf>,
        compiler_path: Option<OsString>,
    },
}

impl LinkResolution {
    /// The probe this resolution's availability answer depends on.
    fn probe(&self) -> MoldProbe {
        match self.linker.as_deref() {
            Some(linker) if linker.contains("mold") => MoldProbe::Linker(linker.to_owned()),
            // With no mold-naming linker configured the link goes through
            // a compiler driver; probe `cc`, the platform's C driver.
            other => MoldProbe::Driver {
                driver: other.unwrap_or("cc").to_owned(),
                b_dirs: b_dirs(&self.rustflags),
                compiler_path: self.compiler_path.clone(),
            },
        }
    }

    /// Why mold cannot run for this link, or `None` when it can.
    async fn unavailable_reason(&self) -> Option<String> {
        probe_unavailable_reason(&self.probe()).await
    }
}

/// Runs `probe` against the machine and reports why mold cannot run for
/// it, or `None` when it can.
async fn probe_unavailable_reason(probe: &MoldProbe) -> Option<String> {
    match probe {
        MoldProbe::Linker(linker) => (!program_resolves(linker)).then(|| {
            format!("the configured linker `{linker}` does not resolve to an executable")
        }),
        MoldProbe::Driver {
            driver,
            b_dirs,
            compiler_path,
        } => (!ld_mold_resolves(driver, b_dirs, compiler_path.as_deref()).await).then(|| {
            format!(
                "`{driver}` finds no `ld.mold` for `-fuse-ld=mold` — run `stow setup` to install mold"
            )
        }),
    }
}

/// Whether `driver` finds an `ld.mold` — answered by asking it to link
/// with `-fuse-ld=mold` rather than by reimplementing each driver's own
/// search rules: collect2's, clang's and a cross gcc's lists differ (the
/// last never looks at `PATH`), and the link probe is the question the
/// real build will ask. `-nostdlib -shared` on an empty translation unit
/// exercises exactly the lookup and nothing else. The configured `-B`
/// prefixes and the effective `COMPILER_PATH` are passed through so the
/// probe sees the environment the build would.
async fn ld_mold_resolves(driver: &str, b_dirs: &[PathBuf], compiler_path: Option<&OsStr>) -> bool {
    let mut probe = async_process::Command::new(driver);
    for dir in b_dirs {
        probe.arg(format!("-B{}", dir.display()));
    }
    probe.args([
        "-fuse-ld=mold",
        "-nostdlib",
        "-shared",
        "-x",
        "c",
        "/dev/null",
        "-o",
        "/dev/null",
    ]);
    if let Some(path) = compiler_path {
        probe.env("COMPILER_PATH", path);
    }
    probe
        .output()
        .await
        .is_ok_and(|output| output.status.success())
}

/// Whether `name` resolves to an executable: a name containing a slash is
/// checked as a path, a bare name is looked up on `PATH`.
fn program_resolves(name: &str) -> bool {
    if name.contains('/') {
        return is_executable(Path::new(name));
    }
    path_contains(name)
}

/// Whether an executable named `name` exists anywhere on `PATH`.
fn path_contains(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| is_executable(&dir.join(name)))
}

/// Whether `target`'s effective linker configuration selects mold: the
/// linker cargo selects for the triple, or any `-C` link option in the
/// effective rustflags. The gate reads the fuller [`resolve_link_from`]
/// answer itself; this stays the question the tests ask.
#[cfg(test)]
async fn uses_mold(target: &str, cargo_dir: &Path, env: EnvLookup<'_>) -> bool {
    let (config, cfgs) =
        futures_util::future::join(CargoConfig::load(cargo_dir, env), rustc_target_cfgs(target))
            .await;
    resolve_link_from(&config, target, cfgs.as_ref(), env).selects_mold
}

/// A rustflag selects mold when a `-C` link option's value names it —
/// `-C link-arg=-fuse-ld=mold`, `-C linker=mold`, a `-C link-args` bundle
/// carrying `-fuse-ld=mold`, and so on.
fn flag_mentions_mold(flag: &str) -> bool {
    let option = flag
        .strip_prefix("--codegen=")
        .or_else(|| flag.strip_prefix("-C"))
        .unwrap_or(flag);
    let Some((key, value)) = option.split_once('=') else {
        return false;
    };
    matches!(key, "linker" | "linker-flavor" | "link-arg" | "link-args") && value.contains("mold")
}

/// The codegen options inside a rustflag list — every `-C`/`--codegen`
/// value, whether written `-C value`, `-Cvalue`, `--codegen value` or
/// `--codegen=value`.
fn codegen_options(rustflags: &[String]) -> Vec<&str> {
    let mut options = Vec::new();
    let mut next = false;
    for flag in rustflags {
        if next {
            options.push(flag.as_str());
            next = false;
            continue;
        }
        match flag.as_str() {
            "-C" | "--codegen" => next = true,
            _ => {
                if let Some(option) = flag
                    .strip_prefix("--codegen=")
                    .or_else(|| flag.strip_prefix("-C"))
                {
                    options.push(option);
                }
            }
        }
    }
    options
}

/// The last `-C linker=` among `rustflags` — the codegen option that
/// overrides a configured `linker` key.
fn rustflags_linker(rustflags: &[String]) -> Option<String> {
    codegen_options(rustflags)
        .into_iter()
        .filter_map(|option| option.strip_prefix("linker="))
        .next_back()
        .map(str::to_owned)
}

/// Every `-B` directory among `rustflags`' `link-arg`/`link-args` values,
/// in the order they reach the driver.
fn b_dirs(rustflags: &[String]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for option in codegen_options(rustflags) {
        let Some((key, value)) = option.split_once('=') else {
            continue;
        };
        let values: Vec<&str> = match key {
            "link-arg" => vec![value],
            "link-args" => value.split_whitespace().collect(),
            _ => continue,
        };
        for value in values {
            if let Some(dir) = value.strip_prefix("-B")
                && !dir.is_empty()
            {
                dirs.push(PathBuf::from(dir));
            }
        }
    }
    dirs
}

/// The rustflags cargo resolves for `target`, honoring cargo's precedence:
/// `CARGO_ENCODED_RUSTFLAGS`, then `RUSTFLAGS`, then — only when neither env
/// source exists — the config tables via [`CargoConfig::rustflags`].
fn effective_rustflags(
    config: &CargoConfig,
    tables: &[(String, &toml_edit::Table)],
    env: EnvLookup<'_>,
) -> Vec<String> {
    if let Some(encoded) = env("CARGO_ENCODED_RUSTFLAGS") {
        return encoded
            .to_string_lossy()
            .split('\x1f')
            .filter(|flag| !flag.is_empty())
            .map(str::to_owned)
            .collect();
    }
    if let Some(flags) = env("RUSTFLAGS").and_then(|flags| flags.into_string().ok()) {
        return shell_words::split(&flags).unwrap_or_default();
    }
    config.rustflags(tables)
}

/// The linker cargo selects for `target`: `CARGO_TARGET_<TRIPLE>_LINKER`,
/// then `target.<triple>.linker`, then a matching `target.<cfg>.linker`.
fn effective_linker(
    target: &str,
    tables: &[(String, &toml_edit::Table)],
    env: EnvLookup<'_>,
) -> Option<String> {
    let env_key = format!(
        "CARGO_TARGET_{}_LINKER",
        target.to_uppercase().replace('-', "_")
    );
    if let Some(linker) = env(&env_key) {
        return Some(linker.to_string_lossy().into_owned());
    }
    let mut cfg_linker = None;
    for (key, table) in tables {
        let Some(linker) = table.get("linker").and_then(toml_edit::Item::as_str) else {
            continue;
        };
        if key == target {
            return Some(linker.to_owned());
        }
        cfg_linker = Some(linker.to_owned());
    }
    cfg_linker
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_file()
        && path
            .metadata()
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// The cargo config files that apply to a cargo invocation at `cargo_dir`,
/// ordered lowest → highest precedence: `$CARGO_HOME/config.toml` first,
/// then every `.cargo/config` and `.cargo/config.toml` from the filesystem
/// root down to `cargo_dir` (the same walk cargo performs).
fn cargo_config_paths(cargo_dir: &Path, env: EnvLookup<'_>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(cargo_home) = crate::config::cargo_home_with(env) {
        paths.push(cargo_home.join("config.toml"));
    }
    let ancestors: Vec<PathBuf> = cargo_dir.ancestors().map(Path::to_path_buf).collect();
    for dir in ancestors.into_iter().rev() {
        paths.push(dir.join(".cargo").join("config"));
        paths.push(dir.join(".cargo").join("config.toml"));
    }
    paths
}

/// The parsed cargo config chain, kept per-file because cargo resolves each
/// key from its highest-precedence definer rather than merging whole files.
struct CargoConfig {
    files: Vec<toml_edit::DocumentMut>,
}

impl CargoConfig {
    /// Only the global `$CARGO_HOME/config.toml` — the read a global
    /// `stow setup` makes, where project-level files must not answer.
    async fn load_global(env: EnvLookup<'_>) -> Self {
        let config = match crate::config::cargo_home_with(env) {
            Some(cargo_home) => {
                let path = cargo_home.join("config.toml");
                async_fs::read_to_string(&path)
                    .await
                    .ok()
                    .and_then(|contents| contents.parse::<toml_edit::DocumentMut>().ok())
            }
            None => None,
        };
        Self {
            files: config.into_iter().collect(),
        }
    }

    async fn load(cargo_dir: &Path, env: EnvLookup<'_>) -> Self {
        let paths = cargo_config_paths(cargo_dir, env);
        // Most of these paths do not exist, and none of the reads depends on
        // another, so the whole chain is read in one round rather than one
        // `await` per directory up the tree. `join_all` keeps the results in
        // the order the paths were built, which is the precedence order.
        let contents =
            futures_util::future::join_all(paths.iter().map(async_fs::read_to_string)).await;
        let files = paths
            .iter()
            .zip(contents)
            .filter_map(|(path, contents)| {
                let contents = contents.ok()?;
                match contents.parse::<toml_edit::DocumentMut>() {
                    Ok(document) => Some(document),
                    Err(error) => {
                        tracing::debug!(path = %path.display(), %error, "ignoring unparseable cargo config file");
                        None
                    }
                }
            })
            .collect();
        Self { files }
    }

    /// The rustflags cargo applies to a build whose target matches
    /// `tables`: the `target.<triple>` and every matching `target.<cfg>`
    /// table's `rustflags` joined together, with `build.rustflags` used
    /// only when no matching target table carries flags — cargo's own
    /// precedence (`get_target_cfgs` → `target_cfgs` in
    /// cargo/src/cargo/util/context/target.rs, plus the documented
    /// `build.rustflags` fallback in the cargo reference).
    fn rustflags(&self, tables: &[(String, &toml_edit::Table)]) -> Vec<String> {
        let target_flags = tables
            .iter()
            .flat_map(|(_, table)| table.get("rustflags").into_iter().flat_map(rustflags_value))
            .collect::<Vec<_>>();
        if !target_flags.is_empty() {
            return target_flags;
        }
        self.lookup(&["build", "rustflags"])
            .into_iter()
            .flat_map(rustflags_value)
            .collect()
    }

    /// The `env.<key>` entry the chain resolves to — `(value, force)` —
    /// accepting both the `[env.KEY]` table shape and a bare
    /// `env.KEY = "…"` string.
    fn env_setting(&self, key: &str) -> Option<(String, bool)> {
        let entry = self.lookup(&["env", key])?;
        if let Some(value) = entry.as_str() {
            return Some((value.to_owned(), false));
        }
        let table = entry.as_table_like()?;
        let value = table.get("value")?.as_str()?.to_owned();
        let force = table
            .get("force")
            .and_then(toml_edit::Item::as_bool)
            .unwrap_or(false);
        Some((value, force))
    }

    /// The last definition of `path` across the precedence-ordered files —
    /// the one cargo would resolve.
    fn lookup(&self, path: &[&str]) -> Option<&toml_edit::Item> {
        self.files.iter().rev().find_map(|file| {
            let mut value = file.as_item();
            for key in path {
                value = value.get(*key)?;
            }
            Some(value)
        })
    }

    /// Every `target.*` table matching `target` across the chain —
    /// `(table key, table)` pairs in precedence order, so later entries are
    /// the higher-precedence definers.
    fn matching_target_tables<'a>(
        &'a self,
        target: &str,
        cfgs: Option<&HashSet<String>>,
    ) -> Vec<(String, &'a toml_edit::Table)> {
        // Keyed by table name so the nearest definer of each table wins;
        // position records first appearance so entries stay in
        // precedence order.
        let mut order: Vec<String> = Vec::new();
        let mut by_key: std::collections::HashMap<String, &toml_edit::Table> =
            std::collections::HashMap::new();
        for file in &self.files {
            let Some(target_tables) = file.get("target").and_then(toml_edit::Item::as_table) else {
                continue;
            };
            for (key, value) in target_tables {
                let Some(table) = value.as_table() else {
                    continue;
                };
                let matches = if key == target {
                    true
                } else if let Some(predicate) = key
                    .strip_prefix("cfg(")
                    .and_then(|key| key.strip_suffix(')'))
                {
                    cfg_matches(predicate, cfgs)
                } else {
                    false
                };
                if matches {
                    if !by_key.contains_key(key) {
                        order.push(key.to_owned());
                    }
                    by_key.insert(key.to_owned(), table);
                }
            }
        }
        order
            .into_iter()
            .filter_map(|key| by_key.get(&key).map(|table| (key, *table)))
            .collect()
    }
}

/// `rustc --print cfg --target <triple>` — the truth about which `cfg()`
/// predicates match. `None` when rustc cannot answer, in which case every
/// cfg table stays a candidate (favoring a read that errs toward mold
/// being selected over one that refuses a working build).
async fn rustc_target_cfgs(target: &str) -> Option<HashSet<String>> {
    let output = async_process::Command::new("rustc")
        .args(["--print", "cfg", "--target", target])
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect(),
    )
}

/// A `rustflags` config value as individual flags: an array stays an array,
/// a string splits on whitespace like cargo does.
pub fn rustflags_value(item: &toml_edit::Item) -> Vec<String> {
    if let Some(array) = item.as_array() {
        return array
            .iter()
            .filter_map(|flag| flag.as_str())
            .map(str::to_owned)
            .collect();
    }
    item.as_str()
        .map(|flags| flags.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Remove the entries [`write_linker_selection`] owns from a rustflag
/// list: the mold selection itself, `-B` prefixes into any `mold/bin`,
/// and an orphaned `-C`/`--codegen` introducer each removal leaves behind.
pub fn strip_stow_linker_flags(existing: Vec<String>) -> Vec<String> {
    let mut flags = Vec::with_capacity(existing.len());
    let mut pending = existing.into_iter().peekable();
    while let Some(flag) = pending.next() {
        if matches!(flag.as_str(), "-C" | "--codegen")
            && pending.peek().is_some_and(|next| is_stow_linker_flag(next))
        {
            pending.next();
            continue;
        }
        if !is_stow_linker_flag(&flag) {
            flags.push(flag);
        }
    }
    flags
}

/// The release-asset arch name and pinned sha256 for a
/// `std::env::consts::ARCH`, or `None` where mold publishes no build.
fn mold_release(arch: &str) -> Option<(&'static str, &'static str)> {
    Some(match arch {
        "x86_64" => (
            "x86_64",
            "6ff270c9bf07d2bec5c98aa324eb7c4daf6a1a4d815c05ff1708049616047855",
        ),
        "aarch64" => (
            "aarch64",
            "16b025652d3d7456689e6025a77e1903bb2a15e7630877c26cc133f5df95b9c6",
        ),
        "arm" => (
            "arm",
            "2d72faa7ba5d88390cb5cfdd96c288700b85e1df09f6fea9fa1f80c132dc5811",
        ),
        "powerpc64" => (
            "ppc64le",
            "e58df6d3cef5d14b14dc6a77d937b35399eeafb5d6bf47e02df54255369fc893",
        ),
        "riscv64" => (
            "riscv64",
            "68ad8f9db63ae19c0e95e8b9dd57080b4194704d04b7e5a03f6f5bd4ce19b06e",
        ),
        "s390x" => (
            "s390x",
            "06f7c57725d3a5b19729c2cf579c4ebb86ca8593dd130d667e27586b0436793c",
        ),
        "loongarch64" => (
            "loongarch64",
            "40acb04a6405660fee39ba2a85bfcd716d72e16fd631a1c320adc96aa843c68f",
        ),
        _ => return None,
    })
}

/// The managed mold install's `bin` dir under the stow tools dir —
/// downloading, checksum-verifying and extracting the pinned release
/// tarball as an ordinary user. An install already on disk is returned
/// as-is.
///
/// # Errors
///
/// Fails when no mold release exists for this architecture, the download
/// or extraction fails, the checksum mismatches, or the installed binary
/// cannot run — each error saying which.
async fn ensure_mold_install() -> stow_types::error::Result<PathBuf> {
    let bin_dir = crate::config::tools_dir()?.join("mold").join("bin");
    if is_executable(&bin_dir.join("mold")) && is_executable(&bin_dir.join("ld.mold")) {
        return Ok(bin_dir);
    }
    let (arch, sha256) = mold_release(std::env::consts::ARCH).ok_or_else(|| {
        stow_types::stow_error!(
            "mold publishes no prebuilt binary for the {} architecture",
            std::env::consts::ARCH
        )
    })?;
    let url = format!(
        "https://github.com/rui314/mold/releases/download/v{MOLD_VERSION}/mold-{MOLD_VERSION}-{arch}-linux.tar.gz"
    );
    let bytes = download(&url).await?;
    let actual = hex::encode(sha2::Sha256::digest(&bytes));
    if actual != sha256 {
        return Err(stow_types::stow_error!(
            "mold {MOLD_VERSION} archive checksum mismatch: expected sha256:{sha256}, got sha256:{actual}"
        ));
    }
    unpack_mold(&bytes, &bin_dir)?;
    // Confirm the installed binary runs on this system rather than
    // reporting a setup that would fail on its first use.
    match async_process::Command::new(bin_dir.join("mold"))
        .arg("--version")
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            tracing::info!(
                path = %bin_dir.display(),
                version = %String::from_utf8_lossy(&output.stdout).trim(),
                "installed mold"
            );
        }
        Ok(output) => {
            return Err(stow_types::stow_error!(
                "the installed mold {MOLD_VERSION} binary cannot run here: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Err(error) => {
            return Err(stow_types::stow_error!(
                "run installed mold --version: {error}"
            ));
        }
    }
    Ok(bin_dir)
}

/// What one download attempt produced: the archive bytes, or a failure
/// classified the way the shared retry policy classifies it — retried
/// with any `Retry-After` hint it carried, or returned to the caller.
enum DownloadOutcome {
    Bytes(Vec<u8>),
    Retryable {
        error: stow_types::error::Error,
        retry_after: Option<std::time::Duration>,
    },
    Fatal(stow_types::error::Error),
}

/// Download `url`, following redirects, into memory — the pinned sha256 is
/// checked before a byte reaches disk. A transient failure — a request
/// that never completed or a [`stow_types::transient::is_transient_status`]
/// answer — is retried under the shared [`stow_types::transient::Backoff`]
/// budget: the release fetch crosses two hosts (github.com's 302 to the
/// release-assets CDN), and one transport error failing a user's `stow
/// setup` is the failure this retry exists to prevent.
async fn download(url: &str) -> stow_types::error::Result<Vec<u8>> {
    let mut backoff = stow_types::transient::Backoff::new();
    loop {
        let wait = match download_once(url).await {
            DownloadOutcome::Bytes(bytes) => return Ok(bytes),
            DownloadOutcome::Retryable { error, retry_after } => {
                let Some(wait) = backoff.next_wait(retry_after) else {
                    return Err(error);
                };
                tracing::warn!(url, %error, "mold download failed; retrying");
                wait
            }
            DownloadOutcome::Fatal(error) => return Err(error),
        };
        tokio::time::sleep(wait).await;
    }
}

/// One attempt at [`download`]: build the request, send it, and read the
/// whole body — a connection lost mid-body leaves nothing usable, so a
/// transport error at any stage retries the whole GET. The GET is a plain
/// read with no side effects, so replaying it is safe.
async fn download_once(url: &str) -> DownloadOutcome {
    use zenwave::Client as _;
    let mut client = zenwave::client()
        .timeout(std::time::Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .follow_redirect();
    let request = match client.get(url) {
        Ok(request) => request,
        Err(error) => {
            return DownloadOutcome::Fatal(stow_types::stow_error!(
                "build mold download request: {error}"
            ));
        }
    };
    let response = match request.await {
        Ok(response) => response,
        Err(error) => {
            return DownloadOutcome::Retryable {
                error: stow_types::stow_error!("download {url}: {error}"),
                retry_after: None,
            };
        }
    };
    let status = response.status();
    if !status.is_success() {
        let retry_after = stow_types::transient::retry_after_hint(response.headers());
        let error = stow_types::stow_error!("download {url}: HTTP {status}");
        return if stow_types::transient::is_transient_status(status.as_u16()) {
            DownloadOutcome::Retryable { error, retry_after }
        } else {
            DownloadOutcome::Fatal(error)
        };
    }
    match response.into_body().into_bytes().await {
        Ok(bytes) => DownloadOutcome::Bytes(bytes.to_vec()),
        Err(error) => DownloadOutcome::Retryable {
            error: stow_types::stow_error!("read {url} body: {error}"),
            retry_after: None,
        },
    }
}

/// Extract `bin/mold` and `bin/ld.mold` from a release tarball into
/// `bin_dir` — each unpacked under a per-process staging dir and renamed
/// into place, so a half-extracted binary never sits where a build looks
/// for it and two concurrent `stow setup` runs cannot race one shared
/// staging name. `ld.mold` is the symlink the compiler driver resolves
/// for `-fuse-ld=mold`; anything else in the archive stays unused.
fn unpack_mold(archive: &[u8], bin_dir: &Path) -> stow_types::error::Result<()> {
    std::fs::create_dir_all(bin_dir).wrap_err_with(|| format!("create {}", bin_dir.display()))?;
    let staging = tempfile::tempdir_in(bin_dir)
        .wrap_err_with(|| format!("stage mold under {}", bin_dir.display()))?;
    let mut entries = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    // The archive is the pinned download — its modes are the install's
    // (mold ships `bin/mold` executable).
    entries.set_preserve_permissions(true);
    let mut seen = HashSet::new();
    for entry in entries.entries().wrap_err("read mold archive")? {
        let mut entry = entry.wrap_err("read mold archive entry")?;
        let path = entry
            .path()
            .wrap_err("read mold archive entry name")?
            .into_owned();
        let (Some(name), Some(parent)) = (
            path.file_name().and_then(OsStr::to_str),
            path.parent()
                .and_then(Path::file_name)
                .and_then(OsStr::to_str),
        ) else {
            continue;
        };
        if parent != "bin" || !matches!(name, "mold" | "ld.mold") {
            continue;
        }
        let staged = staging.path().join(name);
        entry
            .unpack(&staged)
            .wrap_err_with(|| format!("extract {name} to {}", staged.display()))?;
        std::fs::rename(&staged, bin_dir.join(name))
            .wrap_err_with(|| format!("rename {name} into {}", bin_dir.display()))?;
        seen.insert(name.to_owned());
    }
    if seen.len() != 2 {
        return Err(stow_types::stow_error!(
            "mold {MOLD_VERSION} archive did not contain both bin/mold and bin/ld.mold"
        ));
    }
    Ok(())
}

/// Evaluate a `cfg(...)` predicate body against rustc's printed cfg set.
/// Unknown cfgs (`None`) keep the table a candidate.
fn cfg_matches(predicate: &str, cfgs: Option<&HashSet<String>>) -> bool {
    cfgs.is_none_or(|cfgs| eval_cfg(predicate, cfgs))
}

fn eval_cfg(text: &str, cfgs: &HashSet<String>) -> bool {
    let text = text.trim();
    if let Some(inner) = strip_cfg_fn(text, "all") {
        return split_cfg_args(inner).all(|part| eval_cfg(part, cfgs));
    }
    if let Some(inner) = strip_cfg_fn(text, "any") {
        return split_cfg_args(inner).any(|part| eval_cfg(part, cfgs));
    }
    if let Some(inner) = strip_cfg_fn(text, "not") {
        return !eval_cfg(inner, cfgs);
    }
    match text.split_once('=') {
        Some((key, value)) => {
            let leaf = format!("{}={}", key.trim(), value.trim());
            cfgs.contains(&leaf)
        }
        None => cfgs.contains(text),
    }
}

/// The argument list of `name(...)` — `text` with the function stripped —
/// only when `text` is exactly that call.
fn strip_cfg_fn<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.strip_prefix(name)
        .and_then(|rest| rest.trim_start().strip_prefix('('))
        .and_then(|rest| rest.strip_suffix(')'))
}

/// Split `a, b, c` at top level — commas inside nested parentheses are not
/// separators.
fn split_cfg_args(inner: &str) -> impl Iterator<Item = &str> {
    let mut depth = 0usize;
    let mut parts = Vec::new();
    let mut start = 0;
    for (index, ch) in inner.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&inner[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINUX_TARGET: &str = "x86_64-unknown-linux-gnu";

    /// A project directory whose cargo config chain is exactly `config`:
    /// the fixture's own environment answers `CARGO_HOME` with an empty
    /// directory and nothing else — injected into the walk under test, so
    /// no test ever touches the process environment its siblings share.
    struct IsolatedProject {
        _tempdir: tempfile::TempDir,
        project: PathBuf,
        env: std::collections::HashMap<String, OsString>,
    }

    impl IsolatedProject {
        /// The injected environment: `CARGO_HOME` alone.
        fn env(&self) -> impl Fn(&str) -> Option<OsString> + '_ {
            |key| self.env.get(key).cloned()
        }
    }

    fn isolated_project(config: &str) -> IsolatedProject {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let project = tempdir.path().join("project");
        std::fs::create_dir_all(project.join(".cargo")).expect("project .cargo");
        std::fs::write(project.join(".cargo").join("config.toml"), config).expect("write config");
        let cargo_home = tempdir.path().join("cargo-home");
        std::fs::create_dir_all(&cargo_home).expect("cargo home");
        let env = std::collections::HashMap::from([(
            "CARGO_HOME".to_owned(),
            cargo_home.into_os_string(),
        )]);
        IsolatedProject {
            _tempdir: tempdir,
            project,
            env,
        }
    }

    fn detects_mold(config: &str) -> bool {
        let fixture = isolated_project(config);
        let env = fixture.env();
        smol::block_on(uses_mold(LINUX_TARGET, &fixture.project, &env))
    }

    fn written_rustflags(config: &str, bin_dir: &str) -> Vec<String> {
        let mut document = config
            .parse::<toml_edit::DocumentMut>()
            .expect("parse config");
        write_linker_selection(&mut document, Path::new(bin_dir)).expect("write selection");
        document["target"]["cfg(target_os = \"linux\")"]["rustflags"]
            .as_array()
            .expect("rustflags array")
            .iter()
            .map(|value| value.as_str().expect("string flag").to_owned())
            .collect()
    }

    #[test]
    fn target_rustflags_selecting_mold_are_found_in_the_config_chain() {
        assert!(detects_mold(
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n"
        ));
    }

    #[test]
    fn target_rustflags_selecting_another_linker_are_not_read_as_mold() {
        assert!(!detects_mold(
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"link-arg=-fuse-ld=lld\"]\n"
        ));
    }

    #[test]
    fn a_cfg_target_table_selecting_mold_is_matched_against_rustc_cfgs() {
        assert!(detects_mold(
            "[target.'cfg(target_os = \"linux\")']\nlinker = \"mold\"\n"
        ));
    }

    #[test]
    fn a_cfg_target_table_for_another_os_does_not_apply() {
        assert!(!detects_mold(
            "[target.'cfg(target_os = \"macos\")']\nlinker = \"mold\"\n"
        ));
    }

    #[test]
    fn an_empty_config_chain_selects_nothing() {
        assert!(!detects_mold("[build]\n"));
    }

    #[test]
    fn flag_mentions_mold_covers_the_ways_users_select_it() {
        for flag in [
            "link-arg=-fuse-ld=mold",
            "-Clink-arg=-fuse-ld=mold",
            "--codegen=link-arg=-fuse-ld=mold",
            "link-args=-Wl,-plugin -fuse-ld=mold",
            "linker=/usr/local/bin/mold",
            "linker=mold",
        ] {
            assert!(flag_mentions_mold(flag), "{flag} should select mold");
        }
    }

    #[test]
    fn non_mold_flags_do_not_read_as_mold() {
        for flag in [
            "link-arg=-fuse-ld=lld",
            "link-arg=-fuse-ld=gold",
            "linker=lld",
            "opt-level=3",
            "-Ctarget-cpu=x86-64-v3",
            "remap-path-prefix=/ci=/local",
        ] {
            assert!(!flag_mentions_mold(flag), "{flag} is not mold");
        }
    }

    #[test]
    fn written_selection_keeps_existing_rustflags() {
        let flags = written_rustflags(
            "[target.'cfg(target_os = \"linux\")']\nrustflags = [\"-C\", \"target-cpu=native\"]\n",
            "/tools/mold/bin",
        );
        assert_eq!(
            flags,
            ["-C", "target-cpu=native", "-C", "link-arg=-fuse-ld=mold"]
        );
    }

    #[test]
    fn written_selection_uses_environment_not_flags_for_reachability() {
        let mut document = "[build]\n"
            .parse::<toml_edit::DocumentMut>()
            .expect("parse config");
        write_linker_selection(&mut document, Path::new("/tools/mold/bin"))
            .expect("write selection");
        let entry = document["env"]["COMPILER_PATH"]
            .as_table_like()
            .expect("env table");
        assert_eq!(
            entry.get("value").and_then(toml_edit::Item::as_str),
            Some("/tools/mold/bin")
        );
        assert_eq!(
            entry.get("force").and_then(toml_edit::Item::as_bool),
            Some(true)
        );
    }

    #[test]
    fn rewriting_selection_replaces_stow_entries_without_orphans() {
        let flags = written_rustflags(
            "[target.'cfg(target_os = \"linux\")']\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\", \"-C\", \"link-arg=-B/old/tools/mold/bin\", \"-C\", \"opt-level=2\"]\n",
            "/new/tools/mold/bin",
        );
        assert_eq!(flags, ["-C", "opt-level=2", "-C", "link-arg=-fuse-ld=mold"]);
    }

    /// The rustflags a config produces for `target`, resolved the way the
    /// model resolves them — the pieces under test are `CargoConfig::
    /// matching_target_tables` and `CargoConfig::rustflags`, which answer
    /// from the parsed documents alone and never consult an environment.
    fn config_rustflags(config: &str, target: &str, cfgs: Option<&HashSet<String>>) -> Vec<String> {
        let chain = CargoConfig {
            files: vec![
                config
                    .parse::<toml_edit::DocumentMut>()
                    .expect("parse config"),
            ],
        };
        let tables = chain.matching_target_tables(target, cfgs);
        chain.rustflags(&tables)
    }

    /// Cargo joins a `target.<triple>` table's rustflags with every
    /// matching `target.<cfg>` table's, and `build.rustflags` is used only
    /// when no matching table carries flags — the precedence cargo itself
    /// implements in `target_cfgs` (cargo/src/cargo/util/context/
    /// target.rs).
    #[test]
    fn matching_target_tables_join_and_build_rustflags_drops_out() {
        let cfgs: HashSet<String> = std::iter::once("target_os=\"linux\"".to_owned()).collect();
        let flags = config_rustflags(
            "[build]\nrustflags = [\"-C\", \"debuginfo=0\"]\n\
             [target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"target-cpu=native\"]\n\
             [target.'cfg(target_os = \"linux\")']\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n",
            LINUX_TARGET,
            Some(&cfgs),
        );
        assert_eq!(
            flags,
            ["-C", "target-cpu=native", "-C", "link-arg=-fuse-ld=mold"],
            "matching triple + cfg tables join; build.rustflags must not appear"
        );
    }

    /// The other direction: with no matching `target.*` table carrying
    /// flags, `build.rustflags` is the answer.
    #[test]
    fn build_rustflags_applies_when_no_target_table_matches() {
        let cfgs: HashSet<String> = std::iter::once("target_os=\"macos\"".to_owned()).collect();
        let flags = config_rustflags(
            "[build]\nrustflags = [\"-C\", \"debuginfo=0\"]\n\
             [target.'cfg(target_os = \"linux\")']\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n",
            "aarch64-apple-darwin",
            Some(&cfgs),
        );
        assert_eq!(flags, ["-C", "debuginfo=0"]);
    }

    /// Writing stow's selection into a `target.*` table shadows
    /// `build.rustflags` for every matching build — the existing value
    /// moves into the written table rather than disappearing.
    #[test]
    fn written_selection_carries_existing_build_rustflags() {
        let flags = written_rustflags(
            "[build]\nrustflags = [\"-C\", \"debuginfo=0\"]\n",
            "/tools/mold/bin",
        );
        assert_eq!(flags, ["-C", "debuginfo=0", "-C", "link-arg=-fuse-ld=mold"]);
    }

    /// A `build.rustflags` in a shape cargo could not have written fails
    /// loudly — the alternative is the user's flags silently gone.
    #[test]
    fn written_selection_refuses_an_unreadable_build_rustflags() {
        let mut document = "[build]\nrustflags = 42\n"
            .parse::<toml_edit::DocumentMut>()
            .expect("parse config");
        let error = write_linker_selection(&mut document, Path::new("/tools/mold/bin"))
            .expect_err("must refuse");
        assert!(
            format!("{error}").contains("build.rustflags"),
            "unexpected error: {error}"
        );
    }

    /// `stow setup` answers only from the global configuration: a project
    /// `.cargo/config.toml` in an ancestor of the working directory must
    /// not leak into `prepare_global`'s read.
    #[test]
    fn global_load_ignores_project_config_files() {
        let fixture = isolated_project(
            "[target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n",
        );
        let env = fixture.env();
        let global = smol::block_on(CargoConfig::load_global(&env));
        let cfgs: HashSet<String> = std::iter::once("target_os=\"linux\"".to_owned()).collect();
        assert!(
            global
                .matching_target_tables(LINUX_TARGET, Some(&cfgs))
                .is_empty(),
            "the project config answered for a global setup"
        );
        assert!(
            global.rustflags(&[]).is_empty(),
            "project rustflags leaked into the global read"
        );
    }

    #[test]
    fn env_settings_resolve_both_shapes_and_force() {
        let fixture =
            isolated_project("[env.A]\nvalue = \"table\"\nforce = true\n\n[env]\nB = \"string\"\n");
        let env = fixture.env();
        let config = smol::block_on(CargoConfig::load(&fixture.project, &env));
        assert_eq!(config.env_setting("A"), Some(("table".to_owned(), true)));
        assert_eq!(config.env_setting("B"), Some(("string".to_owned(), false)));
        assert_eq!(config.env_setting("MISSING"), None);
    }

    #[test]
    fn codegen_options_reads_joined_and_split_forms() {
        let flags = [
            "-C".to_owned(),
            "linker=mold".to_owned(),
            "-Ctarget-cpu=native".to_owned(),
            "--codegen=link-arg=-B/x".to_owned(),
            "--codegen".to_owned(),
            "link-args=-B/y -B/z".to_owned(),
            "opt-level=3".to_owned(),
        ];
        assert_eq!(
            codegen_options(&flags),
            [
                "linker=mold",
                "target-cpu=native",
                "link-arg=-B/x",
                "link-args=-B/y -B/z"
            ]
        );
        assert_eq!(rustflags_linker(&flags).as_deref(), Some("mold"));
        assert_eq!(
            b_dirs(&flags),
            [
                PathBuf::from("/x"),
                PathBuf::from("/y"),
                PathBuf::from("/z")
            ]
        );
    }

    #[test]
    fn a_rustflags_linker_overrides_the_configured_one() {
        assert_eq!(
            rustflags_linker(&[
                "-C".to_owned(),
                "linker=first".to_owned(),
                "-C".to_owned(),
                "linker=second".to_owned(),
            ])
            .as_deref(),
            Some("second")
        );
    }

    #[test]
    fn eval_cfg_handles_predicates() {
        let cfgs: HashSet<String> = ["target_os=\"linux\"", "target_arch=\"x86_64\"", "unix"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(eval_cfg("target_os=\"linux\"", &cfgs));
        assert!(eval_cfg("unix", &cfgs));
        assert!(!eval_cfg("target_os=\"macos\"", &cfgs));
        assert!(eval_cfg("not(target_os=\"macos\")", &cfgs));
        assert!(eval_cfg(
            "all(target_os=\"linux\", target_arch=\"x86_64\")",
            &cfgs
        ));
        assert!(!eval_cfg(
            "all(target_os=\"linux\", target_arch=\"aarch64\")",
            &cfgs
        ));
        assert!(eval_cfg(
            "any(target_os=\"macos\", target_arch=\"x86_64\")",
            &cfgs
        ));
        assert!(eval_cfg(
            "all(unix, any(target_os=\"linux\", target_os=\"macos\"))",
            &cfgs
        ));
    }

    #[test]
    fn cfg_matches_defaults_to_candidate_when_cfgs_unknown() {
        assert!(cfg_matches("target_os=\"anything\"", None));
        let cfgs: HashSet<String> = HashSet::new();
        assert!(!cfg_matches("unix", Some(&cfgs)));
    }

    #[test]
    fn split_cfg_args_splits_at_top_level_commas() {
        let parts: Vec<&str> =
            split_cfg_args("target_os=\"linux\", any(unix, target_family=\"gnu\")").collect();
        assert_eq!(
            parts,
            vec!["target_os=\"linux\"", "any(unix, target_family=\"gnu\")"]
        );
    }

    /// A stub release server: `refusal` decides the first connection's
    /// fate — `None` drops it unanswered (a transport failure),
    /// `Some(status)` answers that status; every later connection gets a
    /// `200 OK` carrying `body`. Returns the URL and a count of how many
    /// requests the server has seen.
    fn serve_fail_then_ok(
        refusal: Option<&'static str>,
        body: &[u8],
    ) -> (String, std::sync::Arc<std::sync::Mutex<usize>>) {
        use std::io::{BufRead as _, BufReader, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub server");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let requests = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let seen = std::sync::Arc::clone(&requests);
        let refused = refusal.map(|status| {
            format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        });
        let ok = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let body = body.to_vec();
        std::thread::spawn(move || {
            for (index, accepted) in listener.incoming().enumerate() {
                let Ok(mut stream) = accepted else {
                    return;
                };
                *seen.lock().expect("request count") = index + 1;
                let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).expect("read request") == 0 || line == "\r\n" {
                        break;
                    }
                }
                if index == 0 {
                    // `None` leaves the stream to drop unanswered — the
                    // client sees a transport failure, not a response.
                    let Some(ref answer) = refused else {
                        continue;
                    };
                    stream.write_all(answer.as_bytes()).expect("write refusal");
                } else {
                    stream.write_all(ok.as_bytes()).expect("write head");
                    stream.write_all(&body).expect("write body");
                }
                stream.flush().expect("flush");
            }
        });
        (url, requests)
    }

    /// The release fetch crossing a transport failure: the first
    /// connection is closed unanswered — the failure the merge queue hit
    /// — and the shared policy's retry is what serves the archive.
    #[test]
    fn a_transport_failure_on_the_download_is_retried() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async {
            let body = b"the tarball bytes the server serves second";
            let (url, requests) = serve_fail_then_ok(None, body);
            let bytes = download(&url).await.expect("the retried download succeeds");
            assert_eq!(bytes, body);
            assert_eq!(*requests.lock().expect("request count"), 2);
        });
    }

    /// A transient status answer — the other half of the shared policy —
    /// is retried the same way.
    #[test]
    fn a_transient_status_on_the_download_is_retried() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async {
            let body = b"the tarball bytes the server serves second";
            let (url, requests) = serve_fail_then_ok(Some("503 Service Unavailable"), body);
            let bytes = download(&url).await.expect("the retried download succeeds");
            assert_eq!(bytes, body);
            assert_eq!(*requests.lock().expect("request count"), 2);
        });
    }
}

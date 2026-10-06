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
pub async fn provision(
    target: impl std::future::Future<Output = Result<String, String>> + Send,
    explicit_target: Option<&str>,
    cargo_dir: &Path,
) -> stow_types::error::Result<Vec<String>> {
    if !cfg!(target_os = "linux") || explicit_target.is_some_and(|target| !linux_target(target)) {
        return Ok(Vec::new());
    }
    // The availability probe is a process spawn, and it is independent
    // of the target triple unless a `cfg()` target table changes the
    // probe's inputs: launch the probe the config asks for under a
    // target-blind read while rustc's own host probe is still running.
    // When the real target leaves the probe inputs untouched the
    // speculative answer stands; when they change it the probe reruns
    // on the real inputs. `cargo-config2` answers the cfg question
    // lazily on first resolution, so this read costs a rustc probe
    // only when a `cfg()` table exists (stow#517).
    let config = cargo_config(cargo_dir, None)
        .map_err(|error| stow_types::stow_error!("load cargo config: {error}"))?;
    let candidate = resolve_link_from(&config, explicit_target.unwrap_or_default(), &process_env);
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
    let target = target
        .await
        .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
    if !linux_target(&target) {
        if let Some((_, task)) = speculative {
            task.abort();
        }
        return Ok(Vec::new());
    }
    let link = resolve_link_from(&config, &target, &process_env);
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
    let cargo_home = crate::config::cargo_home();
    let config = global_cargo_config(cargo_home.as_deref())
        .map_err(|error| stow_types::stow_error!("load global cargo config: {error}"))?;
    let link = resolve_link_from(&config, &host, &process_env);
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
pub type EnvLookup<'a> = &'a (dyn Fn(&str) -> Option<OsString> + Sync);

/// The process's environment — the [`EnvLookup`] real code reads.
pub fn process_env(key: &str) -> Option<OsString> {
    std::env::var_os(key)
}

/// Resolve `target`'s link configuration over an already-loaded config
/// chain: which `target.*` tables match (cfg tables only when `cfgs` was
/// answered — `None` keeps them all candidates), the effective rustflags
/// and linker they resolve to, and whether the selection picks mold.
/// How the config's linker selection resolves for `target`, read
/// through `cargo-config2`'s cargo-faithful resolution — env rustflags,
/// `CARGO_TARGET_*` overrides, and `target.<triple>` plus every
/// matching `target.<cfg>` table evaluated against `rustc --print
/// cfg`. A failed read — the cfg probe could not run — selects mold:
/// erring toward selection is the read whose worst case is an unused
/// provisioned binary, never a build refused for a linker it could
/// not check (stow#517).
fn resolve_link_from(
    config: &cargo_config2::Config,
    target: &str,
    env: EnvLookup<'_>,
) -> LinkResolution {
    let rustflags = config.rustflags(target);
    let linker = config.linker(target);
    let probe_failed = rustflags.is_err() || linker.is_err();
    let rustflags = rustflags
        .ok()
        .flatten()
        .map(|flags| flags.flags)
        .unwrap_or_default();
    let linker = rustflags_linker(&rustflags).or_else(|| {
        linker.ok().flatten().and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
    });
    LinkResolution {
        selects_mold: probe_failed
            || linker
                .as_deref()
                .is_some_and(|linker| linker.contains("mold"))
            || rustflags.iter().any(|flag| flag_mentions_mold(flag)),
        linker,
        rustflags,
        compiler_path: effective_compiler_path(config, env),
    }
}

/// The `COMPILER_PATH` a build at this config would run under, per
/// cargo's `env` precedence: `force` entries beat the ambient variable,
/// plain entries lose to it and apply only when it is unset.
fn effective_compiler_path(config: &cargo_config2::Config, env: EnvLookup<'_>) -> Option<OsString> {
    let ambient = env("COMPILER_PATH");
    // `CARGO_ENV_<name>` overrides a `[env]` file entry the way cargo
    // applies it — below `force` and the ambient variable, above the
    // file's own entry; `cargo-config2` does not model the prefix.
    let cargo_env = env("CARGO_ENV_COMPILER_PATH");
    match config.env.get("COMPILER_PATH") {
        Some(setting) if setting.force => Some(setting.value.clone()),
        _ => ambient.or(cargo_env).or_else(|| {
            config
                .env
                .get("COMPILER_PATH")
                .map(|setting| setting.value.clone())
        }),
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

/// The cargo configuration `cargo-config2` resolves for an invocation
/// at `cargo_dir` — the `$CARGO_HOME` + ancestor `.cargo/config*` chain
/// merged and overridden the way cargo does, `target.<cfg>` tables
/// evaluated against `rustc --print cfg`. `cargo_home` pins the global
/// file's location; `None` lets the crate resolve `CARGO_HOME` itself.
pub fn cargo_config(
    cargo_dir: &Path,
    cargo_home: Option<&Path>,
) -> Result<cargo_config2::Config, cargo_config2::Error> {
    let mut options = cargo_config2::ResolveOptions::default();
    if let Some(home) = cargo_home {
        options = options.cargo_home(Some(home.to_path_buf()));
    }
    cargo_config2::Config::load_with_options(cargo_dir, options)
}

/// Only the global end of the chain — the read `stow setup` makes,
/// where project-level files must not answer: ancestors of
/// `cargo_home`, which reach `$CARGO_HOME/config.toml` and any
/// system-level `.cargo` configs above it but never a project's.
fn global_cargo_config(
    cargo_home: Option<&Path>,
) -> Result<cargo_config2::Config, cargo_config2::Error> {
    let cargo_home = cargo_home.map(Path::to_path_buf);
    cargo_config2::Config::load_with_options(
        cargo_home.clone().unwrap_or_default(),
        cargo_config2::ResolveOptions::default().cargo_home(cargo_home),
    )
}

/// Every cargo config document cargo reads for an invocation at
/// `cargo_dir` — `(source label, parsed document)` pairs in merge
/// order: the files `cargo-config2` walks plus the `--config`
/// arguments it does not model. Readers needing the documents
/// themselves — the `[unstable]` scan (also unmodeled) and the cache
/// key — share this; resolved values go through `cargo-config2`.
pub fn cargo_config_documents(
    cargo_dir: &Path,
    cargo_args: &[std::ffi::OsString],
) -> Vec<(String, toml_edit::DocumentMut)> {
    let mut documents = Vec::new();
    // The walk yields closest-first and only existing files — reverse
    // to keep the documents in cargo's merge order.
    for path in cargo_config2::Walk::new(cargo_dir)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        match contents.parse::<toml_edit::DocumentMut>() {
            Ok(document) => documents.push((path.display().to_string(), document)),
            Err(error) => {
                tracing::debug!(path = %path.display(), %error, "ignoring unparseable cargo config file");
            }
        }
    }
    documents.extend(config_arg_documents(cargo_dir, cargo_args));
    documents
}

/// The documents `--config` arguments contribute — `(source label,
/// parsed document)` pairs in spelled order, each a file path or an
/// inline `key=value` — the one config input `cargo-config2` does not
/// model.
pub fn config_arg_documents(
    cargo_dir: &Path,
    cargo_args: &[std::ffi::OsString],
) -> Vec<(String, toml_edit::DocumentMut)> {
    let mut documents = Vec::new();
    let mut iter = cargo_args.iter().filter_map(|arg| arg.to_str());
    while let Some(arg) = iter.next() {
        let value = arg
            .strip_prefix("--config=")
            .map(str::to_owned)
            .or_else(|| {
                (arg == "--config")
                    .then(|| iter.next().map(str::to_owned))
                    .flatten()
            });
        let Some(value) = value else {
            continue;
        };
        let (label, contents) = if value.contains('=') {
            (format!("--config {value}"), value)
        } else {
            let path = cargo_dir.join(&value);
            match std::fs::read_to_string(&path) {
                Ok(contents) => (path.display().to_string(), contents),
                Err(_) => continue,
            }
        };
        match contents.parse::<toml_edit::DocumentMut>() {
            Ok(document) => documents.push((label, document)),
            Err(error) => {
                tracing::debug!(source = %label, %error, "ignoring unparseable --config value");
            }
        }
    }
    documents
}

/// `build.target` spelled through `--config`, string or array —
/// consulted between the spelled `--target` and the env/file chain
/// (`--config` outranks both in cargo).
pub fn config_arg_build_target(
    cargo_dir: &Path,
    cargo_args: &[std::ffi::OsString],
) -> Option<Vec<String>> {
    config_arg_documents(cargo_dir, cargo_args)
        .iter()
        .rev()
        .find_map(|(_, document)| {
            let value = document.get("build")?.get("target")?;
            if let Some(target) = value.as_str() {
                return Some(vec![target.to_owned()]);
            }
            value.as_array().map(|array| {
                array
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            })
        })
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
    // The default client already follows redirects; the request bound is
    // a tokio timeout so the awaited error stays `zenwave::Error` — the
    // middleware stack's error type is opaque.
    let mut client = zenwave::client();
    let request = match client.get(url) {
        Ok(request) => request,
        Err(error) => {
            return DownloadOutcome::Fatal(stow_types::stow_error!(
                "build mold download request: {error}"
            ));
        }
    };
    // zenwave lifts 4xx/5xx into `Err` before any status branch — whichever
    // arm carries the response, one `(status, hint)` extraction feeds the
    // single classification below; transport/timeout failures retry the
    // whole GET with no hint.
    let (status, retry_after, error) = match tokio::time::timeout(
        std::time::Duration::from_secs(DOWNLOAD_TIMEOUT_SECS),
        async move { request.await },
    )
    .await
    {
        Ok(Err(error)) => {
            let Some(response) = error.response() else {
                return DownloadOutcome::Retryable {
                    error: stow_types::stow_error!("download {url}: {error}"),
                    retry_after: None,
                };
            };
            (
                response.status().as_u16(),
                stow_types::transient::retry_after_hint(response.headers()),
                stow_types::stow_error!("download {url}: HTTP {}", response.status().as_u16()),
            )
        }
        Ok(Ok(response)) if response.status().is_success() => {
            return match response.into_body().into_bytes().await {
                Ok(bytes) => DownloadOutcome::Bytes(bytes.to_vec()),
                Err(error) => DownloadOutcome::Retryable {
                    error: stow_types::stow_error!("read {url} body: {error}"),
                    retry_after: None,
                },
            };
        }
        Ok(Ok(response)) => (
            response.status().as_u16(),
            stow_types::transient::retry_after_hint(response.headers()),
            stow_types::stow_error!("download {url}: HTTP {}", response.status()),
        ),
        Err(_) => {
            return DownloadOutcome::Retryable {
                error: stow_types::stow_error!("download {url}: timed out"),
                retry_after: None,
            };
        }
    };
    if stow_types::transient::is_transient_status(status) {
        DownloadOutcome::Retryable { error, retry_after }
    } else {
        DownloadOutcome::Fatal(error)
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
        cargo_home: PathBuf,
        env: std::collections::HashMap<String, OsString>,
    }

    impl IsolatedProject {
        /// The injected environment: `CARGO_HOME` alone.
        fn env(&self) -> impl Fn(&str) -> Option<OsString> + '_ {
            |key| self.env.get(key).cloned()
        }

        /// The resolved config for the fixture, with the injected
        /// environment handed to `cargo-config2` — no test ever reads
        /// the process environment its siblings share.
        fn config(&self) -> cargo_config2::Config {
            cargo_config2::Config::load_with_options(
                &self.project,
                cargo_config2::ResolveOptions::default()
                    .cargo_home(Some(self.cargo_home.clone()))
                    .env(self.env.clone()),
            )
            .expect("load config")
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
            cargo_home.clone().into_os_string(),
        )]);
        IsolatedProject {
            _tempdir: tempdir,
            project,
            cargo_home,
            env,
        }
    }

    fn detects_mold(config: &str) -> bool {
        let fixture = isolated_project(config);
        let env = fixture.env();
        resolve_link_from(&fixture.config(), LINUX_TARGET, &env).selects_mold
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

    /// The rustflags a config produces for `target`, resolved through
    /// `cargo-config2` the way cargo resolves them — env overrides,
    /// matching `target.<triple>`/`target.<cfg>` tables joined, then
    /// `build.rustflags` when no matching table carries flags.
    fn config_rustflags(config: &str, target: &str) -> Vec<String> {
        let fixture = isolated_project(config);
        fixture
            .config()
            .rustflags(target)
            .expect("resolve rustflags")
            .map(|flags| flags.flags)
            .unwrap_or_default()
    }

    /// Cargo joins a `target.<triple>` table's rustflags with every
    /// matching `target.<cfg>` table's, and `build.rustflags` is used only
    /// when no matching table carries flags — the precedence cargo itself
    /// implements in `target_cfgs` (cargo/src/cargo/util/context/
    /// target.rs).
    #[test]
    fn target_tables_join_and_build_rustflags_drops_out() {
        let flags = config_rustflags(
            "[build]\nrustflags = [\"-C\", \"debuginfo=0\"]\n\
             [target.x86_64-unknown-linux-gnu]\nrustflags = [\"-C\", \"target-cpu=native\"]\n\
             [target.'cfg(target_os = \"linux\")']\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n",
            LINUX_TARGET,
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
        let flags = config_rustflags(
            "[build]\nrustflags = [\"-C\", \"debuginfo=0\"]\n\
             [target.'cfg(target_os = \"linux\")']\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n",
            "aarch64-apple-darwin",
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
        let global = global_cargo_config(Some(&fixture.cargo_home)).expect("global config");
        assert!(
            global
                .rustflags(LINUX_TARGET)
                .expect("resolve rustflags")
                .is_none(),
            "project rustflags leaked into the global read"
        );
    }

    #[test]
    fn env_settings_resolve_both_shapes_and_force() {
        let fixture =
            isolated_project("[env.A]\nvalue = \"table\"\nforce = true\n\n[env]\nB = \"string\"\n");
        let config = fixture.config();
        let a = config.env.get("A").expect("env.A");
        assert_eq!(a.value, std::ffi::OsStr::new("table"));
        assert!(a.force);
        let b = config.env.get("B").expect("env.B");
        assert_eq!(b.value, std::ffi::OsStr::new("string"));
        assert!(!b.force);
        assert!(!config.env.contains_key("MISSING"));
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

    /// An owned, bounded one-answer HTTP stub on a real loopback socket:
    /// at most `LIMIT` connections, each stream bounded by read/write
    /// timeouts, accepting until the deadline, the limit, or `stop`.
    /// `join` ends it deterministically after the test's assertions;
    /// `Drop` stops it even when a test panics first.
    struct StubServer {
        /// Base URL — `http://127.0.0.1:<port>`.
        url: String,
        requests: std::sync::Arc<std::sync::Mutex<usize>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    /// Accept at most this many connections — far more than the one
    /// request each test expects, so a wrongly-retrying client is
    /// still served and counted.
    const LIMIT: usize = 8;
    /// Overall accept deadline — the thread never outlives it.
    const ACCEPT_BOUND: std::time::Duration = std::time::Duration::from_secs(30);
    /// Per-stream socket bound — no accepted connection stalls the
    /// thread on a slow peer.
    const STREAM_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

    impl StubServer {
        /// How many connections the stub has accepted so far — one per
        /// HTTP request this test makes.
        fn request_count(&self) -> usize {
            *self.requests.lock().expect("request count")
        }

        /// Stop accepting and reap the thread — the deterministic end
        /// when the test's assertions are done.
        fn join(mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                thread.join().expect("stub server thread");
            }
        }
    }

    impl Drop for StubServer {
        /// A test that panics before `join` still stops the thread —
        /// the accept loop polls `stop` between would-block slices.
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// Serve `status_line` (with `extra_headers` ahead of
    /// `content-length: 0`) on every accepted connection, counting each
    /// one — a classification that wrongly retries shows up in the
    /// count.
    fn serve_once(status_line: &'static str, extra_headers: &'static str) -> StubServer {
        use std::io::{BufRead as _, BufReader, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub server");
        listener.set_nonblocking(true).expect("nonblocking accept");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let requests = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let answer = format!(
            "HTTP/1.1 {status_line}\r\n{extra_headers}content-length: 0\r\nconnection: close\r\n\r\n"
        );
        let thread = {
            let seen = std::sync::Arc::clone(&requests);
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + ACCEPT_BOUND;
                let mut served = 0usize;
                while served < LIMIT
                    && std::time::Instant::now() < deadline
                    && !stop.load(std::sync::atomic::Ordering::Relaxed)
                {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            served += 1;
                            *seen.lock().expect("request count") = served;
                            stream
                                .set_read_timeout(Some(STREAM_BOUND))
                                .expect("read timeout");
                            stream
                                .set_write_timeout(Some(STREAM_BOUND))
                                .expect("write timeout");
                            let mut reader =
                                BufReader::new(stream.try_clone().expect("clone stream"));
                            loop {
                                let mut line = String::new();
                                match reader.read_line(&mut line) {
                                    // End of stream or a timed-out,
                                    // refused, or reset read ends the
                                    // header scan — the per-stream
                                    // bound keeps it from hanging.
                                    Ok(0) | Err(_) => break,
                                    Ok(_) if line == "\r\n" => break,
                                    Ok(_) => {}
                                }
                            }
                            stream.write_all(answer.as_bytes()).expect("write answer");
                            stream.flush().expect("flush");
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        StubServer {
            url,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    /// zenwave delivers a terminal status on the `Err` arm — the carried
    /// response still classifies: 404 is `Fatal`, so `download` stops
    /// after exactly one request instead of burning the retry budget.
    #[test]
    fn a_terminal_status_is_fatal_after_one_request() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async {
            let server = serve_once("404 Not Found", "");
            let result =
                tokio::time::timeout(std::time::Duration::from_secs(10), download(&server.url))
                    .await
                    .expect("the download completes within the deadline");
            assert!(result.is_err(), "a terminal status must fail");
            assert_eq!(server.request_count(), 1);
            server.join();
        });
    }

    /// A transient status inside the `Err` keeps its `Retry-After`
    /// hint — the carried response's headers drive the wait.
    #[test]
    fn a_transient_status_error_keeps_the_retry_after_hint() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async {
            let server = serve_once("429 Too Many Requests", "retry-after: 7\r\n");
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                download_once(&server.url),
            )
            .await
            .expect("the download completes within the deadline");
            let DownloadOutcome::Retryable { retry_after, .. } = outcome else {
                panic!("429 must be Retryable");
            };
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(7)));
            assert_eq!(server.request_count(), 1);
            server.join();
        });
    }

    /// A server failure inside the `Err` retries — with no hint when
    /// the response carries none.
    #[test]
    fn a_server_failure_error_is_retryable() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");
        runtime.block_on(async {
            let server = serve_once("500 Internal Server Error", "");
            let outcome = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                download_once(&server.url),
            )
            .await
            .expect("the download completes within the deadline");
            assert!(
                matches!(outcome, DownloadOutcome::Retryable { .. }),
                "500 must be Retryable"
            );
            assert_eq!(server.request_count(), 1);
            server.join();
        });
    }
}

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

use crate::rustc_args::{BuildRustc, detect_rustc_host_target};

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
    stow_config: Option<&crate::config::StowConfig>,
    rustc_vv: &crate::rustc_args::SharedRustcVv,
    cargo_config: cargo_config2::Config,
    build_rustc: &BuildRustc,
) -> stow_types::error::Result<Vec<String>> {
    if !cfg!(target_os = "linux") || explicit_target.is_some_and(|target| !linux_target(target)) {
        return Ok(Vec::new());
    }
    // The driver already loaded the config chain: the evaluation reads
    // a clone of it, never a re-parse, and the env map digests the
    // wrapper removal the evaluation applies (stow#608).
    let env_map = link_env_vars(std::env::vars_os(), wraps_stow_rustc(&cargo_config));
    let target = target
        .await
        .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
    if !linux_target(&target) {
        return Ok(Vec::new());
    }
    // A state DB that cannot be opened is a cache miss, not a build
    // failure: the resolution is fully computable without it (stow#608).
    let pool = match stow_config {
        Some(config) => match config.state_db_pool().await {
            Ok(pool) => Some(pool),
            Err(error) => {
                tracing::warn!(error = %error, "link resolution cache unavailable, resolving without it");
                None
            }
        },
        None => None,
    };
    let cargo_home = process_env("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(crate::config::cargo_home);
    let ctx = LinkResolutionContext {
        cargo_dir,
        cargo_home: cargo_home.as_deref(),
        target: &target,
        env_map: &env_map,
        env: &process_env,
        build_rustc,
        rustc_vv,
    };
    provision_resolved(
        cargo_config,
        &ctx,
        &crate::config::tools_dir()?,
        pool.as_ref(),
    )
    .await
}

/// The inputs `LinkResolutionKey::compute` digests and the resolution
/// reads — one struct because every carrier of them (the build's
/// provision, `stow setup`'s warm, the tests) hands over the same set.
struct LinkResolutionContext<'a> {
    cargo_dir: &'a Path,
    cargo_home: Option<&'a Path>,
    target: &'a str,
    /// The allowlisted environment the key digests.
    env_map: &'a std::collections::BTreeMap<String, OsString>,
    /// The environment the resolution reads (`PATH`, `COMPILER_PATH`).
    env: EnvLookup<'a>,
    /// The build's rustc — `provision_resolved` pins the `target.<cfg>`
    /// evaluation to its executable, the same one `rustc_vv`'s `-vV`
    /// digests into the key (stow#608).
    build_rustc: &'a BuildRustc,
    /// The driver's shared `rustc -vV` of `build_rustc`.
    rustc_vv: &'a crate::rustc_args::SharedRustcVv,
}

/// The cached-or-computed answer to "what `--config` values does this
/// invocation need" (stow#608): a hit skips both the `target.<cfg>`
/// evaluation's `rustc --print cfg` spawn and the mold probe's compiler
/// spawn. `None` for `pool`, a stale row, or any cache failure computes
/// exactly what the uncached path would — the cache may cost a hit,
/// never the build.
async fn provision_resolved(
    config: cargo_config2::Config,
    ctx: &LinkResolutionContext<'_>,
    tools_dir: &Path,
    pool: Option<&sqlx::SqlitePool>,
) -> stow_types::error::Result<Vec<String>> {
    let cache = match pool {
        Some(_) => Some(LinkResolutionKey::compute(ctx).await?),
        None => None,
    };
    if let (Some(pool), Some(key)) = (pool, &cache) {
        match cached_link_args(pool, key).await {
            Ok(Some(args)) => return Ok(args),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(error = %error, "link resolution cache read failed, resolving fresh");
            }
        }
    }
    // The `target.<cfg>` evaluation runs the rustc the key's `-vV`
    // digests — `build.rustc` pinned to the build rustc rather than the
    // rustc `cargo-config2` would otherwise resolve beside `$CARGO`
    // (stow#608).
    let config = link_eval_config(&config, ctx.build_rustc);
    let link = resolve_link_from(&config, ctx.target, ctx.env);
    // For a mold-selecting link the availability probe and the
    // record-time `ld.mold` query are independent questions the same
    // driver command answers — resolved driver, `-B` prefixes,
    // `COMPILER_PATH` — so they run together (stow#608).
    let probed = if link.selects_mold {
        let probe = link.probe();
        let path = (ctx.env)("PATH");
        let query = async {
            match &probe {
                MoldProbe::Driver {
                    driver,
                    b_dirs,
                    compiler_path,
                } => {
                    driver_resolved_program(
                        driver,
                        "ld.mold",
                        b_dirs,
                        compiler_path.as_deref(),
                        path.as_deref(),
                    )
                    .await
                }
                MoldProbe::Linker(_) => None,
            }
        };
        let (unavailable, resolved) = tokio::join!(
            probe_unavailable_reason(&probe, ctx.env)
                .instrument(tracing::debug_span!("stow.precargo.mold_probe")),
            query,
        );
        // The file the driver actually resolves `ld.mold` to is
        // witnessed too, so a driver-internal program directory's
        // `ld.mold` is covered — but only when the probe says mold
        // runs: a failed probe's answer is discarded (stow#608).
        unavailable.is_none().then_some((probe, path, resolved))
    } else {
        None
    };
    let (args, witnesses) = if let Some((probe, path, resolved)) = probed {
        let witnesses = tokio::task::spawn_blocking(move || {
            let mut witnesses = probe_witnesses(&probe, path.as_deref());
            if let Some(resolved) = resolved {
                witnesses.push(witness_path(&resolved));
            }
            witnesses
        })
        .await
        .wrap_err("join link witness task")?;
        (Vec::new(), witnesses)
    } else {
        let bin_dir = ensure_mold_install(tools_dir)
            .instrument(tracing::debug_span!("stow.precargo.mold_install"))
            .await?;
        (selection_args(&bin_dir)?, managed_witnesses(&bin_dir))
    };
    // Only a successful resolution is cached — a build that would be
    // refused re-probes and reports the live reason every time, and a
    // resolution whose `target.<cfg>` read could not run at all is
    // never recorded: it answered by default, not by what the
    // configuration says (stow#517, stow#608).
    if !link.cfg_unreadable
        && let (Some(pool), Some(key)) = (pool, cache)
    {
        // Record only the bytes the resolution actually read: a config
        // document that moved between the key's digest and now is a
        // different key, not a row under this one (stow#608).
        let cargo_dir = ctx.cargo_dir.to_path_buf();
        let cargo_home = ctx.cargo_home.map(Path::to_path_buf);
        let current = tokio::task::spawn_blocking(move || {
            link_config_documents(&cargo_dir, cargo_home.as_deref())
        })
        .await
        .wrap_err("join link document digest task")?;
        if current == key.documents
            && let Err(error) = record_link_args(pool, key, &args, &witnesses).await
        {
            tracing::warn!(error = %error, "link resolution cache write failed; the next build re-probes");
        }
    }
    Ok(args)
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
    let cargo_home = crate::config::cargo_home();
    let loaded = cargo_config(
        &cargo_home.clone().unwrap_or_default(),
        cargo_home.as_deref(),
    )
    .map_err(|error| stow_types::stow_error!("load global cargo config: {error}"))?;
    let build_rustc = BuildRustc::from_cargo_config(&loaded);
    // The host gate and the resolution both ask the build's rustc —
    // the configured `build.rustc` when one is set, the toolchain's
    // `rustc` otherwise (stow#608).
    let host = detect_rustc_host_target(build_rustc.executable())
        .await
        .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
    let config = link_eval_config(&loaded, &build_rustc);
    let link = resolve_link_from(&config, &host, &process_env);
    if link.selects_mold && link.unavailable_reason(&process_env).await.is_none() {
        return Ok(None);
    }
    Ok(Some(
        ensure_mold_install(&crate::config::tools_dir()?).await?,
    ))
}

/// The link resolution a build from a directory with no config of its
/// own performs, run by `stow setup` against the global config it just
/// wrote so the outcome is already recorded when that first build asks
/// (stow#608). The invocation directory passed to the key is
/// `cargo_home` itself — the directory the global read walked — whose
/// document set is the global file plus its ancestors, exactly the set
/// a bare project directory's walk digests (its own ancestors plus the
/// same global file).
///
/// # Errors
///
/// Whatever the config load, the state-DB pool, or the resolution
/// itself fails with.
pub async fn warm_global_link_cache(
    cargo_home: &Path,
    stow_config: &crate::config::StowConfig,
) -> stow_types::error::Result<()> {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    let loaded = cargo_config(cargo_home, Some(cargo_home))
        .map_err(|error| stow_types::stow_error!("load global cargo config: {error}"))?;
    let build_rustc = BuildRustc::from_cargo_config(&loaded);
    // A state DB that cannot be opened costs the warm record, never
    // the setup that already wrote the configuration (stow#608).
    let pool = match stow_config.state_db_pool().await {
        Ok(pool) => Some(pool),
        Err(error) => {
            tracing::warn!(error = %error, "link resolution cache unavailable, setup leaves it cold");
            None
        }
    };
    let env_map = link_env_vars(std::env::vars_os(), wraps_stow_rustc(&loaded));
    let shared_vv = crate::rustc_args::shared_rustc_vv(build_rustc.executable().to_os_string());
    // The resolution's target is the build rustc's own host triple —
    // read from the same `-vV` the key digests, not a probe of some
    // other `rustc` (stow#608).
    let vv = shared_vv
        .clone()
        .await
        .map_err(|error| stow_types::stow_error!("probe rustc -vV: {error}"))?;
    let host = crate::rustc_args::vv_host(vv.as_str())
        .map_err(|error| stow_types::stow_error!("read rustc host target: {error}"))?;
    let ctx = LinkResolutionContext {
        cargo_dir: cargo_home,
        cargo_home: Some(cargo_home),
        target: &host,
        env_map: &env_map,
        env: &process_env,
        build_rustc: &build_rustc,
        rustc_vv: &shared_vv,
    };
    provision_resolved(loaded, &ctx, &crate::config::tools_dir()?, pool.as_ref()).await?;
    Ok(())
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
/// earlier wiring, in any `target` table — are replaced in place, so
/// re-running `setup` rewrites the same keys rather than appending
/// duplicates.
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
    // An earlier wiring may have left stow's flags in any `target`
    // table — strip them everywhere before writing, so the selection
    // below replaces them instead of duplicating them or leaving a
    // table the new selection does not cover.
    for (_, table) in target.iter_mut() {
        let Some(table) = table.as_table_like_mut() else {
            continue;
        };
        let flags = match table.get("rustflags") {
            Some(item) if item.is_array() || item.is_str() => rustflags_value(item),
            _ => continue,
        };
        let flag_count = flags.len();
        let kept = strip_stow_linker_flags(flags);
        if kept.len() == flag_count {
            continue;
        }
        if kept.is_empty() {
            table.remove("rustflags");
        } else {
            let mut array = toml_edit::Array::new();
            array.extend(kept);
            *table.get_mut("rustflags").expect("rustflags exists") =
                toml_edit::Item::Value(toml_edit::Value::Array(array));
        }
    }
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
    flags.extend(existing);
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
    /// The `target.<cfg>` evaluation's `rustc --print cfg` could not
    /// run — the resolution answered by default (stow#517). Such an
    /// answer is never recorded: it says what the fallback computes,
    /// not what the configuration resolves to (stow#608).
    cfg_unreadable: bool,
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
        cfg_unreadable: probe_failed,
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

/// The environment variables the link resolution's outcome can depend
/// on — the key may digest nothing else, or inputs like
/// `CARGO_TARGET_DIR` (a different value every build) would make every
/// build a different key. Each entry names the reader in the code:
/// `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS` and `CARGO_BUILD_RUSTFLAGS`
/// map to `build.rustflags` (cargo-config2's env mapping) which
/// `resolve_link_from`'s rustflags chain reads; the
/// `CARGO_TARGET_<U>_RUSTFLAGS` and `CARGO_TARGET_<U>_LINKER` overrides
/// land in the `target.<triple>` table the same way;
/// `CARGO_BUILD_TARGET` folds into `build.target` on the loaded
/// `Config`; `RUSTC` and `CARGO_BUILD_RUSTC` map to `build.rustc`, the
/// rustc the cfg evaluation probes (`rustc --print cfg`) — the
/// evaluation pins `build.rustc` to the build rustc, so the rustc
/// beside `$CARGO` is never read; the
/// `RUSTC_WRAPPER` / `CARGO_BUILD_RUSTC_WRAPPER` /
/// `RUSTC_WORKSPACE_WRAPPER` / `CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER`
/// chain is what the cfg eval runs rustc through — a non-stow wrapper
/// can legitimately change `--print` answers; `RUSTC_BOOTSTRAP` is read
/// directly via `std::env::var_os` in cargo-config2's resolver
/// (bypassing the injected env); `COMPILER_PATH` and
/// `CARGO_ENV_COMPILER_PATH` feed `effective_compiler_path` (the latter
/// lands in the config's `[env]` table as `COMPILER_PATH`).
/// `PATH` is where the probe and the record-time witnesses resolve
/// `ld.mold` and the driver — a different `PATH` can honestly answer
/// differently (stow#608).
/// `-B` prefixes reach the probe through rustflags, and the probed
/// driver/`ld.mold` are witnessed by resolved absolute path with size
/// and mtime rather than digested — a file that changes under a stable
/// name is still a miss.
const LINK_ENV_VARS: &[&str] = &[
    "PATH",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "RUSTC",
    "CARGO_BUILD_RUSTC",
    "RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_BOOTSTRAP",
    "COMPILER_PATH",
    "CARGO_ENV_COMPILER_PATH",
];

/// Whether `key` is a `CARGO_TARGET_<triple>_LINKER|RUSTFLAGS` override
/// (the target-table env vars the resolution reads — and nothing else
/// under the `CARGO_TARGET_` prefix, in particular not
/// `CARGO_TARGET_DIR`).
fn is_target_table_env(key: &str) -> bool {
    key.strip_prefix("CARGO_TARGET_")
        .is_some_and(|rest| rest.ends_with("_LINKER") || rest.ends_with("_RUSTFLAGS"))
}

/// The environment map the link resolution reads — the allowlist above
/// plus `COMPILER_PATH`, which [`effective_compiler_path`] consults
/// directly. `de_wrapped` records the `RUSTC_WRAPPER=""` override the
/// evaluation runs under when the configured wrapper is stow's own —
/// [`link_eval_config`] clears it — so the digested map is the map the
/// evaluation actually saw.
fn link_env_vars(
    vars: impl IntoIterator<Item = (OsString, OsString)>,
    de_wrapped: bool,
) -> std::collections::BTreeMap<String, OsString> {
    let mut map = std::collections::BTreeMap::new();
    for (key, value) in vars {
        let Ok(key) = key.into_string() else {
            continue;
        };
        if LINK_ENV_VARS.contains(&key.as_str()) || is_target_table_env(&key) {
            map.insert(key, value);
        }
    }
    if de_wrapped {
        map.insert("RUSTC_WRAPPER".to_owned(), OsString::new());
    }
    map
}

/// Content digests of every config document the resolution reads — the
/// files `cargo-config2`'s `Walk` yields for `cargo_dir` plus the global
/// file under `cargo_home` — each as `(label, sha256)` so a changed file
/// is a different key.
fn link_config_documents(cargo_dir: &Path, cargo_home: Option<&Path>) -> Vec<(String, String)> {
    // The walk carries the *injected* cargo home — `Walk::new` would
    // resolve the process `CARGO_HOME` and digest the developer's real
    // global config into every test key (stow#608).
    let paths: Vec<PathBuf> = cargo_home.map_or_else(
        || cargo_config2::Walk::new(cargo_dir).collect(),
        |home| cargo_config2::Walk::with_cargo_home(cargo_dir, Some(home.to_path_buf())).collect(),
    );
    // Only documents that exist enter the key: two invocation
    // directories whose Walk names only absent files then digest the
    // same set — one key per machine, toolchain and target rather than
    // per project directory. A document appearing or disappearing
    // changes the set, so it is still a different key.
    let mut documents = Vec::new();
    for path in paths {
        let Ok(contents) = std::fs::read(&path) else {
            continue;
        };
        documents.push((
            path.display().to_string(),
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&contents)),
        ));
    }
    documents
}

/// Everything the resolution's answer depends on, digested: the
/// `rustc -vV` output of the rustc the `target.<cfg>` evaluation runs
/// (version and host), the build's target triple, every config
/// document's content, and every environment variable the resolution
/// reads. A changed input is a different key, so the probes run again.
struct LinkResolutionKey {
    inputs_digest: String,
    /// The `(label, sha256)` pairs the digest was computed over — the
    /// record path re-reads them to skip recording against documents
    /// that moved since (stow#608).
    documents: Vec<(String, String)>,
}

/// The key format's version, digested first: bumped whenever
/// `selection_args`, `resolve_link_from`, `FUSE_LD_MOLD` or
/// `FileWitness` changes meaning, so rows written under the old
/// semantics miss rather than answer the new question (stow#608).
const LINK_KEY_FORMAT: u32 = 2;

impl LinkResolutionKey {
    async fn compute(ctx: &LinkResolutionContext<'_>) -> stow_types::error::Result<Self> {
        // The `target.<cfg>` evaluation invokes the build rustc — the
        // shared probe is already that executable's `-vV` (stow#608).
        let vv = ctx
            .rustc_vv
            .clone()
            .await
            .map(|vv| (*vv).clone())
            .map_err(|error| {
                stow_types::stow_error!("probe rustc -vV for the link resolution: {error}")
            })?;
        let cargo_dir = ctx.cargo_dir.to_path_buf();
        let cargo_home = ctx.cargo_home.map(Path::to_path_buf);
        // Reading the config documents is a filesystem walk — off the
        // runtime worker (stow#608).
        let documents = tokio::task::spawn_blocking(move || {
            link_config_documents(&cargo_dir, cargo_home.as_deref())
        })
        .await
        .wrap_err("join link document digest task")?;
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        hasher.update(LINK_KEY_FORMAT.to_le_bytes());
        hasher.update(vv.as_bytes());
        hasher.update([0]);
        hasher.update(ctx.target.as_bytes());
        hasher.update([0]);
        for (label, digest) in &documents {
            hasher.update(label.as_bytes());
            hasher.update([0]);
            hasher.update(digest.as_bytes());
            hasher.update([0]);
        }
        for (key, value) in ctx.env_map {
            hasher.update(key.as_bytes());
            hasher.update([0]);
            hasher.update(value.as_encoded_bytes());
            hasher.update([0]);
        }
        Ok(Self {
            inputs_digest: hex::encode(hasher.finalize()),
            documents,
        })
    }
}

/// One file the cached outcome depends on, witnessed by what a lookup
/// would resolve now: the candidate path (as spelled or found on a
/// search dir), the symlink-resolved path, and its size and mtime.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct FileWitness {
    path: PathBuf,
    resolved: Option<PathBuf>,
    exists: bool,
    size: u64,
    mtime_ms: u64,
}

fn witness_path(candidate: &Path) -> FileWitness {
    let metadata = std::fs::metadata(candidate).ok();
    let resolved = std::fs::canonicalize(candidate).ok();
    let (mtime_ms, exists) = metadata
        .as_ref()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|mtime| mtime.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or((0, false), |mtime| {
            (u64::try_from(mtime.as_millis()).unwrap_or(u64::MAX), true)
        });
    FileWitness {
        path: candidate.to_path_buf(),
        resolved,
        exists,
        size: metadata.as_ref().map_or(0, std::fs::Metadata::len),
        mtime_ms,
    }
}

/// The candidate paths a bare `name` resolves through — `PATH` order —
/// or the path itself when the name carries a slash.
fn candidacies(name: &str, path: Option<&OsStr>) -> Vec<PathBuf> {
    if name.contains('/') {
        return vec![PathBuf::from(name)];
    }
    let Some(path) = path else {
        return Vec::new();
    };
    std::env::split_paths(path)
        .map(|dir| dir.join(name))
        .collect()
}

/// The files a [`MoldProbe`] answer depends on — for a driver probe the
/// `ld.mold` it would find through `COMPILER_PATH`, the configured `-B`
/// prefixes and `PATH`, witnessed at every candidate location so a new
/// `ld.mold` appearing earlier in the search order also changes the
/// answer, plus the driver itself the same way.
fn probe_witnesses(probe: &MoldProbe, path: Option<&OsStr>) -> Vec<FileWitness> {
    match probe {
        MoldProbe::Linker(linker) => candidacies(linker, path)
            .iter()
            .map(|candidate| witness_path(candidate))
            .collect(),
        MoldProbe::Driver {
            driver,
            b_dirs,
            compiler_path,
        } => {
            let mut dirs: Vec<PathBuf> = compiler_path
                .as_ref()
                .map(|path| std::env::split_paths(path).collect())
                .unwrap_or_default();
            dirs.extend(b_dirs.iter().cloned());
            if let Some(path) = path {
                dirs.extend(std::env::split_paths(path));
            }
            let mut witnesses = Vec::new();
            for dir in dirs {
                witnesses.push(witness_path(&dir.join("ld.mold")));
            }
            witnesses.extend(
                candidacies(driver, path)
                    .iter()
                    .map(|candidate| witness_path(candidate)),
            );
            witnesses
        }
    }
}

/// The files a managed-install outcome depends on — the install's own
/// `mold` and `ld.mold`, so a removed or replaced install re-probes.
fn managed_witnesses(bin_dir: &Path) -> Vec<FileWitness> {
    vec![
        witness_path(&bin_dir.join("mold")),
        witness_path(&bin_dir.join("ld.mold")),
    ]
}

/// Whether every stored witness still describes the file system —
/// checked path, resolved identity, existence, size and mtime.
fn witnesses_current(witnesses: &[FileWitness]) -> bool {
    witnesses
        .iter()
        .all(|witness| witness_path(&witness.path) == *witness)
}

/// How long a row may sit under a key that stopped being asked: the
/// horizon bounds how long rows under dead keys accumulate, nothing
/// else — a row whose key is still asked never expires, because the
/// key and the witnesses already cover everything that can change the
/// answer (stow#608). Pruned on the record path, which writes anyway,
/// so the read path never executes a write statement.
const LINK_CACHE_ROW_HORIZON: std::time::Duration = std::time::Duration::from_hours(30 * 24);

/// The cached args for `key`, or `None` when absent or stale — a row
/// whose witnessed files changed answers as a miss and is overwritten
/// by the fresh resolution.
async fn cached_link_args(
    pool: &sqlx::SqlitePool,
    key: &LinkResolutionKey,
) -> stow_types::error::Result<Option<Vec<String>>> {
    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT args_json, witnesses_json FROM link_resolution_cache WHERE inputs_digest = ?",
    )
    .bind(&key.inputs_digest)
    .fetch_optional(pool)
    .await?;
    let Some((args_json, witnesses_json)) = row else {
        return Ok(None);
    };
    let witnesses: Vec<FileWitness> =
        serde_json::from_str(&witnesses_json).wrap_err("decode cached link witnesses")?;
    let current = tokio::task::spawn_blocking(move || witnesses_current(&witnesses))
        .await
        .wrap_err("join link witness check task")?;
    if !current {
        return Ok(None);
    }
    let args: Vec<String> = serde_json::from_str(&args_json).wrap_err("decode cached link args")?;
    Ok(Some(args))
}

async fn record_link_args(
    pool: &sqlx::SqlitePool,
    key: LinkResolutionKey,
    args: &[String],
    witnesses: &[FileWitness],
) -> stow_types::error::Result<()> {
    // Rows under keys that stopped being asked accumulate forever
    // otherwise — prune them here, the cold path that writes anyway,
    // so a hit never executes a write statement (stow#608).
    let now_ms: i64 = crate::state_db::db_int(
        crate::state_db::now_millis(),
        "link resolution cache current time",
    )?;
    let horizon_ms: i64 = crate::state_db::db_int(
        crate::state_db::duration_millis(LINK_CACHE_ROW_HORIZON),
        "link resolution cache row horizon",
    )?;
    sqlx::query("DELETE FROM link_resolution_cache WHERE ? - created_at_ms >= ?")
        .bind(now_ms)
        .bind(horizon_ms)
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO link_resolution_cache (inputs_digest, args_json, witnesses_json, created_at_ms) \
         VALUES (?, ?, ?, ?) \
         ON CONFLICT(inputs_digest) DO UPDATE SET \
             args_json = excluded.args_json, \
             witnesses_json = excluded.witnesses_json, \
             created_at_ms = excluded.created_at_ms",
    )
    .bind(&key.inputs_digest)
    .bind(serde_json::to_string(args).wrap_err("encode link args")?)
    .bind(serde_json::to_string(witnesses).wrap_err("encode link witnesses")?)
    .bind(crate::state_db::db_int::<u64, i64>(
        crate::state_db::now_millis(),
        "link resolution cache timestamp",
    )?)
    .execute(pool)
    .await?;
    Ok(())
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
    async fn unavailable_reason(&self, env: EnvLookup<'_>) -> Option<String> {
        probe_unavailable_reason(&self.probe(), env).await
    }
}

/// Runs `probe` against the machine and reports why mold cannot run for
/// it, or `None` when it can. `env` is the environment `PATH` is read
/// from — the injected one, never the process's (stow#608).
async fn probe_unavailable_reason(probe: &MoldProbe, env: EnvLookup<'_>) -> Option<String> {
    match probe {
        MoldProbe::Linker(linker) => (!program_resolves(linker, env("PATH").as_deref())).then(|| {
            format!("the configured linker `{linker}` does not resolve to an executable")
        }),
        MoldProbe::Driver {
            driver,
            b_dirs,
            compiler_path,
        } => (!ld_mold_resolves(driver, b_dirs, compiler_path.as_deref(), env("PATH").as_deref())
            .await)
        .then(|| {
            format!(
                "`{driver}` finds no `ld.mold` for `-fuse-ld=mold` — run `stow setup` to install mold"
            )
        }),
    }
}

/// The driver command the mold probe and the record-time `ld.mold`
/// query share: `driver` resolved on the injected `PATH` — a driver
/// that does not resolve there is never looked up through the
/// process's own — the `-B` prefixes ahead of the caller's arguments,
/// and the effective `COMPILER_PATH` exported (stow#608). `None` when
/// the driver does not resolve on the injected `PATH` — the answer a
/// failed spawn gave.
fn driver_command(
    driver: &str,
    b_dirs: &[PathBuf],
    compiler_path: Option<&OsStr>,
    path: Option<&OsStr>,
) -> Option<async_process::Command> {
    let resolved = candidacies(driver, path)
        .into_iter()
        .find(|candidate| is_executable(candidate))?;
    let mut command = async_process::Command::new(resolved);
    for dir in b_dirs {
        command.arg(format!("-B{}", dir.display()));
    }
    if let Some(path) = compiler_path {
        command.env("COMPILER_PATH", path);
    }
    Some(command)
}

/// Whether `driver` finds an `ld.mold` — answered by asking it to link
/// with `-fuse-ld=mold` rather than by reimplementing each driver's own
/// search rules: collect2's, clang's and a cross gcc's lists differ (the
/// last never looks at `PATH`), and the link probe is the question the
/// real build will ask. `-nostdlib -shared` on an empty translation unit
/// exercises exactly the lookup and nothing else.
async fn ld_mold_resolves(
    driver: &str,
    b_dirs: &[PathBuf],
    compiler_path: Option<&OsStr>,
    path: Option<&OsStr>,
) -> bool {
    let Some(mut probe) = driver_command(driver, b_dirs, compiler_path, path) else {
        return false;
    };
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
    probe
        .output()
        .await
        .is_ok_and(|output| output.status.success())
}

/// Whether `name` resolves to an executable: a name containing a slash is
/// checked as a path, a bare name is looked up on `PATH`.
fn program_resolves(name: &str, path: Option<&OsStr>) -> bool {
    if name.contains('/') {
        return is_executable(Path::new(name));
    }
    path.is_some_and(|path| path_contains(name, path))
}

/// Whether an executable named `name` exists anywhere on `PATH`.
fn path_contains(name: &str, path: &OsStr) -> bool {
    std::env::split_paths(path).any(|dir| is_executable(&dir.join(name)))
}

/// The path `driver` resolves `program` to under the probe's own
/// environment — gcc/clang's `-print-prog-name` run with the same `-B`
/// prefixes and `COMPILER_PATH` the link probe carried, echoed back
/// unresolved when the driver cannot find one. `Some` only for a
/// resolved path, so the caller witnesses real files only (stow#608).
async fn driver_resolved_program(
    driver: &str,
    program: &str,
    b_dirs: &[PathBuf],
    compiler_path: Option<&OsStr>,
    path: Option<&OsStr>,
) -> Option<PathBuf> {
    let output = driver_command(driver, b_dirs, compiler_path, path)?
        .arg(format!("-print-prog-name={program}"))
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let resolved = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    (!resolved.as_os_str().is_empty() && resolved != Path::new(program)).then_some(resolved)
}

/// A rustflag selects mold when a `-C` link option's value names it —
/// `-C link-arg=-fuse-ld=mold`, `-C linker=mold`, a `-C link-args` bundle
/// carrying `-fuse-ld=mold`, and so on.
pub fn flag_mentions_mold(flag: &str) -> bool {
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

/// Whether the configured `rustc-wrapper` is stow's own — the
/// `RUSTC_WRAPPER=""` the link evaluation then runs under, which the
/// key's env map digests (stow#608).
fn wraps_stow_rustc(config: &cargo_config2::Config) -> bool {
    config
        .build
        .rustc_wrapper
        .as_deref()
        .and_then(Path::to_str)
        .is_some_and(crate::commands::is_stow_owned_value)
}

/// The config the link resolution evaluates: a clone of the loaded
/// chain with `build.rustc` pinned to the build's rustc — so the
/// `target.<cfg>` evaluation's `rustc --print cfg`, the key's `-vV`
/// digest and cargo's own build all name one executable, rather than
/// the rustc `cargo-config2` would otherwise resolve beside `$CARGO`
/// (stow#608) — and, when the configured wrapper is stow's own, the
/// wrapper cleared: the shim passes `--print` through unchanged so the
/// answers are identical, while evaluating through it would boot the
/// whole standalone wrapper — its own rustc probes and state-DB open —
/// once per `cfg()` table read. A user-configured wrapper stays: it can
/// legitimately change rustc's answers.
///
/// Correct only while `config` has never evaluated anything:
/// `cargo-config2` memoizes the resolved rustc command in a `OnceCell`
/// on first use, and a clone taken after that keeps the old command,
/// wrapper included. Hand it the freshly loaded chain, never a config
/// a `rustflags`/`linker`/`cfg`/`rustc()` read already touched.
fn link_eval_config(
    config: &cargo_config2::Config,
    build_rustc: &BuildRustc,
) -> cargo_config2::Config {
    let mut config = config.clone();
    config.build.rustc = Some(PathBuf::from(build_rustc.executable()));
    if wraps_stow_rustc(&config) {
        config.build.rustc_wrapper = None;
    }
    config
}

/// Every cargo config document cargo reads for an invocation at
/// `cargo_dir` — `(source label, parsed document)` pairs in merge
/// order: the files `cargo-config2` walks plus the `--config`
/// arguments it does not model. Readers needing the documents
/// themselves — the `[unstable]` scan (also unmodeled) and the cache
/// key — share this; resolved values go through `cargo-config2`.
/// `cargo_home` pins the global file's location; `None` lets the crate
/// resolve `CARGO_HOME` itself.
pub fn cargo_config_documents(
    cargo_dir: &Path,
    cargo_args: &[std::ffi::OsString],
    cargo_home: Option<&Path>,
) -> Vec<(String, toml_edit::DocumentMut)> {
    let mut documents = Vec::new();
    let walk = cargo_home.map_or_else(
        || cargo_config2::Walk::new(cargo_dir),
        |home| cargo_config2::Walk::with_cargo_home(cargo_dir, Some(home.to_path_buf())),
    );
    // The walk yields closest-first and only existing files — reverse
    // to keep the documents in cargo's merge order.
    for path in walk.collect::<Vec<_>>().into_iter().rev() {
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
async fn ensure_mold_install(tools_dir: &Path) -> stow_types::error::Result<PathBuf> {
    let bin_dir = tools_dir.join("mold").join("bin");
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
                // Per attempt: the exhausted retry's error is what the
                // caller surfaces (stow#633).
                tracing::debug!(url, %error, "mold download failed; retrying");
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
        tempdir: tempfile::TempDir,
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
            tempdir,
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
        let loaded =
            cargo_config(&fixture.cargo_home, Some(&fixture.cargo_home)).expect("global config");
        let global = link_eval_config(&loaded, &BuildRustc::from_cargo_config(&loaded));
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
                            // Windows hands accepted sockets the
                            // listener's nonblocking mode; the stream's
                            // own timeouts bound it instead.
                            stream.set_nonblocking(false).expect("blocking stream");
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

    // stow#608: the link resolution's outcome persists in the state DB —
    // a hit skips both the `rustc --print cfg` spawn the `target.<cfg>`
    // evaluation needs and the driver's `-fuse-ld=mold` probe.

    /// A script that records every invocation before behaving like the
    /// tool it stands in for — the probe-observation seam these tests
    /// use: the resolution's subprocesses are spawned by `cargo-config2`
    /// and `ld_mold_resolves` against real binaries, so the fixture
    /// names counting wrappers as `RUSTC` and `linker`.
    fn counting_script(dir: &Path, name: &str, counter: &Path, body: &str) -> PathBuf {
        let script = dir.join(name);
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$0 $* COMPILER_PATH=${{COMPILER_PATH-}}\" >> {}\n{body}\n",
                counter.display()
            ),
        )
        .expect("write counting script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut permissions = std::fs::metadata(&script).expect("metadata").permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&script, permissions).expect("chmod");
        }
        script
    }

    /// The lines a counting script recorded so far.
    fn counter_lines(counter: &Path) -> Vec<String> {
        std::fs::read_to_string(counter)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The fixture's injected environment as the `vars` vector
    /// `cargo_config_for_link_eval` and `link_env_vars` take.
    fn fixture_vars(fixture: &IsolatedProject) -> Vec<(OsString, OsString)> {
        fixture
            .env
            .iter()
            .map(|(key, value)| (OsString::from(key), value.clone()))
            .collect()
    }

    /// The resolution the driver performs: the loaded config, the
    /// build rustc it resolves and the shared `-vV` of its executable —
    /// then [`provision_resolved`] against `pool`, the call a cache row
    /// serves.
    async fn resolve_with_cache(
        fixture: &IsolatedProject,
        tools_dir: &Path,
        pool: &sqlx::SqlitePool,
    ) -> stow_types::error::Result<Vec<String>> {
        let vars = fixture_vars(fixture);
        let loaded = fixture.config();
        let build_rustc = BuildRustc::from_cargo_config(&loaded);
        let env_map = link_env_vars(vars, wraps_stow_rustc(&loaded));
        let env = fixture.env();
        let shared_vv = crate::rustc_args::shared_rustc_vv(build_rustc.executable().to_os_string());
        let ctx = LinkResolutionContext {
            cargo_dir: &fixture.project,
            cargo_home: Some(&fixture.cargo_home),
            target: LINUX_TARGET,
            env_map: &env_map,
            env: &env,
            build_rustc: &build_rustc,
            rustc_vv: &shared_vv,
        };
        provision_resolved(loaded, &ctx, tools_dir, Some(pool)).await
    }

    /// The counting fixture: a fake rustc as `RUSTC` and a fake `cc`
    /// reachable through the injected `PATH` — never the process's — so
    /// every probe the resolution runs leaves a line, and no test
    /// touches the environment its siblings share (stow#608).
    struct CountingFixture {
        tools: tempfile::TempDir,
        /// The state DB's parent — field position only keeps it alive.
        _cache: tempfile::TempDir,
        /// The mold install root handed to the resolution.
        tools_root: tempfile::TempDir,
        fixture: IsolatedProject,
        pool: sqlx::SqlitePool,
        rustc_counter: PathBuf,
        cc_counter: PathBuf,
    }

    /// A counting fake rustc as `RUSTC`, a counting `stow-fake-cc` as
    /// the configured driver, and `PATH` carrying the tools dir so the
    /// driver's bare name resolves under the injected environment —
    /// `-fuse-ld=mold` resolves without linking anything.
    async fn counting_fixture() -> CountingFixture {
        let tools = tempfile::tempdir().expect("tools");
        let rustc_counter = tools.path().join("rustc.count");
        let cc_counter = tools.path().join("cc.count");
        let fake_rustc = counting_script(
            tools.path(),
            "fake-rustc",
            &rustc_counter,
            "exec rustc \"$@\"",
        );
        // A uniquely named driver: the configured `linker`'s basename
        // becomes the probe's program name, so the fake never shadows
        // the machine's real `cc`. Its `-print-prog-name` answer comes
        // from `COMPILER_PATH` the way a real driver's does — the bare
        // name back when nothing there resolves.
        counting_script(
            tools.path(),
            "stow-fake-cc",
            &cc_counter,
            "for arg in \"$@\"; do case \"$arg\" in -print-prog-name=*) \
             prog=\"${arg#-print-prog-name=}\"; found=\"$prog\"; \
             OLDIFS=\"$IFS\"; IFS=':'; \
             for d in $COMPILER_PATH; do [ -f \"$d/$prog\" ] && found=\"$d/$prog\" && break; done; \
             IFS=\"$OLDIFS\"; echo \"$found\"; exit 0;; esac; done; exit 0",
        );
        let mut fixture = isolated_project(&format!(
            "[target.'cfg(target_os = \"linux\")']\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n\n[target.{LINUX_TARGET}]\nlinker = \"stow-fake-cc\"\n",
        ));
        fixture
            .env
            .insert("RUSTC".to_owned(), fake_rustc.into_os_string());
        // The injected PATH: the tools dir first so `stow-fake-cc`
        // resolves, the process's after so nothing else changes.
        let mut entries = vec![tools.path().to_path_buf()];
        if let Some(path) = std::env::var_os("PATH") {
            entries.extend(std::env::split_paths(&path));
        }
        fixture.env.insert(
            "PATH".to_owned(),
            std::env::join_paths(entries).expect("join PATH"),
        );
        let cache = tempfile::tempdir().expect("cache");
        let tools_root = tempfile::tempdir().expect("tools root");
        let pool = crate::state_db::connect(cache.path())
            .await
            .expect("state db");
        CountingFixture {
            tools,
            _cache: cache,
            tools_root,
            fixture,
            pool,
            rustc_counter,
            cc_counter,
        }
    }

    /// A warm row answers without a single probe: the second call spawns
    /// neither `rustc --print cfg` (the `target.<cfg>` evaluation) nor
    /// the driver's `-fuse-ld=mold` link probe.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_cache_hit_skips_both_probes() {
        let fx = counting_fixture().await;
        let args = resolve_with_cache(&fx.fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("first resolution");
        assert_eq!(args, Vec::<String>::new());
        let cfg_after_first = counter_lines(&fx.rustc_counter)
            .into_iter()
            .filter(|line| line.contains("--print"))
            .count();
        assert_eq!(cfg_after_first, 1, "cold key runs one cfg evaluation");
        assert_eq!(
            counter_lines(&fx.cc_counter).len(),
            2,
            "cold key runs the mold probe and the record-time witness query"
        );

        let args = resolve_with_cache(&fx.fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("second resolution");
        assert_eq!(args, Vec::<String>::new());
        let cfg_after_second = counter_lines(&fx.rustc_counter)
            .into_iter()
            .filter(|line| line.contains("--print"))
            .count();
        assert_eq!(cfg_after_second, 1, "warm key runs no cfg evaluation");
        assert_eq!(
            counter_lines(&fx.cc_counter).len(),
            2,
            "warm key runs no mold probe"
        );
    }

    /// Each key input that changes is a different key: a config file's
    /// content, an environment variable, and the probed executable each
    /// miss and re-probe.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_changed_key_input_misses_the_cache() {
        let fx = counting_fixture().await;
        resolve_with_cache(&fx.fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("cold resolution");

        // A config document's content.
        let mut fixture = fx.fixture;
        std::fs::write(
            fixture.project.join(".cargo/config.toml"),
            format!(
                "[target.'cfg(target_os = \"linux\")']\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\", \"-C\", \"link-arg=-Wl,-O2\"]\n\n[target.{LINUX_TARGET}]\nlinker = \"stow-fake-cc\"\n"
            ),
        )
        .expect("rewrite config");
        resolve_with_cache(&fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("changed config document");
        assert_eq!(
            counter_lines(&fx.rustc_counter)
                .into_iter()
                .filter(|line| line.contains("--print"))
                .count(),
            2,
            "a changed config document re-probes"
        );
        assert_eq!(counter_lines(&fx.cc_counter).len(), 4);

        // An environment variable the resolution reads.
        fixture.env.insert(
            "RUSTFLAGS".to_owned(),
            OsString::from("-C link-arg=-fuse-ld=mold -Copt-level=3"),
        );
        resolve_with_cache(&fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("changed env var");
        assert_eq!(
            counter_lines(&fx.rustc_counter)
                .into_iter()
                .filter(|line| line.contains("--print"))
                .count(),
            3,
            "a changed env var re-probes"
        );
        assert_eq!(counter_lines(&fx.cc_counter).len(), 6);

        // The probed executable itself.
        fixture.env.remove("RUSTFLAGS");
        let cc = fx.tools.path().join("stow-fake-cc");
        let mut script = std::fs::read_to_string(&cc).expect("read cc");
        // A longer body is a different file at a different size — the
        // witness catches it without an mtime wait.
        script.push_str("# a different driver body\n");
        std::fs::write(&cc, script).expect("rewrite cc");
        resolve_with_cache(&fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("changed driver");
        assert_eq!(
            counter_lines(&fx.cc_counter).len(),
            8,
            "a changed probed executable re-probes"
        );

        // `PATH` is digested — the search order the witnesses were
        // recorded under — so the same inputs under a different `PATH`
        // are a different key and re-probe.
        let extra = tempfile::tempdir().expect("extra PATH dir");
        let mut entries = vec![extra.path().to_path_buf()];
        entries.extend(std::env::split_paths(&fixture.env["PATH"].clone()));
        fixture.env.insert(
            "PATH".to_owned(),
            std::env::join_paths(entries).expect("join PATH"),
        );
        resolve_with_cache(&fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("changed PATH");
        assert_eq!(
            counter_lines(&fx.cc_counter).len(),
            10,
            "a changed PATH re-probes"
        );

        // A config document appearing in an ancestor directory changes
        // the document set — a different key, so it re-probes.
        let prints_before_ancestor = counter_lines(&fx.rustc_counter)
            .into_iter()
            .filter(|line| line.contains("--print"))
            .count();
        let ancestor = fixture.tempdir.path().join(".cargo");
        std::fs::create_dir_all(&ancestor).expect("ancestor .cargo");
        std::fs::write(
            ancestor.join("config.toml"),
            "[target.'cfg(target_os = \"linux\")']\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n\n[target.x86_64-unknown-linux-gnu]\nlinker = \"stow-fake-cc\"\n",
        )
        .expect("write ancestor config");
        resolve_with_cache(&fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("ancestor document");
        assert_eq!(
            counter_lines(&fx.rustc_counter)
                .into_iter()
                .filter(|line| line.contains("--print"))
                .count(),
            prints_before_ancestor + 1,
            "a document appearing in an ancestor directory re-probes"
        );
    }

    /// Two invocation directories with no config of their own digest the
    /// same document set — only the global file — so the second
    /// resolution is a hit, not a re-probe. The mold wiring lives in
    /// the global config here precisely so a config-less resolution
    /// still pays the probes on a miss and the counters can tell hit
    /// from miss (stow#608).
    #[cfg(unix)]
    #[tokio::test]
    async fn config_less_directories_share_one_key() {
        let fx = counting_fixture().await;
        let fixture = &fx.fixture;
        std::fs::write(
            fixture.cargo_home.join("config.toml"),
            std::fs::read_to_string(fixture.project.join(".cargo/config.toml"))
                .expect("read project config"),
        )
        .expect("write global config");
        std::fs::remove_file(fixture.project.join(".cargo/config.toml"))
            .expect("drop the project config");
        resolve_with_cache(fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("config-less resolution");
        let prints = counter_lines(&fx.rustc_counter)
            .into_iter()
            .filter(|line| line.contains("--print"))
            .count();
        let spawns = counter_lines(&fx.cc_counter).len();
        assert_eq!((prints, spawns), (1, 2), "cold key ran the probes");

        // A bare directory elsewhere: no `.cargo` in it or above it, so
        // its document set is the same global file — the shared key.
        let bare_dir = tempfile::tempdir().expect("bare tempdir");
        let bare = IsolatedProject {
            project: bare_dir.path().to_path_buf(),
            tempdir: bare_dir,
            cargo_home: fixture.cargo_home.clone(),
            env: fixture.env.clone(),
        };
        resolve_with_cache(&bare, fx.tools_root.path(), &fx.pool)
            .await
            .expect("shared-key resolution");
        assert_eq!(
            counter_lines(&fx.rustc_counter)
                .into_iter()
                .filter(|line| line.contains("--print"))
                .count(),
            prints,
            "a config-less directory in another path shares the key"
        );
        assert_eq!(
            counter_lines(&fx.cc_counter).len(),
            spawns,
            "the shared key skips the mold probe too"
        );
    }

    /// stow#608: a failed resolution is never recorded — a `rustc`
    /// whose `--print cfg` fails selects mold by default, and a driver
    /// that finds no `ld.mold` falls through to an install that fails;
    /// neither answer may write a row. The next build pays the probes
    /// again instead of inheriting a guess.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_resolution_is_never_cached() {
        async fn rows(pool: &sqlx::SqlitePool) -> i64 {
            let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM link_resolution_cache")
                .fetch_one(pool)
                .await
                .expect("count rows");
            count
        }

        // (a) `--print cfg` fails while `-vV` succeeds: the selection
        // answered by default, so even a probe-resolved `args = []` is
        // not written — and the second call pays the probe again.
        let fx = counting_fixture().await;
        let cfg_fail = counting_script(
            fx.tools.path(),
            "cfg-fail-rustc",
            &fx.rustc_counter,
            "case \"$*\" in *--print*) exit 1;; *) exec rustc \"$@\";; esac",
        );
        // The cfg-unreadable selection cannot read the configured linker
        // either, so the probe falls back to the platform `cc` — a fake
        // `cc` on the injected PATH keeps the probe off the machine's
        // real toolchain.
        counting_script(fx.tools.path(), "cc", &fx.cc_counter, "exit 0");
        let mut fixture = fx.fixture;
        fixture
            .env
            .insert("RUSTC".to_owned(), cfg_fail.into_os_string());
        let args = resolve_with_cache(&fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("the default answer still resolves");
        assert_eq!(args, Vec::<String>::new());
        assert_eq!(
            rows(&fx.pool).await,
            0,
            "a cfg-unreadable answer is not recorded"
        );
        let prints_before = counter_lines(&fx.rustc_counter)
            .into_iter()
            .filter(|line| line.contains("--print"))
            .count();
        resolve_with_cache(&fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("second resolution");
        assert!(
            counter_lines(&fx.rustc_counter)
                .into_iter()
                .filter(|line| line.contains("--print"))
                .count()
                > prints_before,
            "no row means the second call pays the cfg probe again"
        );
        assert_eq!(rows(&fx.pool).await, 0, "still no row");

        // (b) the probes ran but the install failed: the driver finds no
        // `ld.mold`, `ensure_mold_install` errors out, and no row is
        // written — the failure is reported live every time.
        let fx = counting_fixture().await;
        let cc = fx.tools.path().join("stow-fake-cc");
        let script = std::fs::read_to_string(&cc)
            .expect("read cc")
            .replace("exit 0", "exit 1");
        std::fs::write(&cc, script).expect("rewrite cc");
        // An install root below a regular file fails `ensure_mold_install`
        // deterministically — the download's unpack cannot create the
        // directory, and an unreachable network fails even earlier.
        let blocker = tempfile::NamedTempFile::new().expect("blocker file");
        let tools_root = blocker.path().join("tools");
        let error = resolve_with_cache(&fx.fixture, &tools_root, &fx.pool)
            .await
            .expect_err("the failed install fails the resolution");
        assert_eq!(
            rows(&fx.pool).await,
            0,
            "{error}: a failed resolution is never cached"
        );
        assert_eq!(
            counter_lines(&fx.cc_counter).len(),
            2,
            "the mold probe and the record-time query ran before the failure"
        );
    }

    /// stow#608: the evaluation runs the build's rustc, not the rustc
    /// `cargo-config2` would resolve beside `$CARGO` — `build.rustc`
    /// pinned to it — and never through stow's own wrapper, which would
    /// boot the standalone wrapper once per `cfg()` table read.
    #[test]
    fn the_eval_config_runs_the_build_rustc_without_the_wrapper() {
        let fixture = isolated_project("[build]\nrustc-wrapper = \"stow-rustc-wrapper\"\n");
        let build_rustc = BuildRustc::Configured(OsString::from("/toolchain/build-rustc"));
        let config = link_eval_config(&fixture.config(), &build_rustc);
        assert_eq!(config.rustc().path, PathBuf::from("/toolchain/build-rustc"));
        assert_eq!(config.rustc().args, Vec::<OsString>::new());
    }

    /// stow#608: the record-time `ld.mold` query runs the probe's own
    /// environment — the resolved driver, the `-B` prefixes and the
    /// effective `COMPILER_PATH` — so a `ld.mold` the driver can only
    /// reach through them is among the recorded witnesses.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_ld_mold_query_runs_the_probes_environment() {
        let fx = counting_fixture().await;
        let mut fixture = fx.fixture;
        // A `ld.mold` reachable only through `COMPILER_PATH`, and a `-B`
        // prefix both driver invocations must carry.
        let mold_dir = tempfile::tempdir().expect("mold dir");
        std::fs::write(mold_dir.path().join("ld.mold"), "").expect("ld.mold");
        let b_dir = tempfile::tempdir().expect("-B dir");
        std::fs::write(
            fixture.project.join(".cargo/config.toml"),
            format!(
                "[target.'cfg(target_os = \"linux\")']\nrustflags = [\"-C\", \"link-arg=-fuse-ld=mold\", \"-C\", \"link-arg=-B{}\"]\n\n[target.{LINUX_TARGET}]\nlinker = \"stow-fake-cc\"\n",
                b_dir.path().display(),
            ),
        )
        .expect("write config");
        fixture.env.insert(
            "COMPILER_PATH".to_owned(),
            mold_dir.path().as_os_str().to_os_string(),
        );
        let args = resolve_with_cache(&fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("resolution");
        assert_eq!(args, Vec::<String>::new());
        let lines = counter_lines(&fx.cc_counter);
        assert_eq!(
            lines.len(),
            2,
            "the mold probe and the record-time query ran"
        );
        for line in &lines {
            assert!(
                line.contains(&format!("-B{}", b_dir.path().display())),
                "{line}: the query must carry the probe's -B prefixes"
            );
            assert!(
                line.contains(&format!("COMPILER_PATH={}", mold_dir.path().display())),
                "{line}: the query must carry the probe's COMPILER_PATH"
            );
        }
        let (witnesses_json,): (String,) =
            sqlx::query_as("SELECT witnesses_json FROM link_resolution_cache")
                .fetch_one(&fx.pool)
                .await
                .expect("recorded row");
        let witnesses: Vec<FileWitness> =
            serde_json::from_str(&witnesses_json).expect("decode witnesses");
        assert!(
            witnesses
                .iter()
                .any(|witness| witness.path == mold_dir.path().join("ld.mold") && witness.exists),
            "the ld.mold reachable only through COMPILER_PATH is witnessed"
        );
    }

    /// stow#608: the horizon bounds only how long rows under dead keys
    /// accumulate — a live row never expires: an aged row still answers
    /// its own key with no probe, and recording another key prunes it.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_aged_row_still_answers_and_a_later_record_prunes_it() {
        let fx = counting_fixture().await;
        resolve_with_cache(&fx.fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("cold resolution");
        sqlx::query("UPDATE link_resolution_cache SET created_at_ms = 0")
            .execute(&fx.pool)
            .await
            .expect("age the row");
        let prints_before = counter_lines(&fx.rustc_counter)
            .into_iter()
            .filter(|line| line.contains("--print"))
            .count();
        let spawns_before = counter_lines(&fx.cc_counter).len();
        let args = resolve_with_cache(&fx.fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("the aged row still answers");
        assert_eq!(args, Vec::<String>::new());
        assert_eq!(
            counter_lines(&fx.rustc_counter)
                .into_iter()
                .filter(|line| line.contains("--print"))
                .count(),
            prints_before,
            "the aged row answers its key with no cfg evaluation"
        );
        assert_eq!(
            counter_lines(&fx.cc_counter).len(),
            spawns_before,
            "the aged row answers its key with no mold probe"
        );
        // A different key's record is what prunes the dead row.
        let mut fixture = fx.fixture;
        fixture.env.insert(
            "RUSTFLAGS".to_owned(),
            OsString::from("-C link-arg=-fuse-ld=mold -Copt-level=3"),
        );
        resolve_with_cache(&fixture, fx.tools_root.path(), &fx.pool)
            .await
            .expect("the new key resolves cold");
        let (rows,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM link_resolution_cache")
            .fetch_one(&fx.pool)
            .await
            .expect("count rows");
        assert_eq!(rows, 1, "recording the new key pruned the aged row");
    }
}

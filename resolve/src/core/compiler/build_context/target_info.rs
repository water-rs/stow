//! This modules contains types storing information of target platforms.
//!
//! Normally, call [`RustcTargetData::new`] to construct all the target
//! platform once, and then query info on your demand. For example,
//!
//! * [`RustcTargetData::dep_platform_activated`] to check if platform is activated.
//! * [`RustcTargetData::info`] to get a [`TargetInfo`] for an in-depth query.
//! * [`TargetInfo::rustc_outputs`] to get a list of supported file types.

use crate::core::compiler::CompileKind;
use crate::core::compiler::CompileTarget;
use crate::core::{Dependency, Package, Workspace};
use crate::util::context::{GlobalContext, StringList, TargetConfig};
use crate::util::interning::InternedString;
use crate::util::{CargoResult, Rustc};

use cargo_platform::{Cfg, CfgExpr};

use std::collections::hash_map::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::str;

/// Information about the platform target gleaned from querying rustc.
///
/// [`RustcTargetData`] keeps several of these, one for the host and the others
/// for other specified targets. If no target is specified, it uses a clone from
/// the host.
#[derive(Clone)]
pub struct TargetInfo {
    /// `cfg` information extracted from `rustc --print=cfg`.
    cfg: Vec<Cfg>,
    /// `supports_std` information extracted from `rustc --print=target-spec-json`
    pub supports_std: Option<bool>,
    /// Supported values for `-Csplit-debuginfo=` flag, queried from rustc
    support_split_debuginfo: Vec<String>,
    /// Path to the sysroot.
    pub sysroot: PathBuf,
    /// Path to the "lib" directory in the sysroot which rustc uses for linking
    /// target libraries.
    pub sysroot_target_libdir: PathBuf,
    /// Extra flags to pass to `rustc`, see [`extra_args`].
    pub rustflags: Rc<[String]>,
    /// Extra flags to pass to `rustdoc`, see [`extra_args`].
    pub rustdocflags: Rc<[String]>,
}

impl TargetInfo {
    /// Learns the information of target platform from `rustc` invocation(s).
    ///
    /// Generally, the first time calling this function is expensive, as it may
    /// query `rustc` several times. To reduce the cost, output of each `rustc`
    /// invocation is cached by [`Rustc::cached_output`].
    ///
    /// Constructs a [`TargetInfo`] from injected `rustc --print=cfg` output
    /// rather than querying rustc. The rustflags fixed-point computation runs
    /// exactly as in [`TargetInfo::new`] — only the probe is replaced, which
    /// is what makes this constructor usable on wasm where no rustc exists.
    ///
    /// `sysroot`/`sysroot_target_libdir`/`crate_type` outputs belong to the
    /// build path, which this crate never executes; they are left empty
    /// rather than fabricated.
    pub fn new_injected(
        gctx: &GlobalContext,
        requested_kinds: &[CompileKind],
        rustc: &Rustc,
        kind: CompileKind,
        cfg: Vec<Cfg>,
    ) -> CargoResult<TargetInfo> {
        let mut rustflags =
            extra_args(gctx, requested_kinds, &rustc.host, None, kind, Flags::Rust)?;
        let new_flags = extra_args(
            gctx,
            requested_kinds,
            &rustc.host,
            Some(&cfg),
            kind,
            Flags::Rust,
        )?;
        if new_flags != rustflags {
            let reparsed = extra_args(
                gctx,
                requested_kinds,
                &rustc.host,
                Some(&cfg),
                kind,
                Flags::Rust,
            )?;
            if reparsed != rustflags {
                gctx.shell().warn("non-trivial mutual dependency between target-specific configuration and RUSTFLAGS")?;
            }
            rustflags = reparsed;
        }
        Ok(TargetInfo {
            sysroot: PathBuf::new(),
            sysroot_target_libdir: PathBuf::new(),
            rustflags: rustflags.into(),
            rustdocflags: extra_args(
                gctx,
                requested_kinds,
                &rustc.host,
                Some(&cfg),
                kind,
                Flags::Rustdoc,
            )?
            .into(),
            cfg,
            supports_std: None,
            support_split_debuginfo: Vec::new(),
        })
    }

    fn not_user_specific_cfg(cfg: &CargoResult<Cfg>) -> bool {
        if let Ok(Cfg::Name(cfg_name)) = cfg {
            // This should also include "debug_assertions", but it causes
            // regressions. Maybe some day in the distant future it can be
            // added (and possibly change the warning to an error).
            if cfg_name == "proc_macro" {
                return false;
            }
        }
        true
    }

    /// All the target [`Cfg`] settings.
    pub fn cfg(&self) -> &[Cfg] {
        &self.cfg
    }

    /// Checks if the debuginfo-split value is supported by this target
    pub fn supports_debuginfo_split(&self, split: InternedString) -> bool {
        self.support_split_debuginfo
            .iter()
            .any(|sup| sup.as_str() == split.as_str())
    }

    /// Checks if a target maybe support std.
    ///
    /// If no explicitly stated in target spec json, we treat it as "maybe support".
    ///
    /// This is only useful for `-Zbuild-std` to determine the default set of
    /// crates it is going to build.
    pub fn maybe_support_std(&self) -> bool {
        matches!(self.supports_std, Some(true) | None)
    }
}

/// Compiler flags for either rustc or rustdoc.
#[derive(Debug, Copy, Clone)]
enum Flags {
    Rust,
    Rustdoc,
}

impl Flags {
    fn as_key(self) -> &'static str {
        match self {
            Flags::Rust => "rustflags",
            Flags::Rustdoc => "rustdocflags",
        }
    }

    fn as_env(self) -> &'static str {
        match self {
            Flags::Rust => "RUSTFLAGS",
            Flags::Rustdoc => "RUSTDOCFLAGS",
        }
    }
}

/// Acquire extra flags to pass to the compiler from various locations.
///
/// The locations are:
///
///  - the `CARGO_ENCODED_RUSTFLAGS` environment variable
///  - the `RUSTFLAGS` environment variable
///
/// then if none of those were found
///
///  - `target.*.rustflags` from the config (.cargo/config)
///  - `target.cfg(..).rustflags` from the config
///  - `host.*.rustflags` from the config if compiling a host artifact or without `--target`
///     (requires `-Zhost-config`)
///
/// then if none of those were found
///
///  - `build.rustflags` from the config
///
/// The behavior differs slightly when cross-compiling (or, specifically, when `--target` is
/// provided) for artifacts that are always built for the host (plugins, build scripts, ...).
/// For those artifacts, _only_ `host.*.rustflags` is respected, and no other configuration
/// sources, _regardless of the value of `target-applies-to-host`_. This is counterintuitive, but
/// necessary to retain backwards compatibility with older versions of Cargo.
///
/// Rules above also applies to rustdoc. Just the key would be `rustdocflags`/`RUSTDOCFLAGS`.
fn extra_args(
    gctx: &GlobalContext,
    requested_kinds: &[CompileKind],
    host_triple: &str,
    target_cfg: Option<&[Cfg]>,
    kind: CompileKind,
    flags: Flags,
) -> CargoResult<Vec<String>> {
    if host_artifact_uses_only_host_config(gctx, requested_kinds, kind)? {
        return Ok(rustflags_from_host(gctx, flags, host_triple)?.unwrap_or_else(Vec::new));
    }

    // All other artifacts pick up the RUSTFLAGS, [target.*], and [build], in that order.
    // NOTE: It is impossible to have a [host] section and reach this logic with kind.is_host(),
    // since [host] implies `target-applies-to-host = false`, which always early-returns above.

    if let Some(rustflags) = rustflags_from_env(gctx, flags) {
        Ok(rustflags)
    } else if let Some(rustflags) =
        rustflags_from_target(gctx, host_triple, target_cfg, kind, flags)?
    {
        Ok(rustflags)
    } else if let Some(rustflags) = rustflags_from_build(gctx, flags)? {
        Ok(rustflags)
    } else {
        Ok(Vec::new())
    }
}

/// `extra_args` restricted to `Flags::Rust` — the rustflags a `kind` unit
/// compiles with. Upstream pipes these into `rustc --print cfg` (among
/// other probes); a resolve that replaces the probe reads the `--cfg`
/// values out of this list itself.
pub(crate) fn effective_rustflags(
    gctx: &GlobalContext,
    requested_kinds: &[CompileKind],
    host_triple: &str,
    target_cfg: Option<&[Cfg]>,
    kind: CompileKind,
) -> CargoResult<Vec<String>> {
    extra_args(
        gctx,
        requested_kinds,
        host_triple,
        target_cfg,
        kind,
        Flags::Rust,
    )
}

/// Gets compiler flags from environment variables.
/// See [`extra_args`] for more.
fn rustflags_from_env(gctx: &GlobalContext, flags: Flags) -> Option<Vec<String>> {
    // First try CARGO_ENCODED_RUSTFLAGS from the environment.
    // Prefer this over RUSTFLAGS since it's less prone to encoding errors.
    if let Ok(a) = gctx.get_env(format!("CARGO_ENCODED_{}", flags.as_env())) {
        if a.is_empty() {
            return Some(Vec::new());
        }
        return Some(a.split('\x1f').map(str::to_string).collect());
    }

    // Then try RUSTFLAGS from the environment
    if let Ok(a) = gctx.get_env(flags.as_env()) {
        let args = a
            .split(' ')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        return Some(args.collect());
    }

    // No rustflags to be collected from the environment
    None
}

/// Gets compiler flags from `[target]` section in the config.
/// See [`extra_args`] for more.
fn rustflags_from_target(
    gctx: &GlobalContext,
    host_triple: &str,
    target_cfg: Option<&[Cfg]>,
    kind: CompileKind,
    flag: Flags,
) -> CargoResult<Option<Vec<String>>> {
    let mut rustflags = Vec::new();

    // Then the target.*.rustflags value...
    let target = match &kind {
        CompileKind::Host => host_triple,
        CompileKind::Target(target) => target.short_name(),
    };
    let key = format!("target.{}.{}", target, flag.as_key());
    if let Some(args) = gctx.get::<Option<StringList>>(&key)? {
        rustflags.extend(args.as_slice().iter().cloned());
    }
    // ...including target.'cfg(...)'.rustflags
    if let Some(target_cfg) = target_cfg {
        gctx.target_cfgs()?
            .iter()
            .filter_map(|(key, cfg)| match flag {
                Flags::Rust => cfg
                    .rustflags
                    .as_ref()
                    .map(|rustflags| (key, &rustflags.val)),
                Flags::Rustdoc => cfg
                    .rustdocflags
                    .as_ref()
                    .map(|rustdocflags| (key, &rustdocflags.val)),
            })
            .filter(|(key, _rustflags)| CfgExpr::matches_key(key, target_cfg))
            .for_each(|(_key, cfg_rustflags)| {
                rustflags.extend(cfg_rustflags.as_slice().iter().cloned());
            });
    }

    if rustflags.is_empty() {
        Ok(None)
    } else {
        Ok(Some(rustflags))
    }
}

/// Gets compiler flags from `[host]` section in the config.
/// See [`extra_args`] for more.
fn rustflags_from_host(
    gctx: &GlobalContext,
    flag: Flags,
    host_triple: &str,
) -> CargoResult<Option<Vec<String>>> {
    let target_cfg = gctx.host_cfg_triple(host_triple)?;
    let list = match flag {
        Flags::Rust => &target_cfg.rustflags,
        Flags::Rustdoc => {
            // host.rustdocflags is not a thing, since it does not make sense
            return Ok(None);
        }
    };
    Ok(list.as_ref().map(|l| l.val.as_slice().to_vec()))
}

/// Gets compiler flags from `[build]` section in the config.
/// See [`extra_args`] for more.
fn rustflags_from_build(gctx: &GlobalContext, flag: Flags) -> CargoResult<Option<Vec<String>>> {
    // Then the `build.rustflags` value.
    let build = gctx.build_config()?;
    let list = match flag {
        Flags::Rust => &build.rustflags,
        Flags::Rustdoc => &build.rustdocflags,
    };
    Ok(list.as_ref().map(|l| l.as_slice().to_vec()))
}

/// Whether a host artifact must take its configuration solely from `[host]` and ignore `[target]`.
fn host_artifact_uses_only_host_config(
    gctx: &GlobalContext,
    requested_kinds: &[CompileKind],
    kind: CompileKind,
) -> CargoResult<bool> {
    let target_applies_to_host = gctx.target_applies_to_host()?;

    // Host artifacts should not generally pick up rustflags from anywhere except [host].
    //
    // The one exception to this is if `target-applies-to-host = true`, which opts into a
    // particular (inconsistent) past Cargo behavior where host artifacts _do_ pick up rustflags
    // set elsewhere when `--target` isn't passed.
    if kind.is_host() {
        if target_applies_to_host && requested_kinds == [CompileKind::Host] {
            // This is the past Cargo behavior where we fall back to the same logic as for other
            // artifacts without --target.
        } else {
            // In all other cases, host artifacts just get flags from [host], regardless of
            // --target. Or, phrased differently, no `--target` behaves the same as `--target
            // <host>`, and host artifacts are always "special" (they don't pick up `RUSTFLAGS` for
            // example).
            return Ok(true);
        }
    }

    Ok(false)
}

/// Collection of information about `rustc` and the host and target.
pub struct RustcTargetData<'gctx> {
    /// Information about `rustc` itself.
    pub rustc: Rustc,

    /// Config
    pub gctx: &'gctx GlobalContext,
    requested_kinds: Vec<CompileKind>,

    /// Build information for the "host", which is information about when
    /// `rustc` is invoked without a `--target` flag. This is used for
    /// selecting a linker, and applying link overrides.
    ///
    /// The configuration read into this depends on whether or not
    /// `target-applies-to-host=true`.
    host_config: TargetConfig,
    /// Information about the host platform.
    host_info: TargetInfo,

    /// Build information for targets that we're building for.
    target_config: HashMap<CompileTarget, TargetConfig>,
    /// Information about the target platform that we're building for.
    target_info: HashMap<CompileTarget, TargetInfo>,

    /// Supplies `rustc --print=cfg` output per [`CompileKind`] — the probe
    /// [`TargetInfo::new`] ran upstream is injected (see
    /// [`RustcTargetData::new_injected`]).
    cfg_source: Rc<dyn Fn(CompileKind) -> CargoResult<Vec<Cfg>> + 'gctx>,
}

impl<'gctx> RustcTargetData<'gctx> {
    /// Takes `rustc --print=cfg` output from `cfg_source` — the rustc probe
    /// [`TargetInfo::new`] ran upstream is injected here instead, everything
    /// else (target config resolution, host/target bookkeeping) unchanged.
    ///
    /// `cfg_source` is consulted lazily so that artifact dependencies can pull
    /// in extra targets mid-resolve via [`RustcTargetData::merge_compile_kind`].
    pub fn new_injected(
        ws: &Workspace<'gctx>,
        requested_kinds: &[CompileKind],
        cfg_source: Rc<dyn Fn(CompileKind) -> CargoResult<Vec<Cfg>> + 'gctx>,
    ) -> CargoResult<RustcTargetData<'gctx>> {
        let gctx = ws.gctx();
        let rustc = gctx.load_global_rustc(Some(ws))?;
        let info_for = |kind: CompileKind, rustc: &Rustc| -> CargoResult<TargetInfo> {
            TargetInfo::new_injected(gctx, requested_kinds, rustc, kind, cfg_source(kind)?)
        };
        let mut target_config = HashMap::new();
        let mut target_info = HashMap::new();
        let target_applies_to_host = gctx.target_applies_to_host()?;
        let host_target = CompileTarget::new(&rustc.host, gctx.cli_unstable().json_target_spec)?;
        let host_info = info_for(CompileKind::Host, &rustc)?;

        // This config is used for link overrides and choosing a linker.
        let host_config = if target_applies_to_host {
            gctx.target_cfg_triple(&rustc.host)?
        } else {
            gctx.host_cfg_triple(&rustc.host)?
        };

        // This is a hack. The unit_dependency graph builder "pretends" that
        // `CompileKind::Host` is `CompileKind::Target(host)` if the
        // `--target` flag is not specified. Since the unit_dependency code
        // needs access to the target config data, create a copy so that it
        // can be found. See `rebuild_unit_graph_shared` for why this is done.
        if requested_kinds.iter().any(CompileKind::is_host) {
            target_config.insert(host_target, gctx.target_cfg_triple(&rustc.host)?);

            // If target_applies_to_host is true, the host_info is the target info,
            // otherwise we need to build target info for the target.
            if target_applies_to_host {
                target_info.insert(host_target, host_info.clone());
            } else {
                let host_target_info = info_for(CompileKind::Target(host_target), &rustc)?;
                target_info.insert(host_target, host_target_info);
            }
        };

        let mut res = RustcTargetData {
            rustc,
            gctx,
            requested_kinds: requested_kinds.into(),
            host_config,
            host_info,
            target_config,
            target_info,
            cfg_source,
        };

        // Get all kinds we currently know about.
        //
        // For now, targets can only ever come from the root workspace
        // units and artifact dependencies, so this
        // correctly represents all the kinds that can happen. When we have
        // other ways for targets to appear at places that are not the root units,
        // we may have to revisit this.
        fn artifact_targets(package: &Package) -> impl Iterator<Item = CompileKind> + '_ {
            package
                .manifest()
                .dependencies()
                .iter()
                .filter_map(|d| d.artifact()?.target()?.to_compile_kind())
        }
        let all_kinds = requested_kinds
            .iter()
            .copied()
            .chain(ws.members().flat_map(|p| {
                p.manifest()
                    .default_kind()
                    .into_iter()
                    .chain(p.manifest().forced_kind())
                    .chain(artifact_targets(p))
            }));
        for kind in all_kinds {
            res.merge_compile_kind(kind)?;
        }

        Ok(res)
    }

    /// Insert `kind` into our `target_info` and `target_config` members if it isn't present yet.
    pub fn merge_compile_kind(&mut self, kind: CompileKind) -> CargoResult<()> {
        if let CompileKind::Target(target) = kind {
            if !self.target_config.contains_key(&target) {
                self.target_config
                    .insert(target, self.gctx.target_cfg_triple(target.short_name())?);
            }
            if !self.target_info.contains_key(&target) {
                let info = TargetInfo::new_injected(
                    self.gctx,
                    &self.requested_kinds,
                    &self.rustc,
                    kind,
                    (self.cfg_source)(kind)?,
                )?;
                self.target_info.insert(target, info);
            }
        }
        Ok(())
    }

    /// Returns a "short" name for the given kind, suitable for keying off
    /// configuration in Cargo or presenting to users.
    pub fn short_name<'a>(&'a self, kind: &'a CompileKind) -> &'a str {
        match kind {
            CompileKind::Host => &self.rustc.host,
            CompileKind::Target(target) => target.short_name(),
        }
    }

    /// Whether a dependency should be compiled for the host or target platform,
    /// specified by `CompileKind`.
    pub fn dep_platform_activated(&self, dep: &Dependency, kind: CompileKind) -> bool {
        // If this dependency is only available for certain platforms,
        // make sure we're only enabling it for that platform.
        let Some(platform) = dep.platform() else {
            return true;
        };
        let name = self.short_name(&kind);
        platform.matches(name, self.cfg(kind))
    }

    /// Gets the list of `cfg`s printed out from the compiler for the specified kind.
    pub fn cfg(&self, kind: CompileKind) -> &[Cfg] {
        self.info(kind).cfg()
    }

    /// Information about the given target platform, learned by querying rustc.
    ///
    /// # Panics
    ///
    /// Panics, if the target platform described by `kind` can't be found.
    /// See [`get_info`](Self::get_info) for a non-panicking alternative.
    pub fn info(&self, kind: CompileKind) -> &TargetInfo {
        self.get_info(kind).unwrap()
    }

    /// Information about the given target platform, learned by querying rustc.
    ///
    /// Returns `None` if the target platform described by `kind` can't be found.
    pub fn get_info(&self, kind: CompileKind) -> Option<&TargetInfo> {
        match kind {
            CompileKind::Host => Some(&self.host_info),
            CompileKind::Target(s) => self.target_info.get(&s),
        }
    }

    /// Gets the target configuration for a particular host or target.
    pub fn target_config(&self, kind: CompileKind) -> &TargetConfig {
        match kind {
            CompileKind::Host => &self.host_config,
            CompileKind::Target(s) => &self.target_config[&s],
        }
    }

    pub fn get_unsupported_std_targets(&self) -> Vec<&str> {
        let mut unsupported = Vec::new();
        for (target, target_info) in &self.target_info {
            if target_info.supports_std == Some(false) {
                unsupported.push(target.short_name());
            }
        }
        unsupported
    }

    pub fn requested_kinds(&self) -> &[CompileKind] {
        &self.requested_kinds
    }
}

//! A session no driver opened: the build of a plain `cargo build` through
//! the wrappers `stow setup` installed.
//!
//! The first wrapper of a cargo to find no session sends the environment
//! it runs in. Nothing here was settled before cargo started, so
//! [`BuildFacts`] come from that environment and from the request the
//! wrapper was holding: the configuration it loads, the toolchain of the
//! rustc it names and the directories cargo lays that unit's outputs
//! under. The session lives as long as the cargo that started it.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::facts::BuildFacts;
use super::invocation::{OutputRoots, RefusalPolicy};
use super::{Origin, SessionId};
use crate::config::StowConfig;
use crate::daemon::table::{SessionTable, ToolchainKey};
use crate::daemon::wrapper::{BuildEnvironment, InvocationEnv, Request};
use crate::session_env::SessionEnv;
use crate::state_db::StateDb;
use crate::toolchain::BuildToolchain;
use crate::{artifact_cache, miss_journal, rustc_args};

/// What a cargo sets for one unit or one build script run, which the
/// session must not carry: they describe the process that opened it, not
/// the build.
///
/// The list is cargo's documented "environment variables Cargo sets for
/// crates" and "for build scripts". The jobserver variables are among
/// them: a process the daemon starts with the build's jobserver would take
/// job tokens from cargo. `OUT_DIR` and `TARGET` are read for the output
/// directories before they are dropped.
const UNIT_VARIABLES: &[&str] = &[
    "CARGO_MANIFEST_DIR",
    "CARGO_MANIFEST_LINKS",
    "CARGO_PRIMARY_PACKAGE",
    "CARGO_CRATE_NAME",
    "CARGO_BIN_NAME",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_TARGET_TMPDIR",
    "CARGO_MAKEFLAGS",
    "MAKEFLAGS",
    "MFLAGS",
    "OUT_DIR",
    "TARGET",
    "HOST",
    "PROFILE",
    "DEBUG",
    "OPT_LEVEL",
    "NUM_JOBS",
    "CARGO_RUSTC_CURRENT_DIR",
];

/// The prefixes of the variables cargo sets one of per package, feature,
/// cfg, binary or dependency.
const UNIT_VARIABLE_PREFIXES: [&str; 5] = [
    "CARGO_PKG_",
    "CARGO_CFG_",
    "CARGO_FEATURE_",
    "CARGO_BIN_EXE_",
    "DEP_",
];

/// The environment a session carries: the opener's, less what describes
/// only that opener.
fn session_variables(environ: Vec<(OsString, OsString)>) -> Vec<(OsString, OsString)> {
    environ
        .into_iter()
        .filter(|(name, _)| {
            let is = |other: &str| stow_types::env_name::eq(name, other);
            !UNIT_VARIABLES.iter().any(|unit| is(unit))
                && !name.to_str().is_some_and(|name| {
                    UNIT_VARIABLE_PREFIXES
                        .iter()
                        .any(|prefix| name.starts_with(prefix))
                })
        })
        .collect()
}

/// The origin of a session a cargo's own wrapper opened.
#[derive(Debug, Default)]
pub struct Cargo {
    /// The manifest directory of the package cargo was asked to build,
    /// from the first unit that says so: what the drain re-derives the
    /// build's dependency graph from.
    consumer_manifest_dir: OnceLock<PathBuf>,
}

impl Origin for Cargo {
    fn planned(&self, env: &InvocationEnv) {
        if !env.primary_package {
            return;
        }
        if let Ok(Some(manifest_dir)) = env.manifest_dir() {
            // The first unit that names it wins; later ones name the same.
            let _ = self.consumer_manifest_dir.set(manifest_dir);
        }
    }

    fn journal(
        &self,
        build: &BuildFacts,
        id: SessionId,
        observations: &[artifact_cache::ObservedUnit],
    ) -> bool {
        let Some(target_dir) = build.roots.dirs().first() else {
            return false;
        };
        let consumer = miss_journal::JournalConsumer {
            manifest_dir: self.consumer_manifest_dir.get().map(PathBuf::as_path),
            rustc_version: &build.toolchain.release,
            // The consumer's own target is the one its environment names;
            // without one every unit's own `--target` stands for it.
            target: build
                .public_cache_target
                .as_deref()
                .unwrap_or(&build.toolchain.host_target),
            target_given: false,
            key: None,
        };
        miss_journal::journal_session(
            id,
            build.toolchain.launcher.as_os_str(),
            &consumer,
            observations,
            target_dir,
            "",
            &[],
        );
        !observations.is_empty()
    }
}

/// The request a wrapper was holding when it found no session: what shows
/// which rustc and which output directory the build uses.
#[derive(Debug)]
pub enum Opener {
    /// A rustc invocation of a unit.
    Rustc {
        /// The executable cargo ran the wrapper for.
        executable: OsString,
        /// Its arguments.
        args: Vec<OsString>,
    },
    /// A C/C++ compiler invocation of a build script.
    Cc,
}

impl Opener {
    /// The opener a held request is.
    ///
    /// # Errors
    ///
    /// The request is not one a build's first wrapper request can be, or
    /// its encoding does not decode.
    pub fn of(request: &Request) -> Result<Self, String> {
        match request {
            Request::Plan(plan) => Ok(Self::Rustc {
                executable: plan.executable()?,
                args: plan.args()?,
            }),
            Request::CcPolicy | Request::CcLookup(_) | Request::CcCompiled(_) => Ok(Self::Cc),
            Request::Compiled(_) | Request::Describe(_) => {
                Err("a wrapper's first request must ask for a decision, not report one".to_owned())
            }
        }
    }
}

/// The facts of the build `opener` belongs to, from the environment it ran
/// in.
///
/// # Errors
///
/// The environment does not decode, the configuration or the toolchain
/// does not load, or the opener's output directory is outside cargo's
/// layout.
pub async fn open_facts(
    opener: &Opener,
    environment: &BuildEnvironment,
    table: &SessionTable,
) -> Result<BuildFacts, String> {
    let (environ, cwd) = environment.decode()?;
    let opener_env = SessionEnv::new(environ.clone(), cwd.clone());
    let roots = output_roots(opener, &opener_env)?;
    let env = SessionEnv::new(session_variables(environ.clone()), cwd.clone());
    let blocking_env = env.clone();
    let (config, wrapper, registry_sources) = tokio::task::spawn_blocking(move || {
        let config = StowConfig::load_in(&blocking_env, StateDb::default())
            .map_err(|error| format!("load the build's configuration: {error:#}"))?;
        let wrapper = workspace_wrapper(&blocking_env)?;
        let registry_sources = crate::RegistrySources::from_cargo_config(&blocking_env)
            .map_err(|error| format!("read the build's registry sources: {error:#}"))?;
        Ok::<_, String>((config, wrapper, registry_sources))
    })
    .await
    .map_err(|error| format!("join the build's configuration load: {error}"))??;
    let rustc = rustc_of(opener, &opener_env, wrapper.as_deref())?;
    let toolchain = probe_toolchain(&rustc, wrapper, &env, table).await?;
    let public_cache_disabled =
        !crate::cargo_cmd::PublicCacheMode::for_build(toolchain.release(), config.cache)
            .is_enabled();
    Ok(BuildFacts {
        environ: env.environ().to_vec(),
        cwd,
        toolchain: toolchain.facts(),
        public_cache_target: rustc_args::configured_public_cache_target(&env),
        config: Some(config),
        public_cache_disabled,
        roots,
        // A refused request fails its own wrapper, which fails the build:
        // no driver is needed for that.
        refusal_policy: RefusalPolicy::of_this_build(),
        registry_sources,
        // Standalone wrappers added none either: the session applies the
        // output remap itself.
        rustc_extra_args: Vec::new(),
    })
}

/// The `RUSTC_WORKSPACE_WRAPPER` the build's cargo configuration names,
/// from the same chain cargo reads it from.
fn workspace_wrapper(env: &SessionEnv) -> Result<Option<PathBuf>, String> {
    let options = cargo_config2::ResolveOptions::default()
        .cargo_home(env.cargo_home().map(Path::to_path_buf))
        .env(env.environ().iter().cloned());
    cargo_config2::Config::load_with_options(env.cwd(), options)
        .map(|config| config.build.rustc_workspace_wrapper)
        .map_err(|error| format!("load the build's cargo configuration: {error}"))
}

/// The rustc the build compiles with: the executable cargo ran the
/// wrapper for, or — when that is the configured workspace wrapper — the
/// rustc it was handed as its first argument; for a build script's C
/// compiler, the `RUSTC` cargo told the script.
fn rustc_of(
    opener: &Opener,
    env: &SessionEnv,
    workspace_wrapper: Option<&Path>,
) -> Result<OsString, String> {
    match opener {
        Opener::Rustc { executable, args } => {
            let is_wrapper = workspace_wrapper.is_some_and(|wrapper| {
                let identify = |program: &OsStr| {
                    env.resolve_program(program, env.cwd())
                        .ok()
                        .and_then(|path| same_file::Handle::from_path(path).ok())
                };
                identify(wrapper.as_os_str()).is_some_and(|wrapper| {
                    identify(executable).is_some_and(|executable| executable == wrapper)
                })
            });
            if is_wrapper {
                args.first().cloned().ok_or_else(|| {
                    "the workspace wrapper was run without the rustc it wraps".to_owned()
                })
            } else {
                Ok(executable.clone())
            }
        }
        Opener::Cc => env
            .var_os("RUSTC")
            .map(OsStr::to_owned)
            .ok_or_else(|| "the build script's environment names no RUSTC".to_owned()),
    }
}

/// The toolchain of `rustc` in `env`. The `rustc -vV` answer is kept for
/// the rustc file's identity and modification time, but only when the
/// spelling resolves to the toolchain's own rustc: under rustup the proxy
/// in the cargo home answers for whichever toolchain `env` selects, so its
/// answer is the environment's.
async fn probe_toolchain(
    rustc: &OsStr,
    workspace_wrapper: Option<PathBuf>,
    env: &SessionEnv,
    table: &SessionTable,
) -> Result<BuildToolchain, String> {
    let key = toolchain_key(rustc, env).await;
    let remembered = match &key {
        Some(key) => table.toolchain_probe(key.clone()).await,
        None => None,
    };
    let vv = if let Some(vv) = remembered {
        vv
    } else {
        let vv = std::sync::Arc::new(rustc_args::rustc_vv(rustc, env).await?);
        if let Some(key) = key {
            table.remember_toolchain_probe(key, std::sync::Arc::clone(&vv));
        }
        vv
    };
    BuildToolchain::for_opener(rustc, workspace_wrapper, &vv, env).await
}

/// What a remembered `rustc -vV` is keyed by, when it may be remembered.
async fn toolchain_key(rustc: &OsStr, env: &SessionEnv) -> Option<ToolchainKey> {
    let rustc = rustc.to_owned();
    let env = env.clone();
    tokio::task::spawn_blocking(move || {
        let path = env.resolve_program(&rustc, env.cwd()).ok()?;
        // A rustup proxy lives in the cargo home's `bin`.
        if env
            .cargo_home()
            .is_none_or(|home| path.starts_with(home.join("bin")))
        {
            return None;
        }
        let file = same_file::Handle::from_path(&path).ok()?;
        let modified = std::fs::metadata(&path).ok()?.modified().ok()?;
        Some(ToolchainKey::new(file, modified))
    })
    .await
    .ok()
    .flatten()
}

/// The directories the build's compiler outputs live under, from the
/// output directory of the unit that opened the session, by cargo's
/// layout: `<target>[/<triple>]/<profile>/` holds `deps`, `examples` and
/// `build/<package>-<hash>[/out]`.
fn output_roots(opener: &Opener, env: &SessionEnv) -> Result<OutputRoots, String> {
    let (out_dir, target) = match opener {
        Opener::Rustc { args, .. } => (
            rustc_out_dir(args)
                .ok_or_else(|| "the opening rustc invocation names no --out-dir".to_owned())?,
            rustc_target(args),
        ),
        Opener::Cc => (
            env.var_os("OUT_DIR")
                .map(PathBuf::from)
                .ok_or_else(|| "the build script's environment names no OUT_DIR".to_owned())?,
            env.var_os("TARGET")
                .and_then(OsStr::to_str)
                .map(str::to_owned),
        ),
    };
    let out_dir = env.cwd().join(out_dir);
    let root = target_directory(&out_dir, target.as_deref()).ok_or_else(|| {
        format!(
            "{} is not an output directory of cargo's layout (<target>/<profile>/deps or build/<package>)",
            out_dir.display()
        )
    })?;
    Ok(OutputRoots::new(root, None))
}

/// The target directory an output directory of cargo's layout lies in.
fn target_directory(out_dir: &Path, target: Option<&str>) -> Option<PathBuf> {
    let name = out_dir.file_name()?;
    let parent = out_dir.parent()?;
    let profile = if name == "deps" || name == "examples" {
        parent
    } else if parent.file_name()? == "build" {
        parent.parent()?
    } else if name == "out" && parent.parent()?.file_name()? == "build" {
        parent.parent()?.parent()?
    } else {
        return None;
    };
    let root = profile.parent()?;
    // A unit built `--target <triple>` lives one level further down.
    match target {
        Some(triple) if root.file_name() == Some(OsStr::new(triple)) => {
            root.parent().map(Path::to_path_buf)
        }
        _ => Some(root.to_path_buf()),
    }
}

/// The value of `--out-dir`, in either spelling.
fn rustc_out_dir(args: &[OsString]) -> Option<PathBuf> {
    option_value(args, "--out-dir").map(PathBuf::from)
}

/// The value of `--target`, in either spelling.
fn rustc_target(args: &[OsString]) -> Option<String> {
    option_value(args, "--target")?.to_str().map(str::to_owned)
}

fn option_value(args: &[OsString], option: &str) -> Option<OsString> {
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == option {
            return args.next().cloned();
        }
        if let Some(value) = arg
            .to_str()
            .and_then(|arg| arg.strip_prefix(option))
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(OsString::from(value));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use super::{session_variables, target_directory};

    #[test]
    fn a_units_output_directory_names_its_target_directory() {
        let target = Path::new("/proj/target");
        for (out_dir, triple) in [
            ("/proj/target/debug/deps", None),
            ("/proj/target/release-lto/deps", None),
            ("/proj/target/debug/examples", None),
            ("/proj/target/debug/build/serde-0123abcd", None),
            ("/proj/target/debug/build/serde-0123abcd/out", None),
            (
                "/proj/target/wasm32-unknown-unknown/debug/deps",
                Some("wasm32-unknown-unknown"),
            ),
            (
                "/proj/target/aarch64-apple-darwin/debug/build/cc-1/out",
                Some("aarch64-apple-darwin"),
            ),
            // A host unit of a `--target` build has no triple to strip.
            ("/proj/target/debug/deps", Some("wasm32-unknown-unknown")),
        ] {
            assert_eq!(
                target_directory(Path::new(out_dir), triple),
                Some(PathBuf::from(target)),
                "{out_dir}"
            );
        }
    }

    #[test]
    fn a_directory_outside_cargos_layout_has_no_target_directory() {
        for out_dir in ["/tmp/out", "/proj/target", "/", "/proj/target/debug/other"] {
            assert_eq!(
                target_directory(Path::new(out_dir), None),
                None,
                "{out_dir}"
            );
        }
    }

    #[test]
    fn a_session_carries_neither_the_jobserver_nor_the_units_variables() {
        let kept = |name: &str| (OsString::from(name), OsString::from("v"));
        let environ = vec![
            kept("PATH"),
            kept("CARGO"),
            kept("RUSTUP_TOOLCHAIN"),
            kept("STOW_CACHE_DIR"),
            kept("CARGO_MAKEFLAGS"),
            kept("MAKEFLAGS"),
            kept("MFLAGS"),
            kept("CARGO_PKG_NAME"),
            kept("CARGO_CFG_TARGET_OS"),
            kept("CARGO_FEATURE_STD"),
            kept("DEP_Z_ROOT"),
            kept("OUT_DIR"),
            kept("CARGO_MANIFEST_DIR"),
        ];
        let names: Vec<_> = session_variables(environ)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            names,
            ["PATH", "CARGO", "RUSTUP_TOOLCHAIN", "STOW_CACHE_DIR"]
                .map(OsString::from)
                .to_vec()
        );
    }
}

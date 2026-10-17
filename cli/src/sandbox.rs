//! The opt-in heel sandbox a `stow` cargo build runs inside (stow#779).
//!
//! Build scripts and proc macros are untrusted code: every dependency's
//! build script, every proc-macro expansion and every linker a build
//! script selects runs as a descendant of the cargo stow starts, so they
//! all inherit one sandbox. The stow process that starts cargo stays
//! outside — it resolves, prefetches and supervises on the open side of
//! the boundary, then `cargo fetch` lands the dependencies before the
//! sandboxed cargo runs offline.
//!
//! The grant set below is the whole contract: reads for the workspace,
//! the target directory, cargo's registry and git sources, cargo's
//! configuration (never its credentials files), the toolchain and the
//! system paths compilers need; writes for the target directory — also
//! executable, since cargo runs the build scripts it compiles there —
//! and the sandbox's own temporary directory; nothing else. Environment
//! is an allowlist, so tokens and other variables outside it never reach
//! the build. The network choice is carried in the sandbox's type — a
//! `Sandbox<AllowAll>` or a `Sandbox<DenyAll>` — rather than in a flag a
//! caller could mis-set.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use heel::{Access, IpcRouter, Sandbox, SandboxConfigBuilder, SecurityConfig};
use stow_types::error::Context;

/// Whether heel has a backend for this platform (Linux, macOS, Windows).
/// A `--sandbox` invocation anywhere else fails with this check's error
/// rather than discovering the missing backend mid-build.
pub const SANDBOX_SUPPORTED: bool = cfg!(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows"
));

/// The network policy a sandboxed build gets — resolved once from the
/// `--sandbox`/`--sandbox-deny-network` flags and the `experimental`
/// config, then carried in [`BuildSandbox`]'s type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxNetwork {
    /// The default for `--sandbox`: outbound traffic goes through heel's
    /// proxy and a build that downloads at build time keeps working.
    Allow,
    /// `--sandbox-deny-network`: the kernel refuses every connection;
    /// the supervisor's IPC socket is the only channel out.
    Deny,
}

impl SandboxNetwork {
    /// The request one switch pair makes: deny implies the sandbox.
    pub const fn from_flags(sandbox: bool, deny_network: bool) -> Option<Self> {
        if deny_network {
            Some(Self::Deny)
        } else if sandbox {
            Some(Self::Allow)
        } else {
            None
        }
    }

    /// Merge the flag answer with the config's: either source turns the
    /// sandbox on, and deny in either wins.
    pub const fn merge(flags: Option<Self>, config: Option<Self>) -> Option<Self> {
        match (flags, config) {
            (Some(Self::Deny), _) | (_, Some(Self::Deny)) => Some(Self::Deny),
            (Some(Self::Allow), _) | (_, Some(Self::Allow)) => Some(Self::Allow),
            (None, None) => None,
        }
    }
}

/// What a sandboxed build needs besides its grant list.
pub struct SandboxRequest<'a> {
    /// The policy the sandbox enforces on outbound connections.
    pub network: SandboxNetwork,
    /// The sources cargo compiles — the workspace root, plus the real
    /// workspace on a mirror build, whose sources the mirror links into.
    /// Read-only: a build must not plant sources that a later,
    /// unsandboxed step would run.
    pub source_roots: &'a [PathBuf],
    /// The build's target directory: written and executed, since the
    /// build scripts cargo compiles run out of it.
    pub target_dir: &'a Path,
    /// The build's scratch directory — serve map, cache policy and the
    /// graph tables facades read. `None` for a wrapperless cargo.
    pub scratch_dir: Option<&'a Path>,
    /// The directory the `RUSTC_WRAPPER` and `cc` shims live in.
    pub shims_dir: Option<&'a Path>,
    /// The stow executable the shims resolve to — also the binary heel
    /// bakes into its (here unused) IPC launcher shims, which is how it
    /// gets its execute grant.
    pub runtime_executable: &'a Path,
    /// The rustc the build's probes resolved — its directory and sysroot
    /// are the toolchain the sandboxed cargo invokes.
    pub rustc_executable: &'a Path,
    /// The supervisor's IPC router when the build is supervised; a
    /// passthrough cargo registers none and gets no IPC socket.
    pub ipc: Option<IpcRouter>,
}

/// The sandbox one build's cargo runs in — the network policy spelled
/// in the variant so [`Self::status`] needs no flag to know which it
/// holds.
pub enum BuildSandbox {
    /// `SandboxNetwork::Allow`: heel's proxy passes every request.
    AllowNetwork(Sandbox<heel::AllowAll>),
    /// `SandboxNetwork::Deny`: no proxy; outbound is refused outright.
    DenyNetwork(Sandbox<heel::DenyAll>),
}

/// A command as heel spells it: UTF-8 argv and environment — stow works
/// in terms of `OsString`, converted at the boundary so a non-UTF-8
/// argument is a clear error instead of a mangled exec.
pub struct SandboxedCommand {
    /// The program resolved on the sandbox's `PATH`.
    pub program: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// The environment stow hands it — the sandbox's own `PATH`,
    /// `TMPDIR` and proxy injection still applies.
    pub envs: Vec<(String, String)>,
    /// The directory it runs in.
    pub current_dir: PathBuf,
}

impl SandboxedCommand {
    /// Convert an OS-level launch — argv, env pairs and the working
    /// directory — requiring UTF-8 in each.
    ///
    /// # Errors
    ///
    /// The first non-UTF-8 argument or environment value.
    pub fn new(
        program: impl Into<String>,
        args: &[OsString],
        envs: &[(OsString, OsString)],
        current_dir: &Path,
    ) -> stow_types::error::Result<Self> {
        Ok(Self {
            program: program.into(),
            args: args
                .iter()
                .map(|arg| utf8(arg, "cargo argument"))
                .collect::<stow_types::error::Result<_>>()?,
            envs: envs
                .iter()
                .map(|(key, value)| {
                    Ok((
                        utf8(key, "environment variable name")?,
                        utf8(value, "environment variable value")?,
                    ))
                })
                .collect::<stow_types::error::Result<Vec<_>>>()?,
            current_dir: current_dir.to_path_buf(),
        })
    }
}

fn utf8(value: &OsStr, what: &str) -> stow_types::error::Result<String> {
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| stow_types::stow_error!("{what} {value:?} is not UTF-8 under --sandbox"))
}

impl BuildSandbox {
    /// Create the sandbox one cargo build runs in.
    ///
    /// A sandbox that cannot be set up is an error here — there is no
    /// unsandboxed fallback (stow#779). `runtime_executable` doubles as
    /// the `heel` binary the IPC layout bakes into its launcher shims
    /// and so gets the execute grant the shims and the facades both
    /// need, the same trick `stow-build` plays in CI.
    ///
    /// # Errors
    ///
    /// A grant path that does not resolve, or the sandbox's own
    /// construction failure.
    pub async fn create(mut request: SandboxRequest<'_>) -> stow_types::error::Result<Self> {
        let mut builder = SandboxConfigBuilder::default()
            .filesystem_strict(true)
            .security(SecurityConfig::strict())
            .env_passthroughs(sandbox_env_names(
                std::env::vars_os().filter_map(|(name, _)| name.into_string().ok()),
            ))
            .heel_binary(request.runtime_executable);
        if let Some(router) = request.ipc.take() {
            builder = builder.ipc(router);
        }
        for (path, access, reason) in sandbox_grants(&request)? {
            // The kernel resolves paths through `/var` → `/private/var`
            // and friends; a grant spelled through a symlink does not
            // cover the resolved path, so every grant is canonicalized
            // before heel writes the rule.
            let path = path.canonicalize().map_err(|error| {
                stow_types::stow_error!("canonicalize sandbox grant {}: {error}", path.display())
            })?;
            tracing::debug!(path = %path.display(), ?access, reason, "sandbox grant");
            builder = builder.grant(path, access);
        }
        Ok(match request.network {
            SandboxNetwork::Allow => Self::AllowNetwork(
                Sandbox::with_config(builder.network(heel::AllowAll).build())
                    .await
                    .map_err(|error| {
                        stow_types::stow_error!("create the cargo build sandbox: {error}")
                    })?,
            ),
            SandboxNetwork::Deny => Self::DenyNetwork(
                Sandbox::with_config(builder.network(heel::DenyAll).build())
                    .await
                    .map_err(|error| {
                        stow_types::stow_error!("create the cargo build sandbox: {error}")
                    })?,
            ),
        })
    }

    /// heel's IPC socket, when a router was configured — the endpoint
    /// the facades inside reach the supervisor through.
    pub fn ipc_endpoint(&self) -> Option<&Path> {
        match self {
            Self::AllowNetwork(sandbox) => sandbox.ipc_endpoint(),
            Self::DenyNetwork(sandbox) => sandbox.ipc_endpoint(),
        }
    }

    /// Run `command` in the sandbox and return its exit status — the
    /// sandboxed cargo's own status, which travels up to the caller the
    /// same way the unsandboxed one's does (stow#652).
    ///
    /// # Errors
    ///
    /// A spawn failure; a non-zero cargo status is an `Ok` value.
    pub async fn status(
        &self,
        command: &SandboxedCommand,
    ) -> stow_types::error::Result<std::process::ExitStatus> {
        match self {
            Self::AllowNetwork(sandbox) => run(sandbox, command).await,
            Self::DenyNetwork(sandbox) => run(sandbox, command).await,
        }
    }
}

async fn run<N: heel::NetworkPolicy>(
    sandbox: &Sandbox<N>,
    command: &SandboxedCommand,
) -> stow_types::error::Result<std::process::ExitStatus> {
    sandbox
        .command(command.program.clone())
        .args(command.args.iter().cloned())
        .envs(command.envs.iter().cloned())
        .current_dir(&command.current_dir)
        .status()
        .await
        .map_err(|error| {
            stow_types::stow_error!("run sandboxed cargo {}: {error}", command.program)
        })
}

/// The filesystem grant set for one build — nothing else on the host is
/// reachable. Every entry names what needs it and why, because each one
/// is a hole in the boundary this flag exists to close. Credentials
/// files are deliberately absent: heel's strict protections deny cargo's
/// `credentials`/`credentials.toml`, and the per-file grants below keep
/// it that way — a whole-home grant would silently reopen them.
fn sandbox_grants(
    request: &SandboxRequest<'_>,
) -> stow_types::error::Result<Vec<(PathBuf, Access, &'static str)>> {
    let cargo_home = crate::config::require_cargo_home()?;
    let rustup_home = rustup_home();
    ensure_package_cache_lock(&cargo_home)?;

    let mut grants: Vec<(PathBuf, Access, &'static str)> = request
        .source_roots
        .iter()
        .map(|root| {
            (
                root.clone(),
                Access::READ,
                "the sources cargo compiles — read-only so a build cannot plant inputs a later, unsandboxed step runs",
            )
        })
        .collect();
    grants.push((
        request.target_dir.to_path_buf(),
        Access::WRITE | Access::EXEC,
        "the target directory — build scripts and proc macros are compiled here and must execute",
    ));
    grants.push((
        request.runtime_executable.to_path_buf(),
        Access::READ | Access::EXEC,
        "the stow binary the wrapper shims resolve to",
    ));
    if let Some(dir) = request.scratch_dir {
        grants.push((
            dir.to_path_buf(),
            Access::READ,
            "the build's scratch tables — serve map, cache policy, expanded graph, extra args",
        ));
    }
    if let Some(dir) = request.shims_dir {
        grants.push((
            dir.to_path_buf(),
            Access::READ | Access::EXEC,
            "the rustc/cc wrapper shims cargo invokes",
        ));
    }

    conditional_grants(&cargo_home, rustup_home.as_deref(), &mut grants);
    grants.extend(compiler_search_grants(request.rustc_executable));
    grants.extend(toolchain_grant_dirs());

    Ok(grants)
}

/// The existence-conditional grants — a cargo home may carry no `git`
/// database, a rustup-managed toolchain may put `RUSTUP_HOME` anywhere,
/// `/usr/include` exists only on a host with C headers. Each is pushed
/// only when its path exists: a grant must resolve to a real path.
/// cargo's `credentials`/`credentials.toml` are never among them.
fn conditional_grants(
    cargo_home: &Path,
    rustup_home: Option<&Path>,
    grants: &mut Vec<(PathBuf, Access, &'static str)>,
) {
    grants.push((
        cargo_home.join(".package-cache"),
        Access::READ | Access::WRITE,
        "cargo's package-cache lock — taken on every invocation, --offline included",
    ));
    for (path, access, reason) in [
        (
            cargo_home.join("registry"),
            Access::READ,
            "registry sources and .crate cache — read-only so a build script cannot rewrite another crate's source",
        ),
        (
            cargo_home.join("git"),
            Access::READ,
            "git dependency database and checkouts fetched on the host — read-only like the registry",
        ),
        (
            cargo_home.join("bin"),
            Access::READ | Access::EXEC,
            "the rustup proxy shims `cargo`/`rustc` when PATH leads there",
        ),
        (
            cargo_home.join("config.toml"),
            Access::READ,
            "cargo config: registry sources and [net]/[build] settings the build honours — never credentials",
        ),
        (
            cargo_home.join("config"),
            Access::READ,
            "cargo config: registry sources and [net]/[build] settings the build honours — never credentials",
        ),
        (
            cargo_home.join(".global-cache"),
            Access::READ,
            "cargo's shared HTTP cache — consulted even under --offline",
        ),
    ] {
        if path.exists() {
            grants.push((path, access, reason));
        }
    }
    if let Some(home) = rustup_home
        && home.exists()
    {
        grants.push((
            home.to_path_buf(),
            Access::READ | Access::EXEC,
            "toolchain binaries and the Rust std library sources under the toolchain lib dir",
        ));
    }

    // The distro C header root every build script's `cc`/`c++` reads.
    // heel's system rules cover the exec trees under `/usr` (bin, lib,
    // libexec) but not `/usr/include`.
    let usr_include = Path::new("/usr/include");
    if usr_include.exists() {
        grants.push((
            usr_include.to_path_buf(),
            Access::READ,
            "the system C header root — outside heel's exec rules, which cover /usr/{bin,lib,libexec} but not include",
        ));
    }
}

/// The compilers and their toolchain paths, as the host environment
/// resolves them. `cargo`/`rustc` come off PATH — rustup proxies, a
/// homebrew rust, a CI image toolchain — and the build's own rustc adds
/// its directory and sysroot, which matter when `RUSTC` names a binary
/// outside those places.
fn compiler_search_grants(rustc_executable: &Path) -> Vec<(PathBuf, Access, &'static str)> {
    let mut grants = Vec::new();
    let path_tools: &[&str] = if cfg!(windows) {
        &["cargo", "rustc", "link.exe"]
    } else {
        &["cargo", "rustc"]
    };
    for tool in path_tools {
        if let Some(dir) = resolve_on_path(tool) {
            grants.push((
                dir,
                Access::READ | Access::EXEC,
                "the directory PATH resolves this tool from",
            ));
        }
    }
    if let Some(dir) = rustc_executable.parent()
        && dir.is_dir()
    {
        grants.push((
            dir.to_path_buf(),
            Access::READ | Access::EXEC,
            "the directory the build's rustc lives in",
        ));
    }
    if let Some(sysroot) = rustc_sysroot(rustc_executable) {
        grants.push((
            sysroot,
            Access::READ | Access::EXEC,
            "the rustc sysroot — std rlibs and the toolchain's helper binaries",
        ));
    }
    grants
}

/// The directory an executable named `tool` resolves to on `PATH`.
fn resolve_on_path(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
        .and_then(|found| found.parent().map(Path::to_path_buf))
}

/// `rustc --print sysroot`, for a toolchain whose support files do not
/// live under `RUSTUP_HOME` — a Nix store rustc, a vendor toolchain.
fn rustc_sysroot(rustc_executable: &Path) -> Option<PathBuf> {
    let output = std::process::Command::new(rustc_executable)
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned()))
        .filter(|path| path.is_dir())
}

/// Directories a toolchain lives under, named by toolchain environment
/// variables: the SDK roots (`SDKROOT`, `DEVELOPER_DIR`, the Android
/// roots when the build targets Android) name whole trees; the linker
/// and compiler variables (`CARGO_TARGET_*_LINKER`, `CC_*`, …) name
/// executables whose parent directory is granted the way
/// `resolve_on_path` grants the `cargo`/`rustc` directory.
fn toolchain_grant_dirs() -> Vec<(PathBuf, Access, &'static str)> {
    const TOOLCHAIN_ROOT_VARS: &[&str] = &["SDKROOT", "DEVELOPER_DIR"];
    const TOOLCHAIN_EXE_PREFIXES: &[&str] =
        &["CARGO_TARGET_", "CC_", "CXX_", "AR_", "RANLIB_", "LD"];
    let mut dirs: Vec<(PathBuf, Access, &'static str)> = std::env::vars_os()
        .filter_map(|(name, value)| {
            let name = name.to_str()?;
            if TOOLCHAIN_ROOT_VARS.contains(&name) || ANDROID_ROOT_VARS.contains(&name) {
                let dir = PathBuf::from(value);
                return dir.is_dir().then(|| {
                    (
                        dir,
                        Access::READ | Access::EXEC,
                        "a toolchain install tree named by an SDK root variable",
                    )
                });
            }
            if TOOLCHAIN_EXE_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                // The value must name a real file: a bare name resolves
                // through PATH (covered by the cargo/rustc dirs and the
                // system rules), and a non-file value —
                // `CARGO_TARGET_TMPDIR` and friends — must not leak its
                // parent directory into the grant set.
                let exe = PathBuf::from(value);
                return exe.is_file().then(|| {
                    (
                        exe.parent().unwrap().to_path_buf(),
                        Access::READ | Access::EXEC,
                        "the parent of a toolchain executable named by an env var",
                    )
                });
            }
            None
        })
        .collect();
    // The linker stow itself selects: the managed mold install when the
    // provisioning produced one — covered the same way an env-named one
    // is — and any mold already on PATH through `resolve_on_path`.
    if let Ok(tools) = crate::config::tools_dir()
        && tools.is_dir()
    {
        dirs.push((
            tools,
            Access::READ | Access::EXEC,
            "stow's per-user tools directory — the managed mold install",
        ));
    }
    dirs
}

/// The Android SDK and NDK roots, granted to a build whose toolchain env
/// names them — matching the CI sandbox's list.
const ANDROID_ROOT_VARS: &[&str] = &[
    "ANDROID_HOME",
    "ANDROID_SDK_ROOT",
    "ANDROID_NDK",
    "ANDROID_NDK_HOME",
    "ANDROID_NDK_ROOT",
    "ANDROID_NDK_LATEST_HOME",
];

/// The environment allowlist: the names a build legitimately reads —
/// cargo's own configuration, rustc and rustup settings, the compiler
/// toolchain's variables, locale and terminal information — and nothing
/// else. Registry tokens and credential variables are deliberately
/// absent: `CARGO_REGISTRIES_*_TOKEN` and friends never match a prefix
/// below, and `env`/`SSH_AUTH_SOCK`-style secrets die with the list.
///
/// `names` is the parent environment's variable names; the task's
/// platform decides which toolchain roots apply — the Android ones only
/// for a build that could use them.
fn sandbox_env_names(names: impl Iterator<Item = String>) -> Vec<String> {
    const EXACT: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TERM",
        "LANG",
        "RUST_LOG",
        "RUST_BACKTRACE",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "RUSTC",
        "RUSTDOC",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTUP_TOOLCHAIN",
        "RUSTUP_AUTO_INSTALL",
        "RUSTUP_PER_FORCE_COPY",
        "CARGO",
        "CARGO_INCREMENTAL",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "CC",
        "CXX",
        "AR",
        "RANLIB",
        "LD",
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "SDKROOT",
        "DEVELOPER_DIR",
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "TVOS_DEPLOYMENT_TARGET",
        "WATCHOS_DEPLOYMENT_TARGET",
        "VISIONOS_DEPLOYMENT_TARGET",
        "LIB",
        "INCLUDE",
        "VCINSTALLDIR",
        "VCToolsInstallDir",
        "WindowsSdkDir",
        "WindowsSdkBinPath",
        "WindowsSdkVerBinPath",
        "WindowsSDKVersion",
        "WindowsSDKLibVersion",
        "UniversalCRTSdkDir",
        "UCRTVersion",
        "PKG_CONFIG",
        "PKG_CONFIG_PATH",
        "PKG_CONFIG_LIBDIR",
        "PKG_CONFIG_SYSROOT_DIR",
        "CMAKE_GENERATOR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        // Debugging knobs a user spelled for this build — stow's own
        // wiring (`STOW_*` context, the config blob, the supervisor's
        // endpoint) arrives through `.env` on the command instead.
        "STOW_ENABLE_PREBUILT_DEPS",
        "STOW_TRACE_WRAPPED_COMPILERS",
        "STOW_IDENTITY_TRACE",
        "STOW_TRACE_FILE",
        "STOW_DISABLE_PUBLIC_CACHE",
        "NO_COLOR",
        "CARGO_TERM_COLOR",
    ];
    const PREFIXES: &[&str] = &[
        "CARGO_TARGET_",
        "CARGO_TERM_",
        "CARGO_BUILD_",
        "CC_",
        "CXX_",
        "AR_",
        "RANLIB_",
        "CFLAGS_",
        "CXXFLAGS_",
        "CPPFLAGS_",
        "LDFLAGS_",
        "PKG_CONFIG_",
        "CMAKE_",
        "LC_",
        "RUSTUP_",
    ];
    names
        .filter(|name| {
            name != "CARGO_TARGET_DIR"
                && name != "CARGO_HOME"
                && name != "RUSTUP_HOME"
                && (EXACT.contains(&name.as_str())
                    || ANDROID_ROOT_VARS.contains(&name.as_str())
                    || PREFIXES.iter().any(|prefix| name.starts_with(prefix)))
        })
        .collect()
}

/// Create cargo's package-cache lock file before the sandbox starts.
/// Cargo takes a lock on it on every invocation, `--offline` included,
/// so it has to exist and be writable inside the sandbox.
fn ensure_package_cache_lock(cargo_home: &Path) -> stow_types::error::Result<()> {
    std::fs::create_dir_all(cargo_home)?;
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(cargo_home.join(".package-cache"))
        .map_err(|error| {
            stow_types::stow_error!(
                "create cargo package-cache lock {}: {error}",
                cargo_home.join(".package-cache").display()
            )
        })?;
    Ok(())
}

/// The arguments `cargo fetch` needs from a build's argv: the flags
/// that decide *which* dependencies land so the fetch covers exactly
/// the build's resolution — `--offline`, `--locked` and `--frozen`
/// among them, so a build the user constrained stays constrained in the
/// fetch.
fn fetch_args(cargo_args: &[OsString]) -> Vec<OsString> {
    let mut args = Vec::new();
    let mut iter = cargo_args.iter();
    while let Some(arg) = iter.next() {
        let Some(arg_str) = arg.to_str() else {
            continue;
        };
        if arg_str == "--manifest-path"
            && let Some(value) = iter.next()
        {
            args.push(arg.clone());
            args.push(value.clone());
            continue;
        }
        if let Some(value) = arg_str.strip_prefix("--manifest-path=") {
            args.push(OsString::from(format!("--manifest-path={value}")));
            continue;
        }
        if arg_str == "--target"
            && let Some(value) = iter.next()
        {
            args.push(arg.clone());
            args.push(value.clone());
            continue;
        }
        if let Some(value) = arg_str.strip_prefix("--target=") {
            args.push(OsString::from(format!("--target={value}")));
            continue;
        }
        if matches!(arg_str, "--locked" | "--frozen" | "--offline") {
            args.push(arg.clone());
        }
    }
    args
}

/// The rustup home as cargo's toolchain resolution sees it:
/// `RUSTUP_HOME` when set, else `~/.rustup`.
fn rustup_home() -> Option<PathBuf> {
    std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".rustup")))
}

/// The variables the sandboxed toolchain needs spelled out, not passed
/// through: `CARGO_HOME` and `RUSTUP_HOME` are resolved here — same as
/// the grant computation — so a rustup proxy inside the sandbox never
/// falls back to a home directory it cannot write.
///
/// # Errors
///
/// `CARGO_HOME` unset — the same check `cargo_home` does everywhere.
pub fn toolchain_envs() -> stow_types::error::Result<Vec<(OsString, OsString)>> {
    let mut envs = vec![(
        OsString::from("CARGO_HOME"),
        crate::config::require_cargo_home()?.into_os_string(),
    )];
    if let Some(home) = rustup_home().filter(|home| home.is_dir()) {
        envs.push((OsString::from("RUSTUP_HOME"), home.into_os_string()));
    }
    Ok(envs)
}

/// `cargo fetch` ahead of the sandboxed build: dependencies land on the
/// host, where network and the cargo home's write access are ordinary,
/// so the sandboxed cargo can run `--offline` and still find every
/// source.
///
/// Runs in `current_dir` — for a mirror build the mirrored workspace —
/// forwarding the user's `--manifest-path` and `--target` spellings so
/// the fetch covers exactly the units the build compiles.
///
/// # Errors
///
/// A fetch that cannot run, or one that exits non-zero — the sandboxed
/// build could not proceed without its sources, so it is the command's
/// error, never a fallback to an online build inside the sandbox.
pub async fn fetch_dependencies(
    current_dir: &Path,
    cargo_args: &[OsString],
) -> stow_types::error::Result<()> {
    let mut command = async_process::Command::new("cargo");
    command.arg("fetch").current_dir(current_dir);
    command.args(fetch_args(cargo_args));
    let output = command
        .output()
        .await
        .wrap_err("run cargo fetch ahead of the sandboxed build")?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "cargo fetch failed before the sandboxed build: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fetch_carries_the_builds_offline_flag() {
        let args = fetch_args(&[OsString::from("--offline")]);
        assert_eq!(args, vec![OsString::from("--offline")]);
    }

    #[test]
    fn the_fetch_keeps_the_resolution_pins_and_drops_the_rest() {
        let args = fetch_args(&[
            OsString::from("--locked"),
            OsString::from("--frozen"),
            OsString::from("--offline"),
            OsString::from("--release"),
        ]);
        assert_eq!(
            args,
            vec![
                OsString::from("--locked"),
                OsString::from("--frozen"),
                OsString::from("--offline"),
            ]
        );
    }
}

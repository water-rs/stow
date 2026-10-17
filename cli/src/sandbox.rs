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

use futures_util::StreamExt;
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
    /// The triple build scripts and proc macros compile for — the
    /// rustc's real `host:`, already resolved by the driver's shared
    /// probes rather than re-asked here.
    pub host_target: &'a str,
    /// The directory the sandboxed cargo runs in — where its cargo
    /// configuration chain, and so its `[env]` and `target.*.linker`
    /// tables, is read from.
    pub cargo_dir: &'a Path,
    /// The build's own arguments after the action — a `--target` among
    /// them widens the toolchain discovery to that target's linker.
    pub cargo_args: &'a [OsString],
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
        for (path, access, reason) in sandbox_grants(&request).await? {
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
async fn sandbox_grants(
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
    // The process-spawning halves — rustc's sysroot probe and the
    // driver/linker discovery — are independent of each other and of
    // the sync grants, so they run in one join; the probes inside the
    // discovery are themselves bounded by `PROBE_CONCURRENCY`.
    let (sysroot, toolchain) = futures_util::future::join(
        rustc_sysroot(request.rustc_executable),
        discovered_toolchain_grants(request),
    )
    .await;
    if let Some(sysroot) = sysroot {
        grants.push((
            sysroot,
            Access::READ | Access::EXEC,
            "the rustc sysroot — std rlibs and the toolchain's helper binaries",
        ));
    }
    grants.extend(toolchain?);

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
    grants
}

/// The directory an executable named `tool` resolves to on `PATH`.
fn resolve_on_path(tool: &str) -> Option<PathBuf> {
    resolve_executable(OsStr::new(tool)).and_then(|found| found.parent().map(Path::to_path_buf))
}

/// The executable a tool spelling resolves to: a spelling that carries
/// a path separator must exist as given; a bare name is searched on
/// `PATH`, with the platform's executable suffix tried beside it —
/// `cargo` resolves `cargo.exe` on Windows.
fn resolve_executable(tool: &OsStr) -> Option<PathBuf> {
    let tool_path = Path::new(tool);
    if tool_path.components().count() > 1 {
        return tool_path.is_file().then(|| tool_path.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    let mut suffixed = tool.to_os_string();
    suffixed.push(std::env::consts::EXE_SUFFIX);
    std::env::split_paths(&path)
        .flat_map(|dir| [dir.join(tool), dir.join(&suffixed)])
        .find(|candidate| candidate.is_file())
}

/// `rustc --print sysroot`, for a toolchain whose support files do not
/// live under `RUSTUP_HOME` — a Nix store rustc, a vendor toolchain.
async fn rustc_sysroot(rustc_executable: &Path) -> Option<PathBuf> {
    let output = match async_process::Command::new(rustc_executable)
        .args(["--print", "sysroot"])
        .output()
        .await
    {
        Ok(output) => output,
        Err(error) => {
            tracing::debug!(rustc = %rustc_executable.display(), %error, "rustc sysroot probe could not spawn");
            return None;
        }
    };
    if !output.status.success() {
        tracing::debug!(rustc = %rustc_executable.display(), status = %output.status, "rustc sysroot probe refused");
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    path.is_dir().then_some(path)
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

/// The helpers a gcc- or clang-shaped driver execs outside `PATH`:
/// `collect2` runs the link, `as` the assembly, and the `ld.*` names are
/// what `-fuse-ld=` selects — `ld.mold` is stow's Linux selection
/// (stow#779), `ld.lld` rustc's default where it applies.
const DRIVER_SUBPROGRAMS: &[&str] = &[
    "collect2", "as", "ld", "ld.bfd", "ld.gold", "ld.lld", "ld.mold", "lld", "mold",
];

/// The toolchain a build's compiler drivers and linkers reach,
/// discovered by asking the tools themselves rather than naming a
/// distro layout (stow#779): each driver's `-print-search-dirs`
/// reports the `programs:` trees holding the helpers it execs —
/// `collect2`, `cc1`, `as` and the `ld.*` a `-fuse-ld=` selects, which
/// live outside `PATH` and outside heel's system rules wherever a
/// toolchain does not install under `/usr` — and `-print-prog-name`
/// resolves each helper the way the link does, `ld.mold` in the
/// `COMPILER_PATH` `stow setup` writes included.
async fn discovered_toolchain_grants(
    request: &SandboxRequest<'_>,
) -> stow_types::error::Result<Vec<(PathBuf, Access, &'static str)>> {
    let cargo_home = crate::config::cargo_home();
    // A cargo config cargo itself would refuse is a load error, not a
    // skip: the build fails here the way it would inside the sandbox.
    let config =
        crate::mold::cargo_config(request.cargo_dir, cargo_home.as_deref()).map_err(|error| {
            stow_types::stow_error!("load the cargo config for toolchain discovery: {error}")
        })?;
    let compiler_path = crate::mold::effective_compiler_path(&config, &crate::mold::process_env);
    let mut grants: Vec<(PathBuf, Access, &'static str)> = Vec::new();
    if let Some(compiler_path) = compiler_path.as_deref() {
        for dir in std::env::split_paths(compiler_path) {
            if dir.is_dir() {
                grants.push((
                    dir,
                    Access::READ | Access::EXEC,
                    "a COMPILER_PATH directory — the driver's subprogram search path, where `stow setup` installs `ld.mold`",
                ));
            }
        }
    }
    let targets = build_targets(request);
    let b_dirs = rustflag_b_dirs(&targets, Some(&config));
    for dir in &b_dirs {
        if dir.is_dir() {
            grants.push((
                dir.clone(),
                Access::READ | Access::EXEC,
                "a `-B` prefix the rustflags hand the driver — a subprogram search directory",
            ));
        }
    }
    let drivers = toolchain_drivers(&targets, Some(&config));
    // Every (driver, question) pair is independent — the driver's own
    // directory grant is free — so all of them run in one bounded
    // stream: the cost is the slowest probe, not the sum.
    let mut probes = Vec::new();
    for driver in &drivers {
        probes.push((driver.clone(), "-print-search-dirs".to_owned()));
        for tool in DRIVER_SUBPROGRAMS {
            probes.push((driver.clone(), format!("-print-prog-name={tool}")));
        }
    }
    let results: Vec<(PathBuf, String, Option<String>)> =
        futures_util::stream::iter(probes.into_iter().map(|(driver, flag)| {
            let b_dirs = b_dirs.clone();
            let compiler_path = compiler_path.clone();
            async move {
                let output = driver_probe(&driver, &b_dirs, compiler_path.as_deref(), &flag).await;
                (driver, flag, output)
            }
        }))
        .buffer_unordered(PROBE_CONCURRENCY)
        .collect()
        .await;
    grants.extend(driver_probe_grants(&drivers, &results));
    #[cfg(windows)]
    grants.extend(msvc_toolchain_grants(&targets));
    Ok(grants)
}

/// The grants a finished driver-probe set implies: each driver's own
/// directory, its `-print-search-dirs` program and library trees, and
/// the directories its `-print-prog-name` answers name.
fn driver_probe_grants(
    drivers: &[PathBuf],
    results: &[(PathBuf, String, Option<String>)],
) -> Vec<(PathBuf, Access, &'static str)> {
    let mut grants = Vec::new();
    for driver in drivers {
        if let Some(dir) = driver.parent() {
            grants.push((
                dir.to_path_buf(),
                Access::READ | Access::EXEC,
                "the compiler driver's own directory",
            ));
        }
    }
    for (_driver, flag, output) in results {
        let Some(output) = output.as_deref() else {
            continue;
        };
        if flag == "-print-search-dirs" {
            let (exec_dirs, read_dirs) = parse_search_dirs(output);
            for dir in exec_dirs {
                if dir.is_dir() {
                    grants.push((
                        dir,
                        Access::READ | Access::EXEC,
                        "a driver's program search directory — collect2, cc1, as and the lto helpers it execs",
                    ));
                }
            }
            for dir in read_dirs {
                if dir.is_dir() {
                    grants.push((
                        dir,
                        Access::READ,
                        "a driver's library search directory — the objects and shared libraries it links",
                    ));
                }
            }
            continue;
        }
        let resolved = PathBuf::from(output.trim());
        // A name the driver cannot resolve echoes back unchanged;
        // only a real path carries a grant.
        if !resolved.is_file() {
            continue;
        }
        if let Some(dir) = resolved.parent() {
            grants.push((
                dir.to_path_buf(),
                Access::READ | Access::EXEC,
                "the directory the driver resolves a subprogram to",
            ));
        }
    }
    grants
}

/// `-print-*` probes spawn per (driver, question) — a handful of
/// milliseconds each. Eight keeps a build naming several toolchains
/// inside a bounded burst while still finishing the usual one-driver
/// set in a single wave.
const PROBE_CONCURRENCY: usize = 8;

/// The triples the build compiles for: an explicit `--target` or
/// `CARGO_BUILD_TARGET`, plus the rustc host — build scripts and proc
/// macros always compile for it.
fn build_targets(request: &SandboxRequest<'_>) -> Vec<String> {
    let mut targets: Vec<String> = explicit_build_target(request.cargo_args)
        .or_else(|| std::env::var("CARGO_BUILD_TARGET").ok())
        .into_iter()
        .collect();
    if !targets.iter().any(|target| target == request.host_target) {
        targets.push(request.host_target.to_owned());
    }
    targets
}

/// The `--target` the user spelled, or `None` for a host build.
fn explicit_build_target(cargo_args: &[OsString]) -> Option<String> {
    let mut iter = cargo_args.iter();
    while let Some(arg) = iter.next() {
        let Some(arg) = arg.to_str() else {
            continue;
        };
        if arg == "--target" {
            return iter
                .next()
                .and_then(|value| value.to_str().map(str::to_owned));
        }
        if let Some(value) = arg.strip_prefix("--target=") {
            return Some(value.to_owned());
        }
    }
    None
}

/// Ask a driver one of its `-print-*` introspection questions under
/// the search environment the build's link runs in — the `-B`
/// prefixes first, then `COMPILER_PATH` — so the probe answers the
/// question the sandboxed driver itself would ask.
async fn driver_probe(
    driver: &Path,
    b_dirs: &[PathBuf],
    compiler_path: Option<&OsStr>,
    flag: &str,
) -> Option<String> {
    let mut command = async_process::Command::new(driver);
    for dir in b_dirs {
        command.arg(format!("-B{}", dir.display()));
    }
    command.arg(flag);
    if let Some(compiler_path) = compiler_path {
        command.env("COMPILER_PATH", compiler_path);
    }
    let output = match command.output().await {
        Ok(output) => output,
        Err(error) => {
            tracing::debug!(driver = %driver.display(), flag, %error, "toolchain probe could not spawn");
            return None;
        }
    };
    if !output.status.success() {
        tracing::debug!(driver = %driver.display(), flag, status = %output.status, "toolchain probe refused");
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The `-B` prefixes the build's effective rustflags hand the driver,
/// for each target the build compiles — searched ahead of the driver's
/// own directories for every subprogram.
fn rustflag_b_dirs(targets: &[String], config: Option<&cargo_config2::Config>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(config) = config {
        for target in targets {
            if let Ok(Some(flags)) = config.rustflags(target.as_str()) {
                dirs.extend(crate::mold::b_dirs(&flags.flags));
            }
        }
    }
    dirs
}

/// The compiler drivers and linkers the build can invoke, resolved to
/// real executables: the `cc`/`c++` rustc and the `cc` crate fall back
/// to, the executables the toolchain environment names (`CC`,
/// `CC_<target>`, `CARGO_TARGET_<triple>_LINKER`, `LD`, …), and the
/// linker the cargo configuration selects for each build target.
fn toolchain_drivers(targets: &[String], config: Option<&cargo_config2::Config>) -> Vec<PathBuf> {
    let mut spellings: Vec<OsString> = vec![OsString::from("cc"), OsString::from("c++")];
    for (name, value) in std::env::vars_os() {
        let Some(name) = name.to_str() else {
            continue;
        };
        let toolchain_exe = matches!(name, "CC" | "CXX" | "LD")
            || name.starts_with("CC_")
            || name.starts_with("CXX_")
            || name.starts_with("LD_")
            || (name.starts_with("CARGO_TARGET_") && name.ends_with("_LINKER"));
        if toolchain_exe {
            spellings.push(value);
        }
    }
    if let Some(config) = config {
        for target in targets {
            if let Ok(Some(linker)) = config.linker(target.as_str()) {
                spellings.push(linker.into_os_string());
            }
            if let Ok(Some(flags)) = config.rustflags(target.as_str())
                && let Some(linker) = crate::mold::rustflags_linker(&flags.flags)
            {
                spellings.push(OsString::from(linker));
            }
        }
    }
    let mut drivers: Vec<PathBuf> = Vec::new();
    for spelling in spellings {
        if let Some(exe) = resolve_executable(&spelling)
            && !drivers.contains(&exe)
        {
            drivers.push(exe);
        }
    }
    drivers
}

/// The directory lists a gcc- or clang-shaped driver reports for
/// `-print-search-dirs`: `install:`/`programs:`/`installedDir:` hold
/// the executables it runs — read-and-execute — while `libraries:` is
/// the object and shared-library search path — read only. Values are
/// `key: =dir:dir:…` — the `=` is the driver's list marker, not a path
/// byte.
fn parse_search_dirs(output: &str) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut exec_dirs = Vec::new();
    let mut read_dirs = Vec::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let dirs = value
            .trim()
            .trim_start_matches('=')
            .split(':')
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from);
        match key.trim() {
            "install" | "programs" | "installedDir" => exec_dirs.extend(dirs),
            "libraries" => read_dirs.extend(dirs),
            _ => {}
        }
    }
    (exec_dirs, read_dirs)
}

/// The MSVC toolchain and Windows SDK a `*-msvc` build's `cl.exe` and
/// `link.exe` live in — located the way rustc and the `cc` crate
/// locate them, so the usual Visual Studio install that is not on
/// `PATH` is still found. `find_tool` answers `None` for non-msvc
/// targets, so each build target is simply asked.
#[cfg(windows)]
fn msvc_toolchain_grants(targets: &[String]) -> Vec<(PathBuf, Access, &'static str)> {
    let mut grants = Vec::new();
    for target in targets {
        for name in ["cl.exe", "link.exe"] {
            let Some(tool) = find_msvc_tools::find_tool(target.as_str(), name) else {
                continue;
            };
            if let Some(dir) = tool.path().parent() {
                grants.push((
                    dir.to_path_buf(),
                    Access::READ | Access::EXEC,
                    "the MSVC tool's own directory",
                ));
            }
            for (key, value) in tool.env() {
                let access = if key.as_os_str() == "PATH" {
                    Access::READ | Access::EXEC
                } else {
                    Access::READ
                };
                for dir in std::env::split_paths(value) {
                    if dir.is_dir() {
                        grants.push((
                            dir,
                            access,
                            "a directory the MSVC toolchain's environment names",
                        ));
                    }
                }
            }
        }
    }
    if let Some(sdk) = find_msvc_tools::find_windows_sdk(std::env::consts::ARCH) {
        for dir in sdk.path() {
            if dir.is_dir() {
                grants.push((
                    dir.to_path_buf(),
                    Access::READ | Access::EXEC,
                    "a Windows SDK binary directory",
                ));
            }
        }
        for dir in sdk.libs().chain(sdk.include()) {
            if dir.is_dir() {
                grants.push((
                    dir.to_path_buf(),
                    Access::READ,
                    "a Windows SDK library or include directory",
                ));
            }
        }
    }
    grants
}

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
        "COMPILER_PATH",
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

    #[test]
    fn search_dirs_parse_gccs_install_programs_and_libraries() {
        // gcc 13 on Ubuntu: `install` and `programs` carry the helpers
        // the driver execs, `libraries` the objects it links.
        let output = "install: /usr/lib/gcc/x86_64-linux-gnu/13/\n\
             programs: =/usr/lib/gcc/x86_64-linux-gnu/13/:/usr/lib/gcc/x86_64-linux-gnu/13/../../../../x86_64-linux-gnu/bin/x86_64-linux-gnu/13/:/usr/bin/x86_64-linux-gnu/\n\
             libraries: =/usr/lib/gcc/x86_64-linux-gnu/13/:/usr/lib/gcc/x86_64-linux-gnu/13/../../../../x86_64-linux-gnu/lib/x86_64-linux-gnu/13/:/lib/x86_64-linux-gnu/\n";
        let (exec_dirs, read_dirs) = parse_search_dirs(output);
        assert_eq!(
            exec_dirs,
            vec![
                PathBuf::from("/usr/lib/gcc/x86_64-linux-gnu/13/"),
                PathBuf::from("/usr/lib/gcc/x86_64-linux-gnu/13/"),
                PathBuf::from(
                    "/usr/lib/gcc/x86_64-linux-gnu/13/../../../../x86_64-linux-gnu/bin/x86_64-linux-gnu/13/"
                ),
                PathBuf::from("/usr/bin/x86_64-linux-gnu/"),
            ]
        );
        assert_eq!(
            read_dirs,
            vec![
                PathBuf::from("/usr/lib/gcc/x86_64-linux-gnu/13/"),
                PathBuf::from(
                    "/usr/lib/gcc/x86_64-linux-gnu/13/../../../../x86_64-linux-gnu/lib/x86_64-linux-gnu/13/"
                ),
                PathBuf::from("/lib/x86_64-linux-gnu/"),
            ]
        );
    }

    #[test]
    fn search_dirs_parse_clangs_layout() {
        let output = "programs: =/usr/lib/llvm-18/bin\n\
             libraries: =/usr/lib/llvm-18/lib/clang/18\n";
        let (exec_dirs, read_dirs) = parse_search_dirs(output);
        assert_eq!(exec_dirs, vec![PathBuf::from("/usr/lib/llvm-18/bin")]);
        assert_eq!(
            read_dirs,
            vec![PathBuf::from("/usr/lib/llvm-18/lib/clang/18")]
        );
    }

    #[test]
    fn search_dirs_ignore_unrelated_lines() {
        let (exec_dirs, read_dirs) = parse_search_dirs("gcc version 13.2.0\nno colon here\n");
        assert_eq!(exec_dirs.len(), 0);
        assert_eq!(read_dirs.len(), 0);
    }

    #[test]
    fn an_explicit_target_is_read_from_cargo_args() {
        for args in [
            vec![
                OsString::from("--target"),
                OsString::from("aarch64-unknown-linux-gnu"),
            ],
            vec![OsString::from("--target=aarch64-unknown-linux-gnu")],
        ] {
            assert_eq!(
                explicit_build_target(&args).as_deref(),
                Some("aarch64-unknown-linux-gnu")
            );
        }
        assert_eq!(explicit_build_target(&[OsString::from("--release")]), None);
    }

    #[test]
    fn a_cross_target_keeps_the_real_host_for_the_build_scripts() {
        // A wasm32 consumer build names a target outside every CI
        // family, but its build scripts and proc macros still compile
        // for the rustc's real host — so `build_targets` carries the
        // spelled target AND the host the driver resolved, not a
        // runner-family mapping of the consumer target.
        let dummy = PathBuf::from("/usr/bin/true");
        let args = vec![
            OsString::from("--target"),
            OsString::from("wasm32-unknown-unknown"),
        ];
        let request = SandboxRequest {
            network: SandboxNetwork::Deny,
            source_roots: &[],
            target_dir: Path::new("/tmp"),
            scratch_dir: None,
            shims_dir: None,
            runtime_executable: &dummy,
            rustc_executable: &dummy,
            host_target: "aarch64-apple-darwin",
            cargo_dir: Path::new("/tmp"),
            cargo_args: &args,
            ipc: None,
        };
        let targets = build_targets(&request);
        assert_eq!(
            targets,
            vec![
                "wasm32-unknown-unknown".to_owned(),
                "aarch64-apple-darwin".to_owned(),
            ]
        );
    }
}

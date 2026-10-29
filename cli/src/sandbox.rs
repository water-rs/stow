//! The heel sandbox a `stow` cargo build runs inside (stow#779, stow#1000).
//!
//! Build scripts and proc macros are untrusted code: every dependency's
//! build script, every proc-macro expansion and every linker a build
//! script selects runs as a descendant of the cargo stow starts, so they
//! all inherit one sandbox. The stow process that starts cargo stays
//! outside — it resolves, prefetches and supervises on the open side of
//! the boundary. The isolation level decides what the sandbox is:
//!
//! - `protect` reads and writes the machine as usual except for heel's
//!   fixed denylists — credential stores unreadable, persistence
//!   locations unwritable — and strips credential variables from the
//!   environment. Cargo runs online inside it and fetches for itself
//!   through heel's proxy.
//! - `strict` and `offline` are an allowlist. The grant set below is the
//!   whole contract: reads for the workspace, the target directory,
//!   cargo's registry and git sources, cargo's configuration (never its
//!   credentials files), the toolchain and the system paths compilers
//!   need; writes for the target directory — also executable, since
//!   cargo runs the build scripts it compiles there — and the sandbox's
//!   own temporary directory; nothing else. Environment is an
//!   allowlist, so tokens and other variables outside it never reach the
//!   build. Dependencies are fetched before the sandboxed cargo runs
//!   offline. A crate's `[[isolation.grant]]` widens the set while that
//!   crate is in the build.
//!
//! Every sandboxed build records its network destinations and the accesses
//! the sandbox denied to the audit log. The network choice is carried in
//! the sandbox's type — a `Sandbox<Audited<AllowAll>>` or a
//! `Sandbox<DenyAll>` — rather than in a flag a caller could mis-set.
//!
//! The toolchain roots every build reads the same way — the rustup home,
//! cargo's `registry`/`git`/`bin` and the MSVC installation roots — ride
//! a stable [`Identity`] as persistent read-only grants instead of the
//! per-build set (stow#815): on Windows they are written once for the
//! `heel-id-stow` `AppContainer` profile rather than rewritten per build,
//! and elsewhere heel folds them into each sandbox's ordinary policy.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use futures_util::StreamExt;
use heel::{
    Access, AllowAll, Audited, DenyAll, Grant, Identity, IpcRouter, IpcUnconfigured,
    NetworkAuditLog, NetworkPolicy, ReadDenylist, Sandbox, SandboxConfig, SandboxConfigBuilder,
    SecurityConfig, SecurityConfigBuilder, WriteDenylist,
};
use stow_types::env_name;
use stow_types::error::Context;

use crate::isolation::{Confinement, Isolation};

/// What a sandboxed build needs besides its grant list.
pub struct SandboxRequest<'a> {
    /// The level the sandbox enforces.
    pub confinement: Confinement,
    /// The resolved isolation, whose config carries the per-crate grants
    /// and the audit settings.
    pub isolation: &'a Isolation,
    /// The directory whose `Cargo.lock` names the crates in the build —
    /// the crates whose `[[isolation.grant]]` entries apply.
    pub lockfile_root: &'a Path,
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

/// The network policy the sandbox holds, spelled in the variant so
/// [`BuildSandbox::status`] needs no flag to know which.
enum Network {
    /// Heel's proxy passes every request, each recorded in the audit log.
    Allowed(Sandbox<Audited<AllowAll>>),
    /// No proxy; outbound is refused outright.
    Denied(Sandbox<DenyAll>),
}

/// The sandbox one build's cargo runs in, with the audit log its denied
/// accesses are written to.
pub struct BuildSandbox {
    network: Network,
    audit: DeniedAccessLog,
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
    value.to_str().map(str::to_owned).ok_or_else(|| {
        stow_types::stow_error!("{what} {value:?} is not UTF-8 under a sandboxed level")
    })
}

impl BuildSandbox {
    /// Create the sandbox one cargo build runs in.
    ///
    /// A sandbox that cannot be set up is an error here — there is no
    /// unsandboxed fallback and no weaker level (stow#779, stow#1000).
    /// `runtime_executable` doubles as the `heel` binary the IPC layout
    /// bakes into its launcher shims and so gets the execute grant the
    /// shims and the facades both need, the same trick `stow-build` plays
    /// in CI.
    ///
    /// # Errors
    ///
    /// A grant path that does not resolve, an audit directory that cannot
    /// be prepared, or the sandbox's own construction failure — including
    /// heel refusing a level the platform cannot enforce.
    pub async fn create(mut request: SandboxRequest<'_>) -> stow_types::error::Result<Self> {
        let audit_dir = crate::config::audit_dir()?;
        std::fs::create_dir_all(&audit_dir).map_err(|error| {
            stow_types::stow_error!(
                "create the audit directory {}: {error}",
                audit_dir.display()
            )
        })?;
        let audit = DeniedAccessLog {
            dir: audit_dir,
            files: request.isolation.config.audit_files,
            level: request.isolation.level.as_str(),
        };
        let ipc = request.ipc.take();
        let level = request.isolation.level.as_str();
        let network = if request.confinement.network_allowed() {
            let log = NetworkAuditLog::rolling_daily(&audit.dir, audit.files)
                .map_err(|error| stow_types::stow_error!("open the network audit log: {error}"))?;
            let builder = confined_builder(
                SandboxConfigBuilder::default().network(Audited::new(AllowAll, log)),
                &request,
            )
            .await?;
            Network::Allowed(create_sandbox(build_config(builder, ipc), level).await?)
        } else {
            let builder = confined_builder(SandboxConfigBuilder::default(), &request).await?;
            Network::Denied(create_sandbox(build_config(builder, ipc), level).await?)
        };
        Ok(Self { network, audit })
    }

    /// heel's IPC socket, when a router was configured — the endpoint
    /// the facades inside reach the supervisor through.
    pub fn ipc_endpoint(&self) -> Option<&Path> {
        match &self.network {
            Network::Allowed(sandbox) => sandbox.ipc_endpoint(),
            Network::Denied(sandbox) => sandbox.ipc_endpoint(),
        }
    }

    /// Run `command` in the sandbox and return its exit status — the
    /// sandboxed cargo's own status, which travels up to the caller the
    /// same way the unsandboxed one's does (stow#652).
    ///
    /// The accesses the sandbox denies while it runs are written to the
    /// audit log on platforms that report them.
    ///
    /// # Errors
    ///
    /// A spawn failure, or a denied-access recording that cannot start or
    /// be written; a non-zero cargo status is an `Ok` value.
    pub async fn status(
        &self,
        command: &SandboxedCommand,
    ) -> stow_types::error::Result<std::process::ExitStatus> {
        match &self.network {
            Network::Allowed(sandbox) => self.audited(sandbox, command).await,
            Network::Denied(sandbox) => self.audited(sandbox, command).await,
        }
    }

    async fn audited<N: NetworkPolicy>(
        &self,
        sandbox: &Sandbox<N>,
        command: &SandboxedCommand,
    ) -> stow_types::error::Result<std::process::ExitStatus> {
        let recorder = match sandbox.record_denials().await {
            Ok(recorder) => Some(recorder),
            // The platform's kernel reports no denials a process can follow.
            // The boundary is unaffected; only this record of it is absent.
            Err(heel::Error::UnsupportedSetting { platform, .. }) => {
                tracing::warn!(
                    platform,
                    "denied accesses are not recorded on this platform; network destinations still are"
                );
                None
            }
            Err(error) => {
                return Err(stow_types::stow_error!(
                    "record the accesses the build sandbox denies: {error}"
                ));
            }
        };
        let status = run(sandbox, command).await;
        if let Some(recorder) = recorder {
            let denials = recorder.finish().await.map_err(|error| {
                stow_types::stow_error!("collect the accesses the build sandbox denied: {error}")
            })?;
            self.audit.record(&denials)?;
        }
        status
    }
}

async fn create_sandbox<N: NetworkPolicy>(
    config: SandboxConfig<N>,
    level: &str,
) -> stow_types::error::Result<Sandbox<N>> {
    Sandbox::with_config(config).await.map_err(|error| {
        let cause = match &error {
            // Landlock and the seccomp broker need kernel 6.7.
            heel::Error::UnsupportedPlatformVersion { .. } => {
                "the kernel is too old for the sandbox (Linux 6.7 or newer is required)"
            }
            // heel's own message names the value found and the value needed.
            heel::Error::PtraceScopeTooStrict { .. } => {
                "the host's Yama setting forbids the sandbox broker"
            }
            heel::Error::SeccompNotifyUnavailable(_) => {
                "the host offers no seccomp user notification for the sandbox broker"
            }
            heel::Error::UnsupportedSetting { .. } => {
                "this platform cannot enforce a setting the level needs"
            }
            _ => "the sandbox could not be set up",
        };
        stow_types::stow_error!(
            "isolation level `{level}` cannot be enforced, and stow never runs a build with weaker protection: {cause}: {error}"
        )
    })
}

/// Where a build's denied accesses are written: one line of JSON per denial in
/// a daily file beside heel's network audit files, the oldest removed past
/// `files`.
struct DeniedAccessLog {
    dir: PathBuf,
    files: usize,
    level: &'static str,
}

/// One denied access as the audit log spells it.
#[derive(serde::Serialize)]
struct DeniedAccessRecord<'a> {
    level: &'static str,
    #[serde(flatten)]
    denial: &'a heel::Denial,
}

impl DeniedAccessLog {
    const PREFIX: &'static str = "denied-access";

    fn record(&self, denials: &[heel::Denial]) -> stow_types::error::Result<()> {
        if denials.is_empty() {
            return Ok(());
        }
        let today = time::OffsetDateTime::now_utc().date();
        let path = self.dir.join(format!(
            "{}.{:04}-{:02}-{:02}.jsonl",
            Self::PREFIX,
            today.year(),
            u8::from(today.month()),
            today.day()
        ));
        let mut lines = String::new();
        for denial in denials {
            lines.push_str(
                &serde_json::to_string(&DeniedAccessRecord {
                    level: self.level,
                    denial,
                })
                .map_err(|error| stow_types::stow_error!("serialize a denied access: {error}"))?,
            );
            lines.push('\n');
        }
        {
            use std::io::Write as _;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .and_then(|mut file| file.write_all(lines.as_bytes()))
                .map_err(|error| {
                    stow_types::stow_error!("write the audit log {}: {error}", path.display())
                })?;
        }
        tracing::info!(
            denied = denials.len(),
            log = %path.display(),
            "the build sandbox denied accesses"
        );
        self.prune()
    }

    /// Remove the oldest daily files past the configured count.
    fn prune(&self) -> stow_types::error::Result<()> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&self.dir)
            .map_err(|error| {
                stow_types::stow_error!("read the audit directory {}: {error}", self.dir.display())
            })?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with(Self::PREFIX))
            })
            .collect();
        // The date is in the name, so the names sort oldest first.
        files.sort();
        let excess = files.len().saturating_sub(self.files);
        for path in files.into_iter().take(excess) {
            std::fs::remove_file(&path).map_err(|error| {
                stow_types::stow_error!("remove the old audit log {}: {error}", path.display())
            })?;
        }
        Ok(())
    }
}

/// The part of the sandbox configuration that does not depend on the
/// network policy: the level's file and environment policy, the grants and
/// the stable identity.
async fn confined_builder<N: NetworkPolicy>(
    builder: SandboxConfigBuilder<N, IpcUnconfigured>,
    request: &SandboxRequest<'_>,
) -> stow_types::error::Result<SandboxConfigBuilder<N, IpcUnconfigured>> {
    let mut builder = builder.heel_binary(request.runtime_executable);
    let (env_names, grants): (Vec<String>, Vec<(PathBuf, Access, &'static str)>) = match request
        .confinement
    {
        Confinement::Protect => {
            builder = builder
                .filesystem_strict(false)
                .security(
                    // The denylists are the whole read and write policy; the
                    // home-directory data protections of the strict preset
                    // would deny toolchain state a build reads, so they are
                    // off, and the hardware toggles stay closed.
                    SecurityConfigBuilder::from_permissive()
                        .allow_tcc_prompts(false)
                        .allow_hardware(false)
                        .build(),
                )
                .writable_file_system(true)
                .read_denylist(ReadDenylist::credentials())
                .write_denylist(WriteDenylist::persistence().except(
                    // Cargo's private git clones: their hooks are never run
                    // by a user, and cargo creates and removes them itself.
                    crate::config::require_cargo_home()?.join("git"),
                ));
            let env_names = protect_env_names(
                std::env::vars_os().filter_map(|(name, _)| name.into_string().ok()),
            );
            // Every grant must canonicalize, and cargo has not run to create
            // the target directory — a fresh checkout, or right after
            // `cargo clean` (stow#823).
            std::fs::create_dir_all(request.target_dir).map_err(|error| {
                stow_types::stow_error!(
                    "create the target directory {}: {error}",
                    request.target_dir.display()
                )
            })?;
            let mut grants = protect_grants(request);
            grants.extend(
                toolchain_grants(
                    request,
                    &crate::config::require_cargo_home()?,
                    rustup_home().as_deref(),
                )
                .await?,
            );
            (env_names, grants)
        }
        Confinement::Strict | Confinement::Offline => {
            builder = builder
                .filesystem_strict(true)
                .security(SecurityConfig::strict())
                .identity(stow_identity()?);
            let mut env_names = sandbox_env_names(
                std::env::vars_os().filter_map(|(name, _)| name.into_string().ok()),
            );
            let mut allowlist = sandbox_grants(request).await?;
            let crates = crate::isolation::locked_crates(request.lockfile_root)?;
            for grant in crate::isolation::applicable_grants(&request.isolation.config, &crates) {
                tracing::debug!(crate_name = %grant.crate_name, "isolation grant applies");
                env_names.extend(grant.env.iter().cloned());
                for (paths, access) in [
                    (&grant.read, Access::READ),
                    (&grant.write, Access::WRITE),
                    (&grant.exec, Access::READ | Access::EXEC),
                ] {
                    allowlist.extend(paths.iter().map(|path| {
                        (
                            path.clone(),
                            access,
                            "an [[isolation.grant]] entry for a crate in the build",
                        )
                    }));
                }
            }
            (env_names, allowlist)
        }
    };
    builder = builder.env_passthroughs(env_names);
    for (path, access, reason) in grants {
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
    Ok(builder)
}

/// What `protect` grants for stow's own paths. The machine is otherwise
/// open and the registry needs no grant, but the toolchain does on Linux,
/// where heel executes only under the system trees and the home directory:
/// `toolchain_grants` adds it, read and execute. The target directory is
/// written and executed, and the scratch, shim and stow binary paths may
/// sit under a temporary directory heel does not let a process execute from.
fn protect_grants(request: &SandboxRequest<'_>) -> Vec<(PathBuf, Access, &'static str)> {
    let mut grants = vec![
        (
            request.target_dir.to_path_buf(),
            Access::WRITE | Access::EXEC,
            "the target directory — build scripts and proc macros are compiled here and must execute",
        ),
        (
            request.runtime_executable.to_path_buf(),
            Access::READ | Access::EXEC,
            "the stow binary the wrapper shims resolve to",
        ),
    ];
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
    grants
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

/// The identity every stow sandbox shares (stow#815): `heel-id-stow` on
/// Windows, where the persistent grants are written once for the
/// profile's package SID and heel reconciles them at each sandbox start;
/// on macOS and Linux heel folds them into each sandbox's policy and
/// [`Identity::prepare`]/[`Identity::remove`] are no-ops, so one path
/// serves every platform.
///
/// The persistent set is a fixed function of the user's environment —
/// identical for every build and for `stow setup`. It names only roots
/// every build reads, and none is writable: a build-dependent set would
/// make concurrent builds revoke each other's grants and pay the
/// toolchain ACL rewrite again, while a writable one would persist a
/// hole the per-build boundary exists to close. Writable or
/// build-shaped grants (sources, the target dir, scratch, shims, the
/// package-cache lock, PATH tool dirs, env-named linkers, driver probe
/// answers) stay in [`sandbox_grants`]; where one of those already sits
/// under a persistent root heel skips it as open, so they are not
/// filtered here.
///
/// # Errors
///
/// An invalid identity name (unreachable for `"stow"`) or an
/// unresolvable cargo home.
pub fn stow_identity() -> stow_types::error::Result<Identity> {
    let mut persistent: Vec<(PathBuf, Access)> = Vec::new();
    if let Some(home) = rustup_home().filter(|home| home.is_dir()) {
        persistent.push((home, Access::READ | Access::EXEC));
    }
    let cargo_home = crate::config::require_cargo_home()?;
    for (dir, access) in [
        ("registry", Access::READ),
        ("git", Access::READ),
        ("bin", Access::READ | Access::EXEC),
    ] {
        let dir = cargo_home.join(dir);
        if dir.is_dir() {
            persistent.push((dir, access));
        }
    }
    #[cfg(windows)]
    for root in msvc_identity_roots() {
        if root.is_dir() {
            persistent.push((root, Access::READ | Access::EXEC));
        }
    }
    let mut identity = Identity::named("stow")
        .map_err(|error| stow_types::stow_error!("the stow sandbox identity name: {error}"))?;
    for (path, access) in persistent {
        // Canonicalized like the per-build grants: heel's record and the
        // reconcile compare spellings, so a symlinked home or a stray
        // `..` must not give `setup` and a build different spellings of
        // the same root — the revoke/re-grant churn this exists to remove.
        let path = path.canonicalize().map_err(|error| {
            stow_types::stow_error!(
                "canonicalize the persistent sandbox grant {}: {error}",
                path.display()
            )
        })?;
        identity = identity.persistent_grant(Grant::new(path, access));
    }
    Ok(identity)
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
    // The target dir is granted below and every grant must
    // canonicalize, but cargo has not run to create it — a fresh
    // checkout, or right after `cargo clean` (stow#823).
    std::fs::create_dir_all(request.target_dir).map_err(|error| {
        stow_types::stow_error!(
            "create the target directory {}: {error}",
            request.target_dir.display()
        )
    })?;

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

    conditional_grants(&cargo_home, &mut grants);
    grants.extend(toolchain_grants(request, &cargo_home, rustup_home.as_deref()).await?);

    Ok(grants)
}

/// Everything under which the build finds and executes its toolchain:
/// rustup's home, cargo's `bin` proxies, the compilers' directories, the
/// rustc sysroot, the SDK roots and compiler/linker env vars, stow's own
/// tools directory, and the driver, linker and `COMPILER_PATH` trees the
/// drivers report. Read and execute only. The single source of "toolchain
/// paths": `strict`/`offline` grant it as part of a closed filesystem, and
/// `protect` grants it because heel's Linux rules execute only under the
/// system trees and the home directory, so a toolchain outside them (the
/// managed mold, a `/opt` or `/nix` install) would otherwise be denied.
async fn toolchain_grants(
    request: &SandboxRequest<'_>,
    cargo_home: &Path,
    rustup_home: Option<&Path>,
) -> stow_types::error::Result<Vec<(PathBuf, Access, &'static str)>> {
    let mut grants: Vec<(PathBuf, Access, &'static str)> = Vec::new();
    let bin = cargo_home.join("bin");
    if bin.exists() {
        grants.push((
            bin,
            Access::READ | Access::EXEC,
            "the rustup proxy shims `cargo`/`rustc` when PATH leads there",
        ));
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
            if env_name::eq_any(&name, TOOLCHAIN_ROOT_VARS)
                || env_name::eq_any(&name, ANDROID_ROOT_VARS)
            {
                let dir = PathBuf::from(value);
                return dir.is_dir().then(|| {
                    (
                        dir,
                        Access::READ | Access::EXEC,
                        "a toolchain install tree named by an SDK root variable",
                    )
                });
            }
            if env_name::starts_with_any(&name, TOOLCHAIN_EXE_PREFIXES) {
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

/// Seal a configured builder, applying the supervisor's IPC router
/// when one is registered — `ipc` moves the builder into the
/// `IpcConfigured` typestate (heel#59), so the optional router can only
/// be applied where `build` erases the difference.
fn build_config<N: heel::NetworkPolicy>(
    builder: SandboxConfigBuilder<N, IpcUnconfigured>,
    ipc: Option<IpcRouter>,
) -> SandboxConfig<N> {
    match ipc {
        Some(router) => builder.ipc(router).build(),
        None => builder.build(),
    }
}

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
        let toolchain_exe = env_name::eq_any(&name, &["CC", "CXX", "LD"])
            || env_name::starts_with_any(&name, &["CC_", "CXX_", "LD_"])
            || (env_name::starts_with(&name, "CARGO_TARGET_")
                && env_name::ends_with(&name, "_LINKER"));
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
                let host = std::env::var_os(key);
                let access = if env_name::eq(key, "PATH") {
                    Access::READ | Access::EXEC
                } else {
                    Access::READ
                };
                for dir in added_entries(value, host.as_deref()) {
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

/// Returns only entries `find_msvc_tools` prepended to the host's value.
/// Host PATH/LIB/INCLUDE entries are not toolchain entries to grant.
#[cfg(windows)]
fn added_entries(composed: &OsStr, host: Option<&OsStr>) -> Vec<PathBuf> {
    let host_entries = host
        .map(|host| std::env::split_paths(host).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut added = Vec::new();
    for entry in std::env::split_paths(composed) {
        if !host_entries.contains(&entry) && !added.contains(&entry) {
            added.push(entry);
        }
    }
    added
}

/// The environment allowlist: the names a build legitimately reads —
/// cargo's own configuration, rustc and rustup settings, the compiler
/// toolchain's variables, locale and terminal information — and nothing
/// else. Registry tokens and credential variables are deliberately
/// absent: `CARGO_REGISTRIES_*_TOKEN` and friends never match a prefix
/// below, and `env`/`SSH_AUTH_SOCK`-style secrets die with the list.
///
/// `names` is the parent environment's variable names, matched the way
/// the host's environment does — case-insensitively on Windows, where the
/// search path is stored `Path`.
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
        "VSINSTALLDIR",
        "VSCMD_ARG_TGT_ARCH",
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
            !env_name::eq_any(name, &["CARGO_TARGET_DIR", "CARGO_HOME", "RUSTUP_HOME"])
                && (env_name::eq_any(name, EXACT)
                    || env_name::eq_any(name, ANDROID_ROOT_VARS)
                    || env_name::starts_with_any(name, PREFIXES))
        })
        .collect()
}

/// What `protect` passes through: every host variable except credentials
/// (`isolation::is_credential_variable`), the variables stow sets for the
/// build itself, and the proxy variables heel points at its own proxy.
fn protect_env_names(names: impl Iterator<Item = String>) -> Vec<String> {
    names
        .filter(|name| {
            !crate::isolation::is_credential_variable(name)
                && !env_name::eq_any(name, &["CARGO_TARGET_DIR", "CARGO_HOME", "RUSTUP_HOME"])
                && !["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"]
                    .iter()
                    .any(|proxy| name.eq_ignore_ascii_case(proxy))
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

#[cfg(windows)]
/// Spells the host's MSVC lookup as the variables a developer prompt sets.
/// An existing host prompt passes through; no host match yields an empty list.
fn msvc_developer_environment() -> stow_types::error::Result<Vec<(OsString, OsString)>> {
    if std::env::var_os("VCINSTALLDIR").is_some() {
        return Ok(Vec::new());
    }
    let Some(tool) = find_msvc_tools::find_tool(std::env::consts::ARCH, "link.exe") else {
        tracing::warn!(
            arch = std::env::consts::ARCH,
            "no MSVC installation found for the host; a sandboxed build that links will fail"
        );
        return Ok(Vec::new());
    };
    let mut envs = tool.env().into_iter().cloned().collect::<Vec<_>>();
    envs.extend(developer_prompt_vars(tool.path())?);
    Ok(envs)
}

/// The installation roots the MSVC discovery locates for the host —
/// the Visual Studio root a `link.exe` in the VS 2017+ layout implies
/// and the Windows kit roots the discovered SDK dirs sit under —
/// persisted READ|EXEC on the identity so the toolchain ACL is written
/// once, not per build (stow#815). A `link.exe` outside the VS layout —
/// an SDK or LLVM linker — names no Visual Studio installation, so it
/// adds no root; the per-build grants still cover its directory.
#[cfg(windows)]
fn msvc_identity_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(tool) = find_msvc_tools::find_tool(std::env::consts::ARCH, "link.exe")
        && let Ok(layout) = visual_studio_layout(tool.path())
    {
        roots.push(layout.visual_studio_dir);
    }
    if let Some(sdk) = find_msvc_tools::find_windows_sdk(std::env::consts::ARCH) {
        for dir in sdk.path().chain(sdk.libs()).chain(sdk.include()) {
            if let Some(root) = windows_kit_root(dir)
                && !roots.contains(&root)
            {
                roots.push(root);
            }
        }
    }
    roots
}

/// The kit installation root a discovered Windows SDK directory lives
/// under: every dir the discovery reports sits in the kit's `bin`, `lib`
/// or `include` tree, so the root is the ancestor above that component —
/// whatever `KitsRoot10` or `InstallationFolder` the registry named,
/// never a hardcoded drive. A `bin`/`lib`/`include` at a drive root names
/// no installation, and a dir with none of those components is not an
/// SDK dir; both yield `None`.
#[cfg(windows)]
fn windows_kit_root(dir: &Path) -> Option<PathBuf> {
    let mut root = PathBuf::new();
    for component in dir.components() {
        if component.as_os_str().to_str().is_some_and(|name| {
            ["bin", "lib", "include"]
                .iter()
                .any(|tree| name.eq_ignore_ascii_case(tree))
        }) {
            return root
                .components()
                .any(|part| matches!(part, std::path::Component::Normal(_)))
                .then_some(root);
        }
        root.push(component.as_os_str());
    }
    None
}

/// The directories the Visual Studio 2017+ layout a `link.exe` path
/// implies — `VC\Tools\MSVC\<version>\bin\Host<arch>\<arch>\link.exe`
/// under the installation root — validated component by component so a
/// linker outside that layout cannot masquerade as an installation
/// root.
#[cfg(windows)]
struct VsLayout {
    /// `VSCMD_ARG_TGT_ARCH` — the `<arch>` leaf the linker serves.
    target_arch: OsString,
    /// `VCToolsInstallDir` — the `MSVC\<version>` directory.
    version_dir: PathBuf,
    /// `VCINSTALLDIR` — the `VC` directory.
    vc_dir: PathBuf,
    /// `VSINSTALLDIR` — the Visual Studio installation root.
    visual_studio_dir: PathBuf,
}

#[cfg(windows)]
/// Reads the [`VsLayout`] a Visual Studio 2017+ linker path spells.
/// Paths outside that layout return an error.
fn visual_studio_layout(link: &Path) -> stow_types::error::Result<VsLayout> {
    let invalid_layout = || {
        stow_types::stow_error!(
            "the linker at {} is not in the Visual Studio 2017+ layout, so the sandbox cannot spell out its developer environment",
            link.display()
        )
    };
    let mut up = link.ancestors().skip(1);
    let (
        Some(target_dir),
        Some(host_dir),
        Some(bin_dir),
        Some(version_dir),
        Some(msvc_dir),
        Some(tools_dir),
        Some(vc_dir),
        Some(visual_studio_dir),
    ) = (
        up.next(),
        up.next(),
        up.next(),
        up.next(),
        up.next(),
        up.next(),
        up.next(),
        up.next(),
    )
    else {
        return Err(invalid_layout());
    };
    let Some(target_arch) = target_dir.file_name() else {
        return Err(invalid_layout());
    };
    let Some(host_name) = host_dir.file_name().and_then(OsStr::to_str) else {
        return Err(invalid_layout());
    };
    let is_host_dir = host_name
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Host"))
        && host_name.len() > 4;
    let is_component = |path: &Path, expected: &str| {
        path.file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(expected))
    };
    if !is_component(link, "link.exe")
        || !is_host_dir
        || !is_component(bin_dir, "bin")
        || !is_component(msvc_dir, "MSVC")
        || !is_component(tools_dir, "Tools")
        || !is_component(vc_dir, "VC")
    {
        return Err(invalid_layout());
    }
    Ok(VsLayout {
        target_arch: target_arch.to_os_string(),
        version_dir: version_dir.to_path_buf(),
        vc_dir: vc_dir.to_path_buf(),
        visual_studio_dir: visual_studio_dir.to_path_buf(),
    })
}

#[cfg(windows)]
/// Derives developer-prompt variables from a Visual Studio 2017+ linker path.
/// Paths outside that layout return an error.
fn developer_prompt_vars(link: &Path) -> stow_types::error::Result<Vec<(OsString, OsString)>> {
    let layout = visual_studio_layout(link)?;
    let with_trailing_backslash = |path: &Path| {
        let mut value = path.as_os_str().to_os_string();
        value.push("\\");
        value
    };
    Ok(vec![
        (
            OsString::from("VSINSTALLDIR"),
            with_trailing_backslash(&layout.visual_studio_dir),
        ),
        (
            OsString::from("VCINSTALLDIR"),
            with_trailing_backslash(&layout.vc_dir),
        ),
        (
            OsString::from("VCToolsInstallDir"),
            with_trailing_backslash(&layout.version_dir),
        ),
        (OsString::from("VSCMD_ARG_TGT_ARCH"), layout.target_arch),
    ])
}

/// The variables the sandboxed toolchain needs spelled out, not passed
/// through: `CARGO_HOME` and `RUSTUP_HOME` are resolved here — same as
/// the grant computation — so a rustup proxy inside the sandbox never
/// falls back to a home directory it cannot write. On Windows, rustc
/// and the `cc` crate find MSVC through `find_msvc_tools`; its
/// developer-prompt strategy is the one available without the Visual
/// Studio installer's machine state. This resolves the same `link.exe`,
/// `LIB` and `INCLUDE` as the host without changing compiler arguments,
/// rustflags or target-linker configuration.
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
    #[cfg(windows)]
    envs.extend(msvc_developer_environment()?);
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
    fn the_sandbox_env_admits_the_search_path_under_host_rules() {
        // Windows stores the search path as `Path` and compares names
        // case-insensitively, so it must pass the allowlist there — the
        // failure the runner hit (stow#779). Everywhere else `Path` is a
        // different variable from `PATH` and stays out.
        let admitted = sandbox_env_names(["Path".to_owned()].into_iter());
        #[cfg(windows)]
        assert_eq!(admitted, vec!["Path".to_owned()]);
        #[cfg(not(windows))]
        assert_eq!(admitted, Vec::<String>::new());
        assert_eq!(
            sandbox_env_names(["PATH".to_owned()].into_iter()),
            vec!["PATH".to_owned()]
        );
    }

    #[test]
    fn the_sandbox_env_excludes_the_overridden_dirs_under_host_rules() {
        // `CARGO_TARGET_` is an admitted prefix, so the three directories
        // stow sets itself are refused by name — under the host's rules:
        // on Windows the lowercase spelling is the same variable and is
        // refused too, while elsewhere it never matched the allowlist.
        for name in [
            "CARGO_TARGET_DIR",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "cargo_target_dir",
        ] {
            assert_eq!(
                sandbox_env_names([name.to_owned()].into_iter()),
                Vec::<String>::new()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn added_entries_keeps_only_composed_paths_not_in_the_host() {
        let composed = std::env::join_paths([
            PathBuf::from("a"),
            PathBuf::from("b"),
            PathBuf::from("h1"),
            PathBuf::from("h2"),
        ])
        .unwrap();
        let host = std::env::join_paths([PathBuf::from("h1"), PathBuf::from("h2")]).unwrap();
        assert_eq!(
            added_entries(&composed, Some(&host)),
            vec![PathBuf::from("a"), PathBuf::from("b")]
        );
        assert_eq!(
            added_entries(&composed, None),
            vec![
                PathBuf::from("a"),
                PathBuf::from("b"),
                PathBuf::from("h1"),
                PathBuf::from("h2"),
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn developer_prompt_vars_spells_the_visual_studio_layout() {
        let link =
            Path::new(r"C:\VS\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe");
        assert_eq!(
            developer_prompt_vars(link).unwrap(),
            vec![
                (
                    OsString::from("VSINSTALLDIR"),
                    OsString::from(r"C:\VS\2022\BuildTools\"),
                ),
                (
                    OsString::from("VCINSTALLDIR"),
                    OsString::from(r"C:\VS\2022\BuildTools\VC\"),
                ),
                (
                    OsString::from("VCToolsInstallDir"),
                    OsString::from(r"C:\VS\2022\BuildTools\VC\Tools\MSVC\14.44.35207\"),
                ),
                (OsString::from("VSCMD_ARG_TGT_ARCH"), OsString::from("x64")),
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn developer_prompt_vars_rejects_paths_outside_the_visual_studio_layout() {
        assert!(
            developer_prompt_vars(Path::new(r"C:\Program Files\Git\usr\bin\link.exe")).is_err()
        );
    }

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
    fn protect_passes_the_host_environment_minus_credentials_and_proxies() {
        let names = [
            "PATH",
            "EDITOR",
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "SSH_AUTH_SOCK",
            "https_proxy",
            "ALL_PROXY",
            "CARGO_HOME",
            "CARGO_TARGET_DIR",
            "MY_APP_FLAG",
        ]
        .map(String::from);
        assert_eq!(
            protect_env_names(names.into_iter()),
            ["PATH", "EDITOR", "MY_APP_FLAG"]
        );
    }

    #[test]
    fn a_cross_target_keeps_the_real_host_for_the_build_scripts() {
        // A wasm32 consumer build names a target outside every CI
        // family, but its build scripts and proc macros still compile
        // for the rustc's real host — so `build_targets` carries the
        // spelled target AND the host the driver resolved, not a
        // runner-family mapping of the consumer target.
        let dummy = PathBuf::from("/usr/bin/true");
        let isolation = Isolation::off();
        let args = vec![
            OsString::from("--target"),
            OsString::from("wasm32-unknown-unknown"),
        ];
        let request = SandboxRequest {
            confinement: Confinement::Offline,
            isolation: &isolation,
            lockfile_root: Path::new("/tmp"),
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

    #[test]
    fn the_identity_is_a_function_of_the_environment_not_the_build() {
        // Two builds differing in every build-shaped input — the target
        // spelled, the args, the dirs — must hold the same persistent
        // set, or concurrent builds would revoke each other's toolchain
        // grants and pay the ACL rewrite this removes (stow#815).
        // `stow_identity` takes no `SandboxRequest` at all: the
        // signature is the enforcement, and the requests below stand in
        // for the builds.
        let dummy = PathBuf::from("/usr/bin/true");
        let isolation = Isolation::off();
        let host_args = vec![OsString::from("--release")];
        let cross_args = vec![
            OsString::from("--target"),
            OsString::from("wasm32-unknown-unknown"),
        ];
        let host_build = SandboxRequest {
            confinement: Confinement::Strict,
            isolation: &isolation,
            lockfile_root: Path::new("/tmp"),
            source_roots: &[],
            target_dir: Path::new("/tmp/host-target"),
            scratch_dir: None,
            shims_dir: None,
            runtime_executable: &dummy,
            rustc_executable: &dummy,
            host_target: "aarch64-apple-darwin",
            cargo_dir: Path::new("/tmp/host-project"),
            cargo_args: &host_args,
            ipc: None,
        };
        let cross_build = SandboxRequest {
            confinement: Confinement::Offline,
            isolation: &isolation,
            lockfile_root: Path::new("/tmp"),
            source_roots: &[],
            target_dir: Path::new("/tmp/cross-target"),
            scratch_dir: None,
            shims_dir: None,
            runtime_executable: &dummy,
            rustc_executable: &dummy,
            host_target: "x86_64-pc-windows-msvc",
            cargo_dir: Path::new("/tmp/cross-project"),
            cargo_args: &cross_args,
            ipc: None,
        };
        assert_eq!(
            stow_identity().expect("the identity builds"),
            stow_identity().expect("the identity builds"),
        );
        // And no persistent grant may reach a directory a build owns —
        // sources, target dir, scratch, the dir cargo runs in.
        let identity = stow_identity().expect("the identity builds");
        for grant in identity.persistent_grants() {
            for build_dir in [
                host_build.target_dir,
                cross_build.target_dir,
                host_build.cargo_dir,
                cross_build.cargo_dir,
            ] {
                assert!(
                    !grant.path().starts_with(build_dir),
                    "persistent grant on {} reaches build-owned {}",
                    grant.path().display(),
                    build_dir.display(),
                );
            }
        }
    }

    #[test]
    fn no_persistent_grant_is_writable() {
        // A persistent grant outlives the sandbox: a writable one would
        // hold open a hole the per-build boundary exists to close.
        let identity = stow_identity().expect("the identity builds");
        for grant in identity.persistent_grants() {
            assert!(
                !grant.access().can_write(),
                "persistent grant on {} is writable",
                grant.path().display(),
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_kit_root_reads_the_kit_tree_boundary() {
        assert_eq!(
            windows_kit_root(Path::new(r"C:\Windows Kits\10\bin\10.0.26100.0\x64")),
            Some(PathBuf::from(r"C:\Windows Kits\10"))
        );
        assert_eq!(
            windows_kit_root(Path::new(r"D:\SDKs\8.1\Lib\winv6.3\um\x64")),
            Some(PathBuf::from(r"D:\SDKs\8.1"))
        );
        assert_eq!(
            windows_kit_root(Path::new(r"C:\Windows Kits\10\Include\10.0.26100.0\ucrt")),
            Some(PathBuf::from(r"C:\Windows Kits\10"))
        );
        // A kit tree directly at a drive root names no installation.
        assert_eq!(windows_kit_root(Path::new(r"C:\bin\x64")), None);
        // A dir outside the kit layout derives no root.
        assert_eq!(windows_kit_root(Path::new(r"C:\tools\rust")), None);
    }
}

use std::path::{Path, PathBuf};

use async_fs::create_dir_all;
use async_process::Command;
use heel::{Access, Sandbox, SandboxConfigBuilder};
use stow_types::api::BuildTaskPayload;
use stow_types::capture::CapturedRustcArtifact;
use tempfile::TempDir;
use zenwave::Client;

use crate::capture::{
    CaptureCollector, STOW_BUILD_CAPTURE_DIR_ENV, STOW_BUILD_CAPTURE_IPC_ENV,
    STOW_BUILD_TASK_CRATE_NAME_ENV, STOW_BUILD_TASK_CRATE_VERSION_ENV, StowCaptureCommand,
};
use crate::workspace_mirror;
use stow_shim as wrapper_shim;

const STOW_BUILD_WORKSPACE_ROOT_ENV: &str = "STOW_BUILD_WORKSPACE_ROOT";
const STOW_BUILD_CARGO_SUBCOMMAND_ENV: &str = "STOW_BUILD_CARGO_SUBCOMMAND";
const STOW_BUILD_SOURCE_ROOT_ENV: &str = "STOW_BUILD_SOURCE_ROOT";
/// Test hook forwarded verbatim into the sandbox: a probe build script reads
/// the path it names to prove the sandbox denies it. Never set in production.
const STOW_PROBE_FORBIDDEN_PATH_ENV: &str = "STOW_PROBE_FORBIDDEN_PATH";

pub struct BuildWorkspace {
    _tempdir: Option<TempDir>,
    manifest_path: PathBuf,
    workspace_root: PathBuf,
    capture_dir: PathBuf,
}

impl BuildWorkspace {
    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn capture_dir(&self) -> &Path {
        &self.capture_dir
    }
}

/// A workspace whose cargo phases have run to completion inside the sandbox.
///
/// Owns the run directory holding each phase's `CARGO_TARGET_DIR` — kept
/// outside the workspace root because the sandbox working dir denies
/// execution on every backend — plus the capture records the host collected
/// over IPC.
pub struct BuiltWorkspace {
    workspace: BuildWorkspace,
    _run_dir: TempDir,
    captures: Vec<CapturedRustcArtifact>,
}

impl BuiltWorkspace {
    pub const fn workspace(&self) -> &BuildWorkspace {
        &self.workspace
    }

    pub fn captures(&self) -> &[CapturedRustcArtifact] {
        &self.captures
    }
}

pub async fn create_workspace(
    task: &BuildTaskPayload,
) -> stow_types::error::Result<BuildWorkspace> {
    if let Some(workspace) = open_source_workspace().await? {
        tracing::info!(
            task_id = %task.task_id,
            crate_name = %task.crate_name,
            version = %task.version,
            target = %task.target,
            manifest_path = %workspace.manifest_path().display(),
            workspace_root = %workspace.workspace_root().display(),
            "using existing source workspace for trusted build"
        );
        return Ok(workspace);
    }

    let (tempdir, workspace_root) = create_workspace_root().await?;
    let manifest_path = download_crate_manifest(task, &workspace_root).await?;
    let source_root = manifest_path
        .parent()
        .ok_or_else(|| {
            stow_types::stow_error!(
                "downloaded crate manifest {} has no parent directory",
                manifest_path.display()
            )
        })?
        .to_path_buf();
    let capture_dir = source_root.join(".stow-rustc-capture");
    create_dir_all(&capture_dir).await?;

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        manifest_path = %manifest_path.display(),
        workspace_root = %source_root.display(),
        "created CI build workspace"
    );

    Ok(BuildWorkspace {
        _tempdir: tempdir,
        manifest_path,
        workspace_root: source_root,
        capture_dir,
    })
}

pub async fn build(
    task: &BuildTaskPayload,
    output_dir: &Path,
) -> stow_types::error::Result<BuiltWorkspace> {
    let mirror_key = workspace_mirror::MirrorTaskKey {
        target: task.target.as_str().to_owned(),
        rustc_version: task.rustc_version.as_str().to_owned(),
        preserve_lockfile: task.preserve_lockfile,
    };
    let workspace = stabilize_workspace(create_workspace(task).await?, &mirror_key).await?;

    // Phase 0 runs on the host: `cargo fetch` resolves the dependency graph
    // and populates the registry cache, so the sandboxed phases can run
    // `--frozen` — no lockfile writes, no index access — with every outbound
    // connection an untrusted build script still attempts audited. Feature
    // flags don't exist on `fetch`: it downloads the full dependency closure
    // for every feature and every target.
    let mut fetch = Command::new("cargo");
    fetch
        .arg("fetch")
        .arg("--manifest-path")
        .arg(workspace.manifest_path());
    if task.preserve_lockfile {
        fetch.arg("--locked");
    }
    let status = fetch
        .env("RUSTUP_TOOLCHAIN", task.rustc_version.as_str())
        .status()
        .await
        .map_err(|error| stow_types::stow_error!("run cargo fetch: {error}"))?;
    if !status.success() {
        return Err(stow_types::stow_error!(
            "cargo fetch failed for {} {} on {} with status {}",
            task.crate_name,
            task.version,
            task.target,
            status
        ));
    }

    let audit_log = heel::NetworkAuditLog::file(output_dir.join("network-audit.jsonl"))
        .map_err(|error| stow_types::stow_error!("open network audit log: {error}"))?;
    let remap_flag = format!(
        "--remap-path-prefix={}={}",
        workspace.workspace_root().display(),
        "stow-ci://workspace"
    );
    let rustflags = merged_rustflags(&remap_flag);
    let cargo_subcommand = cargo_subcommand()?;

    let capture_wrapper = std::env::current_exe().map_err(|error| {
        stow_types::stow_error!("resolve current stow-build executable: {error}")
    })?;
    let runtime_wrapper = sibling_runtime_wrapper(&capture_wrapper)?;
    let wrappers = wrapper_shim::materialize_wrapper_shims(&runtime_wrapper, &capture_wrapper)?;

    // The phase target dirs live outside the workspace root on purpose: the
    // sandbox working dir denies `process-exec` on every backend, so a target
    // dir inside it could never run the build scripts it compiles. `run_dir`
    // is held by the returned `BuiltWorkspace` so the scan can still read the
    // outputs.
    let run_dir = TempDir::new()?;
    let (mut collector, capture_command) = CaptureCollector::channel();
    let phases = cargo_phases(cargo_subcommand);

    let setup = PhaseSetup {
        workspace: &workspace,
        wrappers: &wrappers,
        runtime_wrapper: &runtime_wrapper,
        capture_wrapper: &capture_wrapper,
        capture_command: &capture_command,
        audit_log: &audit_log,
        rustflags: &rustflags,
    };
    for &phase in phases {
        let target_dir = phase_target_dir(run_dir.path(), phase);
        run_sandboxed_phase(&setup, task, phase, &target_dir, &mut collector).await?;
    }

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        cargo_subcommand = cargo_subcommand.as_str(),
        "cargo build completed"
    );

    Ok(BuiltWorkspace {
        workspace,
        _run_dir: run_dir,
        captures: collector.into_records()?,
    })
}

/// The per-run state every sandboxed phase shares.
struct PhaseSetup<'a> {
    workspace: &'a BuildWorkspace,
    wrappers: &'a wrapper_shim::WrapperShimPaths,
    runtime_wrapper: &'a Path,
    capture_wrapper: &'a Path,
    capture_command: &'a StowCaptureCommand,
    audit_log: &'a heel::NetworkAuditLog,
    rustflags: &'a str,
}

/// Run one cargo phase inside its own sandbox, then absorb the capture
/// records it delivered. A duplicate identity or a failed cargo is fatal.
async fn run_sandboxed_phase(
    setup: &PhaseSetup<'_>,
    task: &BuildTaskPayload,
    phase: CargoSubcommand,
    target_dir: &Path,
    collector: &mut CaptureCollector,
) -> stow_types::error::Result<()> {
    create_dir_all(target_dir).await?;
    let sandbox = phase_sandbox(
        setup.workspace,
        target_dir,
        setup.wrappers,
        setup.runtime_wrapper,
        setup.capture_wrapper,
        setup.capture_command.clone(),
        setup.audit_log.clone(),
    )
    .await?;
    let ipc_endpoint = sandbox
        .ipc_endpoint()
        .ok_or_else(|| stow_types::stow_error!("IPC-configured sandbox exposed no endpoint"))?
        .to_path_buf();
    let args = cargo_phase_args(setup.workspace, task, phase).await?;

    let status = sandbox
        .command("cargo")
        .args(args)
        .env("RUSTUP_TOOLCHAIN", task.rustc_version.as_str())
        .env("RUSTFLAGS", setup.rustflags)
        .env("RUSTC_WRAPPER", path_arg(&setup.wrappers.rustc_wrapper)?)
        .env("CARGO_TARGET_DIR", path_arg(target_dir)?)
        .env(
            STOW_BUILD_CAPTURE_DIR_ENV,
            path_arg(setup.workspace.capture_dir())?,
        )
        .env(STOW_BUILD_CAPTURE_IPC_ENV, path_arg(&ipc_endpoint)?)
        // The task crate builds from a content-addressed mirror root, so
        // cargo hands rustc a relative `src/lib.rs` and registry-path
        // detection cannot recover its identity. The capture wrapper falls
        // back to these only for units whose `--crate-name` matches.
        .env(STOW_BUILD_TASK_CRATE_NAME_ENV, task.crate_name.as_str())
        .env(STOW_BUILD_TASK_CRATE_VERSION_ENV, task.version.to_string())
        .env("CARGO_HOME", path_arg(&cargo_home()?)?)
        .env("RUSTUP_HOME", path_arg(&rustup_home()?)?)
        .current_dir(setup.workspace.workspace_root())
        .status()
        .await
        .map_err(|error| {
            stow_types::stow_error!("run sandboxed cargo {}: {error}", phase.as_str())
        })?;
    drop(sandbox);

    // Absorb the records this phase delivered before looking at cargo's
    // exit status: a duplicate identity is fatal either way.
    collector.drain(phase.as_str())?;

    if !status.success() {
        return Err(stow_types::stow_error!(
            "cargo {} failed for {} {} on {} with status {}",
            phase.as_str(),
            task.crate_name,
            task.version,
            task.target,
            status
        ));
    }

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        cargo_target_dir = %target_dir.display(),
        cargo_subcommand = phase.as_str(),
        "cargo phase completed"
    );
    Ok(())
}

/// The `cargo` argv for one sandboxed phase.
async fn cargo_phase_args(
    workspace: &BuildWorkspace,
    task: &BuildTaskPayload,
    phase: CargoSubcommand,
) -> stow_types::error::Result<Vec<String>> {
    let mut args = vec![
        phase.as_str().to_owned(),
        // The host already fetched: no network, no lockfile changes.
        "--frozen".to_owned(),
        "--manifest-path".to_owned(),
        path_arg(workspace.manifest_path())?,
    ];
    if phase == CargoSubcommand::Test {
        args.push("--no-run".to_owned());
    }
    args.extend(CargoFeatureArgs::from_task(task).args());
    // The publisher resolves the closure with `--locked` for the same
    // task, so a missing or stale bundled lockfile must fail here, in the
    // untrusted job, rather than after a successful build.
    if task.preserve_lockfile {
        args.push("--locked".to_owned());
    }
    // Only cross-compiles pass `--target`. Passing it for a host build
    // splits cargo's unit graph into host and target halves and changes
    // the flags it gives the host half — build scripts, proc macros and
    // everything they depend on lose `-C debuginfo`, which the lookup side
    // normalizes differently. Users run plain `cargo build`, so a host
    // build here has to be a plain `cargo build` too or the entire
    // proc-macro graph is keyed differently from theirs, and every crate
    // deriving through it misses.
    if !target_is_host(task.target.as_str()).await? {
        args.push("--target".to_owned());
        args.push(task.target.as_str().to_owned());
    }
    Ok(args)
}

/// Build the `heel` sandbox one cargo phase runs in.
///
/// The child starts with no environment and no home directory; every path it
/// can touch is an explicit grant below, and every network connection it
/// attempts is proxied and audited into the run's `network-audit.jsonl`. The
/// grants are what stop a build script from reaching the runner's
/// credentials, the cargo registry sources, or this process's environment.
async fn phase_sandbox(
    workspace: &BuildWorkspace,
    target_dir: &Path,
    wrappers: &wrapper_shim::WrapperShimPaths,
    runtime_wrapper: &Path,
    capture_wrapper: &Path,
    capture_command: StowCaptureCommand,
    audit_log: heel::NetworkAuditLog,
) -> stow_types::error::Result<Sandbox<heel::Audited<heel::AllowAll>>> {
    let mut builder = SandboxConfigBuilder::default()
        .network(heel::Audited::new(heel::AllowAll, audit_log))
        .filesystem_strict(true)
        .working_dir(workspace.workspace_root())
        // The IPC router is what the sandboxed rustc wrapper streams capture
        // records through; the generated `heel ipc` launcher shims are inert
        // here because the wrapper links `heel::IpcClient` directly, but heel
        // still needs a binary path to bake into them — `stow-build` doubles
        // as that binary and gets the EXEC grant the capture shim needs.
        .heel_binary(capture_wrapper)
        .ipc(heel::IpcRouter::new().register(capture_command))
        // `cargo`/`rustc` resolve through the host PATH (and through it the
        // rustup proxies under CARGO_HOME/bin).
        .env_passthrough("PATH")
        // Probe-test hook: names a path a test build script tries to read.
        .env_passthrough(STOW_PROBE_FORBIDDEN_PATH_ENV);

    for (path, access, reason) in sandbox_grants(workspace, target_dir, wrappers, runtime_wrapper)?
    {
        tracing::debug!(path = %path.display(), ?access, reason, "sandbox grant");
        builder = builder.grant(path, access);
    }

    let mut sandbox = Sandbox::with_config(builder.build())
        .await
        .map_err(|error| stow_types::stow_error!("create cargo phase sandbox: {error}"))?;
    // The working dir is the mirrored workspace stow owns — heel must not
    // delete it on drop.
    sandbox.keep_working_dir();
    Ok(sandbox)
}

/// The filesystem grant set for one phase — nothing else on the host is
/// reachable. Every entry names the tool that needs it and why, because each
/// one is a hole in the boundary this task exists to close.
fn sandbox_grants(
    workspace: &BuildWorkspace,
    target_dir: &Path,
    wrappers: &wrapper_shim::WrapperShimPaths,
    runtime_wrapper: &Path,
) -> stow_types::error::Result<Vec<(PathBuf, Access, &'static str)>> {
    let cargo_home = cargo_home()?;
    let rustup_home = rustup_home()?;
    // Cargo takes a lock on this file on every invocation, `--frozen`
    // included, so it has to exist and be writable before the sandbox starts.
    create_dir_all_sync(&cargo_home)?;
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

    let tools_dir = wrappers
        .rustc_wrapper
        .parent()
        .ok_or_else(|| {
            stow_types::stow_error!(
                "wrapper shim {} has no parent directory",
                wrappers.rustc_wrapper.display()
            )
        })?
        .to_path_buf();

    let mut grants = vec![
        (
            cargo_home.join(".package-cache"),
            Access::READ | Access::WRITE,
            "cargo's package-cache lock — taken on every invocation, --frozen included",
        ),
        (
            cargo_home.join("registry"),
            Access::READ,
            "registry sources and .crate cache — read-only so a build script cannot rewrite another crate's source",
        ),
        (
            tools_dir,
            Access::READ | Access::EXEC,
            "the wrapper shim scripts cargo invokes as RUSTC_WRAPPER, plus the stow-runtime/stow-capture symlinks",
        ),
        (
            runtime_wrapper.to_path_buf(),
            Access::READ | Access::EXEC,
            "the rustc/cc shim scripts exec the runtime wrapper binary",
        ),
        (
            target_dir.to_path_buf(),
            Access::WRITE | Access::EXEC,
            "the phase's CARGO_TARGET_DIR — build scripts and proc macros are compiled here and must execute; kept outside the working dir, which never executes",
        ),
        (
            workspace.capture_dir().to_path_buf(),
            Access::WRITE,
            "output snapshots and output-identity sidecars land here; records do not",
        ),
    ];

    // Granted only when it exists: grants must resolve to a real path.
    if rustup_home.exists() {
        grants.push((
            rustup_home,
            Access::READ | Access::EXEC,
            "toolchain binaries and the Rust std library sources under the toolchain lib dir",
        ));
    }
    if cargo_home.join("bin").exists() {
        grants.push((
            cargo_home.join("bin"),
            Access::READ | Access::EXEC,
            "the rustup proxy shims `cargo`/`rustc` when PATH leads there",
        ));
    }
    for config_path in [cargo_home.join("config.toml"), cargo_home.join("config")] {
        if config_path.exists() {
            grants.push((
                config_path,
                Access::READ,
                "cargo config: registry sources and [net]/[build] settings the build honours",
            ));
        }
    }
    if cargo_home.join(".global-cache").exists() {
        grants.push((
            cargo_home.join(".global-cache"),
            Access::READ,
            "cargo's shared HTTP cache — consulted even under --frozen",
        ));
    }

    // Wherever PATH actually resolves `cargo`/`rustc` (rustup proxies, a
    // homebrew rust, a CI image toolchain), its directory needs exec+read.
    for tool in ["cargo", "rustc"] {
        if let Some(dir) = resolve_on_path(tool) {
            grants.push((
                dir,
                Access::READ | Access::EXEC,
                "the directory PATH resolves this tool from",
            ));
        }
    }

    Ok(grants)
}

fn cargo_home() -> stow_types::error::Result<PathBuf> {
    if let Some(path) = std::env::var_os("CARGO_HOME") {
        return Ok(PathBuf::from(path));
    }
    std::env::home_dir()
        .map(|home| home.join(".cargo"))
        .ok_or_else(|| stow_types::stow_error!("cannot determine the cargo home directory"))
}

fn rustup_home() -> stow_types::error::Result<PathBuf> {
    if let Some(path) = std::env::var_os("RUSTUP_HOME") {
        return Ok(PathBuf::from(path));
    }
    std::env::home_dir()
        .map(|home| home.join(".rustup"))
        .ok_or_else(|| stow_types::stow_error!("cannot determine the rustup home directory"))
}

/// The directory PATH resolves `name` from, if any.
fn resolve_on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| candidate.parent().map(Path::to_path_buf))
}

/// A sandboxed command arg is a string; a non-UTF-8 path is a hard error, not
/// a lossy conversion.
fn path_arg(path: &Path) -> stow_types::error::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| stow_types::stow_error!("path {} is not UTF-8", path.display()))
}

fn create_dir_all_sync(path: &Path) -> stow_types::error::Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|error| stow_types::stow_error!("create directory {}: {error}", path.display()))
}

fn merged_rustflags(remap_flag: &str) -> String {
    match std::env::var("RUSTFLAGS") {
        Ok(existing) if !existing.trim().is_empty() => format!("{existing} {remap_flag}"),
        _ => remap_flag.to_owned(),
    }
}

pub struct CargoFeatureArgs {
    no_default_features: bool,
    features: Vec<String>,
}

impl CargoFeatureArgs {
    pub(crate) fn from_task(task: &BuildTaskPayload) -> Self {
        // `FeaturesJson` is already validated (sorted + deduplicated + valid
        // feature names) at deserialize time, so we can read the canonical
        // list directly instead of re-parsing.
        let mut features: Vec<String> = task.features_json.features().to_vec();
        let no_default_features = !features.iter().any(|feature| feature == "default");
        features.retain(|feature| feature != "default");
        Self {
            no_default_features,
            features,
        }
    }

    pub(crate) fn args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.no_default_features {
            args.push("--no-default-features".to_owned());
        }
        if !self.features.is_empty() {
            args.push("--features".to_owned());
            args.push(self.features.join(","));
        }
        args
    }

    pub(crate) fn apply(&self, command: &mut Command) {
        command.args(self.args());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CargoSubcommand {
    Build,
    Check,
    Test,
}

const fn cargo_phases(cargo_subcommand: CargoSubcommand) -> &'static [CargoSubcommand] {
    match cargo_subcommand {
        CargoSubcommand::Build => &[CargoSubcommand::Check, CargoSubcommand::Build],
        CargoSubcommand::Check => &[CargoSubcommand::Check],
        CargoSubcommand::Test => &[CargoSubcommand::Check, CargoSubcommand::Test],
    }
}

/// Each phase's `CARGO_TARGET_DIR`, named by phase so `check` outputs can
/// never alias `build` outputs. Under the run dir, not the workspace root:
/// the sandbox working dir denies `process-exec` on every backend, so
/// anything compiled under it could never run.
fn phase_target_dir(run_dir: &Path, phase: CargoSubcommand) -> PathBuf {
    run_dir.join(format!("target-{}", phase.as_str()))
}

impl CargoSubcommand {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Check => "check",
            Self::Test => "test",
        }
    }
}

/// Whether `target` is the triple this machine natively compiles for.
///
/// Decides whether the trusted build passes `--target`, which in turn decides
/// whether cargo splits its unit graph into host and target halves.
pub async fn target_is_host(target: &str) -> stow_types::error::Result<bool> {
    let output = Command::new("rustc")
        .arg("-vV")
        .output()
        .await
        .map_err(|error| stow_types::stow_error!("run rustc -vV to detect host triple: {error}"))?;
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| stow_types::stow_error!("rustc -vV output is not UTF-8: {error}"))?;
    let host = stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .ok_or_else(|| stow_types::stow_error!("rustc -vV output has no host line"))?
        .trim();
    Ok(host == target)
}

fn cargo_subcommand() -> stow_types::error::Result<CargoSubcommand> {
    match std::env::var(STOW_BUILD_CARGO_SUBCOMMAND_ENV)
        .ok()
        .as_deref()
        .unwrap_or("build")
    {
        "build" => Ok(CargoSubcommand::Build),
        "check" => Ok(CargoSubcommand::Check),
        "test" => Ok(CargoSubcommand::Test),
        other => Err(stow_types::stow_error!(
            "{STOW_BUILD_CARGO_SUBCOMMAND_ENV} must be one of build/check/test, got {other}"
        )),
    }
}

async fn create_workspace_root() -> stow_types::error::Result<(Option<TempDir>, PathBuf)> {
    let Some(path) = std::env::var_os(STOW_BUILD_WORKSPACE_ROOT_ENV) else {
        let tempdir = TempDir::new()?;
        let workspace_root = tempdir.path().to_path_buf();
        return Ok((Some(tempdir), workspace_root));
    };

    let workspace_root = PathBuf::from(path);
    if workspace_root.exists() {
        return Err(stow_types::stow_error!(
            "{STOW_BUILD_WORKSPACE_ROOT_ENV} path already exists: {}",
            workspace_root.display()
        ));
    }
    create_dir_all(&workspace_root).await?;
    Ok((None, workspace_root))
}

async fn open_source_workspace() -> stow_types::error::Result<Option<BuildWorkspace>> {
    let Some(path) = std::env::var_os(STOW_BUILD_SOURCE_ROOT_ENV) else {
        return Ok(None);
    };

    let workspace_root = PathBuf::from(path);
    let manifest_path = workspace_root.join("Cargo.toml");
    if !manifest_path.exists() {
        return Err(stow_types::stow_error!(
            "{STOW_BUILD_SOURCE_ROOT_ENV} must point to a Cargo workspace root with Cargo.toml: {}",
            manifest_path.display()
        ));
    }

    let capture_dir = workspace_root.join(".stow-rustc-capture");
    if capture_dir.exists() {
        async_fs::remove_dir_all(&capture_dir)
            .await
            .map_err(|error| {
                stow_types::stow_error!(
                    "remove existing capture dir {}: {error}",
                    capture_dir.display()
                )
            })?;
    }
    create_dir_all(&capture_dir).await?;

    Ok(Some(BuildWorkspace {
        _tempdir: None,
        manifest_path,
        workspace_root,
        capture_dir,
    }))
}

async fn stabilize_workspace(
    workspace: BuildWorkspace,
    mirror_key: &workspace_mirror::MirrorTaskKey,
) -> stow_types::error::Result<BuildWorkspace> {
    let source_root = workspace.workspace_root().to_path_buf();
    let manifest_relative = workspace
        .manifest_path()
        .strip_prefix(workspace.workspace_root())
        .map_err(|_| {
            stow_types::stow_error!(
                "manifest path {} is outside workspace root {}",
                workspace.manifest_path().display(),
                workspace.workspace_root().display()
            )
        })?
        .to_path_buf();
    let mirror_key_owned = mirror_key.clone();
    let stable_root = smol::unblock(move || {
        workspace_mirror::materialize_workspace(&source_root, &mirror_key_owned)
    })
    .await?;
    if !mirror_key.preserve_lockfile {
        remove_bundled_lockfile(&stable_root)?;
    }
    remove_existing_phase_target_dirs(&stable_root).await?;
    let capture_dir = stable_root.join(".stow-rustc-capture");
    if capture_dir.exists() {
        async_fs::remove_dir_all(&capture_dir)
            .await
            .map_err(|error| {
                stow_types::stow_error!(
                    "remove existing capture dir {}: {error}",
                    capture_dir.display()
                )
            })?;
    }
    create_dir_all(&capture_dir).await?;

    Ok(BuildWorkspace {
        _tempdir: None,
        manifest_path: stable_root.join(manifest_relative),
        workspace_root: stable_root,
        capture_dir,
    })
}

async fn remove_existing_phase_target_dirs(workspace_root: &Path) -> stow_types::error::Result<()> {
    for dir_name in ["target", "target-check", "target-test"] {
        let target_dir = workspace_root.join(dir_name);
        if !target_dir.exists() {
            continue;
        }
        async_fs::remove_dir_all(&target_dir)
            .await
            .map_err(|error| {
                stow_types::stow_error!(
                    "remove existing target dir {}: {error}",
                    target_dir.display()
                )
            })?;
    }
    Ok(())
}

fn sibling_runtime_wrapper(capture_wrapper: &Path) -> stow_types::error::Result<PathBuf> {
    let parent = capture_wrapper.parent().ok_or_else(|| {
        stow_types::stow_error!(
            "cannot determine parent directory of capture wrapper {}",
            capture_wrapper.display()
        )
    })?;

    let candidates = ["stow", "stow-cli"]
        .map(|name| parent.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)));
    candidates
        .iter()
        .find(|candidate| candidate.exists())
        .cloned()
        .ok_or_else(|| {
            stow_types::stow_error!(
                "no runtime wrapper next to capture wrapper {}: tried {}",
                capture_wrapper.display(),
                candidates
                    .iter()
                    .map(|candidate| candidate.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}

pub async fn download_crate_manifest(
    task: &BuildTaskPayload,
    workspace_root: &Path,
) -> stow_types::error::Result<PathBuf> {
    let url = format!(
        "https://crates.io/api/v1/crates/{}/{}/download",
        task.crate_name, task.version
    );
    let mut client = zenwave::client().follow_redirect();
    let response = client
        .get(&url)
        .map_err(|error| stow_types::stow_error!("build crates.io download request: {error}"))?
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "download crate {} {}: {error}",
                task.crate_name,
                task.version
            )
        })?;
    let body = response.into_body().into_bytes().await.map_err(|error| {
        stow_types::stow_error!(
            "read crate download body {} {}: {error}",
            task.crate_name,
            task.version
        )
    })?;

    let crate_name = task.crate_name.as_str().to_owned();
    let crate_version = task.version.to_string();
    let workspace_root = workspace_root.to_path_buf();
    smol::unblock(move || unpack_crate_archive(&workspace_root, &crate_name, &crate_version, &body))
        .await
}

fn unpack_crate_archive(
    workspace_root: &Path,
    crate_name: &str,
    crate_version: &str,
    compressed: &[u8],
) -> stow_types::error::Result<PathBuf> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(compressed));
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(workspace_root).map_err(|error| {
        stow_types::stow_error!(
            "unpack crate archive {} {}: {error}",
            crate_name,
            crate_version
        )
    })?;

    let preferred_root = workspace_root.join(format!("{crate_name}-{crate_version}"));
    let source_root = if preferred_root.exists() {
        preferred_root
    } else {
        let mut top_dirs = std::fs::read_dir(workspace_root)
            .map_err(|error| {
                stow_types::stow_error!(
                    "read unpacked workspace root {}: {error}",
                    workspace_root.display()
                )
            })?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        top_dirs.sort();
        if top_dirs.len() != 1 {
            return Err(stow_types::stow_error!(
                "unexpected crate archive layout for {} {} under {}",
                crate_name,
                crate_version,
                workspace_root.display()
            ));
        }
        top_dirs.remove(0)
    };

    let manifest_path = source_root.join("Cargo.toml");
    if !manifest_path.exists() {
        return Err(stow_types::stow_error!(
            "downloaded crate source is missing Cargo.toml: {}",
            manifest_path.display()
        ));
    }
    Ok(manifest_path)
}

pub fn remove_bundled_lockfile(source_root: &Path) -> stow_types::error::Result<()> {
    let lockfile_path = source_root.join("Cargo.lock");
    if !lockfile_path.exists() {
        return Ok(());
    }
    std::fs::remove_file(&lockfile_path).map_err(|error| {
        stow_types::stow_error!(
            "remove bundled Cargo.lock {}: {error}",
            lockfile_path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;

    use flate2::Compression;
    use tempfile::TempDir;

    use super::{
        BuildWorkspace, STOW_PROBE_FORBIDDEN_PATH_ENV, remove_bundled_lockfile,
        unpack_crate_archive,
    };

    #[test]
    fn unpack_crate_archive_keeps_bundled_lockfile_for_stabilize_stage() {
        let workspace_root = TempDir::new().expect("create workspace root");
        let archive_bytes = build_archive(
            "demo-1.2.3/Cargo.toml",
            b"[package]\nname = \"demo\"\nversion = \"1.2.3\"\nedition = \"2021\"\n",
            "demo-1.2.3/Cargo.lock",
            b"# bundled lockfile",
        );

        let manifest_path =
            unpack_crate_archive(workspace_root.path(), "demo", "1.2.3", &archive_bytes)
                .expect("unpack crate archive");

        assert_eq!(
            manifest_path,
            workspace_root.path().join("demo-1.2.3/Cargo.toml")
        );
        assert!(
            workspace_root.path().join("demo-1.2.3/Cargo.lock").exists(),
            "unpack must not delete the bundled Cargo.lock; stabilize_workspace decides via preserve_lockfile"
        );
    }

    #[test]
    fn remove_bundled_lockfile_deletes_lockfile() {
        let source_root = TempDir::new().expect("create source root");
        std::fs::write(source_root.path().join("Cargo.lock"), "# stale lockfile")
            .expect("write lockfile");

        remove_bundled_lockfile(source_root.path()).expect("remove bundled lockfile");

        assert!(
            !source_root.path().join("Cargo.lock").exists(),
            "bundled Cargo.lock should be removed so CI resolves latest semver-compatible deps"
        );
    }

    fn build_archive(
        manifest_path: &str,
        manifest_bytes: &[u8],
        lockfile_path: &str,
        lockfile_bytes: &[u8],
    ) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        append_file(&mut builder, manifest_path, manifest_bytes);
        append_file(&mut builder, lockfile_path, lockfile_bytes);
        let encoder = builder.into_inner().expect("finish tar archive");
        encoder.finish().expect("finish gzip archive")
    }

    fn append_file<W: Write>(builder: &mut tar::Builder<W>, path: &str, contents: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(contents.len()).expect("contents length fits in u64"));
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, contents)
            .expect("append archive entry");
    }

    /// A process inside the phase sandbox must not be able to read the host
    /// checkout — where the runner's credentials and this source tree live —
    /// nor observe the parent process's environment (`ACTIONS_RUNTIME_TOKEN`
    /// and friends). The probe is a spawned process, which is exactly what a
    /// hostile `build.rs` or proc macro is.
    #[cfg(unix)]
    #[test]
    fn sandboxed_process_cannot_read_host_checkout_or_parent_env() {
        smol::block_on(async {
            // A sentinel only the parent environment carries: it must be
            // invisible inside the sandbox.
            const SENTINEL: &str = "STOW_SANDBOX_PROBE_SENTINEL";

            let workspace_root = TempDir::new().expect("workspace root");
            let capture_dir = workspace_root.path().join(".stow-rustc-capture");
            let target_dir = TempDir::new().expect("target dir");
            let tools_dir = TempDir::new().expect("tools dir");
            std::fs::create_dir_all(&capture_dir).expect("capture dir");

            let workspace = BuildWorkspace {
                _tempdir: None,
                manifest_path: workspace_root.path().join("Cargo.toml"),
                workspace_root: workspace_root.path().to_path_buf(),
                capture_dir,
            };
            let wrappers = stow_shim::WrapperShimPaths {
                rustc_wrapper: tools_dir.path().join("stow-rustc-wrapper"),
                cc_launcher: tools_dir.path().join("stow-cc-launcher"),
                cc_compiler: tools_dir.path().join("stow-cc"),
                cxx_compiler: tools_dir.path().join("stow-cxx"),
            };
            let wrapper = std::env::current_exe().expect("current exe");
            let (_collector, capture_command) = crate::capture::CaptureCollector::channel();
            let audit_log =
                heel::NetworkAuditLog::file(workspace_root.path().join("network-audit.jsonl"))
                    .expect("audit log");

            // The path the probe tries to read is this repository's own
            // manifest — the host checkout a build script must not reach.
            let host_checkout = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
            assert!(host_checkout.exists());
            unsafe {
                std::env::set_var(SENTINEL, "stow-probe-secret");
                std::env::set_var(STOW_PROBE_FORBIDDEN_PATH_ENV, &host_checkout);
            }

            let sandbox = super::phase_sandbox(
                &workspace,
                target_dir.path(),
                &wrappers,
                &wrapper,
                &wrapper,
                capture_command,
                audit_log,
            )
            .await
            .expect("phase sandbox");

            let forbidden = sandbox
                .command("cat")
                .arg(super::path_arg(&host_checkout).expect("utf8 path"))
                .output()
                .await
                .expect("probe output");
            assert!(
                !forbidden.status.success(),
                "sandboxed process read the host checkout: {}",
                String::from_utf8_lossy(&forbidden.stdout)
            );

            let env_output = sandbox.command("env").output().await.expect("env output");
            let env_text = String::from_utf8_lossy(&env_output.stdout);
            assert!(
                !env_text.contains("stow-probe-secret"),
                "sandboxed process saw the parent environment:\n{env_text}"
            );

            // A connection attempt — allowed or not — must land in the audit
            // log. Port 1 refuses everywhere, so this probe is offline-safe.
            let _ = sandbox
                .command("curl")
                .args(["--connect-timeout", "2", "-sS", "http://127.0.0.1:1/"])
                .output()
                .await;
            drop(sandbox);
            let audit = std::fs::read_to_string(workspace_root.path().join("network-audit.jsonl"))
                .expect("read audit log");
            assert!(
                audit.contains("127.0.0.1"),
                "audit log recorded no decision for the probe: {audit}"
            );

            unsafe {
                std::env::remove_var(SENTINEL);
                std::env::remove_var(STOW_PROBE_FORBIDDEN_PATH_ENV);
            }
        });
    }
}

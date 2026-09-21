use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_fs::create_dir_all;
use async_process::Command;
use heel::{Access, Sandbox, SandboxConfigBuilder};
use sha2::Digest as _;
use stow_types::api::{BuildTaskPayload, ProjectSource};
use stow_types::capture::CapturedRustcArtifact;
use tempfile::TempDir;
use zenwave::{Client, ResponseExt};

use crate::capture::{
    CaptureCollector, STOW_BUILD_CAPTURE_DIR_ENV, STOW_BUILD_CAPTURE_IPC_ENV,
    STOW_BUILD_CONSUMER_CRATE_NAME_ENV, STOW_BUILD_TASK_CRATE_NAME_ENV,
    STOW_BUILD_TASK_CRATE_VERSION_ENV, StowCaptureCommand,
};
use crate::dep_scan::{package_has_library_target, task_feature_set};
use crate::retry::retry_with_backoff;
use crate::workspace_mirror;
use stow_shim as wrapper_shim;

const STOW_BUILD_WORKSPACE_ROOT_ENV: &str = "STOW_BUILD_WORKSPACE_ROOT";
const STOW_BUILD_CARGO_SUBCOMMAND_ENV: &str = "STOW_BUILD_CARGO_SUBCOMMAND";
const STOW_BUILD_SOURCE_ROOT_ENV: &str = "STOW_BUILD_SOURCE_ROOT";
/// Test hook forwarded verbatim into the sandbox: a probe build script reads
/// the path it names to prove the sandbox denies it. Never set in production.
const STOW_PROBE_FORBIDDEN_PATH_ENV: &str = "STOW_PROBE_FORBIDDEN_PATH";

/// How a build workspace presents the task crate to cargo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceKind {
    /// A generated consumer package: an empty lib plus a `=<version>`
    /// dependency on the task crate, so cargo compiles it the way every
    /// real dependent does — from the registry source dir, under
    /// `--cap-lints allow`, with the dependency-side `-C metadata` a client
    /// lookup keys on.
    Consumer,
    /// The task crate's own unpacked tree as the root package — the shape
    /// `cargo install` compiles a binary crate in. The only faithful compile
    /// for a crate with no library target: as a dependency it contributes
    /// nothing and its closure never builds, while as the root package its
    /// bins and every transitive dep compile exactly the way `cargo install`
    /// does — deps out of the registry under `--cap-lints allow` with
    /// path-derived identities. The crate's own binary units are observed
    /// only, so there is no publishable artifact for them to mis-key.
    RootPackage,
    /// A real checkout supplied through `STOW_BUILD_SOURCE_ROOT`: the task
    /// crate is the workspace itself, built the way its own project builds
    /// it — the whole point of source mode.
    Source,
}

/// The package name of the generated consumer. `CARGO_PRIMARY_PACKAGE`
/// disambiguates its units from any same-named registry dependency at
/// capture time, so the name itself only needs to be legible.
const CONSUMER_PACKAGE_NAME: &str = "stow-ci-task-consumer";

/// The crates.io registry `source` lockfile entries and dependency
/// references share.
const REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

pub struct BuildWorkspace {
    _tempdir: Option<TempDir>,
    manifest_path: PathBuf,
    workspace_root: PathBuf,
    capture_dir: PathBuf,
    kind: WorkspaceKind,
    /// The task crate's bundled `Cargo.lock` verbatim, carried from the
    /// crate download to the post-`cargo fetch` fidelity check. `Some` only
    /// for a consumer workspace under `preserve_lockfile`.
    bundled_lockfile: Option<String>,
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

    pub const fn kind(&self) -> WorkspaceKind {
        self.kind
    }

    pub fn bundled_lockfile(&self) -> Option<&str> {
        self.bundled_lockfile.as_deref()
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
    let (workspace_root, manifest_path, kind, bundled_lockfile) = if let Some(source) =
        &task.project_source
    {
        // A project-source task builds the pinned checkout itself — the
        // workspace the project's own graph asks for — never a generated
        // consumer over a registry tarball.
        let manifest_path = clone_project_source(source, &workspace_root).await?;
        (workspace_root, manifest_path, WorkspaceKind::Source, None)
    } else {
        let archive = download_crate_archive(task).await?;
        let crate_name = task.crate_name.as_str().to_owned();
        let crate_version = task.version.to_string();
        let unpack_root = workspace_root.clone();
        let (task_manifest_path, crate_checksum) = smol::unblock(move || {
            unpack_crate_archive(&unpack_root, &crate_name, &crate_version, &archive)
                .map(|manifest| (manifest, hex::encode(sha2::Sha256::digest(&archive))))
        })
        .await?;
        let source_root = task_manifest_path
            .parent()
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "downloaded crate manifest {} has no parent directory",
                    task_manifest_path.display()
                )
            })?
            .to_path_buf();

        // A crate with a library target compiles as a registry dependency of a
        // generated consumer package; a binary-only crate is an invalid
        // dependency and compiles as the root package, the `cargo install`
        // shape.
        let package = task_package(&task_manifest_path, task).await?;
        if package_has_library_target(&package, &task_feature_set(task)) {
            let consumer_root = workspace_root.join("consumer");
            let (manifest_path, bundled_lockfile) =
                write_consumer_package(task, &consumer_root, &crate_checksum, &source_root).await?;
            (
                consumer_root,
                manifest_path,
                WorkspaceKind::Consumer,
                bundled_lockfile,
            )
        } else {
            (
                source_root,
                task_manifest_path,
                WorkspaceKind::RootPackage,
                None,
            )
        }
    };
    let capture_dir = workspace_root.join(".stow-rustc-capture");
    create_dir_all(&capture_dir).await?;

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        manifest_path = %manifest_path.display(),
        workspace_root = %workspace_root.display(),
        ?kind,
        "created CI build workspace"
    );

    Ok(BuildWorkspace {
        _tempdir: tempdir,
        manifest_path,
        workspace_root,
        capture_dir,
        kind,
        bundled_lockfile,
    })
}

/// The task crate's own package record, from `cargo metadata --no-deps` on
/// the unpacked manifest — the same read `dep_scan` classifies targets from,
/// used here to decide whether the crate offers a library a dependent would
/// compile.
async fn task_package(
    manifest_path: &Path,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<cargo_metadata::Package> {
    let output = Command::new("cargo")
        .arg("metadata")
        .arg("--format-version")
        .arg("1")
        .arg("--no-deps")
        .arg("--manifest-path")
        .arg(manifest_path)
        .env("RUSTUP_TOOLCHAIN", task.rustc_version.as_str())
        .output()
        .await
        .map_err(|error| stow_types::stow_error!("run cargo metadata on task crate: {error}"))?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "cargo metadata on {} {} failed: {}",
            task.crate_name,
            task.version,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let metadata: cargo_metadata::Metadata = serde_json::from_slice(&output.stdout)?;
    // `--no-deps` emits no resolve graph, so `root_package` cannot answer;
    // the task package is the one this manifest path names.
    metadata
        .packages
        .iter()
        .find(|package| package.manifest_path.as_std_path() == manifest_path)
        .cloned()
        .ok_or_else(|| {
            stow_types::stow_error!(
                "cargo metadata on {} {} reported no package for {}",
                task.crate_name,
                task.version,
                manifest_path.display()
            )
        })
}

/// Write the generated consumer package that makes the task crate a
/// registry dependency: an empty lib target plus a manifest whose only
/// dependency is `name = "=version"` carrying the task's exact feature
/// selection. Cargo then compiles the task crate out of
/// `CARGO_HOME/registry/src/…/<name>-<version>` — under `--cap-lints allow`
/// and with the dependency-side `-C metadata` a real dependent computes,
/// which is the only identity a client lookup can ever key on.
///
/// Returns the consumer manifest path and, under `preserve_lockfile`, the
/// crate's bundled `Cargo.lock` verbatim for the post-fetch fidelity check.
async fn write_consumer_package(
    task: &BuildTaskPayload,
    consumer_root: &Path,
    crate_checksum: &str,
    source_root: &Path,
) -> stow_types::error::Result<(PathBuf, Option<String>)> {
    let bundled_lockfile = if task.preserve_lockfile {
        let bundled_path = source_root.join("Cargo.lock");
        Some(
            async_fs::read_to_string(&bundled_path)
                .await
                .map_err(|error| {
                    stow_types::stow_error!(
                        "{} {} ships no Cargo.lock to preserve ({}): {error}",
                        task.crate_name,
                        task.version,
                        bundled_path.display()
                    )
                })?,
        )
    } else {
        None
    };

    let manifest_path = consumer_root.join("Cargo.toml");
    async_fs::create_dir_all(consumer_root.join("src")).await?;
    async_fs::write(&manifest_path, consumer_manifest(task)?).await?;
    async_fs::write(consumer_root.join("src/lib.rs"), "").await?;
    async_fs::write(
        consumer_root.join("Cargo.lock"),
        consumer_lockfile(task, crate_checksum, bundled_lockfile.as_deref())?,
    )
    .await?;
    Ok((manifest_path, bundled_lockfile))
}

/// `.crate` download attempts: crates.io serves through a CDN where one
/// connection can die — an unroutable IPv6 path, a reset, a 5xx from an
/// edge node — while the next attempt succeeds immediately.
const DOWNLOAD_MAX_ATTEMPTS: u32 = 5;
const DOWNLOAD_RETRY_BASE_DELAY: Duration = Duration::from_secs(1);

/// Whether a failed download attempt is transient: transport and TLS
/// failures, timeouts, mid-body stream truncation, and 5xx responses all
/// clear on a fresh connection. A 4xx is the registry's permanent answer —
/// the crate or version does not exist — and request-construction errors
/// cannot heal either.
fn is_retryable_download_error(error: &zenwave::Error) -> bool {
    error.is_network_error()
        || error.is_timeout()
        || error.is_server_error()
        || matches!(error, zenwave::Error::BodyParse(_) | zenwave::Error::Io(_))
}

/// The `.crate` tarball bytes for the task crate.
async fn download_crate_archive(task: &BuildTaskPayload) -> stow_types::error::Result<Vec<u8>> {
    let url = format!(
        "https://crates.io/api/v1/crates/{}/{}/download",
        task.crate_name, task.version
    );
    retry_with_backoff(
        "crate download",
        DOWNLOAD_MAX_ATTEMPTS,
        DOWNLOAD_RETRY_BASE_DELAY,
        || async {
            let mut client = zenwave::client().follow_redirect();
            let response = client.get(&url)?.await?.error_for_status().await?;
            let body = response.into_body().into_bytes().await?;
            Ok(body.to_vec())
        },
        is_retryable_download_error,
    )
    .await
    .map_err(|error| {
        stow_types::stow_error!(
            "download crate {} {} from {url} after {DOWNLOAD_MAX_ATTEMPTS} attempts: {error}",
            task.crate_name,
            task.version
        )
    })
}

/// `Cargo.toml` shape of the generated consumer package: a real library
/// target cargo compiles (an empty `src/lib.rs`) plus one pinned dependency.
#[derive(serde::Serialize)]
struct ConsumerManifest {
    package: ConsumerPackage,
    dependencies: BTreeMap<String, ConsumerDependency>,
}

#[derive(serde::Serialize)]
struct ConsumerPackage {
    name: &'static str,
    version: &'static str,
    edition: &'static str,
    publish: bool,
}

#[derive(serde::Serialize)]
struct ConsumerDependency {
    version: String,
    #[serde(rename = "default-features", skip_serializing_if = "Option::is_none")]
    default_features: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    features: Vec<String>,
}

/// The generated consumer's manifest. The dependency declaration carries
/// the same meaning `CargoFeatureArgs` gives the task's feature list on a
/// cargo command line: a `"default"` entry means default features on (the
/// key is omitted), anything else means `default-features = false`, and the
/// remaining names are the explicit feature list.
fn consumer_manifest(task: &BuildTaskPayload) -> stow_types::error::Result<String> {
    let CargoFeatureArgs {
        no_default_features,
        features,
    } = CargoFeatureArgs::from_task(task);
    let mut dependencies = BTreeMap::new();
    dependencies.insert(
        task.crate_name.as_str().to_owned(),
        ConsumerDependency {
            version: format!("={}", task.version),
            default_features: no_default_features.then_some(false),
            features,
        },
    );
    toml::to_string(&ConsumerManifest {
        package: ConsumerPackage {
            name: CONSUMER_PACKAGE_NAME,
            version: "0.0.0",
            edition: "2021",
            publish: false,
        },
        dependencies,
    })
    .map_err(|error| stow_types::stow_error!("serialize generated consumer manifest: {error}"))
}

/// The seeded `Cargo.lock` for the generated consumer package.
///
/// Two `[[package]]` entries are always synthesized — the consumer root,
/// naming the task crate by its qualified registry identity, and the task
/// crate itself with the `.crate` tarball checksum — so even a yanked task
/// version resolves through the lock rather than the index, exactly as a
/// real dependent's `cargo update`-generated lockfile allows.
///
/// Under `preserve_lockfile` the crate's bundled lockfile supplies every
/// other entry: the pins `cargo install --locked` would honor seed the
/// resolve verbatim (bundled dev-dependency entries survive in the file;
/// cargo prunes what the consumer graph cannot reach when it rewrites the
/// lock, and the post-fetch check below proves nothing pinned moved).
fn consumer_lockfile(
    task: &BuildTaskPayload,
    crate_checksum: &str,
    bundled_lockfile: Option<&str>,
) -> stow_types::error::Result<String> {
    let mut lock: toml::Table = match bundled_lockfile {
        Some(text) => toml::from_str(text).map_err(|error| {
            stow_types::stow_error!(
                "parse bundled Cargo.lock of {} {}: {error}",
                task.crate_name,
                task.version
            )
        })?,
        None => toml::Table::new(),
    };
    lock.entry("version".to_owned())
        .or_insert(toml::Value::Integer(4));

    let packages = lock
        .entry("package".to_owned())
        .or_insert_with(|| toml::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| {
            stow_types::stow_error!(
                "bundled Cargo.lock of {} {} has a non-array [[package]] key",
                task.crate_name,
                task.version
            )
        })?;
    // The bundled lockfile lists the task crate as the source-less root
    // package; in the consumer graph it is a registry dependency, so its
    // entry is rewritten with source and checksum below.
    packages.retain(|package| !(is_lock_package(package, task) && package.get("source").is_none()));
    packages.push(consumer_lock_entry(task));
    packages.push(task_lock_entry(task, crate_checksum));
    toml::to_string(&lock)
        .map_err(|error| stow_types::stow_error!("serialize generated Cargo.lock: {error}"))
}

/// Whether a `[[package]]` lockfile entry names the task crate.
fn is_lock_package(package: &toml::Value, task: &BuildTaskPayload) -> bool {
    package.get("name").and_then(toml::Value::as_str) == Some(task.crate_name.as_str())
        && package
            .get("version")
            .and_then(toml::Value::as_str)
            .and_then(|version| semver::Version::parse(version).ok())
            .as_ref()
            == Some(task.version.as_semver())
}

/// The consumer root's lockfile entry: name, version, and its single
/// dependency spelled `name version (source)` — the qualified form cargo
/// writes, unambiguous even when the lock holds several versions of the
/// dependency name.
fn consumer_lock_entry(task: &BuildTaskPayload) -> toml::Value {
    let mut package = toml::Table::new();
    package.insert(
        "name".to_owned(),
        toml::Value::String(CONSUMER_PACKAGE_NAME.to_owned()),
    );
    package.insert(
        "version".to_owned(),
        toml::Value::String("0.0.0".to_owned()),
    );
    package.insert(
        "dependencies".to_owned(),
        toml::Value::Array(vec![toml::Value::String(format!(
            "{} {} ({REGISTRY_SOURCE})",
            task.crate_name, task.version
        ))]),
    );
    toml::Value::Table(package)
}

/// The task crate's lockfile entry as a registry package.
fn task_lock_entry(task: &BuildTaskPayload, crate_checksum: &str) -> toml::Value {
    let mut package = toml::Table::new();
    package.insert(
        "name".to_owned(),
        toml::Value::String(task.crate_name.as_str().to_owned()),
    );
    package.insert(
        "version".to_owned(),
        toml::Value::String(task.version.to_string()),
    );
    package.insert(
        "source".to_owned(),
        toml::Value::String(REGISTRY_SOURCE.to_owned()),
    );
    package.insert(
        "checksum".to_owned(),
        toml::Value::String(crate_checksum.to_owned()),
    );
    toml::Value::Table(package)
}

/// One `[[package]]` entry of a lockfile, for the preserve-fidelity diff.
#[derive(serde::Deserialize)]
struct LockfilePackage {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

#[derive(serde::Deserialize)]
struct Lockfile {
    package: Vec<LockfilePackage>,
}

/// After `cargo fetch`, the rewritten `Cargo.lock` must prove the bundled
/// lockfile was honored exactly: every package in it other than the
/// generated consumer root must be a bundled package with identical name
/// and version, and every field the bundled entry pinned — `source`,
/// `checksum` — must still read the same. Fields the bundled entry left
/// open stay open: the task crate's own source-less root entry legitimately
/// gains its registry `source` and `checksum`. Anything beyond that — a
/// moved pin, an added package — means the bundled lockfile is inconsistent
/// with the crate's manifests, the same failure `cargo install --locked`
/// reports, and the build fails instead of silently resolving a different
/// graph.
fn verify_preserved_lockfile(
    bundled_lockfile: &str,
    resolved_lockfile: &str,
    task: &BuildTaskPayload,
) -> stow_types::error::Result<()> {
    let bundled = lockfile_packages(bundled_lockfile, task, "bundled")?;
    let resolved = lockfile_packages(resolved_lockfile, task, "resolved")?;
    let bundled_by_key = bundled
        .iter()
        .map(|package| ((package.name.as_str(), package.version.as_str()), package))
        .collect::<BTreeMap<_, _>>();
    for package in &resolved {
        if package.name == CONSUMER_PACKAGE_NAME {
            continue;
        }
        let key = (package.name.as_str(), package.version.as_str());
        let Some(bundled_package) = bundled_by_key.get(&key) else {
            return Err(stow_types::stow_error!(
                "resolved Cargo.lock contains {} {}, which the bundled lockfile of {} {} does not pin — the bundled lockfile is inconsistent with the crate's manifests",
                package.name,
                package.version,
                task.crate_name,
                task.version
            ));
        };
        for (field, bundled_value, resolved_value) in [
            ("source", &bundled_package.source, &package.source),
            ("checksum", &bundled_package.checksum, &package.checksum),
        ] {
            if bundled_value.is_some() && bundled_value != resolved_value {
                return Err(stow_types::stow_error!(
                    "resolved Cargo.lock moved {} {} {} from {:?} to {:?} — the bundled lockfile of {} {} is inconsistent with the crate's manifests",
                    package.name,
                    package.version,
                    field,
                    bundled_value,
                    resolved_value,
                    task.crate_name,
                    task.version
                ));
            }
        }
    }
    Ok(())
}

fn lockfile_packages(
    lockfile: &str,
    task: &BuildTaskPayload,
    which: &str,
) -> stow_types::error::Result<Vec<LockfilePackage>> {
    toml::from_str::<Lockfile>(lockfile)
        .map(|lockfile| lockfile.package)
        .map_err(|error| {
            stow_types::stow_error!(
                "parse {which} Cargo.lock of {} {}: {error}",
                task.crate_name,
                task.version
            )
        })
}

pub async fn build(
    task: &BuildTaskPayload,
    output_dir: &Path,
) -> stow_types::error::Result<BuiltWorkspace> {
    let mirror_key = workspace_mirror::MirrorTaskKey {
        target: task.target.as_str().to_owned(),
        rustc_version: task.rustc_version.as_str().to_owned(),
        preserve_lockfile: task.uses_source_lockfile(),
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
    // `--locked` asserts the lockfile is already complete for the manifest.
    // A source checkout's and a binary crate's bundled lockfile is; the
    // generated consumer's seeded lockfile is not — fetch must still prune
    // bundled entries the consumer graph cannot reach and fill in the dep
    // edges — so under `preserve_lockfile` the consumer's fidelity is proven
    // by the diff check below instead of by the flag.
    if task.uses_source_lockfile() && workspace.kind() != WorkspaceKind::Consumer {
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
    if let Some(bundled_lockfile) = workspace.bundled_lockfile() {
        let resolved_lockfile =
            async_fs::read_to_string(workspace.workspace_root().join("Cargo.lock"))
                .await
                .map_err(|error| {
                    stow_types::stow_error!(
                        "read resolved Cargo.lock under {}: {error}",
                        workspace.workspace_root().display()
                    )
                })?;
        verify_preserved_lockfile(bundled_lockfile, &resolved_lockfile, task)?;
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
    let wrappers = wrapper_shim::materialize_wrapper_shims(
        &wrapper_shim::tools_dir()?,
        &runtime_wrapper,
        &capture_wrapper,
    )?;

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

    let mut command = sandbox
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
        .env("CARGO_HOME", path_arg(&cargo_home()?)?)
        .env("RUSTUP_HOME", path_arg(&rustup_home()?)?)
        .current_dir(setup.workspace.workspace_root());
    match setup.workspace.kind() {
        // The consumer package is generated scaffolding: the capture
        // wrapper records its units as observed so nothing forged under its
        // name slips in, but it is never a publishable artifact.
        WorkspaceKind::Consumer => {
            command = command.env(STOW_BUILD_CONSUMER_CRATE_NAME_ENV, CONSUMER_PACKAGE_NAME);
        }
        // The task crate builds from a content-addressed mirror root, so
        // cargo hands rustc a relative `src/lib.rs` and registry-path
        // detection cannot recover its identity. The capture wrapper falls
        // back to these only for units whose `--crate-name` matches.
        WorkspaceKind::RootPackage | WorkspaceKind::Source => {
            command = command
                .env(STOW_BUILD_TASK_CRATE_NAME_ENV, task.crate_name.as_str())
                .env(STOW_BUILD_TASK_CRATE_VERSION_ENV, task.version.to_string());
        }
    }
    let status = command.status().await.map_err(|error| {
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
    if task.project_source.is_some() {
        // A project-source task compiles the checkout's whole workspace:
        // the consumer-side analysis (`stow predict` on the workspace root)
        // counts every member's direct deps, so the seed build must cover
        // the union of all members' dependency cones. Feature flags are
        // never passed — each member builds with its own manifest's default
        // feature set, exactly what the project itself compiles.
        args.push("--workspace".to_owned());
    } else if workspace.kind() != WorkspaceKind::Consumer {
        // Task feature flags apply to the task crate's own manifest; a
        // consumer workspace already encoded them in its dependency
        // declaration, and the generated package declares no features of
        // its own for them to mean.
        args.extend(CargoFeatureArgs::from_task(task).args());
    }
    // The publisher resolves the closure with `--locked` for the same
    // task, so a missing or stale bundled lockfile must fail here, in the
    // untrusted job, rather than after a successful build.
    if task.uses_source_lockfile() {
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
        .env_passthrough(STOW_PROBE_FORBIDDEN_PATH_ENV)
        // Toolchain configuration for cross builds: `CARGO_TARGET_*_LINKER`
        // points cargo at the NDK/GNU cross linker, the `cc`-crate `CC_*`/
        // `AR_*`/`CFLAGS_*` forms pick its compiler, and the SDK/NDK root
        // variables let tools locate their own install trees. These carry
        // paths and flags only — the filesystem grants below still decide
        // what a build script can actually read or exec.
        .env_passthroughs(toolchain_env_names());

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
    ensure_package_cache_lock(&cargo_home)?;

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
            "the wrapper shims cargo invokes as RUSTC_WRAPPER, plus the stow-runtime/stow-capture symlinks",
        ),
        (
            runtime_wrapper.to_path_buf(),
            Access::READ | Access::EXEC,
            "the rustc/cc shims resolve to the runtime wrapper binary",
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
    if cargo_home.join("git").exists() {
        grants.push((
            cargo_home.join("git"),
            Access::READ,
            "git dependency database and checkouts fetched on the host in phase 0; read-only like the registry",
        ));
    }
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

    // Cross toolchain install trees named by the toolchain env vars —
    // an NDK under `~/Library/Android` or `/opt`, a sysroot a `SDKROOT`
    // points at. Where the runner image puts them under `/usr` these
    // duplicate heel's system grants and cost nothing.
    for dir in toolchain_grant_dirs() {
        grants.push((
            dir,
            Access::READ | Access::EXEC,
            "cross toolchain install tree named by a toolchain env var",
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

/// Create cargo's package-cache lock file before the sandbox starts.
///
/// Cargo takes a lock on this file on every invocation, `--frozen`
/// included, so it has to exist and be writable inside the sandbox.
fn ensure_package_cache_lock(cargo_home: &Path) -> stow_types::error::Result<()> {
    create_dir_all_sync(cargo_home)?;
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

/// Environment variable names that configure the cross toolchain, gathered
/// from the parent environment at sandbox-build time.
///
/// Exact names cover the compiler drivers the `cc` crate and rustc invoke,
/// the SDK roots those tools locate their install trees through, and
/// pkg-config's sysroot wiring. The prefixed forms are the `cc` crate's
/// per-target overrides (`CC_<target>`, `AR_<target>`, `CFLAGS_<target>`)
/// plus cargo's per-target configuration (`CARGO_TARGET_<TRIPLE>_LINKER`,
/// `_AR`, `_RUNNER`, `_RUSTFLAGS`). `CARGO_TARGET_DIR` is deliberately not a
/// prefix match here — `CARGO_TARGET_DIR` is set explicitly per phase.
fn toolchain_env_names() -> Vec<String> {
    const EXACT: &[&str] = &[
        "CC",
        "CXX",
        "AR",
        "RANLIB",
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "SDKROOT",
        "DEVELOPER_DIR",
        "ANDROID_HOME",
        "ANDROID_SDK_ROOT",
        "ANDROID_NDK",
        "ANDROID_NDK_HOME",
        "ANDROID_NDK_ROOT",
        "ANDROID_NDK_LATEST_HOME",
        "PKG_CONFIG_PATH",
        "PKG_CONFIG_LIBDIR",
        "PKG_CONFIG_SYSROOT_DIR",
        "PKG_CONFIG_ALLOW_CROSS",
    ];
    const PREFIXES: &[&str] = &[
        "CARGO_TARGET_",
        "CC_",
        "CXX_",
        "AR_",
        "RANLIB_",
        "CFLAGS_",
        "CXXFLAGS_",
        "CPPFLAGS_",
        "LDFLAGS_",
    ];
    std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .filter(|name| {
            name != "CARGO_TARGET_DIR"
                && (EXACT.contains(&name.as_str())
                    || PREFIXES.iter().any(|prefix| name.starts_with(prefix)))
        })
        .collect()
}

/// Directories a cross toolchain lives under, gathered from the same
/// environment. The SDK/NDK roots name whole install trees; linker and
/// compiler variables name executables, whose parent directory is granted
/// the way `resolve_on_path` grants the `cargo`/`rustc` directory. On Linux
/// runners these resolve under `/usr` — already covered by heel's system
/// rules — so the grants matter where the toolchain lives in a user-owned
/// location, like the macOS `~/Library/Android` SDK.
fn toolchain_grant_dirs() -> Vec<PathBuf> {
    const TOOLCHAIN_ROOT_VARS: &[&str] = &[
        "SDKROOT",
        "DEVELOPER_DIR",
        "ANDROID_HOME",
        "ANDROID_SDK_ROOT",
        "ANDROID_NDK",
        "ANDROID_NDK_HOME",
        "ANDROID_NDK_ROOT",
        "ANDROID_NDK_LATEST_HOME",
    ];
    const TOOLCHAIN_EXE_PREFIXES: &[&str] = &["CARGO_TARGET_", "CC_", "CXX_", "AR_", "RANLIB_"];
    let mut dirs: Vec<PathBuf> = std::env::vars_os()
        .filter_map(|(name, value)| {
            let name = name.to_str()?;
            if TOOLCHAIN_ROOT_VARS.contains(&name) {
                return Some(PathBuf::from(value));
            }
            if TOOLCHAIN_EXE_PREFIXES
                .iter()
                .any(|prefix| name.starts_with(prefix))
            {
                return PathBuf::from(value).parent().map(Path::to_path_buf);
            }
            None
        })
        .filter(|dir| dir.is_absolute() && dir.is_dir())
        .collect();
    dirs.sort();
    dirs.dedup();
    dirs
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
    pub(crate) no_default_features: bool,
    pub(crate) features: Vec<String>,
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
        kind: WorkspaceKind::Source,
        bundled_lockfile: None,
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
    // A source checkout's or binary crate's bundled Cargo.lock goes when the
    // task does not preserve it; the generated consumer's Cargo.lock is
    // seeded on purpose and stays either way.
    if !mirror_key.preserve_lockfile && workspace.kind() != WorkspaceKind::Consumer {
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
        kind: workspace.kind(),
        bundled_lockfile: workspace.bundled_lockfile,
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

/// Clone the task's project source into `workspace_root` and return the
/// manifest the build phases run against.
///
/// The checkout is pinned to `source.commit`: `git checkout` on a full sha
/// cannot ride a moving branch, so the tree the untrusted build compiles is
/// the tree the submitter measured. Submodules are materialized because
/// workspace members may path-depend on them — a missing one turns into a
/// manifest parse error minutes into the build rather than here.
pub async fn clone_project_source(
    source: &ProjectSource,
    workspace_root: &Path,
) -> stow_types::error::Result<PathBuf> {
    // A blobless clone transfers history without file contents; checkout
    // then fetches exactly the blobs the pinned commit needs. Remotes that
    // do not understand the filter (a plain local path) ignore it and still
    // clone, so the one command covers both.
    run_git(
        workspace_root,
        &["clone", "--filter=blob:none", &source.url, "."],
    )
    .await?;
    run_git(
        workspace_root,
        &[
            "-c",
            "advice.detachedHead=false",
            "checkout",
            &source.commit,
        ],
    )
    .await?;
    run_git(
        workspace_root,
        &["submodule", "update", "--init", "--recursive"],
    )
    .await?;

    let manifest_path = workspace_root.join(&source.manifest_path);
    if !manifest_path.exists() {
        return Err(stow_types::stow_error!(
            "project source {} @ {} has no manifest at {}: {}",
            source.url,
            source.commit,
            source.manifest_path,
            manifest_path.display()
        ));
    }
    Ok(manifest_path)
}

async fn run_git(dir: &Path, args: &[&str]) -> stow_types::error::Result<()> {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .status()
        .await
        .map_err(|error| stow_types::stow_error!("run git {}: {error}", args.join(" ")))?;
    if !status.success() {
        return Err(stow_types::stow_error!(
            "git {} in {} failed with status {}",
            args.join(" "),
            dir.display(),
            status
        ));
    }
    Ok(())
}

pub async fn download_crate_manifest(
    task: &BuildTaskPayload,
    workspace_root: &Path,
) -> stow_types::error::Result<PathBuf> {
    let body = download_crate_archive(task).await?;

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

    use stow_types::api::BuildTaskPayload;
    use stow_types::identity::{
        CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
    };

    use super::{
        BuildWorkspace, STOW_PROBE_FORBIDDEN_PATH_ENV, WorkspaceKind, cargo_home,
        consumer_lockfile, consumer_manifest, remove_bundled_lockfile, sandbox_grants,
        unpack_crate_archive, verify_preserved_lockfile,
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

    fn task_with_features(features: &[&str]) -> BuildTaskPayload {
        BuildTaskPayload {
            task_id: "itoa-task".to_owned(),
            attempt: 1,
            crate_name: CrateName::parse("itoa").expect("crate name"),
            version: CrateVersion::new(semver::Version::parse("1.0.15").expect("version")),
            features_json: FeaturesJson::canonicalize(
                features
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
            )
            .expect("features"),
            target: TargetTriple::parse("aarch64-apple-darwin").expect("target"),
            rustc_version: WireRustcVersion::parse("1.91.1").expect("rustc version"),
            preserve_lockfile: false,
            project_source: None,
        }
    }

    fn dependency<'a>(manifest: &'a toml::Table, name: &str) -> &'a toml::Table {
        manifest["dependencies"][name]
            .as_table()
            .expect("dependency entry is a table")
    }

    #[test]
    fn consumer_manifest_keeps_default_features_when_task_lists_default() {
        let task = task_with_features(&["default", "std"]);
        let manifest: toml::Table =
            toml::from_str(&consumer_manifest(&task).expect("consumer manifest"))
                .expect("generated manifest parses");

        let dependency = dependency(&manifest, "itoa");
        assert_eq!(
            dependency["version"].as_str(),
            Some("=1.0.15"),
            "the task crate is pinned to the exact task version"
        );
        assert_eq!(
            dependency["features"].as_array().map(Vec::as_slice),
            Some([toml::Value::String("std".to_owned())].as_slice()),
            "non-default task features become the dependency's feature list"
        );
        assert!(
            dependency.get("default-features").is_none(),
            "a task listing \"default\" must not disable default features: {dependency:?}"
        );
    }

    #[test]
    fn consumer_manifest_disables_default_features_when_task_omits_default() {
        let task = task_with_features(&["std"]);
        let manifest: toml::Table =
            toml::from_str(&consumer_manifest(&task).expect("consumer manifest"))
                .expect("generated manifest parses");

        let dependency = dependency(&manifest, "itoa");
        assert_eq!(dependency["version"].as_str(), Some("=1.0.15"));
        assert_eq!(
            dependency["features"].as_array().map(Vec::as_slice),
            Some([toml::Value::String("std".to_owned())].as_slice())
        );
        assert_eq!(
            dependency["default-features"].as_bool(),
            Some(false),
            "a task without \"default\" means --no-default-features"
        );
    }

    fn lockfile_package<'a>(lockfile: &'a toml::Table, name: &str) -> Option<&'a toml::Table> {
        lockfile["package"].as_array()?.iter().find_map(|package| {
            let package = package.as_table()?;
            (package["name"].as_str() == Some(name)).then_some(package)
        })
    }

    #[test]
    fn consumer_lockfile_pins_task_crate_as_a_registry_package() {
        let task = task_with_features(&["default"]);
        let lockfile: toml::Table =
            toml::from_str(&consumer_lockfile(&task, &"ab".repeat(32), None).expect("seed lock"))
                .expect("seed lockfile parses");

        let task_entry = lockfile_package(&lockfile, "itoa").expect("task crate entry");
        assert_eq!(task_entry["version"].as_str(), Some("1.0.15"));
        assert_eq!(
            task_entry["source"].as_str(),
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            "the task crate must resolve out of the registry source dir, not a workspace path"
        );
        assert_eq!(
            task_entry["checksum"].as_str(),
            Some("ab".repeat(32).as_str()),
            "the tarball checksum pins even a yanked task version through the lock"
        );

        let consumer =
            lockfile_package(&lockfile, "stow-ci-task-consumer").expect("consumer root entry");
        assert_eq!(
            consumer["dependencies"].as_array().map(Vec::as_slice),
            Some(
                [toml::Value::String(
                    "itoa 1.0.15 (registry+https://github.com/rust-lang/crates.io-index)"
                        .to_owned(),
                )]
                .as_slice()
            ),
            "the consumer root names the task crate by its qualified registry identity"
        );
    }

    #[test]
    fn consumer_lockfile_merges_the_bundled_lockfile() {
        let task = task_with_features(&["default"]);
        let bundled = r#"
version = 4

[[package]]
name = "itoa"
version = "1.0.15"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "11"

[[package]]
name = "dev-dep"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "22"
"#;
        let lockfile: toml::Table = toml::from_str(
            &consumer_lockfile(&task, &"ab".repeat(32), Some(bundled)).expect("seed"),
        )
        .expect("merged seed parses");

        // The bundled source-less root entry for the task crate is rewritten
        // as the registry package it becomes in the consumer graph.
        let task_entry = lockfile_package(&lockfile, "itoa").expect("task entry");
        assert_eq!(
            task_entry["source"].as_str(),
            Some("registry+https://github.com/rust-lang/crates.io-index")
        );
        assert_eq!(
            task_entry["checksum"].as_str(),
            Some("ab".repeat(32).as_str())
        );
        // Every other bundled pin seeds the resolve verbatim — dev-deps
        // included; cargo prunes what the consumer graph cannot reach.
        assert_eq!(
            lockfile_package(&lockfile, "serde").expect("serde")["checksum"].as_str(),
            Some("11")
        );
        assert_eq!(
            lockfile_package(&lockfile, "dev-dep").expect("dev-dep")["checksum"].as_str(),
            Some("22")
        );
        assert!(lockfile_package(&lockfile, "stow-ci-task-consumer").is_some());
    }

    #[test]
    fn verify_preserved_lockfile_accepts_a_pruned_consumer_resolution() {
        let task = task_with_features(&["default"]);
        let bundled = r#"
version = 4

[[package]]
name = "itoa"
version = "1.0.15"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "11"

[[package]]
name = "dev-dep"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "22"
"#;
        // What `cargo fetch` legitimately rewrites: the unreachable
        // dev-dependency is pruned, the task crate's source-less root entry
        // gains its registry source+checksum, and the consumer root lands.
        let resolved = r#"
version = 4

[[package]]
name = "itoa"
version = "1.0.15"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ab"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "11"

[[package]]
name = "stow-ci-task-consumer"
version = "0.0.0"
dependencies = ["itoa"]
"#;
        verify_preserved_lockfile(bundled, resolved, &task)
            .expect("a pruned consumer resolution preserves every bundled pin");
    }

    #[test]
    fn verify_preserved_lockfile_rejects_a_moved_or_added_pin() {
        let task = task_with_features(&["default"]);
        let bundled = r#"
version = 4

[[package]]
name = "itoa"
version = "1.0.15"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "11"
"#;
        // A package the bundled lockfile never pinned — the bundled lock is
        // inconsistent with the manifests, the failure `cargo install
        // --locked` would report.
        let added = r#"
version = 4

[[package]]
name = "itoa"
version = "1.0.15"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ab"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "11"

[[package]]
name = "quote"
version = "1.0.47"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "33"
"#;
        let error = verify_preserved_lockfile(bundled, added, &task)
            .expect_err("an added package means the bundled lockfile was inconsistent");
        assert!(
            error.to_string().contains("quote 1.0.47"),
            "error names the package the bundled lockfile did not pin: {error}"
        );

        // A moved pin: same name+version, different checksum.
        let moved = added.replacen("checksum = \"11\"", "checksum = \"99\"", 1);
        let error = verify_preserved_lockfile(bundled, &moved, &task)
            .expect_err("a moved checksum must fail");
        assert!(
            error.to_string().contains("serde 1.0.228"),
            "error names the package whose pin moved: {error}"
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
                kind: WorkspaceKind::Source,
                bundled_lockfile: None,
            };
            let wrappers = stow_shim::WrapperShimPaths {
                rustc_wrapper: tools_dir.path().join("stow-rustc-wrapper"),
                cc_launcher: tools_dir.path().join("stow-cc-launcher"),
                cc_compiler: tools_dir.path().join("stow-cc"),
                cxx_compiler: tools_dir.path().join("stow-cxx"),
            };
            let wrapper = std::env::current_exe().expect("current exe");

            // The cargo caches the host-side phase 0 `cargo fetch` populates
            // — the registry, and the git dependency database and checkouts —
            // must reach the sandboxed phases, read-only so a build script
            // cannot rewrite another crate's source.
            let cargo_home = cargo_home().expect("cargo home");
            let grants = sandbox_grants(&workspace, target_dir.path(), &wrappers, &wrapper)
                .expect("sandbox grants");
            for dir in ["registry", "git"] {
                let grant = grants
                    .iter()
                    .find(|(path, _, _)| *path == cargo_home.join(dir));
                assert_eq!(
                    grant.map(|(_, access, _)| *access),
                    Some(heel::Access::READ),
                    "$CARGO_HOME/{dir} must be a read-only sandbox grant"
                );
            }

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

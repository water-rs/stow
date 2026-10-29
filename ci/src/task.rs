use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_fs::create_dir_all;
use async_process::Command;
use heel::{Access, Sandbox, SandboxConfigBuilder};
use sha2::Digest as _;
use stow_types::api::BuildTaskPayload;
use stow_types::capture::CapturedRustcArtifact;
use stow_types::env_name;
use tempfile::TempDir;
use zenwave::{Client, ResponseExt};

use crate::capture::{
    CaptureCollector, STOW_BUILD_CAPTURE_DIR_ENV, STOW_BUILD_CAPTURE_IPC_ENV,
    STOW_BUILD_CONSUME_STORE_ENV, STOW_BUILD_TARGET_DIR_REMAP_ENV,
    STOW_BUILD_WRAPPER_CRATE_NAME_ENV, StowCaptureCommand,
};
use crate::consume;
use crate::dep_scan;
use crate::workspace_mirror;
use stow_oci::retry::retry_with_backoff;
use stow_shim as wrapper_shim;

const STOW_BUILD_WORKSPACE_ROOT_ENV: &str = "STOW_BUILD_WORKSPACE_ROOT";
const STOW_BUILD_CARGO_SUBCOMMAND_ENV: &str = "STOW_BUILD_CARGO_SUBCOMMAND";
/// Test hook forwarded verbatim into the sandbox: a probe build script reads
/// the path it names to prove the sandbox denies it. Never set in production.
const STOW_PROBE_FORBIDDEN_PATH_ENV: &str = "STOW_PROBE_FORBIDDEN_PATH";

/// The package name of the generated wrapper. `CARGO_PRIMARY_PACKAGE`
/// disambiguates its units from any same-named registry dependency at
/// capture time, so the name itself only needs to be legible.
pub const WRAPPER_PACKAGE_NAME: &str = "stow-ci-wrapper";

/// The virtual root every phase's `CARGO_TARGET_DIR` remaps to — one value
/// shared by the rustflags string and the wrapper env so the two can never
/// drift.
const TARGET_DIR_VIRTUAL_ROOT: &str = "stow-ci://target";

/// The crates.io registry `source` lockfile entries and dependency
/// references share.
const REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

pub struct BuildWorkspace {
    _tempdir: Option<TempDir>,
    manifest_path: PathBuf,
    workspace_root: PathBuf,
    capture_dir: PathBuf,
    /// The task crate's bundled `Cargo.lock` verbatim, carried from the
    /// crate download to the post-`cargo fetch` fidelity check. `Some` only
    /// under `preserve_lockfile`.
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

    pub fn bundled_lockfile(&self) -> Option<&str> {
        self.bundled_lockfile.as_deref()
    }
}

/// A workspace whose cargo phases have run inside the sandbox.
///
/// Owns the run directory holding each phase's `CARGO_TARGET_DIR` — kept
/// outside the workspace root because the sandbox working dir denies
/// execution on every backend — plus the capture records the host collected
/// over IPC and the phase×invocation unit graphs the phases compiled.
/// The scan reads both: a capture's `target_dir` names the phase and
/// invocation it ran under, and that graph's units carry the resolved
/// feature set the published row is labelled with (stow#611).
pub struct BuiltWorkspace {
    workspace: BuildWorkspace,
    run_dir: TempDir,
    captures: Vec<CapturedRustcArtifact>,
    unit_graphs: Vec<PhaseUnitGraph>,
}

impl BuiltWorkspace {
    pub const fn workspace(&self) -> &BuildWorkspace {
        &self.workspace
    }

    pub fn captures(&self) -> &[CapturedRustcArtifact] {
        &self.captures
    }

    /// The directory every phase's `CARGO_TARGET_DIR` sits under —
    /// [`PhaseUnitGraph::target_dir`] derives the per-phase dirs from it.
    pub fn run_dir(&self) -> &Path {
        self.run_dir.path()
    }

    /// The unit graph of every phase×invocation the build ran.
    pub fn unit_graphs(&self) -> &[PhaseUnitGraph] {
        &self.unit_graphs
    }
}

pub async fn create_workspace(
    task: &BuildTaskPayload,
) -> stow_types::error::Result<BuildWorkspace> {
    let (tempdir, workspace_root) = create_workspace_root().await?;
    let (workspace_root, manifest_path, bundled_lockfile) = {
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

        // Every task crate compiles as a registry dependency of the
        // generated wrapper package. A binary-only crate is an invalid
        // dependency that cargo ignores outright, so the task crate never
        // compiles and the publish stage's closure resolution fails the
        // task instead of publishing nothing.
        let wrapper_root = workspace_root.join("wrapper");
        let (manifest_path, bundled_lockfile) =
            write_wrapper_package(task, &wrapper_root, &crate_checksum, &source_root).await?;
        (wrapper_root, manifest_path, bundled_lockfile)
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
        "created CI build workspace"
    );

    Ok(BuildWorkspace {
        _tempdir: tempdir,
        manifest_path,
        workspace_root,
        capture_dir,
        bundled_lockfile,
    })
}

/// A `BuildWorkspace` view of a directory the caller already owns —
/// the publisher's pristine resolution workspace (stow#588). Its
/// manifest is `create_resolution_workspace`'s return, its workspace
/// root the manifest's parent, and it has no capture dir or bundled
/// lockfile to check.
pub const fn resolution_build_workspace(
    manifest_path: PathBuf,
    workspace_root: PathBuf,
) -> BuildWorkspace {
    BuildWorkspace {
        _tempdir: None,
        manifest_path,
        workspace_root,
        capture_dir: PathBuf::new(),
        bundled_lockfile: None,
    }
}

impl BuildWorkspace {
    /// Set the capture directory — sandboxed-phase tests build the
    /// resolution workspace then run a phase, which needs a real one
    /// (the sandbox grants `capture_dir` and rejects an empty path).
    #[cfg(test)]
    pub fn with_capture_dir(mut self, capture_dir: PathBuf) -> Self {
        self.capture_dir = capture_dir;
        self
    }
}

/// Write the generated wrapper package that makes the task crate a
/// registry dependency: an empty lib target plus a manifest whose only
/// dependency is `name = "=version"` carrying the task's exact feature
/// selection. Cargo then compiles the task crate out of
/// `CARGO_HOME/registry/src/…/<name>-<version>` — under `--cap-lints allow`
/// and with the dependency-side `-C metadata` a real dependent computes,
/// which is the only identity a client lookup can ever key on.
///
/// Returns the wrapper manifest path and, under `preserve_lockfile`, the
/// crate's bundled `Cargo.lock` verbatim for the post-fetch fidelity check.
pub async fn write_wrapper_package(
    task: &BuildTaskPayload,
    wrapper_root: &Path,
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

    let manifest_path = wrapper_root.join("Cargo.toml");
    async_fs::create_dir_all(wrapper_root.join("src")).await?;
    async_fs::write(&manifest_path, wrapper_manifest(task)?).await?;
    async_fs::write(wrapper_root.join("src/lib.rs"), "").await?;
    if task.host_side {
        // Cargo only compiles `[build-dependencies]` when the package
        // has a build script to compile them for, so a host-side
        // wrapper needs one for the task crate's unit to exist.
        async_fs::write(wrapper_root.join("build.rs"), "fn main() {}\n").await?;
    }
    async_fs::write(
        wrapper_root.join("Cargo.lock"),
        wrapper_lockfile(task, crate_checksum, bundled_lockfile.as_deref())?,
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

/// The sparse index's `dl` root (`index.crates.io/config.json`): the CDN
/// cargo itself downloads from. The API's `/download` redirect lands on
/// the same file but is rate-limited per IP under the crawler policy.
const CRATE_DOWNLOAD_BASE: &str = "https://static.crates.io/crates";

/// The `.crate` tarball bytes for the task crate.
async fn download_crate_archive(task: &BuildTaskPayload) -> stow_types::error::Result<Vec<u8>> {
    let name = &task.crate_name;
    let version = &task.version;
    let url = format!("{CRATE_DOWNLOAD_BASE}/{name}/{name}-{version}.crate");
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

/// `Cargo.toml` shape of the generated wrapper package: a real library
/// target cargo compiles (an empty `src/lib.rs`) plus one pinned
/// dependency. A host-side task declares it as a build-dependency
/// instead — the way a consumer's build reaches the crate as a
/// proc-macro or build-script dep — so cargo compiles it as a host
/// unit under the build-override profile, the shape host lookups key
/// on.
#[derive(serde::Serialize)]
struct WrapperManifest {
    package: Package,
    dependencies: BTreeMap<String, Dependency>,
    #[serde(
        rename = "build-dependencies",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    build_dependencies: BTreeMap<String, Dependency>,
}

#[derive(serde::Serialize)]
struct Package {
    name: &'static str,
    version: &'static str,
    edition: &'static str,
    publish: bool,
}

#[derive(serde::Serialize)]
struct Dependency {
    version: String,
    /// The real package name when the table key is an alias: dep pins key
    /// on `<name>-v<version>` so two versions of one crate survive in one
    /// section.
    #[serde(skip_serializing_if = "Option::is_none")]
    package: Option<String>,
    #[serde(rename = "default-features", skip_serializing_if = "Option::is_none")]
    default_features: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    features: Vec<String>,
}

/// The generated wrapper's manifest. The dependency declaration carries
/// the same meaning the task's feature flags would on a cargo command
/// line: a `"default"` entry means default features on (the key is
/// omitted), anything else means `default-features = false`, and the
/// remaining names are the explicit feature list.
fn wrapper_manifest(task: &BuildTaskPayload) -> stow_types::error::Result<String> {
    let TaskFeatureSelection {
        no_default_features,
        features,
    } = TaskFeatureSelection::from_task(task);
    let dependency = Dependency {
        version: format!("={}", task.version),
        package: None,
        default_features: no_default_features.then_some(false),
        features,
    };
    let (mut dependencies, mut build_dependencies) = if task.host_side {
        // The build-dependency declaration is what makes cargo compile
        // the crate as a host unit: the same unit kind a consumer's
        // build computes for a proc-macro's deps, at the same `-C
        // metadata` — so the build produces the artifacts consumers
        // look up (stow#349).
        let mut build_dependencies = BTreeMap::new();
        build_dependencies.insert(task.crate_name.as_str().to_owned(), dependency);
        (BTreeMap::new(), build_dependencies)
    } else {
        let mut dependencies = BTreeMap::new();
        dependencies.insert(task.crate_name.as_str().to_owned(), dependency);
        (dependencies, BTreeMap::new())
    };
    // Every node of the dispatched dependency subgraph becomes an exact
    // pin on the wrapper: `=<version>` with the node's published feature
    // set, in the section matching the side its consumers compile it on
    // (stow#588). The whole transitive closure has to be pinned, not
    // just the task's direct deps: cargo's unification can only widen a
    // declared set, so an unpinned grandchild another consumer widened
    // resolves narrower here and the dep task's key no longer matches
    // the published context. Without the pins the wrapper's own
    // resolution can land on a narrower feature set than the dep task
    // published — cargo compiles the dep under a key nobody published
    // and dep_scan fails the build (stow#431).
    //
    // The table key cannot be the crate name: a closure that carries two
    // semver-incompatible versions of one crate (`syn` 1 and 2 is common)
    // — or a node that shares the task crate's name at another version —
    // would keep only the last insert. Each pin keys on a unique
    // `<name>-v<version>` alias and names the package in `package`. Two
    // pins of one crate+version cannot share a section: the subgraph
    // comes from a single resolve, whose units key per
    // (package, version, features) per side and platform — an alias
    // collision inside a section is a real error, not an ambiguity to
    // disambiguate.
    //
    // The one exception is a pin of the task's own package: cargo
    // requires every declaration from one package to one dependency
    // package to use the same name across all dependency kinds
    // (`Resolve::extern_crate_name_and_dep_name`), so it keys on the
    // task entry's own name. Only an outcome-3 host task's self-twin
    // edge (stow#723) puts its own package in its subgraph — on the
    // other side, in the other section; the same side would collide
    // with the task entry below and fail.
    for node in &task.dependency_subgraph.nodes {
        let selection = TaskFeatureSelection::from_features_json(&node.features_json);
        let pinned = Dependency {
            version: format!("={}", node.version),
            package: Some(node.crate_name.as_str().to_owned()),
            default_features: selection.no_default_features.then_some(false),
            features: selection.features,
        };
        let section = if node.host_side {
            &mut build_dependencies
        } else {
            &mut dependencies
        };
        let alias = if node.crate_name == task.crate_name && node.version == task.version {
            task.crate_name.as_str().to_owned()
        } else {
            pin_alias(node.crate_name.as_str(), &node.version.to_string())
        };
        if section.insert(alias.clone(), pinned).is_some() {
            return Err(stow_types::stow_error!(
                "dep pin alias {alias} collides with an earlier entry in the wrapper manifest"
            ));
        }
    }
    toml::to_string(&WrapperManifest {
        package: Package {
            name: WRAPPER_PACKAGE_NAME,
            version: "0.0.0",
            edition: "2021",
            publish: false,
        },
        dependencies,
        build_dependencies,
    })
    .map_err(|error| stow_types::stow_error!("serialize generated wrapper manifest: {error}"))
}

/// The wrapper manifest's table key for a pin of `crate_name` at
/// `version`: `<name>-v<version>`, spelled in the characters cargo
/// accepts in a dependency name. A semver version holds letters, digits
/// and `-`, which pass through, plus `.` between identifiers and one `+`
/// before build metadata (`toml_datetime 1.1.2+spec-1.1.0`), which do
/// not. `.` becomes `_` and `+` becomes `__`: no identifier is empty, so
/// a doubled underscore can only be the `+`, and two versions of one
/// crate never share an alias.
fn pin_alias(crate_name: &str, version: &str) -> String {
    format!(
        "{crate_name}-v{}",
        version.replace('+', "__").replace('.', "_")
    )
}

/// The seeded `Cargo.lock` for the generated wrapper package.
///
/// Two `[[package]]` entries are always synthesized — the wrapper root,
/// naming the task crate by its qualified registry identity, and the task
/// crate itself with the `.crate` tarball checksum — so even a yanked task
/// version resolves through the lock rather than the index, exactly as a
/// real dependent's `cargo update`-generated lockfile allows.
///
/// Under `preserve_lockfile` the crate's bundled lockfile supplies every
/// other entry: the pins `cargo install --locked` would honor seed the
/// resolve verbatim (bundled dev-dependency entries survive in the file;
/// cargo prunes what the wrapper graph cannot reach when it rewrites the
/// lock, and the post-fetch check below proves nothing pinned moved).
fn wrapper_lockfile(
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
    // package; in the wrapper graph it is a registry dependency, so its
    // entry is rewritten with source and checksum below.
    packages.retain(|package| !(is_lock_package(package, task) && package.get("source").is_none()));
    packages.push(wrapper_lock_entry(task));
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

/// The wrapper root's lockfile entry: name, version, and its single
/// dependency spelled `name version (source)` — the qualified form cargo
/// writes, unambiguous even when the lock holds several versions of the
/// dependency name.
fn wrapper_lock_entry(task: &BuildTaskPayload) -> toml::Value {
    let mut package = toml::Table::new();
    package.insert(
        "name".to_owned(),
        toml::Value::String(WRAPPER_PACKAGE_NAME.to_owned()),
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
/// generated wrapper root must be a bundled package with identical name
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
        if package.name == WRAPPER_PACKAGE_NAME {
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

/// The consumption prefetch (stow#299): pull the signed index slices and
/// stage the verified bundles this task's dependency closure could be
/// served, so each sandboxed rustc unit compiles only what the cache
/// cannot vouch for. A bundle that never arrived is skipped and its unit
/// compiles. The store stays out of `output_dir`: that directory is the
/// publish job's hand-off, and staged bundles are not its contents.
///
/// Returns the store `TempDir` — the lifetime owner the caller must hold
/// for the build — plus the staged store path, or `(None, None)` when
/// nothing verified or the task has no dependency to consume.
///
/// A task with dependencies was dispatched because every one of them is
/// published, so a slice, config or registry failure here is not a cold
/// cache. Building on would compile the whole dependency closure and fail
/// much later on the foreign-unit check, far from the cause (stow#817);
/// the build fails with the failure instead. A bundle the signed index
/// vouches for that does not verify fails it too: it says the published
/// artifact and the signature over it disagree, on the machine whose
/// output every user installs.
async fn stage_consumption_store(
    task: &BuildTaskPayload,
    unit_graphs: &[PhaseUnitGraph],
) -> stow_types::error::Result<(Option<TempDir>, Option<PathBuf>)> {
    if task.dependency_subgraph.nodes.is_empty() {
        return Ok((None, None));
    }
    let store_dir = TempDir::new()?;
    let packages = consumption_packages(task, unit_graphs);
    let consumption = consume::prefetch(task, packages, store_dir.path())
        .await
        .map_err(|error| error.wrap_err("stage cache consumption"))?;
    Ok(if consumption.artifacts > 0 {
        (Some(store_dir), Some(consumption.store_dir))
    } else {
        (None, None)
    })
}

/// One cargo `--unit-graph` answer for one phase×invocation spelling,
/// kept whole: the consumable set reads `entries` and the
/// dependency-context check reads `raw_unit_graph` (stow#588).
pub struct PhaseUnitGraph {
    phase: CargoSubcommand,
    invocation: CargoInvocation,
    /// The spelled `--target`, `None` for the native spelling.
    target: Option<String>,
    graph: stow_cli::ExpandedDependencyGraph,
}

impl PhaseUnitGraph {
    /// The `CARGO_TARGET_DIR` this phase ran under — the value a capture
    /// of one of its units records as `target_dir`, which is how the scan
    /// tells which phase and invocation a record belongs to.
    pub(crate) fn target_dir(&self, run_dir: &Path) -> PathBuf {
        phase_target_dir(run_dir, self.phase, self.invocation)
    }

    /// Phase and invocation spelling, for diagnostics.
    pub(crate) fn label(&self) -> String {
        format!("{} {}", self.phase.as_str(), self.invocation.spelling())
    }

    /// The phase this graph answers for — the closure reads `check`/`build`
    /// graphs into the publishable set and ignores `test` ones.
    pub(crate) const fn phase(&self) -> CargoSubcommand {
        self.phase
    }

    /// The target spelling cargo was given (`None` native).
    #[cfg(test)]
    pub(crate) fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// This graph's units in the shared task-unit model — the resolved
    /// feature set the scan labels each captured unit's row with
    /// (stow#611).
    pub(crate) fn task_units(
        &self,
        host_triple: &str,
    ) -> stow_types::error::Result<Vec<stow_types::unit_graph::TaskUnit>> {
        self.graph.task_units(self.target.as_deref(), host_triple)
    }

    /// [`task_units`] annotated with the cargo unit each task unit was
    /// projected from — twins re-split out of one both-reachable cargo
    /// unit share the origin, which is cargo's native host/target
    /// sharing verdict made visible (stow#723).
    pub(crate) fn task_units_with_origins(
        &self,
        host_triple: &str,
    ) -> stow_types::error::Result<Vec<(stow_types::unit_graph::TaskUnit, u32)>> {
        self.graph
            .task_units_with_origins(self.target.as_deref(), host_triple)
    }
}

/// The host triple of the runner family that builds `task`'s target —
/// the platform a unit cargo gives no `--target` compiles for.
///
/// # Errors
/// Returns an error when no runner family builds the task's target.
pub fn runner_host_triple(task: &BuildTaskPayload) -> stow_types::error::Result<&'static str> {
    Ok(stow_types::api::runner_family(task.target.as_str())
        .ok_or_else(|| {
            stow_types::stow_error!(
                "task {} {} targets {} — no runner family names its host triple",
                task.crate_name.as_str(),
                task.version,
                task.target
            )
        })?
        .host_triple())
}

/// The triple a unit compiled without `--target` is built for in this
/// build: the host rustc reports — or, in a mock-compile build, the
/// runner host the task is dispatched to, the triple its sandboxed
/// phases' rustc answers as.
///
/// # Errors
/// Returns an error when rustc cannot be asked, or the mock finds no
/// runner for the task's target.
#[cfg_attr(
    not(feature = "mock-compile"),
    expect(
        unused_variables,
        reason = "only the mock reads the task: a real build's host is rustc's"
    )
)]
pub async fn compile_host(task: &BuildTaskPayload) -> stow_types::error::Result<String> {
    #[cfg(feature = "mock-compile")]
    if crate::mock_compile::enabled() {
        return Ok(crate::mock_compile::runner_host(task.target.as_str())?.to_owned());
    }
    Ok(
        crate::capture::detect_rustc_toolchain(&OsString::from("rustc"))
            .await?
            .host_target,
    )
}

/// The units this build's workspace will compile, read from cargo's own
/// unit graphs — the consumable set (stow#589). Each graph is computed
/// with the same argv a phase runs (`cargo_phase_args`, minus the
/// subcommand, plus `--unit-graph`) under every invocation spelling the
/// task's phases use — native and `--target` for a host-side task, the
/// task spelling otherwise — because the spelling changes which units
/// cargo compiles, on which side, at which feature set.
///
/// Scheduler pins name only the task's direct dep edges, and a row's
/// recorded dep edges reach only lib `--extern`s — the graph covers the
/// whole resolved closure, build-script deps and transitives included,
/// at the identities cargo will actually compile them at.
pub async fn phase_unit_graphs(
    cargo_home: &Path,
    task: &BuildTaskPayload,
    workspace: &BuildWorkspace,
    cargo_subcommand: CargoSubcommand,
) -> stow_types::error::Result<Vec<PhaseUnitGraph>> {
    // A mock-compile resolve plans under the runner host the sandboxed
    // phases' cargo sees, or the two would disagree on every cfg-gated
    // host dependency. The wrapper script lives as long as the resolves.
    #[cfg(feature = "mock-compile")]
    let mock_wrapper = if crate::mock_compile::enabled() {
        let dir = TempDir::new()
            .map_err(|error| stow_types::stow_error!("create mock host wrapper dir: {error}"))?;
        let wrapper =
            crate::mock_compile::unit_graph_wrapper(dir.path(), runner_host_triple(task)?).await?;
        Some((dir, wrapper))
    } else {
        None
    };
    let mut graphs = Vec::new();
    for &phase in cargo_phases(cargo_subcommand) {
        for &invocation in phase_invocations(task) {
            #[cfg_attr(not(feature = "mock-compile"), allow(unused_mut))]
            let mut phase_args = cargo_phase_args(workspace, task, phase, invocation).await?;
            #[cfg(feature = "mock-compile")]
            if let Some((_, wrapper)) = &mock_wrapper {
                phase_args.push("--config".to_owned());
                phase_args.push(format!(
                    "build.rustc-wrapper={}",
                    toml::Value::String(wrapper.to_string_lossy().into_owned())
                ));
            }
            let passes_target = invocation_passes_target(task, invocation).await?;
            let graph = stow_cli::resolve_exact_dependency_graph(
                workspace.manifest_path(),
                phase.as_str(),
                &phase_args[1..]
                    .iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>(),
                passes_target.then(|| task.target.as_str()),
                workspace.workspace_root(),
                runner_host_triple(task)?,
                &task.rustc_version,
                Some(cargo_home),
            )
            .await?;
            graphs.push(PhaseUnitGraph {
                phase,
                invocation,
                target: passes_target.then(|| task.target.as_str().to_owned()),
                graph,
            });
        }
    }
    Ok(graphs)
}

/// The consumable set across every phase×invocation unit graph.
fn consumption_packages(
    task: &BuildTaskPayload,
    unit_graphs: &[PhaseUnitGraph],
) -> Vec<dep_scan::ConsumablePackage> {
    let mut entries = Vec::new();
    for unit_graph in unit_graphs {
        entries.extend(unit_graph.graph.entries.iter().cloned());
    }
    dep_scan::consumable_packages(task, &entries)
}

/// The compiled dependency-context gate (stow#588): every phase×invocation
/// unit graph must resolve the task's own node to the same `task_id` the
/// dispatch claims — the wrapper's pins reproduce the transitive feature
/// context, so the task node mints only when the compiled graph carries
/// the dispatched subgraph.
///
/// For a host-side task the explicit (`--target <host triple>`) spelling
/// defines identity: it is the resolve shape the resolver minted the
/// dispatch from. The native spelling compiles the same task unit
/// context — the pinned manifest makes cross-side feature unification
/// impossible (host pins live in `[build-dependencies]`, target pins in
/// `[dependencies]`, each at an exact set) — and dedup-shadow edges let
/// a shared unit serve both sides at one identity, so the task node id
/// must agree there too. A disagreement is cargo compiling the task
/// under a context nobody dispatched, and publishing its artifact under
/// `task_id` would mislabel the cache.
pub fn verify_dependency_context(
    task: &BuildTaskPayload,
    unit_graphs: &[PhaseUnitGraph],
) -> stow_types::error::Result<()> {
    let expected = task.verified_dependency_graph()?;
    let host_triple = runner_host_triple(task)?;
    for unit_graph in unit_graphs {
        let units = if unit_graph.target.is_none() && unit_graph.phase != CargoSubcommand::Check {
            // stow#723: under the native spelling cargo itself decides
            // whether a same-feature host/target twin pair merges — a
            // pair re-split out of one cargo unit shared, a pair
            // projected from two units stayed apart. That verdict must
            // equal the `self_twin_edges` predicate the task ids were
            // minted on; a divergence is a probe field this builder does
            // not model (rustflags, links overrides, is_std) deciding
            // differently, and any id minted past it mislabels the
            // cache. Under an explicit `--target` spelling cargo never
            // shares, and in the check phase a target-side lib is a
            // check-mode unit while a host-side lib is build-mode — the
            // probe and the interned unit both carry the mode
            // (`traverse_and_share`), so no pair can merge there and the
            // predicate, which answers for build-mode pairs, does not
            // apply. The ids still agree: the predicate reads only the
            // projected dependency structure, which both phases share.
            let with_origins =
                unit_graph
                    .task_units_with_origins(host_triple)
                    .map_err(|error| {
                        stow_types::stow_error!(
                            "task {} {} ({}): {} {} unit graph does not convert: {error}",
                            task.crate_name.as_str(),
                            task.version,
                            task.target,
                            unit_graph.phase.as_str(),
                            unit_graph.invocation.spelling(),
                        )
                    })?;
            assert_native_sharing_verdicts(&with_origins).map_err(|error| {
                stow_types::stow_error!(
                    "task {} {} ({}): {} {} unit graph: {error}",
                    task.crate_name.as_str(),
                    task.version,
                    task.target,
                    unit_graph.phase.as_str(),
                    unit_graph.invocation.spelling(),
                )
            })?;
            with_origins
                .into_iter()
                .map(|(unit, _)| unit)
                .collect::<Vec<_>>()
        } else {
            unit_graph.task_units(host_triple).map_err(|error| {
                stow_types::stow_error!(
                    "task {} {} ({}): {} {} unit graph does not convert: {error}",
                    task.crate_name.as_str(),
                    task.version,
                    task.target,
                    unit_graph.phase.as_str(),
                    unit_graph.invocation.spelling(),
                )
            })?
        };
        let actual = stow_types::unit_graph::resolved_task_graph(&units, &task.rustc_version)
            .map_err(|error| {
                stow_types::stow_error!(
                    "task {} {} ({}): {} {} unit graph does not resolve: {error}",
                    task.crate_name.as_str(),
                    task.version,
                    task.target,
                    unit_graph.phase.as_str(),
                    unit_graph.invocation.spelling(),
                )
            })?;
        let identity = task.task_node_identity();
        let found = actual
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, node)| node.identity == identity)
            .collect::<Vec<_>>();
        if found.is_empty() {
            return Err(stow_types::stow_error!(
                "task {} {} ({}): {} {} unit graph has no node with the task identity \
                 (crate {} version {} features {:?} target {} rustc {} host_side {})",
                task.crate_name.as_str(),
                task.version,
                task.target,
                unit_graph.phase.as_str(),
                unit_graph.invocation.spelling(),
                task.crate_name.as_str(),
                task.version,
                task.features_json.features(),
                task.target,
                task.rustc_version,
                task.host_side,
            ));
        }
        if found
            .iter()
            .any(|(index, _)| actual.task_id(*index) == Some(task.task_id.as_str()))
        {
            continue;
        }
        let difference = first_context_difference(&expected, &actual);
        return Err(stow_types::stow_error!(
            "task {} {} ({}): {} {} unit graph compiles a different dependency context — {difference}",
            task.crate_name.as_str(),
            task.version,
            task.target,
            unit_graph.phase.as_str(),
            unit_graph.invocation.spelling(),
        ));
    }
    Ok(())
}

/// stow#723: cargo's own sharing verdict on every same-feature
/// host/target twin pair in a native-spelled unit graph — a pair
/// re-split out of one cargo unit shared, a pair emitted from two did
/// not — must equal the `self_twin_edges` predicate the resolver's ids
/// were minted on. A divergence fails the build naming the crate.
fn assert_native_sharing_verdicts(
    units: &[(stow_types::unit_graph::TaskUnit, u32)],
) -> stow_types::error::Result<()> {
    use stow_types::unit_graph::{TaskUnitKey, TaskUnitKind, TaskUnitSide};
    let task_units: Vec<stow_types::unit_graph::TaskUnit> =
        units.iter().map(|(unit, _)| unit.clone()).collect();
    let by_key: std::collections::BTreeMap<&TaskUnitKey, (&stow_types::unit_graph::TaskUnit, u32)> =
        units
            .iter()
            .map(|(unit, origin)| (&unit.key, (unit, *origin)))
            .collect();
    let kept_apart: std::collections::BTreeSet<TaskUnitKey> =
        stow_types::unit_graph::self_twin_edges(&task_units)
            .map_err(|error| stow_types::stow_error!("evaluate the sharing predicate: {error}"))?
            .into_iter()
            .map(|(host, _)| host.key.clone())
            .collect();
    for (unit, origin) in units {
        if unit.key.kind != TaskUnitKind::Lib
            || unit.key.side != TaskUnitSide::Host
            || !unit.is_crates_io
        {
            continue;
        }
        let target_key = TaskUnitKey {
            side: TaskUnitSide::Target,
            ..unit.key.clone()
        };
        let Some((twin, twin_origin)) = by_key.get(&target_key) else {
            continue;
        };
        if twin
            .features
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            != unit
                .features
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
        {
            continue;
        }
        let cargo_shared = origin == twin_origin;
        let predicate_shared = !kept_apart.contains(&unit.key);
        if cargo_shared != predicate_shared {
            return Err(stow_types::stow_error!(
                "cargo {} the `{}` {} host/target twin pair but the sharing predicate {} — a probe input the builder does not model disagreed",
                if cargo_shared { "shared" } else { "kept apart" },
                unit.name,
                unit.version,
                if predicate_shared {
                    "shared"
                } else {
                    "kept them apart"
                },
            ));
        }
    }
    Ok(())
}

/// The first node where the dispatched and compiled graphs disagree:
/// its expected and actual task ids plus the children ids on both
/// sides, so the mismatch names the crate that resolved differently.
fn first_context_difference(
    expected: &stow_types::task_graph::ResolvedTaskGraph,
    actual: &stow_types::task_graph::ResolvedTaskGraph,
) -> String {
    for (index, node) in expected.nodes().iter().enumerate() {
        let expected_children = node
            .dependencies
            .iter()
            .filter_map(|dep| expected.task_id(*dep))
            .collect::<std::collections::BTreeSet<_>>();
        let mut named = None;
        let mut diverged = None;
        for (other_index, other) in actual.nodes().iter().enumerate() {
            if other.identity != node.identity {
                continue;
            }
            let actual_children = other
                .dependencies
                .iter()
                .filter_map(|dep| actual.task_id(*dep))
                .collect::<std::collections::BTreeSet<_>>();
            if actual_children == expected_children {
                named = Some(other_index);
                break;
            }
            diverged.get_or_insert(other_index);
        }
        if named.is_some() {
            continue;
        }
        let expected_id = expected
            .task_id(index)
            .map_or_else(|| "<unresolved>".to_owned(), str::to_owned);
        let expected_kids = expected_children.into_iter().collect::<Vec<_>>().join(", ");
        return diverged.map_or_else(
            || {
                format!(
                    "node {} {} ({}): expected id `{}` children [{}]; the compiled graph has no such node",
                    node.identity.crate_name.as_str(),
                    node.identity.version,
                    node.identity.target,
                    expected_id,
                    expected_kids,
                )
            },
            |other_index| {
                let actual_children = actual.nodes()[other_index]
                    .dependencies
                    .iter()
                    .filter_map(|dep| actual.task_id(*dep))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "node {} {} ({}): expected id `{}` children [{}]; actual id `{}` children [{}]",
                    node.identity.crate_name.as_str(),
                    node.identity.version,
                    node.identity.target,
                    expected_id,
                    expected_kids,
                    actual.task_id(other_index).unwrap_or("<unresolved>"),
                    actual_children,
                )
            },
        );
    }
    "the dispatched subgraph's every node resolved identically; the task id still differs"
        .to_owned()
}

pub async fn build(
    task: &BuildTaskPayload,
    output_dir: &Path,
) -> stow_types::error::Result<BuiltWorkspace> {
    // Resolve and verify the run toolchain once per task — a name whose
    // rustc reports a different release than the pinned `rustc_version`
    // is refused here, before any phase runs cargo.
    verified_run_toolchain(task)?;
    let mirror_key = workspace_mirror::MirrorTaskKey {
        target: task.target.as_str().to_owned(),
        rustc_version: task.rustc_version.as_str().to_owned(),
        preserve_lockfile: task.preserve_lockfile,
    };
    let workspace = stabilize_workspace(create_workspace(task).await?, &mirror_key).await?;

    let cargo_home = cargo_home()?;
    fetch_workspace_dependencies(&cargo_home, task, &workspace).await?;

    let cargo_subcommand = cargo_subcommand()?;
    // Cargo's own unit graphs are computed once for the whole build:
    // the dependency-context check must see exactly what every phase
    // and spelling will compile (stow#588), and consumption reads the
    // same answers — a graph that cannot be produced fails the build,
    // not just the cache path.
    let unit_graphs = phase_unit_graphs(&cargo_home, task, &workspace, cargo_subcommand).await?;
    verify_dependency_context(task, &unit_graphs)?;
    let (_consume_store_dir, consume_store) = stage_consumption_store(task, &unit_graphs).await?;

    let audit_log = heel::NetworkAuditLog::file(output_dir.join("network-audit.jsonl"))
        .map_err(|error| stow_types::stow_error!("open network audit log: {error}"))?;
    let remap_flag = format!(
        "--remap-path-prefix={}={}",
        workspace.workspace_root().display(),
        "stow-ci://workspace"
    );
    let rustflags = merged_rustflags(&remap_flag);

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
        cargo_home: &cargo_home,
        wrappers: &wrappers,
        runtime_wrapper: &runtime_wrapper,
        capture_wrapper: &capture_wrapper,
        capture_command: &capture_command,
        audit_log: &audit_log,
        rustflags: &rustflags,
        target: task.target.as_str(),
        consume_store: consume_store.as_deref(),
    };
    // One sandbox carries every phase and invocation. On Windows building
    // it means a recursive ACL pass over every granted tree — the registry
    // sources, the toolchain, the compiler search dirs — and doing that
    // once per phase×invocation cost tens of minutes per build (stow#431).
    // The grant set below is identical for all phases anyway: the only
    // per-phase path is `CARGO_TARGET_DIR`, and every phase's target dir
    // sits under `run_dir`, which the grant covers.
    let msvc = MsvcToolchain::resolve(task.target.as_str())?;
    let sandbox = phase_sandbox(&setup, run_dir.path(), &msvc).await?;
    let ipc_endpoint = sandbox
        .ipc_endpoint()
        .ok_or_else(|| stow_types::stow_error!("IPC-configured sandbox exposed no endpoint"))?
        .to_path_buf();
    let run = PhaseRun {
        setup: &setup,
        sandbox: &sandbox,
        ipc_endpoint: &ipc_endpoint,
        msvc: &msvc,
    };
    for &phase in phases {
        for &invocation in phase_invocations(task) {
            let target_dir = phase_target_dir(run_dir.path(), phase, invocation);
            run_sandboxed_phase(&run, task, phase, invocation, &target_dir, &mut collector).await?;
        }
    }

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        cargo_subcommand = cargo_subcommand.as_str(),
        "cargo phases finished"
    );

    Ok(BuiltWorkspace {
        workspace,
        run_dir,
        captures: collector.into_records()?,
        unit_graphs,
    })
}

/// The rustup *name* the phases run `cargo` under — a different fact
/// from `task.rustc_version`, which records the release the task's
/// identity pins, not a toolchain name. `RUSTUP_TOOLCHAIN` already
/// carries a name when the caller set one — the build workflow's
/// toolchain step exports it, and a test run inherits the name of the
/// toolchain executing the suite — and the pinned release is the name
/// production's no-export env still resolves (`rustup toolchain
/// install 1.99.0` answers to `1.99.0`). It never asks `rustup show`:
/// a runner's *default* toolchain is not the task's.
pub fn run_toolchain(task: &BuildTaskPayload) -> String {
    std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| task.rustc_version.as_str().to_owned())
}

/// `run_toolchain`'s name, verified once per task against the release
/// its `rustc` actually reports — the same check `Resolver::setup`
/// makes. The ambient name is still just a name: a misconfigured
/// workflow step (or a runner whose `stable` moved past the dispatch's
/// pin) would otherwise compile the whole task under the wrong release
/// and only surface at `validate`, which rejects the scanned artifacts
/// after the build already burned. This refuses before any cargo
/// invocation, naming the toolchain, its reported release, and the
/// task's `rustc_version`. `RUSTUP_AUTO_INSTALL=0` keeps a missing name
/// a refusal instead of a network install.
pub fn verified_run_toolchain(task: &BuildTaskPayload) -> stow_types::error::Result<String> {
    let toolchain = run_toolchain(task);
    let output = std::process::Command::new("rustc")
        .arg("-vV")
        .env("RUSTUP_TOOLCHAIN", &toolchain)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .output()
        .map_err(|error| stow_types::stow_error!("probe run toolchain {toolchain}: {error}"))?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "run toolchain {toolchain}: rustc -vV failed with {}",
            output.status
        ));
    }
    let verbose = String::from_utf8_lossy(&output.stdout);
    let release = verbose
        .lines()
        .find_map(|line| line.strip_prefix("release: "))
        .unwrap_or("<unparsable rustc -vV output>");
    if release != task.rustc_version.as_str() {
        return Err(stow_types::stow_error!(
            "run toolchain {toolchain} reports rustc {release}, \
             not the task's pinned {}",
            task.rustc_version.as_str()
        ));
    }
    Ok(toolchain)
}

/// Phase 0 runs on the host: `cargo fetch` resolves the dependency graph
/// and populates the registry cache, so the sandboxed phases can run
/// `--frozen` — no lockfile writes, no index access — with every outbound
/// connection an untrusted build script still attempts audited. Feature
/// flags don't exist on `fetch`: it downloads the full dependency closure
/// for every feature and every target.
pub async fn fetch_workspace_dependencies(
    cargo_home: &Path,
    task: &BuildTaskPayload,
    workspace: &BuildWorkspace,
) -> stow_types::error::Result<()> {
    let mut fetch = Command::new("cargo");
    fetch
        .arg("fetch")
        .arg("--manifest-path")
        .arg(workspace.manifest_path())
        .env("CARGO_HOME", path_arg(cargo_home)?);
    // Fetch never takes `--locked`: the generated wrapper's seeded lockfile
    // is not one cargo can be held to — it must still prune bundled entries
    // the wrapper graph cannot reach and fill in the dep edges. Under
    // `preserve_lockfile` the lock's fidelity is proven by the diff check
    // below instead of by the flag.
    let status = fetch
        .env("RUSTUP_TOOLCHAIN", run_toolchain(task))
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
    Ok(())
}

/// The per-run state every sandboxed phase shares.
pub struct PhaseSetup<'a> {
    pub workspace: &'a BuildWorkspace,
    /// The cargo home the sandboxed phases see: its caches are granted
    /// read-only and it is exported to them as `CARGO_HOME`. Callers pass
    /// [`cargo_home`]'s answer; a test passes the home its fixture built.
    pub cargo_home: &'a Path,
    pub wrappers: &'a wrapper_shim::WrapperShimPaths,
    pub runtime_wrapper: &'a Path,
    pub capture_wrapper: &'a Path,
    pub capture_command: &'a StowCaptureCommand,
    pub audit_log: &'a heel::NetworkAuditLog,
    pub rustflags: &'a str,
    /// The task's target triple: which cross toolchain's variables and
    /// install trees the sandbox is given.
    pub target: &'a str,
    /// The prefetch-staged verified bundle store, when consumption staged
    /// anything: granted read-only to every phase.
    pub consume_store: Option<&'a Path>,
}

/// The shared resources one sandboxed phase run draws on — the phase
/// inputs plus the build's one sandbox (phases share it because creating
/// one pays the grant-ACL walk over every granted tree, stow#431).
pub struct PhaseRun<'a> {
    pub setup: &'a PhaseSetup<'a>,
    pub sandbox: &'a Sandbox<heel::Audited<heel::AllowAll>>,
    /// heel's IPC socket, exported to sandboxed processes so shimmed
    /// commands reach the host.
    pub ipc_endpoint: &'a Path,
    pub msvc: &'a MsvcToolchain,
}

/// Run one cargo phase inside the build's sandbox, then absorb the capture
/// records it delivered. A duplicate identity is fatal, and so is cargo
/// exiting non-zero — the build compiles one crate, and a phase that
/// cannot finish means the task failed.
pub async fn run_sandboxed_phase(
    run: &PhaseRun<'_>,
    task: &BuildTaskPayload,
    phase: CargoSubcommand,
    invocation: CargoInvocation,
    target_dir: &Path,
    collector: &mut CaptureCollector,
) -> stow_types::error::Result<()> {
    let setup = run.setup;
    create_dir_all(target_dir).await?;
    let args = cargo_phase_args(setup.workspace, task, phase, invocation).await?;

    // A unit that links in more than one phase — a proc-macro's deps like
    // `defmt-parser`, or a build-script crate that `include!`s generated
    // sources — is compiled once per phase into that phase's own
    // CARGO_TARGET_DIR. Without a remap, the phase dir leaks into the
    // artifacts (`OUT_DIR` source files recorded in rmeta, and through the
    // crate hash into dependents' dep hashes), so two captures of the same
    // unit carry different output digests and dep_scan's same-unit proof
    // aborts the build as a forged duplicate. Remapping every phase's
    // target dir to one virtual root makes the outputs byte-identical, the
    // same determinism remap of the workspace root already gives sources.
    // The rustflags carry the flag only as far as the host/target boundary —
    // under `--target` host units never see it — so it also travels through
    // STOW_BUILD_TARGET_DIR_REMAP for the wrapper to append to every rustc
    // argv the boundary drops it from (MSVC CodeView S_OBJNAME embeds the
    // object's own absolute output path; without the remap the two phase
    // dirs hash differently on Windows even though the unit is identical).
    let rustflags = phase_rustflags(setup.rustflags, task.target.as_str(), target_dir);

    let mut command = run
        .sandbox
        .command("cargo")
        .args(args)
        .env("RUSTUP_TOOLCHAIN", run_toolchain(task))
        .env("RUSTFLAGS", rustflags)
        .env("RUSTC_WRAPPER", path_arg(&setup.wrappers.rustc_wrapper)?)
        .env("CARGO_TARGET_DIR", path_arg(target_dir)?)
        .env(
            STOW_BUILD_CAPTURE_DIR_ENV,
            path_arg(setup.workspace.capture_dir())?,
        )
        .env(STOW_BUILD_CAPTURE_IPC_ENV, path_arg(run.ipc_endpoint)?)
        .env("CARGO_HOME", path_arg(run.setup.cargo_home)?)
        .env("RUSTUP_HOME", path_arg(&rustup_home()?)?)
        .current_dir(setup.workspace.workspace_root());
    if let Some(store_dir) = setup.consume_store {
        command = command.env(STOW_BUILD_CONSUME_STORE_ENV, path_arg(store_dir)?);
    }
    // PATH included: the MSVC bin directories come first in it, which is
    // what puts the real linker ahead of whatever else on the runner is
    // called `link`.
    for (key, value) in &run.msvc.env {
        command = command.env(os_str_arg(key)?, os_str_arg(value)?);
    }
    // The wrapper package is generated scaffolding: the capture wrapper
    // records its units as observed so nothing forged under its name slips
    // in, but it is never a publishable artifact.
    command = command.env(STOW_BUILD_WRAPPER_CRATE_NAME_ENV, WRAPPER_PACKAGE_NAME);
    command = command.env(STOW_BUILD_TARGET_DIR_REMAP_ENV, TARGET_DIR_VIRTUAL_ROOT);
    // The sandbox starts with no environment: a mock-compile run's switch
    // reaches the capture wrapper only through this grant.
    #[cfg(feature = "mock-compile")]
    if crate::mock_compile::enabled() {
        command = command
            .env(crate::mock_compile::STOW_BUILD_MOCK_COMPILE_ENV, "1")
            .env(
                crate::mock_compile::STOW_BUILD_MOCK_HOST_ENV,
                runner_host_triple(task)?,
            );
    }
    let passes_target = invocation_passes_target(task, invocation).await?;
    let status = command.status().await.map_err(|error| {
        stow_types::stow_error!("run sandboxed cargo {}: {error}", phase.as_str())
    })?;

    // Absorb the records this phase delivered before looking at cargo's
    // exit status: a duplicate identity is fatal either way. The drain
    // stamps each record with the invocation spelling this run executed —
    // the payload the sandbox reports is untrusted, so the shape the unit
    // registers under comes from the invocation the builder ran.
    let unit_invocation = if passes_target {
        stow_types::public_cache::UnitInvocation::Target
    } else {
        stow_types::public_cache::UnitInvocation::Native
    };
    collector.drain(phase.as_str(), unit_invocation)?;

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

/// How one phase's `cargo` invocation is spelled: whether `--target`
/// reaches the command line. The cargo invocation decides every unit's
/// flag set, so it is part of what the build produces, not an
/// implementation detail: a plain (no `--target`) invocation and a
/// `--target` one compile the same host crate at different unit shapes
/// (`-C debuginfo` applied or not), and consumers on each invocation
/// key on their own.
#[derive(Clone, Copy)]
pub enum CargoInvocation {
    /// Decide from the task's target triple — `--target` only for a
    /// cross build, the spelling a non-host-side task always uses.
    Task,
    /// A plain invocation — never passes `--target`. Produces the host
    /// units a native consumer's build computes (the build-override
    /// profile: no `-C debuginfo`).
    Native,
    /// `--target <task.target>` spelled out — produces the host units a
    /// `--target` consumer's build computes (cargo applies
    /// `-C debuginfo` to the host half whenever `--target` is present,
    /// even to the host triple itself).
    Explicit,
}

impl CargoInvocation {
    /// The argv spelling, for error messages.
    const fn spelling(self) -> &'static str {
        match self {
            Self::Task => "task-spelled",
            Self::Native => "native",
            Self::Explicit => "explicit --target",
        }
    }
}

/// The invocations a task's phases each run under. A host-side task
/// compiles its crate as a host unit, and consumers reach that unit
/// from both invocation spellings — a native build and any `--target`
/// build compute different compile keys for it — so the task runs each
/// phase under both and publishes both artifacts (stow#349). A
/// `KeysApart` target-side task at the runner's host triple does the
/// same: a proc-macro in its `--extern` closure keys the unit
/// differently per spelling, so it publishes the target-side shapes of
/// both (stow#736).
fn phase_invocations(task: &BuildTaskPayload) -> &'static [CargoInvocation] {
    let runs_both_spellings = task.host_side
        || (task.explicit_spelling == stow_types::public_cache::ExplicitSpelling::KeysApart
            && stow_types::api::runner_family(task.target.as_str())
                .is_some_and(|family| family.host_triple() == task.target.as_str()));
    if runs_both_spellings {
        &[CargoInvocation::Native, CargoInvocation::Explicit]
    } else {
        &[CargoInvocation::Task]
    }
}

/// The `cargo` argv for one sandboxed phase.
async fn cargo_phase_args(
    workspace: &BuildWorkspace,
    task: &BuildTaskPayload,
    phase: CargoSubcommand,
    invocation: CargoInvocation,
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
    // Task feature flags never reach the cargo command line: the wrapper
    // package's dependency declaration already encodes the selection, and
    // the generated package declares no features of its own for them to
    // mean.
    //
    // Only cross-compiles pass `--target`. Passing it for a host build
    // splits cargo's unit graph into host and target halves and changes
    // the flags it gives the host half — build scripts, proc macros and
    // everything they depend on gain `-C debuginfo`, which the lookup
    // side normalizes differently. Users run plain `cargo build`, so a
    // host build here has to be a plain `cargo build` too or the entire
    // proc-macro graph is keyed differently from theirs, and every crate
    // deriving through it misses. A host-side task does both spellings —
    // it produces the host units of both invocation shapes, so its
    // `Explicit` run passes `--target` even though its target is the
    // host triple.
    if invocation_passes_target(task, invocation).await? {
        args.push("--target".to_owned());
        args.push(task.target.as_str().to_owned());
    }
    Ok(args)
}

/// Whether this phase's cargo command line carries `--target` — the
/// spelling that splits cargo's unit graph at the host/target boundary.
/// Cross-spelled invocations mirror a cross-compiling consumer; native
/// ones mirror a plain `cargo build`.
async fn invocation_passes_target(
    task: &BuildTaskPayload,
    invocation: CargoInvocation,
) -> stow_types::error::Result<bool> {
    Ok(match invocation {
        CargoInvocation::Task => !target_is_host(task.target.as_str()).await?,
        CargoInvocation::Native => false,
        CargoInvocation::Explicit => true,
    })
}

/// Build the `heel` sandbox every cargo phase of one build runs in.
///
/// The child starts with no environment and no home directory; every path it
/// can touch is an explicit grant below, and every network connection it
/// attempts is proxied and audited into the run's `network-audit.jsonl`. The
/// grants are what stop a build script from reaching the runner's
/// credentials, the cargo registry sources, or this process's environment.
/// `run_dir` is the parent of every phase's `CARGO_TARGET_DIR`: granting it
/// once covers them all, since a directory grant reaches children created
/// after the sandbox exists.
pub async fn phase_sandbox(
    setup: &PhaseSetup<'_>,
    run_dir: &Path,
    msvc: &MsvcToolchain,
) -> stow_types::error::Result<Sandbox<heel::Audited<heel::AllowAll>>> {
    let PhaseSetup {
        workspace,
        wrappers,
        runtime_wrapper,
        capture_wrapper,
        capture_command,
        audit_log,
        target,
        consume_store,
        ..
    } = setup;
    let mut builder = SandboxConfigBuilder::default()
        .network(heel::Audited::new(heel::AllowAll, (*audit_log).clone()))
        .filesystem_strict(true)
        .working_dir(workspace.workspace_root())
        // The IPC router is what the sandboxed rustc wrapper streams capture
        // records through; the generated `heel ipc` launcher shims are inert
        // here because the wrapper links `heel::IpcClient` directly, but heel
        // still needs a binary path to bake into them — `stow-build` doubles
        // as that binary and gets the EXEC grant the capture shim needs.
        .heel_binary(*capture_wrapper)
        .ipc(heel::IpcRouter::new().register((*capture_command).clone()))
        // `cargo`/`rustc` resolve through the host PATH (and through it the
        // rustup proxies under CARGO_HOME/bin).
        .env_passthrough("PATH")
        // Probe-test hook: names a path a test build script tries to read.
        .env_passthrough(STOW_PROBE_FORBIDDEN_PATH_ENV)
        // Toolchain configuration for cross builds: `CARGO_TARGET_*_LINKER`
        // points cargo at the NDK/GNU cross linker, the `cc`-crate `CC_*`/
        // `AR_*`/`CFLAGS_*` forms pick its compiler, and the SDK/NDK root
        // variables let tools locate their own install trees — the Android
        // ones only when the task's target is Android, since a runner image
        // exports them whatever it builds. These carry paths and flags only
        // — the filesystem grants below still decide what a build script
        // can actually read or exec.
        .env_passthroughs(toolchain_env_names(
            target,
            std::env::vars_os().filter_map(|(name, _)| name.into_string().ok()),
        ));

    for (path, access, reason) in sandbox_grants(
        setup.cargo_home,
        workspace,
        run_dir,
        wrappers,
        runtime_wrapper,
        msvc,
        *consume_store,
        target,
    )? {
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
#[allow(clippy::too_many_arguments)]
fn sandbox_grants(
    cargo_home: &Path,
    workspace: &BuildWorkspace,
    run_dir: &Path,
    wrappers: &wrapper_shim::WrapperShimPaths,
    runtime_wrapper: &Path,
    msvc: &MsvcToolchain,
    consume_store: Option<&Path>,
    target: &str,
) -> stow_types::error::Result<Vec<(PathBuf, Access, &'static str)>> {
    let rustup_home = rustup_home()?;
    ensure_package_cache_lock(cargo_home)?;

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
            run_dir.to_path_buf(),
            Access::WRITE | Access::EXEC,
            "parent of every phase's CARGO_TARGET_DIR — build scripts and proc macros are compiled here and must execute; kept outside the working dir, which never executes",
        ),
        (
            workspace.capture_dir().to_path_buf(),
            Access::WRITE,
            "output snapshots and output-identity sidecars land here; records do not",
        ),
    ];

    // Verified bundles the wrapper serves for a cache-hit unit. Read-only
    // so sandboxed code cannot plant an entry of its own — the only writer
    // is the host prefetch, which digest-checks and cosign-verifies every
    // byte before it lands.
    if let Some(store_dir) = consume_store {
        grants.push((
            store_dir.to_path_buf(),
            Access::READ,
            "the verified consume-store the capture wrapper injects cache-hit units from",
        ));
    }

    conditional_grants(cargo_home, &rustup_home, target, &mut grants);

    grants.extend(compiler_search_grants());
    grants.extend(msvc.grants());

    // Under a root Windows opens to every AppContainer — %SystemRoot%,
    // %ProgramFiles%, %ProgramFiles(x86)% — the container already has read
    // and execute; granting again only re-ACLs the whole tree, which was
    // the multi-minute stall each sandbox paid per creation (stow#431).
    // Write grants are kept: the roots give no write access.
    grants.retain(|(path, access, _)| access.can_write() || !in_windows_system_tree(path));

    Ok(grants)
}

/// Whether `path` sits under a directory Windows already opens to every
/// `AppContainer`: `%SystemRoot%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`.
/// This is heel's own `in_system_directory` premise — the one its ancestor
/// traversal relies on — checked the same way, case-insensitively on
/// either separator.
fn in_windows_system_tree(path: &Path) -> bool {
    let path = path.to_string_lossy().to_lowercase();
    ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)"]
        .iter()
        .filter_map(|variable| std::env::var(variable).ok())
        .any(|root| {
            let root = root.to_lowercase();
            path == root
                || path.starts_with(&format!("{root}\\"))
                || path.starts_with(&format!("{root}/"))
        })
}

/// The existence-conditional grants — a bare `cargo_home` may carry no
/// `git` database, a rustup-managed toolchain may put `RUSTUP_HOME`
/// anywhere, `/usr/include` exists only on a host with C headers. Each is
/// pushed only when its path exists: a grant must resolve to a real path.
fn conditional_grants(
    cargo_home: &Path,
    rustup_home: &Path,
    target: &str,
    grants: &mut Vec<(PathBuf, Access, &'static str)>,
) {
    if cargo_home.join("git").exists() {
        grants.push((
            cargo_home.join("git"),
            Access::READ,
            "git dependency database and checkouts fetched on the host in phase 0; read-only like the registry",
        ));
    }
    if rustup_home.exists() {
        grants.push((
            rustup_home.to_path_buf(),
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

    // The distro C header root every build script's `cc`/`c++` reads.
    // heel's system rules cover the exec trees under `/usr` (bin, lib,
    // libexec) but not `/usr/include`, so a `cc` probe dies on
    // `/usr/include/stdc-predef.h: Permission denied`. Read-only like the
    // registry: a sandboxed build must not be able to touch system headers.
    let usr_include = Path::new("/usr/include");
    if usr_include.exists() {
        grants.push((
            usr_include.to_path_buf(),
            Access::READ,
            "the system C header root — outside heel's exec rules, which cover /usr/{bin,lib,libexec} but not include",
        ));
    }

    // Cross toolchain install trees named by the toolchain env vars —
    // an NDK under `~/Library/Android` or `/opt`, a sysroot a `SDKROOT`
    // points at. Where the runner image puts them under `/usr` these
    // duplicate heel's system grants and cost nothing.
    for dir in toolchain_grant_dirs(target, std::env::vars_os()) {
        grants.push((
            dir,
            Access::READ | Access::EXEC,
            "cross toolchain install tree named by a toolchain env var",
        ));
    }
}

/// The compilers and their search paths, as the host environment resolves
/// them.
///
/// `cargo`/`rustc` come off PATH (rustup proxies, a homebrew rust, a CI
/// image toolchain). On Windows `link.exe` joins them: rustc runs the
/// linker it finds on PATH whenever its own MSVC lookup comes up empty,
/// which is what happens in here — that lookup runs `vswhere.exe` out of a
/// Program Files tree this sandbox does not grant. Without this the
/// fallback resolved to Git for Windows' msys `link`, which cannot start
/// inside an `AppContainer` at all, and every Windows build that linked
/// anything — every crate carrying a build script or a proc macro — died
/// with `link.exe returned an unexpected error`. `LIB` and `INCLUDE` are
/// the CRT and Windows SDK search lists that same linker reads.
fn compiler_search_grants() -> Vec<(PathBuf, Access, &'static str)> {
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
    for name in ["LIB", "INCLUDE"] {
        let Some(value) = std::env::var_os(name) else {
            continue;
        };
        for dir in std::env::split_paths(&value).filter(|dir| dir.is_dir()) {
            grants.push((
                dir,
                Access::READ,
                "an MSVC library or include directory named by LIB/INCLUDE",
            ));
        }
    }
    grants
}

pub fn cargo_home() -> stow_types::error::Result<PathBuf> {
    if let Some(path) = std::env::var_os("CARGO_HOME") {
        return Ok(PathBuf::from(path));
    }
    std::env::home_dir()
        .map(|home| home.join(".cargo"))
        .ok_or_else(|| stow_types::stow_error!("cannot determine the cargo home directory"))
}

pub fn rustup_home() -> stow_types::error::Result<PathBuf> {
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

/// The Android SDK and NDK roots. A runner image exports these whatever
/// it is about to build, so they are passed through and their trees
/// granted only to a task that targets Android: granting them to
/// every task made each Windows build rewrite the access control list
/// of the whole SDK, and of each NDK inside it again — minutes per
/// build for a tree no Windows task reads (stow#718).
const ANDROID_ROOT_VARS: &[&str] = &[
    "ANDROID_HOME",
    "ANDROID_SDK_ROOT",
    "ANDROID_NDK",
    "ANDROID_NDK_HOME",
    "ANDROID_NDK_ROOT",
    "ANDROID_NDK_LATEST_HOME",
];

/// Whether `target` builds for Android — a triple whose operating-system
/// component starts with `android` (`aarch64-linux-android`,
/// `armv7-linux-androideabi`, `x86_64-linux-android`, `i686-linux-android`).
fn targets_android(target: &str) -> bool {
    target
        .rsplit('-')
        .next()
        .is_some_and(|os| os.starts_with("android"))
}

/// Environment variable names that configure the cross toolchain, selected
/// out of `names` — the caller passes the parent environment's names at
/// sandbox-build time, and the task's `target` decides which apply.
///
/// Exact names cover the compiler drivers the `cc` crate and rustc invoke
/// and the SDK roots those tools locate their install trees through. The
/// Android SDK/NDK roots (`ANDROID_ROOT_VARS`) count only for a task that
/// targets Android; the runner image exports them whatever the job
/// builds. The prefixed forms are the `cc` crate's per-target overrides
/// (`CC_<target>`, `AR_<target>`, `CFLAGS_<target>`), cargo's per-target
/// configuration (`CARGO_TARGET_<TRIPLE>_LINKER`, `_AR`, `_RUNNER`,
/// `_RUSTFLAGS`), and the `pkg-config` crate's configuration in both its
/// plain and its per-target spelling — the aarch64 job names its cross
/// pkg-config in `PKG_CONFIG_aarch64_unknown_linux_gnu`, so a build
/// script compiling for the host keeps the native one (stow#729).
/// `CARGO_TARGET_DIR` is deliberately not a prefix match here —
/// `CARGO_TARGET_DIR` is set explicitly per phase.
fn toolchain_env_names(target: &str, names: impl Iterator<Item = String>) -> Vec<String> {
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
        // The glibc sysroot root the Linux build job installs:
        // passthrough is what `toolchain_grant_dirs` keys on to grant
        // the whole tree (its bin/ holds the PATH-resolved driver shims).
        "STOW_GLIBC_SYSROOT",
        // The lock-extracted system-library root (stow#850): the
        // sandbox passes it through and `toolchain_grant_dirs` grants
        // read+exec on the tree. `CMAKE_PREFIX_PATH` is how CMake's
        // find_* modules reach the same root.
        "STOW_SYSTEM_LIBS",
        "CMAKE_PREFIX_PATH",
        // The MSVC developer environment. `LIB` and `INCLUDE` are how the
        // linker and the `cc` crate find the CRT and the Windows SDK; the
        // install-root variables are how a build script locates the same
        // toolchain for itself.
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
        "PKG_CONFIG_",
        // bindgen's extra clang args, global and per-target spellings —
        // they carry the system-library root's -isystem include dirs.
        "BINDGEN_EXTRA_CLANG_ARGS",
    ];
    let android = targets_android(target);
    names
        .filter(|name| {
            !env_name::eq(name, "CARGO_TARGET_DIR")
                && (env_name::eq_any(name, EXACT)
                    || (android && env_name::eq_any(name, ANDROID_ROOT_VARS))
                    || env_name::starts_with_any(name, PREFIXES))
        })
        .collect()
}

/// Directories a cross toolchain lives under, selected out of `vars` — the
/// same environment `toolchain_env_names` filters for names, with the
/// task's `target` deciding which roots apply. The SDK roots name whole
/// install trees (`ANDROID_ROOT_VARS` only for a task that targets
/// Android); linker and compiler variables name executables, whose parent
/// directory is granted the way `resolve_on_path` grants the
/// `cargo`/`rustc` directory. On Linux runners these resolve under `/usr`
/// — already covered by heel's system rules — so the grants matter where
/// the toolchain lives in a user-owned location, like the macOS
/// `~/Library/Android` SDK an Android task builds against.
fn toolchain_grant_dirs(
    target: &str,
    vars: impl Iterator<Item = (OsString, OsString)>,
) -> Vec<PathBuf> {
    const TOOLCHAIN_ROOT_VARS: &[&str] = &[
        "SDKROOT",
        "DEVELOPER_DIR",
        // The glibc-2.28 sysroot the Linux build job extracts under the
        // runner's home: sandboxed compiles read its headers and link
        // inputs through it.
        "STOW_GLIBC_SYSROOT",
        // The system-library root extracted from the lock's debs
        // (stow#850): sandboxed pkg-config, compile and link probes
        // read its headers, .pc files and libraries.
        "STOW_SYSTEM_LIBS",
    ];
    const TOOLCHAIN_EXE_PREFIXES: &[&str] = &["CARGO_TARGET_", "CC_", "CXX_", "AR_", "RANLIB_"];
    let android = targets_android(target);
    let mut dirs: Vec<PathBuf> = vars
        .filter_map(|(name, value)| {
            if env_name::eq_any(&name, TOOLCHAIN_ROOT_VARS)
                || (android && env_name::eq_any(&name, ANDROID_ROOT_VARS))
            {
                return Some(PathBuf::from(value));
            }
            if env_name::starts_with_any(&name, TOOLCHAIN_EXE_PREFIXES) {
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

/// The MSVC toolchain a sandboxed Windows build needs, resolved out here
/// on the host: the host architecture's linker for what a task links —
/// its build scripts and proc macros are host binaries — and the task
/// target's own compiler and archiver for what those build scripts
/// compile.
///
/// rustc looks the linker up for itself, but that lookup runs
/// `vswhere.exe` from a Program Files tree the sandbox does not grant, so
/// inside the container it comes up empty and rustc falls back to the
/// first `link.exe` on PATH. On a GitHub Windows runner that is Git for
/// Windows' msys `link`, which cannot even start inside an
/// `AppContainer`: it dies in `NtCreateDirectoryObject` before it reads
/// its arguments. Every Windows build that linked anything — every crate
/// carrying a build script or a proc macro — failed that way, which is
/// two of the nine target triples producing almost nothing.
///
/// A build script's `cc` call hits the same wall: the `cc` crate's own
/// MSVC lookup cannot run inside the sandbox, and it falls back to the
/// first `cl.exe` on PATH — the host's — so an arm64 task compiled its C
/// sources for x86-64 and archived the objects into the artifact
/// (stow#708). The target's own `cl.exe` and `lib.exe` therefore go in
/// through the `cc` crate's per-target `CC_<target>`/`CXX_<target>`/
/// `AR_<target>` variables, with the compiler's directory appended to
/// PATH and granted to the sandbox.
///
/// Resolving all of it out here and handing the answer in costs one
/// lookup per tool and keeps rustc's own behaviour for the linker: it is
/// found on PATH, with `LIB` and `INCLUDE` pointing at the CRT and the
/// Windows SDK.
#[derive(Debug, Default)]
pub struct MsvcToolchain {
    /// `PATH`, `LIB`, `INCLUDE` and the `cc` crate's per-target
    /// `CC_<target>`/`CXX_<target>`/`AR_<target>` as the toolchain needs
    /// to see them, already composed with this process's own values.
    pub env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    /// The host linker's own directory, which holds the DLLs it loads.
    bin_dir: Option<PathBuf>,
    /// The target compiler's own directory — the host linker's when the
    /// task's machine is the host's.
    compiler_dir: Option<PathBuf>,
}

impl MsvcToolchain {
    /// Look the toolchain up for a task on `target`.
    ///
    /// The linker is always the host architecture's — a dependency
    /// crate's own units are rlibs and never reach a linker, so the only
    /// linking a cross task does is its build scripts and proc macros —
    /// while the compiler and archiver are `target`'s own, resolved only
    /// when `target` spells `-windows-msvc`; a `-windows-msvc` task whose
    /// target toolchain is not installed fails here, because its C
    /// sources would otherwise silently come out for the wrong machine.
    /// Empty on every non-Windows host; on a Windows host a missing host
    /// linker still only warns, and the build fails on its own terms
    /// rather than on a missing grant.
    #[cfg(windows)]
    pub fn resolve(target: &str) -> stow_types::error::Result<Self> {
        let tool = find_msvc_tools::find_tool(std::env::consts::ARCH, "link.exe");
        let mut toolchain = match tool {
            Some(tool) => {
                let bin_dir = tool.path().parent().map(Path::to_path_buf);
                tracing::debug!(linker = %tool.path().display(), "resolved the MSVC linker for the sandbox");
                Self {
                    env: tool.env().into_iter().cloned().collect(),
                    bin_dir,
                    compiler_dir: None,
                }
            }
            None => {
                tracing::warn!(
                    arch = std::env::consts::ARCH,
                    "no MSVC installation found for the host; a sandboxed build that links will fail"
                );
                Self::default()
            }
        };
        if target.ends_with("-windows-msvc") {
            let cl = find_msvc_tools::find_tool(target, "cl.exe").ok_or_else(|| {
                stow_types::stow_error!(
                    "no MSVC C toolchain for {target} is installed on this builder: \
                     cl.exe was not found; its C sources would be compiled by the \
                     host's compiler"
                )
            })?;
            let lib = find_msvc_tools::find_tool(target, "lib.exe").ok_or_else(|| {
                stow_types::stow_error!(
                    "no MSVC C toolchain for {target} is installed on this builder: \
                     lib.exe was not found; its C sources would be compiled by the \
                     host's compiler"
                )
            })?;
            let (cl_path, lib_path) = (cl.path(), lib.path());
            toolchain.env.push((
                cc_target_var("CC", target).into(),
                cl_path.as_os_str().to_owned(),
            ));
            toolchain.env.push((
                cc_target_var("CXX", target).into(),
                cl_path.as_os_str().to_owned(),
            ));
            toolchain.env.push((
                cc_target_var("AR", target).into(),
                lib_path.as_os_str().to_owned(),
            ));

            let compiler_dir = cl_path.parent().map(Path::to_path_buf);
            // One PATH entry: the host lookup's composed value, or this
            // process's own when it came back empty. The compiler's
            // directory goes last so a `link.exe` or `cl.exe` lookup by
            // name still resolves to the host's, and is skipped entirely
            // when it is the host's own bin directory — a native x64
            // task.
            let mut dirs: Vec<PathBuf> = match toolchain
                .env
                .iter()
                .find(|(key, _)| env_name::eq(key, "PATH"))
            {
                Some((_, value)) => std::env::split_paths(value).collect(),
                None => std::env::var_os("PATH")
                    .map(|value| std::env::split_paths(&value).collect())
                    .unwrap_or_default(),
            };
            if let Some(dir) = &compiler_dir
                && toolchain.bin_dir.as_ref() != Some(dir)
            {
                dirs.push(dir.clone());
            }
            let path = std::env::join_paths(&dirs).map_err(|error| {
                stow_types::stow_error!("compose the sandbox PATH for {target}: {error}")
            })?;
            match toolchain
                .env
                .iter_mut()
                .find(|(key, _)| env_name::eq(key, "PATH"))
            {
                Some((_, value)) => *value = path,
                None => toolchain.env.push(("PATH".into(), path)),
            }
            toolchain.compiler_dir = compiler_dir;
        }
        Ok(toolchain)
    }

    // The signature is the Windows one's so call sites compile the same
    // on either platform.
    #[allow(clippy::unnecessary_wraps)]
    #[cfg(not(windows))]
    pub fn resolve(_target: &str) -> stow_types::error::Result<Self> {
        Ok(Self::default())
    }

    /// Directories the sandbox must reach: the linker's own, the target
    /// compiler's, and every library or include directory it searches.
    fn grants(&self) -> Vec<(PathBuf, Access, &'static str)> {
        let mut grants = Vec::new();
        if let Some(bin_dir) = self.bin_dir.clone() {
            grants.push((
                bin_dir,
                Access::READ | Access::EXEC,
                "the MSVC linker and the DLLs it loads from its own directory",
            ));
        }
        if let Some(compiler_dir) = self.compiler_dir.clone()
            && self.bin_dir.as_ref() != Some(&compiler_dir)
        {
            grants.push((
                compiler_dir,
                Access::READ | Access::EXEC,
                "the MSVC compiler and archiver for the task's target",
            ));
        }
        for (key, value) in &self.env {
            if key != "LIB" && key != "INCLUDE" {
                continue;
            }
            for dir in std::env::split_paths(value).filter(|dir| dir.is_dir()) {
                grants.push((
                    dir,
                    Access::READ,
                    "a CRT or Windows SDK directory the MSVC linker searches",
                ));
            }
        }
        grants
    }
}

/// The `cc` crate's per-target environment variable spelling:
/// `CC_aarch64_pc_windows_msvc` for `aarch64-pc-windows-msvc`.
#[cfg(windows)]
fn cc_target_var(prefix: &str, target: &str) -> String {
    format!("{prefix}_{}", target.replace('-', "_"))
}

/// The directory PATH resolves `name` from, if any.
///
/// Windows spells an executable with its extension, so a bare `cargo`
/// matches nothing there; the `.exe` form is tried as well rather than
/// leaving every Windows lookup silently empty.
fn resolve_on_path(name: &str) -> Option<PathBuf> {
    let mut candidates = vec![name.to_owned()];
    if cfg!(windows) && !name.contains('.') {
        candidates.push(format!("{name}.exe"));
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .flat_map(|dir| {
            candidates
                .iter()
                .map(move |candidate| dir.join(candidate))
                .collect::<Vec<_>>()
        })
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| candidate.parent().map(Path::to_path_buf))
}

/// A sandboxed env var is a string; a non-UTF-8 one is a hard error, not a
/// lossy conversion that would hand the linker a path it cannot open.
fn os_str_arg(value: &std::ffi::OsStr) -> stow_types::error::Result<&str> {
    value
        .to_str()
        .ok_or_else(|| stow_types::stow_error!("environment value {value:?} is not UTF-8"))
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

/// The link option a linux-gnu task's units link with: mold, pinned by
/// the builder rather than observed from whatever linker the runner image
/// ships. The compile key records it, and the workflow installs mold.
const PINNED_LINK_ARG_RUSTFLAGS: &str = "-C link-arg=-fuse-ld=mold";

/// The `RUSTFLAGS` of one cargo phase: the task's merged flags, the mold
/// pin on a linux-gnu task, and the remap of the phase's target dir to
/// the one virtual root.
///
/// The pin rides `RUSTFLAGS` because that is how a consumer gets it —
/// `stow setup` writes it into `target.'cfg(target_os = "linux")'.rustflags`
/// — and cargo places rustflags before the link arguments a build script
/// emits (`cargo:rustc-link-arg*`). Link arguments are keyed in argv
/// order, so a pin appended after the build script's arguments keyed such
/// a unit differently from every consumer (stow#1067). Cargo applies
/// `RUSTFLAGS` to host units only under a native invocation and to target
/// units only when `--target` is passed, which is exactly the reach a
/// consumer's target rustflags have, so no host unit of a cross-spelled
/// invocation is pinned on either side.
///
/// The target-dir remap also stays in the flags; units the flags do not
/// reach receive it from the capture wrapper (`STOW_BUILD_TARGET_DIR_REMAP`).
fn phase_rustflags(task_rustflags: &str, target: &str, target_dir: &Path) -> String {
    let pin = if target.ends_with("-linux-gnu") {
        format!(" {PINNED_LINK_ARG_RUSTFLAGS}")
    } else {
        String::new()
    };
    format!(
        "{task_rustflags}{pin} --remap-path-prefix={}={}",
        target_dir.display(),
        TARGET_DIR_VIRTUAL_ROOT
    )
}

pub fn merged_rustflags(remap_flag: &str) -> String {
    match std::env::var("RUSTFLAGS") {
        Ok(existing) if !existing.trim().is_empty() => format!("{existing} {remap_flag}"),
        _ => remap_flag.to_owned(),
    }
}

/// The task's feature selection split the way the wrapper manifest needs
/// it: whether default features stay on, and the explicit feature names
/// minus the `"default"` marker.
pub struct TaskFeatureSelection {
    pub no_default_features: bool,
    pub features: Vec<String>,
}

impl TaskFeatureSelection {
    pub fn from_task(task: &BuildTaskPayload) -> Self {
        Self::from_features_json(&task.features_json)
    }

    pub fn from_features_json(features_json: &stow_types::identity::FeaturesJson) -> Self {
        // `FeaturesJson` is already validated (sorted + deduplicated + valid
        // feature names) at deserialize time, so we can read the canonical
        // list directly instead of re-parsing.
        let mut features: Vec<String> = features_json.features().to_vec();
        let no_default_features = !features.iter().any(|feature| feature == "default");
        features.retain(|feature| feature != "default");
        Self {
            no_default_features,
            features,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CargoSubcommand {
    Build,
    Check,
    Test,
}

pub const fn cargo_phases(cargo_subcommand: CargoSubcommand) -> &'static [CargoSubcommand] {
    match cargo_subcommand {
        CargoSubcommand::Build => &[CargoSubcommand::Check, CargoSubcommand::Build],
        CargoSubcommand::Check => &[CargoSubcommand::Check],
        CargoSubcommand::Test => &[CargoSubcommand::Check, CargoSubcommand::Test],
    }
}

/// Each phase's `CARGO_TARGET_DIR`, named by phase so `check` outputs can
/// never alias `build` outputs — and by invocation, so a host-side task's
/// native and `--target` spellings keep separate unit graphs. Under the
/// run dir, not the workspace root: the sandbox working dir denies
/// `process-exec` on every backend, so anything compiled under it could
/// never run.
pub fn phase_target_dir(
    run_dir: &Path,
    phase: CargoSubcommand,
    invocation: CargoInvocation,
) -> PathBuf {
    let suffix = match invocation {
        CargoInvocation::Task => "",
        CargoInvocation::Native => "-native",
        CargoInvocation::Explicit => "-target",
    };
    run_dir.join(format!("target-{}{suffix}", phase.as_str()))
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
    // A mock-compile build answers as the target's runner, whatever
    // machine runs it (`mock_compile` has the why).
    #[cfg(feature = "mock-compile")]
    if crate::mock_compile::enabled() {
        return Ok(crate::mock_compile::runner_host(target)? == target);
    }
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

pub fn cargo_subcommand() -> stow_types::error::Result<CargoSubcommand> {
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

pub fn sibling_runtime_wrapper(capture_wrapper: &Path) -> stow_types::error::Result<PathBuf> {
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

/// Re-create, from the task payload alone, the generated wrapper package
/// the build job resolved the task crate in.
///
/// Resolving through the wrapper is not a detail of where the files sit —
/// it decides which packages cargo resolves. A crate resolved as the root
/// package unifies its own dev-dependencies' feature requests into the
/// normal graph, so a dev-dependency asking for `digest/dev` activates
/// `digest`'s optional `blobby` and the unit graphs carry a package the
/// build, which compiles the crate as somebody else's dependency, never
/// compiles.
/// Resolving the closure that way therefore demanded artifacts that could
/// not exist and failed the publish of `sha2`, `aes` and every other crate
/// whose dev-dependencies enable a feature of a normal one.
///
/// Nothing here trusts the build job: the tarball is downloaded again and
/// the wrapper manifest is generated from the task payload, exactly as
/// [`create_workspace`] generates it in the untrusted job.
pub async fn create_resolution_workspace(
    task: &BuildTaskPayload,
    root: &Path,
) -> stow_types::error::Result<PathBuf> {
    let archive = download_crate_archive(task).await?;
    let crate_name = task.crate_name.as_str().to_owned();
    let crate_version = task.version.to_string();
    let unpack_root = root.to_path_buf();
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
    let wrapper_root = root.join("wrapper");
    let (manifest_path, _) =
        write_wrapper_package(task, &wrapper_root, &crate_checksum, &source_root).await?;
    Ok(manifest_path)
}

pub fn unpack_crate_archive(
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

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use flate2::Compression;
    use tempfile::TempDir;

    use stow_types::api::{BuildTaskPayload, SubgraphNode, TaskSubgraph};
    use stow_types::identity::{
        CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
    };

    use super::{
        BuildWorkspace, CargoInvocation, CargoSubcommand, STOW_PROBE_FORBIDDEN_PATH_ENV,
        cargo_home, phase_invocations, phase_rustflags, phase_target_dir, pin_alias,
        sandbox_grants, targets_android, toolchain_env_names, toolchain_grant_dirs,
        unpack_crate_archive, verify_preserved_lockfile, wrapper_lockfile, wrapper_manifest,
    };

    /// The rustc argv cargo builds for a proc-macro unit: the base
    /// arguments, then the rustflags, then the link arguments the unit's
    /// build script emitted (`cargo:rustc-link-arg`). Cargo places them in
    /// this order whatever the flags are: the rustflags are added with the
    /// base arguments and the build script's outputs after the
    /// dependencies.
    fn linking_unit_argv(rustflags: &[&str], build_script_link_args: &[&str]) -> Vec<OsString> {
        let mut argv: Vec<String> = [
            "--crate-name",
            "serde_derive",
            "--edition=2021",
            "src/lib.rs",
            "--crate-type",
            "proc-macro",
            "--emit",
            "dep-info,link",
            "-C",
            "debuginfo=2",
            "-C",
            "metadata=a52ee596848c66ca",
            "-C",
            "extra-filename=-aa4980adf969014b",
            "--out-dir",
            "/out/deps",
            "-L",
            "dependency=/out/deps",
        ]
        .map(str::to_owned)
        .to_vec();
        argv.extend(rustflags.iter().map(|flag| (*flag).to_owned()));
        for arg in build_script_link_args {
            argv.extend(["-C".to_owned(), format!("link-arg={arg}")]);
        }
        argv.into_iter().map(OsString::from).collect()
    }

    fn linux_compile_key(argv: &[OsString]) -> String {
        let parsed = stow_types::rustc::ParsedRustcArgs::parse(argv).expect("parse argv");
        stow_types::public_cache::stable_unit_identity_for_package(
            &parsed,
            "serde_derive",
            "1.0.210",
            "x86_64-unknown-linux-gnu",
            "1.98.1",
            "[]",
            "[]",
        )
        .expect("identity")
        .compile_key
    }

    /// What `stow setup` writes into the consumer's
    /// `target.'cfg(target_os = "linux")'.rustflags`, before the stow
    /// CLI's wrapper appends the workspace remap.
    const CONSUMER_RUSTFLAGS: [&str; 2] = ["-C", "link-arg=-fuse-ld=mold"];

    /// stow#1067: a unit whose build script emits link arguments keys the
    /// same on the builder and on a consumer, because the builder's mold
    /// pin sits where the consumer's rustflags put it: ahead of the build
    /// script's arguments.
    #[test]
    fn a_build_script_link_arg_keys_the_same_on_the_builder_and_the_consumer() {
        let build_script = ["-Wl,--export-dynamic", "-Wl,-z,relro"];
        let phase = phase_rustflags("", "x86_64-unknown-linux-gnu", Path::new("/phase/target"));
        let builder_flags: Vec<&str> = phase.split_whitespace().collect();
        let builder = linking_unit_argv(&builder_flags, &build_script);
        let consumer = linking_unit_argv(&CONSUMER_RUSTFLAGS, &build_script);

        let parsed = |argv: &[OsString]| {
            stow_types::rustc::ParsedRustcArgs::parse(argv).expect("parse argv")
        };
        assert_eq!(
            parsed(&builder).link_options,
            [
                "link-arg=-fuse-ld=mold",
                "link-arg=-Wl,--export-dynamic",
                "link-arg=-Wl,-z,relro",
            ]
        );
        assert_eq!(
            parsed(&builder).link_options,
            parsed(&consumer).link_options
        );
        assert_eq!(linux_compile_key(&builder), linux_compile_key(&consumer));

        // The consumer's semantic lookup splits the argv into its own
        // options and the build script's and rebuilds the order from the
        // two; that order is the builder's argv order as well.
        let own = stow_types::upload_plan::BuildScriptInputs::from_directives(&[
            "cargo:rustc-link-arg=-Wl,--export-dynamic".to_owned(),
            "cargo:rustc-link-arg=-Wl,-z,relro".to_owned(),
        ]);
        let split = stow_types::upload_plan::ConsumerInputs::of(
            &parsed(&consumer),
            &own,
            "x86_64-unknown-linux-gnu",
        );
        assert_eq!(split.link_options, ["link-arg=-fuse-ld=mold"]);
        let mut rejoined = split.link_options;
        rejoined.extend(own.link_args);
        assert_eq!(rejoined, parsed(&builder).link_options);

        // The order the pin used to have, after the build script's
        // arguments, keys differently: the miss this change removes.
        let mut after = build_script.to_vec();
        after.push("-fuse-ld=mold");
        let old_builder = linking_unit_argv(&[], &after);
        assert_ne!(
            linux_compile_key(&old_builder),
            linux_compile_key(&consumer)
        );
    }

    /// A linking unit without build-script link arguments keeps the key it
    /// was published under, whichever side of the argv the pin sat on. The
    /// literal is the key published before the pin moved into `RUSTFLAGS`.
    #[test]
    fn a_linking_unit_without_build_script_link_args_keeps_its_published_key() {
        let phase = phase_rustflags("", "x86_64-unknown-linux-gnu", Path::new("/phase/target"));
        let builder_flags: Vec<&str> = phase.split_whitespace().collect();
        let key = linux_compile_key(&linking_unit_argv(&builder_flags, &[]));
        let previous = linux_compile_key(&linking_unit_argv(&[], &["-fuse-ld=mold"]));
        assert_eq!(key, previous);
        assert_eq!(
            key,
            "f2ca0f3dc52e71c1a855ac589c178463826917982b38da46fd269112e890229e"
        );
    }

    /// The pin is part of a linux-gnu task's flags and of no other
    /// task's, and the remap stays last.
    #[test]
    fn the_mold_pin_rides_the_rustflags_of_linux_gnu_tasks_only() {
        let dir = Path::new("/phase/target");
        assert_eq!(
            phase_rustflags("--cfg a", "aarch64-unknown-linux-gnu", dir),
            "--cfg a -C link-arg=-fuse-ld=mold --remap-path-prefix=/phase/target=stow-ci://target"
        );
        for target in [
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "aarch64-linux-android",
        ] {
            assert_eq!(
                phase_rustflags("--cfg a", target, dir),
                "--cfg a --remap-path-prefix=/phase/target=stow-ci://target"
            );
        }
    }

    #[test]
    fn unpack_crate_archive_keeps_the_bundled_lockfile() {
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
            "unpack must not delete the bundled Cargo.lock; preserve_lockfile reads it verbatim"
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
            host_side: false,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            dependency_subgraph: TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
        }
    }

    /// stow#817: a task with published dependencies that cannot read its
    /// slice fails with the slice error — building on would compile the
    /// closure the scheduler promised it would be served.
    #[test]
    fn a_task_whose_slice_cannot_be_read_fails_naming_the_slice() {
        let mut task = task_with_features(&[]);
        task.dependency_subgraph = TaskSubgraph {
            root_deps: vec![0],
            nodes: vec![SubgraphNode {
                crate_name: CrateName::parse("cfg-if").expect("crate name"),
                version: CrateVersion::new(semver::Version::new(1, 0, 4)),
                features_json: FeaturesJson::canonicalize(Vec::new()).expect("features"),
                host_side: false,
                keys_apart: false,
                deps: Vec::new(),
            }],
        };

        let error = smol::block_on(crate::consume::slices_for_task_with(&task, |_, _| {
            Box::pin(async {
                Err(stow_types::stow_error!(
                    "ftp://127.0.0.1 is not a supported registry scheme"
                ))
            })
        }))
        .expect_err("an unreadable slice fails the build");
        let text = format!("{error:#}");
        assert!(
            text.contains("index slice for aarch64-apple-darwin"),
            "names the slice: {text}"
        );
        assert!(text.contains("ftp"), "carries the underlying error: {text}");
    }

    /// A task with no dependency node has nothing published to consume,
    /// which the task itself says: no config, slice or registry is asked.
    #[test]
    fn a_task_without_dependencies_consumes_nothing() {
        let cache_dir = TempDir::new().expect("cache dir");
        let (store, path) = smol::block_on(super::stage_consumption_store(
            &task_with_features(&[]),
            &[],
        ))
        .expect("nothing to consume is not a failure");
        assert!(store.is_none() && path.is_none());
        assert!(
            std::fs::read_dir(cache_dir.path())
                .expect("cache dir")
                .next()
                .is_none(),
            "no slice was fetched"
        );
    }

    /// The release the ambient run toolchain's `rustc` reports — parsed
    /// from the same `rustc -vV` probe `verified_run_toolchain` runs.
    fn active_release() -> WireRustcVersion {
        let output = std::process::Command::new("rustc")
            .arg("-vV")
            .output()
            .expect("run rustc -vV");
        let verbose = String::from_utf8_lossy(&output.stdout);
        let release = verbose
            .lines()
            .find_map(|line| line.strip_prefix("release: "))
            .expect("rustc -vV reports a release");
        WireRustcVersion::parse(release).expect("active release parses")
    }

    /// The `host:` triple the ambient toolchain compiles for — the same
    /// `rustc -vV` probe `active_release` reads its release from.
    #[cfg(not(windows))]
    fn host_triple() -> String {
        let output = std::process::Command::new("rustc")
            .arg("-vV")
            .output()
            .expect("run rustc -vV");
        let verbose = String::from_utf8_lossy(&output.stdout);
        verbose
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .expect("rustc -vV reports a host triple")
            .to_owned()
    }

    /// A run toolchain whose `rustc -vV` release differs from the task's
    /// pinned `rustc_version` is refused by the once-per-task check —
    /// which both `build` and `closure::resolve` run before their first
    /// cargo invocation — naming the toolchain, its release, and the
    /// pinned version.
    #[test]
    fn a_mismatched_run_toolchain_is_refused_before_any_cargo() {
        let mut task = task_with_features(&[]);
        task.rustc_version = WireRustcVersion::parse("0.0.0").expect("mismatched version parses");
        let error = super::verified_run_toolchain(&task)
            .expect_err("a toolchain reporting a different release must be refused");
        let message = format!("{error}");
        assert!(
            message.contains(&super::run_toolchain(&task)),
            "the refusal must name the run toolchain: {message}"
        );
        assert!(
            message.contains("0.0.0"),
            "the refusal must name the pinned version: {message}"
        );
        assert!(
            message.contains(&format!("rustc {}", active_release().as_str())),
            "the refusal must name the reported release: {message}"
        );
    }

    /// The same check passes when the toolchain's release equals the
    /// task's pin, returning the name the phases put on `RUSTUP_TOOLCHAIN`.
    #[test]
    fn a_matching_run_toolchain_verifies_and_returns_its_name() {
        let mut task = task_with_features(&[]);
        task.rustc_version = active_release();
        let toolchain = super::verified_run_toolchain(&task)
            .expect("a toolchain reporting the pinned release verifies");
        assert_eq!(toolchain, super::run_toolchain(&task));
    }

    /// A subgraph carrying only the task's direct deps as leaves —
    /// enough to exercise the wrapper manifest's pin section/alias
    /// rules; the build-stage checks a full subgraph against the
    /// toolchain's own unit graph instead.
    fn leaf_pins(nodes: Vec<SubgraphNode>) -> TaskSubgraph {
        TaskSubgraph {
            root_deps: (0..nodes.len())
                .map(|index| u32::try_from(index).expect("test node count fits u32"))
                .collect(),
            nodes,
        }
    }

    fn dependency<'a>(manifest: &'a toml::Table, name: &str) -> &'a toml::Table {
        manifest["dependencies"][name]
            .as_table()
            .expect("dependency entry is a table")
    }

    #[test]
    fn wrapper_manifest_keeps_default_features_when_task_lists_default() {
        let task = task_with_features(&["default", "std"]);
        let manifest: toml::Table =
            toml::from_str(&wrapper_manifest(&task).expect("wrapper manifest"))
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
    fn wrapper_manifest_declares_a_host_side_task_as_a_build_dependency() {
        let mut task = task_with_features(&["std"]);
        task.host_side = true;
        let manifest: toml::Table =
            toml::from_str(&wrapper_manifest(&task).expect("wrapper manifest"))
                .expect("generated manifest parses");

        assert!(
            manifest["dependencies"]
                .as_table()
                .is_none_or(toml::map::Map::is_empty),
            "a host-side task declares no normal dependency"
        );
        let build_dependency = manifest["build-dependencies"]["itoa"]
            .as_table()
            .expect("the task crate is the wrapper's build-dependency");
        assert_eq!(
            build_dependency["version"].as_str(),
            Some("=1.0.15"),
            "the build-dependency pins the exact task version"
        );
        assert_eq!(
            build_dependency["features"].as_array().map(Vec::as_slice),
            Some([toml::Value::String("std".to_owned())].as_slice()),
        );
        assert_eq!(build_dependency["default-features"].as_bool(), Some(false),);
    }

    /// stow#431: without the scheduler's dep pins the wrapper's own
    /// resolution can land on a narrower feature set than the dep task
    /// published — cargo compiles the dep under a key nobody published
    /// and `dep_scan` fails the build. Each pin is an exact `=` version
    /// with the dep's published feature set, in the section matching the
    /// side its consumers compile it on.
    #[test]
    fn wrapper_manifest_pins_task_dependencies_to_their_published_identities() {
        let mut task = task_with_features(&["derive"]);
        task.dependency_subgraph = leaf_pins(vec![
            SubgraphNode {
                crate_name: CrateName::parse("serde_core").expect("crate name"),
                version: CrateVersion::new(semver::Version::parse("1.0.228").expect("version")),
                features_json: FeaturesJson::canonicalize(vec![
                    "alloc".to_owned(),
                    "std".to_owned(),
                ])
                .expect("features"),
                host_side: false,
                keys_apart: false,
                deps: Vec::new(),
            },
            SubgraphNode {
                crate_name: CrateName::parse("syn").expect("crate name"),
                version: CrateVersion::new(semver::Version::parse("2.0.106").expect("version")),
                features_json: FeaturesJson::canonicalize(vec!["default".to_owned()])
                    .expect("features"),
                host_side: true,
                keys_apart: false,
                deps: Vec::new(),
            },
        ]);
        let manifest: toml::Table =
            toml::from_str(&wrapper_manifest(&task).expect("wrapper manifest"))
                .expect("generated manifest parses");

        let dep = dependency(&manifest, "serde_core-v1_0_228");
        assert_eq!(dep["version"].as_str(), Some("=1.0.228"));
        assert_eq!(
            dep["package"].as_str(),
            Some("serde_core"),
            "an aliased pin names its real package"
        );
        assert_eq!(
            dep["features"].as_array().map(Vec::as_slice),
            Some(
                [
                    toml::Value::String("alloc".to_owned()),
                    toml::Value::String("std".to_owned())
                ]
                .as_slice()
            ),
            "the dep's published feature set is pinned verbatim"
        );
        assert_eq!(dep["default-features"].as_bool(), Some(false));

        let host_dep = manifest["build-dependencies"]["syn-v2_0_106"]
            .as_table()
            .expect("a host-side dep pin lands in build-dependencies");
        assert_eq!(host_dep["version"].as_str(), Some("=2.0.106"));
        assert_eq!(host_dep["package"].as_str(), Some("syn"));
        assert!(
            host_dep.get("features").is_none() && host_dep.get("default-features").is_none(),
            "a pin whose set is [\"default\"] resolves to cargo defaults: {host_dep:?}"
        );
        assert!(
            manifest["dependencies"].get("syn-v2_0_106").is_none(),
            "a host-side pin never lands in the target-side section"
        );
    }

    /// A pinned version with build metadata keys under a name cargo
    /// accepts: the `+` left in the alias failed `cargo fetch` for every
    /// task above `toml_datetime 1.1.2+spec-1.1.0` (stow#689).
    #[test]
    fn wrapper_manifest_pins_a_version_with_build_metadata_under_a_valid_alias() {
        let mut task = task_with_features(&["derive"]);
        task.dependency_subgraph = leaf_pins(vec![SubgraphNode {
            crate_name: CrateName::parse("toml_datetime").expect("crate name"),
            version: CrateVersion::new(
                semver::Version::parse("1.1.2+spec-1.1.0").expect("version"),
            ),
            features_json: FeaturesJson::canonicalize(vec!["default".to_owned()])
                .expect("features"),
            host_side: false,
            keys_apart: false,
            deps: Vec::new(),
        }]);
        let manifest: toml::Table =
            toml::from_str(&wrapper_manifest(&task).expect("wrapper manifest"))
                .expect("generated manifest parses");

        let deps = manifest["dependencies"]
            .as_table()
            .expect("dependencies table");
        let pin = &deps["toml_datetime-v1_1_2__spec-1_1_0"];
        assert_eq!(pin["version"].as_str(), Some("=1.1.2+spec-1.1.0"));
        assert_eq!(pin["package"].as_str(), Some("toml_datetime"));
        for name in deps.keys() {
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "cargo rejects the dependency name {name}"
            );
        }
    }

    /// Versions that differ only in where the pre-release ends and the
    /// build metadata begins keep distinct aliases.
    #[test]
    fn pin_aliases_of_distinct_versions_differ() {
        assert_ne!(pin_alias("a", "1.0.0-x.y"), pin_alias("a", "1.0.0-x+y"),);
        assert_eq!(pin_alias("syn", "2.0.106"), "syn-v2_0_106");
    }

    /// Two semver-incompatible versions of one crate in a closure — and a
    /// pin at the task crate's own name — must all survive the generated
    /// manifest: a crate-name key keeps only the last insert (stow#431).
    #[test]
    fn wrapper_manifest_keeps_duplicate_crate_names_under_distinct_aliases() {
        let mut task = task_with_features(&["derive"]);
        let pin = |version: &str, host_side: bool| SubgraphNode {
            crate_name: CrateName::parse("syn").expect("crate name"),
            version: CrateVersion::new(semver::Version::parse(version).expect("version")),
            features_json: FeaturesJson::canonicalize(vec!["default".to_owned()])
                .expect("features"),
            host_side,
            keys_apart: false,
            deps: Vec::new(),
        };
        task.dependency_subgraph = leaf_pins(vec![
            pin("1.0.109", false),
            pin("2.0.106", false),
            SubgraphNode {
                crate_name: task.crate_name.clone(),
                version: CrateVersion::new(semver::Version::parse("9.9.9").expect("version")),
                features_json: FeaturesJson::canonicalize(Vec::new()).expect("features"),
                host_side: false,
                keys_apart: false,
                deps: Vec::new(),
            },
        ]);
        let manifest: toml::Table =
            toml::from_str(&wrapper_manifest(&task).expect("wrapper manifest"))
                .expect("generated manifest parses");

        let deps = manifest["dependencies"]
            .as_table()
            .expect("dependencies table");
        for (alias, version) in [
            ("syn-v1_0_109", "=1.0.109"),
            ("syn-v2_0_106", "=2.0.106"),
            ("itoa-v9_9_9", "=9.9.9"),
        ] {
            let dep = deps
                .get(alias)
                .and_then(toml::Value::as_table)
                .unwrap_or_else(|| panic!("pin {alias} must survive in the manifest"));
            assert_eq!(dep["version"].as_str(), Some(version));
        }
        assert_eq!(
            deps["itoa-v9_9_9"]["package"].as_str(),
            Some("itoa"),
            "the same-name pin points at the task crate's package"
        );
        assert_eq!(
            deps["itoa"]["version"].as_str(),
            Some("=1.0.15"),
            "the task crate's own declaration is untouched"
        );
    }

    /// stow#723: an outcome-3 host task pins its own target twin. Cargo
    /// rejects one package declared under two names across dependency
    /// kinds, so the twin's `[dependencies]` pin keys on the task entry's
    /// own `[build-dependencies]` name.
    #[test]
    fn wrapper_manifest_pins_the_self_twin_under_the_task_crate_name() {
        let mut task = task_with_features(&["std"]);
        task.host_side = true;
        task.dependency_subgraph = leaf_pins(vec![SubgraphNode {
            crate_name: task.crate_name.clone(),
            version: task.version.clone(),
            features_json: task.features_json.clone(),
            host_side: false,
            keys_apart: false,
            deps: Vec::new(),
        }]);
        let manifest: toml::Table =
            toml::from_str(&wrapper_manifest(&task).expect("wrapper manifest"))
                .expect("generated manifest parses");
        assert_eq!(
            manifest["build-dependencies"]["itoa"]["version"].as_str(),
            Some("=1.0.15"),
            "the task crate is the wrapper's build-dependency"
        );
        let twin = manifest["dependencies"]["itoa"]
            .as_table()
            .expect("the target twin pins under the task crate's own name");
        assert_eq!(twin["version"].as_str(), Some("=1.0.15"));
        assert_eq!(twin["package"].as_str(), Some("itoa"));
        assert!(
            manifest["dependencies"]
                .as_table()
                .is_some_and(|deps| deps.len() == 1),
            "no aliased second name for the task's own package"
        );
    }

    #[test]
    fn host_side_task_runs_each_phase_under_both_invocations() {
        let mut task = task_with_features(&["std"]);
        task.host_side = true;
        let invocations = phase_invocations(&task);
        assert_eq!(
            invocations.len(),
            2,
            "a host-side task produces the host units of both invocation spellings"
        );
        assert!(matches!(invocations[0], CargoInvocation::Native));
        assert!(matches!(invocations[1], CargoInvocation::Explicit));

        let task = task_with_features(&["std"]);
        assert_eq!(
            phase_invocations(&task).len(),
            1,
            "a target-side task keeps its single task-target invocation"
        );
    }

    /// stow#736: a `KeysApart` target-side task at the runner's host
    /// triple runs and publishes both spellings like a host-side task;
    /// `KeysApart` at a cross target — whose own spelling is already
    /// explicit — and `KeysAsNative` at the host triple keep `[Task]`.
    #[test]
    fn flagged_target_side_task_at_host_triple_runs_both_invocations() {
        let mut task = task_with_features(&["std"]);
        task.target = TargetTriple::parse("x86_64-unknown-linux-gnu").expect("target");
        task.explicit_spelling = stow_types::public_cache::ExplicitSpelling::KeysApart;
        let invocations = phase_invocations(&task);
        assert_eq!(invocations.len(), 2);
        assert!(matches!(invocations[0], CargoInvocation::Native));
        assert!(matches!(invocations[1], CargoInvocation::Explicit));

        let mut cross = task_with_features(&["std"]);
        cross.target = TargetTriple::parse("wasm32-unknown-unknown").expect("target");
        cross.explicit_spelling = stow_types::public_cache::ExplicitSpelling::KeysApart;
        assert_eq!(
            phase_invocations(&cross).len(),
            1,
            "a cross target's task spelling is already the explicit one"
        );
    }

    #[test]
    fn host_side_phase_target_dirs_separate_the_invocations() {
        let run_dir = PathBuf::from("/tmp/run");
        assert_eq!(
            phase_target_dir(&run_dir, CargoSubcommand::Build, CargoInvocation::Native),
            run_dir.join("target-build-native")
        );
        assert_eq!(
            phase_target_dir(&run_dir, CargoSubcommand::Build, CargoInvocation::Explicit),
            run_dir.join("target-build-target")
        );
        assert_eq!(
            phase_target_dir(&run_dir, CargoSubcommand::Check, CargoInvocation::Task),
            run_dir.join("target-check")
        );
    }

    #[test]
    fn wrapper_manifest_disables_default_features_when_task_omits_default() {
        let task = task_with_features(&["std"]);
        let manifest: toml::Table =
            toml::from_str(&wrapper_manifest(&task).expect("wrapper manifest"))
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
    fn wrapper_lockfile_pins_task_crate_as_a_registry_package() {
        let task = task_with_features(&["default"]);
        let lockfile: toml::Table =
            toml::from_str(&wrapper_lockfile(&task, &"ab".repeat(32), None).expect("seed lock"))
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

        let wrapper = lockfile_package(&lockfile, "stow-ci-wrapper").expect("wrapper root entry");
        assert_eq!(
            wrapper["dependencies"].as_array().map(Vec::as_slice),
            Some(
                [toml::Value::String(
                    "itoa 1.0.15 (registry+https://github.com/rust-lang/crates.io-index)"
                        .to_owned(),
                )]
                .as_slice()
            ),
            "the wrapper root names the task crate by its qualified registry identity"
        );
    }

    #[test]
    fn wrapper_lockfile_merges_the_bundled_lockfile() {
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
            &wrapper_lockfile(&task, &"ab".repeat(32), Some(bundled)).expect("seed"),
        )
        .expect("merged seed parses");

        // The bundled source-less root entry for the task crate is rewritten
        // as the registry package it becomes in the wrapper graph.
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
        // included; cargo prunes what the wrapper graph cannot reach.
        assert_eq!(
            lockfile_package(&lockfile, "serde").expect("serde")["checksum"].as_str(),
            Some("11")
        );
        assert_eq!(
            lockfile_package(&lockfile, "dev-dep").expect("dev-dep")["checksum"].as_str(),
            Some("22")
        );
        assert!(lockfile_package(&lockfile, "stow-ci-wrapper").is_some());
    }

    #[test]
    fn verify_preserved_lockfile_accepts_a_pruned_wrapper_resolution() {
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
        // gains its registry source+checksum, and the wrapper root lands.
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
name = "stow-ci-wrapper"
version = "0.0.0"
dependencies = ["itoa"]
"#;
        verify_preserved_lockfile(bundled, resolved, &task)
            .expect("a pruned wrapper resolution preserves every bundled pin");
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

    /// A crate with a build script must compile inside the phase sandbox.
    ///
    /// One sandboxed `cargo build` over the probe crate rooted at `root` —
    /// the same shape `run_sandboxed_phase` drives, minus the capture
    /// drain. `extra_env` lands on the command after `msvc`'s entries.
    async fn cargo_build_probe(
        root: &Path,
        target_dir: &Path,
        msvc: &super::MsvcToolchain,
        target: &str,
        extra_env: &[(String, String)],
        cargo_home: &Path,
    ) {
        let capture_dir = root.join(".stow-rustc-capture");
        std::fs::create_dir_all(&capture_dir).expect("capture dir");
        let tools_dir = TempDir::new().expect("tools dir");
        let workspace = BuildWorkspace {
            _tempdir: None,
            manifest_path: root.join("Cargo.toml"),
            workspace_root: root.to_path_buf(),
            capture_dir,
            bundled_lockfile: None,
        };
        let exe = std::env::consts::EXE_SUFFIX;
        let wrappers = stow_shim::WrapperShimPaths {
            rustc_wrapper: tools_dir.path().join(format!("stow-rustc-wrapper{exe}")),
            cc_launcher: tools_dir.path().join(format!("stow-cc-launcher{exe}")),
            cc_compiler: tools_dir.path().join(format!("stow-cc{exe}")),
            cxx_compiler: tools_dir.path().join(format!("stow-cxx{exe}")),
        };
        let wrapper = std::env::current_exe().expect("current exe");
        let (_collector, capture_command) = crate::capture::CaptureCollector::channel();
        let audit_log =
            heel::NetworkAuditLog::file(root.join("network-audit.jsonl")).expect("audit log");
        let setup = super::PhaseSetup {
            workspace: &workspace,
            cargo_home,
            wrappers: &wrappers,
            runtime_wrapper: &wrapper,
            capture_wrapper: &wrapper,
            capture_command: &capture_command,
            audit_log: &audit_log,
            rustflags: "",
            target,
            consume_store: None,
        };
        let sandbox = super::phase_sandbox(&setup, target_dir, msvc)
            .await
            .expect("phase sandbox");

        let mut command = sandbox
            .command("cargo")
            .args(["build", "--offline", "--quiet"])
            // The phase command pins both, and cargo then ignores what
            // the cargo home configures for them. With no shim to name,
            // the empty wrapper is cargo's spelling of "none".
            .env("RUSTFLAGS", setup.rustflags)
            .env("RUSTC_WRAPPER", "")
            .env(
                "CARGO_TARGET_DIR",
                super::path_arg(target_dir).expect("utf8 target dir"),
            )
            .env(
                "CARGO_HOME",
                super::path_arg(cargo_home).expect("utf8 cargo home"),
            )
            .env(
                "RUSTUP_HOME",
                super::path_arg(&super::rustup_home().expect("rustup home"))
                    .expect("utf8 rustup home"),
            )
            .current_dir(root);
        for (key, value) in &msvc.env {
            command = command.env(
                super::os_str_arg(key).expect("utf8 env key"),
                super::os_str_arg(value).expect("utf8 env value"),
            );
        }
        for (key, value) in extra_env {
            command = command.env(key, value);
        }
        let output = command.output().await.expect("sandboxed cargo build");
        assert!(
            output.status.success(),
            "cargo build failed inside the sandbox:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// A build script is a host binary, so compiling one runs the linker
    /// inside the sandbox. Windows checks the same thing in
    /// `the_target_c_compiler_runs_inside_the_phase_sandbox`, whose
    /// build script does this and more: a sandbox of its own would
    /// grant the machine's toolchain trees to one more container, and
    /// that takes minutes there.
    #[cfg(not(windows))]
    #[test]
    fn a_build_script_compiles_inside_the_phase_sandbox() {
        smol::block_on(async {
            let workspace_root = TempDir::new().expect("workspace root");
            let root = workspace_root.path();
            std::fs::create_dir_all(root.join("src")).expect("src dir");
            std::fs::write(
                root.join("Cargo.toml"),
                "[package]\nname = \"stow-sandbox-probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\n",
            )
            .expect("write manifest");
            std::fs::write(root.join("src/lib.rs"), "pub fn probe() {}\n").expect("write lib");
            // The whole point: cargo compiles and runs this as a host
            // executable, which is the step that needs a working linker.
            std::fs::write(
                root.join("build.rs"),
                "fn main() { println!(\"cargo::rustc-check-cfg=cfg(probe)\"); }\n",
            )
            .expect("write build script");

            let target_dir = TempDir::new().expect("target dir");
            let host = host_triple();
            let msvc = super::MsvcToolchain::resolve(&host).expect("MSVC toolchain");
            let cargo_home = cargo_home().expect("cargo home");
            cargo_build_probe(root, target_dir.path(), &msvc, &host, &[], &cargo_home).await;
        });
    }

    /// Two shapes that broke on Windows, in one build. A build script is
    /// a host binary, so compiling one runs the linker, and the sandboxed
    /// rustc could not find MSVC's. It picked up Git for Windows' msys
    /// `link` instead, which cannot start inside an `AppContainer` at
    /// all — every Windows build of every crate carrying a build script
    /// or a proc macro failed, and nothing in the test suite noticed
    /// because the only sandbox test was Unix-only.
    ///
    /// stow#708 is the half the linker fix does not reach: inside the
    /// sandbox the `cc` crate's own MSVC lookup comes up empty the same
    /// way rustc's does, and a build script that compiles C for the
    /// task's target then falls back to the first `cl.exe` on PATH —
    /// the host's. `MsvcToolchain` answers by naming the target's own
    /// compiler in `CC_<target>`; the probe uses exactly that variable,
    /// the way `cc` resolves it, and the object it leaves behind must be
    /// an ARM64 COFF (`IMAGE_FILE_MACHINE_ARM64`, `0xAA64`
    /// little-endian).
    #[cfg(windows)]
    #[test]
    fn the_target_c_compiler_runs_inside_the_phase_sandbox() {
        smol::block_on(async {
            let workspace_root = TempDir::new().expect("workspace root");
            let root = workspace_root.path();
            std::fs::create_dir_all(root.join("src")).expect("src dir");
            std::fs::write(
                root.join("Cargo.toml"),
                "[package]\nname = \"stow-sandbox-probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\n",
            )
            .expect("write manifest");
            std::fs::write(root.join("src/lib.rs"), "pub fn probe() {}\n").expect("write lib");
            std::fs::write(
                root.join("probe.c"),
                "#include <stdint.h>\n#include <string.h>\nuint32_t probe(const char *s) { return (uint32_t)strlen(s); }\n",
            )
            .expect("write probe.c");
            // The build script takes the compiler the toolchain env
            // names — `cc` reads `CC_<target>` the same way — compiles
            // the probe with it, and parks the object where the test can
            // check what machine it was built for.
            std::fs::write(
                root.join("build.rs"),
                r#"fn main() {
    let compiler = std::env::var("CC_aarch64_pc_windows_msvc")
        .expect("CC_aarch64_pc_windows_msvc is not set");
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is not set");
    let object = std::path::Path::new(&out_dir).join("probe.obj");
    let output = std::process::Command::new(&compiler)
        .args(["/nologo", "/c", "probe.c"])
        .arg(format!("/Fo{}", object.display()))
        .output()
        .unwrap_or_else(|error| panic!("run {compiler}: {error}"));
    assert!(
        output.status.success(),
        "{compiler} failed:\nstderr: {}\nstdout: {}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
    );
    let probe = std::env::var("STOW_PROBE_OBJECT").expect("STOW_PROBE_OBJECT is not set");
    std::fs::copy(&object, &probe).expect("copy the probe object");
}
"#,
            )
            .expect("write build script");

            let target_dir = TempDir::new().expect("target dir");
            let probe_object = target_dir.path().join("probe.obj");
            let msvc = super::MsvcToolchain::resolve("aarch64-pc-windows-msvc")
                .expect("resolve the arm64 MSVC toolchain");
            let cargo_home = cargo_home().expect("cargo home");
            cargo_build_probe(
                root,
                target_dir.path(),
                &msvc,
                "aarch64-pc-windows-msvc",
                &[(
                    "STOW_PROBE_OBJECT".to_owned(),
                    super::path_arg(&probe_object).expect("utf8 probe path"),
                )],
                &cargo_home,
            )
            .await;
            let bytes = std::fs::read(&probe_object).expect("read the probe object");
            assert!(
                bytes.len() >= 2 && bytes[..2] == [0x64, 0xAA],
                "probe.obj must be an ARM64 COFF object; its first bytes are {bytes:02x?}"
            );
        });
    }

    /// The sandbox starts with no environment, so a sandboxed `env` may
    /// print only the names the builder passes through — `PATH`, the
    /// probe hook, the toolchain set for the task's target — and what
    /// heel itself injects: its IPC endpoint, the temp dir it points at
    /// the working directory, and the proxy config it forwards when
    /// network access is on.
    #[cfg(unix)]
    fn assert_sandbox_env_is_isolated(env_text: &str, target: &str) {
        let mut allowed: std::collections::BTreeSet<String> = [
            "PATH",
            STOW_PROBE_FORBIDDEN_PATH_ENV,
            "HEEL_IPC_ENDPOINT",
            "TMPDIR",
            "TEMP",
            "TMP",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ]
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
        allowed.extend(toolchain_env_names(
            target,
            std::env::vars_os().filter_map(|(name, _)| name.into_string().ok()),
        ));
        let leaked: Vec<String> = env_text
            .lines()
            .filter_map(|line| line.split('=').next())
            .filter(|name| !name.is_empty() && !allowed.contains(*name))
            .map(str::to_owned)
            .collect();
        assert!(
            leaked.is_empty() && env_text.lines().any(|line| line.starts_with("PATH=")),
            "sandboxed process saw the parent environment ({leaked:?}):\n{env_text}"
        );
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
            let workspace_root = TempDir::new().expect("workspace root");
            let target_dir = TempDir::new().expect("target dir");
            let tools_dir = TempDir::new().expect("tools dir");

            let workspace = BuildWorkspace {
                _tempdir: None,
                manifest_path: workspace_root.path().join("Cargo.toml"),
                workspace_root: workspace_root.path().to_path_buf(),
                capture_dir: workspace_root.path().join(".stow-rustc-capture"),
                bundled_lockfile: None,
            };
            std::fs::create_dir_all(workspace.capture_dir()).expect("capture dir");
            let exe = std::env::consts::EXE_SUFFIX;
            let wrappers = stow_shim::WrapperShimPaths {
                rustc_wrapper: tools_dir.path().join(format!("stow-rustc-wrapper{exe}")),
                cc_launcher: tools_dir.path().join(format!("stow-cc-launcher{exe}")),
                cc_compiler: tools_dir.path().join(format!("stow-cc{exe}")),
                cxx_compiler: tools_dir.path().join(format!("stow-cxx{exe}")),
            };
            let wrapper = std::env::current_exe().expect("current exe");

            // The cargo caches the host-side phase 0 `cargo fetch` populates
            // — the registry, and the git dependency database and checkouts —
            // must reach the sandboxed phases, read-only so a build script
            // cannot rewrite another crate's source.
            let cargo_home = cargo_home().expect("cargo home");
            let host = host_triple();
            let msvc = super::MsvcToolchain::resolve(&host).expect("MSVC toolchain");
            let grants = sandbox_grants(
                &cargo_home,
                &workspace,
                target_dir.path(),
                &wrappers,
                &wrapper,
                &msvc,
                None,
                &host,
            )
            .expect("sandbox grants");
            for dir in ["registry", "git"] {
                let grant = grants.iter().find(|(p, _, _)| *p == cargo_home.join(dir));
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

            let setup = super::PhaseSetup {
                workspace: &workspace,
                cargo_home: &cargo_home,
                wrappers: &wrappers,
                runtime_wrapper: &wrapper,
                capture_wrapper: &wrapper,
                capture_command: &capture_command,
                audit_log: &audit_log,
                rustflags: "",
                target: &host,
                consume_store: None,
            };
            let sandbox = super::phase_sandbox(&setup, target_dir.path(), &msvc)
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
            assert_sandbox_env_is_isolated(&String::from_utf8_lossy(&env_output.stdout), &host);

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
        });
    }

    /// A runner image exports the Android SDK/NDK roots whatever the job
    /// builds; their trees reach the grant set only when the task's target
    /// is Android — a Windows task must not pay the ACL rewrite of a tree
    /// it never reads (stow#718).
    #[test]
    fn an_android_root_is_granted_only_to_an_android_task() {
        let sdk = TempDir::new().expect("sdk dir");
        let ndk = TempDir::new().expect("ndk dir");
        let vars = || {
            [
                (
                    OsString::from("ANDROID_HOME"),
                    sdk.path().as_os_str().to_owned(),
                ),
                (
                    OsString::from("ANDROID_NDK_HOME"),
                    ndk.path().as_os_str().to_owned(),
                ),
            ]
            .into_iter()
        };

        assert!(
            toolchain_grant_dirs("x86_64-pc-windows-msvc", vars()).is_empty(),
            "a Windows task must not be granted the runner image's Android trees"
        );
        let dirs = toolchain_grant_dirs("aarch64-linux-android", vars());
        assert_eq!(dirs.len(), 2);
        for dir in [sdk.path(), ndk.path()] {
            assert!(
                dirs.contains(&dir.to_path_buf()),
                "an Android task must be granted {}",
                dir.display()
            );
        }
    }

    /// The same gate on the environment side: the Android variables pass
    /// into a sandboxed phase only when the task targets Android.
    #[test]
    fn an_android_variable_is_passed_only_to_an_android_task() {
        let names = || ["ANDROID_HOME", "ANDROID_NDK_LATEST_HOME"].map(str::to_owned);

        assert!(
            toolchain_env_names("x86_64-pc-windows-msvc", names().into_iter()).is_empty(),
            "a Windows task must not see the runner image's Android variables"
        );
        let passed = toolchain_env_names("aarch64-linux-android", names().into_iter());
        assert_eq!(passed, ["ANDROID_HOME", "ANDROID_NDK_LATEST_HOME"]);
    }

    /// The toolchain variables the build job exports for the task's own
    /// target are not Android-gated: `STOW_GLIBC_SYSROOT` and `SDKROOT`
    /// grant their trees to every task, a `CARGO_TARGET_<TRIPLE>_*`
    /// executable grants its parent directory, and `CC_<target>` passes
    /// through — while `CARGO_TARGET_DIR`, which the phases set
    /// themselves, never does.
    #[test]
    fn the_job_s_own_toolchain_variables_reach_every_task() {
        let sysroot = TempDir::new().expect("sysroot dir");
        let sdkroot = TempDir::new().expect("sdkroot dir");
        let syslibs = TempDir::new().expect("system-libs dir");
        let linker_dir = TempDir::new().expect("linker dir");
        let linker = linker_dir.path().join("aarch64-linux-gnu-ld");
        std::fs::write(&linker, b"#!/bin/sh\n").expect("linker file");

        let vars = || {
            [
                (
                    OsString::from("STOW_GLIBC_SYSROOT"),
                    sysroot.path().as_os_str().to_owned(),
                ),
                (
                    OsString::from("SDKROOT"),
                    sdkroot.path().as_os_str().to_owned(),
                ),
                (
                    OsString::from("STOW_SYSTEM_LIBS"),
                    syslibs.path().as_os_str().to_owned(),
                ),
                (
                    OsString::from("CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER"),
                    linker.as_os_str().to_owned(),
                ),
            ]
            .into_iter()
        };
        let dirs = toolchain_grant_dirs("x86_64-unknown-linux-gnu", vars());
        for dir in [
            sysroot.path(),
            sdkroot.path(),
            syslibs.path(),
            linker_dir.path(),
        ] {
            assert!(
                dirs.contains(&dir.to_path_buf()),
                "{} must be granted to a non-Android task",
                dir.display()
            );
        }

        let passed = toolchain_env_names(
            "aarch64-linux-android",
            ["CC_aarch64_linux_android".to_owned()].into_iter(),
        );
        assert_eq!(passed, ["CC_aarch64_linux_android"]);
        let passed = toolchain_env_names(
            "aarch64-unknown-linux-gnu",
            [
                "PKG_CONFIG_aarch64_unknown_linux_gnu".to_owned(),
                "PKG_CONFIG_PATH".to_owned(),
                "STOW_SYSTEM_LIBS".to_owned(),
                "CMAKE_PREFIX_PATH".to_owned(),
                "BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu".to_owned(),
            ]
            .into_iter(),
        );
        assert_eq!(
            passed,
            [
                "PKG_CONFIG_aarch64_unknown_linux_gnu",
                "PKG_CONFIG_PATH",
                "STOW_SYSTEM_LIBS",
                "CMAKE_PREFIX_PATH",
                "BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu",
            ]
        );
        for target in ["x86_64-unknown-linux-gnu", "aarch64-linux-android"] {
            assert!(
                toolchain_env_names(target, ["CARGO_TARGET_DIR".to_owned()].into_iter()).is_empty(),
                "CARGO_TARGET_DIR must never pass through ({target})"
            );
        }
    }

    /// `targets_android` reads the triple's operating-system component:
    /// Android triples end in `android`/`androideabi`, every other CI
    /// target does not.
    #[test]
    fn only_an_android_triple_targets_android() {
        for target in [
            "aarch64-linux-android",
            "armv7-linux-androideabi",
            "x86_64-linux-android",
            "i686-linux-android",
        ] {
            assert!(targets_android(target), "{target} must target Android");
        }
        for target in [
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-ios",
            "wasm32-unknown-unknown",
            "x86_64-pc-windows-msvc",
        ] {
            assert!(!targets_android(target), "{target} must not target Android");
        }
    }
}

//! `stow-build`: the trusted CI runner behind the `build-crate` workflow.
//!
//! The runner is two stages that never share a process, an environment, or
//! a credential:
//!
//! * `stow-build build` runs in a job with read-only permissions. It downloads
//!   the crate, compiles it with the capture wrapper, scans the outputs, plans
//!   the upload, and writes everything into an output directory (see
//!   [`stage`]). Third-party build scripts and proc-macros execute here, so
//!   nothing this job produces is trusted by itself.
//! * `stow-build publish` runs in a job that holds the GHCR token and the OIDC
//!   grant for cosign — and nothing else. It reads the build output,
//!   re-derives every digest, checks the plan against the task it was
//!   dispatched with and a dependency closure it resolves itself, then pushes
//!   and signs the artifacts and the task's records artifact into GHCR.
//!   Nothing in this binary ever calls the edge: completion reaches the
//!   scheduler through GitHub's `workflow_run` webhook instead
//!   (stow#455).
//!
//! `stow-build serve` is the dev-only local dispatch server, and
//! `stow-build rustc …` is the capture wrapper cargo invokes during `build`.

mod capture;
mod closure;
mod consume;
#[cfg(test)]
mod context_tests;
mod dep_scan;
mod local_server;
#[cfg(feature = "mock-compile")]
mod mock_compile;
mod object_arch;
mod plan;
mod rlib_members;
mod stage;
mod task;
mod validate;
mod workspace_mirror;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use stow_types::api::BuildTaskPayload;
use tracing_subscriber::EnvFilter;

const GITHUB_EVENT_PATH_ENV: &str = "GITHUB_EVENT_PATH";
const GITHUB_RUN_ID_ENV: &str = "GITHUB_RUN_ID";
const GITHUB_RUN_ATTEMPT_ENV: &str = "GITHUB_RUN_ATTEMPT";
const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
const STOW_MOCK_PRIVATE_KEY_PATH_ENV: &str = "STOW_MOCK_PRIVATE_KEY_PATH";
const STOW_MOCK_REGISTRY_ROOT_ENV: &str = "STOW_MOCK_REGISTRY_ROOT";
const STOW_GITHUB_WEBHOOK_SECRET_ENV: &str = "STOW_GITHUB_WEBHOOK_SECRET";
const GITHUB_APP_SLUG_ENV: &str = "GITHUB_APP_SLUG";
/// `mock_compile::STOW_BUILD_MOCK_COMPILE_ENV`, named here for the refusal
/// a build without the feature makes.
#[cfg(not(feature = "mock-compile"))]
const MOCK_COMPILE_ENV: &str = "STOW_BUILD_MOCK_COMPILE";

#[derive(Debug, Parser)]
#[command(name = "stow-build", about, version)]
struct Cli {
    #[command(subcommand)]
    command: Stage,
}

#[derive(Debug, Subcommand)]
enum Stage {
    /// Untrusted stage: compile the task's crate and write the build output.
    Build {
        /// Directory to write the build output into (created if missing).
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Trusted stage: validate a build output, then push, sign and publish
    /// its records artifact into GHCR.
    Publish {
        /// Directory a `build` stage wrote.
        #[arg(long)]
        input_dir: PathBuf,
    },
    /// Print `true` or `false` — whether the dispatched task's signed
    /// records already exist under its `built-<rustc>-<task_id hash>`
    /// marker (stow#877). `build-crate.yml` runs this before the
    /// untrusted stage so a duplicate dispatch exits without building.
    RecordsExist,
    /// Dev-only local dispatch server standing in for GitHub Actions.
    Serve {
        /// Socket address to listen on.
        #[arg(long)]
        listen: std::net::SocketAddr,
    },
}

fn main() -> stow_types::error::Result<()> {
    // reqwest's `rustls-no-provider` TLS path resolves
    // `CryptoProvider::get_default()`, which panics when no process-level
    // provider is installed — it has no crate-feature fallback like
    // `ClientConfig::builder()`. Install `ring` (the only provider in this
    // binary's rustls feature set) up front so provider selection is
    // deterministic regardless of which TLS path runs first.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| stow_types::error::Error::msg("install ring CryptoProvider"))?;
    install_tracing();
    let args = std::env::args_os().collect::<Vec<_>>();
    if capture::is_rustc_wrapper_invocation(&args) {
        return smol::block_on(capture::run_rustc_capture_wrapper(&args));
    }
    let cli = Cli::parse();
    match cli.command {
        Stage::Build { output_dir } => smol::block_on(build_stage(&output_dir)),
        // `RegistrySession` drives reqwest/hyper, which needs a Tokio
        // reactor; the build stage is smol-only because cargo/rustc
        // capture never touches HTTP.
        Stage::Publish { input_dir } => tokio_runtime()?.block_on(publish_stage(&input_dir)),
        Stage::RecordsExist => tokio_runtime()?.block_on(records_exist_stage()),
        Stage::Serve { listen } => tokio_runtime()?.block_on(serve_stage(listen)),
    }
}

fn tokio_runtime() -> stow_types::error::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| stow_types::stow_error!("build tokio runtime: {error}"))
}

async fn build_stage(output_dir: &std::path::Path) -> stow_types::error::Result<()> {
    // The mock compiler exists only in a `mock-compile` build; a switch
    // that reaches any other build must not quietly compile for real.
    #[cfg(not(feature = "mock-compile"))]
    if std::env::var_os(MOCK_COMPILE_ENV).is_some() {
        return Err(stow_types::stow_error!(
            "{MOCK_COMPILE_ENV} is set, but this stow-build was built without the \
             `mock-compile` feature"
        ));
    }
    let task = load_task_payload()?;
    async_fs::create_dir_all(output_dir).await?;
    let built = task::build(&task, output_dir).await?;
    let report = dep_scan::scan_artifacts(&built, &task).await?;
    let dependency_task_ids = task
        .verified_dependency_graph()?
        .dependency_task_ids(0)
        .ok_or_else(|| stow_types::stow_error!("verified dependency graph has no root node"))?;
    let upload_plan =
        plan::build_upload_plan(&report.artifacts, &report.consumed, &dependency_task_ids).await?;
    stage::write_build_output(output_dir, &task, &report, &upload_plan).await?;
    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        workspace_root = %built.workspace().workspace_root().display(),
        artifacts = report.artifacts.len(),
        upload_plan_entries = upload_plan.len(),
        "build stage completed"
    );
    Ok(())
}

async fn publish_stage(input_dir: &std::path::Path) -> stow_types::error::Result<()> {
    let task = load_task_payload()?;
    let pushed = publish(&task, input_dir).await.map_err(|error| {
        tracing::error!(task_id = %task.task_id, %error, "publish stage failed");
        error
    })?;
    tracing::info!(task_id = %task.task_id, pushed, "artifacts pushed");
    Ok(())
}

/// The `build-crate.yml` early-exit check: `true` on stdout when the
/// task's `built-<rustc>-<task_id hash>` marker names a records
/// manifest carrying the task-id annotation — the dispatch is a
/// duplicate and the run exits without building (stow#877).
async fn records_exist_stage() -> stow_types::error::Result<()> {
    let task = load_task_payload()?;
    let credentials = stow_oci::RegistryCredentials::from_env()?;
    let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    let exists = published_manifest(&task, &credentials, &http)
        .await?
        .is_some();
    println!("{exists}");
    Ok(())
}

/// The `built-` marker's manifest bytes when they name a records
/// artifact for `task` — `None` when no earlier run published it. The
/// bytes are the value a re-tag puts under the run's own records tag.
async fn published_manifest(
    task: &BuildTaskPayload,
    credentials: &stow_oci::RegistryCredentials,
    http: &stow_oci::RegistryHttp,
) -> stow_types::error::Result<Option<Vec<u8>>> {
    let repository = stow_types::registry::cache_repository(&task.rustc_version);
    let session =
        stow_oci::RegistryBase::production()?.push_session(&repository, credentials, http);
    let reference = session.reference(&stow_types::records::published_tag(
        task.rustc_version.as_str(),
        &task.task_id,
    ))?;
    let (manifest, manifest_digest) = match session.pull_manifest(&reference).await {
        Ok(pulled) => pulled,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => {
            return Err(stow_types::stow_error!(
                "pull published marker {reference}: {error}"
            ));
        }
    };
    let manifest_json: serde_json::Value = serde_json::from_slice(&manifest)
        .map_err(|error| stow_types::stow_error!("parse published marker manifest: {error}"))?;
    let is_records = manifest_json
        .get("artifactType")
        .and_then(serde_json::Value::as_str)
        == Some(stow_types::records::RECORDS_ARTIFACT_TYPE)
        && manifest_json
            .get("annotations")
            .and_then(|a| a.get(stow_types::records::RECORDS_TASK_ID_ANNOTATION))
            .and_then(serde_json::Value::as_str)
            == Some(task.task_id.as_str());
    if !is_records {
        return Err(stow_types::stow_error!(
            "published marker {reference} does not name a records artifact for {}",
            task.task_id
        ));
    }
    // Every reader verifies the signature before trusting a row: the
    // marker's manifest must carry a records signature bound to the
    // pinned builder identity — an unverifiable marker means build
    // normally (stow#877).
    if !marker_signature_verified(&session, &reference, &manifest_digest).await? {
        return Ok(None);
    }
    Ok(Some(manifest))
}

/// The `built-` marker's manifest verifies only when one signature
/// layer both checks out under the build trust *and* binds a
/// `records-` tag in this repository at this digest — tag aliases
/// share the manifest's digest, so the `sha256-<digest>.sig` bundle
/// indexes the signature the records push wrote, which names the
/// `records-` tag rather than the marker's own.
async fn marker_signature_verified(
    session: &stow_oci::RegistrySession,
    reference: &stow_oci::Reference,
    manifest_digest: &str,
) -> stow_types::error::Result<bool> {
    let trust = records_trust().await?;
    let Ok(materials) =
        stow_oci::pull_signature_materials(session, reference, manifest_digest).await
    else {
        return Ok(false);
    };
    let repository = format!("{}/{}", reference.registry(), reference.repository());
    Ok(materials.iter().any(|material| {
        let Some(bound) = stow_oci::verify::payload_docker_reference(&material.payload_bytes)
        else {
            return false;
        };
        let Some((bound_repo, bound_tag)) = bound.rsplit_once(':') else {
            return false;
        };
        if bound_repo != repository || !stow_types::records::is_records_tag(bound_tag) {
            return false;
        }
        let signature = stow_types::bundle::SigstoreSignature {
            payload_path: material.payload_path.clone(),
            signature: material.signature.clone(),
            certificate_pem: material.certificate_pem.clone(),
            rekor_bundle_json: material.rekor_bundle_json.clone(),
        };
        stow_oci::verify::verify_material(
            &trust,
            &bound,
            manifest_digest,
            &signature,
            &material.payload_bytes,
            stow_types::trusted_builder::CERTIFICATE_IDENTITY,
        )
        .is_ok()
    }))
}

/// The trust a records read verifies against — the mock registry's
/// local key under `STOW_MOCK_PUBLIC_KEY_PATH`, else Fulcio/Rekor with
/// the `build-crate.yml` certificate identity pinned.
async fn records_trust() -> stow_types::error::Result<stow_oci::verify::Trust> {
    #[cfg(feature = "mock-verify")]
    if let Ok(path) = std::env::var("STOW_MOCK_PUBLIC_KEY_PATH") {
        return Ok(stow_oci::verify::Trust::MockKey(path.into()));
    }
    #[cfg(not(feature = "mock-verify"))]
    if std::env::var_os("STOW_MOCK_PUBLIC_KEY_PATH").is_some() {
        return Err(stow_types::stow_error!(
            "STOW_MOCK_PUBLIC_KEY_PATH set but stow-build lacks mock-verify"
        ));
    }
    let cache_dir = std::env::var_os("STOW_CACHE_DIR")
        .map_or_else(
            || {
                std::env::var_os("HOME")
                    .map(|home| std::path::PathBuf::from(home).join(".cache").join("stow"))
            },
            |dir| Some(dir.into()),
        )
        .ok_or_else(|| stow_types::stow_error!("resolve the sigstore trust cache directory"))?;
    Ok(stow_oci::verify::Trust::GithubCi(std::sync::Arc::new(
        stow_oci::verify::load_trust_material(&cache_dir).await?,
    )))
}

async fn publish(
    task: &BuildTaskPayload,
    input_dir: &std::path::Path,
) -> stow_types::error::Result<u32> {
    let credentials = stow_oci::RegistryCredentials::from_env()?;
    // One client for the whole publish: the artifact push and the
    // records push share the trust-store load (stow#624).
    let http = stow_oci::RegistryHttp::new(stow_oci::TransportPolicy::PATIENT).await?;
    // A run whose task's signed records already exist re-tags the
    // proven manifest under its own `records-<…>-<run_id>-<attempt>`
    // tag — the webhook's per-run check still resolves — instead of
    // validating and pushing a second build (stow#877).
    if let Some(manifest) = published_manifest(task, &credentials, &http).await? {
        let repository = stow_types::registry::cache_repository(&task.rustc_version);
        let session =
            stow_oci::RegistryBase::production()?.push_session(&repository, &credentials, &http);
        let reference = session.reference(&stow_types::records::records_tag(
            task.rustc_version.as_str(),
            &task.task_id,
            build_run_from_env()?,
        ))?;
        // The proven manifest is re-signed, not just re-tagged: every
        // reader binds the signature to the tag it pulled, so this
        // run's `records-…-<run>-<attempt>` tag needs its own layer
        // in the shared `sha256-<digest>.sig` bundle (stow#877).
        let reference_string = reference.to_string();
        stow_oci::put_signed_manifest(&session, &reference, &manifest, |digest| {
            let reference_string = reference_string.clone();
            async move { stow_oci::sign_artifact(&reference_string, &digest, &credentials).await }
        })
        .await
        .map_err(|error| stow_types::stow_error!("retag records manifest {reference}: {error}"))?;
        tracing::info!(
            task_id = %task.task_id,
            "records already published — re-tagged, nothing built"
        );
        return Ok(0);
    }
    let output = validated_build_output(task, input_dir).await?;
    let upload_outcome =
        stow_oci::push_artifacts(&output.plan, &task.rustc_version, &credentials, &http).await?;
    let artifact_records = stow_types::upload_plan::build_artifact_records(
        &output.plan,
        &upload_outcome.published_by_reference,
        &measure_glibc_floors(&output.plan)?,
    )?;
    // The records artifact is the only record the run writes: cosigned by
    // this workflow's identity under
    // `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>` — the run
    // identity makes the tag per-build, so a rebuilt task never
    // overwrites an earlier build's rows — and the webhook handler reads
    // this run's tag back before marking the task done.
    let records = stow_oci::push_records(
        &credentials,
        &http,
        &task.rustc_version,
        &task.task_id,
        build_run_from_env()?,
        &artifact_records,
    )
    .await?;

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        artifact_records = artifact_records.len(),
        records_tag = %records.tag,
        "publish stage completed"
    );
    Ok(upload_outcome.newly_pushed)
}

/// Every check the trusted stage makes before anything is pushed: the
/// build output re-read with its digests re-derived, the plan bound to
/// the dispatched task and to a dependency closure resolved here, and
/// each consumption claim verified against the signed index. `publish`
/// runs it before pushing to GHCR; the local CI runs the same function
/// before writing the mock registry, so a mock build lands only what
/// production would have accepted.
async fn validated_build_output(
    task: &BuildTaskPayload,
    input_dir: &std::path::Path,
) -> stow_types::error::Result<stage::BuildOutput> {
    let output = stage::read_build_output(input_dir).await?;
    let closure = closure::resolve(task).await?;
    // Every cache-consumption claim is only as good as the signed index
    // vouching for it — the publisher pulls the slices itself rather than
    // trusting the untrusted job's copy. No claims means the old failure
    // surface: never require the network the publish path did not need
    // before.
    let index_slices = if output.consumed.is_empty() {
        Vec::new()
    } else {
        let config = stow_cli::build_consume::ConsumeConfig::load()
            .map_err(|error| error.wrap_err("load config to verify consumed artifact claims"))?;
        consume::slices_for_task(&config, task)
            .await
            .map_err(|error| {
                error.wrap_err("fetch index slices to verify consumed artifact claims")
            })?
    };
    validate::validate_plan(
        task,
        &output.task,
        &output.plan,
        &closure,
        &output.consumed,
        &index_slices,
    )?;
    Ok(output)
}

/// Measure every planned artifact's glibc floor from its output bytes —
/// the same files the bundle's `files/` members carry — keyed by OCI
/// reference so [`build_artifact_records`] can stamp each record. An
/// output that parses as ELF contributes its highest `GLIBC_x.y`
/// version-needed tag; anything else contributes nothing, so rlibs,
/// rmeta and JSON members all land on `None`. A floor above
/// [`GLIBC_BASELINE`] is a publish failure, not a stored value — the
/// Linux builder's sysroot job keeps every host-loaded output at or
/// below it, so a higher floor means the link escaped the sysroot.
fn measure_glibc_floors(
    plans: &[stow_types::upload_plan::PlannedArtifact],
) -> stow_types::error::Result<
    std::collections::BTreeMap<String, Option<stow_types::glibc::GlibcVersion>>,
> {
    let mut floors = std::collections::BTreeMap::new();
    for plan in plans {
        let mut floor = None;
        for output in &plan.outputs {
            let bytes = std::fs::read(&output.path).map_err(|error| {
                stow_types::stow_error!(
                    "read {} to measure its glibc floor: {error}",
                    output.path.display()
                )
            })?;
            floor = floor.max(stow_types::glibc::min_glibc_of_elf_bytes(&bytes)?);
        }
        if let Some(floor) = floor
            && floor > stow_types::glibc::GLIBC_BASELINE
        {
            return Err(stow_types::stow_error!(
                "artifact {} needs glibc {floor}, above the {baseline} baseline \
                 the index promises — refuse to publish it",
                plan.oci_reference,
                baseline = stow_types::glibc::GLIBC_BASELINE,
            ));
        }
        floors.insert(plan.oci_reference.clone(), floor);
    }
    Ok(floors)
}

async fn serve_stage(listen: std::net::SocketAddr) -> stow_types::error::Result<()> {
    let state = local_server::LocalServerState::new(
        env_required(STOW_EDGE_URL_ENV)?,
        env_required(STOW_GITHUB_WEBHOOK_SECRET_ENV)?,
        env_required(STOW_MOCK_PRIVATE_KEY_PATH_ENV)?,
        env_required(STOW_MOCK_REGISTRY_ROOT_ENV)?,
        env_required(GITHUB_APP_SLUG_ENV)?,
    );
    local_server::serve(listen, state).await
}

/// The task both stages act on — the one `build-crate.yml` input the
/// run was dispatched with. The task rides the `workflow_dispatch`
/// event file (`GITHUB_EVENT_PATH`), so the publish job's copy comes
/// from the scheduler, never from the build job.
fn load_task_payload() -> stow_types::error::Result<BuildTaskPayload> {
    task_from_event_file(std::path::Path::new(&env_required(GITHUB_EVENT_PATH_ENV)?))
}

/// The `workflow_dispatch` event file: only the `task` input is read.
#[derive(serde::Deserialize)]
struct DispatchEvent {
    inputs: Option<DispatchInputs>,
}

#[derive(serde::Deserialize)]
struct DispatchInputs {
    /// The JSON-encoded [`BuildTaskPayload`].
    task: Option<String>,
}

/// The task in the dispatch event file at `event_path`
/// (`.inputs.task`, a JSON-encoded [`BuildTaskPayload`]).
fn task_from_event_file(
    event_path: &std::path::Path,
) -> stow_types::error::Result<BuildTaskPayload> {
    let raw = std::fs::read(event_path).map_err(|error| {
        stow_types::stow_error!(
            "read the dispatch event file {GITHUB_EVENT_PATH_ENV}={}: {error}",
            event_path.display()
        )
    })?;
    task_from_event(&raw, event_path)
}

/// [`task_from_event_file`] over the file's bytes, which the async local
/// CI reads itself. `event_path` only names the file in errors.
pub(crate) fn task_from_event(
    raw: &[u8],
    event_path: &std::path::Path,
) -> stow_types::error::Result<BuildTaskPayload> {
    let event: DispatchEvent = serde_json::from_slice(raw).map_err(|error| {
        stow_types::stow_error!(
            "parse the dispatch event file {}: {error}",
            event_path.display()
        )
    })?;
    let task = event.inputs.and_then(|inputs| inputs.task).ok_or_else(|| {
        stow_types::stow_error!(
            "dispatch event file {} has no `inputs.task`",
            event_path.display()
        )
    })?;
    serde_json::from_str(&task).map_err(|error| {
        stow_types::stow_error!("parse `inputs.task` of {}: {error}", event_path.display())
    })
}

fn env_required(name: &str) -> stow_types::error::Result<String> {
    std::env::var(name).map_err(|_| stow_types::stow_error!("missing required env var {name}"))
}

/// A required environment variable parsed as a number — a missing or
/// non-numeric value errors naming the variable.
fn env_required_number<T: std::str::FromStr>(name: &str) -> stow_types::error::Result<T> {
    env_required(name)?
        .parse()
        .map_err(|_| stow_types::stow_error!("env var {name} must be a number"))
}

/// The Actions run identity the publish stage's records artifact tags
/// itself with — `GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT`, which the
/// runner sets on every job.
fn build_run_from_env() -> stow_types::error::Result<stow_types::records::BuildRun> {
    Ok(stow_types::records::BuildRun {
        run_id: env_required_number(GITHUB_RUN_ID_ENV)?,
        run_attempt: env_required_number(GITHUB_RUN_ATTEMPT_ENV)?,
    })
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(stow_oci::OPERATOR_LOG_FILTER));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // stderr, never stdout: this binary also serves as the capture `rustc` wrapper.
        .with_writer(std::io::stderr)
        .try_init();
}

/// Single-crate tasks for the tests that read one.
#[cfg(test)]
mod task_fixture {
    use stow_types::api::BuildTaskPayload;
    use stow_types::identity::{
        CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion,
    };

    pub fn task(crate_name: &str) -> BuildTaskPayload {
        BuildTaskPayload {
            task_id: format!("task-{crate_name}"),
            attempt: 1,
            crate_name: CrateName::parse(crate_name).unwrap(),
            version: CrateVersion::new(semver::Version::new(1, 0, 0)),
            features_json: FeaturesJson::default(),
            target: TargetTriple::parse("x86_64-unknown-linux-gnu").unwrap(),
            rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
            preserve_lockfile: false,
            host_side: false,
            explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
            dependency_subgraph: stow_types::api::TaskSubgraph {
                root_deps: Vec::new(),
                nodes: Vec::new(),
            },
        }
    }

    /// The encoded `inputs.task` for one name.
    pub fn encoded_task(crate_name: &str) -> String {
        serde_json::to_string(&task(crate_name)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{task_fixture::encoded_task, task_from_event_file};

    fn event_file(contents: &serde_json::Value) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), serde_json::to_vec(contents).unwrap()).unwrap();
        file
    }

    #[test]
    fn a_task_is_read_from_the_event_files_inputs() {
        let event = event_file(&serde_json::json!({
            "inputs": { "task": encoded_task("tokio") }
        }));
        let task = task_from_event_file(event.path()).unwrap();
        assert_eq!(task.task_id, "task-tokio");
        assert_eq!(task.crate_name.as_str(), "tokio");
        assert_eq!(task.rustc_version.as_str(), "1.91.1");
    }

    #[test]
    fn a_missing_event_file_names_the_path() {
        let error = task_from_event_file(std::path::Path::new("/nonexistent/event.json"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("/nonexistent/event.json"), "{error}");
    }

    #[test]
    fn a_missing_task_input_is_named() {
        for contents in [
            serde_json::json!({}),
            serde_json::json!({ "inputs": {} }),
            serde_json::json!({ "inputs": { "task": null } }),
        ] {
            let event = event_file(&contents);
            let error = task_from_event_file(event.path()).unwrap_err().to_string();
            assert!(error.contains("inputs.task"), "{contents}: {error}");
        }
    }

    #[test]
    fn a_malformed_task_input_is_named() {
        let event = event_file(&serde_json::json!({
            "inputs": { "task": "{not json" }
        }));
        let error = task_from_event_file(event.path()).unwrap_err().to_string();
        assert!(error.contains("inputs.task"), "{error}");
    }
}

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
//! * `stow-build publish` runs in a job that holds the GHCR token, the OIDC
//!   grant for cosign, and the edge register secret. It reads the build
//!   output, re-derives every digest, checks the plan against the task it was
//!   dispatched with and a dependency closure it resolves itself, and only
//!   then pushes, signs, registers, and reports completion.
//!
//! `stow-build serve` is the dev-only local dispatch server, and
//! `stow-build rustc …` is the capture wrapper cargo invokes during `build`.

mod auth;
mod backfill;
mod capture;
mod closure;
mod consume;
mod dep_scan;
mod local_server;
mod notify;
mod plan;
mod register;
mod retry;
mod stage;
mod task;
mod validate;
mod workspace_mirror;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use stow_types::api::{BuildCompleteReport, BuildTaskPayload};
use tracing_subscriber::EnvFilter;

const STOW_BUILD_TASK_JSON_ENV: &str = "STOW_BUILD_TASK_JSON";
const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
const STOW_MOCK_PUBLIC_KEY_PATH_ENV: &str = "STOW_MOCK_PUBLIC_KEY_PATH";
const STOW_MOCK_PRIVATE_KEY_PATH_ENV: &str = "STOW_MOCK_PRIVATE_KEY_PATH";
const STOW_MOCK_REGISTRY_ROOT_ENV: &str = "STOW_MOCK_REGISTRY_ROOT";
const SCHEDULER_URL_ENV: &str = "SCHEDULER_URL";

#[derive(Debug, Parser)]
#[command(name = "stow-build", about, version)]
struct Cli {
    #[command(subcommand)]
    command: Stage,
}

#[derive(Debug, Subcommand)]
enum Stage {
    /// Untrusted stage: compile the task crate and write the build output.
    Build {
        /// Directory to write the build output into (created if missing).
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Trusted stage: validate a build output, then push, sign, register and
    /// report it.
    Publish {
        /// Directory a `build` stage wrote.
        #[arg(long)]
        input_dir: PathBuf,
    },
    /// One-time migration: publish the `<tag>.bundle` of every artifact
    /// row registered before bundles existed and re-register it. Needs
    /// `GHCR_USERNAME`/`GHCR_TOKEN` with package write access and the
    /// developer's GitHub token for the edge.
    BackfillBundles {
        /// Rows republished per edge round trip.
        #[arg(long, default_value_t = 200)]
        batch: usize,
    },
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
        Stage::BackfillBundles { batch } => tokio_runtime()?.block_on(async move {
            let republished = backfill::backfill_bundles(batch).await?;
            tracing::info!(republished, "bundle backfill completed");
            Ok(())
        }),
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
    let task = load_task_payload()?;
    async_fs::create_dir_all(output_dir).await?;
    let built = task::build(&task, output_dir).await?;
    let report = dep_scan::scan_artifacts(&built, &task).await?;
    let upload_plan = plan::build_upload_plan(&report.artifacts, &report.consumed).await?;
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
    match publish(&task, input_dir).await {
        Ok(report) => {
            // A 409 means a newer attempt owns the task: the run's report
            // cannot apply, so it is a warn, not a failure (stow#431).
            if !notify::report_completion(&report).await? {
                tracing::warn!(
                    task_id = %task.task_id,
                    "completion report rejected — a newer attempt owns the task"
                );
            }
            Ok(())
        }
        Err(failure) => {
            let (step, error) = (failure.step(), failure.into_error());
            tracing::error!(task_id = %task.task_id, %error, step = %step.as_str(), "publish stage failed");
            let report = BuildCompleteReport {
                task_id: task.task_id.clone(),
                attempt: task.attempt,
                success: false,
                error: Some(error.to_string()),
                failure_step: Some(step),
                artifacts_uploaded: 0,
                github_run_id: None,
            };
            match notify::report_completion(&report).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::warn!(
                        task_id = %task.task_id,
                        "failure report rejected — a newer attempt owns the task"
                    );
                }
                Err(notify_error) => {
                    return Err(stow_types::stow_error!(
                        "{error}; reporting the failure to the scheduler also failed: {notify_error}"
                    ));
                }
            }
            Err(error)
        }
    }
}

/// `publish()`'s error split on the pipeline step that produced it —
/// the report carries the step so the scheduler's failure classes can
/// name `register` what a bare publish-job error text cannot.
enum PublishFailure {
    /// Validate/push/sign work the trusted job owns.
    Stage(stow_types::error::Error),
    /// The `artifacts/register` POST into the edge.
    Register(stow_types::error::Error),
}

impl PublishFailure {
    const fn step(&self) -> stow_types::api::FailureStep {
        match self {
            Self::Stage(_) => stow_types::api::FailureStep::Publish,
            Self::Register(_) => stow_types::api::FailureStep::Register,
        }
    }

    fn into_error(self) -> stow_types::error::Error {
        match self {
            Self::Stage(error) | Self::Register(error) => error,
        }
    }
}

impl From<stow_types::error::Error> for PublishFailure {
    fn from(error: stow_types::error::Error) -> Self {
        Self::Stage(error)
    }
}

async fn publish(
    task: &BuildTaskPayload,
    input_dir: &std::path::Path,
) -> Result<BuildCompleteReport, PublishFailure> {
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

    let credentials = stow_oci::RegistryCredentials::from_env()?;
    let upload_outcome = stow_oci::push_artifacts(&output.plan, &credentials).await?;
    let artifact_records = stow_types::upload_plan::build_artifact_records(
        &output.plan,
        &upload_outcome.published_by_reference,
        &measure_glibc_floors(&output.plan)?,
    )?;
    // A 409 here means the scheduler reclaimed the task while this build
    // ran and a newer attempt owns it — the records can never land, so the
    // publish stops and reports; the report itself conflicts the same way
    // and the job exits quietly (stow#431). A real register failure (5xx,
    // transport) reports with `failure_step: register`.
    if !register::register_artifacts(Some(&task.task_id), &artifact_records)
        .await
        .map_err(PublishFailure::Register)?
    {
        tracing::warn!(
            task_id = %task.task_id,
            "register rejected the records — a newer attempt owns the task"
        );
    }

    tracing::info!(
        task_id = %task.task_id,
        crate_name = %task.crate_name,
        version = %task.version,
        target = %task.target,
        artifact_records = artifact_records.len(),
        "publish stage completed"
    );
    Ok(BuildCompleteReport {
        task_id: task.task_id.clone(),
        attempt: task.attempt,
        success: true,
        error: None,
        failure_step: None,
        artifacts_uploaded: upload_outcome.newly_pushed,
        github_run_id: None,
    })
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
    let state = local_server::LocalServerState {
        scheduler_url: env_required(SCHEDULER_URL_ENV)?,
        edge_url: env_required(STOW_EDGE_URL_ENV)?,
        mock_public_key_path: env_required(STOW_MOCK_PUBLIC_KEY_PATH_ENV)?,
        mock_private_key_path: env_required(STOW_MOCK_PRIVATE_KEY_PATH_ENV)?,
        mock_registry_root: env_required(STOW_MOCK_REGISTRY_ROOT_ENV)?,
        edge_bearer: auth::edge_bearer().await?,
    };
    local_server::serve(listen, state).await
}

/// The task both stages act on. The workflow passes it verbatim from the
/// `workflow_dispatch` input, so the publish job's copy comes from the
/// scheduler, never from the build job.
fn load_task_payload() -> stow_types::error::Result<BuildTaskPayload> {
    let raw_json = env_required(STOW_BUILD_TASK_JSON_ENV)?;
    serde_json::from_str(&raw_json)
        .map_err(|error| stow_types::stow_error!("parse {STOW_BUILD_TASK_JSON_ENV}: {error}"))
}

fn env_required(name: &str) -> stow_types::error::Result<String> {
    std::env::var(name).map_err(|_| stow_types::stow_error!("missing required env var {name}"))
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // stderr, never stdout: this binary also serves as the capture `rustc` wrapper.
        .with_writer(std::io::stderr)
        .try_init();
}

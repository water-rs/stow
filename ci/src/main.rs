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

mod capture;
mod closure;
mod dep_scan;
mod local_server;
mod native;
mod notify;
mod plan;
mod register;
mod sign;
mod stage;
mod task;
mod upload;
mod validate;
mod workspace_mirror;
mod zstd_util;

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use stow_types::api::{BuildCompleteReport, BuildTaskPayload};
use tracing_subscriber::EnvFilter;

const STOW_BUILD_TASK_JSON_ENV: &str = "STOW_BUILD_TASK_JSON";
const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
const STOW_MOCK_PUBLIC_KEY_PATH_ENV: &str = "STOW_MOCK_PUBLIC_KEY_PATH";
const STOW_MOCK_PRIVATE_KEY_PATH_ENV: &str = "STOW_MOCK_PRIVATE_KEY_PATH";
const STOW_MOCK_REGISTRY_ROOT_ENV: &str = "STOW_MOCK_REGISTRY_ROOT";
const SCHEDULER_URL_ENV: &str = "SCHEDULER_URL";
const SCHEDULER_AUTH_TOKEN_ENV: &str = "SCHEDULER_AUTH_TOKEN";
const STOW_REGISTER_AUTH_TOKEN_ENV: &str = "STOW_REGISTER_AUTH_TOKEN";

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
        /// Outcome of the build job, as GitHub reports it. Anything but
        /// `success` is reported to the scheduler as a failed task.
        #[arg(long, value_enum, default_value_t = BuildOutcome::Success)]
        build_outcome: BuildOutcome,
    },
    /// Dev-only local dispatch server standing in for GitHub Actions.
    Serve {
        /// Socket address to listen on.
        #[arg(long)]
        listen: std::net::SocketAddr,
    },
}

/// `needs.build.result` in the publish job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BuildOutcome {
    Success,
    Failure,
    Cancelled,
    Skipped,
}

fn main() -> stow_types::error::Result<()> {
    install_tracing();
    let args = std::env::args_os().collect::<Vec<_>>();
    if capture::is_rustc_wrapper_invocation(&args) {
        return smol::block_on(capture::run_rustc_capture_wrapper(&args));
    }
    let cli = Cli::parse();
    match cli.command {
        Stage::Build { output_dir } => smol::block_on(build_stage(&output_dir)),
        // `oci-client` drives hyper, which needs a Tokio reactor; the build
        // stage is smol-only because cargo/rustc capture never touches HTTP.
        Stage::Publish {
            input_dir,
            build_outcome,
        } => tokio_runtime()?.block_on(publish_stage(&input_dir, build_outcome)),
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
    let upload_plan = plan::build_upload_plan(&report.artifacts).await?;
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

async fn publish_stage(
    input_dir: &std::path::Path,
    build_outcome: BuildOutcome,
) -> stow_types::error::Result<()> {
    let task = load_task_payload()?;
    if build_outcome != BuildOutcome::Success {
        let error = format!("build job ended with result {build_outcome:?}");
        notify::report_completion(&BuildCompleteReport {
            task_id: task.task_id.clone(),
            success: false,
            error: Some(error.clone()),
            artifacts_uploaded: 0,
        })
        .await?;
        return Err(stow_types::stow_error!("{error}"));
    }
    match publish(&task, input_dir).await {
        Ok(report) => {
            notify::report_completion(&report).await?;
            Ok(())
        }
        Err(error) => {
            tracing::error!(task_id = %task.task_id, %error, "publish stage failed");
            let report = BuildCompleteReport {
                task_id: task.task_id.clone(),
                success: false,
                error: Some(error.to_string()),
                artifacts_uploaded: 0,
            };
            if let Err(notify_error) = notify::report_completion(&report).await {
                return Err(stow_types::stow_error!(
                    "{error}; reporting the failure to the scheduler also failed: {notify_error}"
                ));
            }
            Err(error)
        }
    }
}

async fn publish(
    task: &BuildTaskPayload,
    input_dir: &std::path::Path,
) -> stow_types::error::Result<BuildCompleteReport> {
    let output = stage::read_build_output(input_dir).await?;
    let closure = closure::resolve(task).await?;
    validate::validate_plan(task, &output.task, &output.plan, &closure)?;

    let upload_outcome = upload::push_artifacts(&output.plan).await?;
    sign::sign_artifacts(&upload_outcome.pushed_digests_by_reference).await?;
    let artifact_records = stow_types::upload_plan::build_artifact_records(
        &output.plan,
        &upload_outcome.digests_by_reference,
    )?;
    register::register_artifacts(&artifact_records).await?;

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
        success: true,
        error: None,
        artifacts_uploaded: upload_outcome.newly_pushed,
    })
}

async fn serve_stage(listen: std::net::SocketAddr) -> stow_types::error::Result<()> {
    let state = local_server::LocalServerState {
        scheduler_url: env_required(SCHEDULER_URL_ENV)?,
        edge_url: env_required(STOW_EDGE_URL_ENV)?,
        mock_public_key_path: env_required(STOW_MOCK_PUBLIC_KEY_PATH_ENV)?,
        mock_private_key_path: env_required(STOW_MOCK_PRIVATE_KEY_PATH_ENV)?,
        mock_registry_root: env_required(STOW_MOCK_REGISTRY_ROOT_ENV)?,
        scheduler_auth_token: env_required(SCHEDULER_AUTH_TOKEN_ENV)?,
        register_auth_token: env_required(STOW_REGISTER_AUTH_TOKEN_ENV)?,
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

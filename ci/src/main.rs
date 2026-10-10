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
mod plan;
mod stage;
mod task;
mod validate;
mod workspace_mirror;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use stow_types::api::BuildTaskPayload;
use tracing_subscriber::EnvFilter;

const STOW_BUILD_TASK_JSON_ENV: &str = "STOW_BUILD_TASK_JSON";
const STOW_EDGE_URL_ENV: &str = "STOW_EDGE_URL";
const STOW_MOCK_PUBLIC_KEY_PATH_ENV: &str = "STOW_MOCK_PUBLIC_KEY_PATH";
const STOW_MOCK_PRIVATE_KEY_PATH_ENV: &str = "STOW_MOCK_PRIVATE_KEY_PATH";
const STOW_MOCK_REGISTRY_ROOT_ENV: &str = "STOW_MOCK_REGISTRY_ROOT";
const STOW_GITHUB_WEBHOOK_SECRET_ENV: &str = "STOW_GITHUB_WEBHOOK_SECRET";

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
    /// Trusted stage: validate a build output, then push, sign and publish
    /// its records artifact into GHCR.
    Publish {
        /// Directory a `build` stage wrote.
        #[arg(long)]
        input_dir: PathBuf,
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
    let dependency_identity = task
        .verified_dependency_graph()?
        .dependency_identity(0)
        .ok_or_else(|| stow_types::stow_error!("verified dependency graph has no root digest"))?
        .clone();
    let upload_plan =
        plan::build_upload_plan(&report.artifacts, &report.consumed, &dependency_identity).await?;
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

async fn publish(
    task: &BuildTaskPayload,
    input_dir: &std::path::Path,
) -> stow_types::error::Result<u32> {
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
    // The records artifact is the only record the run writes: cosigned by
    // this workflow's identity under `records-<rustc>-<task_id hash>`, where the
    // webhook handler reads it back before marking the task done.
    let records = stow_oci::push_records(
        &credentials,
        task.rustc_version.as_str(),
        &task.task_id,
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
        env_required(STOW_MOCK_PUBLIC_KEY_PATH_ENV)?,
        env_required(STOW_MOCK_PRIVATE_KEY_PATH_ENV)?,
        env_required(STOW_MOCK_REGISTRY_ROOT_ENV)?,
    );
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

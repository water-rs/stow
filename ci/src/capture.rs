use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use async_process::Command;
use stow_types::rustc::ParsedRustcArgs;

pub const STOW_BUILD_CAPTURE_DIR_ENV: &str = "STOW_BUILD_RUSTC_CAPTURE_DIR";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapturedRustcArtifact {
    pub crate_name: String,
    pub crate_types: Vec<String>,
    pub target: Option<String>,
    pub c_metadata: String,
    pub extra_filename: String,
    pub out_dir: PathBuf,
    pub outputs: Vec<CapturedRustcOutput>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum CapturedRustcOutputKind {
    Rlib,
    Rmeta,
    DynamicLibrary,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapturedRustcOutput {
    pub kind: CapturedRustcOutputKind,
    pub path: PathBuf,
}

pub fn is_rustc_wrapper_invocation(args: &[std::ffi::OsString]) -> bool {
    args.get(1)
        .and_then(|arg| arg.to_str())
        .and_then(|path| std::path::Path::new(path).file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("rustc"))
}

pub async fn run_rustc_capture_wrapper(args: &[std::ffi::OsString]) -> eyre::Result<()> {
    let rustc = args
        .get(1)
        .ok_or_else(|| eyre::eyre!("rustc wrapper mode requires rustc path as argv[1]"))?;
    let status = Command::new(rustc).args(&args[2..]).status().await?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    let parsed = match ParsedRustcArgs::parse(&args[2..]) {
        Ok(parsed) => parsed,
        Err(error) if error.contains("missing --crate-name") => {
            std::process::exit(0);
        }
        Err(error) => return Err(eyre::eyre!("parse rustc wrapper arguments: {error}")),
    };
    if !parsed.is_cacheable() {
        std::process::exit(0);
    }

    let record = build_capture_record(&parsed)?;
    let capture_dir = std::env::var_os(STOW_BUILD_CAPTURE_DIR_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| eyre::eyre!("missing {STOW_BUILD_CAPTURE_DIR_ENV} for rustc capture"))?;
    async_fs::create_dir_all(&capture_dir).await?;
    let file_name = unique_capture_file_name(&record)?;
    let output_path = capture_dir.join(file_name);
    async_fs::write(&output_path, serde_json::to_vec(&record)?).await?;
    tracing::debug!(
        crate_name = %record.crate_name,
        c_metadata = %record.c_metadata,
        extra_filename = %record.extra_filename,
        output_path = %output_path.display(),
        "captured rustc invocation for trusted build registration"
    );
    std::process::exit(0);
}

pub async fn load_captured_artifacts(
    capture_dir: &std::path::Path,
) -> eyre::Result<Vec<CapturedRustcArtifact>> {
    let mut artifacts = Vec::new();
    let mut entries = async_fs::read_dir(capture_dir).await?;
    while let Some(entry) = futures_lite::StreamExt::next(&mut entries).await {
        let entry = entry?;
        let path = entry.path();
        if path.extension() != Some(OsStr::new("json")) {
            continue;
        }
        let bytes = async_fs::read(&path).await?;
        let record = serde_json::from_slice::<CapturedRustcArtifact>(&bytes)?;
        artifacts.push(record);
    }
    artifacts.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.c_metadata.cmp(&right.c_metadata))
            .then(left.extra_filename.cmp(&right.extra_filename))
    });
    Ok(artifacts)
}

fn build_capture_record(parsed: &ParsedRustcArgs) -> eyre::Result<CapturedRustcArtifact> {
    let c_metadata = parsed
        .c_metadata
        .clone()
        .ok_or_else(|| eyre::eyre!("cacheable rustc invocation is missing -C metadata"))?;
    let out_dir = parsed
        .out_dir
        .clone()
        .ok_or_else(|| eyre::eyre!("cacheable rustc invocation is missing --out-dir"))?;
    let outputs = collect_outputs(parsed)?;
    if outputs.is_empty() {
        return Err(eyre::eyre!(
            "cacheable rustc invocation produced no restorable outputs for {}",
            parsed.crate_name
        ));
    }

    Ok(CapturedRustcArtifact {
        crate_name: parsed.crate_name.clone(),
        crate_types: parsed.crate_types.clone(),
        target: parsed.target.clone(),
        c_metadata,
        extra_filename: parsed.extra_filename.clone(),
        out_dir,
        outputs,
    })
}

fn collect_outputs(parsed: &ParsedRustcArgs) -> eyre::Result<Vec<CapturedRustcOutput>> {
    let mut outputs = Vec::new();

    if let Some(path) = parsed.output_rlib_path()
        && path.exists()
    {
        outputs.push(CapturedRustcOutput {
            kind: CapturedRustcOutputKind::Rlib,
            path,
        });
    }
    if let Some(path) = parsed.output_rmeta_path()
        && path.exists()
    {
        outputs.push(CapturedRustcOutput {
            kind: CapturedRustcOutputKind::Rmeta,
            path,
        });
    }
    let dynamic_library_path = parsed
        .output_dynamic_library_path()
        .map_err(eyre::Report::msg)?;
    if dynamic_library_path.exists() {
        outputs.push(CapturedRustcOutput {
            kind: CapturedRustcOutputKind::DynamicLibrary,
            path: dynamic_library_path,
        });
    }

    Ok(outputs)
}

fn unique_capture_file_name(record: &CapturedRustcArtifact) -> eyre::Result<String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| eyre::eyre!("system clock before UNIX_EPOCH: {error}"))?
        .as_nanos();
    Ok(format!(
        "{}-{}-{}-{}.json",
        record.crate_name.replace('-', "_"),
        record.c_metadata,
        std::process::id(),
        stamp
    ))
}

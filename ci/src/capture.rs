use std::ffi::OsStr;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use async_process::Command;
use stow_types::error::Context;
use sha2::{Digest, Sha256};
use stow_types::platform::Profile;
use stow_types::public_cache::{
    StableRegistryArtifactIdentity, stable_c_metadata_for_compile_key,
    stable_registry_artifact_identity,
};
use stow_types::rustc::ParsedRustcArgs;

pub const STOW_BUILD_CAPTURE_DIR_ENV: &str = "STOW_BUILD_RUSTC_CAPTURE_DIR";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapturedRustcArtifact {
    pub crate_name: String,
    pub crate_types: Vec<String>,
    pub emit: Vec<String>,
    pub target: Option<String>,
    pub c_metadata: String,
    pub extra_filename: String,
    pub dependencies: Vec<CapturedDependencyIdentity>,
    pub profile: Profile,
    pub out_dir: PathBuf,
    pub outputs: Vec<CapturedRustcOutput>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CapturedDependencyIdentity {
    pub crate_name: String,
    pub path: PathBuf,
    pub compile_key: String,
    pub stable_c_metadata: String,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
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
        .is_some_and(|command| command == "rustc")
}

pub async fn run_rustc_capture_wrapper(args: &[std::ffi::OsString]) -> stow_types::error::Result<()> {
    let rustc = args
        .get(2)
        .ok_or_else(|| stow_types::stow_error!("rustc capture mode requires rustc path as argv[2]"))?;
    let original_parsed = match ParsedRustcArgs::parse(&args[3..]) {
        Ok(parsed) => parsed,
        Err(error) if error.contains("missing --crate-name") => {
            let status = Command::new(rustc).args(&args[3..]).status().await?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(error) => return Err(stow_types::stow_error!("parse rustc wrapper arguments: {error}")),
    };
    if !original_parsed.is_restorable_artifact() {
        let status = Command::new(rustc).args(&args[3..]).status().await?;
        std::process::exit(status.code().unwrap_or(1));
    }

    let capture_dir = std::env::var_os(STOW_BUILD_CAPTURE_DIR_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| stow_types::stow_error!("missing {STOW_BUILD_CAPTURE_DIR_ENV} for rustc capture"))?;
    let (effective_args, effective_parsed, stable_identity) =
        prepare_stable_rustc_invocation(rustc, &args[3..], &original_parsed, &capture_dir).await?;

    let output = Command::new(rustc).args(&effective_args).output().await?;
    if !output.status.success() {
        replay_rustc_output(&output).await?;
        std::process::exit(output.status.code().unwrap_or(1));
    }

    if let (Some(stable_identity), Some(rewritten_parsed)) =
        (stable_identity.as_ref(), effective_parsed.as_ref())
    {
        materialize_original_output_aliases(
            &original_parsed,
            rewritten_parsed,
            stable_identity,
            &capture_dir,
        )
        .await?;
    }

    let parsed = match effective_parsed {
        Some(parsed) => parsed,
        None => {
            replay_rustc_output(&output).await?;
            std::process::exit(0);
        }
    };
    let original_alias_source = stable_identity
        .as_ref()
        .map(|_| &original_parsed)
        .filter(|original| *original != &parsed);
    if let Some(stable_identity) = stable_identity.as_ref() {
        record_capture_output_identities(
            &parsed,
            original_alias_source,
            &stable_identity.compile_key,
            &capture_dir,
        )
        .await?;
    }
    let record = build_capture_record(&parsed, original_alias_source, &capture_dir).await?;
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
    replay_rustc_output(&output).await?;
    std::process::exit(0);
}

async fn replay_rustc_output(output: &async_process::Output) -> stow_types::error::Result<()> {
    let stdout = output.stdout.clone();
    smol::unblock(move || {
        let mut handle = std::io::stdout().lock();
        handle
            .write_all(&stdout)
            .wrap_err("replay captured rustc stdout")?;
        handle.flush().wrap_err("flush captured rustc stdout")
    })
    .await?;

    let stderr = output.stderr.clone();
    smol::unblock(move || {
        let mut handle = std::io::stderr().lock();
        handle
            .write_all(&stderr)
            .wrap_err("replay captured rustc stderr")?;
        handle.flush().wrap_err("flush captured rustc stderr")
    })
    .await
}

async fn prepare_stable_rustc_invocation(
    rustc: &std::ffi::OsString,
    original_args: &[std::ffi::OsString],
    original_parsed: &ParsedRustcArgs,
    capture_dir: &std::path::Path,
) -> stow_types::error::Result<(
    Vec<std::ffi::OsString>,
    Option<ParsedRustcArgs>,
    Option<StableRegistryArtifactIdentity>,
)> {
    let toolchain = detect_rustc_toolchain(rustc).await?;
    let effective_target = original_parsed
        .target
        .clone()
        .unwrap_or_else(|| toolchain.host_target.clone());
    let dependency_c_metadata_json =
        match resolve_dependency_c_metadata_json(capture_dir, original_parsed).await? {
            Some(value) => value,
            None if original_parsed.extern_crates.is_empty() => "[]".to_owned(),
            None => return Ok((original_args.to_vec(), Some(original_parsed.clone()), None)),
        };
    let features_json =
        serde_json::to_string(&original_parsed.features.iter().cloned().collect::<Vec<_>>())?;
    let Some(identity) = stable_registry_artifact_identity(
        original_parsed,
        &effective_target,
        &toolchain.version,
        &features_json,
        &dependency_c_metadata_json,
    )?
    else {
        return Ok((original_args.to_vec(), Some(original_parsed.clone()), None));
    };
    let Some(original_c_metadata) = original_parsed.c_metadata.as_deref() else {
        return Ok((original_args.to_vec(), Some(original_parsed.clone()), None));
    };
    if original_c_metadata == identity.c_metadata
        && original_parsed.extra_filename == identity.extra_filename
    {
        return Ok((
            original_args.to_vec(),
            Some(original_parsed.clone()),
            Some(identity),
        ));
    }
    let rewritten_args = rewrite_codegen_identity_args(
        original_args,
        &identity.c_metadata,
        &identity.extra_filename,
    )?;
    let rewritten_parsed = ParsedRustcArgs::parse(&rewritten_args)
        .map_err(|error| stow_types::stow_error!("parse rewritten rustc wrapper arguments: {error}"))?;
    Ok((rewritten_args, Some(rewritten_parsed), Some(identity)))
}

async fn resolve_dependency_c_metadata_json(
    capture_dir: &std::path::Path,
    parsed: &ParsedRustcArgs,
) -> stow_types::error::Result<Option<String>> {
    let mut identities = parsed
        .extern_crates
        .iter()
        .map(|extern_crate| {
            Ok((
                extern_crate.crate_name.clone(),
                output_identity_path(capture_dir, &extern_crate.path)?,
            ))
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    identities.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));

    let mut resolved = Vec::with_capacity(identities.len());
    for (crate_name, identity_path) in identities {
        if !identity_path.exists() {
            return Ok(None);
        }
        let record = serde_json::from_slice::<MaterializedOutputIdentity>(
            &async_fs::read(&identity_path).await?,
        )?;
        resolved.push(DependencyIdentityRecord {
            crate_name,
            c_metadata: record.stable_c_metadata,
        });
    }
    Ok(Some(serde_json::to_string(&resolved)?))
}

fn rewrite_codegen_identity_args(
    args: &[std::ffi::OsString],
    c_metadata: &str,
    extra_filename: &str,
) -> stow_types::error::Result<Vec<std::ffi::OsString>> {
    let mut rewritten = Vec::with_capacity(args.len());
    let mut iter = args.iter().peekable();
    let mut replaced_metadata = false;
    let mut replaced_extra_filename = false;

    while let Some(arg) = iter.next() {
        let Some(arg_str) = arg.to_str() else {
            rewritten.push(arg.clone());
            continue;
        };
        if arg_str == "-C" {
            let value = iter
                .next()
                .ok_or_else(|| stow_types::stow_error!("missing value after -C while rewriting rustc args"))?;
            let Some(value_str) = value.to_str() else {
                rewritten.push(arg.clone());
                rewritten.push(value.clone());
                continue;
            };
            if value_str.starts_with("metadata=") {
                rewritten.push(arg.clone());
                rewritten.push(std::ffi::OsString::from(format!("metadata={c_metadata}")));
                replaced_metadata = true;
                continue;
            }
            if value_str.starts_with("extra-filename=") {
                rewritten.push(arg.clone());
                rewritten.push(std::ffi::OsString::from(format!(
                    "extra-filename={extra_filename}"
                )));
                replaced_extra_filename = true;
                continue;
            }
            rewritten.push(arg.clone());
            rewritten.push(value.clone());
            continue;
        }
        if arg_str.starts_with("-Cmetadata=") {
            rewritten.push(std::ffi::OsString::from(format!("-Cmetadata={c_metadata}")));
            replaced_metadata = true;
            continue;
        }
        if arg_str.starts_with("-Cextra-filename=") {
            rewritten.push(std::ffi::OsString::from(format!(
                "-Cextra-filename={extra_filename}"
            )));
            replaced_extra_filename = true;
            continue;
        }
        rewritten.push(arg.clone());
    }

    if !replaced_metadata || !replaced_extra_filename {
        return Err(stow_types::stow_error!(
            "failed to rewrite rustc metadata arguments: metadata_replaced={}, extra_filename_replaced={}",
            replaced_metadata,
            replaced_extra_filename
        ));
    }
    Ok(rewritten)
}

async fn materialize_original_output_aliases(
    original_parsed: &ParsedRustcArgs,
    rewritten_parsed: &ParsedRustcArgs,
    identity: &StableRegistryArtifactIdentity,
    capture_dir: &std::path::Path,
) -> stow_types::error::Result<()> {
    materialize_optional_alias(
        rewritten_parsed.output_rlib_path(),
        original_parsed.output_rlib_path(),
        &identity.compile_key,
        capture_dir,
    )
    .await?;
    materialize_optional_alias(
        rewritten_parsed.output_rmeta_path(),
        original_parsed.output_rmeta_path(),
        &identity.compile_key,
        capture_dir,
    )
    .await?;
    materialize_optional_alias(
        rewritten_parsed
            .output_dynamic_library_path()
            .map_err(stow_types::error::Error::msg)?,
        original_parsed
            .output_dynamic_library_path()
            .map_err(stow_types::error::Error::msg)?,
        &identity.compile_key,
        capture_dir,
    )
    .await?;
    materialize_optional_alias(
        rewritten_parsed.output_dep_info_path(),
        original_parsed.output_dep_info_path(),
        &identity.compile_key,
        capture_dir,
    )
    .await?;
    touch_invoked_timestamp_alias(original_parsed).await?;
    Ok(())
}

async fn materialize_optional_alias(
    source_path: Option<PathBuf>,
    alias_path: Option<PathBuf>,
    compile_key: &str,
    capture_dir: &std::path::Path,
) -> stow_types::error::Result<()> {
    let (Some(source_path), Some(alias_path)) = (source_path, alias_path) else {
        return Ok(());
    };
    if !source_path.exists() {
        return Ok(());
    }
    record_materialized_output_identity(capture_dir, &source_path, compile_key).await?;
    if source_path == alias_path {
        return Ok(());
    }
    if let Some(parent) = alias_path.parent() {
        async_fs::create_dir_all(parent).await?;
    }
    let source_for_copy = source_path.clone();
    let alias_for_copy = alias_path.clone();
    smol::unblock(move || {
        if alias_for_copy.exists() {
            std::fs::remove_file(&alias_for_copy).wrap_err_with(|| {
                format!(
                    "remove original cargo output alias {}",
                    alias_for_copy.display()
                )
            })?;
        }
        reflink::reflink_or_copy(&source_for_copy, &alias_for_copy).wrap_err_with(|| {
            format!(
                "materialize original cargo output alias {} from {}",
                alias_for_copy.display(),
                source_for_copy.display()
            )
        })
    })
    .await?;
    record_materialized_output_identity(capture_dir, &alias_path, compile_key).await?;
    Ok(())
}

#[derive(Debug, Clone)]
struct RustcToolchain {
    version: String,
    host_target: String,
}

async fn detect_rustc_toolchain(rustc: &std::ffi::OsString) -> stow_types::error::Result<RustcToolchain> {
    let output = Command::new(rustc)
        .arg("-vV")
        .output()
        .await
        .wrap_err("spawn rustc -vV for stable capture identity")?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "rustc -vV failed while preparing stable capture identity: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| stow_types::stow_error!("rustc -vV output is not UTF-8: {error}"))?;
    let version = stdout
        .lines()
        .find_map(|line| line.strip_prefix("release: ").map(str::to_owned))
        .ok_or_else(|| stow_types::stow_error!("rustc -vV output missing release line"))?;
    let host_target = stdout
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
        .ok_or_else(|| stow_types::stow_error!("rustc -vV output missing host line"))?;
    Ok(RustcToolchain {
        version,
        host_target,
    })
}

async fn touch_invoked_timestamp_alias(parsed: &ParsedRustcArgs) -> stow_types::error::Result<()> {
    let Some(out_dir) = parsed.out_dir.as_ref() else {
        return Ok(());
    };
    let Some(profile_dir) = out_dir.parent() else {
        return Ok(());
    };
    let fingerprint_dir = profile_dir.join(".fingerprint").join(format!(
        "{}{}",
        parsed.crate_name.replace('_', "-"),
        parsed.extra_filename
    ));
    let timestamp_path = fingerprint_dir.join("invoked.timestamp");
    smol::unblock(move || {
        std::fs::create_dir_all(&fingerprint_dir).wrap_err_with(|| {
            format!("create cargo fingerprint dir {}", fingerprint_dir.display())
        })?;
        std::fs::write(&timestamp_path, [])
            .wrap_err_with(|| format!("write {}", timestamp_path.display()))
    })
    .await
}

async fn record_materialized_output_identity(
    capture_dir: &std::path::Path,
    output_path: &std::path::Path,
    compile_key: &str,
) -> stow_types::error::Result<()> {
    let record = MaterializedOutputIdentity {
        output_path: output_path_string(output_path)?,
        compile_key: compile_key.to_owned(),
        stable_c_metadata: stable_c_metadata_for_compile_key(compile_key)?,
    };
    let identity_path = output_identity_path(capture_dir, output_path)?;
    let parent = identity_path.parent().ok_or_else(|| {
        stow_types::stow_error!(
            "output identity path {} has no parent",
            identity_path.display()
        )
    })?;
    async_fs::create_dir_all(parent).await?;
    async_fs::write(identity_path, serde_json::to_vec(&record)?).await?;
    Ok(())
}

async fn record_capture_output_identities(
    parsed: &ParsedRustcArgs,
    original_alias_source: Option<&ParsedRustcArgs>,
    compile_key: &str,
    capture_dir: &std::path::Path,
) -> stow_types::error::Result<()> {
    for output in collect_outputs(parsed, original_alias_source)? {
        record_materialized_output_identity(capture_dir, &output.path, compile_key).await?;
    }
    Ok(())
}

fn output_identity_path(
    capture_dir: &std::path::Path,
    output_path: &std::path::Path,
) -> stow_types::error::Result<PathBuf> {
    let output_path = output_path_string(output_path)?;
    Ok(capture_dir.join("output-identities").join(format!(
        "{}.json",
        hex::encode(Sha256::digest(output_path.as_bytes()))
    )))
}

fn output_path_string(path: &std::path::Path) -> stow_types::error::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| stow_types::stow_error!("path {} is not valid UTF-8", path.display()))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MaterializedOutputIdentity {
    output_path: String,
    compile_key: String,
    stable_c_metadata: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadedOutputIdentity {
    pub(crate) compile_key: String,
    pub(crate) stable_c_metadata: String,
}

pub(crate) async fn load_output_identity(
    capture_dir: &std::path::Path,
    output_path: &std::path::Path,
) -> stow_types::error::Result<Option<LoadedOutputIdentity>> {
    let identity_path = output_identity_path(capture_dir, output_path)?;
    if !identity_path.exists() {
        return Ok(None);
    }
    let bytes = async_fs::read(&identity_path).await?;
    let record = serde_json::from_slice::<MaterializedOutputIdentity>(&bytes)?;
    Ok(Some(LoadedOutputIdentity {
        compile_key: record.compile_key,
        stable_c_metadata: record.stable_c_metadata,
    }))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DependencyIdentityRecord {
    crate_name: String,
    c_metadata: String,
}

pub async fn load_captured_artifacts(
    capture_dir: &std::path::Path,
) -> stow_types::error::Result<Vec<CapturedRustcArtifact>> {
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

async fn build_capture_record(
    parsed: &ParsedRustcArgs,
    original_alias_source: Option<&ParsedRustcArgs>,
    capture_dir: &std::path::Path,
) -> stow_types::error::Result<CapturedRustcArtifact> {
    let c_metadata = parsed
        .c_metadata
        .clone()
        .ok_or_else(|| stow_types::stow_error!("cacheable rustc invocation is missing -C metadata"))?;
    let out_dir = parsed
        .out_dir
        .clone()
        .ok_or_else(|| stow_types::stow_error!("cacheable rustc invocation is missing --out-dir"))?;
    let outputs = collect_outputs(parsed, original_alias_source)?;
    if outputs.is_empty() {
        return Err(stow_types::stow_error!(
            "cacheable rustc invocation produced no restorable outputs for {}",
            parsed.crate_name
        ));
    }
    let dependencies = load_recorded_dependencies(capture_dir, parsed).await?;

    Ok(CapturedRustcArtifact {
        crate_name: parsed.crate_name.clone(),
        crate_types: parsed.crate_types.clone(),
        emit: parsed.emit.iter().cloned().collect(),
        target: parsed.target.clone(),
        c_metadata,
        extra_filename: parsed.extra_filename.clone(),
        dependencies,
        profile: parsed.profile().map_err(stow_types::error::Error::msg)?,
        out_dir,
        outputs,
    })
}

async fn load_recorded_dependencies(
    capture_dir: &std::path::Path,
    parsed: &ParsedRustcArgs,
) -> stow_types::error::Result<Vec<CapturedDependencyIdentity>> {
    let mut dependencies = Vec::with_capacity(parsed.extern_crates.len());
    for extern_crate in &parsed.extern_crates {
        let identity = load_output_identity(capture_dir, &extern_crate.path)
            .await?
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "missing output identity sidecar for extern crate {} at {} while building capture record",
                    extern_crate.crate_name,
                    extern_crate.path.display()
                )
            })?;
        dependencies.push(CapturedDependencyIdentity {
            crate_name: extern_crate.crate_name.clone(),
            path: extern_crate.path.clone(),
            compile_key: identity.compile_key,
            stable_c_metadata: identity.stable_c_metadata,
        });
    }
    dependencies.sort_by(|left, right| {
        left.crate_name
            .cmp(&right.crate_name)
            .then(left.path.cmp(&right.path))
    });
    dependencies.dedup_by(|left, right| left.crate_name == right.crate_name && left.path == right.path);
    Ok(dependencies)
}

fn collect_outputs(
    parsed: &ParsedRustcArgs,
    original_alias_source: Option<&ParsedRustcArgs>,
) -> stow_types::error::Result<Vec<CapturedRustcOutput>> {
    let mut outputs = Vec::new();
    let mut seen_paths = std::collections::BTreeSet::new();
    let require_dynamic_library = parsed.emit.iter().any(|emit| emit == "link");
    let stable_rlib_path = parsed.output_rlib_path();
    let stable_rlib_exists = stable_rlib_path.as_ref().is_some_and(|path| path.exists());
    let stable_rmeta_path = parsed.output_rmeta_path();
    let stable_rmeta_exists = stable_rmeta_path.as_ref().is_some_and(|path| path.exists());
    let stable_dynamic_library_path = parsed
        .output_dynamic_library_path()
        .map_err(stow_types::error::Error::msg)?;
    let stable_dynamic_library_exists = stable_dynamic_library_path
        .as_ref()
        .is_some_and(|path| path.exists());

    collect_output_path(
        &mut outputs,
        &mut seen_paths,
        stable_rlib_path,
        CapturedRustcOutputKind::Rlib,
        false,
    )?;
    collect_output_path(
        &mut outputs,
        &mut seen_paths,
        stable_rmeta_path,
        CapturedRustcOutputKind::Rmeta,
        false,
    )?;
    collect_output_path(
        &mut outputs,
        &mut seen_paths,
        stable_dynamic_library_path,
        CapturedRustcOutputKind::DynamicLibrary,
        require_dynamic_library,
    )?;

    if let Some(original_alias_source) = original_alias_source {
        collect_output_path(
            &mut outputs,
            &mut seen_paths,
            original_alias_source.output_rlib_path(),
            CapturedRustcOutputKind::Rlib,
            stable_rlib_exists,
        )?;
        collect_output_path(
            &mut outputs,
            &mut seen_paths,
            original_alias_source.output_rmeta_path(),
            CapturedRustcOutputKind::Rmeta,
            stable_rmeta_exists,
        )?;
        collect_output_path(
            &mut outputs,
            &mut seen_paths,
            original_alias_source
                .output_dynamic_library_path()
                .map_err(stow_types::error::Error::msg)?,
            CapturedRustcOutputKind::DynamicLibrary,
            require_dynamic_library && stable_dynamic_library_exists,
        )?;
    }

    validate_duplicate_output_kinds(&outputs)?;
    Ok(outputs)
}

fn collect_output_path(
    outputs: &mut Vec<CapturedRustcOutput>,
    seen_paths: &mut std::collections::BTreeSet<PathBuf>,
    path: Option<PathBuf>,
    kind: CapturedRustcOutputKind,
    require_exists: bool,
) -> stow_types::error::Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if !path.exists() {
        if require_exists {
            return Err(stow_types::stow_error!(
                "expected captured rustc output alias {} for {:?} is missing",
                path.display(),
                kind
            ));
        }
        return Ok(());
    }
    if !seen_paths.insert(path.clone()) {
        return Ok(());
    }
    outputs.push(CapturedRustcOutput { kind, path });
    Ok(())
}

fn validate_duplicate_output_kinds(outputs: &[CapturedRustcOutput]) -> stow_types::error::Result<()> {
    let mut digests_by_kind = std::collections::BTreeMap::new();
    for output in outputs {
        let bytes = std::fs::read(&output.path)
            .wrap_err_with(|| format!("read captured rustc output {}", output.path.display()))?;
        let digest = hex::encode(Sha256::digest(&bytes));
        if let Some(existing_digest) = digests_by_kind.get(&output.kind) {
            if existing_digest != &digest {
                return Err(stow_types::stow_error!(
                    "captured rustc outputs for {:?} disagree: {} != {}",
                    output.kind,
                    existing_digest,
                    digest
                ));
            }
            continue;
        }
        digests_by_kind.insert(output.kind, digest);
    }
    Ok(())
}

fn unique_capture_file_name(record: &CapturedRustcArtifact) -> stow_types::error::Result<String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| stow_types::stow_error!("system clock before UNIX_EPOCH: {error}"))?
        .as_nanos();
    Ok(format!(
        "{}-{}-{}-{}.json",
        record.crate_name.replace('-', "_"),
        record.c_metadata,
        std::process::id(),
        stamp
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::{
        CapturedRustcOutputKind, build_capture_record, collect_outputs, load_output_identity,
        record_capture_output_identities, unique_capture_file_name,
    };
    use stow_types::rustc::ParsedRustcArgs;

    fn parsed_lib(crate_name: &str, out_dir: PathBuf, extra_filename: &str) -> ParsedRustcArgs {
        ParsedRustcArgs {
            crate_name: crate_name.to_owned(),
            crate_types: vec!["lib".to_owned()],
            features: BTreeSet::new(),
            emit: BTreeSet::from([
                "dep-info".to_owned(),
                "link".to_owned(),
                "metadata".to_owned(),
            ]),
            json: BTreeSet::new(),
            input_path: None,
            target: Some("aarch64-apple-darwin".to_owned()),
            c_metadata: Some(extra_filename.trim_start_matches('-').to_owned()),
            out_dir: Some(out_dir),
            extra_filename: extra_filename.to_owned(),
            opt_level: Some("0".to_owned()),
            debuginfo: Some("1".to_owned()),
            panic_strategy: None,
            debug_assertions: Some(true),
            overflow_checks: Some(true),
            native_search_paths: Vec::new(),
            extern_crates: Vec::new(),
            has_custom_codegen: false,
        }
    }

    #[test]
    fn collect_outputs_includes_original_aliases_when_present() {
        let tempdir = tempdir().expect("tempdir");
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create out dir");

        let stable = parsed_lib("chrono", out_dir.clone(), "-47d1962f861b84d6");
        let original = parsed_lib("chrono", out_dir.clone(), "-9168d4b8524764cc");

        let stable_rlib = stable.output_rlib_path().expect("stable rlib");
        let stable_rmeta = stable.output_rmeta_path().expect("stable rmeta");
        let original_rlib = original.output_rlib_path().expect("original rlib");
        let original_rmeta = original.output_rmeta_path().expect("original rmeta");

        std::fs::write(&stable_rlib, b"chrono-rlib").expect("write stable rlib");
        std::fs::write(&stable_rmeta, b"chrono-rmeta").expect("write stable rmeta");
        std::fs::copy(&stable_rlib, &original_rlib).expect("copy original rlib");
        std::fs::copy(&stable_rmeta, &original_rmeta).expect("copy original rmeta");

        let outputs = collect_outputs(&stable, Some(&original)).expect("collect outputs");
        assert_eq!(outputs.len(), 4);
        assert_eq!(
            outputs
                .iter()
                .filter(|output| output.kind == CapturedRustcOutputKind::Rlib)
                .count(),
            2
        );
        assert_eq!(
            outputs
                .iter()
                .filter(|output| output.kind == CapturedRustcOutputKind::Rmeta)
                .count(),
            2
        );

        smol::block_on(async {
            let capture_dir = tempdir.path().join("capture");
            let record = build_capture_record(&stable, Some(&original), &capture_dir)
                .await
                .expect("capture record");
            assert_eq!(record.outputs.len(), 4);
            let _ = unique_capture_file_name(&record).expect("unique capture file name");
        });
    }

    #[test]
    fn collect_outputs_rejects_mismatched_duplicate_output_kind_bytes() {
        let tempdir = tempdir().expect("tempdir");
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create out dir");

        let stable = parsed_lib("chrono", out_dir.clone(), "-47d1962f861b84d6");
        let original = parsed_lib("chrono", out_dir.clone(), "-9168d4b8524764cc");

        std::fs::write(
            stable.output_rlib_path().expect("stable rlib"),
            b"stable-rlib",
        )
        .expect("write stable rlib");
        std::fs::write(
            stable.output_rmeta_path().expect("stable rmeta"),
            b"stable-rmeta",
        )
        .expect("write stable rmeta");
        std::fs::write(
            original.output_rlib_path().expect("original rlib"),
            b"original-rlib",
        )
        .expect("write original rlib");
        std::fs::write(
            original.output_rmeta_path().expect("original rmeta"),
            b"original-rmeta",
        )
        .expect("write original rmeta");

        let error = collect_outputs(&stable, Some(&original)).expect_err("mismatch should fail");
        assert!(
            error
                .to_string()
                .contains("captured rustc outputs for Rlib disagree")
        );
    }

    #[test]
    fn record_capture_output_identities_writes_stable_outputs_without_aliases() {
        smol::block_on(async {
            let tempdir = tempdir().expect("tempdir");
            let out_dir = tempdir.path().join("deps");
            let capture_dir = tempdir.path().join("capture");
            std::fs::create_dir_all(&out_dir).expect("create out dir");

            let parsed = parsed_lib("tokei", out_dir.clone(), "-fedf2529b3e2aa76");
            let rlib_path = parsed.output_rlib_path().expect("rlib");
            let rmeta_path = parsed.output_rmeta_path().expect("rmeta");
            std::fs::write(&rlib_path, b"tokei-rlib").expect("write rlib");
            std::fs::write(&rmeta_path, b"tokei-rmeta").expect("write rmeta");

            record_capture_output_identities(
                &parsed,
                None,
                "fedf2529b3e2aa76deadbeef",
                &capture_dir,
            )
            .await
            .expect("record capture identities");

            let rlib_compile_key = load_output_identity(&capture_dir, &rlib_path)
                .await
                .expect("load rlib compile key")
                .expect("rlib compile key")
                .compile_key;
            let rmeta_compile_key = load_output_identity(&capture_dir, &rmeta_path)
                .await
                .expect("load rmeta compile key")
                .expect("rmeta compile key")
                .compile_key;
            assert_eq!(rlib_compile_key, "fedf2529b3e2aa76deadbeef");
            assert_eq!(rmeta_compile_key, "fedf2529b3e2aa76deadbeef");
        });
    }

    #[test]
    fn collect_outputs_allows_missing_original_rlib_alias_for_metadata_only_units() {
        let tempdir = tempdir().expect("tempdir");
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create out dir");

        let mut stable = parsed_lib("memchr", out_dir.clone(), "-5f9bd34fd597ff84");
        stable.emit = BTreeSet::from(["dep-info".to_owned(), "metadata".to_owned()]);
        let mut original = parsed_lib("memchr", out_dir.clone(), "-74ba23c4585fed0d");
        original.emit = stable.emit.clone();

        std::fs::write(
            stable.output_rmeta_path().expect("stable rmeta"),
            b"memchr-rmeta",
        )
        .expect("write stable rmeta");
        std::fs::write(
            original.output_rmeta_path().expect("original rmeta"),
            b"memchr-rmeta",
        )
        .expect("write original rmeta");

        let outputs = collect_outputs(&stable, Some(&original)).expect("collect outputs");
        assert_eq!(outputs.len(), 2);
        assert_eq!(
            outputs
                .iter()
                .filter(|output| output.kind == CapturedRustcOutputKind::Rmeta)
                .count(),
            2
        );
        assert_eq!(
            outputs
                .iter()
                .filter(|output| output.kind == CapturedRustcOutputKind::Rlib)
                .count(),
            0
        );
    }

    fn parsed_proc_macro(
        crate_name: &str,
        out_dir: PathBuf,
        extra_filename: &str,
    ) -> ParsedRustcArgs {
        ParsedRustcArgs {
            crate_name: crate_name.to_owned(),
            crate_types: vec!["proc-macro".to_owned()],
            features: BTreeSet::new(),
            emit: BTreeSet::from(["dep-info".to_owned(), "metadata".to_owned()]),
            json: BTreeSet::new(),
            input_path: None,
            target: Some("aarch64-apple-darwin".to_owned()),
            c_metadata: Some(extra_filename.trim_start_matches('-').to_owned()),
            out_dir: Some(out_dir),
            extra_filename: extra_filename.to_owned(),
            opt_level: Some("0".to_owned()),
            debuginfo: Some("1".to_owned()),
            panic_strategy: None,
            debug_assertions: Some(true),
            overflow_checks: Some(true),
            native_search_paths: Vec::new(),
            extern_crates: Vec::new(),
            has_custom_codegen: false,
        }
    }

    #[test]
    fn collect_outputs_allows_proc_macro_metadata_without_dynamic_library_alias() {
        let tempdir = tempdir().expect("tempdir");
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create out dir");

        let stable = parsed_proc_macro("pest_derive", out_dir.clone(), "-098f75b919e2b10c");
        let original = parsed_proc_macro("pest_derive", out_dir.clone(), "-2f0c1ba89e51fd44");

        std::fs::write(
            stable.output_rmeta_path().expect("stable rmeta"),
            b"pest-derive-rmeta",
        )
        .expect("write stable rmeta");
        std::fs::write(
            original.output_rmeta_path().expect("original rmeta"),
            b"pest-derive-rmeta",
        )
        .expect("write original rmeta");

        let outputs = collect_outputs(&stable, Some(&original)).expect("collect outputs");
        assert_eq!(outputs.len(), 2);
        assert_eq!(
            outputs
                .iter()
                .filter(|output| output.kind == CapturedRustcOutputKind::Rmeta)
                .count(),
            2
        );
        assert_eq!(
            outputs
                .iter()
                .filter(|output| output.kind == CapturedRustcOutputKind::DynamicLibrary)
                .count(),
            0
        );
    }

    #[test]
    fn collect_outputs_allows_linked_static_libs_without_dynamic_library_alias() {
        let tempdir = tempdir().expect("tempdir");
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create out dir");

        let mut stable = parsed_lib("unicode_ident", out_dir.clone(), "-0e63365407e7f07c");
        stable.emit = BTreeSet::from([
            "dep-info".to_owned(),
            "metadata".to_owned(),
            "link".to_owned(),
        ]);
        let mut original = parsed_lib("unicode_ident", out_dir.clone(), "-3aeafff9a4e30afb");
        original.emit = stable.emit.clone();

        std::fs::write(
            stable.output_rlib_path().expect("stable rlib"),
            b"unicode-ident-rlib",
        )
        .expect("write stable rlib");
        std::fs::write(
            stable.output_rmeta_path().expect("stable rmeta"),
            b"unicode-ident-rmeta",
        )
        .expect("write stable rmeta");
        std::fs::write(
            original.output_rlib_path().expect("original rlib"),
            b"unicode-ident-rlib",
        )
        .expect("write original rlib");
        std::fs::write(
            original.output_rmeta_path().expect("original rmeta"),
            b"unicode-ident-rmeta",
        )
        .expect("write original rmeta");

        let outputs = collect_outputs(&stable, Some(&original)).expect("collect outputs");
        assert_eq!(
            outputs
                .iter()
                .filter(|output| output.kind == CapturedRustcOutputKind::Rlib)
                .count(),
            2
        );
        assert_eq!(
            outputs
                .iter()
                .filter(|output| output.kind == CapturedRustcOutputKind::Rmeta)
                .count(),
            2
        );
        assert_eq!(
            outputs
                .iter()
                .filter(|output| output.kind == CapturedRustcOutputKind::DynamicLibrary)
                .count(),
            0
        );
    }
}

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_process::Command;
use sha2::{Digest, Sha256};
use stow_types::capture::{
    CapturedDependencyIdentity, CapturedRustcArtifact, CapturedRustcOutput, CapturedRustcOutputKind,
};
use stow_types::error::Context;
use stow_types::public_cache::{
    StableRegistryArtifactIdentity, stable_registry_artifact_identity_for_package,
};
use stow_types::rustc::ParsedRustcArgs;

pub use stow_shim::CAPTURE_DIR_ENV as STOW_BUILD_CAPTURE_DIR_ENV;
pub const STOW_BUILD_CAPTURE_IPC_ENV: &str = "STOW_BUILD_CAPTURE_IPC";
pub const STOW_BUILD_TASK_CRATE_NAME_ENV: &str = "STOW_BUILD_TASK_CRATE_NAME";
pub const STOW_BUILD_TASK_CRATE_VERSION_ENV: &str = "STOW_BUILD_TASK_CRATE_VERSION";
const STOW_CAPTURE_COMMAND: &str = "stow-capture";
const OUTPUT_IDENTITY_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const OUTPUT_IDENTITY_WAIT_INTERVAL: Duration = Duration::from_millis(10);

pub fn is_rustc_wrapper_invocation(args: &[std::ffi::OsString]) -> bool {
    args.get(1)
        .and_then(|arg| arg.to_str())
        .is_some_and(|command| command == "rustc")
}

pub async fn run_rustc_capture_wrapper(
    args: &[std::ffi::OsString],
) -> stow_types::error::Result<()> {
    let rustc = args.get(2).ok_or_else(|| {
        stow_types::stow_error!("rustc capture mode requires rustc path as argv[2]")
    })?;
    let original_parsed = match ParsedRustcArgs::parse(&args[3..]) {
        Ok(parsed) => parsed,
        Err(error) if error.contains("missing --crate-name") => {
            let status = Command::new(rustc).args(&args[3..]).status().await?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(error) => {
            return Err(stow_types::stow_error!(
                "parse rustc wrapper arguments: {error}"
            ));
        }
    };
    if !original_parsed.is_restorable_artifact() {
        let status = Command::new(rustc).args(&args[3..]).status().await?;
        // Cargo units that produce nothing restorable are still reported, so
        // a record forged inside the sandbox collides with this genuine one
        // instead of slipping in unobserved. An invocation without
        // `-C metadata` is not a cargo unit at all — a build script or cargo
        // itself probing rustc — and has no identity anything could be
        // forged under, so it is run and never recorded: a build script may
        // probe as often as it likes under one crate name.
        if status.success()
            && let Some(c_metadata) = original_parsed.c_metadata.as_deref()
        {
            let record = observed_capture_record(&original_parsed, c_metadata)?;
            send_capture_record(record).await?;
        }
        std::process::exit(status.code().unwrap_or(1));
    }

    let capture_dir = capture_dir()?;
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

    // `prepare_stable_rustc_invocation` currently never yields `None` here;
    // if that changes, exiting silently would lose a restorable unit with no
    // record at all — fail instead so cargo surfaces the pipeline bug.
    let Some(parsed) = effective_parsed else {
        return Err(stow_types::stow_error!(
            "restorable rustc invocation for `{}` produced no parsed arguments to record",
            original_parsed.crate_name
        ));
    };
    let original_alias_source = stable_identity
        .as_ref()
        .map(|_| &original_parsed)
        .filter(|original| *original != &parsed);
    let output_identity = stable_identity
        .as_ref()
        .map(|identity| (identity.compile_key.as_str(), identity.c_metadata.as_str()))
        .or_else(|| {
            parsed
                .c_metadata
                .as_deref()
                .map(|c_metadata| (c_metadata, c_metadata))
        });
    if let Some((compile_key, c_metadata)) = output_identity {
        record_capture_output_identities(
            &parsed,
            original_alias_source,
            compile_key,
            c_metadata,
            &capture_dir,
        )
        .await?;
    }
    let record_compile_key = output_identity
        .map(|(compile_key, _)| compile_key.to_owned())
        .ok_or_else(|| {
            stow_types::stow_error!(
                "restorable rustc invocation for `{}` has no compile key identity",
                parsed.crate_name
            )
        })?;
    let record = build_capture_record(
        &parsed,
        original_alias_source,
        record_compile_key,
        &capture_dir,
    )
    .await?;
    send_capture_record(record).await?;
    replay_rustc_output(&output).await?;
    std::process::exit(0);
}

fn capture_dir() -> stow_types::error::Result<PathBuf> {
    std::env::var_os(STOW_BUILD_CAPTURE_DIR_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            stow_types::stow_error!("missing {STOW_BUILD_CAPTURE_DIR_ENV} for rustc capture")
        })
}

/// The registry package identity for a captured rustc invocation.
///
/// Path detection comes first: dependency crates build out of
/// `CARGO_HOME/registry/src/…/<name>-<version>/` and carry their identity in
/// the path. The task crate builds from the content-addressed workspace
/// mirror with a relative `src/lib.rs`, so the dispatcher supplies its
/// identity through `STOW_BUILD_TASK_CRATE_*` — applied only when the unit's
/// `--crate-name` matches, so a build script or unrelated target can never
/// be attributed to the task package.
fn capture_package_identity(
    parsed: &ParsedRustcArgs,
) -> stow_types::error::Result<Option<(String, String)>> {
    if let Some(identity) = stow_types::public_cache::detect_registry_crate_version(parsed)? {
        return Ok(Some(identity));
    }
    let (Some(name), Some(version)) = (
        std::env::var_os(STOW_BUILD_TASK_CRATE_NAME_ENV),
        std::env::var_os(STOW_BUILD_TASK_CRATE_VERSION_ENV),
    ) else {
        return Ok(None);
    };
    let name = name.to_str().ok_or_else(|| {
        stow_types::stow_error!("{STOW_BUILD_TASK_CRATE_NAME_ENV} is not valid UTF-8")
    })?;
    let version = version.to_str().ok_or_else(|| {
        stow_types::stow_error!("{STOW_BUILD_TASK_CRATE_VERSION_ENV} is not valid UTF-8")
    })?;
    if stow_types::public_cache::canonical_crate_name(&parsed.crate_name)
        != stow_types::public_cache::canonical_crate_name(name)
    {
        return Ok(None);
    }
    Ok(Some((name.to_owned(), version.to_owned())))
}

/// Hand the record to the host collector over the sandbox IPC channel.
///
/// The record never touches the sandbox filesystem: it crosses straight to
/// the host, so nothing inside the sandbox can edit or forge it after rustc
/// exits. `heel::IpcClient` is blocking by design (it serves short-lived shim
/// processes), so the call runs on the blocking pool.
async fn send_capture_record(record: CapturedRustcArtifact) -> stow_types::error::Result<()> {
    let endpoint = std::env::var_os(STOW_BUILD_CAPTURE_IPC_ENV)
        .map(PathBuf::from)
        .ok_or_else(|| {
            stow_types::stow_error!("missing {STOW_BUILD_CAPTURE_IPC_ENV} for rustc capture")
        })?;
    smol::unblock(move || {
        let mut client = heel::IpcClient::connect(&endpoint).map_err(|error| {
            stow_types::stow_error!(
                "connect capture IPC endpoint {}: {error}",
                endpoint.display()
            )
        })?;
        let accepted: Result<(), String> = client
            .call(STOW_CAPTURE_COMMAND, &record)
            .map_err(|error| stow_types::stow_error!("send capture record over IPC: {error}"))?;
        accepted.map_err(|error| stow_types::stow_error!("capture IPC rejected record: {error}"))
    })
    .await
}

/// The record for a cargo unit that produces nothing restorable: a
/// build-script compile, a binary, a test. Its identity still lands in the
/// capture set so that anything forged under that identity collides with it.
fn observed_capture_record(
    parsed: &ParsedRustcArgs,
    c_metadata: &str,
) -> stow_types::error::Result<CapturedRustcArtifact> {
    Ok(CapturedRustcArtifact {
        crate_name: parsed.crate_name.clone(),
        crate_version: capture_package_identity(parsed)?.map(|(_, version)| version),
        crate_types: parsed.crate_types.clone(),
        emit: parsed.emit.iter().cloned().collect(),
        target: parsed.target.clone(),
        // Observed units carry no stable identity; cargo's ephemeral
        // `-C metadata` is the only key they ever had.
        compile_key: c_metadata.to_owned(),
        c_metadata: c_metadata.to_owned(),
        extra_filename: parsed.extra_filename.clone(),
        dependencies: Vec::new(),
        profile: parsed.profile().map_err(stow_types::error::Error::msg)?,
        out_dir: parsed.out_dir.clone().unwrap_or_default(),
        target_dir: std::env::var_os("CARGO_TARGET_DIR").map_or_else(PathBuf::new, PathBuf::from),
        build_script_out_dir: std::env::var_os("OUT_DIR").map(PathBuf::from),
        outputs: Vec::new(),
        restorable: false,
    })
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
    let dependency_c_metadata_json = match resolve_dependency_c_metadata_json(
        capture_dir,
        original_parsed,
    )
    .await?
    {
        Some(value) => value,
        None if original_parsed.extern_crates.is_empty() => "[]".to_owned(),
        // Registry crates only ever depend on registry crates, and cargo
        // finishes building a dependency before any dependent rustc
        // invocation starts, so every `--extern` must already have a
        // materialized identity. A miss is a capture-pipeline bug; caching
        // this artifact under an ephemeral identity would poison the
        // registry with rows no CLI lookup can ever hit.
        None => {
            return Err(stow_types::stow_error!(
                "missing materialized dependency identity for `{}`: cannot derive a stable public-cache identity",
                original_parsed.crate_name
            ));
        }
    };
    let features_json =
        serde_json::to_string(&original_parsed.features.iter().cloned().collect::<Vec<_>>())?;
    // A restorable unit with no stable identity must not compile at all:
    // `run_rustc_capture_wrapper` would otherwise fall back to cargo's
    // ephemeral `-C metadata` as the record's compile key and register a row
    // no CLI lookup can ever hit — the silent-registry-poison failure this
    // pipeline exists to prevent.
    let Some((package_name, package_version)) = capture_package_identity(original_parsed)? else {
        return Err(stow_types::stow_error!(
            "restorable rustc invocation for `{}` has no stable identity (input path {:?})",
            original_parsed.crate_name,
            original_parsed.input_path,
        ));
    };
    let identity = stable_registry_artifact_identity_for_package(
        original_parsed,
        &package_name,
        &package_version,
        &effective_target,
        &toolchain.version,
        &features_json,
        &dependency_c_metadata_json,
    )?;
    let Some(original_c_metadata) = original_parsed.c_metadata.as_deref() else {
        return Err(stow_types::stow_error!(
            "restorable rustc invocation for `{}` is missing -C metadata",
            original_parsed.crate_name
        ));
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
    let rewritten_parsed = ParsedRustcArgs::parse(&rewritten_args).map_err(|error| {
        stow_types::stow_error!("parse rewritten rustc wrapper arguments: {error}")
    })?;
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
                extern_crate.path.clone(),
                output_identity_path(capture_dir, &extern_crate.path)?,
            ))
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
    identities.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));

    let mut resolved = Vec::with_capacity(identities.len());
    for (crate_name, output_path, identity_path) in identities {
        if !wait_for_output_identity_path(&identity_path, &output_path).await? {
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
    let mut iter = args.iter();
    let mut replaced_metadata = false;
    let mut replaced_extra_filename = false;

    while let Some(arg) = iter.next() {
        let Some(arg_str) = arg.to_str() else {
            rewritten.push(arg.clone());
            continue;
        };
        if arg_str == "-C" {
            let value = iter.next().ok_or_else(|| {
                stow_types::stow_error!("missing value after -C while rewriting rustc args")
            })?;
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
        &identity.c_metadata,
        capture_dir,
    )
    .await?;
    materialize_optional_alias(
        rewritten_parsed.output_rmeta_path(),
        original_parsed.output_rmeta_path(),
        &identity.compile_key,
        &identity.c_metadata,
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
        &identity.c_metadata,
        capture_dir,
    )
    .await?;
    materialize_optional_alias(
        rewritten_parsed.output_dep_info_path(),
        original_parsed.output_dep_info_path(),
        &identity.compile_key,
        &identity.c_metadata,
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
    c_metadata: &str,
    capture_dir: &std::path::Path,
) -> stow_types::error::Result<()> {
    let (Some(source_path), Some(alias_path)) = (source_path, alias_path) else {
        return Ok(());
    };
    if !source_path.exists() {
        return Ok(());
    }
    record_materialized_output_identity(capture_dir, &source_path, compile_key, c_metadata).await?;
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
    record_materialized_output_identity(capture_dir, &alias_path, compile_key, c_metadata).await?;
    Ok(())
}

#[derive(Debug, Clone)]
struct RustcToolchain {
    version: String,
    host_target: String,
}

async fn detect_rustc_toolchain(
    rustc: &std::ffi::OsString,
) -> stow_types::error::Result<RustcToolchain> {
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
    c_metadata: &str,
) -> stow_types::error::Result<()> {
    let record = MaterializedOutputIdentity {
        output_path: output_path_string(output_path)?,
        compile_key: compile_key.to_owned(),
        stable_c_metadata: c_metadata.to_owned(),
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
    c_metadata: &str,
    capture_dir: &std::path::Path,
) -> stow_types::error::Result<()> {
    for output in collect_outputs(parsed, original_alias_source)? {
        record_materialized_output_identity(capture_dir, &output.path, compile_key, c_metadata)
            .await?;
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
pub struct LoadedOutputIdentity {
    pub(crate) compile_key: String,
    pub(crate) stable_c_metadata: String,
}

pub async fn load_output_identity(
    capture_dir: &std::path::Path,
    output_path: &std::path::Path,
) -> stow_types::error::Result<Option<LoadedOutputIdentity>> {
    let identity_path = output_identity_path(capture_dir, output_path)?;
    if !wait_for_output_identity_path(&identity_path, output_path).await? {
        return Ok(None);
    }
    let bytes = async_fs::read(&identity_path).await?;
    let record = serde_json::from_slice::<MaterializedOutputIdentity>(&bytes)?;
    Ok(Some(LoadedOutputIdentity {
        compile_key: record.compile_key,
        stable_c_metadata: record.stable_c_metadata,
    }))
}

async fn wait_for_output_identity_path(
    identity_path: &std::path::Path,
    output_path: &std::path::Path,
) -> stow_types::error::Result<bool> {
    if identity_path.exists() {
        return Ok(true);
    }

    let deadline = Instant::now() + OUTPUT_IDENTITY_WAIT_TIMEOUT;
    loop {
        smol::Timer::after(OUTPUT_IDENTITY_WAIT_INTERVAL).await;
        if identity_path.exists() {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Err(stow_types::stow_error!(
                "timed out waiting for output identity sidecar {} for rustc output {}; cargo may have exposed the dependency through pipelining before stow finished recording its identity",
                identity_path.display(),
                output_path.display()
            ));
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DependencyIdentityRecord {
    crate_name: String,
    c_metadata: String,
}

async fn build_capture_record(
    parsed: &ParsedRustcArgs,
    original_alias_source: Option<&ParsedRustcArgs>,
    compile_key: String,
    capture_dir: &std::path::Path,
) -> stow_types::error::Result<CapturedRustcArtifact> {
    let c_metadata = parsed.c_metadata.clone().ok_or_else(|| {
        stow_types::stow_error!("cacheable rustc invocation is missing -C metadata")
    })?;
    let out_dir = parsed.out_dir.clone().ok_or_else(|| {
        stow_types::stow_error!("cacheable rustc invocation is missing --out-dir")
    })?;
    let outputs = snapshot_outputs(
        capture_dir,
        parsed,
        collect_outputs(parsed, original_alias_source)?,
    )
    .await?;
    if outputs.is_empty() {
        return Err(stow_types::stow_error!(
            "cacheable rustc invocation produced no restorable outputs for {}",
            parsed.crate_name
        ));
    }
    let dependencies = load_recorded_dependencies(capture_dir, parsed).await?;

    Ok(CapturedRustcArtifact {
        crate_name: parsed.crate_name.clone(),
        crate_version: capture_package_identity(parsed)?.map(|(_, version)| version),
        crate_types: parsed.crate_types.clone(),
        emit: parsed.emit.iter().cloned().collect(),
        target: parsed.target.clone(),
        compile_key,
        c_metadata,
        extra_filename: parsed.extra_filename.clone(),
        dependencies,
        // The same normalization the CLI applies when it looks an artifact up
        // (`stow_types::public_cache::normalized_cache_profile`), not the raw
        // `-C` flags. `parsed.profile()` reports debuginfo 0 when rustc was
        // given no `-C debuginfo`, while the lookup side reports 1 for that
        // case and for every metadata-only invocation. Storing the raw profile
        // made those two disagree by construction, so every pipelined
        // `--emit=metadata` unit missed, was evicted, and counted toward the
        // circuit breaker — which then bypassed the cache for the rest of the
        // build.
        profile: stow_types::public_cache::normalized_cache_profile(parsed)?,
        out_dir,
        target_dir: std::env::var_os("CARGO_TARGET_DIR").map_or_else(PathBuf::new, PathBuf::from),
        build_script_out_dir: std::env::var_os("OUT_DIR").map(PathBuf::from),
        outputs,
        restorable: true,
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
    dependencies
        .dedup_by(|left, right| left.crate_name == right.crate_name && left.path == right.path);
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
    // Hash the bytes rustc just wrote, before anything else in the build can
    // touch them. The scan re-hashes the file it plans against this digest.
    let bytes = std::fs::read(&path)
        .wrap_err_with(|| format!("read captured rustc output {}", path.display()))?;
    outputs.push(CapturedRustcOutput {
        kind,
        path,
        snapshot_path: None,
        sha256: hex::encode(Sha256::digest(&bytes)),
    });
    Ok(())
}

async fn snapshot_outputs(
    capture_dir: &std::path::Path,
    parsed: &ParsedRustcArgs,
    outputs: Vec<CapturedRustcOutput>,
) -> stow_types::error::Result<Vec<CapturedRustcOutput>> {
    if outputs.is_empty() {
        return Ok(outputs);
    }
    let c_metadata = parsed.c_metadata.as_deref().unwrap_or("no-metadata");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| stow_types::stow_error!("system clock before UNIX_EPOCH: {error}"))?
        .as_nanos();
    let snapshot_dir = capture_dir.join("output-snapshots").join(format!(
        "{}-{}-{}-{}",
        parsed.crate_name.replace('-', "_"),
        c_metadata,
        std::process::id(),
        stamp
    ));
    async_fs::create_dir_all(&snapshot_dir).await?;

    let mut snapshot_outputs = Vec::with_capacity(outputs.len());
    for mut output in outputs {
        let file_name = output
            .path
            .file_name()
            .ok_or_else(|| {
                stow_types::stow_error!(
                    "captured rustc output {} has no file name",
                    output.path.display()
                )
            })?
            .to_owned();
        let snapshot_path = snapshot_dir.join(file_name);
        let source_path = output.path.clone();
        let snapshot_for_copy = snapshot_path.clone();
        smol::unblock(move || {
            reflink::reflink_or_copy(&source_path, &snapshot_for_copy).wrap_err_with(|| {
                format!(
                    "snapshot rustc output {} into {}",
                    source_path.display(),
                    snapshot_for_copy.display()
                )
            })
        })
        .await?;
        // The recorded digest describes the output at rustc exit; the snapshot
        // has to carry exactly those bytes, so a rewrite that landed between
        // hashing and copying fails here instead of reaching the scan.
        let snapshot_bytes = async_fs::read(&snapshot_path).await.wrap_err_with(|| {
            format!("read snapshot of rustc output {}", snapshot_path.display())
        })?;
        if hex::encode(Sha256::digest(&snapshot_bytes)) != output.sha256 {
            return Err(stow_types::stow_error!(
                "snapshot {} does not match the rustc-exit digest {} of {}",
                snapshot_path.display(),
                output.sha256,
                output.path.display()
            ));
        }
        output.snapshot_path = Some(snapshot_path);
        snapshot_outputs.push(output);
    }
    Ok(snapshot_outputs)
}

fn validate_duplicate_output_kinds(
    outputs: &[CapturedRustcOutput],
) -> stow_types::error::Result<()> {
    let mut digests_by_kind = std::collections::BTreeMap::new();
    for output in outputs {
        if let Some(existing_digest) = digests_by_kind.get(&output.kind) {
            if existing_digest != &output.sha256 {
                return Err(stow_types::stow_error!(
                    "captured rustc outputs for {:?} disagree: {} != {}",
                    output.kind,
                    existing_digest,
                    output.sha256
                ));
            }
            continue;
        }
        digests_by_kind.insert(output.kind, output.sha256.clone());
    }
    Ok(())
}

/// What makes one rustc invocation a distinct unit for collision purposes.
///
/// Keyed on the spec tuple — crate name, version, `-C metadata`, the kinds of
/// output produced and the emit set — plus `target`, `out_dir` and
/// `target_dir`, which are what tell apart a legitimately repeated unit: the
/// same crate compiled once per cargo phase (the phases build into separate
/// target dirs). Every record has a `-C metadata`; invocations without one
/// (rustc probes) never reach the collector.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct CaptureIdentity {
    crate_name: String,
    crate_version: Option<String>,
    c_metadata: String,
    output_kinds: Vec<CapturedRustcOutputKind>,
    emit: Vec<String>,
    target: Option<String>,
    out_dir: PathBuf,
    target_dir: PathBuf,
}

impl CaptureIdentity {
    fn of(record: &CapturedRustcArtifact) -> Self {
        let mut output_kinds = record
            .outputs
            .iter()
            .map(|output| output.kind)
            .collect::<Vec<_>>();
        output_kinds.sort();
        output_kinds.dedup();
        let mut emit = record.emit.clone();
        emit.sort();
        emit.dedup();
        Self {
            crate_name: record.crate_name.clone(),
            crate_version: record.crate_version.clone(),
            c_metadata: record.c_metadata.clone(),
            output_kinds,
            emit,
            target: record.target.clone(),
            out_dir: record.out_dir.clone(),
            target_dir: record.target_dir.clone(),
        }
    }
}

/// Host-side collector behind the `stow-capture` IPC command.
///
/// The sandboxed wrapper sends one record per rustc invocation it wraps; a
/// second record for an identity means a sandboxed process other than the
/// wrapper spoke on the channel, which is fatal to the whole build stage —
/// never silently ignored.
pub struct CaptureCollector {
    receiver: smol::channel::Receiver<CapturedRustcArtifact>,
    records: std::collections::BTreeMap<CaptureIdentity, CapturedRustcArtifact>,
}

impl CaptureCollector {
    /// The command registered on the sandbox's IPC router, plus the collector
    /// the records land in.
    pub fn channel() -> (Self, StowCaptureCommand) {
        let (sender, receiver) = smol::channel::unbounded();
        (
            Self {
                receiver,
                records: std::collections::BTreeMap::new(),
            },
            StowCaptureCommand { sender },
        )
    }

    /// Absorb every record the phase has delivered so far, failing on a
    /// duplicate identity. Runs after the phase's cargo exits; the error names
    /// the phase and carries both records.
    pub fn drain(&mut self, phase: &str) -> stow_types::error::Result<()> {
        while let Ok(record) = self.receiver.try_recv() {
            let identity = CaptureIdentity::of(&record);
            if let Some(existing) = self.records.insert(identity, record.clone()) {
                return Err(stow_types::stow_error!(
                    "cargo {phase} yielded two capture records for one rustc unit {} {} (c_metadata {}):\n{}\n{}",
                    record.crate_name,
                    record.crate_version.as_deref().unwrap_or("<unknown>"),
                    record.c_metadata,
                    serde_json::to_string(&existing)?,
                    serde_json::to_string(&record)?
                ));
            }
        }
        Ok(())
    }

    /// All collected records, in the deterministic order the file-based
    /// capture used to produce.
    ///
    /// Drains the channel once more first: a record still in flight at this
    /// point arrived after the last phase's drain — an IPC delivery outside
    /// the window the collector accounts for — so it is fatal, never dropped.
    pub fn into_records(self) -> stow_types::error::Result<Vec<CapturedRustcArtifact>> {
        if let Ok(record) = self.receiver.try_recv() {
            return Err(stow_types::stow_error!(
                "capture collector received a record for {} {} (c_metadata {}) after the final phase drained",
                record.crate_name,
                record.crate_version.as_deref().unwrap_or("<unknown>"),
                record.c_metadata
            ));
        }
        let mut records = self.records.into_values().collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.crate_name
                .cmp(&right.crate_name)
                .then(left.c_metadata.cmp(&right.c_metadata))
                .then(left.extra_filename.cmp(&right.extra_filename))
        });
        Ok(records)
    }
}

/// The `stow-capture` host command: park each record until the collector
/// drains. `Response` carries `Err` only when the channel is closed — a
/// duplicate is not reported to the caller, it aborts the phase at drain.
/// Cloned once per phase; every clone feeds the same collector channel.
#[derive(Clone)]
pub struct StowCaptureCommand {
    sender: smol::channel::Sender<CapturedRustcArtifact>,
}

impl heel::IpcCommand for StowCaptureCommand {
    fn name(&self) -> std::borrow::Cow<'static, str> {
        STOW_CAPTURE_COMMAND.into()
    }

    type Args = CapturedRustcArtifact;
    type Response = Result<(), String>;

    fn handle(
        &self,
        record: CapturedRustcArtifact,
    ) -> impl std::future::Future<Output = Self::Response> + Send {
        std::future::ready(self.sender.try_send(record).map_err(|error| {
            let record = error.into_inner();
            format!(
                "capture collector is closed; cannot record {} {}",
                record.crate_name, record.c_metadata
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::{
        CapturedRustcOutputKind, build_capture_record, collect_outputs, load_output_identity,
        record_capture_output_identities,
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
            embed_metadata: None,
            has_custom_codegen: false,
        }
    }

    #[test]
    fn collect_outputs_includes_original_aliases_when_present() {
        let tempdir = tempdir().expect("tempdir");
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create out dir");

        let stable = parsed_lib("chrono", out_dir.clone(), "-47d1962f861b84d6");
        let original = parsed_lib("chrono", out_dir, "-9168d4b8524764cc");

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
            let record = build_capture_record(
                &stable,
                Some(&original),
                "test-compile-key".to_owned(),
                &capture_dir,
            )
            .await
            .expect("capture record");
            assert_eq!(record.outputs.len(), 4);
            assert!(
                record
                    .outputs
                    .iter()
                    .all(|output| output.sha256.len() == 64),
                "every recorded output carries its rustc-exit sha256"
            );
        });
    }

    #[test]
    fn collect_outputs_rejects_mismatched_duplicate_output_kind_bytes() {
        let tempdir = tempdir().expect("tempdir");
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create out dir");

        let stable = parsed_lib("chrono", out_dir.clone(), "-47d1962f861b84d6");
        let original = parsed_lib("chrono", out_dir, "-9168d4b8524764cc");

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
                "fedf2529b3e2aa76",
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
        let mut original = parsed_lib("memchr", out_dir, "-74ba23c4585fed0d");
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
            embed_metadata: None,
            has_custom_codegen: false,
        }
    }

    #[test]
    fn collect_outputs_allows_proc_macro_metadata_without_dynamic_library_alias() {
        let tempdir = tempdir().expect("tempdir");
        let out_dir = tempdir.path().join("deps");
        std::fs::create_dir_all(&out_dir).expect("create out dir");

        let stable = parsed_proc_macro("pest_derive", out_dir.clone(), "-098f75b919e2b10c");
        let original = parsed_proc_macro("pest_derive", out_dir, "-2f0c1ba89e51fd44");

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
        let mut original = parsed_lib("unicode_ident", out_dir, "-3aeafff9a4e30afb");
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

    fn sample_record(c_metadata: &str, target_dir: PathBuf) -> super::CapturedRustcArtifact {
        super::CapturedRustcArtifact {
            crate_name: "itoa".to_owned(),
            crate_version: Some("1.0.15".to_owned()),
            crate_types: vec!["lib".to_owned()],
            emit: vec![
                "dep-info".to_owned(),
                "link".to_owned(),
                "metadata".to_owned(),
            ],
            target: Some("aarch64-apple-darwin".to_owned()),
            compile_key: format!("{c_metadata}deadbeef"),
            c_metadata: c_metadata.to_owned(),
            extra_filename: format!("-{c_metadata}"),
            dependencies: Vec::new(),
            profile: stow_types::platform::Profile {
                opt_level: "0".to_owned(),
                debuginfo: 1,
                debug_assertions: true,
                overflow_checks: true,
                panic: stow_types::platform::PanicStrategy::Unwind,
            },
            out_dir: target_dir.join("debug/deps"),
            target_dir,
            build_script_out_dir: None,
            outputs: Vec::new(),
            restorable: true,
        }
    }

    #[test]
    fn collector_rejects_a_duplicate_identity() {
        let (mut collector, command) = super::CaptureCollector::channel();
        let record = sample_record("47d1962f861b84d6", PathBuf::from("/tmp/target-build"));

        smol::block_on(async {
            use heel::IpcCommand;
            command.handle(record.clone()).await.expect("first record");
            // A forged second record under the same identity: accepted into
            // the channel like any caller, then fatal at drain.
            command.handle(record).await.expect("second record");
        });

        let error = collector.drain("build").expect_err("duplicate is fatal");
        assert!(
            error.to_string().contains("two capture records"),
            "error names the collision: {error}"
        );
    }

    #[test]
    fn collector_distinguishes_phases_by_target_dir() {
        let (mut collector, command) = super::CaptureCollector::channel();
        let check = sample_record("47d1962f861b84d6", PathBuf::from("/tmp/target-check"));
        let build = sample_record("47d1962f861b84d6", PathBuf::from("/tmp/target-build"));

        smol::block_on(async {
            use heel::IpcCommand;
            command.handle(check).await.expect("check record");
            command.handle(build).await.expect("build record");
        });

        collector
            .drain("build")
            .expect("the same unit in a second phase is not a duplicate");
        assert_eq!(collector.into_records().expect("records").len(), 2);
    }

    #[test]
    fn a_record_arriving_after_the_final_drain_is_fatal() {
        let (collector, command) = super::CaptureCollector::channel();
        smol::block_on(async {
            use heel::IpcCommand;
            command
                .handle(sample_record(
                    "0e63365407e7f07c",
                    PathBuf::from("/tmp/target-check"),
                ))
                .await
                .expect("check record");
        });
        // No drain between the send and into_records: the record is still in
        // flight, which is exactly the lost-record case the invariant rejects.
        let error = collector
            .into_records()
            .expect_err("an undrained record must be fatal");
        assert!(
            error.to_string().contains("after the final phase drained"),
            "{error}"
        );
    }

    #[test]
    fn capture_record_round_trips_through_the_ipc_channel() {
        smol::block_on(async {
            let working = tempdir().expect("working dir");
            let (mut collector, command) = super::CaptureCollector::channel();
            let heel_binary = std::env::current_exe().expect("current exe");
            let mut sandbox = heel::Sandbox::with_config(
                heel::SandboxConfigBuilder::default()
                    .network(heel::AllowAll)
                    .working_dir(working.path())
                    .heel_binary(&heel_binary)
                    .ipc(heel::IpcRouter::new().register(command))
                    .build(),
            )
            .await
            .expect("ipc sandbox");
            sandbox.keep_working_dir();
            let endpoint = sandbox.ipc_endpoint().expect("ipc endpoint").to_path_buf();

            let record = sample_record("0e63365407e7f07c", PathBuf::from("/tmp/target-build"));
            let sent = record.clone();
            smol::unblock(move || {
                let mut client = heel::IpcClient::connect(&endpoint).expect("connect");
                let accepted: Result<(), String> = client
                    .call(super::STOW_CAPTURE_COMMAND, &sent)
                    .expect("call");
                accepted.expect("accepted");
            })
            .await;

            collector.drain("check").expect("drain");
            assert_eq!(collector.into_records().expect("records"), vec![record]);
        });
    }

    #[test]
    fn restorable_unit_without_stable_identity_is_fatal() {
        smol::block_on(async {
            // The task env is only ever set inside the build sandbox, so a
            // relative input path leaves no identity to compute here.
            let capture_dir = tempdir().expect("capture dir");
            let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
            let args = vec![std::ffi::OsString::from("src/lib.rs")];
            let mut parsed = parsed_lib(
                "itoa",
                PathBuf::from("/tmp/target-check/debug/deps"),
                "-c89425c946911fe2",
            );
            parsed.input_path = Some(PathBuf::from("src/lib.rs"));

            let error =
                super::prepare_stable_rustc_invocation(&rustc, &args, &parsed, capture_dir.path())
                    .await
                    .expect_err("a restorable unit without a stable identity must be fatal");
            assert!(error.to_string().contains("no stable identity"), "{error}");
        });
    }
}

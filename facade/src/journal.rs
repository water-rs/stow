//! The pending-cc journal a build's cold-path `stow cc` facades append to.
//!
//! It is the deferred-store record drained after cargo exits, so the
//! facade never pays the content-key/preprocess/store pipeline for a
//! compile nothing could have served (stow#347).

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use stow_types::error::Context;

use crate::cc::ResolvedCompiler;

/// File prefix of a pending-cc journal inside the build's target dir.
pub const CC_PENDING_PREFIX: &str = "stow-cc-pending.";
/// File suffix of a pending-cc journal.
pub const CC_PENDING_SUFFIX: &str = ".jsonl";

/// The env var carrying the journal path to this build's `stow cc`
/// facades — its presence is the once-per-build cold decision (stow#347).
pub const CC_PENDING_ENV: &str = "STOW_CC_PENDING_JOURNAL";

/// One deferred C-object store.
///
/// The compiler identity and arguments the drain replays to compute the
/// content key, then store the object — the work a cold-cache `stow cc`
/// facade never pays (stow#347).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct CcPendingEntry {
    /// The compiler program the facade exec'd.
    pub program: String,
    /// Its environment overrides.
    pub env: Vec<(String, String)>,
    /// The wrapped compiler arguments.
    pub args: Vec<String>,
    /// Whether the compile succeeded — a failure records an error,
    /// never a store.
    pub success: bool,
}

/// The journal a build's cold-path cc facades append to:
/// `<target_dir>/stow-cc-pending.<build>.jsonl`, drained like the miss
/// journal it sits beside.
#[must_use]
pub fn cc_pending_path(target_dir: &Path, build: &str) -> PathBuf {
    target_dir.join(format!("{CC_PENDING_PREFIX}{build}{CC_PENDING_SUFFIX}"))
}

/// A cold-path cc facade's deferred-store record: the compiler it ran
/// and the compile's outcome. Non-UTF-8 arguments cannot be journaled
/// faithfully, so the entry — never the compile — is dropped.
///
/// # Errors
///
/// Serialization failures and the journal file's own write errors.
pub fn append_cc_pending(
    journal: &Path,
    compiler: &ResolvedCompiler,
    args: &[OsString],
    success: bool,
) -> stow_types::error::Result<()> {
    let Some(program) = compiler.program.to_str().map(str::to_owned) else {
        return Ok(());
    };
    let Some(env) = compiler
        .env
        .iter()
        .map(|(key, value)| Some((key.to_str()?.to_owned(), value.to_str()?.to_owned())))
        .collect::<Option<Vec<_>>>()
    else {
        return Ok(());
    };
    let Some(args) = args
        .iter()
        .map(|arg| arg.to_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
    else {
        return Ok(());
    };
    let entry = CcPendingEntry {
        program,
        env,
        args,
        success,
    };
    let line = serde_json::to_string(&entry)
        .map_err(|error| stow_types::stow_error!("serialize a pending C compile: {error}"))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(journal)
        .wrap_err_with(|| format!("open pending C compile journal {}", journal.display()))?;
    file.write_all(line.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .wrap_err_with(|| format!("append to pending C compile journal {}", journal.display()))
        .map_err(|error| stow_types::stow_error!("{error}"))
}

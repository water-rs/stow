//! Rustc capture records shared between the capture wrapper and the build
//! stage.
//!
//! The wrapper runs inside the untrusted sandbox and hands each record to the
//! host over heel's IPC channel, so a record on the host is the host's own
//! copy of what rustc did — never a file the sandbox could rewrite after the
//! fact. Keeping the type here means the wrapper side and the collector side
//! serialize exactly the same shape.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::platform::Profile;

/// One rustc invocation the capture wrapper observed, recorded as it exited.
///
/// Every invocation cargo routes through the wrapper produces a record — not
/// only the ones whose outputs are restorable artifacts — so that a record
/// forged inside the sandbox collides with the genuine one the wrapper sent.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CapturedRustcArtifact {
    pub crate_name: String,
    /// The crate version this invocation actually compiled, read from the
    /// registry source path.
    ///
    /// Recorded because a dependency graph can legitimately contain two
    /// versions of one crate (bitflags 1.3.2 alongside 2.5.0, say), and they
    /// share a library target name. Attributing captures by name alone let one
    /// version's compiled bytes be registered under the other's identity.
    #[serde(default)]
    pub crate_version: Option<String>,
    pub crate_types: Vec<String>,
    pub emit: Vec<String>,
    pub target: Option<String>,
    /// Full compile key of this invocation: the 64-hex blake3 stable identity
    /// for registry crates, or cargo's ephemeral `-C metadata` for
    /// non-registry roots. `c_metadata` is its 16-hex stable prefix.
    ///
    /// Empty for invocations with no `-C metadata` (rustc probes carry none).
    pub compile_key: String,
    /// Empty for invocations with no `-C metadata`.
    pub c_metadata: String,
    pub extra_filename: String,
    /// Resolved dependency identities for restorable units; always empty for
    /// observed ones (nothing downstream resolves their externs).
    pub dependencies: Vec<CapturedDependencyIdentity>,
    pub profile: Profile,
    /// Cargo's `--out-dir` for this invocation; empty for rustc probes, which
    /// take no `--out-dir`.
    pub out_dir: PathBuf,
    /// The `CARGO_TARGET_DIR` the invocation ran under. The same unit is
    /// legitimately compiled once per cargo phase, and the phase's target dir
    /// is what tells those records apart.
    #[serde(default)]
    pub target_dir: PathBuf,
    /// Cargo's `OUT_DIR` env for crates with a build script: the exact
    /// per-invocation build dir, recorded so native-artifact capture never
    /// has to guess which `{crate}-{hash}` directory belongs to this
    /// invocation.
    #[serde(default)]
    pub build_script_out_dir: Option<PathBuf>,
    pub outputs: Vec<CapturedRustcOutput>,
    /// `true` when this unit's outputs are artifacts the pipeline plans and
    /// publishes; `false` for units that produce nothing publishable
    /// (build-script compiles, binaries, tests, rustc probes), which are
    /// recorded purely so a forged record has something to collide with.
    #[serde(default)]
    pub restorable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapturedDependencyIdentity {
    pub crate_name: String,
    pub path: PathBuf,
    pub compile_key: String,
    pub stable_c_metadata: String,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum CapturedRustcOutputKind {
    Rlib,
    Rmeta,
    DynamicLibrary,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CapturedRustcOutput {
    pub kind: CapturedRustcOutputKind,
    pub path: PathBuf,
    #[serde(default)]
    pub snapshot_path: Option<PathBuf>,
    /// SHA-256 of the bytes at `path`, computed by the wrapper the moment
    /// rustc exited. The scan re-hashes the file it is about to plan and
    /// requires equality, so an output rewritten after rustc finished can
    /// never reach the plan.
    pub sha256: String,
}

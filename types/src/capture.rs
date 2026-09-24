//! Rustc capture records shared between the capture wrapper and the build
//! stage.
//!
//! The wrapper runs inside the untrusted sandbox and hands each record to the
//! host over heel's IPC channel, so a record on the host is the host's own
//! copy of what rustc did — never a file the sandbox could rewrite after the
//! fact. Keeping the type here means the wrapper side and the collector side
//! serialize exactly the same shape.

use std::path::PathBuf;

use crate::platform::Profile;

/// One rustc invocation the capture wrapper observed, recorded as it exited.
///
/// Every cargo unit routed through the wrapper produces a record — not only
/// the ones whose outputs are restorable artifacts — so that a record forged
/// inside the sandbox collides with the genuine one the wrapper sent. An
/// invocation with no `-C metadata` is not a cargo unit (a build script or
/// cargo itself probing rustc); it runs unrecorded, so an empty `c_metadata`
/// arriving on the channel can only be a forgery.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapturedRustcArtifact {
    /// The `--crate-name` rustc was invoked with.
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
    /// The `--crate-type` list rustc was invoked with.
    pub crate_types: Vec<String>,
    /// The `--emit` list rustc was invoked with.
    pub emit: Vec<String>,
    /// The `--target` triple rustc was invoked with, when cargo passed one.
    pub target: Option<String>,
    /// Full compile key of this invocation: the 64-hex blake3 stable identity
    /// for registry crates, or cargo's ephemeral `-C metadata` for
    /// non-registry roots. `c_metadata` is its 16-hex stable prefix.
    ///
    pub compile_key: String,
    /// Cargo's `-C metadata` for this invocation, or its stable prefix when
    /// the invocation was rewritten under a stable identity. Never empty in a
    /// genuine record.
    pub c_metadata: String,
    /// Cargo's `-C extra-filename` for this invocation.
    pub extra_filename: String,
    /// Resolved dependency identities for restorable units; always empty for
    /// observed ones (nothing downstream resolves their externs).
    pub dependencies: Vec<CapturedDependencyIdentity>,
    /// The effective rustc profile (`opt-level`, `debuginfo`, …) of this
    /// invocation.
    pub profile: Profile,
    /// Cargo's `--out-dir` for this invocation; empty when the unit took
    /// none.
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
    /// The outputs rustc wrote, each with the digest taken as rustc exited.
    pub outputs: Vec<CapturedRustcOutput>,
    /// `true` when this unit's outputs are artifacts the pipeline plans and
    /// publishes; `false` for cargo units that produce nothing publishable
    /// (build-script compiles, binaries, tests), which are recorded purely so
    /// a forged record has something to collide with.
    #[serde(default)]
    pub restorable: bool,
    /// `true` when the unit was served from a verified published artifact
    /// instead of compiled: no rustc ran, so nothing is planned, but the
    /// record still carries the artifact's identity and output paths so
    /// dependents can resolve their `--extern` edges against it and the
    /// publish stage can check the claim against the signed index.
    #[serde(default)]
    pub consumed: bool,
    /// The cargo invocation spelling the unit was produced under —
    /// `native` for a plain build, `target` for a `--target` build. The
    /// sandbox payload never sets it: the collector stamps it from the
    /// invocation it ran, so a forged record cannot claim a spelling it
    /// did not compile under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation: Option<crate::public_cache::UnitInvocation>,
    /// Wall-clock milliseconds the rustc invocation took — what a cache hit
    /// on this artifact saves a consumer. Records captured before the field
    /// existed carry no timing and count as zero.
    #[serde(default)]
    pub compile_millis: u64,
}

/// One dependency edge of a captured invocation: which `--extern` it was
/// given and which stable identity that extern resolved to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapturedDependencyIdentity {
    /// The crate name the `--extern` flag names.
    pub crate_name: String,
    /// The artifact path the `--extern` flag points at.
    pub path: PathBuf,
    /// The full stable compile key of that dependency's own invocation.
    pub compile_key: String,
    /// The 16-hex stable `-C metadata` prefix of that dependency.
    pub stable_c_metadata: String,
}

/// The kind of artifact one captured rustc output is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum CapturedRustcOutputKind {
    /// A `lib*.rlib` static Rust crate archive.
    Rlib,
    /// A `lib*.rmeta` metadata-only output.
    Rmeta,
    /// A `lib*.{so,dylib,dll}` dynamic library output.
    DynamicLibrary,
}

/// One file rustc wrote for a captured invocation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapturedRustcOutput {
    /// Which kind of artifact this output is.
    pub kind: CapturedRustcOutputKind,
    /// Where rustc wrote it inside the invocation's `--out-dir`.
    pub path: PathBuf,
    /// The frozen copy the wrapper took at rustc exit, when one exists.
    #[serde(default)]
    pub snapshot_path: Option<PathBuf>,
    /// SHA-256 of the bytes at `path`, computed by the wrapper the moment
    /// rustc exited. The scan re-hashes the file it is about to plan and
    /// requires equality, so an output rewritten after rustc finished can
    /// never reach the plan.
    pub sha256: String,
}

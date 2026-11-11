//! The wire between the rustc facade and the build's session.
//!
//! One length-prefixed JSON frame per message, both directions. The
//! wrapper asks what to do with one rustc invocation and, when it is told
//! to compile, reports the result so the session can finish the work
//! that only exists after a real compile (stable aliases, output
//! bookkeeping). The session answers the report with a receipt that
//! precedes that work, so the facade exits with rustc.

use std::ffi::OsString;

use serde::{Deserialize, Serialize};

use super::session::os_bytes;

/// What the facade sends.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Request {
    /// One rustc invocation, before anything has run.
    Plan(Plan),
    /// The result of a compile the session asked for. Answered with
    /// [`Answer::Received`] before the session's bookkeeping, which the
    /// facade never waits for (stow#1431).
    Compiled(Compiled),
    /// The C compiler wrapper asking whether the object cache holds the
    /// object a keyed invocation would produce. Answered with
    /// [`Answer::CcHit`] or [`Answer::CcMiss`]; a hit's records are
    /// written after the answer.
    CcLookup(CcLookup),
    /// The C compiler wrapper reporting the compile a [`Answer::CcMiss`]
    /// sent it to run. Answered with [`Answer::Received`] once the object
    /// is snapshotted; the store and its records follow the answer.
    CcCompiled(CcCompiled),
    /// Whether the build's C/C++ object cache is on. Asked before the
    /// wrapper spends the compiler on a cache key. Answered with
    /// [`Answer::CcPolicy`].
    CcPolicy,
}

impl Request {
    /// Parse the JSON body of one request frame — the deserialize half
    /// of [`read_frame`], for a peer reading frames on a blocking
    /// transport.
    ///
    /// # Errors
    ///
    /// Malformed JSON.
    pub fn from_frame_body(body: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(body).map_err(|error| format!("decode frame: {error}"))
    }
}

/// The per-invocation environment the deciding process cannot read for
/// itself.
///
/// The daemon's environment is not the invocation's, so the facade carries the values the
/// classification needs (stow#1006).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvocationEnv {
    /// The invocation's `CARGO_PRIMARY_PACKAGE` fact — set on the units of
    /// the crate cargo is building, which are never cached.
    pub primary_package: bool,
    /// The invocation's `CARGO_MANIFEST_DIR` — cargo sets it on every
    /// rustc call — OS-encoded like the argv. The git-source detection
    /// reads the manifest path inside the checkout from it rather than
    /// probing ancestor directories for a `Cargo.toml`.
    pub manifest_dir: Option<Vec<u8>>,
    /// The invocation's `OUT_DIR` — set on the units of a crate with a
    /// build script — OS-encoded like the argv. The output file beside it
    /// says which `--cfg` and link arguments the build script, rather than
    /// the consumer, put on the command line (stow#1047).
    pub out_dir: Option<Vec<u8>>,
    /// The invocation's working directory — what a relative spelling in
    /// its argv or environment resolves against — OS-encoded like the
    /// argv. Cargo runs rustc in the workspace root or the package
    /// directory, which is not the directory the deciding process runs in.
    pub cwd: Option<Vec<u8>>,
}

impl InvocationEnv {
    /// The values this process's invocation carries — only ever called in
    /// the facade, which IS the invocation process.
    #[must_use]
    pub fn current() -> Self {
        Self {
            primary_package: std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some(),
            manifest_dir: std::env::var_os("CARGO_MANIFEST_DIR")
                .map(|value| os_bytes::encode(&value)),
            out_dir: std::env::var_os("OUT_DIR").map(|value| os_bytes::encode(&value)),
            cwd: std::env::current_dir()
                .ok()
                .map(|dir| os_bytes::encode(dir.as_os_str())),
        }
    }

    /// An environment with no variables set, running in `cwd`.
    #[must_use]
    pub fn in_dir(cwd: &std::path::Path) -> Self {
        Self {
            cwd: Some(os_bytes::encode(cwd.as_os_str())),
            ..Self::default()
        }
    }

    /// An environment with no variables set, running in the test's own
    /// working directory.
    ///
    /// # Panics
    ///
    /// The working directory cannot be read.
    #[cfg(test)]
    #[must_use]
    pub fn for_tests() -> Self {
        Self::in_dir(&std::env::current_dir().expect("the test's working directory"))
    }

    /// The decoded working directory.
    ///
    /// # Errors
    ///
    /// When the peer's encoding is not decodable on this platform.
    pub fn cwd(&self) -> Result<Option<std::path::PathBuf>, String> {
        self.cwd
            .as_ref()
            .map(|bytes| os_bytes::decode(bytes).map(std::path::PathBuf::from))
            .transpose()
    }

    /// The decoded `CARGO_MANIFEST_DIR`.
    ///
    /// # Errors
    ///
    /// When the peer's encoding is not decodable on this platform.
    pub fn manifest_dir(&self) -> Result<Option<std::path::PathBuf>, String> {
        self.manifest_dir
            .as_ref()
            .map(|bytes| os_bytes::decode(bytes).map(std::path::PathBuf::from))
            .transpose()
    }

    /// The decoded `OUT_DIR`.
    ///
    /// # Errors
    ///
    /// When the peer's encoding is not decodable on this platform.
    pub fn out_dir(&self) -> Result<Option<std::path::PathBuf>, String> {
        self.out_dir
            .as_ref()
            .map(|bytes| os_bytes::decode(bytes).map(std::path::PathBuf::from))
            .transpose()
    }
}

/// One rustc invocation as the facade received it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Plan {
    /// The real rustc cargo asked for.
    pub executable: Vec<u8>,
    /// Everything after the executable, in order.
    pub args: Vec<Vec<u8>>,
    /// The invocation's environment the daemon cannot see.
    pub env: InvocationEnv,
}

/// The facade reporting the compile the session asked for. The session
/// answers it with a receipt that precedes its bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Compiled {
    /// Whether rustc exited successfully.
    pub success: bool,
    /// How long rustc ran, in milliseconds: the compile time a later local
    /// hit on this unit saves.
    pub compile_millis: u64,
}

/// One keyed C/C++ compile as the wrapper computed it: the key covers
/// everything that shapes the object, so the daemon never sees the
/// command line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CcLookup {
    /// The object's cache key.
    pub cache_key: String,
}

/// The wrapper reporting the compile a [`CcLookup`] miss sent it to run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CcCompiled {
    /// The key the miss was for.
    pub cache_key: String,
    /// The compiler's output file, OS-encoded like the argv: the object
    /// the daemon snapshots into the cache.
    pub output_path: Vec<u8>,
    /// Whether the compiler exited successfully.
    pub success: bool,
}

impl CcCompiled {
    /// Build a report for this compile.
    #[must_use]
    pub fn new(cache_key: String, output_path: &std::path::Path, success: bool) -> Self {
        Self {
            cache_key,
            output_path: os_bytes::encode(output_path.as_os_str()),
            success,
        }
    }

    /// The compiler's output file.
    ///
    /// # Errors
    ///
    /// When the peer's encoding is not decodable on this platform.
    pub fn output_path(&self) -> Result<std::path::PathBuf, String> {
        os_bytes::decode(&self.output_path).map(std::path::PathBuf::from)
    }
}

/// The rustc artifact-notification lines a served invocation owes cargo.
///
/// Each entry is one complete `{"$message_type":"artifact",…}` line —
/// the JSON message rustc itself would have printed under
/// `--json=…artifacts…`. The session computes them because it holds
/// the serve decision, but only the process cargo spawned may write
/// them: cargo reads artifact notifications from its own child's stderr,
/// so the lines travel with the `Served` answer and the facade prints
/// them just before it exits (stow#633). An invocation whose `--json`
/// set lacks `artifacts` carries an empty set.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ArtifactNotifications(pub Vec<String>);

impl ArtifactNotifications {
    /// The notification lines, each a complete JSON message without its
    /// terminating newline.
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

/// The compile a wrapper runs, as the deciding process fixed it: the
/// executable and the full argument list, the build's own extra arguments
/// included. The wrapper adds nothing and removes nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompileCommand {
    /// The executable, OS-encoded like the argv.
    pub executable: Vec<u8>,
    /// Everything after the executable, in order.
    pub args: Vec<Vec<u8>>,
}

impl CompileCommand {
    /// A command running `executable` with `args`.
    #[must_use]
    pub fn new(executable: &std::ffi::OsStr, args: &[OsString]) -> Self {
        Self {
            executable: os_bytes::encode(executable),
            args: args.iter().map(|arg| os_bytes::encode(arg)).collect(),
        }
    }

    /// The executable to run.
    ///
    /// # Errors
    ///
    /// When the peer's encoding is not decodable on this platform.
    pub fn executable(&self) -> Result<OsString, String> {
        os_bytes::decode(&self.executable)
    }

    /// The arguments to run it with.
    ///
    /// # Errors
    ///
    /// When the peer's encoding is not decodable on this platform.
    pub fn args(&self) -> Result<Vec<OsString>, String> {
        self.args.iter().map(|arg| os_bytes::decode(arg)).collect()
    }
}

/// What the session answers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Answer {
    /// The unit's outputs are in the target directory; the facade exits 0
    /// without running rustc. The payload is the artifact-notification
    /// lines the facade owes cargo's stderr first (stow#633).
    Served(ArtifactNotifications),
    /// Nothing serves this unit. The facade runs exactly the command in
    /// the answer and then sends [`Compiled`] on the same connection,
    /// which holds the compile until it does.
    Compile(CompileCommand),
    /// The report arrived and the unit's rustc is recorded as exited; the
    /// session's bookkeeping runs after this answer and the facade
    /// exits with the compile's own status without waiting for it
    /// (stow#1431).
    Received,
    /// The object cache holds the object: the wrapper clones the file at
    /// `object` (OS-encoded) to the compiler's output path and exits 0.
    CcHit {
        /// The cached object's path.
        object: Vec<u8>,
    },
    /// The object cache does not hold it: the wrapper runs the real
    /// compiler and then sends [`CcCompiled`].
    CcMiss,
    /// The answer to [`Request::CcPolicy`].
    CcPolicy {
        /// The build's C/C++ object cache is on.
        enabled: bool,
    },
    /// The session could not answer. The facade fails the build with
    /// this message rather than quietly compiling without the cache.
    Failed {
        /// Why the session could not answer.
        message: String,
    },
}

impl Plan {
    /// Build a plan for this invocation.
    #[must_use]
    pub fn new(executable: &std::ffi::OsStr, args: &[OsString], env: InvocationEnv) -> Self {
        Self {
            executable: os_bytes::encode(executable),
            args: args.iter().map(|arg| os_bytes::encode(arg)).collect(),
            env,
        }
    }

    /// The real rustc this invocation wraps.
    ///
    /// # Errors
    ///
    /// When the peer's encoding is not decodable on this platform.
    pub fn executable(&self) -> Result<OsString, String> {
        os_bytes::decode(&self.executable)
    }

    /// The wrapped arguments, in order.
    ///
    /// # Errors
    ///
    /// When the peer's encoding is not decodable on this platform.
    pub fn args(&self) -> Result<Vec<OsString>, String> {
        self.args.iter().map(|arg| os_bytes::decode(arg)).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{Answer, ArtifactNotifications, Plan, Request};

    /// The messages cross a process boundary as JSON.
    fn round_trip<T: serde::Serialize + serde::de::DeserializeOwned>(message: &T) -> T {
        serde_json::from_slice(&serde_json::to_vec(message).expect("encode")).expect("decode")
    }

    #[test]
    fn a_plan_round_trips() {
        let plan = Plan::new(
            std::ffi::OsStr::new("/usr/bin/rustc"),
            &[OsString::from("--crate-name"), OsString::from("serde")],
            super::InvocationEnv::for_tests(),
        );
        let decoded = round_trip(&Request::Plan(plan.clone()));
        assert_eq!(decoded, Request::Plan(plan));
        let Request::Plan(decoded) = decoded else {
            panic!("a plan decodes as a plan");
        };
        assert_eq!(decoded.executable().expect("executable"), "/usr/bin/rustc");
        assert_eq!(decoded.args().expect("args"), vec!["--crate-name", "serde"]);
    }

    /// The artifact-notification lines a served unit owes cargo ride the
    /// answer itself (stow#633).
    #[test]
    fn a_served_answer_round_trips_its_notifications() {
        let lines = ArtifactNotifications(vec![
            r#"{"$message_type":"artifact","artifact":"/tmp/out/libserde-abc.rmeta","emit":"metadata"}"#
                .to_owned(),
            r#"{"$message_type":"artifact","artifact":"/tmp/out/libserde-abc.rlib","emit":"link"}"#
                .to_owned(),
        ]);
        assert_eq!(
            round_trip(&Answer::Served(lines.clone())),
            Answer::Served(lines)
        );
    }
}

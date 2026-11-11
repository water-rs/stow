//! The wire between the rustc facade and the build supervisor.
//!
//! One length-prefixed JSON frame per message, both directions. The
//! wrapper asks what to do with one rustc invocation and, when it is told
//! to compile, reports the result so the supervisor can finish the work
//! that only exists after a real compile (stable aliases, output
//! bookkeeping). The supervisor answers the report with a receipt that
//! precedes that work, so the facade exits with rustc.

use std::ffi::OsString;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::os_bytes;

/// Largest frame either side accepts. A rustc command line is a few
/// kilobytes; the cap exists so a confused peer cannot ask for an
/// allocation.
const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;

/// What the facade sends.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Request {
    /// One rustc invocation, before anything has run.
    Plan(Plan),
    /// The result of a compile the supervisor asked for. Answered with
    /// [`Answer::Received`] before the supervisor's bookkeeping, which the
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
/// Under a supervised build the supervisor's environment is the driver's,
/// not the invocation's, so the facade carries the values the
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
    /// Proves the sender is part of this build; checked on every frame.
    pub token: String,
    /// The real rustc cargo asked for.
    pub executable: Vec<u8>,
    /// Everything after the executable, in order.
    pub args: Vec<Vec<u8>>,
    /// The invocation's environment the supervisor cannot see.
    pub env: InvocationEnv,
}

/// The facade reporting the compile the supervisor asked for. The
/// supervisor answers it with a receipt that precedes its bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Compiled {
    /// Proves the sender is part of this build; checked on every frame.
    pub token: String,
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
    /// Proves the sender is part of this build; checked on every frame.
    pub token: String,
    /// The object's cache key.
    pub cache_key: String,
}

/// The wrapper reporting the compile a [`CcLookup`] miss sent it to run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CcCompiled {
    /// Proves the sender is part of this build; checked on every frame.
    pub token: String,
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
    pub fn new(
        token: String,
        cache_key: String,
        output_path: &std::path::Path,
        success: bool,
    ) -> Self {
        Self {
            token,
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
/// `--json=…artifacts…`. The supervisor computes them because it holds
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

/// What the supervisor answers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Answer {
    /// The unit's outputs are in the target directory; the facade exits 0
    /// without running rustc. The payload is the artifact-notification
    /// lines the facade owes cargo's stderr first (stow#633).
    Served(ArtifactNotifications),
    /// Nothing serves this unit. The facade runs the real rustc and then
    /// sends [`Compiled`] on the same connection, which holds the compile
    /// until it does.
    Compile,
    /// The report arrived and the unit's rustc is recorded as exited; the
    /// supervisor's bookkeeping runs after this answer and the facade
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
    /// The supervisor could not answer. The facade fails the build with
    /// this message rather than quietly compiling without the cache.
    Failed {
        /// Why the supervisor could not answer.
        message: String,
    },
}

impl Plan {
    /// Build a plan for this invocation.
    #[must_use]
    pub fn new(
        token: String,
        executable: &std::ffi::OsStr,
        args: &[OsString],
        env: InvocationEnv,
    ) -> Self {
        Self {
            token,
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

/// Write one length-prefixed JSON frame.
///
/// # Errors
///
/// Serialization failures and the transport's own write errors.
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<(), String>
where
    W: AsyncWrite + Unpin + Send,
    T: Serialize + Sync,
{
    let body = serde_json::to_vec(message).map_err(|error| format!("encode frame: {error}"))?;
    let length = u32::try_from(body.len())
        .map_err(|_| format!("frame of {} bytes exceeds the wire limit", body.len()))?;
    if length > MAX_FRAME_BYTES {
        return Err(format!("frame of {length} bytes exceeds the wire limit"));
    }
    writer
        .write_all(&length.to_le_bytes())
        .await
        .map_err(|error| format!("write frame length: {error}"))?;
    writer
        .write_all(&body)
        .await
        .map_err(|error| format!("write frame body: {error}"))?;
    writer
        .flush()
        .await
        .map_err(|error| format!("flush frame: {error}"))
}

/// Read one length-prefixed JSON frame. `Ok(None)` is a clean end of
/// stream — the peer closed between frames.
///
/// # Errors
///
/// A truncated frame, an over-long frame, and malformed JSON.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, String>
where
    R: AsyncRead + Unpin + Send,
    T: serde::de::DeserializeOwned,
{
    let mut length_bytes = [0u8; 4];
    match reader.read_exact(&mut length_bytes).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(format!("read frame length: {error}")),
    }
    let length = u32::from_le_bytes(length_bytes);
    if length > MAX_FRAME_BYTES {
        return Err(format!("peer announced a {length}-byte frame"));
    }
    let mut body = vec![0u8; length as usize];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|error| format!("read frame body: {error}"))?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| format!("decode frame: {error}"))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::{Answer, ArtifactNotifications, Plan, Request, read_frame, write_frame};

    #[tokio::test]
    async fn a_plan_round_trips_through_a_frame() {
        let plan = Plan::new(
            "token".to_owned(),
            std::ffi::OsStr::new("/usr/bin/rustc"),
            &[OsString::from("--crate-name"), OsString::from("serde")],
            super::InvocationEnv::for_tests(),
        );
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &Request::Plan(plan.clone()))
            .await
            .expect("write");
        let decoded: Request = read_frame(&mut buffer.as_slice())
            .await
            .expect("read")
            .expect("a frame");
        assert_eq!(decoded, Request::Plan(plan.clone()));
        let Request::Plan(decoded) = decoded else {
            panic!("a plan frame decodes as a plan");
        };
        assert_eq!(decoded.executable().expect("executable"), "/usr/bin/rustc");
        assert_eq!(decoded.args().expect("args"), vec!["--crate-name", "serde"]);
    }

    /// A peer that closes between frames is not an error: that is how a
    /// facade that got its answer disconnects.
    #[tokio::test]
    async fn an_empty_stream_is_a_clean_end() {
        let decoded: Option<Answer> = read_frame(&mut [].as_slice()).await.expect("read");
        assert!(decoded.is_none());
    }

    /// The artifact-notification lines a served unit owes cargo ride the
    /// answer itself (stow#633).
    #[tokio::test]
    async fn a_served_answer_round_trips_its_notifications() {
        let lines = ArtifactNotifications(vec![
            r#"{"$message_type":"artifact","artifact":"/tmp/out/libserde-abc.rmeta","emit":"metadata"}"#
                .to_owned(),
            r#"{"$message_type":"artifact","artifact":"/tmp/out/libserde-abc.rlib","emit":"link"}"#
                .to_owned(),
        ]);
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &Answer::Served(lines.clone()))
            .await
            .expect("write");
        let decoded: Answer = read_frame(&mut buffer.as_slice())
            .await
            .expect("read")
            .expect("a frame");
        assert_eq!(decoded, Answer::Served(lines));
    }

    /// A frame cut in half is an error, not a clean end — the difference
    /// decides whether the build fails or silently loses the cache.
    #[tokio::test]
    async fn a_truncated_frame_is_an_error() {
        let mut buffer = Vec::new();
        write_frame(
            &mut buffer,
            &Answer::Served(ArtifactNotifications::default()),
        )
        .await
        .expect("write");
        buffer.truncate(buffer.len() - 1);
        let error = read_frame::<_, Answer>(&mut buffer.as_slice())
            .await
            .expect_err("a truncated frame must not read as a clean end");
        assert!(error.contains("read frame body"), "{error}");
    }
}

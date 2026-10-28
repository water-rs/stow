//! The wire between the rustc facade and the build supervisor.
//!
//! One length-prefixed JSON frame per message, both directions. The
//! wrapper asks what to do with one rustc invocation and, when it is told
//! to compile, reports the result so the supervisor can finish the work
//! that only exists after a real compile (stable aliases, output
//! bookkeeping).

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
    /// The result of a compile the supervisor asked for.
    Compiled(Compiled),
    /// A compile the facade already decided on its own — the local-build
    /// mark before rustc starts and the report after it ends. One-way:
    /// the supervisor never answers it.
    Observed(Observed),
    /// A facade whose unit a `pending` serve map does not cover asks the
    /// supervisor to answer only once the build's final map has landed —
    /// or at once when it already has. The wait moves off the file
    /// system so every platform speaks it over the transport it already
    /// carries (stow#347).
    AwaitServeMap(AwaitServeMap),
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
    #[serde(default)]
    pub primary_package: bool,
    /// The invocation's `OUT_DIR` — cargo exports it on a links crate's
    /// units — OS-encoded like the argv.
    #[serde(default)]
    pub out_dir: Option<Vec<u8>>,
}

impl InvocationEnv {
    /// The values this process's invocation carries — only ever called in
    /// the facade, which IS the invocation process.
    #[must_use]
    pub fn current() -> Self {
        Self {
            primary_package: std::env::var_os("CARGO_PRIMARY_PACKAGE").is_some(),
            out_dir: std::env::var_os("OUT_DIR").map(|value| os_bytes::encode(&value)),
        }
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
    #[serde(default)]
    pub env: InvocationEnv,
}

/// The facade reporting the compile the supervisor asked for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Compiled {
    /// Proves the sender is part of this build; checked on every frame.
    pub token: String,
    /// The ticket the [`Answer::Compile`] carried.
    pub ticket: u64,
    /// Whether rustc exited successfully.
    pub success: bool,
}

/// The facade telling the supervisor about a compile it ran without
/// asking first.
///
/// A unit the build's serve map already ruled out needs no plan round
/// trip, but the build still has to mark it as locally built before
/// rustc starts and observe how it ended afterwards.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Observed {
    /// Proves the sender is part of this build; checked on every frame.
    pub token: String,
    /// The real rustc cargo asked for.
    pub executable: Vec<u8>,
    /// Everything after the executable, in order.
    pub args: Vec<Vec<u8>>,
    /// `None` marks the unit as compiling locally — the bookkeeping
    /// [`crate::provenance::record_local_build`] does inside a `Compile`
    /// decision, carried as a frame because this unit never asked for a
    /// decision. `Some` reports the finished compile's exit status.
    pub success: Option<bool>,
    /// The invocation's environment the supervisor cannot see.
    #[serde(default)]
    pub env: InvocationEnv,
}

impl Observed {
    /// Build an observation for this invocation.
    #[must_use]
    pub fn new(
        token: String,
        executable: &std::ffi::OsStr,
        args: &[OsString],
        success: Option<bool>,
        env: InvocationEnv,
    ) -> Self {
        Self {
            token,
            executable: os_bytes::encode(executable),
            args: args.iter().map(|arg| os_bytes::encode(arg)).collect(),
            success,
            env,
        }
    }

    /// The real rustc this invocation wrapped.
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

/// The serve-map wait is the whole request — the token is its only
/// payload, since the answer's timing, not its contents, is the signal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AwaitServeMap {
    /// Proves the sender is part of this build; checked on every frame.
    pub token: String,
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
    /// sends [`Compiled`] carrying `ticket`.
    Compile {
        /// The ticket the [`Compiled`] report carries back.
        ticket: u64,
    },
    /// The report was applied; the facade exits with the compile's own
    /// status.
    Recorded,
    /// The build's serve map is final: the facade re-reads the map file
    /// and decides on what it finds (stow#347).
    ServeMapReady,
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
            super::InvocationEnv::default(),
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

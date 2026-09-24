//! The wire between the rustc facade and the build supervisor.
//!
//! One length-prefixed JSON frame per message, both directions. The
//! wrapper asks what to do with one rustc invocation and, when it is told
//! to compile, reports the result so the supervisor can finish the work
//! that only exists after a real compile (stable aliases, output
//! bookkeeping).

use std::ffi::OsString;

use serde::{Deserialize, Serialize};

use crate::os_bytes;

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
    /// A fast-path facade's own compile outcome: the build's serve map
    /// already said nothing could serve the unit, so no `Plan` ever
    /// happened. `success: None` is the pre-compile provenance mark — a
    /// one-way write the facade does not await — and `Some(_)` the
    /// post-compile report, the same one-way write (stow#347).
    Observed(Observed),
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
}

/// The facade reporting the compile the supervisor asked for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Compiled {
    /// The shared secret; a report without it is refused.
    pub token: String,
    /// The ticket the [`Answer::Compile`] carried.
    pub ticket: u64,
    /// Whether rustc exited successfully.
    pub success: bool,
}

/// A fast-path facade reporting a compile the supervisor never planned.
///
/// The unit was outside the serve map, so bookkeeping is all that is
/// owed. `success: None` marks the locally-built crate ahead of the
/// compile (the dependents' window is rustc's own emit timing); a
/// `Some` reports the finished compile for the deferred bookkeeping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Observed {
    /// The shared secret; a report without it is refused.
    pub token: String,
    /// The invocation, exactly as a [`Plan`] would carry it.
    pub plan: Plan,
    /// `None` ahead of rustc, `Some(_)` after it exits.
    pub success: Option<bool>,
}

/// What the supervisor answers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Answer {
    /// The unit's outputs are in the target directory; the facade exits 0
    /// without running rustc.
    Served,
    /// Nothing serves this unit. The facade runs the real rustc and then
    /// sends [`Compiled`] carrying `ticket`.
    Compile {
        /// The compile's bookkeeping identity on this connection.
        ticket: u64,
    },
    /// The report was applied; the facade exits with the compile's own
    /// status.
    Recorded,
    /// The supervisor could not answer. The facade fails the build with
    /// this message rather than quietly compiling without the cache.
    Failed {
        /// Why the plan could not be answered.
        message: String,
    },
}

impl Plan {
    /// Build a plan for this invocation.
    #[must_use]
    pub fn new(token: String, executable: &std::ffi::OsStr, args: &[OsString]) -> Self {
        Self {
            token,
            executable: os_bytes::encode(executable),
            args: args.iter().map(|arg| os_bytes::encode(arg)).collect(),
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
#[cfg(feature = "tokio")]
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<(), String>
where
    W: tokio::io::AsyncWrite + Unpin + Send,
    T: Serialize + Sync,
{
    use tokio::io::AsyncWriteExt;

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
#[cfg(feature = "tokio")]
pub async fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, String>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    T: serde::de::DeserializeOwned,
{
    use tokio::io::AsyncReadExt;

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

/// [`write_frame`] for the synchronous facade — the fast-path wrapper
/// owns no tokio runtime, so it speaks the same framing over blocking
/// `std` streams.
///
/// # Errors
///
/// Serialization failures and the transport's own write errors.
pub fn write_frame_sync<W, T>(writer: &mut W, message: &T) -> Result<(), String>
where
    W: std::io::Write,
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
        .map_err(|error| format!("write frame length: {error}"))?;
    writer
        .write_all(&body)
        .map_err(|error| format!("write frame body: {error}"))?;
    writer
        .flush()
        .map_err(|error| format!("flush frame: {error}"))
}

/// [`read_frame`] for the synchronous facade.
///
/// # Errors
///
/// A truncated frame, an over-long frame, and malformed JSON.
pub fn read_frame_sync<R, T>(reader: &mut R) -> Result<Option<T>, String>
where
    R: std::io::Read,
    T: serde::de::DeserializeOwned,
{
    let mut length_bytes = [0u8; 4];
    match reader.read_exact(&mut length_bytes) {
        Ok(()) => {}
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
        .map_err(|error| format!("read frame body: {error}"))?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| format!("decode frame: {error}"))
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use std::ffi::OsString;

    use super::{Answer, Plan, Request, read_frame, write_frame};

    #[tokio::test]
    async fn a_plan_round_trips_through_a_frame() {
        let plan = Plan::new(
            "token".to_owned(),
            std::ffi::OsStr::new("/usr/bin/rustc"),
            &[OsString::from("--crate-name"), OsString::from("serde")],
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

    /// A frame cut in half is an error, not a clean end — the difference
    /// decides whether the build fails or silently loses the cache.
    #[tokio::test]
    async fn a_truncated_frame_is_an_error() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &Answer::Served)
            .await
            .expect("write");
        buffer.truncate(buffer.len() - 1);
        let error = read_frame::<_, Answer>(&mut buffer.as_slice())
            .await
            .expect_err("a truncated frame must not read as a clean end");
        assert!(error.contains("read frame body"), "{error}");
    }
}

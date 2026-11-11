//! The daemon's wire format: a versioned envelope around JSON messages.
//!
//! Every frame is `[u32 length][u16 protocol][JSON]`, both integers
//! big-endian. `length` counts the bytes after the length field itself:
//! the protocol number and the JSON. The first frame a client sends is a
//! [`Hello`] naming its [`Role`]; every later client frame is a
//! [`ControlRequest`] from a control connection or a [`WrapperRequest`]
//! from a wrapper connection, and the daemon answers with [`Response`]s.
//!
//! The two request types are separate so that a wrapper connection cannot
//! even decode a request that opens or ends a session.
//!
//! Status clients are synchronous and std-only (see [`super::start`]) and
//! the daemon is async, so the encoding and the header parse live here
//! once and each side only adds its own reads and writes.

use std::io::Read;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use stow_types::error::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::events::{LogRecord, SpanRecord};
use super::session::{SessionEnd, SessionFacts, SessionId};

/// The protocol number this build speaks. Bumped when a message changes
/// in a way an older peer cannot read.
pub const PROTOCOL: u16 = 2;

/// The oldest protocol number this build still reads. A daemon serves
/// `PROTOCOL_FLOOR..=PROTOCOL`.
pub const PROTOCOL_FLOOR: u16 = 2;

const LENGTH_BYTES: usize = 4;
const PROTOCOL_BYTES: usize = 2;
const HEADER_BYTES: usize = LENGTH_BYTES + PROTOCOL_BYTES;

/// The largest frame a peer may announce. The length field is read from
/// the wire before anything is allocated for it. An `OpenSession` carries
/// a workspace's unit table and its serve map, which for a large workspace
/// run to many mebibytes; the bound only stops a corrupt length from
/// becoming a multi-gigabyte allocation.
const MAX_FRAME_BYTES: usize = 64 << 20;

/// Whether this build reads frames stamped `protocol`.
#[must_use]
pub const fn speaks(protocol: u16) -> bool {
    PROTOCOL_FLOOR <= protocol && protocol <= PROTOCOL
}

/// What a connection is for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// A driver: it asks for status, opens one session and owns it for as
    /// long as the connection lives.
    Control,
    /// A rustc or C/C++ wrapper of a build, speaking for that session.
    Wrapper {
        /// The session the wrapper's requests are decided under.
        session: SessionRef,
    },
}

/// How a wrapper names its session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionRef {
    /// The session a driver opened, by the id the daemon minted.
    Id(SessionId),
}

/// The first frame of every connection: who the client is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The protocol the client speaks.
    pub protocol: u16,
    /// The client's stow version.
    pub stow_version: String,
    /// What the connection is for.
    pub role: Role,
}

impl Hello {
    /// The hello of this build, for a connection of `role`.
    #[must_use]
    pub fn new(role: Role) -> Self {
        Self {
            protocol: PROTOCOL,
            stow_version: env!("CARGO_PKG_VERSION").to_owned(),
            role,
        }
    }
}

/// What a driver asks of the daemon on a control connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "request")]
pub enum ControlRequest {
    /// Report the daemon's version and protocol.
    Status,
    /// Open the session these facts describe. The connection then belongs
    /// to the session: its end ends the session.
    OpenSession(Box<SessionFacts>),
    /// The build is over: drain the session's bookkeeping, write its miss
    /// journal and close it.
    EndSession,
}

/// What a wrapper asks of its session.
pub use crate::daemon::wrapper::Request as WrapperRequest;

/// What the daemon pushes to the driver that owns a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum Event {
    /// Cargo's resolution is over: the first request that describes a
    /// compile unit arrived.
    ResolutionDone,
    /// An event the session's tasks recorded, which the driver's own
    /// subscriber records again.
    Log(LogRecord),
    /// A span the session's tasks opened; the driver opens it again so its
    /// trace file records the decision spans.
    SpanOpened(SpanRecord),
    /// The span of this id, from a [`Event::SpanOpened`], closed.
    SpanClosed {
        /// The id the opening record named.
        id: u64,
    },
}

/// What the daemon answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "response")]
pub enum Response {
    /// The answer to [`ControlRequest::Status`].
    Status {
        /// The daemon's stow version.
        stow_version: String,
        /// The protocol the daemon speaks.
        protocol: u16,
    },
    /// The daemon refused the connection; it closes it after this frame.
    Rejected {
        /// Why.
        reason: String,
    },
    /// The session is open; wrappers name it by this id.
    SessionOpened {
        /// The session the daemon minted.
        session: SessionId,
    },
    /// The session ended; the answer to [`ControlRequest::EndSession`].
    SessionEnded(SessionEnd),
    /// A push to the control connection's driver.
    Event(Event),
    /// The request is still being decided: sent every half answer bound
    /// while it is, so a wrapper tells a slow decision from a wedged
    /// daemon.
    Working,
    /// The answer to a [`WrapperRequest`].
    Answer(crate::daemon::wrapper::Answer),
}

/// One frame as it came off the wire: the protocol number the sender
/// stamped on it and the undecoded JSON.
#[derive(Debug)]
pub struct Frame {
    /// The sender's protocol number.
    pub protocol: u16,
    payload: Vec<u8>,
}

impl Frame {
    /// Decode the payload as `T`.
    ///
    /// # Errors
    ///
    /// The payload is not a JSON `T`.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.payload).wrap_err("decode the daemon frame")
    }
}

/// Encode `message` as one frame.
///
/// # Errors
///
/// The message does not serialize, or is larger than a frame may be.
///
/// # Panics
///
/// Never in practice: a frame within [`MAX_FRAME_BYTES`] fits its `u32`
/// length.
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>> {
    let payload = serde_json::to_vec(message).wrap_err("encode the daemon frame")?;
    let length = payload.len() + PROTOCOL_BYTES;
    if length > MAX_FRAME_BYTES {
        return Err(stow_types::stow_error!(
            "daemon frame of {length} bytes exceeds the {MAX_FRAME_BYTES} byte limit"
        ));
    }
    let length = u32::try_from(length).expect("a frame within the limit fits a u32");
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&PROTOCOL.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// The payload length a header announces, and the protocol it carries.
fn parse_header(header: [u8; HEADER_BYTES]) -> Result<(usize, u16)> {
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    let protocol = u16::from_be_bytes([header[4], header[5]]);
    let length = usize::try_from(length).expect("a u32 fits a usize");
    if !(PROTOCOL_BYTES..=MAX_FRAME_BYTES).contains(&length) {
        return Err(stow_types::stow_error!(
            "daemon frame announces {length} bytes, outside {PROTOCOL_BYTES}..={MAX_FRAME_BYTES}"
        ));
    }
    Ok((length - PROTOCOL_BYTES, protocol))
}

/// Read one frame.
///
/// # Errors
///
/// The peer closed or stalled mid-frame, or announced a bad length.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Frame> {
    let mut header = [0; HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .wrap_err("read a daemon frame header")?;
    let (payload_length, protocol) = parse_header(header)?;
    let mut payload = vec![0; payload_length];
    reader
        .read_exact(&mut payload)
        .wrap_err("read a daemon frame payload")?;
    Ok(Frame { protocol, payload })
}

/// Write `message` as one frame and flush, on the daemon's side.
///
/// # Errors
///
/// The message does not encode or the write fails.
pub async fn write_frame_async<W: AsyncWrite + Unpin + Send, T: Serialize + Sync>(
    writer: &mut W,
    message: &T,
) -> Result<()> {
    let frame = encode(message)?;
    writer
        .write_all(&frame)
        .await
        .wrap_err("write a daemon frame")?;
    writer.flush().await.wrap_err("flush a daemon frame")
}

/// Read one frame on the daemon's side; `None` when the peer closed
/// cleanly between frames.
///
/// # Errors
///
/// The peer closed or stalled mid-frame, or announced a bad length.
pub async fn read_frame_async<R: AsyncRead + Unpin + Send>(
    reader: &mut R,
) -> Result<Option<Frame>> {
    let mut header = [0; HEADER_BYTES];
    match reader.read_exact(&mut header[..1]).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).wrap_err("read a daemon frame header"),
    }
    reader
        .read_exact(&mut header[1..])
        .await
        .wrap_err("read a daemon frame header")?;
    let (payload_length, protocol) = parse_header(header)?;
    let mut payload = vec![0; payload_length];
    reader
        .read_exact(&mut payload)
        .await
        .wrap_err("read a daemon frame payload")?;
    Ok(Some(Frame { protocol, payload }))
}

#[cfg(test)]
mod tests {
    use super::{ControlRequest, Hello, PROTOCOL, Response, Role, encode, read_frame};
    use crate::daemon::session::SessionFacts;

    #[test]
    fn a_frame_is_length_then_protocol_then_json() {
        let frame = encode(&ControlRequest::Status).expect("encode");
        let json = br#"{"request":"Status"}"#;
        let mut expected = u32::try_from(json.len() + 2)
            .expect("length")
            .to_be_bytes()
            .to_vec();
        expected.extend_from_slice(&PROTOCOL.to_be_bytes());
        expected.extend_from_slice(json);
        assert_eq!(frame, expected);
    }

    #[test]
    fn frames_round_trip_in_sequence() {
        let mut wire = encode(&Hello::new(Role::Control)).expect("hello");
        wire.extend(
            encode(&Response::Status {
                stow_version: "1.2.3".to_owned(),
                protocol: PROTOCOL,
            })
            .expect("status"),
        );
        let mut reader = wire.as_slice();
        let hello = read_frame(&mut reader).expect("first");
        assert_eq!(hello.protocol, PROTOCOL);
        assert_eq!(
            hello.decode::<Hello>().expect("hello"),
            Hello::new(Role::Control)
        );
        let status = read_frame(&mut reader).expect("second");
        assert_eq!(
            status.decode::<Response>().expect("response"),
            Response::Status {
                stow_version: "1.2.3".to_owned(),
                protocol: PROTOCOL,
            }
        );
    }

    /// `OpenSession` survives the wire: the frame the driver writes decodes
    /// to the same facts, including an environment whose values are not
    /// text.
    #[tokio::test]
    async fn open_session_round_trips_through_a_frame() {
        use std::ffi::OsString;

        use crate::daemon::session::invocation::{OutputRoots, RefusalPolicy};
        use crate::toolchain::BuildToolchain;

        let mut facts = SessionFacts::for_tests(
            BuildToolchain::for_tests().await.facts(),
            OutputRoots::new("/workspace/target".into(), None),
            RefusalPolicy::FailBuild,
        );
        facts.build.environ = vec![
            (OsString::from("RUST_LOG"), OsString::from("stow_cli=debug")),
            #[cfg(unix)]
            (OsString::from("RAW"), {
                use std::os::unix::ffi::OsStringExt as _;
                OsString::from_vec(vec![b'a', 0xff, b'b'])
            }),
        ];
        facts.build.rustc_extra_args = vec!["--remap-path-prefix=/workspace=.".to_owned()];

        let wire = encode(&ControlRequest::OpenSession(Box::new(facts.clone()))).expect("encode");
        let frame = read_frame(&mut wire.as_slice()).expect("frame");
        assert_eq!(frame.protocol, PROTOCOL);
        let ControlRequest::OpenSession(decoded) =
            frame.decode::<ControlRequest>().expect("decode")
        else {
            panic!("an OpenSession decodes as an OpenSession");
        };
        assert_eq!(
            serde_json::to_value(&*decoded).expect("decoded facts"),
            serde_json::to_value(&facts).expect("original facts"),
        );
        assert_eq!(decoded.build.environ, facts.build.environ);
        assert_eq!(decoded.build.rustc_extra_args, facts.build.rustc_extra_args);
    }

    #[test]
    fn a_corrupt_length_is_refused_before_allocating() {
        let mut wire = u32::MAX.to_be_bytes().to_vec();
        wire.extend_from_slice(&PROTOCOL.to_be_bytes());
        assert!(read_frame(&mut wire.as_slice()).is_err());
        let mut short = 1_u32.to_be_bytes().to_vec();
        short.extend_from_slice(&PROTOCOL.to_be_bytes());
        assert!(read_frame(&mut short.as_slice()).is_err());
    }
}

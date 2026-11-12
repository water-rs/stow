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
//!
//! # Versions
//!
//! Each side states the protocols it speaks: [`PROTOCOL_FLOOR`] through
//! [`PROTOCOL`]. A daemon serves every protocol of its range and stamps
//! each frame it writes with the protocol the connection negotiated
//! ([`Negotiated`], which only [`negotiate`] builds). A client stamps every
//! frame with its own [`PROTOCOL`].
//!
//! Everything that differs between protocols is decided in this module. A
//! difference is a plain `fn (Negotiated) -> bool` in the `gates` section
//! below, named for what it gates and deleted once the floor passes the
//! protocol that introduced it; no other module compares protocol numbers.
//!
//! # The core
//!
//! A peer of any version reads the core, whatever number stamps it, because
//! it is how a newer client reaches an older daemon and how an older client
//! reads a newer daemon's refusal. These encodings never change: the frame
//! header, the [`HelloCore`] fields of a [`Hello`], [`ControlRequest::Status`]
//! and [`ControlRequest::Retire`], and [`Response::Status`],
//! [`Response::Rejected`] and [`Response::Retiring`]. The golden bytes in
//! the tests pin each, and so does the `stow daemon` command line a daemon
//! starts its successor with (`cli_args`).

use std::io::Read;
use std::ops::RangeInclusive;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use stow_types::error::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use super::events::{LogRecord, SpanRecord};
use super::session::{SessionEnd, SessionFacts, SessionId, os_bytes};

/// The protocol number this build speaks. Bumped when a message changes
/// in a way an older peer cannot read. Protocols 2 and 3 were never
/// released.
pub const PROTOCOL: u16 = 4;

/// The oldest protocol number this build still reads. A daemon serves
/// `PROTOCOL_FLOOR..=PROTOCOL`.
pub const PROTOCOL_FLOOR: u16 = 4;

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

/// The protocol a connection was negotiated at: what a daemon stamps on
/// every frame it writes on it.
///
/// Only [`negotiate`] builds one, so a daemon cannot write a frame at a
/// protocol it did not agree on with its client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated(u16);

impl Negotiated {
    /// The protocol number.
    #[must_use]
    pub const fn protocol(self) -> u16 {
        self.0
    }

    /// Whether a client frame stamped `stamp` belongs to this connection:
    /// a client stamps every frame with the protocol it said hello with.
    #[must_use]
    pub const fn admits(self, stamp: u16) -> bool {
        self.0 == stamp
    }

    /// The protocol of this build, for a test that plays a daemon.
    #[cfg(test)]
    pub(crate) const fn for_tests() -> Self {
        Self(PROTOCOL)
    }
}

/// What a daemon makes of a client's [`HelloCore`].
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    /// The client's protocol is in the daemon's range: serve it at that
    /// protocol.
    Serve(Negotiated),
    /// The client speaks a protocol above the daemon's: the daemon is the
    /// older stow.
    Newer,
    /// The client speaks a protocol below the daemon's floor. The daemon
    /// never downgrades itself for an old client, because two installs
    /// would fight over the endpoint.
    Older {
        /// The protocol the client speaks, which stamps the refusal so the
        /// client can read it.
        peer: u16,
        /// Why, naming both ranges.
        reason: String,
    },
}

/// Decide which protocol, if any, a daemon speaking `ours` serves the
/// client `core` describes at.
#[must_use]
pub fn negotiate(core: &HelloCore, ours: &RangeInclusive<u16>) -> Admission {
    let (floor, protocol) = (*ours.start(), *ours.end());
    if core.protocol > protocol {
        Admission::Newer
    } else if core.protocol < floor {
        Admission::Older {
            peer: core.protocol,
            reason: format!(
                "the client (stow {}) speaks protocols {} through {}, this daemon speaks protocols {floor} through {protocol}",
                core.stow_version, core.floor, core.protocol
            ),
        }
    } else {
        Admission::Serve(Negotiated(core.protocol))
    }
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
    /// The session of the cargo that started the wrapper: no driver opened
    /// one, so the daemon finds the cargo from the connection itself and
    /// opens the session when the cargo's first wrapper describes the
    /// build.
    Cargo {
        /// The wrapper's `CARGO` — the executable of the cargo that
        /// started it — OS-encoded; absent when the wrapper's environment
        /// has none.
        cargo: Option<Vec<u8>>,
        /// The `RUST_LOG` directives the wrapper wants the events of its
        /// requests at, besides the warnings and errors it always gets;
        /// set only when the wrapper traces (`STOW_TRACE_WRAPPED_COMPILERS`).
        rust_log: Option<String>,
    },
}

/// The first frame of every connection: who the client is.
///
/// The fields before `role` are the [`HelloCore`], which a daemon reads
/// before it knows what `role` can say at the client's protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// The newest protocol the client speaks.
    pub protocol: u16,
    /// The oldest protocol the client speaks.
    pub floor: u16,
    /// The client's stow version.
    pub stow_version: String,
    /// The client's runtime executable, OS-encoded: what a daemon that
    /// must give way to this client starts as its successor.
    pub executable: Vec<u8>,
    /// What the connection is for.
    pub role: Role,
}

/// The part of a [`Hello`] that never changes between protocols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloCore {
    /// The newest protocol the client speaks.
    pub protocol: u16,
    /// The oldest protocol the client speaks.
    pub floor: u16,
    /// The client's stow version.
    pub stow_version: String,
    /// The client's runtime executable, OS-encoded.
    pub executable: Vec<u8>,
}

impl Hello {
    /// The hello of this build, for a connection of `role` from the stow
    /// runtime executable `executable`.
    #[must_use]
    pub fn new(role: Role, executable: &Path) -> Self {
        Self {
            protocol: PROTOCOL,
            floor: PROTOCOL_FLOOR,
            stow_version: env!("CARGO_PKG_VERSION").to_owned(),
            executable: os_bytes::encode(executable.as_os_str()),
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
    /// Replace the daemon with `executable`, which an installer just put
    /// in place: the daemon drains, then starts that binary in its place.
    Retire {
        /// The successor's executable, OS-encoded.
        executable: Vec<u8>,
    },
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
        /// The newest protocol the daemon speaks.
        protocol: u16,
        /// The oldest protocol the daemon speaks.
        floor: u16,
    },
    /// The daemon refused the connection; it closes it after this frame.
    Rejected {
        /// Why.
        reason: String,
    },
    /// The daemon is giving way to another stow and acted on nothing of
    /// this request: reconnect, and the request is served by the
    /// successor.
    Retiring {
        /// The version of the daemon that is leaving.
        stow_version: String,
        /// The time the daemon has left to drain, in milliseconds.
        until_millis: u64,
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

impl Response {
    /// Whether this is one of the core responses, which every peer reads
    /// whatever protocol stamps the frame.
    #[must_use]
    pub const fn is_core(&self) -> bool {
        matches!(
            self,
            Self::Status { .. } | Self::Rejected { .. } | Self::Retiring { .. }
        )
    }
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

/// Encode `message` as one frame stamped with this build's [`PROTOCOL`]:
/// every client frame is.
///
/// # Errors
///
/// The message does not serialize, or is larger than a frame may be.
pub fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>> {
    encode_at(PROTOCOL, message)
}

/// Encode `message` as one frame stamped `stamp`: a daemon writes at the
/// protocol its client's connection negotiated, and a test plays a peer of
/// another version.
///
/// # Errors
///
/// The message does not serialize, or is larger than a frame may be.
///
/// # Panics
///
/// Never in practice: a frame within [`MAX_FRAME_BYTES`] fits its `u32`
/// length.
pub fn encode_at<T: Serialize>(stamp: u16, message: &T) -> Result<Vec<u8>> {
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
    frame.extend_from_slice(&stamp.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode a daemon's answer. A core response is read whatever protocol
/// stamps it; anything else only when this build speaks that protocol.
///
/// # Errors
///
/// The frame is not a response, or is stamped with a protocol this build
/// does not speak and is not a core response.
pub fn read_response(frame: &Frame) -> Result<Response> {
    if speaks(frame.protocol) {
        return frame.decode();
    }
    match frame.decode::<Response>() {
        Ok(response) if response.is_core() => Ok(response),
        _ => Err(stow_types::stow_error!(
            "the stow daemon speaks protocol {}, this stow speaks {PROTOCOL_FLOOR} through {PROTOCOL}",
            frame.protocol
        )),
    }
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

/// Write `message` as one frame stamped `at` and flush, on the daemon's
/// side.
///
/// # Errors
///
/// The message does not encode or the write fails.
pub async fn write_frame_async<W: AsyncWrite + Unpin + Send, T: Serialize + Sync>(
    writer: &mut W,
    at: Negotiated,
    message: &T,
) -> Result<()> {
    write_stamped(writer, at.protocol(), message).await
}

/// Write the core response `response` stamped with the protocol of a peer
/// that has not been admitted, so the peer reads it.
///
/// # Errors
///
/// The write fails.
///
/// # Panics
///
/// In a debug build, when `response` is not a core response: a peer of
/// another protocol may not read it.
pub async fn write_core_async<W: AsyncWrite + Unpin + Send>(
    writer: &mut W,
    peer: u16,
    response: &Response,
) -> Result<()> {
    debug_assert!(response.is_core(), "{response:?} is not a core response");
    write_stamped(writer, peer, response).await
}

async fn write_stamped<W: AsyncWrite + Unpin + Send, T: Serialize + Sync>(
    writer: &mut W,
    stamp: u16,
    message: &T,
) -> Result<()> {
    let frame = encode_at(stamp, message)?;
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
    use std::path::Path;

    use super::{
        Admission, ControlRequest, Hello, HelloCore, PROTOCOL, PROTOCOL_FLOOR, Response, Role,
        encode, encode_at, negotiate, read_frame, read_response,
    };
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

    /// The bytes of `message` after the frame header.
    fn json_of<T: serde::Serialize>(message: &T) -> String {
        String::from_utf8(encode_at(0, message).expect("encode")[6..].to_vec()).expect("utf8")
    }

    /// The core never changes between protocols, so a peer of any version
    /// reads it: any change to one of these encodings fails here.
    #[test]
    fn the_core_encodings_are_pinned() {
        assert_eq!(
            json_of(&Hello {
                protocol: 4,
                floor: 4,
                stow_version: "1.2.3".to_owned(),
                executable: b"/s".to_vec(),
                role: Role::Control,
            }),
            r#"{"protocol":4,"floor":4,"stow_version":"1.2.3","executable":[47,115],"role":"Control"}"#
        );
        assert_eq!(json_of(&ControlRequest::Status), r#"{"request":"Status"}"#);
        assert_eq!(
            json_of(&ControlRequest::Retire {
                executable: b"/s".to_vec()
            }),
            r#"{"request":"Retire","executable":[47,115]}"#
        );
        assert_eq!(
            json_of(&Response::Retiring {
                stow_version: "1.2.3".to_owned(),
                until_millis: 10_000,
            }),
            r#"{"response":"Retiring","stow_version":"1.2.3","until_millis":10000}"#
        );
        assert_eq!(
            json_of(&Response::Status {
                stow_version: "1.2.3".to_owned(),
                protocol: 4,
                floor: 4,
            }),
            r#"{"response":"Status","stow_version":"1.2.3","protocol":4,"floor":4}"#
        );
        // Byte-identical to the refusal of the released 0.16 daemon, which
        // speaks protocol 1.
        assert_eq!(
            json_of(&Response::Rejected {
                reason: "no".to_owned()
            }),
            r#"{"response":"Rejected","reason":"no"}"#
        );
    }

    /// An older daemon reads a newer client's protocol and executable even
    /// when the client's role has variants the daemon does not know.
    #[test]
    fn a_hello_decodes_as_its_core_whatever_its_role() {
        let hello = br#"{"protocol":9,"floor":4,"stow_version":"9.0.0","executable":[47,115],"role":{"Wrapper":{"session":{"Unheard":1}}}}"#;
        let core: HelloCore = serde_json::from_slice(hello).expect("core");
        assert_eq!(
            core,
            HelloCore {
                protocol: 9,
                floor: 4,
                stow_version: "9.0.0".to_owned(),
                executable: b"/s".to_vec(),
            }
        );
        assert!(serde_json::from_slice::<Hello>(hello).is_err());
    }

    fn core_at(protocol: u16, floor: u16) -> HelloCore {
        HelloCore {
            protocol,
            floor,
            stow_version: "1.0.0".to_owned(),
            executable: Vec::new(),
        }
    }

    #[test]
    fn a_client_inside_the_daemons_range_is_served_at_its_own_protocol() {
        for client in 3..=5 {
            assert!(
                matches!(
                    negotiate(&core_at(client, client), &(3..=5)),
                    Admission::Serve(at) if at.protocol() == client
                ),
                "{client}"
            );
        }
    }

    #[test]
    fn a_client_above_the_daemons_range_is_newer() {
        assert_eq!(negotiate(&core_at(6, 4), &(3..=5)), Admission::Newer);
    }

    #[test]
    fn a_client_below_the_daemons_floor_is_refused_in_its_own_protocol() {
        let Admission::Older { peer, reason } = negotiate(&core_at(2, 2), &(3..=5)) else {
            panic!("a client below the floor is refused");
        };
        assert_eq!(peer, 2);
        assert!(
            reason.contains("protocols 2 through 2") && reason.contains("protocols 3 through 5"),
            "{reason}"
        );
    }

    /// A daemon writes every frame at the protocol it negotiated, which an
    /// older client in its range then reads.
    #[tokio::test]
    async fn a_daemon_stamps_its_frames_with_the_negotiated_protocol() {
        let Admission::Serve(at) = negotiate(&core_at(3, 3), &(3..=5)) else {
            panic!("protocol 3 is in the range");
        };
        let mut wire = Vec::new();
        super::write_frame_async(&mut wire, at, &Response::Working)
            .await
            .expect("write");
        let frame = read_frame(&mut wire.as_slice()).expect("frame");
        assert_eq!(frame.protocol, 3);
        assert_eq!(
            frame.decode::<Response>().expect("response"),
            Response::Working
        );
    }

    /// The daemon of this build serves exactly the protocols it reads.
    #[test]
    fn this_builds_range_is_what_it_speaks() {
        assert!(super::speaks(PROTOCOL) && super::speaks(PROTOCOL_FLOOR));
        assert!(!super::speaks(PROTOCOL + 1) && !super::speaks(PROTOCOL_FLOOR - 1));
    }

    /// A frame stamped outside the range decodes only as the core.
    #[test]
    fn a_response_stamped_outside_the_range_decodes_only_as_core() {
        let foreign = PROTOCOL + 1;
        let read = |response: &Response| {
            let wire = encode_at(foreign, response).expect("encode");
            read_response(&read_frame(&mut wire.as_slice()).expect("frame"))
        };
        for core in [
            Response::Rejected {
                reason: "no".to_owned(),
            },
            Response::Retiring {
                stow_version: "9.0.0".to_owned(),
                until_millis: 1,
            },
            Response::Status {
                stow_version: "9.0.0".to_owned(),
                protocol: foreign,
                floor: foreign,
            },
        ] {
            assert_eq!(read(&core).expect("a core response"), core);
        }
        let error = read(&Response::Working).expect_err("not core");
        assert!(error.to_string().contains("speaks protocol"), "{error}");
        let wire = encode_at(PROTOCOL, &Response::Working).expect("encode");
        assert_eq!(
            read_response(&read_frame(&mut wire.as_slice()).expect("frame")).expect("in range"),
            Response::Working
        );
    }

    fn hello(role: Role) -> Hello {
        Hello::new(role, Path::new("/stow"))
    }

    #[test]
    fn frames_round_trip_in_sequence() {
        let mut wire = encode(&hello(Role::Control)).expect("hello");
        wire.extend(
            encode(&Response::Status {
                stow_version: "1.2.3".to_owned(),
                protocol: PROTOCOL,
                floor: PROTOCOL_FLOOR,
            })
            .expect("status"),
        );
        let mut reader = wire.as_slice();
        let first = read_frame(&mut reader).expect("first");
        assert_eq!(first.protocol, PROTOCOL);
        assert_eq!(
            first.decode::<Hello>().expect("hello"),
            hello(Role::Control)
        );
        let status = read_frame(&mut reader).expect("second");
        assert_eq!(
            status.decode::<Response>().expect("response"),
            Response::Status {
                stow_version: "1.2.3".to_owned(),
                protocol: PROTOCOL,
                floor: PROTOCOL_FLOOR,
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

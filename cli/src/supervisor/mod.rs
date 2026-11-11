//! What decides a build's rustc and C/C++ wrapper requests.
//!
//! One rustc invocation used to be one `stow` process that loaded the
//! config, opened the state database, read the verified index slice and
//! built its own HTTP transport. The transport is the expensive part:
//! zenwave pools connections and shares one QUIC endpoint per *process*,
//! so a build of 39 units opened up to 39 connections and HTTP/3's
//! multiplexing had nothing to multiplex over.
//!
//! So the wrapper is a thin client. It parses its command line, asks the
//! build's session on the per-user daemon (see [`crate::daemon`]) what to
//! do with the invocation, and either exits or execs the real rustc.
//! Everything else — config, index, local cache, network, statistics,
//! admissions — belongs to the daemon, which holds one connection to the
//! edge for every build it serves.

pub mod invocation;
pub mod os_bytes;
pub mod protocol;
pub mod server;

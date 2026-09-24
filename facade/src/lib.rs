//! The facade half of the supervised build, shared between the `stow-facade`
//! binary the wrapper shims exec and `stow-cli` itself (wrapper shims
//! materialized before the facade existed still point at it — the same code
//! answers them).
//!
//! A facade's contract is speed: it must not pay for work the supervising
//! build already paid for. Everything here is synchronous `std` I/O and
//! env reading — the modules only reach for a supervisor connection when
//! the build's own serve map cannot answer the invocation.

pub mod cc;
pub mod client;
pub mod endpoint;
pub mod journal;
pub mod os_bytes;
pub mod protocol;
pub mod servable;
pub mod wrapper;

//! The descriptors a process inherited, Unix.
//!
//! A descriptor a child inherits from a build — a make jobserver pipe, a
//! lock file, a socket — keeps that resource open for as long as the
//! daemon lives (sccache#2145: an inherited jobserver descriptor hung a
//! build). The set is read from `/dev/fd`, which lists the open
//! descriptors on Linux and macOS alike, so nothing probes the rlimit's
//! whole range.

use std::os::fd::RawFd;

/// The first descriptor that is neither stdin, stdout nor stderr.
pub const FIRST_INHERITED: RawFd = 3;

/// The open descriptors numbered `first` and above. The set includes the
/// descriptor of the directory listing itself, which is closed by the
/// time the caller sees it; the callers tolerate `EBADF` for that reason.
pub fn open_from(first: RawFd) -> std::io::Result<Vec<RawFd>> {
    let mut open = Vec::new();
    for entry in std::fs::read_dir("/dev/fd")? {
        let name = entry?.file_name();
        let fd = name
            .to_str()
            .and_then(|text| text.parse::<RawFd>().ok())
            .ok_or_else(|| {
                std::io::Error::other(format!("unexpected entry {} in /dev/fd", name.display()))
            })?;
        if fd >= first {
            open.push(fd);
        }
    }
    Ok(open)
}

/// Mark each descriptor close-on-exec, so the next `exec` drops it.
///
/// Async-signal-safe: only `fcntl`, so a `pre_exec` hook may call it. It
/// marks rather than closes because the standard library's spawn holds a
/// descriptor of its own across the hook, on which it reports a failed
/// `exec`.
pub fn mark_close_on_exec(fds: &[RawFd]) -> std::io::Result<()> {
    for &fd in fds {
        // SAFETY: `fcntl` with `F_SETFD` reads no memory.
        let result = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        if result == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBADF) {
                return Err(error);
            }
        }
    }
    Ok(())
}

/// Let each descriptor survive the next `exec`.
pub fn clear_close_on_exec(fds: &[RawFd]) -> std::io::Result<()> {
    for &fd in fds {
        // SAFETY: `fcntl` with `F_SETFD` reads no memory.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, 0) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Close each descriptor.
pub fn close(fds: &[RawFd]) {
    for &fd in fds {
        // SAFETY: the caller owns no descriptor of these numbers: they
        // were inherited, and `EBADF` for one already closed is the only
        // failure `close` has here.
        unsafe { libc::close(fd) };
    }
}

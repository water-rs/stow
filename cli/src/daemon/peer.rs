//! The process at the far end of a client's connection, and ending it.
//!
//! A daemon that speaks a protocol older than [`RETIRE_SINCE`] cannot be
//! asked to retire: it refuses the client's hello. The client then ends
//! that process, by the id the kernel reports for the listener it is
//! connected to, and takes the start path. Nothing here is reached for a
//! daemon that can retire.
//!
//! [`RETIRE_SINCE`]: super::protocol::RETIRE_SINCE

use std::io;
use std::time::Duration;

/// The pause between looks at whether the ended process is gone.
#[cfg(unix)]
const GONE_POLL: Duration = Duration::from_millis(10);

/// The process listening at the other end of the connected socket.
///
/// # Errors
///
/// The platform cannot say.
#[cfg(target_os = "macos")]
pub fn server_pid(socket: &impl std::os::fd::AsRawFd) -> io::Result<u32> {
    let mut pid: libc::pid_t = 0;
    let mut length =
        libc::socklen_t::try_from(size_of::<libc::pid_t>()).expect("pid_t is a few bytes");
    // SAFETY: the descriptor is a connected socket the caller holds, and
    // `pid` and `length` describe the buffer the kernel writes.
    let read = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut length,
        )
    };
    if read != 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(pid).map_err(|_| io::Error::other("the platform reports no peer process id"))
}

/// The process listening at the other end of the connected socket.
///
/// # Errors
///
/// The platform cannot say.
#[cfg(target_os = "linux")]
pub fn server_pid(socket: &impl std::os::fd::AsRawFd) -> io::Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length =
        libc::socklen_t::try_from(size_of::<libc::ucred>()).expect("ucred is a few bytes");
    // SAFETY: the descriptor is a connected socket the caller holds, and
    // `credentials` and `length` describe the buffer the kernel writes.
    let read = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    if read != 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(credentials.pid)
        .map_err(|_| io::Error::other("the platform reports no peer process id"))
}

/// The process serving the connected pipe.
///
/// # Errors
///
/// The platform cannot say.
#[cfg(windows)]
pub fn server_pid(pipe: &impl std::os::windows::io::AsRawHandle) -> io::Result<u32> {
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let mut pid = 0_u32;
    // SAFETY: the handle is the client end of a connected pipe the caller
    // holds, and `pid` is a valid out parameter.
    let read = unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle().cast(), &raw mut pid) };
    if read == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

/// End the process `pid` and wait until it is gone, for at most `bound`.
///
/// # Errors
///
/// The process cannot be ended, or is still there when the bound runs out.
#[cfg(unix)]
pub fn end(pid: u32, bound: Duration) -> io::Result<()> {
    let pid = libc::pid_t::try_from(pid).map_err(io::Error::other)?;
    // SAFETY: signalling a process id has no memory-safety preconditions.
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        let error = io::Error::last_os_error();
        // Gone already: that is what was asked for.
        return if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        };
    }
    let deadline = std::time::Instant::now() + bound;
    // SAFETY: signal 0 only probes for the process.
    while unsafe { libc::kill(pid, 0) } == 0 {
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("process {pid} did not exit within {} s", bound.as_secs()),
            ));
        }
        std::thread::sleep(GONE_POLL);
    }
    Ok(())
}

/// End the process `pid` and wait until it is gone, for at most `bound`.
///
/// # Errors
///
/// The process cannot be ended, or is still there when the bound runs out.
#[cfg(windows)]
pub fn end(pid: u32, bound: Duration) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
    };

    // SAFETY: `OpenProcess` takes three integers and returns a handle or
    // null.
    let process = unsafe { OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `process` is the open handle received above.
    let terminated = unsafe { TerminateProcess(process, 1) };
    let ended = if terminated == 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `process` is the open handle received above.
        let waited = unsafe {
            WaitForSingleObject(
                process,
                u32::try_from(bound.as_millis()).unwrap_or(u32::MAX),
            )
        };
        if waited == WAIT_OBJECT_0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("process {pid} did not exit within {} s", bound.as_secs()),
            ))
        }
    };
    // SAFETY: `process` is the open handle received above and is not used
    // again.
    unsafe { CloseHandle(process) };
    ended
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    #[cfg(unix)]
    #[test]
    fn the_listener_of_a_connection_is_found_and_ended() {
        use std::os::unix::net::{UnixListener, UnixStream};

        let dir = tempfile::tempdir().expect("dir");
        let socket = dir.path().join("a.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let client = UnixStream::connect(&socket).expect("connect");
        // The listener is this process, which is what the kernel reports.
        assert_eq!(
            super::server_pid(&client).expect("peer pid"),
            std::process::id()
        );
        drop(listener);

        // A process of its own is ended and waited for.
        let mut child = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        // The child is reaped by the wait below, so only its exit status
        // tells that it was ended; a zombie still answers signal 0, which
        // the bound would report.
        let waiting = std::thread::spawn(move || child.wait().expect("wait").success());
        super::end(pid, Duration::from_secs(10)).expect("end the process");
        assert!(
            !waiting.join().expect("waiter"),
            "the process was signalled"
        );
    }
}

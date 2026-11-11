//! The cargo process a wrapper runs under, and the moment it exits.
//!
//! A build nobody opened a session for belongs to the cargo that started
//! it: the daemon finds that cargo from the wrapper's connection and ends
//! the build's session when the cargo is gone. Both halves ask the
//! operating system and keep nothing between events: the owner is read
//! from the kernel's process table when a wrapper connects, and the exit
//! is a readiness event the kernel delivers, never a poll.
//!
//! A process is named by its id and its start time, because an id alone
//! is reused once its process is gone.
#![cfg_attr(
    not(all(test, unix)),
    expect(
        dead_code,
        reason = "the daemon's implicit sessions use it from the next commit"
    )
)]

use std::io;
use std::path::{Path, PathBuf};

/// A cargo process: its id and the time it started, which together name
/// it for as long as the machine is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CargoOwner {
    /// The process id.
    pub pid: u32,
    /// When the process started, in the platform's own ticks. Ticks are
    /// only compared with those of the same table.
    pub started: u64,
}

impl std::fmt::Display for CargoOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "pid {} started at tick {}",
            self.pid, self.started
        )
    }
}

/// What the daemon reads of the machine's processes.
pub trait ProcessTable {
    /// The process that started `pid`. A process whose parent exited
    /// answers with whatever adopted it.
    ///
    /// # Errors
    ///
    /// `NotFound` when `pid` is gone; any other error is the platform's.
    fn parent(&self, pid: u32) -> io::Result<u32>;

    /// When `pid` started.
    ///
    /// # Errors
    ///
    /// `NotFound` when `pid` is gone; any other error is the platform's.
    fn started(&self, pid: u32) -> io::Result<u64>;

    /// The executable `pid` runs.
    ///
    /// # Errors
    ///
    /// The platform's: the image of a process another user owns is not
    /// readable.
    fn image(&self, pid: u32) -> io::Result<PathBuf>;
}

/// The process table of the machine this daemon runs on.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsProcessTable;

impl ProcessTable for OsProcessTable {
    fn parent(&self, pid: u32) -> io::Result<u32> {
        imp::parent(pid)
    }

    fn started(&self, pid: u32) -> io::Result<u64> {
        imp::started(pid)
    }

    fn image(&self, pid: u32) -> io::Result<PathBuf> {
        imp::image(pid)
    }
}

/// The cargo that started the wrapper whose connection came from process
/// `peer`.
///
/// `cargo` is the `CARGO` the wrapper was started with: cargo sets it for
/// every process it starts and they pass it on, so the owner is the
/// nearest ancestor running that executable. Build scripts and `CMake` put
/// processes between a wrapper and its cargo, which is why the parent
/// alone is not enough. Executables are compared by file identity, never
/// by spelling. Without `CARGO` the wrapper's parent owns it.
///
/// # Errors
///
/// No ancestor runs `cargo`, a process on the way is gone or was
/// replaced by another one under the same id, or the table cannot be read.
pub fn owner_of(
    peer: u32,
    cargo: Option<&Path>,
    table: &impl ProcessTable,
) -> Result<CargoOwner, String> {
    let cargo_file = cargo
        .map(|path| {
            same_file::Handle::from_path(path)
                .map_err(|error| format!("open `CARGO` ({}): {error}", path.display()))
        })
        .transpose()?;
    let read = |what: &str, pid: u32, value: io::Result<u64>| {
        value.map_err(|error| format!("read the {what} of process {pid}: {error}"))
    };
    let mut child = peer;
    let mut child_started = read("start time", child, table.started(child))?;
    loop {
        let parent = table
            .parent(child)
            .map_err(|error| format!("read the parent of process {child}: {error}"))?;
        // Pid 0 and 1 are no cargo: the wrapper's ancestors ran out, or its
        // cargo exited and init adopted it.
        if parent <= 1 || parent == child {
            return Err(cargo.map_or_else(
                || format!("the parent of process {child} is gone"),
                |path| {
                    format!(
                        "the cargo that started this wrapper (`CARGO`={}) is not among its ancestors",
                        path.display()
                    )
                },
            ));
        }
        let started = read("start time", parent, table.started(parent))?;
        // A parent never starts after its child: one that did is a process
        // that took the id of a parent that exited.
        if started > child_started {
            return Err(format!(
                "process {parent}, recorded as the parent of {child}, started after it: the parent exited and its id was reused"
            ));
        }
        let owns = cargo_file.as_ref().is_none_or(|cargo_file| {
            table
                .image(parent)
                .ok()
                .and_then(|image| same_file::Handle::from_path(image).ok())
                .is_some_and(|image| &image == cargo_file)
        });
        if owns {
            return Ok(CargoOwner {
                pid: parent,
                started,
            });
        }
        child = parent;
        child_started = started;
    }
}

/// A process's exit, as an event.
///
/// Armed once and waited on once: the kernel wakes the waiter when the
/// process exits, so a watch costs nothing until then.
#[derive(Debug)]
pub struct ExitWatch {
    /// `None` when the process was already gone when the watch was armed.
    watch: Option<imp::Watch>,
}

impl ExitWatch {
    /// Watch `owner` for exit. A process that is already gone is a watch
    /// that has fired.
    ///
    /// The watch is armed before the owner's start time is read again, so
    /// an id that was reused between the walk that found it and the arming
    /// is caught: what the watch is on would be the wrong process.
    ///
    /// # Errors
    ///
    /// The platform cannot watch a process, or `owner`'s id now names
    /// another process.
    pub fn arm(owner: CargoOwner, table: &impl ProcessTable) -> Result<Self, String> {
        let watch = imp::arm(owner.pid)
            .map_err(|error| format!("watch process {} for its exit: {error}", owner.pid))?;
        match table.started(owner.pid) {
            Ok(started) if started == owner.started => Ok(Self { watch }),
            Ok(_) => Err(format!(
                "process id {} was reused between finding the cargo and watching it",
                owner.pid
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self { watch: None }),
            Err(error) => Err(format!(
                "read the start time of process {}: {error}",
                owner.pid
            )),
        }
    }

    /// Resolves when the process has exited.
    ///
    /// # Errors
    ///
    /// The platform's readiness wait failed.
    pub async fn exited(self) -> io::Result<()> {
        match self.watch {
            Some(watch) => watch.exited().await,
            None => Ok(()),
        }
    }
}

/// The process on the other end of `stream`, as the kernel knows it.
///
/// # Errors
///
/// The platform cannot say.
#[cfg(unix)]
pub fn peer_pid(stream: &tokio::net::UnixStream) -> io::Result<u32> {
    stream
        .peer_cred()?
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or_else(|| io::Error::other("the platform reports no process id for the peer"))
}

/// The process on the other end of `pipe`, as the kernel knows it.
///
/// # Errors
///
/// The platform cannot say.
#[cfg(windows)]
pub fn peer_pid(pipe: &tokio::net::windows::named_pipe::NamedPipeServer) -> io::Result<u32> {
    imp::peer_pid(pipe)
}

#[cfg(target_os = "linux")]
mod imp {
    //! `/proc` for the table and a pidfd for the watch.

    use std::io;
    use std::os::fd::{FromRawFd as _, OwnedFd};
    use std::path::PathBuf;

    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;

    /// The fields of `/proc/<pid>/stat` the table reads: the parent and the
    /// start time, in clock ticks since boot.
    ///
    /// The command name is parenthesised and may hold anything, so the
    /// fields are counted from the last closing parenthesis.
    pub(super) fn parse_stat(stat: &str) -> Option<(u32, u64)> {
        let (_, after_name) = stat.rsplit_once(')')?;
        let mut fields = after_name.split_whitespace();
        // After the name: state (field 3), then the parent (field 4), and the
        // start time is field 22.
        let parent = fields.nth(1)?.parse().ok()?;
        let started = fields.nth(17)?.parse().ok()?;
        Some((parent, started))
    }

    fn stat(pid: u32) -> io::Result<(u32, u64)> {
        let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
            // Reading the file of a process that exited between the open and
            // the read reports `ESRCH`.
            if error.raw_os_error() == Some(libc::ESRCH) {
                io::ErrorKind::NotFound.into()
            } else {
                error
            }
        })?;
        parse_stat(&text).ok_or_else(|| io::Error::other(format!("malformed /proc/{pid}/stat")))
    }

    pub(super) fn parent(pid: u32) -> io::Result<u32> {
        stat(pid).map(|(parent, _)| parent)
    }

    pub(super) fn started(pid: u32) -> io::Result<u64> {
        stat(pid).map(|(_, started)| started)
    }

    pub(super) fn image(pid: u32) -> io::Result<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
    }

    /// A pidfd, readable once its process has exited.
    #[derive(Debug)]
    pub(super) struct Watch(AsyncFd<OwnedFd>);

    /// `None` when `pid` is already gone.
    pub(super) fn arm(pid: u32) -> io::Result<Option<Watch>> {
        let pid = libc::pid_t::try_from(pid)
            .map_err(|_| io::Error::other(format!("process id {pid} is out of range")))?;
        // SAFETY: `pidfd_open` takes a process id and a flags word and
        // returns a new descriptor or -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ESRCH) => Ok(None),
                Some(libc::ENOSYS) => Err(io::Error::other(
                    "the daemon needs pidfd_open, which Linux provides from 5.3",
                )),
                _ => Err(error),
            };
        }
        let fd = i32::try_from(fd).expect("a descriptor fits an int");
        // SAFETY: `fd` is a descriptor `pidfd_open` just returned, which
        // nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Some(Watch(AsyncFd::with_interest(fd, Interest::READABLE)?)))
    }

    impl Watch {
        pub(super) async fn exited(self) -> io::Result<()> {
            self.0.readable().await.map(drop)
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    //! `proc_pidinfo` for the table and a kqueue for the watch.

    use std::io;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::path::PathBuf;

    use tokio::io::Interest;
    use tokio::io::unix::AsyncFd;

    fn info(pid: u32) -> io::Result<libc::proc_bsdinfo> {
        let pid = libc::c_int::try_from(pid)
            .map_err(|_| io::Error::other(format!("process id {pid} is out of range")))?;
        let size = libc::c_int::try_from(size_of::<libc::proc_bsdinfo>())
            .expect("a process info struct is a few hundred bytes");
        // SAFETY: a zeroed `proc_bsdinfo` is plain integers and byte arrays.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        // SAFETY: the buffer is `size` bytes of a `proc_bsdinfo`, which is
        // what `PROC_PIDTBSDINFO` fills.
        let filled = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        if filled == size {
            return Ok(info);
        }
        let error = io::Error::last_os_error();
        // A short or empty answer is a process that is gone, or one this
        // user may not inspect.
        Err(
            if error.raw_os_error() == Some(libc::ESRCH) || filled == 0 {
                io::ErrorKind::NotFound.into()
            } else {
                error
            },
        )
    }

    pub(super) fn parent(pid: u32) -> io::Result<u32> {
        info(pid).map(|info| info.pbi_ppid)
    }

    pub(super) fn started(pid: u32) -> io::Result<u64> {
        info(pid).map(|info| info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
    }

    pub(super) fn image(pid: u32) -> io::Result<PathBuf> {
        use std::os::unix::ffi::OsStringExt as _;
        let pid = libc::c_int::try_from(pid)
            .map_err(|_| io::Error::other(format!("process id {pid} is out of range")))?;
        let mut path =
            vec![0_u8; usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).expect("positive")];
        // SAFETY: the buffer is as long as the length passed with it.
        let length = unsafe {
            libc::proc_pidpath(
                pid,
                path.as_mut_ptr().cast(),
                u32::try_from(path.len()).expect("a path buffer is a few KiB"),
            )
        };
        let length = usize::try_from(length)
            .ok()
            .filter(|length| *length > 0)
            .ok_or_else(io::Error::last_os_error)?;
        path.truncate(length);
        Ok(PathBuf::from(std::ffi::OsString::from_vec(path)))
    }

    /// A kqueue holding one `NOTE_EXIT` registration: readable once the
    /// process has exited.
    #[derive(Debug)]
    pub(super) struct Watch(AsyncFd<OwnedFd>);

    /// `None` when `pid` is already gone.
    pub(super) fn arm(pid: u32) -> io::Result<Option<Watch>> {
        // SAFETY: `kqueue` takes nothing and returns a new descriptor or -1.
        let queue = unsafe { libc::kqueue() };
        if queue < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `queue` is a descriptor `kqueue` just returned, which
        // nothing else owns.
        let queue = unsafe { OwnedFd::from_raw_fd(queue) };
        // A process the daemon starts must not inherit the watch.
        // SAFETY: `F_SETFD` on a descriptor this function owns.
        if unsafe { libc::fcntl(queue.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let change = libc::kevent {
            ident: pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            // A receipt answers the registration at once, so a process that
            // is already gone is told apart from one that is being watched.
            flags: libc::EV_ADD | libc::EV_ONESHOT | libc::EV_RECEIPT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: a zeroed `kevent` is plain integers and a null pointer.
        let mut receipt: libc::kevent = unsafe { std::mem::zeroed() };
        // SAFETY: one change in, one receipt out, both valid for the call.
        let registered = unsafe {
            libc::kevent(
                queue.as_raw_fd(),
                &raw const change,
                1,
                &raw mut receipt,
                1,
                std::ptr::null(),
            )
        };
        if registered < 0 {
            return Err(io::Error::last_os_error());
        }
        if registered == 1 && receipt.flags & libc::EV_ERROR != 0 && receipt.data != 0 {
            let errno = i32::try_from(receipt.data).expect("an errno fits an int");
            return if errno == libc::ESRCH {
                Ok(None)
            } else {
                Err(io::Error::from_raw_os_error(errno))
            };
        }
        Ok(Some(Watch(AsyncFd::with_interest(
            queue,
            Interest::READABLE,
        )?)))
    }

    impl Watch {
        pub(super) async fn exited(self) -> io::Result<()> {
            self.0.readable().await.map(drop)
        }
    }
}

#[cfg(windows)]
mod imp {
    //! A ToolHelp snapshot and process handles for the table, and a
    //! thread-pool wait on the process handle for the watch.

    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStringExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use tokio::sync::oneshot;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, INFINITE, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW, RegisterWaitForSingleObject, UnregisterWaitEx,
        WT_EXECUTEONLYONCE,
    };

    /// A process handle, closed on drop.
    struct Process(HANDLE);

    impl Drop for Process {
        fn drop(&mut self) {
            // SAFETY: the handle was opened by `open` and is closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    // SAFETY: a process handle is usable from any thread.
    unsafe impl Send for Process {}

    fn open(pid: u32, access: u32) -> io::Result<Process> {
        // SAFETY: `OpenProcess` takes three integers and returns a handle
        // or null.
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            let error = io::Error::last_os_error();
            // No process has this id.
            return Err(
                if error.raw_os_error() == i32::try_from(ERROR_INVALID_PARAMETER).ok() {
                    io::ErrorKind::NotFound.into()
                } else {
                    error
                },
            );
        }
        Ok(Process(handle))
    }

    pub(super) fn parent(pid: u32) -> io::Result<u32> {
        // SAFETY: the snapshot is closed below.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a zeroed `PROCESSENTRY32` is plain integers and bytes.
        let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = u32::try_from(size_of::<PROCESSENTRY32>()).expect("a few hundred bytes");
        let mut found = None;
        // SAFETY: `snapshot` is open and `entry` has its size set.
        if unsafe { Process32First(snapshot, &raw mut entry) } != 0 {
            loop {
                if entry.th32ProcessID == pid {
                    found = Some(entry.th32ParentProcessID);
                    break;
                }
                // SAFETY: as above.
                if unsafe { Process32Next(snapshot, &raw mut entry) } == 0 {
                    break;
                }
            }
        }
        // SAFETY: `snapshot` is the handle opened above.
        unsafe { CloseHandle(snapshot) };
        found.ok_or_else(|| io::ErrorKind::NotFound.into())
    }

    pub(super) fn started(pid: u32) -> io::Result<u64> {
        let process = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: the handle is open and every out parameter is a valid
        // `FILETIME`.
        let read = unsafe {
            GetProcessTimes(
                process.0,
                &raw mut created,
                &raw mut exited,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }

    pub(super) fn image(pid: u32) -> io::Result<PathBuf> {
        let process = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        // 32767 UTF-16 units is the longest path Windows allows.
        let mut buffer = vec![0_u16; 32768];
        let mut length = u32::try_from(buffer.len()).expect("a few KiB");
        // SAFETY: the buffer holds `length` units and the call writes at
        // most that many, setting `length` to how many.
        let read = unsafe {
            QueryFullProcessImageNameW(process.0, 0, buffer.as_mut_ptr(), &raw mut length)
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        let length = usize::try_from(length).expect("u32 fits usize");
        Ok(PathBuf::from(std::ffi::OsString::from_wide(
            &buffer[..length],
        )))
    }

    pub(super) fn peer_pid(
        pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> io::Result<u32> {
        let mut pid = 0_u32;
        // SAFETY: the handle is the server end of a connected pipe and
        // `pid` is a valid out parameter.
        let read =
            unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle().cast(), &raw mut pid) };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(pid)
    }

    /// What the thread-pool callback reaches.
    struct Shared {
        /// Taken by the callback, which sends the exit.
        sender: Mutex<Option<oneshot::Sender<()>>>,
        /// The callback ran, and consumed its reference.
        ran: AtomicBool,
    }

    unsafe extern "system" fn on_exit(context: *mut c_void, _timed_out: bool) {
        // SAFETY: `context` is the reference `arm` leaked for this callback,
        // which runs once.
        let shared = unsafe { Arc::from_raw(context.cast::<Shared>()) };
        shared.ran.store(true, Ordering::Release);
        if let Some(sender) = shared.sender.lock().expect("the exit sender").take() {
            // A watch that was dropped needs no event.
            let _ = sender.send(());
        }
    }

    /// A thread-pool wait on a process handle, completing a channel.
    pub(super) struct Watch {
        wait: HANDLE,
        context: *const Shared,
        shared: Arc<Shared>,
        exit: oneshot::Receiver<()>,
        /// Keeps the handle open for as long as the wait is registered.
        _process: Process,
    }

    impl std::fmt::Debug for Watch {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.debug_struct("Watch").finish_non_exhaustive()
        }
    }

    // SAFETY: the wait handle and the context pointer are only used by this
    // value's drop, and the pool's callback reaches `Shared` through an
    // `Arc` of `Send` parts.
    unsafe impl Send for Watch {}

    /// `None` when `pid` is already gone.
    pub(super) fn arm(pid: u32) -> io::Result<Option<Watch>> {
        let process = match open(pid, SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION) {
            Ok(process) => process,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let (sender, exit) = oneshot::channel();
        let shared = Arc::new(Shared {
            sender: Mutex::new(Some(sender)),
            ran: AtomicBool::new(false),
        });
        let context = Arc::into_raw(Arc::clone(&shared));
        let mut wait: HANDLE = std::ptr::null_mut();
        // SAFETY: the process handle stays open as long as the wait does,
        // and `context` is a leaked `Arc` the callback or `drop` releases.
        let registered = unsafe {
            RegisterWaitForSingleObject(
                &raw mut wait,
                process.0,
                Some(on_exit),
                context.cast(),
                INFINITE,
                WT_EXECUTEONLYONCE,
            )
        };
        if registered == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: the callback was never registered, so the reference
            // is still ours.
            drop(unsafe { Arc::from_raw(context) });
            return Err(error);
        }
        Ok(Some(Watch {
            wait,
            context,
            shared,
            exit,
            _process: process,
        }))
    }

    impl Watch {
        pub(super) async fn exited(mut self) -> io::Result<()> {
            // The sender is dropped only by a callback that already sent,
            // so a closed channel is an exit too.
            let _ = (&mut self.exit).await;
            Ok(())
        }
    }

    impl Drop for Watch {
        fn drop(&mut self) {
            // SAFETY: `wait` is the registration made in `arm`. Passing
            // `INVALID_HANDLE_VALUE` blocks until a callback that is running
            // has returned, so none touches `Shared` after this.
            unsafe { UnregisterWaitEx(self.wait, INVALID_HANDLE_VALUE) };
            if !self.shared.ran.load(Ordering::Acquire) {
                // SAFETY: the callback never ran, so its reference is
                // still ours.
                drop(unsafe { Arc::from_raw(self.context) });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::{CargoOwner, ExitWatch, OsProcessTable, ProcessTable, owner_of};

    /// A table of made-up processes: `(parent, started, image)` by id.
    struct Fake(HashMap<u32, (u32, u64, PathBuf)>);

    impl ProcessTable for Fake {
        fn parent(&self, pid: u32) -> io::Result<u32> {
            self.0
                .get(&pid)
                .map(|entry| entry.0)
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }

        fn started(&self, pid: u32) -> io::Result<u64> {
            self.0
                .get(&pid)
                .map(|entry| entry.1)
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }

        fn image(&self, pid: u32) -> io::Result<PathBuf> {
            self.0
                .get(&pid)
                .map(|entry| entry.2.clone())
                .ok_or_else(|| io::ErrorKind::NotFound.into())
        }
    }

    /// Two real files standing for two executables, and the processes
    /// 100 (cargo) <- 200 (a build script) <- 300 (a C compiler wrapper).
    fn tree(dir: &Path) -> (Fake, PathBuf, PathBuf) {
        let cargo = dir.join("cargo");
        let other = dir.join("other");
        std::fs::write(&cargo, b"cargo").expect("cargo image");
        std::fs::write(&other, b"other").expect("other image");
        let table = Fake(HashMap::from([
            (1, (0, 1, other.clone())),
            (100, (1, 10, cargo.clone())),
            (200, (100, 20, other.clone())),
            (300, (200, 30, other.clone())),
        ]));
        (table, cargo, other)
    }

    #[test]
    fn the_owner_is_the_nearest_ancestor_running_cargo() {
        let dir = tempfile::tempdir().expect("dir");
        let (table, cargo, _) = tree(dir.path());
        assert_eq!(
            owner_of(300, Some(&cargo), &table),
            Ok(CargoOwner {
                pid: 100,
                started: 10
            })
        );
        assert_eq!(
            owner_of(200, Some(&cargo), &table).map(|owner| owner.pid),
            Ok(100)
        );
    }

    #[test]
    fn without_cargo_the_owner_is_the_parent() {
        let dir = tempfile::tempdir().expect("dir");
        let (table, _, _) = tree(dir.path());
        assert_eq!(owner_of(300, None, &table).map(|owner| owner.pid), Ok(200));
    }

    #[test]
    fn a_cargo_missing_from_the_ancestors_fails_naming_it() {
        let dir = tempfile::tempdir().expect("dir");
        let (table, _, other) = tree(dir.path());
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, b"elsewhere").expect("image");
        let error = owner_of(300, Some(&elsewhere), &table).expect_err("no such ancestor");
        assert!(
            error.contains("not among its ancestors") && error.contains("elsewhere"),
            "{error}"
        );
        // An orphan: its parent is init.
        let error = owner_of(100, Some(&other), &table).expect_err("orphan");
        assert!(error.contains("not among its ancestors"), "{error}");
    }

    #[test]
    fn a_parent_started_after_its_child_is_not_its_owner() {
        let dir = tempfile::tempdir().expect("dir");
        let (mut table, cargo, _) = tree(dir.path());
        // The cargo that started 200 exited and its id went to a newer one.
        table.0.get_mut(&100).expect("cargo").1 = 25;
        let error = owner_of(300, Some(&cargo), &table).expect_err("a reused id");
        assert!(error.contains("reused"), "{error}");
    }

    /// A table whose answers about one process change as it is read.
    struct Reused(u64);

    impl ProcessTable for Reused {
        fn parent(&self, _pid: u32) -> io::Result<u32> {
            Ok(1)
        }

        fn started(&self, _pid: u32) -> io::Result<u64> {
            Ok(self.0)
        }

        fn image(&self, _pid: u32) -> io::Result<PathBuf> {
            Err(io::ErrorKind::NotFound.into())
        }
    }

    #[tokio::test]
    async fn a_pid_reused_between_reads_fails_the_watch() {
        let own = OsProcessTable
            .started(std::process::id())
            .expect("this process's start time");
        let error = ExitWatch::arm(
            CargoOwner {
                pid: std::process::id(),
                started: own,
            },
            &Reused(own + 1),
        )
        .expect_err("a different start time");
        assert!(error.contains("reused"), "{error}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_connections_peer_is_the_process_on_its_other_end() {
        let (local, _remote) = tokio::net::UnixStream::pair().expect("a connected pair");
        assert_eq!(super::peer_pid(&local).expect("peer"), std::process::id());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_stat_line_parses_whatever_the_command_is_called() {
        let stat = "4242 (a) b (c) S 17 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 18446744073709551615";
        assert_eq!(super::imp::parse_stat(stat), Some((17, 987_654)));
    }

    const ROLE_ENV: &str = "STOW_OWNER_TEST_ROLE";
    const ROLE_TEST: &str = "daemon::owner::tests::process_in_the_owner_tests";

    /// The other half of the process tests: the test binary re-run under a
    /// role. It is a no-op in a normal run.
    ///
    /// `middle` starts a `sleeper` and prints the sleeper's id; both end
    /// when their shared standard input does.
    #[test]
    fn process_in_the_owner_tests() {
        let Some(role) = std::env::var_os(ROLE_ENV) else {
            return;
        };
        if role == "middle" {
            let sleeper = role_command("sleeper", Stdio::inherit(), Stdio::null())
                .spawn()
                .expect("spawn the sleeper");
            println!("{}", sleeper.id());
            let mut sleeper = sleeper;
            sleeper.wait().expect("wait for the sleeper");
        } else {
            io::copy(&mut io::stdin(), &mut io::sink()).expect("wait for the end of input");
        }
    }

    fn role_command(role: &str, stdin: Stdio, stdout: Stdio) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args(["--exact", ROLE_TEST, "--nocapture"])
            .env(ROLE_ENV, role)
            .stdin(stdin)
            .stdout(stdout)
            .stderr(Stdio::null());
        command
    }

    /// A process that lives until its standard input ends.
    fn sleeper() -> std::process::Child {
        role_command("sleeper", Stdio::piped(), Stdio::null())
            .spawn()
            .expect("spawn a sleeper")
    }

    #[test]
    fn this_process_owns_its_grandchild_when_cargo_names_it() {
        use std::io::BufRead as _;

        // The middle process runs a copy of this executable, so that it is
        // not "cargo" even though this process is.
        let dir = tempfile::tempdir().expect("dir");
        let copy = dir.path().join(
            std::env::current_exe()
                .expect("exe")
                .file_name()
                .expect("name"),
        );
        std::fs::copy(std::env::current_exe().expect("exe"), &copy).expect("copy the executable");
        let mut middle = Command::new(&copy)
            .args(["--exact", ROLE_TEST, "--nocapture"])
            .env(ROLE_ENV, "middle")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the middle process");
        let mut lines = std::io::BufReader::new(middle.stdout.take().expect("stdout")).lines();
        let sleeper_pid: u32 = loop {
            let line = lines
                .next()
                .expect("the middle process prints")
                .expect("line");
            if let Ok(pid) = line.trim().parse() {
                break pid;
            }
        };
        let own_exe = std::env::current_exe().expect("exe");
        let owner = owner_of(sleeper_pid, Some(&own_exe), &OsProcessTable);
        drop(middle.stdin.take());
        middle.wait().expect("wait for the middle process");
        assert_eq!(
            owner.map(|owner| owner.pid),
            Ok(std::process::id()),
            "the sleeper's grandparent is this process"
        );
    }

    #[tokio::test]
    async fn an_exit_watch_fires_when_its_process_exits() {
        let mut child = sleeper();
        let owner = CargoOwner {
            pid: child.id(),
            started: OsProcessTable.started(child.id()).expect("start time"),
        };
        let watch = ExitWatch::arm(owner, &OsProcessTable).expect("arm");
        let fired = tokio::spawn(watch.exited());
        // Nothing has happened to the process yet.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!fired.is_finished(), "the watch fired before the exit");
        child.kill().expect("kill the sleeper");
        tokio::time::timeout(Duration::from_secs(10), fired)
            .await
            .expect("the watch fires within 10 s")
            .expect("join")
            .expect("the wait succeeded");
        child.wait().expect("reap");
    }

    #[tokio::test]
    async fn a_watch_armed_on_an_exited_process_fires_at_once() {
        let mut child = sleeper();
        let owner = CargoOwner {
            pid: child.id(),
            started: OsProcessTable.started(child.id()).expect("start time"),
        };
        child.kill().expect("kill the sleeper");
        child.wait().expect("reap");
        let watch = ExitWatch::arm(owner, &OsProcessTable).expect("arm on a process that is gone");
        tokio::time::timeout(Duration::from_secs(10), watch.exited())
            .await
            .expect("fires at once")
            .expect("the wait succeeded");
    }
}

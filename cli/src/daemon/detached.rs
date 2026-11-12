//! Starting a process that keeps nothing of the one that starts it.
//!
//! On Unix the process also outlives its starter. On Windows it does not
//! leave the starter's job object, and a build's cargo runs in a job that
//! kills every member when cargo ends, so only a starter outside any such
//! job — the daemon, which the Task Scheduler starts (`scheduled_task`) —
//! starts a process meant to outlive a build.
//!
//! Such a process keeps nothing of its starter: whatever it inherits stays
//! open for as long as it runs. A pipe is the sharp case — a caller that
//! reads the starter's output to its end waits for the detached process
//! too, so a build whose driver started the daemon never finishes for a
//! caller collecting its output — and an inherited make jobserver
//! descriptor hangs a build the same way (sccache#2145).
//!
//! * Unix: a session of its own, the three standard descriptors set here,
//!   and every other descriptor the starter holds marked close-on-exec.
//! * Windows: `CreateProcessW` given exactly the three standard handles in
//!   a `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. The standard library's
//!   `Command` passes `bInheritHandles` with no list, so its child
//!   inherits every inheritable handle of the starter — the standard
//!   handles the starter itself inherited among them, which stay
//!   inheritable — and the controls that narrow it (`inherit_handles`,
//!   `spawn_with_attributes`) are unstable.

use std::ffi::OsString;
use std::path::Path;

/// A started detached process.
#[cfg(unix)]
pub type Child = std::process::Child;
#[cfg(windows)]
pub use windows::{Child, arguments_text};

/// A process to start detached: the program, its arguments, exactly the
/// environment named here, null standard input and output, and the
/// standard error given or null.
#[derive(Debug)]
pub struct Detached<'a> {
    program: &'a Path,
    args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    cwd: Option<&'a Path>,
    stderr: Option<std::fs::File>,
}

impl<'a> Detached<'a> {
    /// `program` with no arguments, an empty environment, the starter's
    /// working directory and a null standard error.
    #[must_use]
    pub const fn new(program: &'a Path) -> Self {
        Self {
            program,
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            stderr: None,
        }
    }

    /// Append an argument.
    #[must_use]
    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Add a variable to the environment the process starts with.
    #[must_use]
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Add every variable of `vars` to the environment the process starts
    /// with.
    #[must_use]
    pub fn envs(mut self, vars: impl IntoIterator<Item = (OsString, OsString)>) -> Self {
        self.env.extend(vars);
        self
    }

    /// Run the process in `dir`.
    #[must_use]
    pub const fn current_dir(mut self, dir: &'a Path) -> Self {
        self.cwd = Some(dir);
        self
    }

    /// Send the process's standard error to `file`.
    #[must_use]
    pub fn stderr(mut self, file: std::fs::File) -> Self {
        self.stderr = Some(file);
        self
    }

    /// Start the process.
    ///
    /// # Errors
    ///
    /// The process cannot be started.
    #[cfg(unix)]
    pub fn spawn(self) -> std::io::Result<Child> {
        use std::os::unix::process::CommandExt as _;
        use std::process::Stdio;

        use super::descriptors;

        let mut command = std::process::Command::new(self.program);
        command
            .args(&self.args)
            .env_clear()
            .envs(self.env.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(self.stderr.map_or_else(Stdio::null, Stdio::from));
        if let Some(dir) = self.cwd {
            command.current_dir(dir);
        }
        let inherited = descriptors::open_from(descriptors::FIRST_INHERITED)?;
        // SAFETY: the hook calls only `setsid` and `fcntl`, both
        // async-signal-safe, and reads a list built before the fork.
        unsafe {
            command.pre_exec(move || {
                // A session of its own: a signal aimed at the starter's
                // process group never reaches the process.
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                descriptors::mark_close_on_exec(&inherited)
            });
        }
        command.spawn()
    }

    /// Start the process.
    ///
    /// # Errors
    ///
    /// The process cannot be started.
    #[cfg(windows)]
    pub fn spawn(self) -> std::io::Result<Child> {
        windows::spawn(self)
    }
}

#[cfg(windows)]
mod windows {
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::os::windows::process::ExitStatusExt as _;
    use std::process::ExitStatus;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS,
        DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    use super::Detached;

    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    const SPACE: u16 = b' ' as u16;
    const TAB: u16 = b'\t' as u16;
    const EQUALS: u16 = b'=' as u16;

    /// A started detached process: its handle, which waits on it and
    /// ends it, and nothing else of it.
    #[derive(Debug)]
    pub struct Child {
        process: OwnedHandle,
    }

    impl Child {
        /// The process's exit status when it has exited, `None` while it
        /// runs.
        ///
        /// # Errors
        ///
        /// The wait fails.
        pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            match self.wait_for(0)? {
                WAIT_TIMEOUT => Ok(None),
                _ => self.exit_status().map(Some),
            }
        }

        /// Wait for the process to exit.
        ///
        /// # Errors
        ///
        /// The wait fails.
        pub fn wait(&mut self) -> io::Result<ExitStatus> {
            self.wait_for(INFINITE)?;
            self.exit_status()
        }

        /// End the process.
        ///
        /// # Errors
        ///
        /// The process cannot be ended.
        pub fn kill(&mut self) -> io::Result<()> {
            /// The exit code the standard library's `Child::kill` ends a
            /// process with.
            const KILLED: u32 = 1;
            // SAFETY: the handle is this child's own, open until it drops.
            if unsafe { TerminateProcess(self.process.as_raw_handle(), KILLED) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Wait up to `millis` for the process; the wait's outcome,
        /// `WAIT_OBJECT_0` or `WAIT_TIMEOUT`.
        fn wait_for(&self, millis: u32) -> io::Result<u32> {
            // SAFETY: the handle is this child's own, open until it drops.
            let outcome = unsafe { WaitForSingleObject(self.process.as_raw_handle(), millis) };
            match outcome {
                WAIT_OBJECT_0 | WAIT_TIMEOUT => Ok(outcome),
                _ => Err(io::Error::last_os_error()),
            }
        }

        fn exit_status(&self) -> io::Result<ExitStatus> {
            let mut code = 0_u32;
            // SAFETY: the handle is this child's own and `code` outlives
            // the call.
            if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &raw mut code) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(ExitStatus::from_raw(code))
        }
    }

    pub fn spawn(detached: Detached<'_>) -> io::Result<Child> {
        let Detached {
            program,
            args,
            env,
            cwd,
            stderr,
        } = detached;
        let null = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("NUL")?;
        let null_handle: HANDLE = null.as_raw_handle();
        let stderr_handle: HANDLE = stderr.as_ref().map_or(
            null_handle,
            std::os::windows::io::AsRawHandle::as_raw_handle,
        );
        // A handle appears in the list once.
        let mut handles = vec![null_handle];
        if stderr_handle != null_handle {
            handles.push(stderr_handle);
        }
        // The listed handles are inheritable for the call alone: they are
        // this function's own and close when it returns. A process another
        // thread starts in between with every inheritable handle (the
        // standard library's spawn) may take one along — a handle on `NUL`
        // or on a log file, which holds nothing open that anyone waits on.
        for &handle in &handles {
            // SAFETY: `handle` is an open handle this function owns.
            if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let attributes = HandleList::new(&handles)?;
        let application = wide_nul(program.as_os_str());
        let mut command_line = command_line(program.as_os_str(), &args)?;
        let environment = environment_block(&env)?;
        let cwd = cwd.map(|dir| wide_nul(dir.as_os_str()));

        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb =
            u32::try_from(size_of::<STARTUPINFOEXW>()).expect("STARTUPINFOEXW is a few bytes");
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = null_handle;
        startup.StartupInfo.hStdOutput = null_handle;
        startup.StartupInfo.hStdError = stderr_handle;
        startup.lpAttributeList = attributes.as_ptr();
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: every string is NUL-terminated and outlives the call,
        // the environment block is double-NUL-terminated UTF-16 as
        // `CREATE_UNICODE_ENVIRONMENT` declares, and `startup` is a
        // `STARTUPINFOEXW` as `EXTENDED_STARTUPINFO_PRESENT` declares,
        // whose attribute list and the handles it names live until after
        // the call. Inheritance is on and the list narrows it to those
        // handles.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                // No console of the starter's, and a Ctrl-C aimed at the
                // starter's process group never reaches the process.
                DETACHED_PROCESS
                    | CREATE_NEW_PROCESS_GROUP
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                cwd.as_ref().map_or(ptr::null(), std::vec::Vec::as_ptr),
                (&raw const startup).cast(),
                &raw mut information,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call returned both handles, this function's to own.
        unsafe { CloseHandle(information.hThread) };
        // SAFETY: as above; the process handle is owned from here.
        let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess) };
        Ok(Child { process })
    }

    /// An initialized attribute list holding one
    /// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, which points into the handles
    /// it was built from: they outlive it.
    struct HandleList<'handles> {
        /// The list, inside `storage`.
        list: LPPROC_THREAD_ATTRIBUTE_LIST,
        /// The list's memory; `u64` elements keep it aligned for the
        /// system's use. Its heap block stays put when the `Vec` moves.
        _storage: Vec<u64>,
        handles: std::marker::PhantomData<&'handles [HANDLE]>,
    }

    impl<'handles> HandleList<'handles> {
        fn new(handles: &'handles [HANDLE]) -> io::Result<Self> {
            let mut size = 0_usize;
            // SAFETY: a null list asks only for the size; the call fails
            // with `ERROR_INSUFFICIENT_BUFFER` and sets `size`.
            unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &raw mut size) };
            if size == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut storage = vec![0_u64; size.div_ceil(size_of::<u64>())];
            let list: LPPROC_THREAD_ATTRIBUTE_LIST = storage.as_mut_ptr().cast();
            // SAFETY: `storage` holds at least `size` bytes.
            if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &raw mut size) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let initialized = Self {
                list,
                _storage: storage,
                handles: std::marker::PhantomData,
            };
            // SAFETY: the list is initialized for one attribute, and the
            // value is `handles`, which outlives the list.
            let updated = unsafe {
                UpdateProcThreadAttribute(
                    initialized.list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    size_of_val(handles),
                    ptr::null_mut(),
                    ptr::null(),
                )
            };
            if updated == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(initialized)
        }

        const fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.list
        }
    }

    impl Drop for HandleList<'_> {
        fn drop(&mut self) {
            // SAFETY: the list was initialized and is not used again.
            unsafe { DeleteProcThreadAttributeList(self.list) };
        }
    }

    fn wide_nul(text: &OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// The command line `CreateProcessW` takes, NUL-terminated, quoted so
    /// the parser every Rust and C runtime starts with — Microsoft's
    /// "Parsing C command-line arguments" rules, which
    /// `CommandLineToArgvW` and `std::env::args` follow — splits it back
    /// into exactly `program` and `args`.
    pub(super) fn command_line(program: &OsStr, args: &[OsString]) -> io::Result<Vec<u16>> {
        let program: Vec<u16> = program.encode_wide().collect();
        // The program name ends at the next quote and knows no escapes.
        if program.contains(&QUOTE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a program path holds a quote",
            ));
        }
        let mut line = vec![QUOTE];
        line.extend(program);
        line.push(QUOTE);
        for arg in args {
            line.push(SPACE);
            push_argument(&mut line, arg);
        }
        line.push(0);
        Ok(line)
    }

    /// `args` as the argument part of a command line, quoted as
    /// [`command_line`] quotes them, for a field that holds one (a
    /// scheduled task's `Arguments`).
    ///
    /// # Errors
    ///
    /// An argument is not valid Unicode.
    pub fn arguments_text(args: &[OsString]) -> io::Result<String> {
        let mut line = Vec::new();
        for (index, arg) in args.iter().enumerate() {
            if index > 0 {
                line.push(SPACE);
            }
            push_argument(&mut line, arg);
        }
        String::from_utf16(&line).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "an argument is not valid Unicode",
            )
        })
    }

    /// Append `arg` as one argument: quoted when it is empty or holds a
    /// space or tab; a quote is escaped with a backslash, and the
    /// backslashes before a quote — or before the closing quote — are
    /// doubled, the only place a backslash is special.
    fn push_argument(line: &mut Vec<u16>, arg: &OsStr) {
        let units: Vec<u16> = arg.encode_wide().collect();
        let quoted = units.is_empty() || units.iter().any(|&unit| unit == SPACE || unit == TAB);
        if quoted {
            line.push(QUOTE);
        }
        let mut backslashes = 0;
        for unit in units {
            if unit == BACKSLASH {
                backslashes += 1;
            } else {
                if unit == QUOTE {
                    line.extend(std::iter::repeat_n(BACKSLASH, backslashes + 1));
                }
                backslashes = 0;
            }
            line.push(unit);
        }
        if quoted {
            line.extend(std::iter::repeat_n(BACKSLASH, backslashes));
            line.push(QUOTE);
        }
    }

    /// The environment block `CREATE_UNICODE_ENVIRONMENT` declares:
    /// `name=value` entries, each NUL-terminated, sorted by name ignoring
    /// case as the block's documentation asks, the block itself ending in
    /// one more NUL.
    fn environment_block(env: &[(OsString, OsString)]) -> io::Result<Vec<u16>> {
        let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, what.to_owned());
        let mut entries = Vec::with_capacity(env.len());
        for (name, value) in env {
            let name: Vec<u16> = name.encode_wide().collect();
            let value: Vec<u16> = value.encode_wide().collect();
            // A name may begin with `=` (the per-drive working
            // directories are such variables) but holds none after.
            if name.is_empty() || name[1..].contains(&EQUALS) || name.contains(&0) {
                return Err(invalid(
                    "an environment variable name is empty or holds `=` or NUL",
                ));
            }
            if value.contains(&0) {
                return Err(invalid("an environment variable value holds NUL"));
            }
            entries.push((name, value));
        }
        let folded = |name: &[u16]| -> Vec<u16> {
            name.iter()
                .map(|&unit| {
                    u8::try_from(unit).map_or(unit, |byte| u16::from(byte.to_ascii_uppercase()))
                })
                .collect()
        };
        entries.sort_by_cached_key(|(name, _)| folded(name));
        let mut block = Vec::new();
        for (name, value) in entries {
            block.extend(name);
            block.push(EQUALS);
            block.extend(value);
            block.push(0);
        }
        if block.is_empty() {
            block.push(0);
        }
        block.push(0);
        Ok(block)
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::{OsStr, OsString};
        use std::os::windows::ffi::OsStringExt as _;

        /// The arguments `line` splits into, by the system's own parser.
        fn split(line: &[u16]) -> Vec<OsString> {
            use windows_sys::Win32::Foundation::LocalFree;
            use windows_sys::Win32::UI::Shell::CommandLineToArgvW;
            let mut count = 0;
            // SAFETY: `line` is NUL-terminated; the returned array is
            // freed below.
            let argv = unsafe { CommandLineToArgvW(line.as_ptr(), &raw mut count) };
            assert!(!argv.is_null(), "the line parses");
            let count = usize::try_from(count).expect("a count of arguments");
            let split = (0..count)
                .map(|index| {
                    // SAFETY: `argv` holds `count` NUL-terminated strings.
                    unsafe {
                        let arg = *argv.add(index);
                        let mut length = 0;
                        while *arg.add(length) != 0 {
                            length += 1;
                        }
                        OsString::from_wide(std::slice::from_raw_parts(arg, length))
                    }
                })
                .collect();
            // SAFETY: the array came from `CommandLineToArgvW`.
            unsafe { LocalFree(argv.cast()) };
            split
        }

        #[test]
        fn arguments_are_quoted_for_a_field_that_holds_a_command_line() {
            let args = ["daemon", "--run-dir", r"C:\Users\a b\run"].map(OsString::from);
            assert_eq!(
                super::arguments_text(&args).expect("text"),
                r#"daemon --run-dir "C:\Users\a b\run""#
            );
        }

        /// Every argument survives the line as it was, whatever spaces,
        /// quotes and backslashes it holds.
        #[test]
        fn the_command_line_splits_back_into_its_arguments() {
            let program = OsStr::new(r"C:\Program Files\stow\stow.exe");
            let args: Vec<OsString> = [
                "daemon",
                "--ready",
                r"\\.\pipe\stow-ready-1",
                "",
                "two words",
                r#"a "quoted" word"#,
                r"trailing\",
                r"trailing\\ and space\\",
                r#"slash\"quote"#,
                "\t",
            ]
            .map(OsString::from)
            .to_vec();
            let line = super::command_line(program, &args).expect("a command line");
            let mut expected = vec![program.to_owned()];
            expected.extend(args);
            assert_eq!(split(&line), expected);
        }
    }
}

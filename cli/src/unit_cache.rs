//! The local cache for units the registry identity cannot key (stow#978):
//! path and git dependencies, workspace members, primary packages, and
//! registry units compiled with custom codegen or as a staticlib — the
//! crate types sccache caches, `lib`/`rlib` and `staticlib`.
//!
//! Such a unit's source is not an immutable registry tarball, so it is
//! keyed by content in two stages:
//!
//! - the *invocation key*, computed before rustc runs: the toolchain
//!   (`rustc -vV` and the change stamps of the sysroot files a compile
//!   loads), the working directory, the argv with search paths dropped
//!   and every `--extern` replaced by the digest of the file it names,
//!   every library file the native search directories hold — what rustc
//!   can bundle into the artifact — and for a staticlib every rlib on the
//!   crate search path, and the environment cargo and rustc read outside
//!   dep-info;
//! - the *unit key*: the invocation key plus every file the compile's
//!   dep-info lists (by contents), the entries rustc's module search reads
//!   beside each of them, the value of every variable read through
//!   `env!`/`option_env!`, and the inputs the package's build script
//!   declares: the `output` file cargo writes beside `OUT_DIR`, every
//!   `cargo:rerun-if-changed` path — a directory recursively, the way
//!   cargo walks it — and every `cargo:rerun-if-env-changed` variable's
//!   value.
//!
//! An entry records its dep-info file list under its invocation key, and a
//! lookup re-hashes that list as it stands now: no extra rustc pass runs on
//! a hit or a miss.
//!
//! Every path and value is keyed raw, as rustc and the code it runs see
//! it: a proc macro reads `CARGO_MANIFEST_DIR` or the working directory
//! through `std::env` and may embed what it read, which
//! `--remap-path-prefix` never rewrites. An entry is therefore served only
//! to an invocation in the same directories. `--out-dir` is keyed exactly
//! when the artifact embeds it.
//!
//! What no key here sees is what a proc macro reads without dep-info or
//! a `rerun-if-*` line tracking it: a variable outside the keyed set that
//! no `rerun-if-env-changed` declares, a file the compile does not list
//! that no `rerun-if-changed` names, a database. sccache and ccache leave
//! the same gap.
//!
//! Nothing here mints a node or reports anything upstream: the entries
//! live beside the bundle entries, under the same per-rustc directory,
//! staging, copy-on-write clone path and LRU budget.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stow_types::error::Context;

use crate::artifact_cache::{
    LRU_STAMP_INTERVAL_MS, acquire_entry_exclusive_lock_async, acquire_entry_shared_lock,
    evict_entries, path_to_string, recorded_millis, remove_orphaned_entry_dir, sha256_file_bytes,
};
use crate::config::StowConfig;
use crate::inject::{OutputDirWriters, write_cached_output};
use crate::rustc_args::ParsedRustcArgs;
use crate::state_db::{db_int, now_millis};
use crate::supervisor::protocol::ServedStderr;

/// Directory, beside `bundles/`, holding unit entries.
const UNITS_DIR: &str = "units";
/// Layout and key version; part of every cache key and entry path.
const UNIT_LAYOUT_VERSION: &str = "unit-v2";
/// Largest stderr a stored entry replays. The served lines travel in one
/// supervisor frame, so an entry never carries more than a small part of it.
pub const MAX_DIAGNOSTICS_BYTES: usize = 1024 * 1024;

/// Crate types a unit entry can restore — the ones sccache caches. A
/// linked crate type (`proc-macro`, `dylib`, `bin`, `cdylib`) runs the
/// system linker, whose inputs — the linker, the files its arguments
/// name, the C toolchain's objects and libraries — no key here sees.
const CACHEABLE_CRATE_TYPES: &[&str] = &["lib", "rlib", "staticlib"];
/// `--emit` kinds a unit entry can restore; `dep-info` is required.
const CACHEABLE_EMITS: &[&str] = &["dep-info", "metadata", "link"];
/// The variables cargo sets for the unit it compiles, besides
/// `CARGO_PKG_*` — what a proc macro reads without dep-info tracking it.
/// Cargo's own configuration variables (`CARGO_TARGET_DIR`,
/// `CARGO_PROFILE_*`, …) reach rustc only through the argv cargo builds
/// from them, so they are not keyed.
const CARGO_UNIT_VARS: &[&str] = &[
    "CARGO",
    "CARGO_MANIFEST_DIR",
    "CARGO_MANIFEST_PATH",
    "CARGO_CRATE_NAME",
    "CARGO_BIN_NAME",
    "CARGO_PRIMARY_PACKAGE",
    "CARGO_TARGET_TMPDIR",
    "CARGO_RUSTC_CURRENT_DIR",
    "OUT_DIR",
];
/// Variables rustc itself reads that change what it produces.
const RUSTC_READ_VARS: &[&str] = &["RUSTC_BOOTSTRAP", "RUSTC_FORCE_RUSTC_VERSION", "SDKROOT"];
/// `-Z` options the cache cannot model: they read or write files the key
/// does not hash, add dep-info lines it does not parse, or print to stdout
/// or skip the outputs instead of writing them. A name ending in `-` is a
/// family.
const UNMODELED_UNSTABLE_OPTIONS: &[&str] = &[
    "checksum-hash-algorithm",
    "codegen-backend",
    "dump-",
    "llvm-plugins",
    "ls",
    "no-analysis",
    "no-codegen",
    "parse-crate-root-only",
    "print-",
    "profile-sample-use",
    "remap-cwd-prefix",
    "self-profile",
    "split-dwarf",
    "temps-dir",
    "unpretty",
];
/// The `--print` request a compile can carry: rustc reports it on stderr,
/// which the entry replays. Every other request prints to stdout.
const REPLAYED_PRINT: &str = "native-static-libs";
/// rustc flags whose value is the next argument.
const SEPARATE_VALUE_FLAGS: &[&str] = &[
    "--crate-name",
    "--crate-type",
    "--target",
    "--cfg",
    "--check-cfg",
    "--out-dir",
    "--extern",
    "--emit",
    "--json",
    "--edition",
    "--error-format",
    "--cap-lints",
    "--codegen",
    "--color",
    "--diagnostic-width",
    "--remap-path-prefix",
    "--sysroot",
    "--print",
    "-C",
    "-Z",
    "-L",
    "-l",
    "-A",
    "-W",
    "-D",
    "-F",
    "-o",
];
/// How far a file timestamp may trail the clock that `started` read: the
/// kernel stamps files from a coarse clock that lags by up to a tick.
const FINE_TIMESTAMP_SLACK: Duration = Duration::from_millis(50);
/// The same on a filesystem that keeps whole seconds — a timestamp with no
/// sub-second part — where FAT rounds to two.
const COARSE_TIMESTAMP_SLACK: Duration = Duration::from_secs(2);

/// The process one rustc invocation runs in: its working directory and
/// environment. Carried explicitly because the process that decides — the
/// build supervisor — is not the process cargo spawned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationEnv {
    /// The directory cargo started rustc in.
    pub cwd: PathBuf,
    /// The environment cargo started rustc with.
    pub vars: BTreeMap<OsString, OsString>,
}

impl InvocationEnv {
    /// This process's own working directory and environment.
    ///
    /// # Errors
    ///
    /// When the working directory cannot be read.
    pub fn current() -> stow_types::error::Result<Self> {
        Ok(Self {
            cwd: std::env::current_dir().wrap_err("read the rustc working directory")?,
            vars: std::env::vars_os().collect(),
        })
    }

    fn var(&self, name: &str) -> Option<&OsStr> {
        self.vars.get(OsStr::new(name)).map(OsString::as_os_str)
    }
}

/// The toolchain an invocation compiles with: its `rustc -vV` text and
/// its sysroot (`rustc --print sysroot`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolchain {
    /// The full `rustc -vV` text.
    pub verbose_version: String,
    /// The directory `rustc --print sysroot` names.
    pub sysroot: PathBuf,
}

/// One version of a file, known without reading it: its size, its
/// identity and both timestamps. The change time is the kernel's own — no
/// tool sets it — so every write, rename onto the path or timestamp
/// restore moves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChangeStamp {
    len: u64,
    file_id: (u64, u64),
    modified: SystemTime,
    changed: SystemTime,
}

impl ChangeStamp {
    #[cfg(unix)]
    fn read(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let metadata = std::fs::metadata(path)?;
        Ok(Self {
            len: metadata.len(),
            file_id: (metadata.dev(), metadata.ino()),
            modified: metadata.modified()?,
            changed: unix_time(metadata.ctime(), metadata.ctime_nsec())?,
        })
    }

    #[cfg(windows)]
    fn read(path: &Path) -> std::io::Result<Self> {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;

        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FileBasicInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        };

        // Backup semantics open a directory as well as a file.
        let file = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)?;
        let handle = file.as_raw_handle();
        let mut basic = FILE_BASIC_INFO::default();
        let basic_size = u32::try_from(std::mem::size_of::<FILE_BASIC_INFO>())
            .expect("FILE_BASIC_INFO fits in a u32");
        // SAFETY: `handle` is open for the call, and `basic` is a writable
        // FILE_BASIC_INFO of the size passed.
        if unsafe {
            GetFileInformationByHandleEx(handle, FileBasicInfo, (&raw mut basic).cast(), basic_size)
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let mut identity = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: `handle` is open for the call, and `identity` is a
        // writable BY_HANDLE_FILE_INFORMATION.
        if unsafe { GetFileInformationByHandle(handle, &raw mut identity) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let metadata = file.metadata()?;
        Ok(Self {
            len: metadata.len(),
            file_id: (
                u64::from(identity.dwVolumeSerialNumber),
                (u64::from(identity.nFileIndexHigh) << 32) | u64::from(identity.nFileIndexLow),
            ),
            modified: metadata.modified()?,
            changed: windows_time(basic.ChangeTime)?,
        })
    }

    /// The fields as key bytes.
    fn key_bytes(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.len,
            self.file_id.0,
            self.file_id.1,
            nanos_since_epoch(self.modified),
            nanos_since_epoch(self.changed)
        )
    }
}

#[cfg(unix)]
fn unix_time(seconds: i64, nanos: i64) -> std::io::Result<SystemTime> {
    let nanos = u64::try_from(nanos)
        .map(Duration::from_nanos)
        .map_err(|_| std::io::Error::other(format!("change time has {nanos} nanoseconds")))?;
    let whole = Duration::from_secs(seconds.unsigned_abs());
    Ok(if seconds >= 0 {
        UNIX_EPOCH + whole + nanos
    } else {
        UNIX_EPOCH - whole + nanos
    })
}

/// A Windows timestamp: 100 ns ticks since 1601-01-01.
#[cfg(windows)]
fn windows_time(ticks: i64) -> std::io::Result<SystemTime> {
    const TICKS_TO_UNIX_EPOCH: u64 = 11_644_473_600 * 10_000_000;
    let ticks = u64::try_from(ticks)
        .map_err(|_| std::io::Error::other(format!("change time is {ticks} ticks")))?;
    Ok(if ticks >= TICKS_TO_UNIX_EPOCH {
        UNIX_EPOCH + Duration::from_nanos((ticks - TICKS_TO_UNIX_EPOCH) * 100)
    } else {
        UNIX_EPOCH - Duration::from_nanos((TICKS_TO_UNIX_EPOCH - ticks) * 100)
    })
}

fn nanos_since_epoch(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i128::try_from(after.as_nanos()).expect("a timestamp fits in i128"),
        Err(before) => {
            -i128::try_from(before.duration().as_nanos()).expect("a timestamp fits in i128")
        }
    }
}

/// Whether a file stamped `time` was written at or after `started`, given
/// how far its filesystem's clock may trail the one `started` read.
fn written_since(time: SystemTime, started: SystemTime) -> bool {
    let coarse = time
        .duration_since(UNIX_EPOCH)
        .is_ok_and(|since| since.subsec_nanos() == 0);
    let slack = if coarse {
        COARSE_TIMESTAMP_SLACK
    } else {
        FINE_TIMESTAMP_SLACK
    };
    time + slack >= started
}

/// Content digests this process already computed, each valid while its
/// file still carries the change stamp it was read under — every unit of
/// a build reads the same rmeta, rlib and native library files.
#[derive(Debug, Default)]
pub struct DigestMemo(Mutex<HashMap<PathBuf, (ChangeStamp, String)>>);

impl DigestMemo {
    /// The blake3 of `path`'s contents and the stamp it carries once read.
    /// A file that changed while it was read is not memoized; its stamp
    /// then shows the change.
    fn digest(&self, path: &Path) -> std::io::Result<(ChangeStamp, String)> {
        let before = ChangeStamp::read(path)?;
        if let Some((stamp, digest)) = self.0.lock().expect("digest memo mutex").get(path)
            && *stamp == before
        {
            return Ok((before, digest.clone()));
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update_reader(std::fs::File::open(path)?)?;
        let digest = hasher.finalize().to_hex().to_string();
        let after = ChangeStamp::read(path)?;
        if after == before {
            self.0
                .lock()
                .expect("digest memo mutex")
                .insert(path.to_path_buf(), (before, digest.clone()));
        }
        Ok((after, digest))
    }
}

/// One output file of a unit entry, stored under `files/<file_name>` and
/// served to `<out-dir>/<file_name>` — the file names are the argv's own,
/// which the key covers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct UnitOutput {
    file_name: String,
    /// The artifact notification rustc prints for the file (`metadata`,
    /// `link`), or `None` for a file it leaves beside them unannounced —
    /// the objects of unpacked split debuginfo.
    emit: Option<String>,
    sha256: String,
}

/// What a dep-info file says the compile read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct UnitInputs {
    /// Every file the dep-info lists, spelled as rustc spelled it —
    /// relative to the working directory, or absolute — sorted.
    files: Vec<String>,
    /// Every variable read through `env!`/`option_env!`, sorted.
    env: Vec<String>,
}

/// Whether a computation produced a key, or found an input it cannot
/// hash — the unit is then compiled and not cached, for the reason given.
#[derive(Debug)]
pub enum Keying<T> {
    Keyed(T),
    Uncacheable(String),
}

/// The pre-compile state a store needs: the invocation key and the
/// process the compile ran in.
#[derive(Debug, Clone)]
pub struct UnitPlan {
    invocation_key: String,
    target: String,
    rustc_version: String,
    env: InvocationEnv,
    /// Taken before rustc started: an input changed at or after it may
    /// not be what rustc read, and an output older than it is not this
    /// compile's.
    started: SystemTime,
}

/// What a lookup came to.
#[derive(Debug)]
pub enum UnitLookup {
    /// The outputs and dep-info are in place; these lines are owed to
    /// cargo's stderr.
    Served(ServedStderr),
    /// No entry matches; compile and store under this plan.
    Compile(Box<UnitPlan>),
}

/// Every `-C`/`--codegen` option as `(key, value)`, in argv order, with
/// `-g` as the `debuginfo=2` it abbreviates.
fn codegen_options(args: &[OsString]) -> Vec<(&str, Option<&str>)> {
    let mut options = Vec::new();
    let mut iter = args.iter().filter_map(|arg| arg.to_str());
    while let Some(arg) = iter.next() {
        if arg == "-g" {
            options.push(("debuginfo", Some("2")));
            continue;
        }
        let option = match arg {
            "-C" | "--codegen" => iter.next(),
            _ => arg
                .strip_prefix("--codegen=")
                .or_else(|| arg.strip_prefix("-C")),
        };
        if let Some(option) = option {
            options.push(
                option
                    .split_once('=')
                    .map_or((option, None), |(key, value)| (key, Some(value))),
            );
        }
    }
    options
}

/// Why this unit is compiled without the unit cache, or `None` when its
/// shape is one the cache can key and restore.
pub fn refusal(parsed: &ParsedRustcArgs, args: &[OsString]) -> Option<String> {
    if parsed.crate_types.is_empty() {
        return Some("no --crate-type".to_owned());
    }
    if let Some(kind) = parsed
        .crate_types
        .iter()
        .find(|kind| !CACHEABLE_CRATE_TYPES.contains(&kind.as_str()))
    {
        return Some(format!("crate type `{kind}` is not cached"));
    }
    if parsed.out_dir.is_none() {
        return Some("no --out-dir".to_owned());
    }
    if parsed.input_path.is_none() {
        return Some("no input file".to_owned());
    }
    if !parsed.emit.contains("dep-info") {
        return Some("no dep-info emitted".to_owned());
    }
    if let Some(emit) = parsed
        .emit
        .iter()
        .find(|emit| !CACHEABLE_EMITS.contains(&emit.as_str()))
    {
        return Some(format!("--emit `{emit}` is not cached"));
    }
    if parsed
        .target
        .as_deref()
        .is_some_and(|target| Path::new(target).extension() == Some(OsStr::new("json")))
    {
        return Some("a target spec file is not hashed".to_owned());
    }
    for (key, _) in codegen_options(args) {
        if key == "incremental" {
            return Some("incremental compilation state is not cached".to_owned());
        }
        if key == "profile-use" || key == "profile-sample-use" {
            return Some(format!("`-C {key}` reads a profile the key does not hash"));
        }
    }
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let Some(arg) = arg.to_str() else {
            return Some("an argument is not UTF-8".to_owned());
        };
        if arg.starts_with('@') {
            return Some("an @argfile is not hashed".to_owned());
        }
        if arg == "-o" || arg.starts_with("--sysroot") {
            return Some(format!("`{arg}` is not cached"));
        }
        let print = if arg == "--print" {
            iter.next().and_then(|value| value.to_str())
        } else {
            arg.strip_prefix("--print=")
        };
        if let Some(request) = print
            && request != REPLAYED_PRINT
        {
            return Some(format!("`--print {request}` writes to stdout"));
        }
        let unstable = if arg == "-Z" {
            iter.next().and_then(|value| value.to_str())
        } else {
            arg.strip_prefix("-Z")
        };
        if let Some(option) = unstable {
            let key = option.split_once('=').map_or(option, |(key, _)| key);
            if UNMODELED_UNSTABLE_OPTIONS
                .iter()
                .any(|name| key == *name || (name.ends_with('-') && key.starts_with(name)))
            {
                return Some(format!("`-Z {option}` is not modeled by the unit cache"));
            }
        }
    }
    None
}

/// Whether the artifact embeds `--out-dir` itself, as measured: with
/// debuginfo on, an MSVC-like target's objects record their own path, and
/// an ELF target's record the split DWARF path when split debuginfo is
/// `packed` or `unpacked`; an Apple target's artifacts never do, and with
/// debuginfo off no target's do.
fn out_dir_reaches_output(args: &[OsString], target: &str) -> bool {
    let mut debuginfo = false;
    let mut split = None;
    for (key, value) in codegen_options(args) {
        match key {
            "debuginfo" => debuginfo = !matches!(value, Some("0" | "none")),
            "split-debuginfo" => split = value,
            _ => {}
        }
    }
    let vendor = target.split('-').nth(1);
    if !debuginfo || vendor == Some("apple") {
        return false;
    }
    let msvc_like = target.ends_with("-msvc") || target.split('-').any(|part| part == "uefi");
    msvc_like || matches!(split, Some("packed" | "unpacked"))
}

/// Length-prefixed fields under one blake3 domain, so no two field lists
/// share an encoding.
struct KeyHasher(blake3::Hasher);

impl KeyHasher {
    fn new(domain: &str) -> Self {
        Self(blake3::Hasher::new_derive_key(domain))
    }

    fn field(&mut self, bytes: &[u8]) {
        self.0.update(&(bytes.len() as u64).to_le_bytes());
        self.0.update(bytes);
    }

    fn finish(self) -> String {
        self.0.finalize().to_hex().to_string()
    }
}

/// Whether the invocation key reads `name` from the environment.
fn is_keyed_var(name: &str) -> bool {
    name.starts_with("CARGO_PKG_")
        || CARGO_UNIT_VARS.contains(&name)
        || RUSTC_READ_VARS.contains(&name)
        || name.ends_with("_DEPLOYMENT_TARGET")
}

/// The `-L` directories rustc searches: `(native libraries, crates)`.
fn search_dirs(args: &[OsString], cwd: &Path) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let (mut native, mut crates) = (Vec::new(), Vec::new());
    let mut iter = args.iter().filter_map(|arg| arg.to_str());
    while let Some(arg) = iter.next() {
        let value = if arg == "-L" {
            iter.next()
        } else {
            arg.strip_prefix("-L")
        };
        let Some(value) = value else {
            continue;
        };
        match value.split_once('=') {
            Some(("native", path)) => native.push(cwd.join(path)),
            Some(("crate" | "dependency", path)) => crates.push(cwd.join(path)),
            // Frameworks are only ever linked, which no cached crate type does.
            Some(("framework", _)) => {}
            Some(("all", path)) => {
                native.push(cwd.join(path));
                crates.push(cwd.join(path));
            }
            _ => {
                native.push(cwd.join(value));
                crates.push(cwd.join(value));
            }
        }
    }
    (native, crates)
}

/// Whether `name` is a dynamic library, which producing an rlib or a
/// staticlib never reads.
fn is_dynamic_library(name: &str) -> bool {
    // Windows names are case-insensitive.
    let name = name.to_ascii_lowercase();
    let versioned_so = name.split_once(".so.").is_some_and(|(_, version)| {
        version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    });
    versioned_so
        || [".so", ".dylib", ".dll", ".tbd"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

/// Key every regular file directly in `dir` whose name `include` accepts,
/// by contents. A missing directory is keyed as absent.
fn key_directory_files(
    key: &mut KeyHasher,
    memo: &DigestMemo,
    dir: &Path,
    include: impl Fn(&str) -> bool,
) -> Result<(), String> {
    key.field(dir.as_os_str().as_encoded_bytes());
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            key.field(b"absent");
            return Ok(());
        }
        Err(error) => return Err(format!("list {}: {error}", dir.display())),
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|error| format!("list {}: {error}", dir.display()))?
            .path();
        let Some(name) = path.file_name().map(OsStr::to_owned) else {
            continue;
        };
        let Some(name) = name.to_str().map(str::to_owned) else {
            return Err(format!("{} has a non-UTF-8 entry", dir.display()));
        };
        if include(&name) && path.is_file() {
            files.push((name, path));
        }
    }
    files.sort();
    for (name, path) in files {
        let (_, digest) = memo
            .digest(&path)
            .map_err(|error| format!("hash {}: {error}", path.display()))?;
        key.field(name.as_bytes());
        key.field(digest.as_bytes());
    }
    Ok(())
}

/// Key the toolchain beyond `rustc -vV`, which two builds of one commit
/// share: the sysroot, and the change stamp of every file a compile for
/// `target` loads from it — the compiler's own libraries and the target's
/// standard library. Stamps, not contents: the files are written once
/// per install, and they are a quarter of a gigabyte.
fn key_toolchain(key: &mut KeyHasher, toolchain: &Toolchain, target: &str) -> Result<(), String> {
    key.field(toolchain.verbose_version.as_bytes());
    key.field(toolchain.sysroot.as_os_str().as_encoded_bytes());
    let sysroot = &toolchain.sysroot;
    let rustc = format!("rustc{}", std::env::consts::EXE_SUFFIX);
    let list = |dir: &Path, include: &dyn Fn(&str) -> bool| -> Result<Vec<PathBuf>, String> {
        let mut files = Vec::new();
        for entry in
            std::fs::read_dir(dir).map_err(|error| format!("list {}: {error}", dir.display()))?
        {
            let path = entry
                .map_err(|error| format!("list {}: {error}", dir.display()))?
                .path();
            if path.is_file()
                && path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(include)
            {
                files.push(path);
            }
        }
        Ok(files)
    };
    // The compiler: `rustc` and the libraries it loads — beside it on
    // Windows, under `lib` elsewhere.
    let mut files = list(&sysroot.join("bin"), &|name| {
        name == rustc
            || Path::new(name)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))
    })?;
    files.extend(list(&sysroot.join("lib"), &|_| true)?);
    let target_dir = sysroot.join("lib").join("rustlib").join(target);
    let spec = target_dir.join("target.json");
    if spec.is_file() {
        files.push(spec);
    }
    for entry in walkdir::WalkDir::new(target_dir.join("lib")).sort_by_file_name() {
        let entry =
            entry.map_err(|error| format!("walk the target's standard library: {error}"))?;
        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    files.sort();
    for path in files {
        let stamp = ChangeStamp::read(&path)
            .map_err(|error| format!("stat {}: {error}", path.display()))?;
        key.field(path.as_os_str().as_encoded_bytes());
        key.field(stamp.key_bytes().as_bytes());
    }
    Ok(())
}

/// Compute the invocation key: everything that decides the compile's
/// output and is known before rustc runs. Blocking: it reads every
/// `--extern` and searched library. An `Err` names what cannot be keyed.
fn invocation_key(
    args: &[OsString],
    parsed: &ParsedRustcArgs,
    env: &InvocationEnv,
    toolchain: &Toolchain,
    target: &str,
    memo: &DigestMemo,
) -> Result<String, String> {
    if let Some(name) = parsed.target.as_deref()
        && let Some(path) = env.var("RUST_TARGET_PATH")
        && std::env::split_paths(path).any(|dir| dir.join(format!("{name}.json")).exists())
    {
        return Err(format!(
            "RUST_TARGET_PATH holds a spec for `{name}` the key does not hash"
        ));
    }
    let mut sections = KeyHasher::new("stow.local-unit.invocation.v2");

    let mut key = KeyHasher::new("stow.local-unit.toolchain.v2");
    key_toolchain(&mut key, toolchain, target)?;
    sections.field(key.finish().as_bytes());

    sections.field(env.cwd.as_os_str().as_encoded_bytes());

    let keep_out_dir = out_dir_reaches_output(args, target);
    let mut key = KeyHasher::new("stow.local-unit.argv.v2");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let arg = arg
            .to_str()
            .ok_or_else(|| "an argument is not UTF-8".to_owned())?;
        let (flag, value) = if SEPARATE_VALUE_FLAGS.contains(&arg) {
            let value = iter
                .next()
                .and_then(|value| value.to_str())
                .ok_or_else(|| format!("`{arg}` has no UTF-8 value"))?;
            (arg, Some(value))
        } else if let Some((flag, value)) = arg.split_once('=')
            && flag.starts_with("--")
            && SEPARATE_VALUE_FLAGS.contains(&flag)
        {
            (flag, Some(value))
        } else if let Some(value) = arg.strip_prefix("-L") {
            ("-L", Some(value))
        } else {
            (arg, None)
        };
        match (flag, value) {
            // What the searches find is keyed by content below, and the
            // rendering width of diagnostics is not part of the artifact.
            ("-L" | "--diagnostic-width", _) => {}
            ("--out-dir", _) if !keep_out_dir => {}
            ("--extern", Some(spec)) => {
                key.field(b"--extern");
                match spec.split_once('=') {
                    Some((name, path)) => {
                        let path = env.cwd.join(path);
                        let (_, digest) = memo.digest(&path).map_err(|error| {
                            format!("--extern {name} at {}: {error}", path.display())
                        })?;
                        key.field(format!("{name}={digest}").as_bytes());
                    }
                    None => key.field(spec.as_bytes()),
                }
            }
            (flag, value) => {
                key.field(flag.as_bytes());
                if let Some(value) = value {
                    key.field(value.as_bytes());
                }
            }
        }
    }
    sections.field(key.finish().as_bytes());

    // A static library rustc bundles is found on the native search path by
    // a name the source may give (`#[link(kind = "static")]`), so every
    // library file there is keyed.
    let (native_dirs, crate_dirs) = search_dirs(args, &env.cwd);
    let mut key = KeyHasher::new("stow.local-unit.native.v2");
    for dir in native_dirs {
        key_directory_files(&mut key, memo, &dir, |name| !is_dynamic_library(name))?;
    }
    sections.field(key.finish().as_bytes());

    // A staticlib archives the objects of every rlib in its dependency
    // closure, which the direct externs' contents do not pin: a rebuilt
    // `-sys` crate's bundled objects leave its dependents' rmeta alone.
    // An rlib reads only the rmeta of its transitive dependencies, which
    // the direct externs pin through the dependency hashes they record.
    let mut key = KeyHasher::new("stow.local-unit.crates.v2");
    if parsed.crate_types.iter().any(|kind| kind == "staticlib") {
        for dir in crate_dirs {
            key_directory_files(&mut key, memo, &dir, |name| {
                Path::new(name).extension() == Some(OsStr::new("rlib"))
            })?;
        }
    }
    sections.field(key.finish().as_bytes());

    let mut key = KeyHasher::new("stow.local-unit.env.v2");
    for (name, value) in &env.vars {
        if name.to_str().is_some_and(is_keyed_var) {
            key.field(name.as_encoded_bytes());
            key.field(value.as_encoded_bytes());
        }
    }
    sections.field(key.finish().as_bytes());
    Ok(sections.finish())
}

/// What one dep-info file lists: its files' spellings in order, and its
/// `# env-dep:` lines verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DepInfo {
    files: Vec<String>,
    env_lines: Vec<String>,
}

impl DepInfo {
    /// Every variable the `# env-dep:` lines name, sorted.
    fn env_names(&self) -> Vec<String> {
        self.env_lines
            .iter()
            .filter_map(|line| line.strip_prefix("# env-dep:"))
            .map(|rest| {
                rest.split_once('=')
                    .map_or(rest, |(name, _)| name)
                    .to_owned()
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Parse rustc's Makefile-syntax dep-info: `target: deps` rules whose
/// paths escape spaces as `\ `, then `# env-dep:NAME[=VALUE]` lines. Any
/// other comment is an input the key does not model.
fn parse_dep_info(text: &str) -> Result<DepInfo, String> {
    let mut files = Vec::new();
    let mut seen = BTreeSet::new();
    let mut env_lines = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if line.starts_with("# env-dep:") {
            env_lines.push(line.to_owned());
            continue;
        }
        if line.starts_with('#') {
            return Err(format!("dep-info line `{line}` is not modeled"));
        }
        let deps = match line.find(": ") {
            Some(index) => &line[index + 2..],
            None if line.ends_with(':') => "",
            None => return Err(format!("dep-info line `{line}` is not a rule")),
        };
        for dep in split_escaped(deps) {
            if seen.insert(dep.clone()) {
                files.push(dep);
            }
        }
    }
    Ok(DepInfo { files, env_lines })
}

/// Split a dep-info dependency list on spaces that `\ ` does not escape.
fn split_escaped(deps: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut chars = deps.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' if chars.peek() == Some(&' ') => {
                current.push(' ');
                chars.next();
            }
            ' ' => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            other => current.push(other),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn escape_dep_path(path: &str) -> String {
    path.replace(' ', "\\ ")
}

/// The directories rustc's module search reads beside the inputs: each
/// input's own directory, where `mod foo;` finds `foo.rs` or `foo/`, and
/// for a `.rs` input the directory of its name, where its own `mod`
/// children live. Dep-info lists the file a search found, never the
/// candidates it rejected — the second of `foo.rs` and `foo/mod.rs` that
/// fails the compile with E0761.
fn module_search_dirs(paths: &[PathBuf]) -> BTreeSet<PathBuf> {
    let mut dirs = BTreeSet::new();
    for path in paths {
        if let Some(parent) = path.parent() {
            dirs.insert(parent.to_path_buf());
        }
        if path.extension() == Some(OsStr::new("rs")) {
            dirs.insert(path.with_extension(""));
        }
    }
    dirs
}

/// The entries of `dir` a module search can find — directories, and files
/// named `*.rs` — with the directory's stamp, or `None` when it does not
/// exist. Names starting with `.` are never module names.
fn module_search_listing(dir: &Path) -> std::io::Result<Option<(ChangeStamp, Vec<Vec<u8>>)>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let bytes = name.as_encoded_bytes();
        if bytes.starts_with(b".") {
            continue;
        }
        let is_dir = entry.file_type()?.is_dir() || entry.path().is_dir();
        if is_dir {
            let mut dir_entry = bytes.to_vec();
            dir_entry.push(b'/');
            names.push(dir_entry);
        } else if bytes.ends_with(b".rs") {
            names.push(bytes.to_vec());
        }
    }
    names.sort();
    Ok(Some((ChangeStamp::read(dir)?, names)))
}

/// The inputs a package's build script declares, hashed once per
/// invocation: its section digest and the latest change among the files
/// and directories it names. `None` when the invocation has no `OUT_DIR`
/// — the package has no build script.
#[derive(Debug)]
struct BuildScriptInputs {
    digest: String,
    newest_change: SystemTime,
}

/// Hash the `output` file cargo writes beside `OUT_DIR` and the inputs
/// its `cargo:rerun-if-changed`/`cargo::rerun-if-changed` and
/// `cargo:rerun-if-env-changed`/`cargo::rerun-if-env-changed` lines
/// declare — what a build script or a proc macro then reads without
/// dep-info tracking it, the way cargo's own rebuild decision watches
/// it. A relative path resolves against `CARGO_MANIFEST_DIR`.
///
/// The `output` file must read: `OUT_DIR` is set only for a package
/// whose build script ran, and cargo always writes its captured stdout
/// there. A missing one is an inconsistent state, an error that fails
/// the invocation — never an absent input.
fn build_script_inputs(
    env: &InvocationEnv,
    memo: &DigestMemo,
) -> Result<Option<BuildScriptInputs>, (PathBuf, std::io::Error)> {
    let Some(out_dir) = env.var("OUT_DIR") else {
        return Ok(None);
    };
    let out_dir = Path::new(out_dir);
    let output = out_dir
        .parent()
        .ok_or_else(|| {
            (
                out_dir.to_path_buf(),
                std::io::Error::other("OUT_DIR has no parent to hold the build script's output"),
            )
        })?
        .join("output");
    let bytes = std::fs::read(&output).map_err(|error| (output.clone(), error))?;
    let stamp = ChangeStamp::read(&output).map_err(|error| (output.clone(), error))?;
    let mut newest_change = stamp.changed;
    let mut key = KeyHasher::new("stow.local-unit.build-script.v2");
    key.field(&bytes);
    let text = String::from_utf8_lossy(&bytes);
    let mut declared_paths = Vec::new();
    let mut declared_vars = Vec::new();
    for line in text.lines() {
        let Some(rest) = line
            .strip_prefix("cargo::")
            .or_else(|| line.strip_prefix("cargo:"))
        else {
            continue;
        };
        match rest.split_once('=') {
            Some(("rerun-if-changed", path)) => declared_paths.push(path),
            Some(("rerun-if-env-changed", name)) => declared_vars.push(name),
            _ => {}
        }
    }
    declared_paths.sort_unstable();
    declared_paths.dedup();
    let manifest_dir = env.var("CARGO_MANIFEST_DIR").map(PathBuf::from);
    for declared in declared_paths {
        key.field(declared.as_bytes());
        let path = Path::new(declared);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            let Some(manifest_dir) = &manifest_dir else {
                return Err((
                    output,
                    std::io::Error::other(format!(
                        "`rerun-if-changed={declared}` is relative, but CARGO_MANIFEST_DIR is unset"
                    )),
                ));
            };
            manifest_dir.join(path)
        };
        key_build_script_path(&mut key, memo, &path, &mut newest_change)?;
    }
    for name in declared_vars {
        key.field(name.as_bytes());
        match env.var(name) {
            Some(value) => {
                key.field(b"set");
                key.field(value.as_encoded_bytes());
            }
            None => key.field(b"unset"),
        }
    }
    Ok(Some(BuildScriptInputs {
        digest: key.finish(),
        newest_change,
    }))
}

/// Key one `rerun-if-changed` path as it stands: a file by contents, a
/// directory by the relative path and contents of every file under it,
/// and a missing path by a marker and its nearest surviving ancestor's
/// stamp — so one removed while rustc ran still fails the
/// changed-while-compiling check instead of storing as absent.
fn key_build_script_path(
    key: &mut KeyHasher,
    memo: &DigestMemo,
    path: &Path,
    newest_change: &mut SystemTime,
) -> Result<(), (PathBuf, std::io::Error)> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            key.field(b"absent");
            let mut ancestor = path.parent();
            while let Some(dir) = ancestor {
                match ChangeStamp::read(dir) {
                    Ok(stamp) => {
                        *newest_change = (*newest_change).max(stamp.changed);
                        return Ok(());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        ancestor = dir.parent();
                    }
                    Err(error) => return Err((dir.to_path_buf(), error)),
                }
            }
            return Ok(());
        }
        Err(error) => return Err((path.to_path_buf(), error)),
    };
    if metadata.is_dir() {
        key.field(b"dir");
        for entry in walkdir::WalkDir::new(path).sort_by_file_name() {
            let entry = entry.map_err(|error| {
                (
                    error
                        .path()
                        .map_or_else(|| path.to_path_buf(), Path::to_path_buf),
                    std::io::Error::other(error),
                )
            })?;
            let entry_path = entry.path();
            if entry_path.is_dir() {
                let stamp = ChangeStamp::read(entry_path)
                    .map_err(|error| (entry_path.to_path_buf(), error))?;
                *newest_change = (*newest_change).max(stamp.changed);
            } else if entry_path.is_file() {
                let relative = entry_path
                    .strip_prefix(path)
                    .expect("a walked entry is under the walked directory");
                let (stamp, digest) = memo
                    .digest(entry_path)
                    .map_err(|error| (entry_path.to_path_buf(), error))?;
                *newest_change = (*newest_change).max(stamp.changed);
                key.field(relative.as_os_str().as_encoded_bytes());
                key.field(digest.as_bytes());
            }
        }
        return Ok(());
    }
    if metadata.is_file() {
        key.field(b"file");
        let (stamp, digest) = memo
            .digest(path)
            .map_err(|error| (path.to_path_buf(), error))?;
        *newest_change = (*newest_change).max(stamp.changed);
        key.field(digest.as_bytes());
        return Ok(());
    }
    // A named pipe, socket or device cannot be hashed; its stamp is the
    // only honest key.
    key.field(b"other");
    let stamp = ChangeStamp::read(path).map_err(|error| (path.to_path_buf(), error))?;
    *newest_change = (*newest_change).max(stamp.changed);
    key.field(stamp.key_bytes().as_bytes());
    Ok(())
}

/// A unit key and the latest change time among what it read.
#[derive(Debug)]
struct UnitKey {
    key: String,
    newest_change: SystemTime,
}

/// The unit key over `inputs` as they stand now. Blocking. An `Err` is
/// the input or directory that could not be read.
fn unit_key(
    invocation_key: &str,
    inputs: &UnitInputs,
    env: &InvocationEnv,
    build_script: Option<&BuildScriptInputs>,
    memo: &DigestMemo,
) -> Result<UnitKey, (PathBuf, std::io::Error)> {
    let mut key = KeyHasher::new("stow.local-unit.v2");
    key.field(invocation_key.as_bytes());
    let mut newest_change = UNIX_EPOCH;
    let paths = inputs
        .files
        .iter()
        .map(|spelling| env.cwd.join(spelling))
        .collect::<Vec<_>>();
    let mut files = KeyHasher::new("stow.local-unit.inputs.v2");
    for (spelling, path) in inputs.files.iter().zip(&paths) {
        let (stamp, digest) = memo.digest(path).map_err(|error| (path.clone(), error))?;
        newest_change = newest_change.max(stamp.changed);
        files.field(spelling.as_bytes());
        files.field(digest.as_bytes());
    }
    key.field(files.finish().as_bytes());
    let mut dirs = KeyHasher::new("stow.local-unit.module-search.v2");
    for dir in module_search_dirs(&paths) {
        dirs.field(dir.as_os_str().as_encoded_bytes());
        match module_search_listing(&dir).map_err(|error| (dir.clone(), error))? {
            Some((stamp, names)) => {
                newest_change = newest_change.max(stamp.changed);
                for name in names {
                    dirs.field(&name);
                }
            }
            None => dirs.field(b"\0absent"),
        }
    }
    key.field(dirs.finish().as_bytes());
    // `env!` values are embedded verbatim, so they are keyed raw.
    let mut vars = KeyHasher::new("stow.local-unit.env-deps.v2");
    for name in &inputs.env {
        vars.field(name.as_bytes());
        match env.var(name) {
            Some(value) => {
                vars.field(b"set");
                vars.field(value.as_encoded_bytes());
            }
            None => vars.field(b"unset"),
        }
    }
    key.field(vars.finish().as_bytes());
    if let Some(build_script) = build_script {
        newest_change = newest_change.max(build_script.newest_change);
        key.field(build_script.digest.as_bytes());
    }
    Ok(UnitKey {
        key: key.finish(),
        newest_change,
    })
}

fn cache_key(target: &str, unit_key: &str) -> String {
    format!("{UNIT_LAYOUT_VERSION}/{target}/{unit_key}")
}

fn entry_relative_dir(target: &str, unit_key: &str) -> PathBuf {
    PathBuf::from(UNITS_DIR)
        .join(UNIT_LAYOUT_VERSION)
        .join(target)
        .join(unit_key)
}

/// A stored entry as a serve reads it, under the entry's shared lock.
#[derive(Debug, Clone, sqlx::FromRow)]
struct UnitEntryRow {
    inputs_json: String,
    env_dep_lines_json: String,
    outputs_json: String,
    diagnostics: String,
    relative_dir: String,
    last_accessed_ms: i64,
}

/// Where a lookup's invocation runs and with what: the facts a key reads
/// that are not the argv.
#[derive(Debug, Clone, Copy)]
pub struct LookupContext<'a> {
    /// The process cargo started rustc in.
    pub env: &'a InvocationEnv,
    /// The toolchain the invocation compiles with.
    pub toolchain: &'a Toolchain,
    /// The unit's target: its `--target`, else the host.
    pub target: &'a str,
    /// The release the per-rustc cache directory is named for.
    pub rustc_version: &'a str,
    /// The host triple.
    pub host: &'a str,
}

/// Look `parsed` up: serve a matching entry, or return the plan its
/// compile stores under.
///
/// # Errors
///
/// A failure of the cache itself — the state database, a malformed row,
/// an entry that cannot be written into the target directory, the
/// declared build-script inputs of a unit with `OUT_DIR` that cannot be
/// read. An entry that fails to serve is removed so the next build
/// compiles it.
pub async fn lookup(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
    args: &[OsString],
    context: LookupContext<'_>,
    memo: &Arc<DigestMemo>,
) -> stow_types::error::Result<Keying<UnitLookup>> {
    let started = SystemTime::now();
    let invocation_key = {
        let (args, parsed, env, toolchain, target, memo) = (
            args.to_vec(),
            parsed.clone(),
            context.env.clone(),
            context.toolchain.clone(),
            context.target.to_owned(),
            Arc::clone(memo),
        );
        tokio::task::spawn_blocking(move || {
            invocation_key(&args, &parsed, &env, &toolchain, &target, &memo)
        })
        .await
        .wrap_err("join unit invocation key task")?
    };
    let invocation_key = match invocation_key {
        Ok(key) => key,
        Err(reason) => return Ok(Keying::Uncacheable(reason)),
    };
    let connection = config.state_db_pool().await?;
    let candidates = sqlx::query_as::<_, (String, String)>(
        "SELECT cache_key, inputs_json FROM unit_cache_entries \
         WHERE rustc_version = ? AND invocation_key = ?",
    )
    .bind(context.rustc_version)
    .bind(&invocation_key)
    .fetch_all(&connection)
    .await
    .wrap_err("read unit cache candidates")?;
    let plan = UnitPlan {
        invocation_key,
        target: context.target.to_owned(),
        rustc_version: context.rustc_version.to_owned(),
        env: context.env.clone(),
        started,
    };
    if let Some(cache_key) = matching_entry(&plan, candidates, memo).await? {
        match serve_entry(config, &connection, parsed, &plan, &cache_key, context.host).await {
            Ok(Some(stderr)) => return Ok(Keying::Keyed(UnitLookup::Served(stderr))),
            Ok(None) => {}
            Err(error) => {
                let removed = remove_entry(config, &connection, &plan, &cache_key).await;
                return Err(match removed {
                    Ok(()) => error,
                    Err(remove_error) => stow_types::stow_error!(
                        "{error}; removing the unservable entry {cache_key} also failed: {remove_error}"
                    ),
                });
            }
        }
    }
    Ok(Keying::Keyed(UnitLookup::Compile(Box::new(plan))))
}

/// The cache key of the candidate whose unit key the inputs re-hash to,
/// hashing each distinct input list once. A candidate whose inputs no
/// longer read is a miss, not a failure; the declared build-script
/// inputs of a unit with `OUT_DIR` must read, or the invocation fails.
async fn matching_entry(
    plan: &UnitPlan,
    candidates: Vec<(String, String)>,
    memo: &Arc<DigestMemo>,
) -> stow_types::error::Result<Option<String>> {
    let (plan, memo) = (plan.clone(), Arc::clone(memo));
    tokio::task::spawn_blocking(move || {
        let build_script = build_script_inputs(&plan.env, &memo).map_err(|(path, error)| {
            stow_types::stow_error!(
                "read the declared build-script inputs at {}: {error}",
                path.display()
            )
        })?;
        let mut by_inputs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (cache_key, inputs_json) in candidates {
            by_inputs.entry(inputs_json).or_default().push(cache_key);
        }
        for (inputs_json, cache_keys) in by_inputs {
            let inputs: UnitInputs = serde_json::from_str(&inputs_json)
                .wrap_err("parse unit cache inputs_json")?;
            let unit_key = match unit_key(
                &plan.invocation_key,
                &inputs,
                &plan.env,
                build_script.as_ref(),
                &memo,
            ) {
                Ok(unit_key) => unit_key.key,
                Err((path, error)) => {
                    tracing::debug!(path = %path.display(), %error, "unit cache candidate's input no longer reads");
                    continue;
                }
            };
            let wanted = cache_key(&plan.target, &unit_key);
            if cache_keys.contains(&wanted) {
                return Ok(Some(wanted));
            }
        }
        Ok(None)
    })
    .await
    .wrap_err("join unit cache match task")?
}

/// Write a matching entry's outputs and dep-info into the target
/// directory. The row is read under the entry's shared lock, so it is the
/// row of the files being served; `None` means the entry vanished under a
/// concurrent eviction.
async fn serve_entry(
    config: &StowConfig,
    connection: &sqlx::SqlitePool,
    parsed: &ParsedRustcArgs,
    plan: &UnitPlan,
    cache_key: &str,
    host: &str,
) -> stow_types::error::Result<Option<ServedStderr>> {
    let version_dir = config.artifact_cache_version_dir(&plan.rustc_version);
    let _lease = tokio::task::spawn_blocking({
        let version_dir = version_dir.clone();
        let cache_key = cache_key.to_owned();
        move || acquire_entry_shared_lock(&version_dir, &cache_key)
    })
    .await
    .wrap_err("join unit cache lease task")??;
    let Some(row) = sqlx::query_as::<_, UnitEntryRow>(
        "SELECT inputs_json, env_dep_lines_json, outputs_json, diagnostics, relative_dir, \
                last_accessed_ms \
         FROM unit_cache_entries WHERE rustc_version = ? AND cache_key = ?",
    )
    .bind(&plan.rustc_version)
    .bind(cache_key)
    .fetch_optional(connection)
    .await
    .wrap_err("read unit cache entry")?
    else {
        return Ok(None);
    };
    let entry_dir = version_dir.join(&row.relative_dir);
    if !entry_dir.exists() {
        return Ok(None);
    }
    let out_dir = parsed
        .out_dir
        .as_ref()
        .ok_or_else(|| stow_types::stow_error!("served unit has no --out-dir"))?;
    let outputs: Vec<UnitOutput> =
        serde_json::from_str(&row.outputs_json).wrap_err("parse unit cache outputs_json")?;
    // Every output lands before dep-info, which cargo reads as "done".
    for output in &outputs {
        write_cached_output(
            &entry_dir.join("files").join(&output.file_name),
            &out_dir.join(&output.file_name),
            Some(&output.sha256),
            OutputDirWriters::StowOnly,
        )
        .await?;
    }
    let inputs: UnitInputs =
        serde_json::from_str(&row.inputs_json).wrap_err("parse unit cache inputs_json")?;
    let env_lines: Vec<String> = serde_json::from_str(&row.env_dep_lines_json)
        .wrap_err("parse unit cache env_dep_lines_json")?;
    let dep_info_path = parsed
        .output_dep_info_path()
        .ok_or_else(|| stow_types::stow_error!("served unit has no dep-info path"))?;
    let dep_info = render_dep_info(&dep_info_path, out_dir, &outputs, &inputs, &env_lines)?;
    async_fs::write(&dep_info_path, dep_info)
        .await
        .wrap_err_with(|| format!("write served dep-info {}", dep_info_path.display()))?;
    if now_millis().saturating_sub(recorded_millis(row.last_accessed_ms)) > LRU_STAMP_INTERVAL_MS {
        sqlx::query(
            "UPDATE unit_cache_entries SET last_accessed_ms = ? \
             WHERE rustc_version = ? AND cache_key = ?",
        )
        .bind(db_int::<_, i64>(
            now_millis(),
            "unit cache last_accessed_ms",
        )?)
        .bind(&plan.rustc_version)
        .bind(cache_key)
        .execute(connection)
        .await
        .wrap_err("touch unit cache entry")?;
    }
    let mut lines: Vec<String> = row.diagnostics.lines().map(str::to_owned).collect();
    if parsed.requests_json_artifact_notifications() {
        lines.extend(artifact_notifications(
            &dep_info_path,
            out_dir,
            &outputs,
            parsed,
            host,
        )?);
    }
    tracing::info!(
        crate_name = %parsed.crate_name,
        target = %plan.target,
        "served rustc invocation from the local unit cache"
    );
    Ok(Some(ServedStderr(lines)))
}

/// The dep-info rustc writes: one rule per announced output and for the
/// dep-info itself, a phony rule per input, then the env-dep lines. The
/// key holds the working directory, every input spelling and every
/// env-dep value raw, so this is the compile's own dep-info byte for byte.
fn render_dep_info(
    dep_info_path: &Path,
    out_dir: &Path,
    outputs: &[UnitOutput],
    inputs: &UnitInputs,
    env_lines: &[String],
) -> stow_types::error::Result<String> {
    let deps = inputs
        .files
        .iter()
        .map(|path| escape_dep_path(path))
        .collect::<Vec<_>>();
    let joined = deps.join(" ");
    let mut text = String::new();
    let targets = outputs
        .iter()
        .filter(|output| output.emit.is_some())
        .map(|output| out_dir.join(&output.file_name))
        .chain(std::iter::once(dep_info_path.to_path_buf()));
    for target in targets {
        let target = path_to_string(&target)?;
        text.push_str(&escape_dep_path(&target));
        text.push_str(": ");
        text.push_str(&joined);
        text.push('\n');
    }
    text.push('\n');
    for dep in &deps {
        text.push_str(dep);
        text.push_str(":\n");
    }
    text.push('\n');
    for line in env_lines {
        text.push_str(line);
        text.push('\n');
    }
    Ok(text)
}

/// The artifact notifications rustc prints for these outputs, in its
/// emission order: dep-info, metadata, then each linked output.
fn artifact_notifications(
    dep_info_path: &Path,
    out_dir: &Path,
    outputs: &[UnitOutput],
    parsed: &ParsedRustcArgs,
    host: &str,
) -> stow_types::error::Result<Vec<String>> {
    let notify = |artifact: PathBuf, emit: &'static str| {
        serde_json::to_string(&crate::RustcArtifactNotification {
            message_type: "artifact",
            artifact,
            emit,
        })
        .wrap_err("serialize rustc artifact notification")
    };
    let mut lines = vec![notify(dep_info_path.to_path_buf(), "dep-info")?];
    if parsed.emit.contains("metadata") {
        for output in outputs
            .iter()
            .filter(|output| output.emit.as_deref() == Some("metadata"))
        {
            lines.push(notify(out_dir.join(&output.file_name), "metadata")?);
        }
    }
    if parsed.emit.contains("link") {
        for path in expected_link_outputs(parsed, host)? {
            lines.push(notify(path, "link")?);
        }
    }
    Ok(lines)
}

/// The linked outputs the argv makes rustc write, in crate-type order.
fn expected_link_outputs(
    parsed: &ParsedRustcArgs,
    host: &str,
) -> stow_types::error::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for kind in &parsed.crate_types {
        let path = match kind.as_str() {
            "lib" | "rlib" => parsed.output_rlib_path(),
            "staticlib" => parsed
                .output_staticlib_path(host)
                .map_err(stow_types::error::Error::msg)?,
            other => {
                return Err(stow_types::stow_error!(
                    "unit cache has no output for crate type `{other}`"
                ));
            }
        };
        let path = path.ok_or_else(|| {
            stow_types::stow_error!("unit cache could not name the `{kind}` output")
        })?;
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    Ok(paths)
}

/// Every file the compile left in `--out-dir` for this unit: the
/// announced outputs, which a successful compile must have written, plus
/// anything else under the unit's own `<crate><extra-filename>.` stem
/// written since rustc started — the objects unpacked split debuginfo
/// leaves for the debugger.
///
/// # Errors
///
/// An announced output that is missing, or older than the compile: rustc
/// reported success without writing what its argv asks for.
fn collect_outputs(
    parsed: &ParsedRustcArgs,
    plan: &UnitPlan,
    host: &str,
) -> stow_types::error::Result<Vec<(PathBuf, Option<&'static str>)>> {
    let out_dir = parsed
        .out_dir
        .as_ref()
        .ok_or_else(|| stow_types::stow_error!("stored unit has no --out-dir"))?;
    let mut outputs = Vec::new();
    if parsed.emit.contains("metadata") {
        let rmeta = parsed
            .output_rmeta_path()
            .ok_or_else(|| stow_types::stow_error!("stored unit has no rmeta path"))?;
        outputs.push((rmeta, Some("metadata")));
    }
    if parsed.emit.contains("link") {
        for path in expected_link_outputs(parsed, host)? {
            outputs.push((path, Some("link")));
        }
    }
    for (path, _) in &outputs {
        require_written_by(path, plan.started)?;
    }
    let stem = format!("{}{}.", parsed.crate_name, parsed.extra_filename);
    let dep_info = parsed
        .output_dep_info_path()
        .ok_or_else(|| stow_types::stow_error!("stored unit has no dep-info path"))?;
    let entries =
        std::fs::read_dir(out_dir).wrap_err_with(|| format!("list {}", out_dir.display()))?;
    for entry in entries {
        let entry = entry.wrap_err_with(|| format!("list {}", out_dir.display()))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        if !name.starts_with(&stem)
            || path == dep_info
            || outputs.iter().any(|(known, _)| known == &path)
        {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .wrap_err_with(|| format!("stat {}", path.display()))?;
        if written_since(modified, plan.started) {
            outputs.push((path, None));
        }
    }
    Ok(outputs)
}

/// Fail unless `path` exists and was written by the compile that started
/// at `started`.
fn require_written_by(path: &Path, started: SystemTime) -> stow_types::error::Result<()> {
    let stamp = ChangeStamp::read(path).wrap_err_with(|| {
        format!(
            "rustc reported success, but its output {} cannot be read",
            path.display()
        )
    })?;
    if !written_since(stamp.modified, started) {
        return Err(stow_types::stow_error!(
            "rustc reported success, but {} predates the compile: it is an earlier compile's",
            path.display()
        ));
    }
    Ok(())
}

/// Store a successful compile's outputs under its unit key.
///
/// # Errors
///
/// A failure of the cache itself, or a compile that reported success
/// without writing its dep-info and outputs, or the declared build-script
/// inputs of a unit with `OUT_DIR` that cannot be read. An input that
/// cannot be keyed — one that changed or vanished while rustc ran — is
/// not an error: the compile is left unstored and a debug line names the
/// reason.
pub async fn store(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
    plan: &UnitPlan,
    diagnostics: &str,
    host: &str,
    memo: &Arc<DigestMemo>,
) -> stow_types::error::Result<()> {
    let skip = |reason: &str| {
        tracing::debug!(crate_name = %parsed.crate_name, %reason, "not storing unit in the local unit cache");
        Ok(())
    };
    if diagnostics.len() > MAX_DIAGNOSTICS_BYTES {
        return skip(&format!("stderr exceeds {MAX_DIAGNOSTICS_BYTES} bytes"));
    }
    let prepared = {
        let (parsed, plan, host, memo) = (
            parsed.clone(),
            plan.clone(),
            host.to_owned(),
            Arc::clone(memo),
        );
        tokio::task::spawn_blocking(move || prepare_store(&parsed, &plan, &host, &memo))
            .await
            .wrap_err("join unit cache store preparation")??
    };
    let prepared = match prepared {
        Keying::Keyed(prepared) => prepared,
        Keying::Uncacheable(reason) => return skip(&reason),
    };

    let version_dir = config.artifact_cache_version_dir(&plan.rustc_version);
    let cache_key = cache_key(&plan.target, &prepared.unit_key);
    let relative_dir = entry_relative_dir(&plan.target, &prepared.unit_key);
    let entry_dir = version_dir.join(&relative_dir);
    let connection = config.state_db_pool().await?;
    let write_lease = acquire_entry_exclusive_lock_async(&version_dir, &cache_key).await?;
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM unit_cache_entries WHERE rustc_version = ? AND cache_key = ?",
    )
    .bind(&plan.rustc_version)
    .bind(&cache_key)
    .fetch_optional(&connection)
    .await
    .wrap_err("read unit cache entry")?;
    match (existing.is_some(), entry_dir.exists()) {
        (true, true) => return Ok(()),
        (true, false) => {
            delete_unit_entry(&connection, &plan.rustc_version, &cache_key).await?;
        }
        (false, true) => remove_orphaned_entry_dir(entry_dir.clone()).await?,
        (false, false) => {}
    }
    // Hashed only once the entry is known to be new: a duplicate store
    // never reads its outputs.
    let outputs = tokio::task::spawn_blocking({
        let files = prepared.outputs.clone();
        move || hash_outputs(files)
    })
    .await
    .wrap_err("join unit cache output hash task")??;
    let staging = config
        .artifact_cache_staging_dir(&plan.rustc_version)
        .await?;
    let size_bytes = tokio::task::spawn_blocking({
        let staging = staging.clone();
        let entry_dir = entry_dir.clone();
        let files = prepared
            .outputs
            .iter()
            .map(|(path, _)| path.clone())
            .collect::<Vec<_>>();
        move || stage_entry_blocking(staging.path(), &entry_dir, &files)
    })
    .await
    .wrap_err("join unit cache stage task")??;
    sqlx::query(
        "INSERT INTO unit_cache_entries \
         (rustc_version, cache_key, invocation_key, inputs_json, env_dep_lines_json, \
          outputs_json, diagnostics, relative_dir, size_bytes, last_accessed_ms) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&plan.rustc_version)
    .bind(&cache_key)
    .bind(&plan.invocation_key)
    .bind(serde_json::to_string(&prepared.inputs).wrap_err("serialize unit inputs")?)
    .bind(serde_json::to_string(&prepared.env_lines).wrap_err("serialize env-dep lines")?)
    .bind(serde_json::to_string(&outputs).wrap_err("serialize unit outputs")?)
    .bind(filtered_diagnostics(diagnostics))
    .bind(path_to_string(&relative_dir)?)
    .bind(db_int::<_, i64>(size_bytes, "unit cache size_bytes")?)
    .bind(db_int::<_, i64>(
        now_millis(),
        "unit cache last_accessed_ms",
    )?)
    .execute(&connection)
    .await
    .wrap_err("insert unit cache entry")?;
    drop(write_lease);
    evict_entries(
        &connection,
        &plan.rustc_version,
        &version_dir,
        config.artifact_cache_max_bytes,
        &cache_key,
    )
    .await
}

/// The stderr an entry replays: rustc's, without its artifact
/// notifications, which a serve rebuilds for the serving invocation.
fn filtered_diagnostics(diagnostics: &str) -> String {
    diagnostics
        .lines()
        .filter(|line| !line.starts_with("{\"$message_type\":\"artifact\""))
        .fold(String::new(), |mut text, line| {
            text.push_str(line);
            text.push('\n');
            text
        })
}

/// Each output's record: its name, notification and sha256.
fn hash_outputs(
    files: Vec<(PathBuf, Option<&'static str>)>,
) -> stow_types::error::Result<Vec<UnitOutput>> {
    files
        .into_iter()
        .map(|(path, emit)| {
            let file_name = path
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or_else(|| {
                    stow_types::stow_error!("output {} has no UTF-8 name", path.display())
                })?
                .to_owned();
            let (sha256, _) = sha256_file_bytes(&path)?;
            Ok(UnitOutput {
                file_name,
                emit: emit.map(str::to_owned),
                sha256,
            })
        })
        .collect()
}

/// A compile resolved into what its entry records.
#[derive(Debug)]
struct PreparedStore {
    unit_key: String,
    inputs: UnitInputs,
    env_lines: Vec<String>,
    /// Each output in `--out-dir`, with the notification rustc printed.
    outputs: Vec<(PathBuf, Option<&'static str>)>,
}

/// Read what a successful compile left: its dep-info, its outputs, and
/// its inputs as they stand.
fn prepare_store(
    parsed: &ParsedRustcArgs,
    plan: &UnitPlan,
    host: &str,
    memo: &DigestMemo,
) -> stow_types::error::Result<Keying<PreparedStore>> {
    let dep_info_path = parsed
        .output_dep_info_path()
        .ok_or_else(|| stow_types::stow_error!("stored unit has no dep-info path"))?;
    require_written_by(&dep_info_path, plan.started)?;
    let text = std::fs::read_to_string(&dep_info_path)
        .wrap_err_with(|| format!("read dep-info {}", dep_info_path.display()))?;
    let dep_info = parse_dep_info(&text).map_err(|reason| {
        stow_types::stow_error!("dep-info {}: {reason}", dep_info_path.display())
    })?;
    let outputs = collect_outputs(parsed, plan, host)?;
    let inputs = UnitInputs {
        files: dep_info
            .files
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        env: dep_info.env_names(),
    };
    let build_script = build_script_inputs(&plan.env, memo).map_err(|(path, error)| {
        stow_types::stow_error!(
            "read the declared build-script inputs at {} after a successful compile: {error}",
            path.display()
        )
    })?;
    let unit_key = match unit_key(
        &plan.invocation_key,
        &inputs,
        &plan.env,
        build_script.as_ref(),
        memo,
    ) {
        Ok(unit_key) => unit_key,
        Err((path, error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Keying::Uncacheable(format!(
                "input {} was removed while rustc ran",
                path.display()
            )));
        }
        Err((path, error)) => {
            return Err(stow_types::stow_error!(
                "read unit input {} after a successful compile: {error}",
                path.display()
            ));
        }
    };
    // The change time, not the modification time: a copy, extraction or
    // restore that keeps an old mtime still moves it. The inputs are
    // hashed after the compile, so one changed since rustc started may not
    // be what rustc read.
    if written_since(unit_key.newest_change, plan.started) {
        return Ok(Keying::Uncacheable(
            "an input or a directory rustc searched changed while rustc ran".to_owned(),
        ));
    }
    Ok(Keying::Keyed(PreparedStore {
        unit_key: unit_key.key,
        inputs,
        env_lines: dep_info.env_lines,
        outputs,
    }))
}

/// Clone the outputs into a temp entry in the process's staging directory
/// and rename it into place — the bundle entries' discipline: a partial
/// stage never lands, and a crash leaves only what the staging sweep
/// reclaims.
fn stage_entry_blocking(
    staging_dir: &Path,
    entry_dir: &Path,
    files: &[PathBuf],
) -> stow_types::error::Result<u64> {
    let tempdir = tempfile::Builder::new()
        .prefix("unit-")
        .tempdir_in(staging_dir)
        .wrap_err_with(|| format!("create temp unit entry for {}", entry_dir.display()))?;
    let files_dir = tempdir.path().join("files");
    std::fs::create_dir_all(&files_dir)
        .wrap_err_with(|| format!("create unit entry files dir {}", files_dir.display()))?;
    let mut size_bytes = 0u64;
    for source in files {
        let file_name = source.file_name().ok_or_else(|| {
            stow_types::stow_error!("unit output {} has no file name", source.display())
        })?;
        let dest = files_dir.join(file_name);
        reflink::reflink_or_copy(source, &dest)
            .wrap_err_with(|| format!("clone {} into the unit cache", source.display()))?;
        size_bytes = size_bytes.saturating_add(
            std::fs::metadata(&dest)
                .wrap_err_with(|| format!("stat staged unit file {}", dest.display()))?
                .len(),
        );
    }
    let parent = entry_dir.parent().ok_or_else(|| {
        stow_types::stow_error!("unit entry dir {} has no parent", entry_dir.display())
    })?;
    std::fs::create_dir_all(parent)
        .wrap_err_with(|| format!("create unit entry parent {}", parent.display()))?;
    std::fs::rename(tempdir.path(), entry_dir).wrap_err_with(|| {
        format!(
            "move unit entry {} into place at {}",
            tempdir.path().display(),
            entry_dir.display()
        )
    })?;
    Ok(size_bytes)
}

/// Remove a unit entry — row and directory — under its exclusive lock.
async fn remove_entry(
    config: &StowConfig,
    connection: &sqlx::SqlitePool,
    plan: &UnitPlan,
    cache_key: &str,
) -> stow_types::error::Result<()> {
    let version_dir = config.artifact_cache_version_dir(&plan.rustc_version);
    let lock = acquire_entry_exclusive_lock_async(&version_dir, cache_key).await?;
    delete_unit_entry(connection, &plan.rustc_version, cache_key).await?;
    let unit_key = cache_key
        .rsplit_once('/')
        .map_or(cache_key, |(_, unit_key)| unit_key);
    let entry_dir = version_dir.join(entry_relative_dir(&plan.target, unit_key));
    if entry_dir.exists() {
        remove_orphaned_entry_dir(entry_dir).await?;
    }
    drop(lock);
    Ok(())
}

/// Delete one unit entry's row; the caller owns its directory.
///
/// # Errors
///
/// The state database's own failure.
pub async fn delete_unit_entry(
    connection: &sqlx::SqlitePool,
    rustc_version: &str,
    cache_key: &str,
) -> stow_types::error::Result<()> {
    sqlx::query("DELETE FROM unit_cache_entries WHERE rustc_version = ? AND cache_key = ?")
        .bind(rustc_version)
        .bind(cache_key)
        .execute(connection)
        .await
        .wrap_err("delete unit cache entry")?;
    Ok(())
}

#[cfg(test)]
mod tests;

//! The local cache for units the registry identity cannot key (stow#978):
//! path and git dependencies, workspace members, primary packages, and
//! registry units compiled with custom codegen or as a staticlib.
//!
//! Such a unit's source is not an immutable registry tarball, so it is
//! keyed by content in two stages:
//!
//! - the *invocation key*, computed before rustc runs: the full `rustc -vV`
//!   text, the argv with output locations and search paths dropped and
//!   every `--extern` replaced by the digest of the file it names, the
//!   working directory, the native libraries `-l` resolves to, and the
//!   environment cargo and rustc read outside dep-info;
//! - the *unit key*: the invocation key plus every file the compile's
//!   dep-info lists (by contents) and the value of every variable it read
//!   through `env!`/`option_env!`.
//!
//! An entry records its dep-info file list under its invocation key, and a
//! lookup re-hashes that list as it stands now: no extra rustc pass runs on
//! a hit or a miss. Paths are normalized by rustc's own
//! `--remap-path-prefix` rules — a path rustc writes into the artifact in
//! its remapped form is keyed in that form, so a checkout in another
//! directory under the same remap hits; every other absolute path is
//! keyed raw.
//!
//! Nothing here mints a node or reports anything upstream: the entries
//! live beside the bundle entries, under the same per-rustc directory,
//! staging, copy-on-write clone path and LRU budget.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use sqlx::FromRow;
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
const UNIT_LAYOUT_VERSION: &str = "unit-v1";
/// Largest stderr a stored entry replays. The served lines travel in one
/// supervisor frame, so an entry never carries more than a small part of it.
pub const MAX_DIAGNOSTICS_BYTES: usize = 1024 * 1024;

/// Crate types a unit entry can restore — the shapes sccache caches
/// (`lib`/`rlib`, `staticlib`) and the dynamic libraries the bundle
/// entries already restore.
const CACHEABLE_CRATE_TYPES: &[&str] = &["lib", "rlib", "staticlib", "proc-macro", "dylib"];
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
const RUSTC_READ_VARS: &[&str] = &["RUSTC_BOOTSTRAP", "SDKROOT"];
/// `-Z` options that read or write files the key cannot see.
const FILE_READING_UNSTABLE_OPTIONS: &[&str] = &[
    "codegen-backend",
    "dump-",
    "llvm-plugins",
    "profile-sample-use",
    "remap-cwd-prefix",
    "self-profile",
    "split-dwarf",
    "temps-dir",
];
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

/// One `--remap-path-prefix FROM=TO` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemapRule {
    from: PathBuf,
    to: String,
}

/// How a path is spelled in a key and in a stored entry: as rustc was
/// handed it relative to the working directory, in the remapped form
/// rustc writes into the artifact, or raw.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum InputPath {
    Relative(String),
    Remapped { to: String, rest: String },
    Absolute(String),
}

impl InputPath {
    fn key_bytes(&self) -> String {
        match self {
            Self::Relative(path) => format!("relative:{path}"),
            Self::Remapped { to, rest } => format!("remapped:{to}\0{rest}"),
            Self::Absolute(path) => format!("absolute:{path}"),
        }
    }
}

/// What a dep-info file says the compile read.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct UnitInputs {
    /// Every file the dep-info lists, normalized and sorted.
    files: Vec<InputPath>,
    /// Every variable read through `env!`/`option_env!`, sorted.
    env: Vec<String>,
}

/// One output file of a unit entry, stored under `files/<file_name>` and
/// served to `<out-dir>/<file_name>` — the file names are the argv's own,
/// which the key covers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct UnitOutput {
    file_name: String,
    /// The artifact notification rustc prints for the file (`metadata`,
    /// `link`), or `None` for a file it leaves beside them unannounced —
    /// the object files of unpacked split debuginfo.
    emit: Option<String>,
    sha256: String,
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
    remaps: Vec<RemapRule>,
    /// Taken before rustc started: a listed source modified at or after it
    /// may not be what rustc read, so the compile is not stored.
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
        let codegen = if arg == "-C" {
            iter.next().and_then(|value| value.to_str())
        } else {
            arg.strip_prefix("-C")
        };
        if let Some(option) = codegen {
            let key = option.split_once('=').map_or(option, |(key, _)| key);
            if key == "incremental" {
                return Some("incremental compilation state is not cached".to_owned());
            }
            if key == "profile-use" || key == "profile-sample-use" {
                return Some(format!("`-C {key}` reads a profile the key does not hash"));
            }
            continue;
        }
        let unstable = if arg == "-Z" {
            iter.next().and_then(|value| value.to_str())
        } else {
            arg.strip_prefix("-Z")
        };
        if let Some(option) = unstable
            && FILE_READING_UNSTABLE_OPTIONS
                .iter()
                .any(|prefix| option.starts_with(prefix))
        {
            return Some(format!(
                "`-Z {option}` reads or writes files the key does not hash"
            ));
        }
    }
    None
}

/// The parsed `--remap-path-prefix` rules, in argv order.
fn remap_rules(args: &[OsString]) -> Result<Vec<RemapRule>, String> {
    let mut rules = Vec::new();
    let mut iter = args.iter().filter_map(|arg| arg.to_str());
    while let Some(arg) = iter.next() {
        let value = if arg == "--remap-path-prefix" {
            iter.next()
        } else {
            arg.strip_prefix("--remap-path-prefix=")
        };
        let Some(value) = value else {
            continue;
        };
        // rustc splits on the last `=`: a FROM may contain one.
        let (from, to) = value
            .rsplit_once('=')
            .ok_or_else(|| format!("--remap-path-prefix `{value}` has no `=`"))?;
        rules.push(RemapRule {
            from: PathBuf::from(from),
            to: to.to_owned(),
        });
    }
    Ok(rules)
}

/// `path` as the key spells it: rustc applies the last rule whose FROM is
/// a component prefix of the path.
fn normalize(path: &Path, remaps: &[RemapRule]) -> Result<InputPath, String> {
    let utf8 = |path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("path {} is not UTF-8", path.display()))
    };
    if path.is_relative() {
        return Ok(InputPath::Relative(utf8(path)?));
    }
    for rule in remaps.iter().rev() {
        if let Ok(rest) = path.strip_prefix(&rule.from) {
            let rest = rest
                .components()
                .map(|component| match component {
                    Component::Normal(part) => part
                        .to_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("path {} is not UTF-8", path.display())),
                    other => Err(format!(
                        "path {} has a `{}` component under a remapped prefix",
                        path.display(),
                        other.as_os_str().display()
                    )),
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            return Ok(InputPath::Remapped {
                to: rule.to.clone(),
                rest,
            });
        }
    }
    Ok(InputPath::Absolute(utf8(path)?))
}

/// The path a stored spelling names in this invocation, or `None` when no
/// remap rule of this invocation maps to its `TO`.
fn denormalize(input: &InputPath, cwd: &Path, remaps: &[RemapRule]) -> Option<PathBuf> {
    match input {
        InputPath::Relative(path) => Some(cwd.join(path)),
        InputPath::Remapped { to, rest } => {
            remaps.iter().rev().find(|rule| &rule.to == to).map(|rule| {
                rest.split('/')
                    .filter(|part| !part.is_empty())
                    .fold(rule.from.clone(), |path, part| path.join(part))
            })
        }
        InputPath::Absolute(path) => Some(PathBuf::from(path)),
    }
}

/// The spelling rustc writes into dep-info for a stored input: relative as
/// handed over, absolute otherwise — dep-info carries real paths, never
/// remapped ones.
fn dep_info_spelling(input: &InputPath, cwd: &Path, remaps: &[RemapRule]) -> Option<String> {
    match input {
        InputPath::Relative(path) => Some(path.clone()),
        other => denormalize(other, cwd, remaps).and_then(|path| path.to_str().map(str::to_owned)),
    }
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

/// The blake3 of a file's contents, or `None` when it cannot be read.
fn file_digest(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(file).ok()?;
    Some(hasher.finalize().to_hex().to_string())
}

/// A variable's value as the key reads it: UTF-8, with an absolute path
/// under a remap rule in its remapped form.
fn env_value(value: &OsStr, remaps: &[RemapRule]) -> Result<String, String> {
    let value = value
        .to_str()
        .ok_or_else(|| "a hashed environment variable is not UTF-8".to_owned())?;
    let path = Path::new(value);
    if path.is_absolute() && remaps.iter().any(|rule| path.starts_with(&rule.from)) {
        return Ok(normalize(path, remaps)?.key_bytes());
    }
    Ok(value.to_owned())
}

/// Whether the invocation key reads `name` from the environment.
fn is_keyed_var(name: &str) -> bool {
    name.starts_with("CARGO_PKG_")
        || CARGO_UNIT_VARS.contains(&name)
        || RUSTC_READ_VARS.contains(&name)
        || name.ends_with("_DEPLOYMENT_TARGET")
}

/// The `-L` directories rustc searches native libraries in.
fn native_search_dirs(args: &[OsString], cwd: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
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
        let path = match value.split_once('=') {
            Some(("native" | "all", path)) => path,
            Some(("crate" | "dependency" | "framework", _)) => continue,
            _ => value,
        };
        dirs.push(cwd.join(path));
    }
    dirs
}

/// The files a `-l [KIND[:MODS]=]NAME[:RENAME]` resolves to on the `-L`
/// directories, with their digests. A name found nowhere is a system
/// library, keyed by its spelling alone, as the toolchain is.
fn native_library_digests(spec: &str, dirs: &[PathBuf]) -> Vec<(String, String)> {
    let (kind, name) = spec.split_once('=').unwrap_or(("", spec));
    if kind.starts_with("framework") {
        return Vec::new();
    }
    let name = name.split_once(':').map_or(name, |(name, _)| name);
    let candidates = [
        format!("lib{name}.a"),
        format!("{name}.lib"),
        format!("lib{name}.so"),
        format!("lib{name}.dylib"),
        format!("lib{name}.dll.a"),
    ];
    let mut digests = Vec::new();
    for dir in dirs {
        for candidate in &candidates {
            let path = dir.join(candidate);
            if let Some(digest) = file_digest(&path) {
                digests.push((path.display().to_string(), digest));
            }
        }
    }
    digests
}

/// Compute the invocation key: everything that decides the compile's
/// output and is known before rustc runs. Blocking: it reads every
/// `--extern` and native library.
fn invocation_key_blocking(
    args: &[OsString],
    parsed: &ParsedRustcArgs,
    env: &InvocationEnv,
    rustc_vv: &str,
    remaps: &[RemapRule],
) -> Keying<String> {
    match invocation_key_fields(args, parsed, env, rustc_vv, remaps) {
        Ok(key) => key,
        Err(reason) => Keying::Uncacheable(reason),
    }
}

fn invocation_key_fields(
    args: &[OsString],
    parsed: &ParsedRustcArgs,
    env: &InvocationEnv,
    rustc_vv: &str,
    remaps: &[RemapRule],
) -> Result<Keying<String>, String> {
    let mut key = KeyHasher::new("stow.local-unit.invocation.v1");
    key.field(rustc_vv.as_bytes());
    key.field(normalize(&env.cwd, remaps)?.key_bytes().as_bytes());
    let input_spelling = parsed
        .input_path
        .as_ref()
        .and_then(|path| path.to_str())
        .ok_or_else(|| "the input path is not UTF-8".to_owned())?;
    let search_dirs = native_search_dirs(args, &env.cwd);
    let mut input_seen = false;
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
        } else if let Some(value) = arg.strip_prefix("-l") {
            ("-l", Some(value))
        } else {
            (arg, None)
        };
        match (flag, value) {
            // Where the outputs go and where dependencies are searched —
            // the outputs' names are the argv's own, and what the search
            // finds is keyed by content below — and the rendering width
            // of diagnostics.
            ("--out-dir" | "-L" | "--diagnostic-width", _) => {}
            ("--extern", Some(spec)) => {
                key.field(b"--extern");
                match spec.split_once('=') {
                    Some((name, path)) => {
                        let path = env.cwd.join(path);
                        let Some(digest) = file_digest(&path) else {
                            return Ok(Keying::Uncacheable(format!(
                                "--extern {name} at {} is unreadable",
                                path.display()
                            )));
                        };
                        key.field(format!("{name}={digest}").as_bytes());
                    }
                    None => key.field(spec.as_bytes()),
                }
            }
            // rustc writes only TO into the artifact; FROM decides which
            // paths are remapped, and every keyed path is keyed remapped.
            ("--remap-path-prefix", Some(rule)) => {
                let (_, to) = rule
                    .rsplit_once('=')
                    .ok_or_else(|| format!("--remap-path-prefix `{rule}` has no `=`"))?;
                key.field(b"--remap-path-prefix");
                key.field(to.as_bytes());
            }
            ("-l", Some(spec)) => {
                key.field(b"-l");
                key.field(spec.as_bytes());
                for (path, digest) in native_library_digests(spec, &search_dirs) {
                    key.field(path.as_bytes());
                    key.field(digest.as_bytes());
                }
            }
            (flag, value) => {
                if value.is_none() && !input_seen && flag == input_spelling {
                    input_seen = true;
                    key.field(b"input");
                    key.field(normalize(Path::new(flag), remaps)?.key_bytes().as_bytes());
                    continue;
                }
                key.field(flag.as_bytes());
                if let Some(value) = value {
                    key.field(value.as_bytes());
                }
            }
        }
    }
    if !input_seen {
        return Err("the input path is not a standalone argument".to_owned());
    }
    for (name, value) in &env.vars {
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_keyed_var(name) {
            continue;
        }
        key.field(name.as_bytes());
        key.field(env_value(value, remaps)?.as_bytes());
    }
    Ok(Keying::Keyed(key.finish()))
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

/// The unit key over `inputs` as they stand now.
fn unit_key_blocking(
    invocation_key: &str,
    inputs: &UnitInputs,
    env: &InvocationEnv,
    remaps: &[RemapRule],
) -> Keying<String> {
    let mut key = KeyHasher::new("stow.local-unit.v1");
    key.field(invocation_key.as_bytes());
    for input in &inputs.files {
        let Some(path) = denormalize(input, &env.cwd, remaps) else {
            return Keying::Uncacheable(format!(
                "no remap rule of this invocation maps to the input {}",
                input.key_bytes()
            ));
        };
        let Some(digest) = file_digest(&path) else {
            return Keying::Uncacheable(format!("input {} is unreadable", path.display()));
        };
        key.field(input.key_bytes().as_bytes());
        key.field(digest.as_bytes());
    }
    for name in &inputs.env {
        key.field(name.as_bytes());
        // `env!` values are embedded verbatim: keyed raw, never remapped.
        match env.var(name) {
            Some(value) => {
                let Some(value) = value.to_str() else {
                    return Keying::Uncacheable(format!("env-dep {name} is not UTF-8"));
                };
                key.field(b"set");
                key.field(value.as_bytes());
            }
            None => key.field(b"unset"),
        }
    }
    Keying::Keyed(key.finish())
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

#[derive(Debug, Clone, FromRow)]
struct UnitEntryRow {
    cache_key: String,
    inputs_json: String,
    env_dep_lines_json: String,
    outputs_json: String,
    diagnostics: String,
    relative_dir: String,
    last_accessed_ms: i64,
}

/// Look `parsed` up: serve a matching entry, or return the plan its
/// compile stores under.
///
/// # Errors
///
/// A failure of the cache itself — the state database, a malformed row,
/// an entry that cannot be written into the target directory. The caller
/// compiles without storing.
#[expect(
    clippy::too_many_arguments,
    reason = "the lookup reads one invocation's every independent fact"
)]
pub async fn lookup(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
    args: &[OsString],
    env: &InvocationEnv,
    rustc_vv: &str,
    target: &str,
    rustc_version: &str,
    host: &str,
) -> stow_types::error::Result<Keying<UnitLookup>> {
    let started = SystemTime::now();
    let remaps = match remap_rules(args) {
        Ok(remaps) => remaps,
        Err(reason) => return Ok(Keying::Uncacheable(reason)),
    };
    let invocation_key = {
        let (args, parsed, env, rustc_vv, remaps) = (
            args.to_vec(),
            parsed.clone(),
            env.clone(),
            rustc_vv.to_owned(),
            remaps.clone(),
        );
        tokio::task::spawn_blocking(move || {
            invocation_key_blocking(&args, &parsed, &env, &rustc_vv, &remaps)
        })
        .await
        .wrap_err("join unit invocation key task")?
    };
    let invocation_key = match invocation_key {
        Keying::Keyed(key) => key,
        Keying::Uncacheable(reason) => return Ok(Keying::Uncacheable(reason)),
    };
    let connection = config.state_db_pool().await?;
    let rows = sqlx::query_as::<_, UnitEntryRow>(
        "SELECT cache_key, inputs_json, env_dep_lines_json, outputs_json, diagnostics, \
                relative_dir, last_accessed_ms \
         FROM unit_cache_entries \
         WHERE rustc_version = ? AND invocation_key = ?",
    )
    .bind(rustc_version)
    .bind(&invocation_key)
    .fetch_all(&connection)
    .await
    .wrap_err("read unit cache candidates")?;
    let plan = UnitPlan {
        invocation_key,
        target: target.to_owned(),
        rustc_version: rustc_version.to_owned(),
        env: env.clone(),
        remaps,
        started,
    };
    if let Some(row) = matching_entry(&plan, rows).await? {
        let (cache_key, relative_dir) = (row.cache_key.clone(), row.relative_dir.clone());
        match serve_entry(config, &connection, parsed, &plan, row, host).await {
            Ok(Some(stderr)) => return Ok(Keying::Keyed(UnitLookup::Served(stderr))),
            Ok(None) => {}
            Err(error) => {
                // An entry that cannot be served is removed, so the
                // compile this falls back to stores a working one.
                remove_entry(
                    config,
                    &connection,
                    &plan.rustc_version,
                    &cache_key,
                    &relative_dir,
                )
                .await?;
                return Err(error);
            }
        }
    }
    Ok(Keying::Keyed(UnitLookup::Compile(Box::new(plan))))
}

/// The row whose unit key the inputs re-hash to, hashing each distinct
/// input list once.
async fn matching_entry(
    plan: &UnitPlan,
    rows: Vec<UnitEntryRow>,
) -> stow_types::error::Result<Option<UnitEntryRow>> {
    if rows.is_empty() {
        return Ok(None);
    }
    let plan = plan.clone();
    tokio::task::spawn_blocking(move || {
        let mut by_inputs: BTreeMap<String, Vec<UnitEntryRow>> = BTreeMap::new();
        for row in rows {
            by_inputs.entry(row.inputs_json.clone()).or_default().push(row);
        }
        for (inputs_json, rows) in by_inputs {
            let inputs: UnitInputs = serde_json::from_str(&inputs_json)
                .wrap_err("parse unit cache inputs_json")?;
            let unit_key =
                match unit_key_blocking(&plan.invocation_key, &inputs, &plan.env, &plan.remaps) {
                    Keying::Keyed(key) => key,
                    Keying::Uncacheable(reason) => {
                        tracing::debug!(%reason, "unit cache candidate does not apply to this checkout");
                        continue;
                    }
                };
            let wanted = cache_key(&plan.target, &unit_key);
            if let Some(row) = rows.into_iter().find(|row| row.cache_key == wanted) {
                return Ok(Some(row));
            }
        }
        Ok(None)
    })
    .await
    .wrap_err("join unit cache match task")?
}

/// Write a matching entry's outputs and dep-info into the target
/// directory. `None` means the entry vanished under a concurrent eviction.
async fn serve_entry(
    config: &StowConfig,
    connection: &sqlx::SqlitePool,
    parsed: &ParsedRustcArgs,
    plan: &UnitPlan,
    row: UnitEntryRow,
    host: &str,
) -> stow_types::error::Result<Option<ServedStderr>> {
    let version_dir = config.artifact_cache_version_dir(&plan.rustc_version);
    let entry_dir = version_dir.join(&row.relative_dir);
    let _lease = tokio::task::spawn_blocking({
        let version_dir = version_dir.clone();
        let cache_key = row.cache_key.clone();
        move || acquire_entry_shared_lock(&version_dir, &cache_key)
    })
    .await
    .wrap_err("join unit cache lease task")??;
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
    let dep_info = render_dep_info(&dep_info_path, out_dir, &outputs, &inputs, &env_lines, plan)?;
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
        .bind(&row.cache_key)
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

/// The dep-info rustc would write for this checkout: one rule per output
/// and for the dep-info itself, a phony rule per input, then the env-dep
/// lines — which match a fresh compile's byte for byte, since the key
/// holds their raw values.
fn render_dep_info(
    dep_info_path: &Path,
    out_dir: &Path,
    outputs: &[UnitOutput],
    inputs: &UnitInputs,
    env_lines: &[String],
    plan: &UnitPlan,
) -> stow_types::error::Result<String> {
    let deps = inputs
        .files
        .iter()
        .map(|input| {
            dep_info_spelling(input, &plan.env.cwd, &plan.remaps)
                .map(|path| escape_dep_path(&path))
                .ok_or_else(|| {
                    stow_types::stow_error!(
                        "served unit input {} has no path in this checkout",
                        input.key_bytes()
                    )
                })
        })
        .collect::<stow_types::error::Result<Vec<_>>>()?;
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
            "proc-macro" | "dylib" => parsed
                .output_dynamic_library_path(host)
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
/// announced outputs, plus anything else under the unit's own
/// `<crate><extra-filename>.` stem written since rustc started — the
/// object files unpacked split debuginfo leaves for the debugger.
fn collect_outputs(
    parsed: &ParsedRustcArgs,
    plan: &UnitPlan,
    host: &str,
) -> Result<Vec<(PathBuf, Option<&'static str>)>, String> {
    let out_dir = parsed.out_dir.as_ref().ok_or("no --out-dir")?;
    let mut outputs = Vec::new();
    if parsed.emit.contains("metadata") {
        outputs.push((
            parsed.output_rmeta_path().ok_or("no rmeta path")?,
            Some("metadata"),
        ));
    }
    if parsed.emit.contains("link") {
        for path in expected_link_outputs(parsed, host).map_err(|error| error.to_string())? {
            outputs.push((path, Some("link")));
        }
    }
    let stem = format!("{}{}.", parsed.crate_name, parsed.extra_filename);
    let dep_info = parsed.output_dep_info_path().ok_or("no dep-info path")?;
    let entries = std::fs::read_dir(out_dir)
        .map_err(|error| format!("list {}: {error}", out_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("list {}: {error}", out_dir.display()))?;
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
            .map_err(|error| format!("stat {}: {error}", path.display()))?;
        if modified >= plan.started {
            outputs.push((path, None));
        }
    }
    Ok(outputs)
}

/// Store a successful compile's outputs under its unit key.
///
/// # Errors
///
/// A failure of the cache itself. An input that cannot be keyed is not an
/// error: the compile is left unstored and a debug line names the reason.
pub async fn store(
    config: &StowConfig,
    parsed: &ParsedRustcArgs,
    plan: &UnitPlan,
    diagnostics: &str,
    host: &str,
) -> stow_types::error::Result<()> {
    let skip = |reason: String| {
        tracing::debug!(crate_name = %parsed.crate_name, %reason, "not storing unit in the local unit cache");
        Ok(())
    };
    if diagnostics.len() > MAX_DIAGNOSTICS_BYTES {
        return skip(format!("stderr exceeds {MAX_DIAGNOSTICS_BYTES} bytes"));
    }
    // The announcements are rebuilt for the serving checkout's paths.
    let diagnostics = diagnostics
        .lines()
        .filter(|line| !line.starts_with("{\"$message_type\":\"artifact\""))
        .fold(String::new(), |mut text, line| {
            text.push_str(line);
            text.push('\n');
            text
        });
    let prepared = {
        let (parsed, plan, host) = (parsed.clone(), plan.clone(), host.to_owned());
        tokio::task::spawn_blocking(move || prepare_store(&parsed, &plan, &host))
            .await
            .wrap_err("join unit cache store preparation")?
    };
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(reason) => return skip(reason),
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
    let staging = config
        .artifact_cache_staging_dir(&plan.rustc_version)
        .await?;
    let size_bytes = tokio::task::spawn_blocking({
        let staging = staging.clone();
        let entry_dir = entry_dir.clone();
        let files = prepared.files.clone();
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
    .bind(serde_json::to_string(&prepared.outputs).wrap_err("serialize unit outputs")?)
    .bind(&diagnostics)
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

/// A compile resolved into what its entry records.
struct PreparedStore {
    unit_key: String,
    inputs: UnitInputs,
    env_lines: Vec<String>,
    outputs: Vec<UnitOutput>,
    /// `(source in out-dir, file name)` pairs to stage.
    files: Vec<(PathBuf, String)>,
}

fn prepare_store(
    parsed: &ParsedRustcArgs,
    plan: &UnitPlan,
    host: &str,
) -> Result<PreparedStore, String> {
    let dep_info_path = parsed.output_dep_info_path().ok_or("no dep-info path")?;
    let text = std::fs::read_to_string(&dep_info_path)
        .map_err(|error| format!("read dep-info {}: {error}", dep_info_path.display()))?;
    let dep_info = parse_dep_info(&text)?;
    let files = dep_info
        .files
        .iter()
        .map(|spelling| normalize(Path::new(spelling), &plan.remaps))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let inputs = UnitInputs {
        files: files.into_iter().collect(),
        env: dep_info.env_names(),
    };
    let unit_key = match unit_key_blocking(&plan.invocation_key, &inputs, &plan.env, &plan.remaps) {
        Keying::Keyed(key) => key,
        Keying::Uncacheable(reason) => return Err(reason),
    };
    // After hashing: a write that lands before the hash and one that lands
    // after it both leave an mtime at or past the compile's start.
    for spelling in &dep_info.files {
        let modified = std::fs::metadata(plan.env.cwd.join(spelling))
            .and_then(|metadata| metadata.modified())
            .map_err(|error| format!("stat input {spelling}: {error}"))?;
        if modified >= plan.started {
            return Err(format!("input {spelling} changed while rustc ran"));
        }
    }
    let mut outputs = Vec::new();
    let mut staged = Vec::new();
    for (path, emit) in collect_outputs(parsed, plan, host)? {
        let file_name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| format!("output {} has no UTF-8 name", path.display()))?
            .to_owned();
        let (sha256, _) = sha256_file_bytes(&path).map_err(|error| error.to_string())?;
        outputs.push(UnitOutput {
            file_name: file_name.clone(),
            emit: emit.map(str::to_owned),
            sha256,
        });
        staged.push((path, file_name));
    }
    Ok(PreparedStore {
        unit_key,
        inputs,
        env_lines: dep_info.env_lines,
        outputs,
        files: staged,
    })
}

/// Clone the outputs into a temp entry in the process's staging directory
/// and rename it into place — the bundle entries' discipline: a partial
/// stage never lands, and a crash leaves only what the staging sweep
/// reclaims.
fn stage_entry_blocking(
    staging_dir: &Path,
    entry_dir: &Path,
    files: &[(PathBuf, String)],
) -> stow_types::error::Result<u64> {
    let tempdir = tempfile::Builder::new()
        .prefix("unit-")
        .tempdir_in(staging_dir)
        .wrap_err_with(|| format!("create temp unit entry for {}", entry_dir.display()))?;
    let files_dir = tempdir.path().join("files");
    std::fs::create_dir_all(&files_dir)
        .wrap_err_with(|| format!("create unit entry files dir {}", files_dir.display()))?;
    let mut size_bytes = 0u64;
    for (source, file_name) in files {
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
    rustc_version: &str,
    cache_key: &str,
    relative_dir: &str,
) -> stow_types::error::Result<()> {
    let version_dir = config.artifact_cache_version_dir(rustc_version);
    let lock = acquire_entry_exclusive_lock_async(&version_dir, cache_key).await?;
    delete_unit_entry(connection, rustc_version, cache_key).await?;
    let entry_dir = version_dir.join(relative_dir);
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
mod tests {
    use std::ffi::OsString;
    use std::path::Path;

    use super::{
        InputPath, InvocationEnv, Keying, RemapRule, UnitInputs, invocation_key_blocking,
        normalize, parse_dep_info, refusal, remap_rules, unit_key_blocking,
    };
    use crate::rustc_args::ParsedRustcArgs;

    /// One checkout of a workspace whose member `mylib` depends on `dep`:
    /// the sources, the dependency's rmeta, and the argv and environment
    /// cargo hands rustc for `mylib` there.
    struct Checkout {
        _dir: tempfile::TempDir,
        root: std::path::PathBuf,
    }

    impl Checkout {
        fn new(lib_rs: &str, dep_rmeta: &[u8]) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let root = dir.path().join("ws");
            std::fs::create_dir_all(root.join("mylib/src")).expect("create src");
            std::fs::write(root.join("mylib/src/lib.rs"), lib_rs).expect("write lib.rs");
            std::fs::create_dir_all(root.join("target/deps")).expect("create deps");
            std::fs::write(root.join("target/deps/libdep-1.rmeta"), dep_rmeta)
                .expect("write rmeta");
            Self { _dir: dir, root }
        }

        fn args(&self) -> Vec<OsString> {
            let root = self.root.display();
            [
                "--crate-name".to_owned(),
                "mylib".to_owned(),
                "--edition=2021".to_owned(),
                "mylib/src/lib.rs".to_owned(),
                "--crate-type".to_owned(),
                "lib".to_owned(),
                "--emit=dep-info,metadata,link".to_owned(),
                "-C".to_owned(),
                "metadata=0123abcd".to_owned(),
                "-C".to_owned(),
                "extra-filename=-0123abcd".to_owned(),
                "--out-dir".to_owned(),
                format!("{root}/target/deps"),
                "-L".to_owned(),
                format!("dependency={root}/target/deps"),
                "--extern".to_owned(),
                format!("dep={root}/target/deps/libdep-1.rmeta"),
                format!("--remap-path-prefix={root}=stow-ci://workspace"),
            ]
            .into_iter()
            .map(OsString::from)
            .collect()
        }

        fn env(&self, extra: &[(&str, &str)]) -> InvocationEnv {
            let mut vars = std::collections::BTreeMap::new();
            vars.insert(
                OsString::from("CARGO_MANIFEST_DIR"),
                OsString::from(self.root.join("mylib")),
            );
            vars.insert(OsString::from("CARGO_PKG_NAME"), OsString::from("mylib"));
            // Cargo's own configuration reaches rustc only through argv.
            vars.insert(
                OsString::from("CARGO_TARGET_DIR"),
                OsString::from(self.root.join("target")),
            );
            for (name, value) in extra {
                vars.insert(OsString::from(name), OsString::from(value));
            }
            InvocationEnv {
                cwd: self.root.clone(),
                vars,
            }
        }

        fn invocation_key(&self, env: &InvocationEnv) -> String {
            let args = self.args();
            let parsed = ParsedRustcArgs::parse(&args).expect("parse argv");
            assert_eq!(refusal(&parsed, &args), None);
            let remaps = remap_rules(&args).expect("remap rules");
            match invocation_key_blocking(
                &args,
                &parsed,
                env,
                "rustc 1.91.1 (ed61e7d7e 2025-11-07)",
                &remaps,
            ) {
                Keying::Keyed(key) => key,
                Keying::Uncacheable(reason) => panic!("uncacheable: {reason}"),
            }
        }

        fn unit_key(&self, env: &InvocationEnv, env_deps: &[&str]) -> String {
            let remaps = remap_rules(&self.args()).expect("remap rules");
            let inputs = UnitInputs {
                files: vec![normalize(Path::new("mylib/src/lib.rs"), &remaps).expect("normalize")],
                env: env_deps.iter().map(|name| (*name).to_owned()).collect(),
            };
            match unit_key_blocking(&self.invocation_key(env), &inputs, env, &remaps) {
                Keying::Keyed(key) => key,
                Keying::Uncacheable(reason) => panic!("uncacheable: {reason}"),
            }
        }
    }

    const LIB_RS: &str = "pub const FLAVOR: Option<&str> = option_env!(\"FLAVOR\");\n";

    #[test]
    fn a_path_dependency_keys_the_same_in_two_checkouts() {
        let first = Checkout::new(LIB_RS, b"rmeta");
        let second = Checkout::new(LIB_RS, b"rmeta");
        assert_ne!(first.root, second.root);
        assert_eq!(
            first.unit_key(&first.env(&[]), &["FLAVOR"]),
            second.unit_key(&second.env(&[]), &["FLAVOR"])
        );
    }

    #[test]
    fn an_edited_source_file_changes_the_key() {
        let first = Checkout::new(LIB_RS, b"rmeta");
        let edited = Checkout::new("pub const FLAVOR: Option<&str> = None;\n", b"rmeta");
        assert_ne!(
            first.unit_key(&first.env(&[]), &["FLAVOR"]),
            edited.unit_key(&edited.env(&[]), &["FLAVOR"])
        );
    }

    #[test]
    fn an_env_read_variable_change_changes_the_key() {
        let checkout = Checkout::new(LIB_RS, b"rmeta");
        let unset = checkout.unit_key(&checkout.env(&[]), &["FLAVOR"]);
        let set = checkout.unit_key(&checkout.env(&[("FLAVOR", "a")]), &["FLAVOR"]);
        let other = checkout.unit_key(&checkout.env(&[("FLAVOR", "b")]), &["FLAVOR"]);
        assert_ne!(unset, set);
        assert_ne!(set, other);
    }

    #[test]
    fn a_rebuilt_dependency_changes_the_invocation_key() {
        let first = Checkout::new(LIB_RS, b"rmeta");
        let rebuilt = Checkout::new(LIB_RS, b"other rmeta");
        assert_ne!(
            first.invocation_key(&first.env(&[])),
            rebuilt.invocation_key(&rebuilt.env(&[]))
        );
    }

    #[test]
    fn an_unremapped_absolute_path_is_keyed_raw() {
        let remaps = vec![RemapRule {
            from: "/work/a".into(),
            to: "stow-ci://workspace".to_owned(),
        }];
        assert_eq!(
            normalize(Path::new("/work/a/src/lib.rs"), &remaps).expect("normalize"),
            InputPath::Remapped {
                to: "stow-ci://workspace".to_owned(),
                rest: "src/lib.rs".to_owned(),
            }
        );
        assert_eq!(
            normalize(Path::new("/work/ab/src/lib.rs"), &remaps).expect("normalize"),
            InputPath::Absolute("/work/ab/src/lib.rs".to_owned())
        );
    }

    #[test]
    fn dep_info_lists_files_and_env_deps() {
        let text = "/t/deps/libmylib-1.rmeta: mylib/src/lib.rs /w/with\\ space.rs\n\
                    /t/deps/mylib-1.d: mylib/src/lib.rs /w/with\\ space.rs\n\n\
                    mylib/src/lib.rs:\n/w/with\\ space.rs:\n\n\
                    # env-dep:FLAVOR=a\n# env-dep:UNSET\n";
        let dep_info = parse_dep_info(text).expect("parse");
        assert_eq!(dep_info.files, vec!["mylib/src/lib.rs", "/w/with space.rs"]);
        assert_eq!(dep_info.env_names(), vec!["FLAVOR", "UNSET"]);
        assert!(parse_dep_info("# checksum:blake3=00 file_len:1 a.rs\n").is_err());
    }

    #[test]
    fn incremental_units_are_refused() {
        let args: Vec<OsString> = [
            "--crate-name",
            "mylib",
            "src/lib.rs",
            "--crate-type",
            "lib",
            "--emit=dep-info,metadata,link",
            "--out-dir",
            "/t/deps",
            "-C",
            "incremental=/t/incremental",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let parsed = ParsedRustcArgs::parse(&args).expect("parse argv");
        assert!(refusal(&parsed, &args).is_some_and(|reason| reason.contains("incremental")));
    }
}

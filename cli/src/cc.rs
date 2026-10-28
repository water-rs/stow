use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use async_process::Command;
use sha2::{Digest, Sha256};
use stow_types::error::Context;

use crate::artifact_cache::{LRU_STAMP_INTERVAL_MS, recorded_millis};
use crate::config::StowConfig;
use crate::state_db::{db_int, now_millis};

/// Which language the compiler shim was invoked for — the two roles resolve
/// to different POSIX defaults and the same `cl.exe` on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CcKind {
    /// The `stow-cc` shim (`CC`).
    C,
    /// The `stow-cxx` shim (`CXX`).
    Cxx,
}

/// The real compiler a shim invocation execs, plus the environment that
/// compiler needs — empty on POSIX; the MSVC toolchain's `PATH`/`LIB`/
/// `INCLUDE` for an msvc target, where `cl.exe` finds nothing on its own.
/// The environment is resolved per invocation (the way the `cc` crate
/// resolves it inside every build script) rather than snapshotted into the
/// cargo configuration, so a Visual Studio update cannot strand it.
#[derive(Debug, Clone)]
pub struct ResolvedCompiler {
    pub program: OsString,
    pub env: Vec<(OsString, OsString)>,
}

impl ResolvedCompiler {
    /// An explicitly recorded compiler: used verbatim with no toolchain env.
    pub const fn explicit(program: OsString) -> Self {
        Self {
            program,
            env: Vec::new(),
        }
    }
}

/// Resolve the compiler an invocation with no recorded toolchain runs.
/// `target` is the `TARGET` variable cargo sets for a build script — the
/// compilation's real destination, so an x64→aarch64 cross build gets the
/// right `cl.exe`/`LIB`/`INCLUDE`; when it is absent (a manual shim call
/// outside a build) the host applies.
///
/// On an msvc target it is the `cl.exe` `find_msvc_tools` locates (the same
/// lookup `cc` performs), carrying that tool's environment; any other
/// Windows target keeps the `cc`/`c++` names.
///
/// # Errors
/// Fails when the target is msvc but no MSVC toolchain can be found —
/// wiring a bare `cl` would produce a spawn error with no hint of the
/// cause.
#[cfg(windows)]
pub fn resolve_compiler(
    kind: CcKind,
    target: Option<&str>,
) -> stow_types::error::Result<ResolvedCompiler> {
    if let Some(target) = target_for_resolution(target) {
        let tool = find_msvc_tools::find_tool(target.as_str(), "cl.exe").ok_or_else(|| {
            stow_types::stow_error!(
                "no MSVC toolchain found for target {target} — install \
                 Visual Studio Build Tools, or set STOW_REAL_CC to a compiler"
            )
        })?;
        return Ok(ResolvedCompiler {
            program: tool.path().as_os_str().to_owned(),
            env: tool
                .env()
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
        });
    }
    Ok(platform_driver(kind))
}

/// The POSIX form of [`resolve_compiler`]: infallible, because the `cc`/
/// `c++` driver names always resolve — `TARGET` is accepted for signature
/// parity and ignored.
#[cfg(not(windows))]
pub fn resolve_compiler(kind: CcKind, _target: Option<&str>) -> ResolvedCompiler {
    platform_driver(kind)
}

/// `cc`/`c++`, the compiler driver the `cc` crate execs on every
/// non-msvc resolution.
fn platform_driver(kind: CcKind) -> ResolvedCompiler {
    ResolvedCompiler::explicit(OsString::from(match kind {
        CcKind::C => "cc",
        CcKind::Cxx => "c++",
    }))
}

/// The `TARGET`-or-host triple an msvc lookup applies, or `None` when the
/// compilation is not for an msvc target (`*-windows-gnu`, `wasm32`, …).
/// `find_tool` needs the host architecture when `TARGET` is absent —
/// cargo sets the variable only for build scripts, not for a shim a user
/// invokes by hand.
#[cfg(windows)]
fn target_for_resolution(target: Option<&str>) -> Option<String> {
    target.map_or_else(
        || Some(format!("{}-pc-windows-msvc", std::env::consts::ARCH)),
        |triple| triple.contains("msvc").then(|| triple.to_owned()),
    )
}

const PROBE_FLAGS: &[&str] = &[
    "--version",
    "-v",
    "-V",
    "-dumpversion",
    "-dumpmachine",
    "-print-search-dirs",
];
const FLAGS_WITH_VALUE: &[&str] = &[
    "-I",
    "-isystem",
    "-include",
    "-imacros",
    "-iquote",
    "-idirafter",
    "-iprefix",
    "-iwithprefix",
    "-iwithprefixbefore",
    "-x",
    "-std",
    "-target",
    "-arch",
    "-D",
    "-U",
    "-Xpreprocessor",
    "-Xclang",
    "-Xlinker",
    "-Xassembler",
];

/// Which header set the requested depfile must record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepfileMode {
    /// `-MMD`: user headers only.
    UserHeadersOnly,
    /// `-MD`: all headers, including system headers.
    AllHeaders,
}

/// A depfile rule target requested via `-MT` or `-MQ`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepfileTarget {
    /// `-MT`: target name used verbatim.
    Plain(OsString),
    /// `-MQ`: target name the compiler make-quotes when emitting the rule.
    Quoted(OsString),
}

/// A `-MD`/`-MMD` depfile request extracted from the compiler invocation.
#[derive(Debug, Clone)]
pub struct DepfileRequest {
    pub mode: DepfileMode,
    pub path: PathBuf,
    pub targets: Vec<DepfileTarget>,
    pub phony_headers: bool,
}

impl DepfileRequest {
    /// Append the equivalent depfile flags to a compiler command so the
    /// preprocessor pass writes the requested depfile as a side effect.
    fn append_compiler_args(&self, command: &mut Command) {
        command.arg(match self.mode {
            DepfileMode::UserHeadersOnly => "-MMD",
            DepfileMode::AllHeaders => "-MD",
        });
        command.arg("-MF").arg(&self.path);
        for target in &self.targets {
            match target {
                DepfileTarget::Plain(value) => command.arg("-MT").arg(value),
                DepfileTarget::Quoted(value) => command.arg("-MQ").arg(value),
            };
        }
        if self.phony_headers {
            command.arg("-MP");
        }
    }
}

/// How a `-M`-family argument was handled while scanning the command line.
enum DepfileArg {
    /// Not a depfile flag; the main parser handles the argument.
    Unrelated,
    /// A depfile option was recorded.
    Consumed,
    /// A dependency mode that produces no cacheable object (`-M`, `-MM`,
    /// `-MG`, `-MJ`); the invocation must pass through to the real compiler.
    Passthrough,
}

/// Accumulates `-M`-family depfile options while scanning a compile command
/// line.
#[derive(Default)]
struct DepfileOptions {
    mode: Option<DepfileMode>,
    path: Option<PathBuf>,
    targets: Vec<DepfileTarget>,
    phony_headers: bool,
}

impl DepfileOptions {
    fn consume(
        &mut self,
        arg: &str,
        iter: &mut std::slice::Iter<'_, OsString>,
    ) -> stow_types::error::Result<DepfileArg> {
        match arg {
            "-MD" => self.mode = Some(DepfileMode::AllHeaders),
            "-MMD" => self.mode = Some(DepfileMode::UserHeadersOnly),
            "-MP" => self.phony_headers = true,
            "-M" | "-MM" | "-MG" | "-MJ" => return Ok(DepfileArg::Passthrough),
            "-MF" | "-MT" | "-MQ" => {
                let Some(value) = iter.next() else {
                    return Err(stow_types::stow_error!("missing value after {arg}"));
                };
                self.apply(arg, value);
            }
            _ if arg.starts_with("-MJ") => return Ok(DepfileArg::Passthrough),
            _ => {
                if arg.len() <= 3 {
                    return Ok(DepfileArg::Unrelated);
                }
                let (flag, value) = arg.split_at(3);
                if !matches!(flag, "-MF" | "-MT" | "-MQ") {
                    return Ok(DepfileArg::Unrelated);
                }
                self.apply(flag, OsStr::new(value));
            }
        }
        Ok(DepfileArg::Consumed)
    }

    fn apply(&mut self, flag: &str, value: &OsStr) {
        match flag {
            "-MF" => self.path = Some(PathBuf::from(value)),
            "-MT" => self.targets.push(DepfileTarget::Plain(value.to_owned())),
            "-MQ" => self.targets.push(DepfileTarget::Quoted(value.to_owned())),
            _ => unreachable!("depfile value flag {flag}"),
        }
    }

    /// Whether depfile side-options (`-MF`, `-MT`, `-MQ`, `-MP`) were given
    /// without a `-MD`/`-MMD` mode — a shape stow does not reproduce.
    const fn side_options_without_mode(&self) -> bool {
        self.mode.is_none()
            && (self.path.is_some() || !self.targets.is_empty() || self.phony_headers)
    }

    fn build(self, output_path: &Path) -> Option<DepfileRequest> {
        self.mode.map(|mode| DepfileRequest {
            mode,
            path: self.path.unwrap_or_else(|| output_path.with_extension("d")),
            targets: if self.targets.is_empty() {
                vec![DepfileTarget::Plain(output_path.as_os_str().to_owned())]
            } else {
                self.targets
            },
            phony_headers: self.phony_headers,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ParsedCcInvocation {
    pub output_path: PathBuf,
    pub depfile: Option<DepfileRequest>,
    pub preprocess_args: Vec<OsString>,
    pub compile_hash_args: Vec<OsString>,
}

pub async fn try_compile(
    config: &StowConfig,
    compiler: &ResolvedCompiler,
    compiler_args: &[OsString],
) -> stow_types::error::Result<CcOutcome> {
    let expanded_args = expand_response_args(compiler_args)?;
    let Some(parsed) = ParsedCcInvocation::parse(&expanded_args)? else {
        return Ok(CcOutcome::Passthrough);
    };
    let compiler_fingerprint = compiler_fingerprint(compiler).await?;
    if let Some(depfile) = parsed.depfile.as_ref()
        && let Some(parent) = depfile.path.parent()
        && !parent.as_os_str().is_empty()
    {
        // clang creates the depfile's parent directory while gcc errors on a
        // missing one; stow follows clang.
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create C depfile directory {}", parent.display()))?;
    }
    let preprocessed = preprocess_source(compiler, &parsed).await?;
    let cache_key = cache_key(&compiler_fingerprint, &parsed, &preprocessed);
    let cache_path = cc_cache_path(config, &cache_key);

    if let Some(parent) = cache_path.parent() {
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create C cache directory {}", parent.display()))?;
    }

    if cache_path.exists() {
        record_cc_hit(config, &cache_key, &cache_path).await?;
        if let Some(parent) = parsed.output_path.parent()
            && !parent.as_os_str().is_empty()
        {
            async_fs::create_dir_all(parent)
                .await
                .wrap_err_with(|| format!("create C output directory {}", parent.display()))?;
        }
        let source = cache_path.clone();
        let output = parsed.output_path.clone();
        smol::unblock(move || serve_cached_object_blocking(&source, &output)).await?;
        return Ok(CcOutcome::Hit {
            cache_key,
            output_path: parsed.output_path,
        });
    }

    Ok(CcOutcome::Miss {
        cache_key,
        cache_path,
        output_path: parsed.output_path,
    })
}

fn expand_response_args(args: &[OsString]) -> stow_types::error::Result<Vec<OsString>> {
    let mut expanded = Vec::with_capacity(args.len());
    for arg in args {
        expand_response_arg(arg, 0, &mut expanded)?;
    }
    Ok(expanded)
}

fn expand_response_arg(
    arg: &OsString,
    depth: usize,
    output: &mut Vec<OsString>,
) -> stow_types::error::Result<()> {
    if depth > 8 {
        return Err(stow_types::stow_error!(
            "C compiler response file nesting exceeds maximum depth"
        ));
    }
    let Some(raw) = arg.to_str() else {
        output.push(arg.clone());
        return Ok(());
    };
    let Some(path) = raw.strip_prefix('@') else {
        output.push(arg.clone());
        return Ok(());
    };
    if path.is_empty() {
        return Err(stow_types::stow_error!(
            "invalid empty C compiler response file argument"
        ));
    }
    let contents = std::fs::read_to_string(path)
        .wrap_err_with(|| format!("read C compiler response file {path}"))?;
    let tokens = shell_words::split(&contents).map_err(|error| {
        stow_types::stow_error!("parse C compiler response file {path}: {error}")
    })?;
    for token in tokens {
        let nested = OsString::from(token);
        expand_response_arg(&nested, depth + 1, output)?;
    }
    Ok(())
}

/// Store a freshly compiled object under its cache key: clone it into a
/// uniquely named file beside the key, then rename that into place, so a
/// concurrent lookup sees either no object or a complete one (stow#837).
/// The first writer wins; a later store of the same key leaves it alone.
///
/// The published object joins `cc_cache_entries` — the shared
/// `artifact_cache_max_bytes` LRU the rustc entries live under
/// (stow#980) — and the post-store eviction pass runs against the whole
/// cache.
pub async fn store_compiled_object(
    config: &StowConfig,
    cache_path: &Path,
    output_path: &Path,
) -> stow_types::error::Result<()> {
    let cache_key = cache_path
        .file_stem()
        .and_then(OsStr::to_str)
        .ok_or_else(|| {
            stow_types::stow_error!(
                "C object cache path {} has no cache-key file name",
                cache_path.display()
            )
        })?
        .to_owned();
    let cache_path = cache_path.to_path_buf();
    let output_path = output_path.to_path_buf();
    let staged_path = cache_path.clone();
    smol::unblock(move || stage_compiled_object_blocking(&staged_path, &output_path)?.publish())
        .await?;
    let size_bytes = async_fs::metadata(&cache_path)
        .await
        .wrap_err_with(|| format!("stat stored C/C++ object {}", cache_path.display()))?
        .len();
    let connection = config.state_db_pool().await?;
    upsert_cc_cache_entry(&connection, &cache_key, size_bytes, now_millis()).await?;
    crate::artifact_cache::evict_after_cc_store(config, &connection, &cache_key).await
}

/// How a file reached its destination: a copy-on-write clone sharing the
/// source's blocks, or a byte copy on a filesystem that cannot clone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Cloned,
    Copied,
}

/// Clone `source` to the not-yet-existing `destination` (APFS
/// `clonefile`, Linux `FICLONE`), copying only where the filesystem cannot
/// clone.
fn clone_or_copy(source: &Path, destination: &Path) -> std::io::Result<Placement> {
    let placement = match reflink_copy::reflink_or_copy(source, destination)? {
        None => Placement::Cloned,
        Some(_) => Placement::Copied,
    };
    if placement == Placement::Copied {
        tracing::debug!(
            source = %source.display(),
            destination = %destination.display(),
            "filesystem cannot clone; copied C/C++ object bytes"
        );
    }
    Ok(placement)
}

/// A compiled object cloned into the cache directory under a temporary
/// name, not yet visible at its cache key.
struct StagedObject {
    staged: tempfile::NamedTempFile<Placement>,
    cache_path: PathBuf,
}

impl StagedObject {
    /// Rename the staged object onto its cache key unless another writer
    /// got there first; either way the key then holds a complete object.
    fn publish(self) -> stow_types::error::Result<()> {
        match self.staged.persist_noclobber(&self.cache_path) {
            Ok(_) => Ok(()),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(
                stow_types::error::Error::from(error.error).wrap_err(format!(
                    "move compiled object into cache at {}",
                    self.cache_path.display()
                )),
            ),
        }
    }
}

fn stage_compiled_object_blocking(
    cache_path: &Path,
    output_path: &Path,
) -> stow_types::error::Result<StagedObject> {
    let cache_dir = cache_path.parent().ok_or_else(|| {
        stow_types::stow_error!("C object cache path {} has no parent", cache_path.display())
    })?;
    let staged = tempfile::Builder::new()
        .prefix(".stage-")
        .suffix(".o")
        .make_in(cache_dir, |staged| clone_or_copy(output_path, staged))
        .wrap_err_with(|| {
            format!(
                "stage compiled object {} in C object cache {}",
                output_path.display(),
                cache_dir.display()
            )
        })?;
    Ok(StagedObject {
        staged,
        cache_path: cache_path.to_path_buf(),
    })
}

/// Serve a cached object: replace whatever sits at `output_path` with a
/// clone of the cache entry.
fn serve_cached_object_blocking(
    cache_path: &Path,
    output_path: &Path,
) -> stow_types::error::Result<Placement> {
    match std::fs::remove_file(output_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(stow_types::error::Error::from(error)
                .wrap_err(format!("remove stale object {}", output_path.display())));
        }
    }
    clone_or_copy(cache_path, output_path).wrap_err_with(|| {
        format!(
            "serve cached object {} into {}",
            cache_path.display(),
            output_path.display()
        )
    })
}

fn cc_cache_path(config: &StowConfig, cache_key: &str) -> PathBuf {
    cc_object_path(&config.cc_cache_dir(), cache_key)
}

/// The object file `cache_key` is stored at inside the C/C++ object
/// cache directory — `cc_dir` is `StowConfig::cc_cache_dir`.
pub fn cc_object_path(cc_dir: &Path, cache_key: &str) -> PathBuf {
    cc_dir.join(format!("{cache_key}.o"))
}

/// A `cc_cache_entries` row for the shared LRU: the object file's size
/// and its last-access stamp.
pub struct CcCacheIndexEntry {
    pub size_bytes: u64,
    pub last_accessed_ms: u64,
}

/// Every C/C++ object's row — the `cc/` half of the candidate list
/// `evict_entries` orders.
pub async fn list_cc_cache_entries(
    connection: &sqlx::SqlitePool,
) -> stow_types::error::Result<BTreeMap<String, CcCacheIndexEntry>> {
    let rows = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT cache_key, size_bytes, last_accessed_ms FROM cc_cache_entries",
    )
    .fetch_all(connection)
    .await?;
    let mut entries = BTreeMap::new();
    for (cache_key, size_bytes, last_accessed_ms) in rows {
        entries.insert(
            cache_key,
            CcCacheIndexEntry {
                size_bytes: db_int(size_bytes, "cc cache entry size_bytes")?,
                last_accessed_ms: db_int(last_accessed_ms, "cc cache entry last_accessed_ms")?,
            },
        );
    }
    Ok(entries)
}

/// Remove an object's row — `evict_entries` deletes the file itself.
pub async fn delete_cc_cache_entry(
    connection: &sqlx::SqlitePool,
    cache_key: &str,
) -> stow_types::error::Result<()> {
    sqlx::query("DELETE FROM cc_cache_entries WHERE cache_key = ?")
        .bind(cache_key)
        .execute(connection)
        .await?;
    Ok(())
}

/// Bump the object's LRU stamp for a hit, under the same staleness
/// window `artifact_cache_entries` uses. A file at the key with no row
/// is a store that died after publishing — the bytes are
/// content-addressed and already complete, so the hit adopts them into
/// the budget rather than leave them off the LRU.
async fn record_cc_hit(
    config: &StowConfig,
    cache_key: &str,
    cache_path: &Path,
) -> stow_types::error::Result<()> {
    let connection = config.state_db_pool().await?;
    let stamp: Option<i64> =
        sqlx::query_scalar("SELECT last_accessed_ms FROM cc_cache_entries WHERE cache_key = ?")
            .bind(cache_key)
            .fetch_optional(&connection)
            .await?;
    let now = now_millis();
    if let Some(stamp) = stamp {
        if now.saturating_sub(recorded_millis(stamp)) > LRU_STAMP_INTERVAL_MS {
            touch_cc_cache_entry(&connection, cache_key, now).await?;
        }
    } else {
        let size_bytes = async_fs::metadata(cache_path)
            .await
            .wrap_err_with(|| format!("stat C/C++ object {}", cache_path.display()))?
            .len();
        upsert_cc_cache_entry(&connection, cache_key, size_bytes, now).await?;
    }
    Ok(())
}

/// Write the object's row — on a store, or a hit adopting a published
/// object whose row never landed. The upsert stays one statement against
/// a racing store of the same key: the content is identical, so the
/// later writer's stamp wins.
async fn upsert_cc_cache_entry(
    connection: &sqlx::SqlitePool,
    cache_key: &str,
    size_bytes: u64,
    last_accessed_ms: u64,
) -> stow_types::error::Result<()> {
    sqlx::query(
        "INSERT INTO cc_cache_entries (cache_key, size_bytes, last_accessed_ms) \
         VALUES (?, ?, ?) \
         ON CONFLICT(cache_key) DO UPDATE SET \
             size_bytes = excluded.size_bytes, \
             last_accessed_ms = excluded.last_accessed_ms",
    )
    .bind(cache_key)
    .bind(db_int::<_, i64>(size_bytes, "cc cache entry size_bytes")?)
    .bind(db_int::<_, i64>(
        last_accessed_ms,
        "cc cache entry last_accessed_ms",
    )?)
    .execute(connection)
    .await?;
    Ok(())
}

/// Rewrite the object's LRU stamp — the same fail-fast as
/// `touch_artifact_cache_entry`: a row that vanished mid-hit was
/// evicted, which is not a state to bump over.
async fn touch_cc_cache_entry(
    connection: &sqlx::SqlitePool,
    cache_key: &str,
    last_accessed_ms: u64,
) -> stow_types::error::Result<()> {
    let result =
        sqlx::query("UPDATE cc_cache_entries SET last_accessed_ms = ? WHERE cache_key = ?")
            .bind(db_int::<_, i64>(
                last_accessed_ms,
                "cc cache entry last_accessed_ms",
            )?)
            .bind(cache_key)
            .execute(connection)
            .await?;
    if result.rows_affected() != 1 {
        return Err(stow_types::stow_error!(
            "cc cache entry {cache_key} is missing from the state database"
        ));
    }
    Ok(())
}

async fn compiler_fingerprint(compiler: &ResolvedCompiler) -> stow_types::error::Result<Vec<u8>> {
    let output = Command::new(&compiler.program)
        .arg("--version")
        .envs(compiler.env.iter().cloned())
        .output()
        .await
        .wrap_err("spawn compiler --version")?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "compiler --version failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

async fn preprocess_source(
    compiler: &ResolvedCompiler,
    parsed: &ParsedCcInvocation,
) -> stow_types::error::Result<Vec<u8>> {
    let mut command = Command::new(&compiler.program);
    command
        .args(&parsed.preprocess_args)
        .envs(compiler.env.iter().cloned());
    if let Some(depfile) = parsed.depfile.as_ref() {
        depfile.append_compiler_args(&mut command);
    }
    let output = command.output().await.wrap_err("spawn C preprocessor")?;
    if !output.status.success() {
        return Err(stow_types::stow_error!(
            "C preprocessing failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(output.stdout)
}

fn cache_key(
    compiler_fingerprint: &[u8],
    parsed: &ParsedCcInvocation,
    preprocessed: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"stow-cc-v1");
    hasher.update(compiler_fingerprint);
    for arg in &parsed.compile_hash_args {
        hash_os_string(&mut hasher, arg);
    }
    hasher.update(preprocessed);
    hex::encode(hasher.finalize())
}

fn hash_os_string(hasher: &mut Sha256, value: &OsStr) {
    let encoded = value.to_string_lossy();
    hasher.update((encoded.len() as u64).to_le_bytes());
    hasher.update(encoded.as_bytes());
}

impl ParsedCcInvocation {
    pub fn parse(args: &[OsString]) -> stow_types::error::Result<Option<Self>> {
        if args.is_empty() {
            return Ok(None);
        }
        if args
            .iter()
            .filter_map(|arg| arg.to_str())
            .any(|arg| PROBE_FLAGS.contains(&arg))
        {
            return Ok(None);
        }

        let mut source_path = None;
        let mut output_path = None;
        let mut depfile_options = DepfileOptions::default();
        let mut preprocess_args = Vec::new();
        let mut compile_hash_args = Vec::new();
        let mut iter = args.iter();
        let mut seen_compile_flag = false;

        while let Some(arg) = iter.next() {
            let Some(arg_str) = arg.to_str() else {
                return Ok(None);
            };

            match depfile_options.consume(arg_str, &mut iter)? {
                DepfileArg::Consumed => continue,
                DepfileArg::Passthrough => return Ok(None),
                DepfileArg::Unrelated => {}
            }

            match arg_str {
                "-c" => {
                    seen_compile_flag = true;
                }
                "-o" => {
                    let Some(path) = iter.next() else {
                        return Err(stow_types::stow_error!("missing value after -o"));
                    };
                    output_path = Some(PathBuf::from(path));
                }
                flag if FLAGS_WITH_VALUE.contains(&flag) => {
                    let Some(value) = iter.next() else {
                        return Err(stow_types::stow_error!("missing value after {arg_str}"));
                    };
                    preprocess_args.push(arg.clone());
                    preprocess_args.push(value.clone());
                    compile_hash_args.push(arg.clone());
                    compile_hash_args.push(value.clone());
                }
                value if value.starts_with("-o") && value.len() > 2 => {
                    output_path = Some(PathBuf::from(&value[2..]));
                }
                value
                    if value.starts_with("-I")
                        || value.starts_with("-D")
                        || value.starts_with("-U")
                        || value.starts_with("-std=")
                        || value.starts_with("-isystem")
                        || value.starts_with("-include")
                        || value.starts_with("-imacros")
                        || value.starts_with("-iquote")
                        || value.starts_with("-target")
                        || value.starts_with("-arch") =>
                {
                    preprocess_args.push(arg.clone());
                    compile_hash_args.push(arg.clone());
                }
                value if value.starts_with('-') => {
                    preprocess_args.push(arg.clone());
                    compile_hash_args.push(arg.clone());
                }
                _ => {
                    if source_path.is_some() {
                        return Ok(None);
                    }
                    source_path = Some(PathBuf::from(arg));
                    preprocess_args.push(arg.clone());
                }
            }
        }

        if !seen_compile_flag {
            return Ok(None);
        }

        let Some(_source_path) = source_path else {
            return Ok(None);
        };
        let Some(output_path) = output_path else {
            return Ok(None);
        };

        if depfile_options.side_options_without_mode() {
            return Ok(None);
        }
        let depfile = depfile_options.build(&output_path);

        preprocess_args.push(OsString::from("-E"));
        preprocess_args.push(OsString::from("-P"));

        Ok(Some(Self {
            output_path,
            depfile,
            preprocess_args,
            compile_hash_args,
        }))
    }
}

#[derive(Debug, Clone)]
pub enum CcOutcome {
    Passthrough,
    Hit {
        cache_key: String,
        output_path: PathBuf,
    },
    Miss {
        cache_key: String,
        cache_path: PathBuf,
        output_path: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::time::Duration;

    #[cfg(unix)]
    use super::CcOutcome;
    use super::{DepfileMode, DepfileTarget, ParsedCcInvocation};
    #[cfg(unix)]
    use crate::config::{StowConfig, VerifyMode};

    fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
        values.iter().map(std::ffi::OsString::from).collect()
    }

    #[cfg(unix)]
    fn test_config(cache_dir: PathBuf) -> StowConfig {
        StowConfig {
            edge_url: "http://127.0.0.1:8787".to_owned(),
            registry_base_url: "http://127.0.0.1:8787".to_owned(),
            cache_dir,
            request_timeout: Duration::from_secs(15),
            negative_cache_ttl: Duration::from_mins(5),
            circuit_reset_after: Duration::from_mins(1),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: crate::config::DEFAULT_ARTIFACT_CACHE_MAX_BYTES,
            index_refresh_interval: Duration::from_mins(1),
            verify_mode: VerifyMode::GithubCi,
            state_db: crate::state_db::StateDb::default(),
            trust_material: std::sync::Arc::default(),
            registry_http: std::sync::Arc::default(),
            artifact_cache_staging: std::sync::Arc::default(),
            experimental: crate::config::ExperimentalConfig::default(),
        }
    }

    /// The msvc lookup keys on `TARGET`, not the machine: an
    /// `aarch64-pc-windows-msvc` target resolves for aarch64, a `*-gnu`
    /// target or wasm skips the MSVC path entirely.
    #[cfg(windows)]
    #[test]
    fn target_for_resolution_follows_the_build_target() {
        assert_eq!(
            super::target_for_resolution(Some("aarch64-pc-windows-msvc")).as_deref(),
            Some("aarch64-pc-windows-msvc")
        );
        assert_eq!(
            super::target_for_resolution(Some("x86_64-pc-windows-msvc")).as_deref(),
            Some("x86_64-pc-windows-msvc")
        );
        assert_eq!(
            super::target_for_resolution(Some("x86_64-pc-windows-gnu")),
            None
        );
        assert_eq!(
            super::target_for_resolution(Some("wasm32-unknown-unknown")),
            None
        );
        // No TARGET (a manual shim call) resolves for the host arch.
        assert_eq!(
            super::target_for_resolution(None).as_deref(),
            Some(format!("{}-pc-windows-msvc", std::env::consts::ARCH)).as_deref()
        );
    }

    /// With no MSVC toolchain needed — a non-msvc target or a POSIX host —
    /// the resolution is the plain `cc`/`c++` driver name.
    #[test]
    fn non_msvc_targets_resolve_to_the_platform_driver() {
        #[cfg(not(windows))]
        let cases = [
            ("x86_64-unknown-linux-gnu", "cc"),
            ("x86_64-pc-windows-msvc", "cc"), // unreachable on POSIX
        ];
        #[cfg(windows)]
        let cases = [
            ("x86_64-pc-windows-gnu", "cc"),
            ("wasm32-unknown-unknown", "cc"),
        ];
        for (target, expected) in cases {
            let resolved = super::resolve_compiler(super::CcKind::C, Some(target));
            #[cfg(windows)]
            let resolved = resolved.expect("resolve");
            assert_eq!(resolved.program, OsString::from(expected));
            assert!(resolved.env.is_empty(), "env leaked for {target}");
        }
    }

    #[test]
    fn expands_response_file_arguments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rsp = dir.path().join("args.rsp");
        std::fs::write(&rsp, "-I include -DNAME=VALUE -c source.c -o source.o")
            .expect("write response file");
        let values = vec![OsString::from(format!("@{}", rsp.display()))];
        let expanded = super::expand_response_args(&values).expect("expand response args");
        assert_eq!(
            expanded,
            vec![
                OsString::from("-I"),
                OsString::from("include"),
                OsString::from("-DNAME=VALUE"),
                OsString::from("-c"),
                OsString::from("source.c"),
                OsString::from("-o"),
                OsString::from("source.o"),
            ]
        );
    }

    #[test]
    fn parses_basic_compile_invocation() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-O2",
            "-Wall",
            "-I",
            "include",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        assert_eq!(parsed.output_path, std::path::PathBuf::from("out/foo.o"));
        assert!(parsed.preprocess_args.iter().any(|arg| arg == "-E"));
    }

    #[test]
    fn treats_version_probe_as_passthrough() {
        let parsed =
            ParsedCcInvocation::parse(&args(&["--version"])).expect("parse should succeed");
        assert!(parsed.is_none());
    }

    #[test]
    fn parses_mmd_depfile_with_defaults_from_output_path() {
        let parsed =
            ParsedCcInvocation::parse(&args(&["-MMD", "-c", "src/foo.c", "-o", "out/foo.o"]))
                .expect("parse should succeed")
                .expect("compile should be cacheable");

        let depfile = parsed.depfile.expect("depfile request");
        assert_eq!(depfile.mode, DepfileMode::UserHeadersOnly);
        assert_eq!(depfile.path, PathBuf::from("out/foo.d"));
        assert_eq!(
            depfile.targets,
            vec![DepfileTarget::Plain(OsString::from("out/foo.o"))]
        );
        assert!(!depfile.phony_headers);
    }

    #[test]
    fn parses_md_depfile_with_explicit_options() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-MD",
            "-MF",
            "deps/x.d",
            "-MT",
            "x.o",
            "-MP",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        let depfile = parsed.depfile.expect("depfile request");
        assert_eq!(depfile.mode, DepfileMode::AllHeaders);
        assert_eq!(depfile.path, PathBuf::from("deps/x.d"));
        assert_eq!(
            depfile.targets,
            vec![DepfileTarget::Plain(OsString::from("x.o"))]
        );
        assert!(depfile.phony_headers);
    }

    #[test]
    fn parses_attached_depfile_option_forms() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-MMD",
            "-MFfoo.d",
            "-MTfoo.o",
            "-MQbar.o",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        let depfile = parsed.depfile.expect("depfile request");
        assert_eq!(depfile.mode, DepfileMode::UserHeadersOnly);
        assert_eq!(depfile.path, PathBuf::from("foo.d"));
        assert_eq!(
            depfile.targets,
            vec![
                DepfileTarget::Plain(OsString::from("foo.o")),
                DepfileTarget::Quoted(OsString::from("bar.o")),
            ]
        );
        assert!(!depfile.phony_headers);
    }

    #[test]
    fn xpreprocessor_value_is_not_a_depfile_flag() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-Xpreprocessor",
            "-MD",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        assert!(parsed.depfile.is_none());
        assert_eq!(parsed.compile_hash_args, args(&["-Xpreprocessor", "-MD"]));
        assert_eq!(
            parsed.preprocess_args,
            args(&["-Xpreprocessor", "-MD", "src/foo.c", "-E", "-P"])
        );
    }

    #[test]
    fn xclang_value_is_not_a_depfile_flag() {
        let parsed =
            ParsedCcInvocation::parse(&args(&["-Xclang", "-MF", "x.d", "-c", "-o", "out/foo.o"]))
                .expect("parse should succeed")
                .expect("compile should be cacheable");

        assert!(parsed.depfile.is_none());
        assert_eq!(parsed.compile_hash_args, args(&["-Xclang", "-MF"]));
        assert_eq!(
            parsed.preprocess_args,
            args(&["-Xclang", "-MF", "x.d", "-E", "-P"])
        );
    }

    #[test]
    fn repeated_mf_last_wins() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-MD",
            "-MF",
            "first.d",
            "-MF",
            "second.d",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        assert_eq!(
            parsed.depfile.expect("depfile request").path,
            PathBuf::from("second.d")
        );
    }

    #[test]
    fn repeated_md_mmd_last_wins() {
        for (flags, expected) in [
            (&["-MD", "-MMD"][..], DepfileMode::UserHeadersOnly),
            (&["-MMD", "-MD"][..], DepfileMode::AllHeaders),
        ] {
            let mut argv = flags.to_vec();
            argv.extend(["-c", "src/foo.c", "-o", "out/foo.o"]);
            let parsed = ParsedCcInvocation::parse(&args(&argv))
                .expect("parse should succeed")
                .expect("compile should be cacheable");
            assert_eq!(
                parsed.depfile.expect("depfile request").mode,
                expected,
                "mode for {argv:?}"
            );
        }
    }

    #[test]
    fn repeated_mt_accumulates_in_order() {
        let parsed = ParsedCcInvocation::parse(&args(&[
            "-MMD",
            "-MT",
            "a.o",
            "-MT",
            "b.o",
            "-c",
            "src/foo.c",
            "-o",
            "out/foo.o",
        ]))
        .expect("parse should succeed")
        .expect("compile should be cacheable");

        assert_eq!(
            parsed.depfile.expect("depfile request").targets,
            vec![
                DepfileTarget::Plain(OsString::from("a.o")),
                DepfileTarget::Plain(OsString::from("b.o")),
            ]
        );
    }

    #[test]
    fn depfile_options_without_md_or_mmd_pass_through() {
        for invocation in [
            &["-MF", "x.d"][..],
            &["-MT", "x.o"][..],
            &["-MQ", "x.o"][..],
            &["-MP"][..],
        ] {
            let mut argv = vec!["-c", "src/foo.c", "-o", "out/foo.o"];
            argv.extend_from_slice(invocation);
            let parsed = ParsedCcInvocation::parse(&args(&argv)).expect("parse should succeed");
            assert!(parsed.is_none(), "expected passthrough for {argv:?}");
        }
    }

    #[test]
    fn non_compile_dependency_modes_pass_through() {
        for invocation in [
            &["-M"][..],
            &["-MM"][..],
            &["-MG"][..],
            &["-MJ", "x.json"][..],
            &["-MJx.json"][..],
        ] {
            let mut argv = vec!["-c", "src/foo.c", "-o", "out/foo.o"];
            argv.extend_from_slice(invocation);
            let parsed = ParsedCcInvocation::parse(&args(&argv)).expect("parse should succeed");
            assert!(parsed.is_none(), "expected passthrough for {argv:?}");
        }
    }

    /// A store is invisible at its key until it is complete: the staged
    /// clone sits under a temporary name, so a lookup in that window
    /// misses instead of reading a partial object, and publishing a second
    /// store of the same key keeps the first (stow#837).
    #[test]
    fn a_staged_object_is_invisible_until_published() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("key.o");
        let first_output = dir.path().join("first.o");
        let second_output = dir.path().join("second.o");
        std::fs::write(&first_output, b"first object").expect("write first object");
        std::fs::write(&second_output, b"second object").expect("write second object");

        let first = super::stage_compiled_object_blocking(&cache_path, &first_output)
            .expect("stage first object");
        let second = super::stage_compiled_object_blocking(&cache_path, &second_output)
            .expect("stage second object");
        assert!(!cache_path.exists(), "a staged object must not be visible");

        first.publish().expect("publish first object");
        second.publish().expect("a losing store is not an error");
        assert_eq!(
            std::fs::read(&cache_path).expect("read cached object"),
            b"first object"
        );
        let leftovers = std::fs::read_dir(dir.path())
            .expect("list cache dir")
            .map(|entry| entry.expect("cache dir entry").file_name())
            .filter(|name| name.to_string_lossy().starts_with(".stage-"))
            .collect::<Vec<_>>();
        assert!(
            leftovers.is_empty(),
            "staged files left behind: {leftovers:?}"
        );
    }

    /// On a copy-on-write filesystem — APFS here — both directions clone:
    /// the store shares the compiled object's blocks and the serve shares
    /// the cache entry's.
    #[cfg(target_os = "macos")]
    #[test]
    fn store_and_serve_clone_on_apfs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache_path = dir.path().join("key.o");
        let compiled = dir.path().join("compiled.o");
        let served = dir.path().join("served.o");
        std::fs::write(&compiled, b"object bytes").expect("write compiled object");
        std::fs::write(&served, b"stale object").expect("write stale output");

        let staged = super::stage_compiled_object_blocking(&cache_path, &compiled)
            .expect("stage compiled object");
        assert_eq!(*staged.staged.as_file(), super::Placement::Cloned);
        staged.publish().expect("publish compiled object");

        let placement =
            super::serve_cached_object_blocking(&cache_path, &served).expect("serve object");
        assert_eq!(placement, super::Placement::Cloned);
        assert_eq!(
            std::fs::read(&served).expect("read served"),
            b"object bytes"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cache_hit_writes_requested_depfile() {
        let cc = super::ResolvedCompiler::explicit(OsString::from("cc"));
        if let Err(error) = async_process::Command::new(&cc.program)
            .arg("--version")
            .output()
            .await
        {
            if error.kind() == std::io::ErrorKind::NotFound {
                return;
            }
            panic!("spawn cc --version: {error}");
        }
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path();
        std::fs::write(dir.join("value.h"), "#define VALUE 1\n").expect("write header");
        std::fs::write(
            dir.join("demo.c"),
            "#include \"value.h\"\nint demo(void) { return VALUE; }\n",
        )
        .expect("write source");
        let build = dir.join("build");
        std::fs::create_dir_all(&build).expect("create build dir");
        let object = build.join("demo.o");
        let config = test_config(dir.join("stow-cache"));

        let compiler_args = vec![
            OsString::from("-MMD"),
            OsString::from("-c"),
            dir.join("demo.c").into_os_string(),
            OsString::from("-o"),
            object.clone().into_os_string(),
        ];

        let first = super::try_compile(&config, &cc, &compiler_args)
            .await
            .expect("first try_compile");
        let CcOutcome::Miss {
            cache_path,
            output_path,
            ..
        } = first
        else {
            panic!("first compile must be a cache miss");
        };
        let status = async_process::Command::new(&cc.program)
            .args(&compiler_args)
            .status()
            .await
            .expect("spawn cc");
        assert!(status.success());
        super::store_compiled_object(&config, &cache_path, &output_path)
            .await
            .expect("store compiled object");

        std::fs::remove_dir_all(&build).expect("remove build dir");

        let second = super::try_compile(&config, &cc, &compiler_args)
            .await
            .expect("second try_compile");
        let CcOutcome::Hit { cache_key, .. } = second else {
            panic!("second compile must be a cache hit");
        };
        assert!(object.exists());
        let pool = crate::state_db::connect(&config.cache_dir)
            .await
            .expect("connect state db");
        let row: Option<i64> =
            sqlx::query_scalar("SELECT last_accessed_ms FROM cc_cache_entries WHERE cache_key = ?")
                .bind(&cache_key)
                .fetch_optional(&pool)
                .await
                .expect("load cc cache entry");
        assert!(row.is_some(), "a hit object must carry a state-db row");
        let depfile = std::fs::read_to_string(build.join("demo.d")).expect("read depfile");
        assert!(depfile.contains("value.h"), "depfile contents: {depfile}");
        assert!(
            depfile.contains(&format!("{}:", object.display())),
            "depfile contents: {depfile}"
        );
    }

    /// Every store leaves `cc/` inside `artifact_cache_max_bytes`: the
    /// oldest object's file and row go, the freshest stays (stow#980).
    #[cfg(unix)]
    #[tokio::test]
    async fn cc_objects_stay_under_the_budget_across_stores() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path().join("stow-cache"));
        let cc_dir = config.cc_cache_dir();
        std::fs::create_dir_all(&cc_dir).expect("create cc dir");
        let output = tempdir.path().join("output.o");
        std::fs::write(&output, b"object bytes").expect("write output object");
        config.artifact_cache_max_bytes = std::fs::metadata(&output)
            .expect("stat output object")
            .len();

        for key in ["key-a", "key-b", "key-c"] {
            super::store_compiled_object(&config, &cc_dir.join(format!("{key}.o")), &output)
                .await
                .expect("store compiled object");
        }

        let pool = crate::state_db::connect(&config.cache_dir)
            .await
            .expect("connect state db");
        let entries = super::list_cc_cache_entries(&pool)
            .await
            .expect("list cc cache entries");
        assert_eq!(
            entries.keys().collect::<Vec<_>>(),
            vec!["key-c"],
            "only the freshest object may survive the budget"
        );
        assert!(cc_dir.join("key-c.o").exists());
        for key in ["key-a", "key-b"] {
            assert!(
                !cc_dir.join(format!("{key}.o")).exists(),
                "evicted object {key} left its file behind"
            );
        }
    }

    /// A hit moves the object to the back of the shared LRU: the entry
    /// the bump passed is the one the next store evicts (stow#980).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_hit_refreshes_the_objects_lru_position() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let mut config = test_config(tempdir.path().join("stow-cache"));
        let cc_dir = config.cc_cache_dir();
        std::fs::create_dir_all(&cc_dir).expect("create cc dir");
        let output = tempdir.path().join("output.o");
        std::fs::write(&output, b"object bytes").expect("write output object");
        let object_size = std::fs::metadata(&output)
            .expect("stat output object")
            .len();
        config.artifact_cache_max_bytes = 2 * object_size;

        let first = cc_dir.join("first.o");
        let second = cc_dir.join("second.o");
        super::store_compiled_object(&config, &first, &output)
            .await
            .expect("store first object");
        super::store_compiled_object(&config, &second, &output)
            .await
            .expect("store second object");

        let pool = crate::state_db::connect(&config.cache_dir)
            .await
            .expect("connect state db");
        // `first` starts the pass as the least recently used; the hit
        // must push it behind `second` before `third` is stored.
        super::touch_cc_cache_entry(&pool, "first", 1)
            .await
            .expect("stale first object's stamp");
        super::record_cc_hit(&config, "first", &first)
            .await
            .expect("hit on first object");

        super::store_compiled_object(&config, &cc_dir.join("third.o"), &output)
            .await
            .expect("store third object");

        let entries = super::list_cc_cache_entries(&pool)
            .await
            .expect("list cc cache entries");
        assert!(
            entries.contains_key("first"),
            "the hit keeps first in the cache"
        );
        assert!(
            !entries.contains_key("second"),
            "the un-touched entry is evicted first"
        );
        assert!(entries.contains_key("third"));
        assert!(first.exists());
        assert!(!second.exists());
        assert!(cc_dir.join("third.o").exists());
    }
}

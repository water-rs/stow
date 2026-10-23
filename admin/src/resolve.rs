//! In-process resolves for the preheat lanes (#427) — the published
//! `cargo` crate (`stow-resolver`) drives each resolve where the edge
//! used to, so the lanes no longer call `/api/v1/admin/resolve/*`.
//!
//! ## Concurrency
//!
//! cargo's `GlobalContext` is not `Sync`, so a lane fans its resolves
//! out on [`RESOLVE_CONCURRENCY`] worker threads; each `resolve` call
//! builds its own context on the calling thread. Every worker owns a
//! `Resolver` on its own `CARGO_HOME` shard under one root
//! (`STOW_RESOLVE_CARGO_HOME` when set, a per-process tempdir
//! otherwise): a resolve holds cargo's `CacheLockMode::DownloadExclusive`
//! package-cache lock for its whole selection phase, so workers on one
//! shared home would serialize the network-bound index work the pool
//! exists to overlap. The cost is an index/`.crate` body fetched up to
//! once per worker instead of once per lane — bounded by the worker
//! count, and amortized to nothing once the root survives across runs.
//!
//! The bound is small on purpose: a resolve spends most of its wall
//! time in network round-trips (index files, `.crate` bodies, git
//! fetches), so a handful of lanes already hides the latency while
//! keeping crates.io/git pressure moderate.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};

use stow_types::error::Context as _;
use stow_types::identity::{TargetTriple, WireRustcVersion};

/// How many resolves a lane runs at once; `STOW_RESOLVE_CONCURRENCY`
/// overrides it — the measurement knob stow#884's tuning is read
/// through.
pub const RESOLVE_CONCURRENCY: usize = 4;

/// The env var naming the shared resolve root: every resolve
/// `CARGO_HOME` this process creates lives beneath it — `main` for the
/// pool's own resolver, `worker-N` per [`ResolvePool::run`] worker.
/// Unset, the root is a per-process tempdir.
const RESOLVE_HOME_ENV: &str = "STOW_RESOLVE_CARGO_HOME";

/// The env var overriding [`RESOLVE_CONCURRENCY`].
const RESOLVE_CONCURRENCY_ENV: &str = "STOW_RESOLVE_CONCURRENCY";

/// Where the pool's resolve `CARGO_HOME`s live: a caller-owned
/// directory (`STOW_RESOLVE_CARGO_HOME`), persistent across runs so
/// the sparse-index and `.crate` caches amortize over a wave — the
/// `resolve-request.yml` `--cargo-home` pattern grown to a lane — or a
/// per-process tempdir when the variable is unset.
enum ResolveRoot {
    /// `STOW_RESOLVE_CARGO_HOME`; the caller owns its lifecycle.
    Persistent(PathBuf),
    /// Per-process scratch — the default isolation.
    Temp(tempfile::TempDir),
}

impl ResolveRoot {
    fn path(&self) -> &Path {
        match self {
            Self::Persistent(path) => path,
            Self::Temp(dir) => dir.path(),
        }
    }
}

/// The resolver one lane run holds: the pool's own resolver plus the
/// facts each [`Self::run`] worker needs to build its own, and the
/// runtime handle workers drive the fetch half of a crates.io resolve
/// through — a pool thread carries no executor context of its own.
pub struct ResolvePool {
    /// The lane's own resolver on `<root>/main` — the single-shot
    /// `binary`/`plan`/`submit` resolves drive it through
    /// `resolver()`/`shared()`.
    resolver: Arc<stow_resolver::Resolver>,
    /// The pinned toolchain version a worker's resolver probes.
    rustc_version: WireRustcVersion,
    /// The executable a worker's resolver copies per family host as
    /// `rustc-shim-<host>`.
    shim_source: PathBuf,
    /// The root every resolve home this process creates lives under.
    root: ResolveRoot,
    runtime: tokio::runtime::Handle,
}

impl ResolvePool {
    /// Build the session pinned to `rustc_version`'s rustup toolchain —
    /// `rustup which --toolchain` for its real rustc and `-vV` to prove
    /// the release — then write the per-runner-family rustc shims.
    ///
    /// # Errors
    /// `rustc_version` is not an installed toolchain, or probing failed.
    pub(crate) fn new(rustc_version: &WireRustcVersion) -> stow_types::error::Result<Self> {
        let shim = std::env::current_exe().wrap_err("current executable path")?;
        let root = match std::env::var_os(RESOLVE_HOME_ENV) {
            Some(root) => ResolveRoot::Persistent(PathBuf::from(root)),
            None => ResolveRoot::Temp(tempfile::tempdir().wrap_err("resolve root tempdir")?),
        };
        let resolver = Self::resolver_at(&root.path().join("main"), rustc_version, shim.clone())?;
        Ok(Self {
            resolver: Arc::new(resolver),
            rustc_version: rustc_version.clone(),
            shim_source: shim,
            root,
            runtime: tokio::runtime::Handle::current(),
        })
    }

    /// A resolver whose `CARGO_HOME` is `home` — the one constructor
    /// both the pool's own resolver and every worker's go through.
    fn resolver_at(
        home: &Path,
        rustc_version: &WireRustcVersion,
        shim_source: PathBuf,
    ) -> stow_types::error::Result<stow_resolver::Resolver> {
        stow_resolver::Resolver::with_cargo_home(home.to_path_buf(), rustc_version, shim_source)
            .wrap_err(format!("resolver session for rustc {rustc_version}"))
    }

    /// The runtime handle workers hand to [`resolve_crate`]'s fetch
    /// half — pool threads have no executor context of their own.
    pub(crate) const fn runtime(&self) -> &tokio::runtime::Handle {
        &self.runtime
    }

    /// The session's `Resolver`, for lanes that resolve on the calling
    /// thread (single-shot `binary`/`plan` runs need no pool).
    pub(crate) fn resolver(&self) -> &stow_resolver::Resolver {
        &self.resolver
    }

    /// A shared handle — workers clone it so every thread's resolves
    /// draw on the same `CARGO_HOME`.
    pub(crate) fn shared(&self) -> Arc<stow_resolver::Resolver> {
        self.resolver.clone()
    }

    /// Fan `items` across worker threads, each with its own resolver on
    /// `<root>/worker-N`. A resolve holds cargo's
    /// `CacheLockMode::DownloadExclusive` package-cache lock for its
    /// whole selection phase (`stow-resolver`'s `resolve_with_previous`),
    /// so workers sharing one `CARGO_HOME` would serialize exactly the
    /// phase the pool exists to overlap (stow#884) — separate homes are
    /// what make the workers parallel. Each result reaches `on_item` on
    /// the calling thread in completion order — the projects lane
    /// submits a repo's batch the moment its resolve returns, so a
    /// mid-lane failure costs only the repositories still queued. A
    /// per-item failure lands at its own index; it never stops the wave.
    ///
    /// # Errors
    /// `STOW_RESOLVE_CONCURRENCY` fails to parse, or a worker's resolver
    /// session fails to probe its toolchain — deterministic failures
    /// reported before any item runs rather than as N identical item
    /// failures.
    pub(crate) fn run<T, R, F, G>(
        &self,
        items: &[T],
        work: F,
        mut on_item: G,
    ) -> stow_types::error::Result<()>
    where
        T: Send + Sync,
        R: Send,
        F: Fn(&stow_resolver::Resolver, &tokio::runtime::Handle, &T) -> Result<R, String>
            + Send
            + Sync,
        G: FnMut(usize, &T, Result<R, String>),
    {
        if items.is_empty() {
            return Ok(());
        }
        let workers = resolve_concurrency()?.min(items.len());
        let resolvers: Vec<stow_resolver::Resolver> = (0..workers)
            .map(|worker| {
                Self::resolver_at(
                    &self.root.path().join(format!("worker-{worker}")),
                    &self.rustc_version,
                    self.shim_source.clone(),
                )
            })
            .collect::<stow_types::error::Result<_>>()?;
        let resolvers = &resolvers;
        let next = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel::<(usize, Result<R, String>)>();
        let work = &work;
        std::thread::scope(|scope| {
            for resolver in resolvers {
                let tx = tx.clone();
                let next = &next;
                let runtime = &self.runtime;
                scope.spawn(move || {
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= items.len() {
                            break;
                        }
                        // A panic is a bug, not an item failure:
                        // `thread::scope` re-raises it at the join.
                        let result = work(resolver, runtime, &items[index]);
                        if tx.send((index, result)).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(tx);
            // `rx` ends when every worker's sender dropped — that is the
            // whole run.
            for (index, result) in rx {
                on_item(index, &items[index], result);
            }
        });
        Ok(())
    }
}

/// The worker bound: `RESOLVE_CONCURRENCY`, or
/// `STOW_RESOLVE_CONCURRENCY` when set — the knob the concurrency
/// measurements are taken through.
fn resolve_concurrency() -> stow_types::error::Result<usize> {
    match std::env::var(RESOLVE_CONCURRENCY_ENV) {
        Ok(raw) => raw.parse().wrap_err(format!(
            "{RESOLVE_CONCURRENCY_ENV}={raw}: not a worker count"
        )),
        Err(std::env::VarError::NotPresent) => Ok(RESOLVE_CONCURRENCY),
        Err(error) => Err(error).wrap_err(format!("read {RESOLVE_CONCURRENCY_ENV}")),
    }
}

/// The target list as plain strings — the resolver's wire shape.
pub fn target_strings(targets: &[TargetTriple]) -> Vec<String> {
    targets
        .iter()
        .map(|target| target.as_str().to_owned())
        .collect()
}

/// Resolve one published `.crate` into its task batch plus publish
/// flags — the edge's `resolve_crate` contract. The tarball's bundled
/// `Cargo.lock` is dropped like every other lane's — the resolve lands
/// on the latest semver-compatible versions.
/// Sync: callers run it on a pool worker, which carries no executor
/// context — `runtime` drives the tarball fetch half.
pub fn resolve_crate(
    resolver: &stow_resolver::Resolver,
    runtime: &tokio::runtime::Handle,
    crate_name: &str,
    version: &semver::Version,
    targets: &[TargetTriple],
    rustc_version: &WireRustcVersion,
    downloads: u64,
) -> Result<stow_resolver::SourceResolve, String> {
    let targets = target_strings(targets);
    let rustc_version = rustc_version.clone();
    let crate_name = crate_name.to_owned();
    let version = version.clone();
    runtime
        .block_on(resolver.resolve_crate(
            &crate_name,
            &version,
            &targets,
            &rustc_version,
            downloads,
        ))
        .map_err(|error| format!("resolve {crate_name} {version}: {error:#}"))
}

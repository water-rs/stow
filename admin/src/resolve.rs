//! In-process resolves for the preheat lanes (#427) — the published
//! `cargo` crate (`stow-resolver`) drives each resolve where the edge
//! used to, so the lanes no longer call `/api/v1/admin/resolve/*`.
//!
//! ## Concurrency
//!
//! cargo's `GlobalContext` is not `Sync`, so a lane fans its resolves
//! out on [`RESOLVE_CONCURRENCY`] worker threads; each `resolve` call
//! builds its own context on the calling thread, so one shared
//! `Resolver` (toolchain facts, isolated `CARGO_HOME`, sanitized env)
//! serves every worker — cargo's own file locks arbitrate the shared
//! sparse index and download caches. Threads rather than processes:
//! results come back through a channel instead of serialized IPC, and
//! every worker draws on the one warmed index rather than fetching its
//! own copy.
//!
//! The bound is small on purpose: a resolve spends most of its wall
//! time in network round-trips (index files, `.crate` bodies, git
//! fetches), so a handful of lanes already hides the latency while
//! keeping crates.io/git pressure moderate.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};

use stow_types::error::Context as _;
use stow_types::identity::{TargetTriple, WireRustcVersion};

/// How many resolves a lane runs at once.
pub const RESOLVE_CONCURRENCY: usize = 4;

/// The resolver one lane run holds: a session-owned `CARGO_HOME` in a
/// temp dir shared by every worker's resolves.
pub struct ResolvePool {
    resolver: Arc<stow_resolver::Resolver>,
}

impl ResolvePool {
    /// Build the session: resolve the real toolchain (`rustup which
    /// rustc`, `-vV`) and write the per-runner-family rustc shims.
    ///
    /// # Errors
    /// Toolchain probing failures.
    pub(crate) fn new() -> stow_types::error::Result<Self> {
        let shim = std::env::current_exe().wrap_err("current executable path")?;
        let resolver = stow_resolver::Resolver::new(shim)
            .wrap_err("resolver session (rustc on PATH must be the lane's toolchain)")?;
        Ok(Self {
            resolver: Arc::new(resolver),
        })
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

    /// Fan `items` across [`RESOLVE_CONCURRENCY`] worker threads. Each
    /// result reaches `on_item` on the calling thread in completion
    /// order — the projects lane submits a repo's batch the moment its
    /// resolve returns, so a mid-lane failure costs only the
    /// repositories still queued. A per-item failure lands at its own
    /// index; it never stops the wave.
    pub(crate) fn run<T, R, F, G>(&self, items: &[T], work: F, mut on_item: G)
    where
        T: Send + Sync,
        R: Send,
        F: Fn(&stow_resolver::Resolver, &T) -> Result<R, String> + Send + Sync,
        G: FnMut(usize, &T, Result<R, String>),
    {
        if items.is_empty() {
            return;
        }
        let workers = RESOLVE_CONCURRENCY.min(items.len());
        let next = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel::<(usize, Result<R, String>)>();
        let work = &work;
        std::thread::scope(|scope| {
            for _ in 0..workers {
                let tx = tx.clone();
                let next = &next;
                let resolver = self.resolver.clone();
                scope.spawn(move || {
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= items.len() {
                            break;
                        }
                        // A panic is a bug, not an item failure:
                        // `thread::scope` re-raises it at the join.
                        let result = work(&resolver, &items[index]);
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
/// `Cargo.lock` stays in place: the `cargo install --locked` resolve.
/// Sync: callers run it on a pool worker or inside `smol::unblock`.
pub fn resolve_crate(
    resolver: &stow_resolver::Resolver,
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
    smol::block_on(resolver.resolve_crate(
        &crate_name,
        &version,
        &targets,
        &rustc_version,
        downloads,
    ))
    .map_err(|error| format!("resolve {crate_name} {version}: {error:#}"))
}

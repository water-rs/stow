//! `resolve-memprof`: the worker's `resolve_github_project` chain run
//! natively for heap attribution — one repo, one target, lockfiles under
//! the selected workspace dropped, the source tree in a `MemoryVfs`, one
//! shared `IndexCachesRoot`, `api::resolve` once.
//!
//! Usage: `resolve-memprof <owner/repo> <git_ref> <target> (--record DIR | --replay DIR)`
//!
//! Build with `--features dhat-heap` for a dhat profile
//! (`dhat-heap.json`), or `--features mem-profile` for the counting
//! allocator's per-tag marks.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::SystemTime;

use anyhow::Context;
use stow_resolve::api::{self, StowResolveInput};
use stow_resolve::github_tree::{fetch_github_tree, select_manifest};
use stow_resolve::rustc_data;
use stow_resolve::sources::registry::IndexCachesRoot;
use stow_resolve::testing::{RecordedHttp, RecordingHttp, ReqwestHttp};
use stow_resolve::util::alloc_profile;
use stow_resolve::util::context::GlobalContext;
use stow_resolve::util::context::environment::Env;
use stow_resolve::util::fs::{MemoryVfs, OsVfs, RawDirEntry, RawMetadata, Vfs, set_vfs};
use stow_resolve::util::network::http_async::{Client, HttpClient};
use stow_resolve::util::shell::Shell;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(all(feature = "mem-profile", not(feature = "dhat-heap")))]
#[global_allocator]
static ALLOC: alloc_profile::Counting<std::alloc::System> =
    alloc_profile::Counting(std::alloc::System);

const PIN_VERSION: &str = "1.98.1";

/// Paths under `cargo_home` go to the real fs (the host tarball unpack
/// writes through `std::fs`); everything else stays in memory.
struct CargoHomeOverlay {
    inner: Rc<dyn Vfs>,
    cargo_home: PathBuf,
}

impl CargoHomeOverlay {
    fn backend(&self, path: &Path) -> &dyn Vfs {
        if path.starts_with(&self.cargo_home) {
            &OsVfs
        } else {
            self.inner.as_ref()
        }
    }
}

impl Vfs for CargoHomeOverlay {
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.backend(path).read(path)
    }
    fn write(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
        self.backend(path).write(path, data)
    }
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.backend(path).create_dir_all(path)
    }
    fn read_dir(&self, path: &Path) -> std::io::Result<Vec<RawDirEntry>> {
        self.backend(path).read_dir(path)
    }
    fn metadata(&self, path: &Path) -> std::io::Result<RawMetadata> {
        self.backend(path).metadata(path)
    }
    fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.backend(path).remove_file(path)
    }
    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.backend(path).remove_dir_all(path)
    }
    fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
        self.backend(path).canonicalize(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.backend(from).rename(from, to)
    }
    fn mtime(&self, path: &Path) -> std::io::Result<SystemTime> {
        self.backend(path).mtime(path)
    }
    fn set_mtime(&self, path: &Path, t: SystemTime) -> std::io::Result<()> {
        self.backend(path).set_mtime(path, t)
    }
}

fn host_of(target: &str) -> &'static str {
    if target.contains("apple") {
        "aarch64-apple-darwin"
    } else if target.contains("windows") {
        "x86_64-pc-windows-msvc"
    } else {
        "x86_64-unknown-linux-gnu"
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 6 || args.len() == 8,
        "usage: resolve-memprof <owner/repo> <git_ref> <target[,target..]> (--record|--replay) DIR [--emit FILE]"
    );
    let emit = (args.len() == 8).then(|| PathBuf::from(&args[7]));
    let (repo, git_ref, target, mode, dir) = (
        args[1].clone(),
        args[2].clone(),
        args[3].clone(),
        args[4].clone(),
        PathBuf::from(&args[5]),
    );
    let http: Rc<dyn HttpClient> = match mode.as_str() {
        "--record" => Rc::new(RecordingHttp::new(ReqwestHttp::new(), dir)),
        "--replay" => Rc::new(RecordedHttp::new(dir)),
        other => anyhow::bail!("unknown mode {other}"),
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let work = std::env::temp_dir().join(format!("resolve-memprof-{}", std::process::id()));
    let cargo_home = work.join("cargo-home");
    std::fs::create_dir_all(&cargo_home)?;

    #[cfg(feature = "dhat-heap")]
    let profiler = dhat::Profiler::new_heap();
    #[cfg(feature = "mem-profile")]
    alloc_profile::reset();
    alloc_profile::mark("request_start");

    let units = rt.block_on(run(http, &repo, &git_ref, &target, &cargo_home, emit.as_deref()))?;

    alloc_profile::mark("request_end");
    #[cfg(feature = "dhat-heap")]
    drop(profiler);
    for line in alloc_profile::take_marks() {
        println!("MEMPROF {line}");
    }
    println!("units={units}");
    let _ = std::fs::remove_dir_all(&work);
    Ok(())
}

#[allow(clippy::future_not_send)]
async fn run(
    http: Rc<dyn HttpClient>,
    repo: &str,
    git_ref: &str,
    targets: &str,
    cargo_home: &Path,
    emit: Option<&Path>,
) -> anyhow::Result<usize> {
    let client = Client::new(http);
    let tree = alloc_profile::tagged(
        alloc_profile::Tag::Source,
        fetch_github_tree(&client, repo, git_ref),
    )
    .await
    .context("tree fetch")?;
    let files = tree.files;
    let root = PathBuf::from("/ws");
    let vfs = MemoryVfs::new();
    let manifest_rel = select_manifest(&files).context("no Cargo.toml")?;
    let manifest_path = root.join(&manifest_rel);
    let ws_root = manifest_rel
        .parent()
        .map_or_else(PathBuf::new, Path::to_path_buf);
    for (path, data) in files {
        let is_ws_lockfile = path.file_name().and_then(|n| n.to_str()) == Some("Cargo.lock")
            && path.starts_with(&ws_root);
        if !is_ws_lockfile {
            vfs.insert(root.join(path), data);
        }
    }
    alloc_profile::mark("source");

    let vfs: Rc<dyn Vfs> = Rc::new(CargoHomeOverlay {
        inner: Rc::new(vfs),
        cargo_home: cargo_home.to_path_buf(),
    });
    let index_caches = IndexCachesRoot::default();
    let mut emitted = String::new();
    let mut units = 0;
    for target in targets.split(',') {
        set_vfs(vfs.clone());
        let host_triple = host_of(target).to_string();
        let mut cfg = BTreeMap::new();
        for triple in [host_triple.clone(), target.to_string()] {
            cfg.insert(
                triple.clone(),
                rustc_data::cfg(PIN_VERSION, &triple).context("no vendored cfg")?,
            );
        }
        let mut gctx = GlobalContext::new_for_resolve(
            root.clone(),
            cargo_home.to_path_buf(),
            Shell::new(),
            Env::new(),
            false,
        )?;
        gctx.set_http(client.clone());
        gctx.share_index_caches(index_caches.clone());
        let output = api::resolve(
            &gctx,
            StowResolveInput {
                manifest_path: manifest_path.clone(),
                filter_platforms: vec![target.to_string()],
                host_triple: host_triple.clone(),
                features: Vec::new(),
                all_features: false,
                no_default_features: false,
                members_are_crates_io: false,
                rustc_verbose_version: rustc_data::verbose_version(PIN_VERSION, &host_triple)
                    .context("no vendored -vV")?
                    .to_string(),
                cfg,
            },
        )
        .await?;
        alloc_profile::mark("target_resolved");
        units += output.units.len();
        if emit.is_some() {
            emitted.push_str(target);
            emitted.push('\t');
            emitted.push_str(&serde_json::to_string(&(&output.units, &output.roots))?);
            emitted.push('\n');
        }
        println!("target={target} units={}", output.units.len());
        drop(output);
        alloc_profile::mark("target_output");
    }
    if let Some(path) = emit {
        std::fs::write(path, emitted)?;
    }
    Ok(units)
}

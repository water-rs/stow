//! Differential harness: stow-resolve vs real cargo.
//!
//! For every corpus entry × target the harness runs
//! `cargo build --unit-graph -Z unstable-options --target T` and
//! `cargo metadata --filter-platform T` on the same manifest — on the
//! *pinned stable* toolchain (the rustc data the worker consumes comes from
//! the vendored `rustc-data` table for that version; `RUSTC_BOOTSTRAP=1`
//! lets stable cargo accept `-Z`) — then runs [`stow_resolve::api::resolve`]
//! for units and [`stow_resolve::api::metadata`] for metadata parity,
//! and diffs:
//!   * `metadata` — the `cargo metadata` payload, per-node features/deps;
//!   * `units` — one node per `(pkg, platform, side, kind)` against the
//!     unit graph's lib/proc-macro/build-script units.
//!
//! `host_triple` is set per runner family: the same target on a different
//! family carries a different host side, so run each family on its own
//! runner (`--family linux|macos|windows`; the runner's native platform is
//! asserted to equal the family's host triple before diffing).
//!
//! HTTP for stow-resolve goes through the injected `HttpClient`: `live`
//! proxies crates.io/codeload directly, `record` additionally stores every
//! response, and `replay` answers from the stored fixture only — cargo
//! then runs `--offline` against the recorded `cargo-home`.
//!
//! Usage: `resolve-diff [--only NAME] [--target T] [--family F]
//!          [--live|--record DIR|--replay DIR]`

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use http::Request;
use std::rc::Rc;
use stow_resolve::api::{self, StowResolveInput, StowUnitKind};
use stow_resolve::rustc_data;
use stow_resolve::testing::{RecordedHttp, RecordingHttp, ReqwestHttp};
use stow_resolve::util::context::GlobalContext;
use stow_resolve::util::context::environment::Env;
use stow_resolve::util::fs::{OsVfs, set_vfs};
use stow_resolve::util::network::http_async::Client;
use stow_resolve::util::shell::Shell;

/// The pinned stable the vendored rustc-data table and the cargo pin
/// (`cargo 1.98.1 / 797e8a9b`) were cut from. The resolve under test reads
/// `rustc_data::{verbose_version,cfg}` for this version — never the
/// machine's toolchain — so CI and the worker see the same identity.
const PIN_VERSION: &str = "1.98.1";

/// `(family name, host triple, target triples)` — mirrors
/// `RunnerFamily::targets`/`host_triple` in `stow-types`; kept local so the
/// resolve crate never takes a stow-types dependency.
const FAMILIES: &[(&str, &str, &[&str])] = &[
    (
        "linux",
        "x86_64-unknown-linux-gnu",
        &[
            "aarch64-linux-android",
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "wasm32-unknown-unknown",
        ],
    ),
    (
        "macos",
        "aarch64-apple-darwin",
        &[
            "aarch64-apple-darwin",
            "aarch64-apple-ios",
            "aarch64-apple-ios-sim",
        ],
    ),
    (
        "windows",
        "x86_64-pc-windows-msvc",
        &["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"],
    ),
];

fn host_triple_of(target: &str) -> Option<&'static str> {
    FAMILIES
        .iter()
        .find(|(_, _, ts)| ts.contains(&target))
        .map(|(_, h, _)| *h)
}

/// Corpus entries: crates.io packages resolve from their published `.crate`
/// tarball; GitHub projects from a repo tarball; `Fixture` workspaces are
/// generated locally under `workdir/fixtures/<name>` (their crates.io/git
/// traffic still goes through the injected client, so `--record` captures
/// and `--replay` serves it).
///
/// `features` is the *complete* feature set the request lane would carry —
/// `features_json` semantics: `"default"` present means defaults on.
const CORPUS: &[CorpusSource] = &[
    CorpusSource::Registry {
        name: "serde_json",
        features: &["default"],
        live_only: false,
    },
    // A request without `default` in the set: the request lane's
    // `no_default_features` derivation lands here.
    CorpusSource::Registry {
        name: "serde_json",
        features: &["preserve_order"],
        live_only: false,
    },
    CorpusSource::Registry {
        name: "serde",
        features: &["default", "derive"],
        live_only: false,
    },
    CorpusSource::Registry {
        name: "tokio",
        features: &["default", "full"],
        live_only: false,
    },
    CorpusSource::Registry {
        name: "bevy",
        features: &["default"],
        // ~50M of `registry/cache` — recorded fixtures stay lean for CI;
        // the scheduled live job covers it.
        live_only: true,
    },
    CorpusSource::Registry {
        name: "ripgrep",
        // ripgrep defines no `default` feature — the complete set is empty.
        features: &[],
        live_only: true,
    },
    // A proc-macro *crate* root — the request lane's HostDep root keying.
    CorpusSource::Registry {
        name: "proc-macro2",
        features: &["default"],
        live_only: false,
    },
    CorpusSource::GitHub {
        repo: "zed-industries/zed",
        rev: "main",
        // A full zed checkout + dependency cache is GBs — live only.
        live_only: true,
    },
    // Synthetic workspaces covering the workspace boundary behaviors:
    // proc-macro member keying, glob members, in-tree `.cargo/config.toml`
    // (rustflags cfg + directory source replacement), a github.com git dep,
    // and a nested Cargo.lock.
    CorpusSource::Fixture {
        name: "proc-macro-member",
    },
    CorpusSource::Fixture {
        name: "glob-members",
    },
    CorpusSource::Fixture {
        name: "cargo-config",
    },
    CorpusSource::Fixture { name: "git-dep" },
    CorpusSource::Fixture {
        name: "nested-lock",
    },
];

enum CorpusSource {
    /// A crates.io package at its latest non-prerelease, non-yanked version.
    Registry {
        name: &'static str,
        features: &'static [&'static str],
        /// Excluded from `--replay` runs (too heavy to commit).
        live_only: bool,
    },
    /// A GitHub repo tarball (`codeload`), holding the workspace at `rev`.
    GitHub {
        repo: &'static str,
        rev: &'static str,
        live_only: bool,
    },
    /// A workspace generated under the workdir from templates below.
    Fixture { name: &'static str },
}

enum Mode {
    Live,
    Record(PathBuf),
    Replay(PathBuf),
}

struct Args {
    mode: Mode,
    only: Option<String>,
    target: Option<String>,
    family: Option<String>,
    emit_units: Option<PathBuf>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut mode = Mode::Live;
    let mut only = None;
    let mut target = None;
    let mut family = None;
    let mut emit_units = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--live" => mode = Mode::Live,
            "--record" => mode = Mode::Record(PathBuf::from(it.next().context("--record DIR")?)),
            "--replay" => mode = Mode::Replay(PathBuf::from(it.next().context("--replay DIR")?)),
            "--only" => only = Some(it.next().context("--only NAME")?),
            "--target" => target = Some(it.next().context("--target T")?),
            "--family" => family = Some(it.next().context("--family F")?),
            "--emit-units" => {
                emit_units = Some(PathBuf::from(it.next().context("--emit-units DIR")?));
            }
            other => bail!("unknown arg {other}"),
        }
    }
    Ok(Args {
        mode,
        only,
        target,
        family,
        emit_units,
    })
}

/// Runs the pinned-stable cargo in `dir`, returns stdout.
/// `RUSTC_BOOTSTRAP=1` is what lets a stable toolchain take `-Z
/// unstable-options` for the `--unit-graph` reference — the resolver under
/// test consumes the same version's vendored `-vV`/`--print cfg`.
fn cargo(dir: &Path, args: &[String], cargo_home: &Path, offline: bool) -> anyhow::Result<String> {
    let args: Vec<String> = args.to_vec();
    let mut cmd = Command::new("rustup");
    cmd.args(["run", PIN_VERSION, "cargo"]).args(&args);
    if offline {
        cmd.arg("--offline");
    }
    cmd.current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .env("RUSTC_BOOTSTRAP", "1")
        .env_remove("CARGO_TERM_COLOR");
    let out = cmd.output()?;
    if !out.status.success() {
        bail!(
            "cargo {args:?} failed in {}:\n{}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// Fetch one URL through `client` into bytes (recorded when recording).
#[allow(clippy::future_not_send)]
async fn fetch(client: &Client, url: &str) -> anyhow::Result<Vec<u8>> {
    let resp = client
        .request(Request::builder().uri(url).body(Vec::new())?)
        .await?;
    anyhow::ensure!(resp.status().is_success(), "{url}: {}", resp.status());
    Ok(resp.body().clone())
}

/// Latest published version of a crates.io package via the sparse index.
#[allow(clippy::future_not_send)]
async fn latest_version(client: &Client, name: &str) -> anyhow::Result<String> {
    let path = match name.len() {
        1 => format!("1/{name}"),
        2 => format!("2/{name}"),
        3 => format!("3/{}/{}", &name[..1], name),
        _ => format!("{}/{}/{}", &name[..2], &name[2..4], name),
    };
    let body = fetch(client, &format!("https://index.crates.io/{path}")).await?;
    let mut best: Option<semver::Version> = None;
    for line in body.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_slice(line)?;
        if v["yanked"].as_bool().unwrap_or(false) {
            continue;
        }
        let ver = semver::Version::parse(v["vers"].as_str().unwrap())?;
        if ver.pre.is_empty() && best.as_ref().is_none_or(|b| ver > *b) {
            best = Some(ver);
        }
    }
    best.map(|v| v.to_string())
        .ok_or_else(|| anyhow::anyhow!("no published version of {name}"))
}

/// Download + extract a tarball into `out_dir`, returning the package root
/// (the single top-level directory).
fn extract_tgz(bytes: &[u8], out_dir: &Path) -> anyhow::Result<PathBuf> {
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut ar = tar::Archive::new(gz);
    let mut top: Option<String> = None;
    for e in ar.entries()? {
        let mut e = e?;
        let p = e.path()?.to_path_buf();
        if let Some(first) = p.components().next() {
            let first = first.as_os_str().to_string_lossy().to_string();
            if first == "pax_global_header" {
                continue;
            }
            match &top {
                Some(t) if t == &first => {}
                Some(t) => bail!(
                    "tarball has multiple top-level dirs: `{t}` vs `{first}` (entry {})",
                    p.display()
                ),
                None => top = Some(first),
            }
        }
        let dest = out_dir.join(&p);
        if e.header().entry_type().is_dir() {
            fs::create_dir_all(&dest)?;
        } else {
            fs::create_dir_all(dest.parent().unwrap())?;
            let mut data = Vec::new();
            std::io::Read::read_to_end(&mut e, &mut data)?;
            fs::write(&dest, &data)?;
        }
    }
    Ok(out_dir.join(top.context("empty tarball")?))
}

fn write_fixture(dir: &Path, files: &[(&str, &str)]) -> anyhow::Result<()> {
    for (rel, content) in files {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, content)?;
    }
    Ok(())
}

/// Build the `cargo-config` fixture's vendored `itoa`: extract the fetched
/// `.crate` into `vendor/itoa` and write the `.cargo-checksum.json` a
/// directory source requires — `files` empty + `package` = the crate's
/// sha256, the format `cargo vendor` emits.
#[allow(clippy::future_not_send)]
async fn write_vendored_itoa(client: &Client, root: &Path) -> anyhow::Result<()> {
    let version = latest_version(client, "itoa").await?;
    let url = format!("https://static.crates.io/crates/itoa/itoa-{version}.crate");
    let bytes = fetch(client, &url).await?;
    let vendor = root.join("vendor");
    extract_tgz(&bytes, &vendor)?;
    let mut hasher = stow_resolve::util::sha256::Sha256::new();
    hasher.update(&bytes);
    let checksum = hasher.finish_hex();
    fs::write(
        vendor
            .join(format!("itoa-{version}"))
            .join(".cargo-checksum.json"),
        format!("{{\"files\":{{}},\"package\":\"{checksum}\"}}"),
    )?;
    Ok(())
}

/// A fixture workspace generated under `workdir/fixtures/<name>`; returns
/// its root manifest. The git-dep fixture's `git = "..."` dependency is
/// what exercises `CodeloadGitSource`.
#[allow(clippy::future_not_send)]
async fn prepare_fixture(client: &Client, workdir: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let root = workdir.join("fixtures").join(name);
    match name {
        // Proc-macro *member* of a workspace root: its lib's `proc-macro`
        // flag keys it `FeaturesFor::HostDep` on the runner-family host.
        "proc-macro-member" => write_fixture(
            &root,
            &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers = [\"macros\", \"app\"]\nresolver = \"2\"\n",
                ),
                (
                    "macros/Cargo.toml",
                    concat!(
                        "[package]\nname = \"fixture-macros\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                        "[lib]\nproc-macro = true\n",
                        "[dependencies]\nproc-macro2 = \"1\"\nquote = \"1\"\nsyn = \"2\"\n",
                    ),
                ),
                (
                    "macros/src/lib.rs",
                    "extern crate proc_macro;\nuse proc_macro::TokenStream;\n\
                     #[proc_macro_derive(FixtureMacro)]\n\
                     pub fn fixture_macro(input: TokenStream) -> TokenStream { input }\n",
                ),
                (
                    "app/Cargo.toml",
                    concat!(
                        "[package]\nname = \"fixture-app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                        "[dependencies]\nfixture-macros = { path = \"../macros\" }\n",
                    ),
                ),
                ("app/src/main.rs", "fn main() {}\n"),
            ],
        )?,
        // `members = ["crates/*"]` — the glob must expand through the VFS,
        // not the real filesystem.
        "glob-members" => write_fixture(
            &root,
            &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
                ),
                (
                    "crates/alpha/Cargo.toml",
                    concat!(
                        "[package]\nname = \"fixture-alpha\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                        "[dependencies]\nserde = \"1\"\n",
                    ),
                ),
                ("crates/alpha/src/lib.rs", "pub fn alpha() {}\n"),
                (
                    "crates/beta/Cargo.toml",
                    concat!(
                        "[package]\nname = \"fixture-beta\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                        "[dependencies]\nfixture-alpha = { path = \"../alpha\" }\n",
                    ),
                ),
                ("crates/beta/src/lib.rs", "pub fn beta() {}\n"),
            ],
        )?,
        // In-tree `.cargo/config.toml`: `build.rustflags` injects a `--cfg`
        // that gates a `target.'cfg(...)'.dependencies` edge, and
        // `[source.crates-io]` is replaced by a `directory` source — both
        // must reach the resolve through the in-VFS config walk.
        "cargo-config" => {
            write_fixture(
                &root,
                &[
                    (
                        "Cargo.toml",
                        concat!(
                            "[package]\nname = \"fixture-cfg\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
                            "[target.'cfg(stow_fixture_cfg)'.dependencies]\nitoa = \"1\"\n",
                        ),
                    ),
                    ("src/lib.rs", "pub fn cfg_fixture() {}\n"),
                    (
                        ".cargo/config.toml",
                        concat!(
                            "[build]\nrustflags = [\"--cfg\", \"stow_fixture_cfg\"]\n",
                            "[source.crates-io]\nreplace-with = \"vendored-sources\"\n",
                            "[source.vendored-sources]\ndirectory = \"vendor\"\n",
                        ),
                    ),
                ],
            )?;
            write_vendored_itoa(client, &root).await?;
        }
        // A github.com git dependency: resolved through `CodeloadGitSource`
        // (ls-remote + tarball) so its crates.io deps become nodes.
        "git-dep" => write_fixture(
            &root,
            &[
                (
                    "Cargo.toml",
                    concat!(
                        "[package]\nname = \"fixture-git\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
                        "[dependencies]\nserde_json = { git = \"https://github.com/serde-rs/json\", branch = \"master\" }\n",
                    ),
                ),
                ("src/lib.rs", "pub fn git_fixture() {}\n"),
            ],
        )?,
        // A lockfile under a member directory must be ignored — stow drops
        // every `Cargo.lock` inside a selected workspace, cargo only reads
        // the workspace root's.
        "nested-lock" => write_fixture(
            &root,
            &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers = [\"inner\"]\nresolver = \"2\"\n",
                ),
                (
                    "inner/Cargo.toml",
                    concat!(
                        "[package]\nname = \"fixture-inner\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                        "[dependencies]\nitoa = \"1\"\n",
                    ),
                ),
                ("inner/src/lib.rs", "pub fn inner() {}\n"),
                // A stale lockfile pinning an ancient itoa — resolution must
                // ignore it (the latest semver-compatible wins).
                (
                    "inner/Cargo.lock",
                    concat!(
                        "version = 3\n\n",
                        "[[package]]\nname = \"itoa\"\nversion = \"0.1.0\"\n",
                    ),
                ),
            ],
        )?,
        other => bail!("unknown fixture {other}"),
    }
    Ok(root.join("Cargo.toml"))
}

/// Prepare the corpus manifest dirs: on `live`/`record` downloads happen
/// (and, in `record`, land in the fixture); on `replay` the recorded
/// responses serve every fetch.
#[allow(clippy::future_not_send)]
async fn prepare_corpus(
    client: &Client,
    workdir: &Path,
    only: Option<&str>,
    skip_live_only: bool,
) -> anyhow::Result<Vec<(String, PathBuf, Vec<String>, bool)>> {
    let mut out = Vec::new();
    for entry in CORPUS {
        let name = match entry {
            CorpusSource::Registry { name, .. } => name.to_string(),
            CorpusSource::GitHub { repo, .. } => repo.to_string(),
            CorpusSource::Fixture { name } => format!("fixture:{name}"),
        };
        let live_only = match entry {
            CorpusSource::Registry { live_only, .. } | CorpusSource::GitHub { live_only, .. } => {
                *live_only
            }
            CorpusSource::Fixture { .. } => false,
        };
        if skip_live_only && live_only {
            continue;
        }
        if let Some(only) = only
            && !name.contains(only)
        {
            continue;
        }
        match entry {
            CorpusSource::Registry { name, features, .. } => {
                let ver = latest_version(client, name).await?;
                let url = format!("https://static.crates.io/crates/{name}/{name}-{ver}.crate");
                let bytes = fetch(client, &url).await?;
                let dir = workdir.join(format!("{name}-{ver}"));
                let root = extract_tgz(&bytes, &dir)?;
                out.push((
                    format!("{name}@{ver}"),
                    root.join("Cargo.toml"),
                    features.iter().map(ToString::to_string).collect(),
                    // A `.crate` tarball's member is the published crate.
                    true,
                ));
            }
            CorpusSource::GitHub { repo, rev, .. } => {
                // Same fetch the projects lane runs: codeload tarball
                // plus submodule trees at the pinned gitlink commits.
                let tree = stow_resolve::github_tree::fetch_github_tree(client, repo, rev).await?;
                for note in &tree.notes {
                    eprintln!("{repo}: {note}");
                }
                let safe = repo.replace('/', "-");
                let dir = workdir.join(&safe);
                for (rel, data) in &tree.files {
                    let path = dir.join(rel);
                    fs::create_dir_all(path.parent().unwrap())?;
                    fs::write(path, data)?;
                }
                // The manifest the lane resolves: same `select_manifest`
                // the worker side runs.
                let manifest = stow_resolve::github_tree::select_manifest(&tree.files)
                    .with_context(|| format!("{repo}: tarball contains no Cargo.toml"))?;
                out.push((
                    repo.to_string(),
                    dir.join(manifest),
                    Vec::new(),
                    // A project checkout's members are sources, not crates.
                    false,
                ));
            }
            CorpusSource::Fixture { name } => {
                let manifest = prepare_fixture(client, workdir, name).await?;
                out.push((format!("fixture:{name}"), manifest, Vec::new(), false));
            }
        }
    }
    Ok(out)
}

/// A cargo unit-graph unit reduced to the fields stow compares.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RefUnit {
    name: String,
    version: String,
    platform: String,
    kind: &'static str,
    features: Vec<String>,
    deps: BTreeSet<(String, String, String, &'static str)>,
}

fn ref_kind(target_kind: &[String], mode: &str) -> Option<&'static str> {
    if target_kind.iter().any(|k| k == "custom-build") {
        return Some(if mode == "run-custom-build" {
            "run-build-script"
        } else {
            "build-script"
        });
    }
    if mode == "build"
        && target_kind.iter().any(|k| {
            k == "lib" || k == "proc-macro" || k == "cdylib" || k == "dylib" || k == "rlib"
        })
    {
        return Some("lib");
    }
    None
}

/// Parse `cargo build --unit-graph` JSON into `RefUnit`s.
fn parse_unit_graph(json: &serde_json::Value, host_triple: &str) -> anyhow::Result<Vec<RefUnit>> {
    let units = json["units"].as_array().context("unit-graph units")?;
    // First pass: key per unit index.
    let mut keys = Vec::new();
    let mut keep = Vec::new();
    for u in units {
        let kind = u["target"]["kind"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let mode = u["mode"].as_str().unwrap_or("");
        let pk = ref_kind(&kind, mode);
        let pkg = u["pkg_id"].as_str().unwrap();
        let platform = match &u["platform"] {
            serde_json::Value::Null => host_triple.to_string(),
            serde_json::Value::String(s) => s.clone(),
            _ => bail!("unexpected platform {}", u["platform"]),
        };
        let (name, version) = split_pkg_spec(pkg);
        keys.push((name, version, platform, pk.unwrap_or("other")));
        keep.push(pk.is_some());
    }
    let mut out = Vec::new();
    for (i, u) in units.iter().enumerate() {
        if !keep[i] {
            continue;
        }
        let (name, version, platform, kind) = keys[i].clone();
        let mut deps = BTreeSet::new();
        for d in u["dependencies"].as_array().unwrap() {
            let idx = usize::try_from(d["index"].as_u64().unwrap()).unwrap();
            if keep[idx] {
                deps.insert(keys[idx].clone());
            }
        }
        out.push(RefUnit {
            name,
            version,
            platform,
            kind,
            features: u["features"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap().to_string())
                .collect(),
            deps,
        });
    }
    Ok(out)
}

/// `registry+URL#name@version` / `path+file://...#name@version` → (name, version).
fn split_pkg_spec(spec: &str) -> (String, String) {
    let frag = spec.rsplit('#').next().unwrap_or(spec);
    if let Some((n, v)) = frag.rsplit_once('@') {
        return (n.to_string(), v.to_string());
    }
    // `path+file:///x#version` / `git+...?rev=sha#version`: the name is
    // omitted when the path basename carries it.
    let path = spec.split('#').next().unwrap_or(spec);
    let path = path.split('?').next().unwrap_or(path);
    let n = path.rsplit('/').next().unwrap_or(path);
    (n.to_string(), frag.to_string())
}

const fn stow_kind(kind: StowUnitKind) -> &'static str {
    match kind {
        StowUnitKind::Lib => "lib",
        StowUnitKind::BuildScript => "build-script",
        StowUnitKind::RunBuildScript => "run-build-script",
    }
}

fn diff(label: &str, stow_units: &[RefUnit], ref_units: &[RefUnit], errors: &mut Vec<String>) {
    // Multiset key counts first — a duplicate stow unit is invisible to the
    // set compare below.
    let count = |units: &[RefUnit]| -> BTreeMap<(String, String, String, &'static str), usize> {
        let mut m = BTreeMap::new();
        for u in units {
            *m.entry((
                u.name.clone(),
                u.version.clone(),
                u.platform.clone(),
                u.kind,
            ))
            .or_default() += 1;
        }
        m
    };
    let sc = count(stow_units);
    let rc = count(ref_units);
    for (k, n) in &sc {
        let r = rc.get(k).copied().unwrap_or(0);
        if *n != r {
            errors.push(format!(
                "{label}: unit {}-{} {} {} count {n} stow vs {r} cargo",
                k.0, k.1, k.2, k.3
            ));
        }
    }
    let stow_set: BTreeSet<_> = stow_units.iter().collect();
    let ref_set: BTreeSet<_> = ref_units.iter().collect();
    for missing in ref_set.difference(&stow_set) {
        // Try to find the same (name,version,platform,kind) to report what differs.
        let same_key = stow_set.iter().find(|u| {
            u.name == missing.name
                && u.version == missing.version
                && u.platform == missing.platform
                && u.kind == missing.kind
        });
        match same_key {
            Some(u) => errors.push(format!(
                "{label}: unit {}-{} {} {} feature/dep mismatch\n  stow.features={:?}\n  cargo.features={:?}\n  stow-only-deps={:?}\n  cargo-only-deps={:?}",
                missing.name,
                missing.version,
                missing.platform,
                missing.kind,
                u.features,
                missing.features,
                u.deps.difference(&missing.deps).collect::<Vec<_>>(),
                missing.deps.difference(&u.deps).collect::<Vec<_>>(),
            )),
            None => errors.push(format!(
                "{label}: missing unit {}-{} {} {}",
                missing.name, missing.version, missing.platform, missing.kind
            )),
        }
    }
    for extra in stow_set.difference(&ref_set) {
        errors.push(format!(
            "{label}: extra unit {}-{} {} {}",
            extra.name, extra.version, extra.platform, extra.kind
        ));
    }
}

/// The runner this harness executes on, via the vendored `verbose` of the
/// pinned stable for *this* machine — `rustc -vV`'s `host:` line.
fn local_host_triple() -> anyhow::Result<String> {
    let out = Command::new("rustup")
        .args(["run", PIN_VERSION, "rustc", "-vV"])
        .output()?;
    anyhow::ensure!(out.status.success(), "rustc -vV failed");
    let vv = String::from_utf8(out.stdout)?;
    vv.lines()
        .find_map(|l| l.strip_prefix("host: "))
        .map(ToString::to_string)
        .context("no host line in rustc -vV")
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    run().await
}

#[allow(clippy::future_not_send)]
#[allow(clippy::too_many_lines)]
async fn run() -> anyhow::Result<()> {
    let args = parse_args()?;
    let workdir = std::env::home_dir()
        .expect("home dir")
        .join(".cache/stow/resolve-diff");
    fs::create_dir_all(&workdir)?;

    // Targets: all nine `CI_TARGET_TRIPLES`, or one family, or one triple.
    // Every target's host side is keyed at its runner-family host triple —
    // assert the machine actually *is* that host so the cargo reference's
    // host units land on the same triple.
    let targets: Vec<String> = if let Some(t) = &args.target {
        vec![t.clone()]
    } else if let Some(fam) = &args.family {
        FAMILIES
            .iter()
            .find(|(n, _, _)| n == fam)
            .with_context(|| format!("unknown family {fam}"))
            .map(|(_, _, ts)| ts.iter().map(ToString::to_string).collect())?
    } else {
        FAMILIES
            .iter()
            .flat_map(|(_, _, ts)| ts.iter().map(ToString::to_string))
            .collect()
    };
    let local_host = local_host_triple()?;
    for t in &targets {
        let host = host_triple_of(t).with_context(|| format!("{t} is not a CI target"))?;
        anyhow::ensure!(
            host == local_host,
            "target {t}'s runner family hosts on {host} but this machine is {local_host}; \
             run with --family {} on a matching runner",
            FAMILIES
                .iter()
                .find(|(_, h, _)| *h == host)
                .map_or("<none>", |(n, _, _)| *n)
        );
    }

    let fixture_dir = match &args.mode {
        Mode::Record(d) | Mode::Replay(d) => {
            fs::create_dir_all(d)?;
            // Vendored cargo code asserts absolute paths.
            Some(d.canonicalize()?)
        }
        Mode::Live => None,
    };
    let cargo_home = fixture_dir
        .as_ref()
        .map_or_else(|| workdir.join("cargo-home"), |d| d.join("cargo-home"));
    fs::create_dir_all(&cargo_home)?;

    // The HTTP layer for corpus prep *and* the resolver.
    let reqwest_client = ReqwestHttp::new();
    let stow_client = match &args.mode {
        Mode::Live => Client::new(Rc::new(reqwest_client)),
        Mode::Record(d) => Client::new(Rc::new(RecordingHttp::new(reqwest_client, d.join("http")))),
        Mode::Replay(d) => Client::new(Rc::new(RecordedHttp::new(d.join("http")))),
    };

    let offline = matches!(args.mode, Mode::Replay(_));
    set_vfs(Rc::new(OsVfs));

    let corpus = prepare_corpus(
        &stow_client,
        &workdir.join("corpus"),
        args.only.as_deref(),
        // `--record` produces replay fixtures, so it skips what replay
        // cannot carry; `--live` runs everything.
        !matches!(args.mode, Mode::Live),
    )
    .await?;
    let mut errors: Vec<String> = Vec::new();

    for (label, manifest, features, members_are_crates_io) in &corpus {
        if let Some(only) = &args.only
            && !label.contains(only.as_str())
        {
            continue;
        }
        let manifest_dir = manifest.parent().unwrap().to_path_buf();
        // `features` is the complete set: no `"default"` in it means
        // `--no-default-features` on both sides.
        let no_default_features = !features.iter().any(|f| f == "default");
        let mut feature_args: Vec<String> = Vec::new();
        if !features.is_empty() {
            feature_args.extend(["--features".to_string(), features.join(",")]);
        }
        if no_default_features {
            feature_args.push("--no-default-features".to_string());
        }
        for target in &targets {
            let host_triple = host_triple_of(target).unwrap();
            let tag = format!("{label} {target}");
            println!("=== {tag}");

            // 1. cargo references on the pinned stable.
            let metadata_ref = cargo(
                &manifest_dir,
                &[
                    vec![
                        "metadata".to_string(),
                        "--format-version".to_string(),
                        "1".to_string(),
                        "--filter-platform".to_string(),
                        target.clone(),
                    ],
                    feature_args.clone(),
                ]
                .concat(),
                &cargo_home,
                offline,
            )?;
            let unit_graph_ref = cargo(
                &manifest_dir,
                &[
                    vec![
                        "build".to_string(),
                        "--unit-graph".to_string(),
                        "-Z".to_string(),
                        "unstable-options".to_string(),
                        "--target".to_string(),
                        target.clone(),
                    ],
                    feature_args.clone(),
                ]
                .concat(),
                &cargo_home,
                offline,
            )?;
            let ref_meta: serde_json::Value = serde_json::from_str(&metadata_ref)?;
            let ref_units = parse_unit_graph(&serde_json::from_str(&unit_graph_ref)?, host_triple)?;

            // 2. stow-resolve — rustc identity and cfg data come from the
            // vendored table for the pinned stable, exactly as the worker
            // consumes them.
            let cfg = {
                let mut m = BTreeMap::new();
                for t in targets
                    .iter()
                    .map(String::as_str)
                    .chain(FAMILIES.iter().map(|(_, h, _)| *h))
                {
                    if m.contains_key(t) {
                        continue;
                    }
                    m.insert(
                        t.to_string(),
                        rustc_data::cfg(PIN_VERSION, t)
                            .with_context(|| format!("no vendored cfg for {PIN_VERSION} {t}"))?,
                    );
                }
                m
            };
            let input = StowResolveInput {
                manifest_path: manifest.clone(),
                filter_platforms: vec![target.clone()],
                host_triple: host_triple.to_string(),
                features: features.clone(),
                all_features: false,
                no_default_features,
                rustc_verbose_version: rustc_data::verbose_version(PIN_VERSION, host_triple)
                    .with_context(|| format!("no vendored -vV for {PIN_VERSION} {host_triple}"))?
                    .to_string(),
                cfg: cfg.clone(),
                members_are_crates_io: *members_are_crates_io,
            };
            let mut gctx = GlobalContext::new_for_resolve(
                manifest_dir.clone(),
                cargo_home.clone(),
                Shell::new(),
                Env::new(),
                offline,
            )?;
            gctx.set_http(stow_client.clone());
            let started = std::time::Instant::now();
            let stow = api::resolve(&gctx, input.clone()).await?;
            println!("    stow-resolve: {:?} elapsed", started.elapsed());
            if let Some(dir) = &args.emit_units {
                emit_units(dir, label, target, &stow.units)?;
            }

            let mut metadata_gctx = GlobalContext::new_for_resolve(
                manifest_dir.clone(),
                cargo_home.clone(),
                Shell::new(),
                Env::new(),
                offline,
            )?;
            metadata_gctx.set_http(stow_client.clone());
            let started = std::time::Instant::now();
            let metadata = api::metadata(&metadata_gctx, input).await?;
            println!("    stow metadata: {:?} elapsed", started.elapsed());
            let stow_meta = serde_json::to_value(&metadata)?;

            // 3. metadata parity (path-normalized).
            check_metadata(&tag, &ref_meta, &stow_meta, &manifest_dir, &mut errors);

            // `has_binary` parity: cargo's target autodiscovery reports
            // declared `[[bin]]` and `src/main.rs`/`src/bin/*` alike, so a
            // member binary under `crates/` counts just as a root one.
            let ref_has_binary = ref_meta["packages"].as_array().is_some_and(|packages| {
                packages.iter().any(|pkg| {
                    let in_members = ref_meta["workspace_members"]
                        .as_array()
                        .is_some_and(|m| m.iter().any(|id| id == &pkg["id"]));
                    in_members
                        && pkg["targets"].as_array().is_some_and(|targets| {
                            targets.iter().any(|t| {
                                t["kind"]
                                    .as_array()
                                    .is_some_and(|k| k.iter().any(|k| k == "bin"))
                            })
                        })
                })
            });
            if ref_has_binary != stow.has_binary {
                errors.push(format!(
                    "{tag}: has_binary differs: cargo={ref_has_binary} stow={}",
                    stow.has_binary
                ));
            }

            // 4. unit parity.
            let stow_units: Vec<RefUnit> = stow
                .units
                .iter()
                .map(|u| RefUnit {
                    name: u.name.clone(),
                    version: u.version.clone(),
                    platform: u.key.platform.clone(),
                    kind: stow_kind(u.unit_kind),
                    features: u.features.clone(),
                    deps: u
                        .deps
                        .iter()
                        .map(|d| {
                            let (n, v) = split_pkg_spec(&d.key.pkg.to_string());
                            (n, v, d.key.platform.clone(), stow_kind(d.key.kind))
                        })
                        .collect(),
                })
                .collect();
            diff(&tag, &stow_units, &ref_units, &mut errors);
            println!(
                "    {} ref units, {} stow units",
                ref_units.len(),
                stow_units.len()
            );
        }
    }

    if let Some(dir) = &fixture_dir {
        // `registry/src` and `git/checkouts` re-materialize from
        // `registry/cache` and `git/db` under `--offline`; drop them so the
        // committed fixture stays small.
        let _ = fs::remove_dir_all(dir.join("cargo-home/registry/src"));
        let _ = fs::remove_dir_all(dir.join("cargo-home/git/checkouts"));
    }

    if errors.is_empty() {
        println!("OK — all corpus entries match cargo");
        Ok(())
    } else {
        for e in &errors {
            println!("{e}");
        }
        bail!("{} differences", errors.len())
    }
}

/// Compare stow's `metadata` doc against `cargo metadata`'s, normalizing
/// paths that legitimately differ (cargo embeds absolute workspace/registry
/// paths; stow's VFS paths are identical only under `OsVfs`, which the harness
/// uses — so compare them verbatim and let real diffs surface).
fn check_metadata(
    tag: &str,
    cargo_meta: &serde_json::Value,
    stow_meta: &serde_json::Value,
    _manifest_dir: &Path,
    errors: &mut Vec<String>,
) {
    // Compare resolve.nodes by id: features + dep_kinds.
    let node_map = |meta: &serde_json::Value| -> BTreeMap<String, serde_json::Value> {
        meta["resolve"]["nodes"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|n| (n["id"].as_str().unwrap_or_default().to_string(), n.clone()))
                    .collect()
            })
            .unwrap_or_default()
    };
    let c = node_map(cargo_meta);
    let s = node_map(stow_meta);
    for (id, cn) in &c {
        match s.get(id) {
            None => errors.push(format!("{tag}: metadata node missing in stow: {id}")),
            Some(sn) => {
                if cn["features"] != sn["features"] {
                    errors.push(format!(
                        "{tag}: metadata node {id} features differ: cargo={:?} stow={:?}",
                        cn["features"], sn["features"]
                    ));
                }
                if cn["deps"] != sn["deps"] {
                    errors.push(format!("{tag}: metadata node {id} deps differ"));
                }
            }
        }
    }
    for id in s.keys() {
        if !c.contains_key(id) {
            errors.push(format!("{tag}: extra metadata node in stow: {id}"));
        }
    }
    // Package set parity by name+version+source.
    let pkgs = |meta: &serde_json::Value| -> BTreeSet<String> {
        meta["packages"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|p| p["id"].as_str().unwrap_or_default().to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    let cp = pkgs(cargo_meta);
    let sp = pkgs(stow_meta);
    for id in cp.difference(&sp) {
        errors.push(format!("{tag}: metadata package missing in stow: {id}"));
    }
    for id in sp.difference(&cp) {
        errors.push(format!("{tag}: extra metadata package in stow: {id}"));
    }
}

/// Write a cell's resolved units as verbatim `StowUnit` JSON — the
/// worker's `task_graph` bench replays the same type production runs on.
fn emit_units(
    dir: &Path,
    label: &str,
    target: &str,
    units: &[stow_resolve::api::StowUnit],
) -> anyhow::Result<()> {
    fs::create_dir_all(dir)?;
    let file = dir.join(format!(
        "{}--{}.units.json",
        label.replace(['/', ':', '@'], "-"),
        target
    ));
    fs::write(&file, serde_json::to_vec(units)?)?;
    println!("    units -> {}", file.display());
    Ok(())
}

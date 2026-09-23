//! Differential harness: stow-resolve vs real cargo.
//!
//! For every corpus entry × target the harness runs
//! `cargo +nightly build --unit-graph -Z unstable-options --target T` and
//! `cargo metadata --filter-platform T` on the same manifest, runs
//! [`stow_resolve::api::resolve`] over it, and diffs:
//!   * `metadata` — the `cargo metadata` payload, path-normalized;
//!   * `units` — one node per `(pkg, platform, side, kind)` against the
//!     unit graph's lib/proc-macro/build-script units.
//!
//! HTTP for stow-resolve goes through the injected `HttpClient`: `live`
//! proxies crates.io directly, `record` additionally stores every response,
//! and `replay` answers from the stored fixture only.
//!
//! Usage: `resolve-diff [--only NAME] [--target T] [--live|--record DIR|--replay DIR]`

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use http::{Request, Response};
use std::pin::Pin;
use std::rc::Rc;
use stow_resolve::api::{self, StowResolveInput, StowUnitKind};
use stow_resolve::testing::{RecordedHttp, RecordingHttp};
use stow_resolve::util::context::GlobalContext;
use stow_resolve::util::context::environment::Env;
use stow_resolve::util::fs::{OsVfs, set_vfs};
use stow_resolve::util::network::http_async::{Client, HttpClient};
use stow_resolve::util::shell::Shell;

const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "wasm32-unknown-unknown",
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
];

/// Corpus entries: crates.io packages resolve from their published `.crate`
/// tarball; GitHub projects from a repo tarball, which carries the real
/// workspace manifests.
const CORPUS: &[CorpusSource] = &[
    CorpusSource::Registry {
        name: "serde_json",
        extra_features: &[],
    },
    CorpusSource::Registry {
        name: "serde",
        extra_features: &["derive"],
    },
    CorpusSource::Registry {
        name: "tokio",
        extra_features: &["full"],
    },
    CorpusSource::Registry {
        name: "bevy",
        extra_features: &[],
    },
    CorpusSource::Registry {
        name: "ripgrep",
        extra_features: &[],
    },
    CorpusSource::GitHub {
        repo: "zed-industries/zed",
        rev: "main",
    },
];

enum CorpusSource {
    /// A crates.io package at its latest non-prerelease, non-yanked version.
    Registry {
        name: &'static str,
        extra_features: &'static [&'static str],
    },
    /// A GitHub repo tarball (`codeload`), holding the workspace at `rev`.
    GitHub {
        repo: &'static str,
        rev: &'static str,
    },
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
}

fn parse_args() -> anyhow::Result<Args> {
    let mut mode = Mode::Live;
    let mut only = None;
    let mut target = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--live" => mode = Mode::Live,
            "--record" => mode = Mode::Record(PathBuf::from(it.next().context("--record DIR")?)),
            "--replay" => mode = Mode::Replay(PathBuf::from(it.next().context("--replay DIR")?)),
            "--only" => only = Some(it.next().context("--only NAME")?),
            "--target" => target = Some(it.next().context("--target T")?),
            other => bail!("unknown arg {other}"),
        }
    }
    Ok(Args { mode, only, target })
}

/// The live client — a thin reqwest adapter.
struct ReqwestHttp {
    inner: reqwest::Client,
}

impl HttpClient for ReqwestHttp {
    fn request<'a>(
        &'a self,
        request: Request<Vec<u8>>,
    ) -> Pin<Box<dyn std::future::Future<Output = CargoResult<Response<Vec<u8>>>> + 'a>> {
        let (parts, body) = request.into_parts();
        let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).unwrap();
        let mut builder = self.inner.request(method, parts.uri.to_string());
        for (k, v) in &parts.headers {
            builder = builder.header(k.as_str(), v.to_str().unwrap_or(""));
        }
        Box::pin(async move {
            let resp = builder.body(body).send().await?;
            let status = resp.status();
            let mut out = Response::builder().status(status.as_u16());
            for (k, v) in resp.headers() {
                out = out.header(k.as_str(), v.to_str().unwrap_or(""));
            }
            let bytes = resp.bytes().await?;
            Ok(out.body(bytes.to_vec())?)
        })
    }
}

type CargoResult<T> = anyhow::Result<T>;

/// rustc identity + cfg data for the reference toolchain (nightly).
fn rustc_inputs() -> anyhow::Result<(String, String)> {
    let vv = Command::new("rustup")
        .args(["run", "nightly", "rustc", "-vV"])
        .output()?;
    anyhow::ensure!(vv.status.success(), "rustc -vV failed");
    let vv = String::from_utf8(vv.stdout)?;
    let host = vv
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .context("no host line in rustc -vV")?
        .to_string();
    Ok((vv, host))
}

fn rustc_cfg(target: &str) -> anyhow::Result<Vec<String>> {
    let out = Command::new("rustup")
        .args([
            "run", "nightly", "rustc", "--print", "cfg", "--target", target,
        ])
        .output()?;
    anyhow::ensure!(out.status.success(), "rustc --print cfg {target} failed");
    Ok(String::from_utf8(out.stdout)?
        .lines()
        .map(ToString::to_string)
        .collect())
}

/// Runs a cargo command in `dir`, returns stdout.
fn cargo(dir: &Path, args: &[String], cargo_home: &Path, offline: bool) -> anyhow::Result<String> {
    let args: Vec<String> = args.to_vec();
    let mut cmd = Command::new("rustup");
    cmd.args(["run", "nightly", "cargo"]).args(&args);
    if offline {
        cmd.arg("--offline");
    }
    cmd.current_dir(dir)
        .env("CARGO_HOME", cargo_home)
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

/// Prepare the corpus manifest dir: on `live`/`record` it is downloaded (and,
/// in `record`, the fetch lands in the fixture); on `replay` the recorded
/// responses are reused through the fixture client.
#[allow(clippy::future_not_send)]
async fn prepare_corpus(
    client: &Client,
    workdir: &Path,
    only: Option<&str>,
) -> anyhow::Result<Vec<(String, PathBuf, Vec<String>)>> {
    let mut out = Vec::new();
    for entry in CORPUS {
        let name = match entry {
            CorpusSource::Registry { name, .. } => name.to_string(),
            CorpusSource::GitHub { repo, .. } => repo.to_string(),
        };
        if let Some(only) = only
            && !name.contains(only)
        {
            continue;
        }
        match entry {
            CorpusSource::Registry {
                name,
                extra_features,
            } => {
                let ver = latest_version(client, name).await?;
                let url = format!("https://static.crates.io/crates/{name}/{name}-{ver}.crate");
                let bytes = fetch(client, &url).await?;
                let dir = workdir.join(format!("{name}-{ver}"));
                let root = extract_tgz(&bytes, &dir)?;
                out.push((
                    format!("{name}@{ver}"),
                    root.join("Cargo.toml"),
                    extra_features.iter().map(ToString::to_string).collect(),
                ));
            }
            CorpusSource::GitHub { repo, rev } => {
                let url = format!("https://codeload.github.com/{repo}/tar.gz/{rev}");
                let bytes = fetch(client, &url).await?;
                let safe = repo.replace('/', "-");
                let dir = workdir.join(&safe);
                let root = extract_tgz(&bytes, &dir)?;
                out.push((repo.to_string(), root.join("Cargo.toml"), Vec::new()));
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
    let (vv, host_triple) = rustc_inputs()?;
    let targets: Vec<String> = args.target.map_or_else(
        || TARGETS.iter().map(ToString::to_string).collect(),
        |t| vec![t],
    );

    let fixture_dir = match &args.mode {
        Mode::Record(d) | Mode::Replay(d) => Some(d.clone()),
        Mode::Live => None,
    };
    let cargo_home =
        fixture_dir.map_or_else(|| workdir.join("cargo-home"), |d| d.join("cargo-home"));
    fs::create_dir_all(&cargo_home)?;

    // The HTTP layer for corpus prep *and* the resolver.
    let reqwest_client = ReqwestHttp {
        inner: reqwest::Client::new(),
    };
    let stow_client = match &args.mode {
        Mode::Live => Client::new(Rc::new(reqwest_client)),
        Mode::Record(d) => Client::new(Rc::new(RecordingHttp::new(reqwest_client, d.join("http")))),
        Mode::Replay(d) => Client::new(Rc::new(RecordedHttp::new(d.join("http")))),
    };

    let offline = matches!(args.mode, Mode::Replay(_));
    set_vfs(Rc::new(OsVfs));

    let corpus =
        prepare_corpus(&stow_client, &workdir.join("corpus"), args.only.as_deref()).await?;
    let mut errors: Vec<String> = Vec::new();

    for (label, manifest, features) in &corpus {
        if let Some(only) = &args.only
            && !label.contains(only.as_str())
        {
            continue;
        }
        let manifest_dir = manifest.parent().unwrap().to_path_buf();
        for target in &targets {
            let tag = format!("{label} {target}");
            println!("=== {tag}");

            // 1. cargo references.
            let mut feature_args: Vec<String> = Vec::new();
            for f in features {
                feature_args.extend(["--features".to_string(), f.clone()]);
            }
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
                    feature_args,
                ]
                .concat(),
                &cargo_home,
                offline,
            )?;
            let ref_meta: serde_json::Value = serde_json::from_str(&metadata_ref)?;
            let ref_units =
                parse_unit_graph(&serde_json::from_str(&unit_graph_ref)?, &host_triple)?;

            // 2. stow-resolve.
            let cfg = {
                let mut m = BTreeMap::new();
                for t in targets.iter().chain(std::iter::once(&host_triple)) {
                    m.insert(t.clone(), rustc_cfg(t)?);
                }
                m
            };
            let gctx = GlobalContext::new_for_resolve(
                manifest_dir.clone(),
                cargo_home.clone(),
                Shell::new(),
                Env::new(),
                offline,
            )?;
            let stow = {
                let mut gctx = gctx;
                gctx.set_http(stow_client.clone());
                let started = std::time::Instant::now();
                let output = api::resolve(
                    &gctx,
                    StowResolveInput {
                        manifest_path: manifest.clone(),
                        filter_platforms: vec![target.clone()],
                        host_triple: host_triple.clone(),
                        features: features.clone(),
                        all_features: false,
                        no_default_features: false,
                        rustc_verbose_version: vv.clone(),
                        cfg: cfg.clone(),
                    },
                )
                .await?;
                println!("    stow-resolve: {:?} elapsed", started.elapsed());
                output
            };
            let stow_meta = serde_json::to_value(&stow.metadata)?;

            // 3. metadata parity (path-normalized).
            check_metadata(&tag, &ref_meta, &stow_meta, &manifest_dir, &mut errors);

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

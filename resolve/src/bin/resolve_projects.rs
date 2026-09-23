//! `resolve-projects`: run the projects lane's resolve natively over a
//! `projects.toml` — the same `fetch_github_tree` + `select_manifest` +
//! `api::resolve` chain the worker's `resolve_github_project` runs, at the
//! vendored rustc identity the lane's tasks carry.
//!
//! Each repo is fetched (codeload tarball plus submodule trees at the
//! pinned gitlink commits), written to a workdir, and resolved once per
//! `--target`. A repo counts as resolved only when every requested target
//! resolves — the lane's verdict — and a fetch or resolve failure prints
//! as that repo's skip reason. The tree directory is removed after the
//! repo's resolves, so a full-list run stays disk-bounded.
//!
//! Usage: `resolve-projects [--file projects.toml] [--target T]...
//!          [--only SUBSTR]... [--from N] [--limit N]`
//!
//! Defaults: the file at `preheat/projects.toml`, the four linux-family
//! CI targets (host side resolves on `x86_64-unknown-linux-gnu`, matching
//! this machine's vendored data).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Instant;

use anyhow::{Context, bail};
use stow_resolve::api::{self, StowResolveInput};
use stow_resolve::github_tree::{fetch_github_tree, select_manifest};
use stow_resolve::rustc_data;
use stow_resolve::testing::ReqwestHttp;
use stow_resolve::util::context::GlobalContext;
use stow_resolve::util::context::environment::Env;
use stow_resolve::util::fs::{OsVfs, set_vfs};
use stow_resolve::util::network::http_async::Client;
use stow_resolve::util::shell::Shell;

/// The pinned stable the vendored rustc-data table was cut from — the
/// identity every resolve under test reports.
const PIN_VERSION: &str = "1.98.1";

/// `(runner family host triple, target triples)` — mirrors
/// `RunnerFamily::targets`/`host_triple` in `stow-types`; kept local so
/// the resolve crate never takes a stow-types dependency.
const FAMILIES: &[(&str, &[&str])] = &[
    (
        "x86_64-unknown-linux-gnu",
        &[
            "aarch64-linux-android",
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "wasm32-unknown-unknown",
        ],
    ),
    (
        "aarch64-apple-darwin",
        &[
            "aarch64-apple-darwin",
            "aarch64-apple-ios",
            "aarch64-apple-ios-sim",
        ],
    ),
    (
        "x86_64-pc-windows-msvc",
        &["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"],
    ),
];

const DEFAULT_TARGETS: &[&str] = FAMILIES[0].1;

struct Args {
    file: PathBuf,
    targets: Vec<String>,
    only: Vec<String>,
    from: usize,
    limit: Option<usize>,
}

fn parse_args() -> anyhow::Result<Args> {
    let mut args = Args {
        file: PathBuf::from("preheat/projects.toml"),
        targets: Vec::new(),
        only: Vec::new(),
        from: 0,
        limit: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--file" => args.file = PathBuf::from(it.next().context("--file PATH")?),
            "--target" => args.targets.push(it.next().context("--target T")?),
            "--only" => args.only.push(it.next().context("--only SUBSTR")?),
            "--from" => args.from = it.next().context("--from N")?.parse()?,
            "--limit" => args.limit = Some(it.next().context("--limit N")?.parse()?),
            other => bail!("unknown arg {other}"),
        }
    }
    if args.targets.is_empty() {
        args.targets
            .extend(DEFAULT_TARGETS.iter().map(ToString::to_string));
    }
    for target in &args.targets {
        if !FAMILIES.iter().any(|(_, ts)| ts.contains(&target.as_str())) {
            bail!("`{target}` is not a CI target");
        }
    }
    Ok(args)
}

fn host_of(target: &str) -> &'static str {
    FAMILIES
        .iter()
        .find(|(_, ts)| ts.contains(&target))
        .map(|(h, _)| *h)
        .unwrap()
}

/// The `projects.toml` schema the lane reads.
#[derive(serde::Deserialize)]
struct ProjectsFile {
    project: Vec<ProjectEntry>,
}

#[derive(serde::Deserialize)]
struct ProjectEntry {
    repo: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    run().await
}

#[allow(clippy::future_not_send)]
#[allow(clippy::too_many_lines)]
async fn run() -> anyhow::Result<()> {
    let args = parse_args()?;
    let raw = fs::read(&args.file).with_context(|| format!("read {}", args.file.display()))?;
    let file: ProjectsFile =
        toml::from_str(&String::from_utf8(raw).context("projects file is not UTF-8")?)
            .context("parse projects file")?;
    let repos: Vec<String> = file
        .project
        .iter()
        .map(|entry| entry.repo.trim().to_string())
        .filter(|repo| args.only.is_empty() || args.only.iter().any(|sub| repo.contains(sub)))
        .collect();

    let workdir = std::env::home_dir()
        .expect("home dir")
        .join(".cache/stow/resolve-projects");
    fs::create_dir_all(&workdir)?;
    let cargo_home = workdir.join("cargo-home");
    fs::create_dir_all(&cargo_home)?;

    let client = Client::new(Rc::new(ReqwestHttp::new()));
    set_vfs(Rc::new(OsVfs));

    // Every host triple a requested target can carry plus the targets
    // themselves — the injected `--print cfg` source.
    let mut cfg = BTreeMap::new();
    let mut triples: std::collections::BTreeSet<String> = args.targets.iter().cloned().collect();
    triples.extend(FAMILIES.iter().map(|(h, _)| (*h).to_string()));
    for triple in triples {
        cfg.insert(
            triple.clone(),
            rustc_data::cfg(PIN_VERSION, &triple)
                .with_context(|| format!("no vendored cfg for {PIN_VERSION} {triple}"))?
                .clone(),
        );
    }

    let mut resolved = 0usize;
    let mut skipped: Vec<(String, String)> = Vec::new();
    let total = repos.len();
    for (index, url) in repos.iter().enumerate().skip(args.from) {
        if let Some(limit) = args.limit
            && index >= args.from + limit
        {
            break;
        }
        let repo = url
            .trim_start_matches("https://github.com/")
            .trim_end_matches(".git")
            .trim_end_matches('/')
            .to_string();
        let tag = format!("[{}/{total}]", index + 1);
        let started = Instant::now();
        match resolve_repo(&client, &workdir, &cargo_home, &cfg, &repo, &args.targets).await {
            Ok(units) => {
                resolved += 1;
                println!(
                    "{tag} {repo}: resolved — {units} task units, {:?}",
                    started.elapsed()
                );
            }
            Err(reason) => {
                skipped.push((repo.clone(), format!("{reason:#}")));
                println!("{tag} {repo}: skipped — {reason:#}");
            }
        }
    }

    println!(
        "\nresolved={resolved} skipped={} total={total}",
        skipped.len()
    );
    for (repo, reason) in &skipped {
        println!("  {repo}: {reason}");
    }
    Ok(())
}

/// One repository through the lane's pipeline: fetch the tree, pick the
/// manifest the lane picks, resolve once per target. Returns the unit
/// count of the last resolve (identical shape across targets) or the
/// skip reason as the error.
#[allow(clippy::future_not_send)]
async fn resolve_repo(
    client: &Client,
    workdir: &Path,
    cargo_home: &Path,
    cfg: &BTreeMap<String, Vec<String>>,
    repo: &str,
    targets: &[String],
) -> anyhow::Result<usize> {
    let tree = fetch_github_tree(client, repo, "HEAD")
        .await
        .context("tree fetch")?;
    for note in &tree.notes {
        eprintln!("    {repo}: {note}");
    }
    let manifest_rel = select_manifest(&tree.files)
        .ok_or_else(|| anyhow::anyhow!("tree contains no Cargo.toml"))?;

    let dir = workdir.join(repo.replace('/', "-"));
    let _ = fs::remove_dir_all(&dir);
    for (rel, data) in &tree.files {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, data)?;
    }
    let result = resolve_at(client, cargo_home, cfg, &dir.join(&manifest_rel), targets).await;
    let _ = fs::remove_dir_all(&dir);
    result
}

/// `api::resolve` once per target — the worker's `resolve_workspace`
/// shape with `OsVfs` standing in for the request's `MemoryVfs` and the
/// shared `cargo_home` carrying the sparse-index cache across repos.
#[allow(clippy::future_not_send)]
async fn resolve_at(
    client: &Client,
    cargo_home: &Path,
    cfg: &BTreeMap<String, Vec<String>>,
    manifest_path: &Path,
    targets: &[String],
) -> anyhow::Result<usize> {
    let manifest_dir = manifest_path.parent().unwrap().to_path_buf();
    let mut units = 0;
    for target in targets {
        let host_triple = host_of(target).to_string();
        let mut gctx = GlobalContext::new_for_resolve(
            manifest_dir.clone(),
            cargo_home.to_path_buf(),
            Shell::new(),
            Env::new(),
            false,
        )?;
        gctx.set_http(client.clone());
        let output = api::resolve(
            &gctx,
            StowResolveInput {
                manifest_path: manifest_path.to_path_buf(),
                filter_platforms: vec![target.clone()],
                host_triple: host_triple.clone(),
                // The projects lane resolves with defaults on and no
                // seed features — `source_resolve`'s shape verbatim.
                features: Vec::new(),
                all_features: false,
                no_default_features: false,
                rustc_verbose_version: rustc_data::verbose_version(PIN_VERSION, &host_triple)
                    .with_context(|| format!("no vendored -vV for {PIN_VERSION} {host_triple}"))?
                    .to_string(),
                cfg: cfg.clone(),
                members_are_crates_io: false,
            },
        )
        .await
        .with_context(|| format!("resolve {target}"))?;
        units = output.units.len();
    }
    Ok(units)
}

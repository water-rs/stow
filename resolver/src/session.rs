//! One [`Resolver`] per process (or per worker, when callers fan out):
//! it owns the toolchain facts, the isolated `CARGO_HOME`, and the
//! per-runner-family rustc shims, and `resolve` runs the
//! select-once / project-per-target fan-out the vendored
//! `ResolveSession` ran.
//!
//! ## Host probing
//!
//! Host-side units must answer cfg questions for the runner family's
//! host triple, not this machine's. Cargo runs rustc through
//! `build.rustc-wrapper`, so each family gets a `GlobalContext` whose
//! wrapper is a copy of the session's shim executable named
//! `rustc-shim-<host>` ([`crate::shim`]): `rustc -vV` returns the real
//! output with the `host:` line rewritten to the family triple (so
//! `Rustc::host` — the `CompileKind::Host` target — is the family
//! triple), and every `--print` probe that lacks `--target` gets
//! `--target <family>` injected, so host `cfg` / file-name probing is
//! the family's own. `CompileKind::Target` probes already pass
//! `--target` explicitly and go through untouched.
//!
//! The first family's context performs version selection for the whole
//! fan-out — selection is target-independent — and each family's
//! `Workspace`/`RustcTargetData` projects it onto its targets.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use cargo::CargoResult;
use cargo::core::Workspace;
use cargo::core::compiler::{CompileKind, CompileKindFallback, RustcTargetData};
use cargo::core::resolver::features::{CliFeatures, ForceAllTargets, HasDevUnits};
use cargo::ops::Packages;
use cargo::util::GlobalContext;
use cargo_util_terminal::Shell;
use stow_types::api::{CI_TARGET_TRIPLES, EnqueueRequest, EnqueueSource, runner_family};
use stow_types::identity::WireRustcVersion;
use tracing::{debug, info};

use crate::emit::emit_units;
use crate::enqueue::enqueue_requests_from_output;
use crate::select::select_ws_with_opts;
use crate::units::{StowResolveOutput, StowUnitKind};

/// Feature set + lockfile inputs for one resolve — the knobs the lanes
/// carry into `resolve_crate`/`resolve_github_project` today.
#[derive(Debug, Clone, Default)]
pub struct ResolveOptions {
    /// Seed features (`-F` flags); empty for the admin lanes.
    pub features: Vec<String>,
    /// `--all-features`.
    pub all_features: bool,
    /// `--no-default-features`.
    pub no_default_features: bool,
    /// Whether the workspace's members are crates.io packages — a
    /// `.crate` tarball's member *is* the published package so its
    /// units may become tasks; a project checkout's members are
    /// sources only (`members_are_crates_io`).
    pub members_are_crates_io: bool,
    /// Contents of the root `Cargo.lock` the caller dropped — yanked
    /// admission + git pins. `None` when the tree never had a lockfile.
    pub dropped_lockfile: Option<String>,
}

/// What an admin resolve lane learns about the source: publish-shape
/// flags plus the per-target task batch — `worker_resolver::SourceResolve`
/// parity.
#[derive(Debug)]
pub struct SourceResolve {
    /// Whether the source ships a `[[bin]]` — the binaries lane's skip
    /// condition, taken from cargo's own target knowledge.
    pub has_binary: bool,
    /// Whether a workspace member publishes a library target.
    pub has_library: bool,
    /// One task batch per requested target, in request order.
    pub targets: Vec<(String, Vec<EnqueueRequest>)>,
}

/// A native resolve session: toolchain facts, the isolated cargo home,
/// and the per-family shims, shared across however many resolves the
/// owner runs.
#[derive(Debug)]
pub struct Resolver {
    /// Session-owned scratch: shim executables and per-family rustc caches.
    dir: tempfile::TempDir,
    /// The `CARGO_HOME` every context in this session gets — isolated
    /// from the user's real cargo home so no user config leaks in, and
    /// shared across this session's resolves so index caches live
    /// across projects.
    cargo_home: PathBuf,
    /// Real rustc binary of the toolchain the session pins.
    rustc: PathBuf,
    /// The executable copied per family host as `rustc-shim-<host>` —
    /// `stow-admin`'s own binary in production, `stow-rustc-shim` in
    /// tests.
    shim_source: PathBuf,
    /// This machine's own triple — the fallback host for a target no
    /// [`runner_family`] names.
    host_triple: String,
    /// The toolchain's release version.
    version: semver::Version,
    /// The environment cargo contexts spawn with: the process env
    /// minus `CARGO*`/`RUST*` so neither user cargo config nor rustup
    /// state leaks into a resolve.
    env: HashMap<String, String>,
    /// Precomputed rustc shim executables, one per runner-family host
    /// triple plus this machine's own — copied once so concurrent
    /// resolves on a shared `Resolver` never rewrite a copy another
    /// thread may be executing.
    shims: HashMap<String, PathBuf>,
}

impl Resolver {
    /// A session with a fresh, session-owned `CARGO_HOME` — the default
    /// isolation the issue states ("an isolated `CARGO_HOME` per run that
    /// the process owns"). `rustc_version` names the rustup toolchain the
    /// session probes — the rustc every task the session emits pins —
    /// and `shim_source` is the executable copied per family host as
    /// `rustc-shim-<host>`: it must dispatch a `rustc-shim-*` `argv[0]`
    /// to [`crate::shim::run`].
    ///
    /// # Errors
    /// `rustc_version`'s toolchain is not installed, or probing failed.
    pub fn new(rustc_version: &WireRustcVersion, shim_source: PathBuf) -> CargoResult<Self> {
        let dir = tempfile::tempdir().context("resolver scratch dir")?;
        let cargo_home = dir.path().join("cargo-home");
        std::fs::create_dir_all(&cargo_home).context("cargo home")?;
        Self::setup(dir, cargo_home, rustc_version, shim_source)
    }

    /// A session whose `CARGO_HOME` is a caller-owned directory — still
    /// not the user's real cargo home, but persistent across runs so
    /// the sparse-index and src caches amortize over a lane's many
    /// resolves. The directory is created if absent; the caller owns
    /// its lifecycle (concurrent writers must serialize themselves —
    /// cargo's own file locks arbitrate within the directory).
    /// `rustc_version` and `shim_source` are as [`Resolver::new`]'s.
    ///
    /// # Errors
    /// Directory creation or toolchain probing failures.
    pub fn with_cargo_home(
        cargo_home: PathBuf,
        rustc_version: &WireRustcVersion,
        shim_source: PathBuf,
    ) -> CargoResult<Self> {
        std::fs::create_dir_all(&cargo_home).context("cargo home")?;
        let dir = tempfile::tempdir().context("resolver scratch dir")?;
        Self::setup(dir, cargo_home, rustc_version, shim_source)
    }

    fn setup(
        dir: tempfile::TempDir,
        cargo_home: PathBuf,
        rustc_version: &WireRustcVersion,
        shim_source: PathBuf,
    ) -> CargoResult<Self> {
        // The session probes the toolchain its tasks pin, never
        // whichever rustc happens to be active: `rustup which
        // --toolchain` resolves that toolchain's real binary, and
        // `RUSTUP_AUTO_INSTALL=0` keeps an absent toolchain a failure
        // instead of a download.
        let requested = rustc_version.as_str();
        let output = std::process::Command::new("rustup")
            .args(["which", "--toolchain", requested, "rustc"])
            .env("RUSTUP_AUTO_INSTALL", "0")
            .output()
            .with_context(|| format!("run rustup which --toolchain {requested} rustc"))?;
        anyhow::ensure!(
            output.status.success(),
            "rustup has no toolchain for `{requested}` — install it with \
             `rustup toolchain install {requested}`: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let rustc = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned());
        anyhow::ensure!(
            rustc.is_file(),
            "rustup resolved `{requested}`'s rustc to {}, which is not a file",
            rustc.display()
        );
        let output = std::process::Command::new(&rustc)
            .arg("-vV")
            .output()
            .with_context(|| format!("run {} -vV", rustc.display()))?;
        anyhow::ensure!(
            output.status.success(),
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let verbose_version = String::from_utf8(output.stdout).context("rustc -vV utf8")?;
        let host_triple = verbose_version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .map(str::trim)
            .context("rustc -vV reports no host")?
            .to_owned();
        let release = verbose_version
            .lines()
            .find_map(|line| line.strip_prefix("release: "))
            .map(str::trim)
            .context("rustc -vV reports no release")?;
        // The toolchain that answered must *be* the pinned release — a
        // custom-linked toolchain or a stale rustup dir that reports
        // anything else gives the tasks facts from a different compiler.
        anyhow::ensure!(
            release == requested,
            "rustc `{requested}` resolves to {} reporting release {release} — \
             the toolchain's release must equal the pinned version",
            rustc.display()
        );
        let version = semver::Version::parse(release)
            .with_context(|| format!("rustc release `{release}` is not semver"))?;
        info!(?rustc, %host_triple, %version, ?cargo_home, "resolver session");
        let mut session = Self {
            dir,
            cargo_home,
            rustc,
            shim_source,
            host_triple,
            version,
            env: Self::sanitized_env(),
            shims: HashMap::new(),
        };
        // Every host triple a resolve can probe under: each CI runner
        // family's host, plus this machine's own as the fallback for a
        // non-CI target.
        let hosts: std::collections::BTreeSet<String> = CI_TARGET_TRIPLES
            .iter()
            .filter_map(|target| {
                runner_family(target).map(|family| family.host_triple().to_owned())
            })
            .chain(std::iter::once(session.host_triple.clone()))
            .collect();
        for host in hosts {
            let path = session.write_shim(&host)?;
            session.shims.insert(host, path);
        }
        Ok(session)
    }

    /// The pinned toolchain's release — verified to equal the
    /// `rustc_version` the session was constructed for.
    #[must_use]
    pub const fn version(&self) -> &semver::Version {
        &self.version
    }

    /// This machine's host triple.
    #[must_use]
    pub fn host_triple(&self) -> &str {
        &self.host_triple
    }

    /// The environment a spawned process is stripped to — `CARGO*` and
    /// `RUST*` out (no user cargo config, no rustup proxying, no
    /// caller rustflags), everything else (PATH, HOME, proxies, SSL
    /// certs, git's auth helpers) through.
    fn sanitized_env() -> HashMap<String, String> {
        std::env::vars()
            .filter(|(name, _)| !name.starts_with("CARGO") && !name.starts_with("RUST"))
            .collect()
    }

    /// The host triple host-side units for `target` probe as: the
    /// runner family's host when the target is a CI target, this
    /// machine's own triple otherwise.
    fn host_for(&self, target: &str) -> &str {
        runner_family(target).map_or(self.host_triple.as_str(), |family| family.host_triple())
    }

    /// The shim for `host`: a copy of the session's shim executable
    /// named `rustc-shim-<host>`, so the copy's file stem carries the
    /// family triple to [`crate::shim::run`].
    fn write_shim(&self, host: &str) -> CargoResult<PathBuf> {
        let path = self.dir.path().join(format!(
            "rustc-shim-{}{}",
            host.replace('/', "_"),
            std::env::consts::EXE_SUFFIX
        ));
        // Temp-file + rename: a lazy shim copy for a non-CI host can
        // race a sibling resolve — rename keeps the visible file whole.
        let tmp = path.with_extension("tmp");
        std::fs::copy(&self.shim_source, &tmp)
            .with_context(|| format!("copy {} to {}", self.shim_source.display(), tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("rename to {}", path.display()))?;
        Ok(path)
    }

    /// A `GlobalContext` for a resolve rooted at `cwd`, probing rustc
    /// through the `host` family's shim. Isolated `CARGO_HOME`,
    /// sanitized env, `build.rustc`/`build.rustc-wrapper` pinned — the
    /// highest-priority config source, so no ambient config can
    /// override them. Values go through `toml::Value`'s `Display` so
    /// Windows paths escape correctly; a non-UTF-8 path is an error.
    fn gctx(&self, cwd: &Path, host: &str) -> CargoResult<GlobalContext> {
        let shim = self
            .shims
            .get(host)
            .cloned()
            .map_or_else(|| self.write_shim(host), Ok)?;
        let rustc = self
            .rustc
            .to_str()
            .with_context(|| format!("rustc path `{}` is not UTF-8", self.rustc.display()))?;
        let shim = shim
            .to_str()
            .with_context(|| format!("shim path `{}` is not UTF-8", shim.display()))?;
        let mut gctx = GlobalContext::new(Shell::new(), cwd.to_path_buf(), self.cargo_home.clone());
        // cargo persists the family's rustc probe facts in
        // `<target dir>/.rustc_info.json`; the dir must exist before
        // the context is handed it, or every resolve re-probes.
        let target_dir = self.dir.path().join("target").join(host.replace('/', "_"));
        std::fs::create_dir_all(&target_dir)
            .with_context(|| format!("create target dir {}", target_dir.display()))?;
        let target_dir = Some(target_dir);
        gctx.configure(
            0,
            false,
            None,
            false,
            false,
            false,
            &target_dir,
            &[],
            &[
                format!("build.rustc={}", toml::Value::String(rustc.to_owned())),
                format!(
                    "build.rustc-wrapper={}",
                    toml::Value::String(shim.to_owned())
                ),
            ],
        )?;
        gctx.set_env(self.env.clone());
        Ok(gctx)
    }

    /// Resolve `manifest`'s workspace once per target: the vendored
    /// `ResolveSession::prepare` + `project` semantics —
    /// `Packages::Default` specs, `HasDevUnits::No`, one selection
    /// shared across targets, host-side units probing at each runner
    /// family's host triple.
    ///
    /// Returns one [`StowResolveOutput`] per requested target, in
    /// request order.
    ///
    /// # Errors
    /// Manifest, resolve, or emission failures.
    pub fn resolve(
        &self,
        manifest: &Path,
        opts: &ResolveOptions,
        targets: &[String],
    ) -> CargoResult<Vec<(String, StowResolveOutput)>> {
        let cli_features = CliFeatures::from_command_line(
            &opts.features,
            opts.all_features,
            !opts.no_default_features,
        )?;

        // Targets grouped by the host triple their host-side units
        // probe at — one GlobalContext + Workspace per family.
        let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for target in targets {
            groups
                .entry(self.host_for(target))
                .or_default()
                .push(target.as_str());
        }
        let cwd = manifest.parent().context("manifest has no parent dir")?;
        let gctxs: Vec<GlobalContext> = groups
            .keys()
            .map(|host| self.gctx(cwd, host))
            .collect::<CargoResult<_>>()?;
        let wss: Vec<Workspace> = gctxs
            .iter()
            .map(|gctx| Workspace::new(manifest, gctx))
            .collect::<CargoResult<_>>()?;

        let specs = Packages::Default.to_package_id_specs(&wss[0])?;
        let selection = select_ws_with_opts(
            &wss[0],
            &cli_features,
            &specs,
            HasDevUnits::No,
            false,
            opts.dropped_lockfile.as_deref(),
        )?;
        let has_binary = wss[0]
            .members()
            .any(|member| member.targets().iter().any(cargo::core::Target::is_bin));

        let force_all = if targets.is_empty() {
            ForceAllTargets::Yes
        } else {
            ForceAllTargets::No
        };
        let mut outputs = Vec::with_capacity(targets.len());
        for (index, (host, family_targets)) in groups.iter().enumerate() {
            for target in family_targets {
                let requested = [(*target).to_owned()];
                let kinds = CompileKind::from_requested_targets_with_fallback(
                    &gctxs[index],
                    &requested,
                    CompileKindFallback::JustHost,
                )?;
                let mut target_data = RustcTargetData::new(&wss[index], &kinds)?;
                debug!(%target, %host, "resolve target");
                let specs_and_features = selection.project(
                    &wss[index],
                    &mut target_data,
                    &kinds,
                    &cli_features,
                    force_all,
                )?;
                let (units, roots) = emit_units(
                    &wss[index],
                    &selection.pkg_set,
                    &specs_and_features,
                    &kinds,
                    host,
                    opts.members_are_crates_io,
                )?;
                outputs.push((
                    (*target).to_owned(),
                    StowResolveOutput {
                        units,
                        roots,
                        has_binary,
                    },
                ));
            }
        }
        Ok(outputs)
    }

    /// The admin crate lane: resolve one published `.crate` into
    /// per-target task batches. The tarball's bundled `Cargo.lock` is
    /// dropped like every other lane's — its pins survive only as
    /// `dropped_lockfile` admission, and the resolve lands on the
    /// latest semver-compatible versions.
    ///
    /// # Errors
    /// Fetch, manifest, resolve, or emission failures.
    pub async fn resolve_crate(
        &self,
        crate_name: &str,
        version: &semver::Version,
        targets: &[String],
        rustc_version: &WireRustcVersion,
        downloads: u64,
    ) -> CargoResult<SourceResolve> {
        let outputs = self
            .resolve_crate_units(crate_name, version, &ResolveOptions::default(), targets)
            .await?;
        Ok(Self::source_resolve(&outputs, rustc_version, downloads))
    }

    /// Resolve one published `.crate` into its raw per-target unit
    /// outputs — the `preheat plan` lane's input, which emits
    /// `EnqueueRequest`s itself so the request lane's coverage pruning
    /// can apply. `opts.features`/`no_default_features`/`all_features`
    /// name the seed feature set; `members_are_crates_io` is forced on —
    /// a `.crate` member is the published package.
    ///
    /// # Errors
    /// Fetch, manifest, resolve, or emission failures.
    pub async fn resolve_crate_units(
        &self,
        crate_name: &str,
        version: &semver::Version,
        opts: &ResolveOptions,
        targets: &[String],
    ) -> CargoResult<Vec<(String, StowResolveOutput)>> {
        let dir = self
            .dir
            .path()
            .join(format!("crate-{crate_name}-{version}"));
        std::fs::create_dir_all(&dir).context("crate dir")?;
        let package_dir = crate::fetch::fetch_crate(crate_name, version, &dir).await?;
        self.resolve_package_dir(&package_dir, opts, targets)
    }

    /// The post-fetch half of [`Resolver::resolve_crate_units`], split
    /// out so a test can drive it on a fixture package dir: the
    /// unpacked tree's bundled `Cargo.lock` is dropped exactly like
    /// [`Resolver::resolve_git`]'s checkout — every lane resolves at
    /// the latest semver-compatible versions, the lockfile's pins
    /// surviving only as `dropped_lockfile` admission.
    ///
    /// # Errors
    /// Manifest, resolve, or emission failures.
    pub fn resolve_package_dir(
        &self,
        package_dir: &Path,
        opts: &ResolveOptions,
        targets: &[String],
    ) -> CargoResult<Vec<(String, StowResolveOutput)>> {
        let tree = crate::fetch::prepare_project_tree(package_dir, true)?;
        let opts = ResolveOptions {
            members_are_crates_io: true,
            dropped_lockfile: tree.dropped_lockfile,
            ..opts.clone()
        };
        self.resolve(&tree.manifest_path, &opts, targets)
    }

    /// The admin projects lane: fetch a git tree (any https host,
    /// depth-1), drop its `Cargo.lock`, and resolve into per-target
    /// task batches.
    ///
    /// # Errors
    /// Fetch, manifest, resolve, or emission failures.
    pub fn resolve_git(
        &self,
        url: &str,
        git_ref: &str,
        targets: &[String],
        rustc_version: &WireRustcVersion,
        downloads: u64,
    ) -> CargoResult<SourceResolve> {
        let dir = self
            .dir
            .path()
            .join(format!("git-{:x}", fnv(url.as_bytes())));
        std::fs::create_dir_all(&dir).context("git dir")?;
        let root = crate::fetch::fetch_git(url, git_ref, &dir)?;
        let tree = crate::fetch::prepare_project_tree(&root, true)?;
        let opts = ResolveOptions {
            members_are_crates_io: false,
            dropped_lockfile: tree.dropped_lockfile,
            ..ResolveOptions::default()
        };
        let outputs = self.resolve(&tree.manifest_path, &opts, targets)?;
        Ok(Self::source_resolve(&outputs, rustc_version, downloads))
    }

    /// `source_resolve` parity: per-target unit outputs → per-target
    /// enqueue batches, plus the lane's publish-shape flags.
    fn source_resolve(
        outputs: &[(String, StowResolveOutput)],
        rustc_version: &WireRustcVersion,
        downloads: u64,
    ) -> SourceResolve {
        let mut has_binary = false;
        let mut has_library = false;
        let mut batches = Vec::with_capacity(outputs.len());
        for (target, output) in outputs {
            if output.roots.iter().any(|key| key.kind == StowUnitKind::Lib) {
                has_library = true;
            }
            has_binary |= output.has_binary;
            let (requests, _) = enqueue_requests_from_output(
                &output.units,
                rustc_version,
                EnqueueSource::CrateUpdate,
                downloads,
            )
            .expect("emit_units emits well-formed units");
            batches.push((target.clone(), requests));
        }
        SourceResolve {
            has_binary,
            has_library,
            targets: batches,
        }
    }
}

/// A tiny deterministic hash for naming per-repo scratch dirs — not
/// cryptographic, just collision-shy enough for a tempdir name.
fn fnv(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    /// A `--config` value built through `toml::Value`'s `Display`
    /// parses back to the verbatim path — backslashes and quotes
    /// escape instead of breaking the dotted-key expression.
    #[test]
    fn config_path_round_trips_through_toml() {
        let path = r#"C:\Users\RUNNER~1\AppData\Local\Temp\stow "quoted"\rustc-shim-x86_64-pc-windows-msvc.exe"#;
        for key in ["build.rustc", "build.rustc-wrapper"] {
            let arg = format!("{key}={}", toml::Value::String(path.to_owned()));
            let parsed = toml::from_str::<toml::Table>(&arg).unwrap();
            let (top, leaf) = key.split_once('.').unwrap();
            assert_eq!(
                parsed.get(top).and_then(|top| top.get(leaf)),
                Some(&toml::Value::String(path.to_owned())),
            );
        }
    }
}

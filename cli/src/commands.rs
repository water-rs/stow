//! User-facing top-level subcommands: `stow setup`, `status`, `clean`,
//! `check-artifact`, `fetch-artifact`, `purge-cache-dir`.
//!
//! The runtime command (`stow run`/`stow rustc`/`stow cc`) and the cargo
//! drivers (`stow check`/`stow build`/`stow test`) live elsewhere; this
//! module is the dev/maintenance surface.

use std::fmt::Write as _;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use stow_types::error::Context;
use toml_edit::{DocumentMut, Item, Table, Value};

use crate::build_dirs::BUILD_DIR_PARENT;
use crate::cli_args::{
    CheckArtifactArgs, FetchArtifactArgs, IndexRefreshArgs, PurgeCacheDirArgs, SetupArgs, StatsArgs,
};
use crate::config::{self, StowConfig};
use crate::daemon::DaemonProbe;
use crate::daemon::client::Restarted;
use crate::fetch;
use crate::index;
use crate::mold;
use crate::resolve;
use crate::rustc_args::{detect_rustc_host_target, detect_rustc_version};
use crate::session_env::SessionEnv;
use crate::state_db::StateDb;
use crate::stats;
use crate::term_style::Palette;
use crate::wrapper_shim;
use crate::write_stdout;

/// Right-aligned label width shared by `stow setup` and `stow status`.
const LABEL_WIDTH: usize = 16;

/// Platform daemon login service managed by `stow setup`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DaemonServicePlan {
    /// macOS `LaunchAgent` plist and launchd label.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    LaunchAgent { plist: PathBuf, label: String },
    /// Windows Task Scheduler task name.
    #[cfg_attr(not(windows), allow(dead_code))]
    ScheduledTask { name: String },
}

/// How an agent skill target appears in the setup plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkillPlanMode {
    /// Unconditionally installed (`--install-skill`).
    Install,
    /// Detected agent home needing update; user will be asked on an interactive terminal.
    Prompt,
}

/// One coding-agent skill file targeted by `stow setup`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SkillTargetPlan {
    path: PathBuf,
    mode: SkillPlanMode,
}

/// Read-only plan of every path and setting `stow setup` will create, update,
/// or clean before anything touches disk.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupPlan {
    cargo_config_path: PathBuf,
    cargo_config_exists: bool,
    shims_dir: PathBuf,
    host_target: String,
    rustc_version: String,
    rustc_wrapper: String,
    cc_key: String,
    cc_compiler: String,
    cxx_key: String,
    cxx_compiler: String,
    cc_launcher: String,
    real_cc: Option<String>,
    real_cxx: Option<String>,
    build_dir: BuildDirPlacement,
    mold: mold::GlobalMoldPlan,
    stale_project_configs: Vec<PathBuf>,
    daemon_service: Option<DaemonServicePlan>,
    skill_targets: Vec<SkillTargetPlan>,
    fetch_index_slice: bool,
}

/// Applied outcomes reported after `stow setup` finishes writing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SetupOutcome {
    config_path: PathBuf,
    build_dir: BuildDirPlacement,
    mold_bin_dir: Option<PathBuf>,
    selects_mold: bool,
    cleaned_stale_configs: Vec<PathBuf>,
    daemon_service: Option<DaemonServicePlan>,
    installed_skills: Vec<PathBuf>,
}

/// Whether stdin and stdout are both interactive terminals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalMode {
    Interactive,
    NonInteractive,
}

impl TerminalMode {
    const fn from_stdio(stdin_tty: bool, stdout_tty: bool) -> Self {
        if stdin_tty && stdout_tty {
            Self::Interactive
        } else {
            Self::NonInteractive
        }
    }
}

/// Terminal and flag inputs that decide whether `stow setup` prompts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetupPromptContext {
    yes: bool,
    ci_env: bool,
    terminal: TerminalMode,
}

impl SetupPromptContext {
    /// Whether `stow setup` should ask for interactive confirmation before writing.
    const fn should_prompt(self) -> bool {
        !self.yes && !self.ci_env && matches!(self.terminal, TerminalMode::Interactive)
    }
}

/// Parse a `[Y/n]` confirmation line: empty (Enter), `y`, or `yes` approves.
fn parse_confirm_answer(answer: &str) -> bool {
    let trimmed = answer.trim();
    trimmed.is_empty() || trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes")
}

/// Prompt the user to confirm applying the rendered setup plan.
fn confirm_setup_with(
    reader: &mut impl std::io::BufRead,
    writer: &mut impl std::io::Write,
    palette: Palette,
) -> stow_types::error::Result<bool> {
    write!(writer, "{} ", palette.bold("Apply these changes? [Y/n]:"))
        .wrap_err("write setup confirmation prompt")?;
    writer.flush().wrap_err("flush setup confirmation prompt")?;
    let mut answer = String::new();
    let bytes = reader
        .read_line(&mut answer)
        .wrap_err("read setup confirmation answer")?;
    if bytes == 0 {
        // EOF (e.g. Ctrl-D) declines rather than silently writing files.
        return Ok(false);
    }
    Ok(parse_confirm_answer(&answer))
}

fn push_kv(out: &mut String, palette: Palette, key: &str, value: impl std::fmt::Display) {
    let label = format!("{key:>LABEL_WIDTH$}:");
    let _ = writeln!(out, "  {} {value}", palette.key(label));
}

/// Render the pre-write `stow setup` plan.
fn render_setup_plan(plan: &SetupPlan, palette: Palette) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", palette.heading("stow setup plan"));
    let config_action = if plan.cargo_config_exists {
        palette.dim("(update)")
    } else {
        palette.ok("(create)")
    };
    push_kv(
        &mut out,
        palette,
        "config",
        format!("{} {config_action}", plan.cargo_config_path.display()),
    );
    push_kv(&mut out, palette, "rustc-wrapper", &plan.rustc_wrapper);
    push_kv(
        &mut out,
        palette,
        "cc",
        format!(
            "{} {}",
            plan.cc_compiler,
            palette.dim(format!("({})", plan.cc_key))
        ),
    );
    push_kv(
        &mut out,
        palette,
        "cxx",
        format!(
            "{} {}",
            plan.cxx_compiler,
            palette.dim(format!("({})", plan.cxx_key))
        ),
    );
    push_kv(
        &mut out,
        palette,
        "cc-launcher",
        format!(
            "{} {}",
            plan.cc_launcher,
            palette.dim("(CMAKE_{C,CXX}_COMPILER_LAUNCHER)")
        ),
    );
    if let Some(real_cc) = &plan.real_cc {
        push_kv(&mut out, palette, "STOW_REAL_CC", real_cc);
    }
    if let Some(real_cxx) = &plan.real_cxx {
        push_kv(&mut out, palette, "STOW_REAL_CXX", real_cxx);
    }
    push_kv(&mut out, palette, "build-dir", plan.build_dir.value_text());
    render_setup_plan_extras(&mut out, plan, palette);
    out
}

fn render_setup_plan_extras(out: &mut String, plan: &SetupPlan, palette: Palette) {
    match &plan.mold {
        mold::GlobalMoldPlan::NotNeeded => {}
        mold::GlobalMoldPlan::AlreadyConfigured => {
            push_kv(
                out,
                palette,
                "linker",
                format!("mold {}", palette.dim("(already configured)")),
            );
        }
        mold::GlobalMoldPlan::Managed {
            bin_dir,
            needs_download,
        } => {
            let note = if *needs_download {
                format!(" {}", palette.warn("(will download)"))
            } else {
                String::new()
            };
            push_kv(
                out,
                palette,
                "linker",
                format!("mold ({}){note}", bin_dir.join("mold").display()),
            );
        }
    }
    push_kv(out, palette, "shims", plan.shims_dir.display());
    if let Some(service) = &plan.daemon_service {
        match service {
            DaemonServicePlan::LaunchAgent { plist, label } => {
                push_kv(
                    out,
                    palette,
                    "launch agent",
                    format!("{} {}", plist.display(), palette.dim(format!("({label})"))),
                );
            }
            DaemonServicePlan::ScheduledTask { name } => {
                push_kv(
                    out,
                    palette,
                    "scheduled task",
                    format!("{name} {}", palette.dim("(Windows Task Scheduler)")),
                );
            }
        }
    }
    for skill in &plan.skill_targets {
        let note = match skill.mode {
            SkillPlanMode::Install => palette.ok("(install)"),
            SkillPlanMode::Prompt => palette.dim("(detected; will ask)"),
        };
        push_kv(
            out,
            palette,
            "agent skill",
            format!("{} {note}", skill.path.display()),
        );
    }
    for stale in &plan.stale_project_configs {
        push_kv(
            out,
            palette,
            "stale cleanup",
            format!("{} {}", stale.display(), palette.warn("(strip stow keys)")),
        );
    }
    if plan.fetch_index_slice {
        push_kv(
            out,
            palette,
            "index slice",
            format!("{} / rustc {}", plan.host_target, plan.rustc_version),
        );
    }
}

/// Render the completion summary after `stow setup` applies changes.
fn render_setup_complete(outcome: &SetupOutcome, palette: Palette) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{}", palette.ok_bold("stow setup complete"));
    push_kv(
        &mut out,
        palette,
        "configured",
        outcome.config_path.display(),
    );
    match (&outcome.mold_bin_dir, outcome.selects_mold) {
        (Some(dir), _) => {
            push_kv(
                &mut out,
                palette,
                "linker",
                format!("mold ({})", dir.join("mold").display()),
            );
        }
        (None, true) if cfg!(target_os = "linux") => {
            push_kv(
                &mut out,
                palette,
                "linker",
                format!("mold {}", palette.dim("(already configured)")),
            );
        }
        _ => {}
    }
    push_kv(
        &mut out,
        palette,
        "build-dir",
        outcome.build_dir.value_text(),
    );
    for path in &outcome.cleaned_stale_configs {
        push_kv(
            &mut out,
            palette,
            "cleaned",
            format!("stale stow wiring from {}", path.display()),
        );
    }
    if let Some(service) = &outcome.daemon_service {
        match service {
            DaemonServicePlan::LaunchAgent { plist, .. } => {
                push_kv(&mut out, palette, "launch agent", plist.display());
            }
            DaemonServicePlan::ScheduledTask { name } => {
                push_kv(&mut out, palette, "scheduled task", name);
            }
        }
    }
    for path in &outcome.installed_skills {
        push_kv(&mut out, palette, "stow skill", path.display());
    }
    out
}

struct PreparedSetup {
    current_dir: PathBuf,
    cargo_home: PathBuf,
    resolved_wrappers: ResolvedWrapperPlan,
    stow_config: StowConfig,
    interactive: bool,
    plan: SetupPlan,
}

async fn prepare_setup(
    args: &SetupArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<PreparedSetup> {
    let current_dir = std::env::current_dir().wrap_err("resolve current directory")?;
    let cargo_home = config::require_cargo_home()?;
    let config_path = cargo_home.join("config.toml");
    let env = SessionEnv::of_this_process()?;
    let (host_target, rustc_version, mold_plan) = tokio::join!(
        detect_rustc_host_target(std::ffi::OsStr::new("rustc"), &env),
        detect_rustc_version(std::ffi::OsStr::new("rustc"), &env),
        mold::plan_global(),
    );
    let host_target = host_target
        .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
    let rustc_version =
        rustc_version.map_err(|error| stow_types::stow_error!("detect rustc version: {error}"))?;
    let mold_plan = mold_plan?;
    let resolved_wrappers = resolve_wrapper_executables(&cargo_home)?;
    let planned_shims = wrapper_shim::planned_wrapper_shims(&resolved_wrappers.shims_dir);
    let cargo_config_exists = async_fs::metadata(&config_path).await.is_ok();
    let stale_configs = stale_project_configs(&current_dir, &cargo_home);
    let build_dir = match user_build_dir(&cargo_home, &env)? {
        Some(user) => BuildDirPlacement::User(user),
        None if args.no_build_dir => BuildDirPlacement::Disabled,
        None => BuildDirPlacement::Stow(stow_build_dir_template(&config::cache_dir(&env)?)?),
    };
    let stow_config = StowConfig::load(state_db.clone())?;
    let interactive = SetupPromptContext {
        yes: args.yes,
        ci_env: std::env::var_os("CI").is_some(),
        terminal: TerminalMode::from_stdio(
            std::io::stdin().is_terminal(),
            std::io::stdout().is_terminal(),
        ),
    }
    .should_prompt();
    let scoped = host_target.replace(['-', '.'], "_");
    let real_cc = configured_c_compiler(&host_target)
        .or_else(|| read_recorded_env(&config_path, "STOW_REAL_CC"));
    let real_cxx = configured_cxx_compiler(&host_target)
        .or_else(|| read_recorded_env(&config_path, "STOW_REAL_CXX"));
    let plan = SetupPlan {
        cargo_config_path: config_path,
        cargo_config_exists,
        shims_dir: resolved_wrappers.shims_dir.clone(),
        host_target,
        rustc_version,
        rustc_wrapper: shim_path(&planned_shims.rustc_wrapper, "rustc wrapper")?,
        cc_key: format!("CC_{scoped}"),
        cc_compiler: shim_path(&planned_shims.cc_compiler, "cc compiler")?,
        cxx_key: format!("CXX_{scoped}"),
        cxx_compiler: shim_path(&planned_shims.cxx_compiler, "cxx compiler")?,
        cc_launcher: shim_path(&planned_shims.cc_launcher, "cc launcher")?,
        real_cc,
        real_cxx,
        build_dir,
        mold: mold_plan,
        stale_project_configs: stale_configs,
        daemon_service: planned_daemon_service()?,
        skill_targets: planned_skill_targets(args, interactive)?,
        fetch_index_slice: stow_config.cache.reaches_network(),
    };
    Ok(PreparedSetup {
        current_dir,
        cargo_home,
        resolved_wrappers,
        stow_config,
        interactive,
        plan,
    })
}

/// `stow setup`: write the stow wiring into the user's global cargo
/// configuration — `$CARGO_HOME/config.toml` — so every cargo invocation
/// on the machine routes through the stow rustc/cc wrappers; or, with
/// `--github-env`, print the equivalent `KEY=VALUE` job-environment
/// wiring on stdout.
pub async fn setup_project(args: SetupArgs, state_db: &StateDb) -> stow_types::error::Result<()> {
    if args.github_env {
        return print_setup_env(state_db).await;
    }
    let prepared = prepare_setup(&args, state_db).await?;
    let palette = Palette::for_stdout();
    write_stdout(&render_setup_plan(&prepared.plan, palette))?;

    if prepared.interactive {
        let confirmed = smol::unblock(move || {
            let stdin = std::io::stdin();
            let mut reader = stdin.lock();
            let mut stdout = std::io::stdout();
            confirm_setup_with(&mut reader, &mut stdout, palette)
        })
        .await?;
        if !confirmed {
            write_stdout(&format!(
                "{}\n",
                palette.warn("setup cancelled — no files were modified")
            ))?;
            return Ok(());
        }
    }

    let outcome = apply_setup(&args, &prepared).await?;
    write_stdout(&render_setup_complete(&outcome, palette))?;
    Ok(())
}

async fn apply_setup(
    args: &SetupArgs,
    prepared: &PreparedSetup,
) -> stow_types::error::Result<SetupOutcome> {
    let mold_bin_dir = mold::apply_global_plan(&prepared.plan.mold).await?;
    let wrappers = materialize_wrappers(&prepared.resolved_wrappers)?;
    let cleaned = clean_stale_project_configs(&prepared.current_dir, &prepared.cargo_home)?;
    let (config_path, selects_mold) = write_cargo_config(
        &prepared.cargo_home,
        &wrappers,
        &prepared.plan.host_target,
        configured_c_compiler(&prepared.plan.host_target).as_deref(),
        configured_cxx_compiler(&prepared.plan.host_target).as_deref(),
        mold_bin_dir.as_deref(),
        prepared.plan.build_dir.stow_template(),
    )
    .await?;
    if cfg!(target_os = "linux") {
        mold::warm_global_link_cache(&prepared.cargo_home, &prepared.stow_config).await?;
    }

    let identity = crate::sandbox::stow_identity()?;
    let identity_name = identity.name().to_owned();
    smol::unblock(move || identity.prepare())
        .await
        .map_err(|error| {
            stow_types::stow_error!("prepare the {identity_name} sandbox identity: {error}")
        })?;

    if prepared.stow_config.cache.reaches_network() {
        index::ensure_slice(
            &prepared.stow_config,
            &prepared.plan.host_target,
            &prepared.plan.rustc_version,
        )
        .await
        .map_err(|error| {
            stow_types::stow_error!(
                "fetch the {} index slice for rustc {}: {error}",
                prepared.plan.host_target,
                prepared.plan.rustc_version
            )
        })?;
    }

    tracing::info!(
        path = %config_path.display(),
        rustc_wrapper = %wrappers.rustc,
        cc_compiler = %wrappers.cc_compiler,
        cxx_compiler = %wrappers.cxx_compiler,
        cc_launcher = %wrappers.cc_launcher,
        mold_bin_dir = ?mold_bin_dir,
        "configured cargo for stow"
    );

    #[cfg(target_os = "macos")]
    let installed_service = {
        let installed = install_launch_agent(&wrappers.runtime_executable).await?;
        Some(DaemonServicePlan::LaunchAgent {
            plist: installed.plist,
            label: crate::daemon::launch_agent::LABEL.to_owned(),
        })
    };
    #[cfg(windows)]
    let installed_service = {
        let task = register_daemon_task(&wrappers.runtime_executable).await?;
        Some(DaemonServicePlan::ScheduledTask { name: task })
    };
    #[cfg(not(any(target_os = "macos", windows)))]
    let installed_service = None;

    let installed_skills = maybe_setup_stow_skill(args, prepared.interactive).await?;
    Ok(SetupOutcome {
        config_path,
        build_dir: prepared.plan.build_dir.clone(),
        mold_bin_dir,
        selects_mold,
        cleaned_stale_configs: cleaned,
        daemon_service: installed_service,
        installed_skills,
    })
}

/// Compute the daemon login service target for this platform without writing.
#[cfg_attr(
    not(any(target_os = "macos", windows)),
    allow(clippy::missing_const_for_fn, clippy::unnecessary_wraps)
)]
fn planned_daemon_service() -> stow_types::error::Result<Option<DaemonServicePlan>> {
    #[cfg(target_os = "macos")]
    {
        let plist = dirs::home_dir()
            .ok_or_else(|| stow_types::stow_error!("resolve home directory"))?
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{}.plist", crate::daemon::launch_agent::LABEL));
        Ok(Some(DaemonServicePlan::LaunchAgent {
            plist,
            label: crate::daemon::launch_agent::LABEL.to_owned(),
        }))
    }
    #[cfg(windows)]
    {
        let run_dir = crate::daemon::RunDir::locate()?;
        Ok(Some(DaemonServicePlan::ScheduledTask {
            name: crate::daemon::scheduled_task::task_name(&run_dir),
        }))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        Ok(None)
    }
}

/// Read an existing non-stow `[env]` entry from `config_path` without modifying it.
fn read_recorded_env(config_path: &Path, key: &str) -> Option<String> {
    let document = std::fs::read_to_string(config_path)
        .ok()?
        .parse::<DocumentMut>()
        .ok()?;
    document
        .get("env")
        .and_then(Item::as_table)
        .and_then(|env| env.get(key))
        .and_then(env_item_value)
        .map(str::to_owned)
        .filter(|value| !is_stow_owned_value(value))
}

/// Register the Task Scheduler task that starts the daemon for the run
/// directory this process resolves, and return its name.
#[cfg(windows)]
async fn register_daemon_task(runtime_executable: &Path) -> stow_types::error::Result<String> {
    let runtime_executable = runtime_executable.to_owned();
    tokio::task::spawn_blocking(move || {
        let run_dir = crate::daemon::RunDir::locate()?;
        crate::daemon::scheduled_task::register(&run_dir, &runtime_executable)
    })
    .await
    .wrap_err("register the daemon's scheduled task")?
}

/// Write the daemon's `LaunchAgent` under the user's `~/Library` and load
/// it into their GUI domain.
#[cfg(target_os = "macos")]
async fn install_launch_agent(
    runtime_executable: &Path,
) -> stow_types::error::Result<crate::daemon::launch_agent::Installed> {
    use crate::daemon::launch_agent::{SystemLaunchctl, install};
    let agents_dir = dirs::home_dir()
        .ok_or_else(|| stow_types::stow_error!("resolve home directory"))?
        .join("Library")
        .join("LaunchAgents");
    let runtime_executable = runtime_executable.to_owned();
    tokio::task::spawn_blocking(move || {
        // SAFETY: `getuid` has no preconditions and cannot fail.
        let uid = unsafe { libc::getuid() };
        install(
            &agents_dir,
            &runtime_executable,
            uid,
            &SystemLaunchctl::from_env(),
        )
    })
    .await
    .wrap_err("install the launch agent")?
}

/// Write `cargo_dir/config.toml` pointing cargo at `wrappers` and — when
/// `mold_bin_dir` carries a managed install — selecting mold for every
/// Linux target, with the install dir reaching the linker through the
/// `[env]` table rather than a rustflag so it stays out of the compile
/// key. An existing document keeps every unrelated setting: the
/// `build.rustc-wrapper`, `[env]` compiler keys and stow's linker wiring
/// are replaced in place, so re-running `setup` — including over a stale
/// `/tmp/stow-tools` entry left by an older stow — rewrites the same keys
/// instead of appending duplicates. Returns the config path and whether
/// the written document selects mold, so the caller's report follows the
/// file rather than the probe answer.
async fn write_cargo_config(
    cargo_dir: &Path,
    wrappers: &WrapperCommands,
    host_target: &str,
    real_cc: Option<&str>,
    real_cxx: Option<&str>,
    mold_bin_dir: Option<&Path>,
    build_dir: Option<&str>,
) -> stow_types::error::Result<(PathBuf, bool)> {
    let config_path = cargo_dir.join("config.toml");
    async_fs::create_dir_all(cargo_dir)
        .await
        .wrap_err_with(|| format!("create {}", cargo_dir.display()))?;

    let mut document = if async_fs::metadata(&config_path).await.is_ok() {
        async_fs::read_to_string(&config_path)
            .await
            .wrap_err_with(|| format!("read {}", config_path.display()))?
            .parse::<DocumentMut>()
            .wrap_err_with(|| format!("parse {}", config_path.display()))?
    } else {
        DocumentMut::new()
    };

    // A compiler recorded by an earlier setup lives in this document, not
    // in the environment — carry it forward so re-running setup never
    // forgets the toolchain the caller configured the first time.
    let recorded = |key: &str| -> Option<String> {
        document
            .get("env")
            .and_then(Item::as_table)
            .and_then(|env| env.get(key))
            .and_then(env_item_value)
            .map(str::to_owned)
            .filter(|value| !is_stow_owned_value(value))
    };
    let real_cc = real_cc
        .map(str::to_owned)
        .or_else(|| recorded("STOW_REAL_CC"));
    let real_cxx = real_cxx
        .map(str::to_owned)
        .or_else(|| recorded("STOW_REAL_CXX"));

    configure_document(
        &mut document,
        wrappers,
        compiler_env_entries(
            wrappers,
            host_target,
            real_cc.as_deref(),
            real_cxx.as_deref(),
        ),
        mold_bin_dir,
        build_dir,
    )?;
    let selects_mold = document_selects_mold(&document);

    async_fs::write(&config_path, document.to_string())
        .await
        .wrap_err_with(|| format!("write {}", config_path.display()))?;
    Ok((config_path, selects_mold))
}

/// Point `document` at `wrappers` and `mold_bin_dir`: `build.rustc-wrapper`,
/// the `[env]` compiler entries, and the mold linker selection when setup
/// provisioned one. Entries an earlier stow wrote and this revision no
/// longer emits are removed first — by value, never by key name alone —
/// and replacement of the rest is by key, so the operation is idempotent.
/// The linker selection is the one entry the clean step never owns:
/// `mold::write_linker_selection` replaces it in place when a new one is
/// written, and with no `mold_bin_dir` — the configuration already
/// selects a reachable mold — the document's linker entries stand
/// exactly as they are.
fn configure_document(
    document: &mut DocumentMut,
    wrappers: &WrapperCommands,
    env_entries: Vec<(String, String)>,
    mold_bin_dir: Option<&Path>,
    build_dir: Option<&str>,
) -> stow_types::error::Result<()> {
    clean_stow_owned_entries(document, LinkerSelection::Keep);
    set_build_wrapper(document, &wrappers.rustc);
    if let Some(build_dir) = build_dir {
        ensure_table(document, "build")["build-dir"] = Item::Value(Value::from(build_dir));
    }
    // The selection writes `env.COMPILER_PATH`, so it goes ahead of the
    // rewritten env keys: remove-then-write appends after the entries a
    // pass keeps, and keeping the selection identical across a run that
    // writes nothing needs it first in the table.
    if let Some(bin_dir) = mold_bin_dir {
        mold::write_linker_selection(document, bin_dir)?;
    }
    for (key, value) in env_entries {
        set_env_wrapper(document, &key, &value);
    }
    Ok(())
}

/// `stow setup --github-env`: emit the job-environment equivalent of what
/// `stow setup` writes into the cargo configuration, plus the resolved edge
/// configuration, as `KEY=VALUE` lines. Consumers append it to `$GITHUB_ENV`
/// so the wiring applies to the whole job instead of one project.
async fn print_setup_env(state_db: &StateDb) -> stow_types::error::Result<()> {
    let wrappers = detect_wrapper_commands()?;
    let config = StowConfig::load(state_db.clone())?;
    let host_target = detect_rustc_host_target(
        std::ffi::OsStr::new("rustc"),
        &SessionEnv::of_this_process()?,
    )
    .await
    .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}"))?;
    write_stdout(&setup_env_output(
        &wrappers,
        &host_target,
        configured_c_compiler(&host_target).as_deref(),
        configured_cxx_compiler(&host_target).as_deref(),
        &config,
    ))
}

/// The C/C++ environment `stow setup` wires, shared by the `.cargo/config.toml`
/// `[env]` table and the `--github-env` output so the two can never drift.
///
/// The shims are wired through the `cc` crate's own target-scoped keys —
/// `CC_<triple>` / `CXX_<triple>` for the host target — rather than bare
/// `CC`/`CXX`, so other targets (`*-windows-gnu`, `wasm32`, cross builds)
/// keep the toolchain `cc`-rs resolves for them instead of being forced
/// onto the host compiler. The `CMAKE_*_COMPILER_LAUNCHER` variables have
/// no target-scoped form; they stay bare — the launcher wraps whichever
/// compiler `CMake` picked, so it is correct on every target.
///
/// `STOW_REAL_CC` / `STOW_REAL_CXX` are written only when the caller had
/// an explicit toolchain configured; without them the shims resolve the
/// platform's compiler per invocation, the way the `cc` crate does.
fn compiler_env_entries(
    wrappers: &WrapperCommands,
    host_target: &str,
    real_cc: Option<&str>,
    real_cxx: Option<&str>,
) -> Vec<(String, String)> {
    let scoped = host_target.replace(['-', '.'], "_");
    let mut entries = Vec::with_capacity(6);
    if let Some(real_cc) = real_cc {
        entries.push(("STOW_REAL_CC".to_owned(), real_cc.to_owned()));
    }
    if let Some(real_cxx) = real_cxx {
        entries.push(("STOW_REAL_CXX".to_owned(), real_cxx.to_owned()));
    }
    entries.extend([
        (format!("CC_{scoped}"), wrappers.cc_compiler.clone()),
        (format!("CXX_{scoped}"), wrappers.cxx_compiler.clone()),
        (
            "CMAKE_C_COMPILER_LAUNCHER".to_owned(),
            wrappers.cc_launcher.clone(),
        ),
        (
            "CMAKE_CXX_COMPILER_LAUNCHER".to_owned(),
            wrappers.cc_launcher.clone(),
        ),
    ]);
    entries
}

/// The job-environment variables `stow setup` wires, in a fixed order so the
/// output is stable for consumers that diff it.
fn setup_env_output(
    wrappers: &WrapperCommands,
    host_target: &str,
    real_cc: Option<&str>,
    real_cxx: Option<&str>,
    config: &StowConfig,
) -> String {
    let rustc_wrapper = [("RUSTC_WRAPPER".to_owned(), wrappers.rustc.clone())];
    let edge = [
        ("STOW_EDGE_URL".to_owned(), config.edge_url.clone()),
        (
            "STOW_VERIFY_MODE".to_owned(),
            config.verify_mode.as_str().to_owned(),
        ),
    ];
    rustc_wrapper
        .into_iter()
        .chain(compiler_env_entries(
            wrappers,
            host_target,
            real_cc,
            real_cxx,
        ))
        .chain(edge)
        .fold(String::new(), |mut output, (key, value)| {
            // Writing to a String cannot fail.
            let _ = writeln!(output, "{key}={value}");
            output
        })
}

/// Cargo wiring section of [`StatusReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum CargoWiringStatus {
    /// `$CARGO_HOME/config.toml` does not exist yet.
    NotConfigured { config_path: PathBuf },
    /// `$CARGO_HOME/config.toml` was parsed.
    Configured {
        config_path: PathBuf,
        rustc_wrapper: Option<String>,
        cc_compiler: Option<String>,
        cxx_compiler: Option<String>,
        cc_launcher: Option<String>,
        build_dir: String,
        linker_mold: bool,
    },
}

/// Remote cache and daemon state section of [`StatusReport`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteDaemonStatus {
    edge_url: Option<String>,
    remote_cache: Option<bool>,
    daemon: DaemonProbe,
}

/// Structured data rendered by `stow status`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StatusReport {
    cargo: CargoWiringStatus,
    remote: RemoteDaemonStatus,
    summary: stats::StatsSummary,
    local: stats::LocalStats,
    stale_project_configs: Vec<PathBuf>,
}

/// Format a `hits / (hits + misses)` percentage, or `None` with zero lookups.
#[expect(
    clippy::cast_precision_loss,
    reason = "lookup counters are far below 2^53"
)]
fn format_hit_rate(hits: u64, misses: u64) -> Option<String> {
    let total = hits.saturating_add(misses);
    if total == 0 {
        return None;
    }
    Some(format!("{:.1}%", (hits as f64 / total as f64) * 100.0))
}

fn format_cache_line(hits: u64, misses: u64, errors: u64, palette: Palette) -> String {
    let hits_text = if hits > 0 {
        palette.ok(format!("{} hits", grouped_count(hits)))
    } else {
        palette.dim(format!("{} hits", grouped_count(hits)))
    };
    let misses_text = if misses > 0 {
        palette.warn(format!("{} misses", grouped_count(misses)))
    } else {
        palette.dim(format!("{} misses", grouped_count(misses)))
    };
    let rate_text = format_hit_rate(hits, misses).map_or_else(
        || palette.dim("(—)".to_owned()),
        |rate| palette.bold(format!("({rate} hit rate)")),
    );
    let errors_text = if errors > 0 {
        palette.err(format!("{} errors", grouped_count(errors)))
    } else {
        palette.dim(format!("{} errors", grouped_count(errors)))
    };
    format!("{hits_text}, {misses_text} {rate_text}, {errors_text}")
}

fn render_optional_wiring(value: Option<&str>, palette: Palette) -> String {
    value.map_or_else(|| palette.warn("<missing>").to_string(), ToOwned::to_owned)
}

/// Render [`StatusReport`] as a grouped, human-friendly summary.
fn render_status_report(report: &StatusReport, palette: Palette) -> String {
    let mut out = String::new();
    render_cargo_wiring_section(&mut out, &report.cargo, palette);
    let _ = writeln!(out);
    render_remote_daemon_section(&mut out, &report.remote, palette);
    let _ = writeln!(out);
    render_cache_perf_section(&mut out, report.summary, report.local, palette);
    if !report.stale_project_configs.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", palette.warn("Warnings"));
        for path in &report.stale_project_configs {
            let _ = writeln!(
                out,
                "  {} {} — left by an older stow; `stow setup` removes it",
                palette.warn("stale stow wiring:"),
                path.display()
            );
        }
    }
    out
}

fn render_cargo_wiring_section(out: &mut String, cargo: &CargoWiringStatus, palette: Palette) {
    let _ = writeln!(out, "{}", palette.heading("Cargo wiring"));
    match cargo {
        CargoWiringStatus::NotConfigured { config_path } => {
            let _ = writeln!(
                out,
                "  {} {} is missing — run `stow setup`",
                palette.warn("not configured:"),
                config_path.display()
            );
        }
        CargoWiringStatus::Configured {
            config_path,
            rustc_wrapper,
            cc_compiler,
            cxx_compiler,
            cc_launcher,
            build_dir,
            linker_mold,
        } => {
            push_kv(out, palette, "config", config_path.display());
            push_kv(
                out,
                palette,
                "rustc-wrapper",
                render_optional_wiring(rustc_wrapper.as_deref(), palette),
            );
            push_kv(
                out,
                palette,
                "cc",
                render_optional_wiring(cc_compiler.as_deref(), palette),
            );
            push_kv(
                out,
                palette,
                "cxx",
                render_optional_wiring(cxx_compiler.as_deref(), palette),
            );
            push_kv(
                out,
                palette,
                "cc-launcher",
                render_optional_wiring(cc_launcher.as_deref(), palette),
            );
            push_kv(out, palette, "build-dir", build_dir);
            if *linker_mold {
                push_kv(out, palette, "linker", "mold");
            }
        }
    }
}

fn render_remote_daemon_section(out: &mut String, remote: &RemoteDaemonStatus, palette: Palette) {
    let _ = writeln!(out, "{}", palette.heading("Remote & daemon"));
    push_kv(
        out,
        palette,
        "edge-url",
        render_optional_wiring(remote.edge_url.as_deref(), palette),
    );
    let remote_state = match remote.remote_cache {
        Some(true) => palette.ok("on").to_string(),
        Some(false) => palette.warn("off (local-only)").to_string(),
        None => palette.warn("<unavailable>").to_string(),
    };
    push_kv(out, palette, "remote-cache", remote_state);
    let daemon_state = match &remote.daemon {
        DaemonProbe::Running(status) => palette
            .ok(format!(
                "running (stow {}, protocol {})",
                status.stow_version, status.protocol
            ))
            .to_string(),
        DaemonProbe::Retiring { stow_version } => palette
            .warn(format!("retiring (stow {stow_version})"))
            .to_string(),
        DaemonProbe::NotRunning => palette.dim("not running").to_string(),
        DaemonProbe::Unavailable(reason) => {
            palette.err(format!("unavailable ({reason})")).to_string()
        }
    };
    push_kv(out, palette, "daemon", daemon_state);
}

fn render_cache_perf_section(
    out: &mut String,
    summary: stats::StatsSummary,
    local: stats::LocalStats,
    palette: Palette,
) {
    let _ = writeln!(out, "{}", palette.heading("Cache performance"));
    push_kv(
        out,
        palette,
        "rust-cache",
        format_cache_line(
            summary.rust_hits,
            summary.rust_misses,
            summary.rust_errors,
            palette,
        ),
    );
    push_kv(
        out,
        palette,
        "cc-cache",
        format_cache_line(
            summary.cc_hits,
            summary.cc_misses,
            summary.cc_errors,
            palette,
        ),
    );
    push_kv(
        out,
        palette,
        "cpu-saved",
        format_cpu_millis(local.cpu_millis_saved),
    );
    push_kv(
        out,
        palette,
        "bytes-served",
        format_bytes(local.bytes_served),
    );
    push_kv(
        out,
        palette,
        "bytes-downloaded",
        format_bytes(local.bytes_downloaded),
    );
}

/// `stow status`: print Cargo wrapper wiring, remote and daemon state,
/// cache performance counters, and any stale per-project wiring.
pub async fn status_project(state_db: &StateDb) -> stow_types::error::Result<()> {
    let cargo_home = config::require_cargo_home()?;
    let config_path = cargo_home.join("config.toml");

    let cargo = if async_fs::metadata(&config_path).await.is_ok() {
        let document = async_fs::read_to_string(&config_path)
            .await
            .wrap_err_with(|| format!("read {}", config_path.display()))?
            .parse::<DocumentMut>()
            .wrap_err_with(|| format!("parse {}", config_path.display()))?;

        let rustc_wrapper = document
            .get("build")
            .and_then(Item::as_table)
            .and_then(|table| table.get("rustc-wrapper"))
            .and_then(Item::as_str)
            .map(str::to_owned);

        // The shims are wired under the `cc` crate's target-scoped keys for the
        // host triple; an unrecognized answer still reports whatever scoped
        // keys are present rather than pretending nothing is wired.
        let scoped = |base: &str| -> Option<String> {
            document
                .get("env")
                .and_then(Item::as_table)
                .map(|env| {
                    env.iter()
                        .filter(|(key, _)| key.starts_with(&format!("{base}_")) || *key == base)
                        .filter_map(|(_, item)| env_item_value(item).map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .filter(|values| !values.is_empty())
                .map(|values| values.join(", "))
        };
        let cc_compiler = scoped("CC");
        let cxx_compiler = scoped("CXX");
        let cc_launcher = env_value(&document, "CMAKE_C_COMPILER_LAUNCHER").map(str::to_owned);
        let build_dir = std::env::var_os("CARGO_BUILD_BUILD_DIR").map_or_else(
            || {
                document
                    .get("build")
                    .and_then(Item::as_table_like)
                    .and_then(|table| table.get("build-dir"))
                    .and_then(Item::as_str)
                    .map_or_else(|| "target/ (default)".to_owned(), str::to_owned)
            },
            |env_val| format!("{} (CARGO_BUILD_BUILD_DIR)", env_val.to_string_lossy()),
        );
        let linker_mold = cfg!(target_os = "linux") && document_selects_mold(&document);
        CargoWiringStatus::Configured {
            config_path: config_path.clone(),
            rustc_wrapper,
            cc_compiler,
            cxx_compiler,
            cc_launcher,
            build_dir,
            linker_mold,
        }
    } else {
        CargoWiringStatus::NotConfigured {
            config_path: config_path.clone(),
        }
    };

    let daemon_fut = tokio::task::spawn_blocking(|| {
        std::env::current_exe().map_or_else(
            |error| DaemonProbe::Unavailable(error.to_string()),
            |exe| crate::daemon::probe_if_running(&exe),
        )
    });

    let loaded_config = StowConfig::load(state_db.clone()).ok();
    let stats_fut = async {
        let Some(cfg) = loaded_config.as_ref() else {
            return (stats::StatsSummary::default(), stats::LocalStats::default());
        };
        let summary_fut = async {
            if crate::state_db::state_db_path(&cfg.cache_dir).exists() {
                stats::read_summary(cfg).await.unwrap_or_default()
            } else {
                stats::StatsSummary::default()
            }
        };
        let local_fut = async { stats::read_local_stats(cfg).await.unwrap_or_default() };
        tokio::join!(summary_fut, local_fut)
    };

    let (daemon_res, (summary, local)) = tokio::join!(daemon_fut, stats_fut);
    let daemon = daemon_res.unwrap_or_else(|error| DaemonProbe::Unavailable(error.to_string()));
    let remote = RemoteDaemonStatus {
        edge_url: loaded_config.as_ref().map(|cfg| cfg.edge_url.clone()),
        remote_cache: loaded_config.as_ref().map(|cfg| cfg.cache.remote),
        daemon,
    };

    let stale_project_configs = std::env::current_dir()
        .map_or_default(|current_dir| stale_project_configs(&current_dir, &cargo_home));

    let report = StatusReport {
        cargo,
        remote,
        summary,
        local,
        stale_project_configs,
    };
    write_stdout(&render_status_report(&report, Palette::for_stdout()))?;

    Ok(())
}

/// `stow update`: replace this install with the latest stow-cli release.
/// The cargo-dist install receipt — `stow-cli-receipt.json`, written by
/// the shell and powershell installers — records the install prefix and
/// the GitHub repository, and axoupdater downloads that release's own
/// installer and runs it against the recorded prefix, so a `cargo
/// install` or source build cannot clobber itself (the receipt check
/// fails first, with the reason). Afterwards the wrapper shims under
/// this binary's own shim dir — [`crate::config::shims_dir`] — are
/// re-materialized so they keep resolving to the fresh binary.
pub async fn update_self() -> stow_types::error::Result<()> {
    let mut updater = axoupdater::AxoUpdater::new_for("stow-cli");
    if let Ok(token) = std::env::var("STOW_CLI_GITHUB_TOKEN")
        .or_else(|_| std::env::var("GITHUB_TOKEN"))
        .or_else(|_| std::env::var("GH_TOKEN"))
    {
        updater.set_github_token(&token);
    }
    updater.load_receipt().map_err(|error| {
        stow_types::stow_error!(
            "no install receipt — this binary was not installed by the stow \
             installer, so it cannot update itself ({error})"
        )
    })?;
    update_with(updater).await
}

/// The update proper once a receipt is loaded, split from the updater's
/// construction so a test can drive it with the state a receipt would
/// produce — a foreign `install_prefix` via `set_install_dir` — without
/// mutating the process environment axoupdater reads its paths from.
async fn update_with(mut updater: axoupdater::AxoUpdater) -> stow_types::error::Result<()> {
    if !updater
        .check_receipt_is_for_this_executable()
        .map_err(|error| stow_types::stow_error!("check the install receipt: {error}"))?
    {
        let prefix = updater
            .install_prefix_root()
            .map_or_else(|_| "<unknown>".to_owned(), |root| root.to_string());
        return Err(stow_types::stow_error!(
            "the install receipt records a different install prefix ({prefix}) — \
             this stow was not installed by the installer and cannot update itself"
        ));
    }
    // The installer replaces the executable at this path, which reads as
    // deleted afterwards on Linux and is renamed aside on Windows.
    let exe = std::env::current_exe().wrap_err("resolve the current executable")?;
    let result = updater
        .run()
        .await
        .map_err(|error| stow_types::stow_error!("update stow-cli: {error}"))?;
    match &result {
        Some(update) => write_stdout(&format!(
            "updated stow-cli to {} ({})\n",
            update.new_version, update.new_version_tag
        ))?,
        None => write_stdout("stow-cli is already up to date\n")?,
    }
    let installed = result.as_ref().map(|update| update.new_version.to_string());
    if let Some(report) = restart_daemon_after(
        installed.as_deref(),
        &exe,
        crate::daemon::client::retire_onto,
    )
    .await?
    {
        write_stdout(&format!("{report}\n"))?;
    }
    let wrappers = detect_wrapper_commands()?;
    tracing::info!(
        rustc_wrapper = %wrappers.rustc,
        cc_compiler = %wrappers.cc_compiler,
        "refreshed wrapper shims"
    );
    Ok(())
}

/// Put the running daemon onto the stow an update installed. The process
/// that ran the update is the old binary, at the version the daemon runs,
/// so the daemon is asked to retire onto `exe`, where the new one now is.
/// Nothing is asked when the update installed nothing (`installed` is
/// `None`), and a daemon that is not running is not started.
///
/// Returns what to tell the person, if anything.
///
/// # Errors
///
/// The daemon cannot be restarted, or comes back as a stow other than the
/// installed one.
async fn restart_daemon_after(
    installed: Option<&str>,
    exe: &Path,
    retire: impl AsyncFnOnce(&Path) -> stow_types::error::Result<Option<Restarted>>,
) -> stow_types::error::Result<Option<String>> {
    let Some(installed) = installed else {
        return Ok(None);
    };
    let Some(restarted) = retire(exe).await? else {
        return Ok(None);
    };
    if restarted.now != installed {
        return Err(stow_types::stow_error!(
            "the stow daemon restarted as stow {}, but stow {installed} was installed: \
             the executable that starts the daemon is not the one installed{}",
            restarted.now,
            if cfg!(windows) {
                "; run `stow setup` to register the installed stow's task"
            } else {
                ""
            }
        ));
    }
    Ok(Some(format!(
        "restarted the stow daemon: {} -> {}",
        restarted.left, restarted.now
    )))
}

/// `stow stats`: print this install's own cache counters — served hits,
/// misses, errors, CPU time saved, bytes served and bytes downloaded —
/// from `stats.json`
/// and the per-crate counters in the cache directory. Local-only: the
/// command sends nothing.
pub async fn stats_command(args: StatsArgs, state_db: &StateDb) -> stow_types::error::Result<()> {
    let config = StowConfig::load(state_db.clone())?;
    let report = stats_report(&config).await?;
    if args.json {
        let body = serde_json::to_string(&report).wrap_err("serialize local stats")?;
        write_stdout(&format!("{body}\n"))
    } else {
        write_stdout(&local_stats_table(&report))
    }
}

/// The counters `stow stats` reports: the bundle-level totals from
/// `stats.json` plus the per-crate lookup counters from `crate_stats`.
#[derive(Debug, serde::Serialize)]
struct StatsReport {
    /// Served cache hits.
    hits: u64,
    /// Lookups the edge had no artifact for.
    misses: u64,
    /// Lookups that failed without producing a miss.
    errors: u64,
    /// Sum of the served bundles' recorded compile times.
    cpu_millis_saved: u64,
    /// Sum of every served cache entry's byte size.
    bytes_served: u64,
    /// The part of `bytes_served` that crossed the network.
    bytes_downloaded: u64,
}

async fn stats_report(config: &StowConfig) -> stow_types::error::Result<StatsReport> {
    let local = stats::read_local_stats(config).await?;
    let summary = stats::read_summary(config).await?;
    Ok(StatsReport {
        hits: local.hits,
        misses: summary.rust_misses.saturating_add(summary.cc_misses),
        errors: summary.rust_errors.saturating_add(summary.cc_errors),
        cpu_millis_saved: local.cpu_millis_saved,
        bytes_served: local.bytes_served,
        bytes_downloaded: local.bytes_downloaded,
    })
}

/// `12_345_678` → `"12,345,678"`.
fn grouped_count(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Compile milliseconds for the table: seconds under a minute, minutes
/// under an hour, hours above.
#[expect(
    clippy::cast_precision_loss,
    reason = "saved CPU time is far below 2^53 milliseconds"
)]
fn format_cpu_millis(millis: u64) -> String {
    if millis >= 3_600_000 {
        format!("{:.1} h", millis as f64 / 3_600_000.0)
    } else if millis >= 60_000 {
        format!("{:.1} min", millis as f64 / 60_000.0)
    } else {
        format!("{:.1} s", millis as f64 / 1_000.0)
    }
}

/// Byte counts for the table, in binary units.
#[expect(
    clippy::cast_precision_loss,
    reason = "downloaded bytes are far below 2^53"
)]
fn format_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    const KIB: u64 = 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// The short table `stow stats` prints.
fn local_stats_table(report: &StatsReport) -> String {
    format!(
        "cache hits          {}\ncache misses        {}\ncache errors        {}\nCPU time saved      {}\nbytes served        {}\nbytes downloaded    {}\n",
        grouped_count(report.hits),
        grouped_count(report.misses),
        grouped_count(report.errors),
        format_cpu_millis(report.cpu_millis_saved),
        format_bytes(report.bytes_served),
        format_bytes(report.bytes_downloaded),
    )
}

/// `stow clean`: remove cached artifacts and build directories while
/// preserving verified index slices and local stats (`--all` removes the
/// entire `$STOW_CACHE_DIR`).
pub async fn clean_project(
    args: crate::cli_args::CleanArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<()> {
    let cache_dir = config::cache_dir(&SessionEnv::of_this_process()?)?;
    if !cache_dir.exists() {
        write_stdout(&format!("cache dir missing: {}\n", cache_dir.display()))?;
        return Ok(());
    }
    let _ = tokio::task::spawn_blocking(|| -> stow_types::error::Result<bool> {
        let exe = std::env::current_exe().wrap_err("resolve current executable")?;
        let settings = crate::daemon::Settings::from_env()?;
        crate::daemon::stop_if_running(&exe, settings)
    })
    .await;
    let skipped_build_dirs = clean_cache_dir(&cache_dir, args.all, state_db).await?;
    if skipped_build_dirs > 0 {
        let noun = if skipped_build_dirs == 1 {
            "directory"
        } else {
            "directories"
        };
        write_stdout(&format!(
            "removed {} (skipped {skipped_build_dirs} active build {noun} under {BUILD_DIR_PARENT})\n",
            cache_dir.display()
        ))
    } else {
        write_stdout(&format!("removed {}\n", cache_dir.display()))
    }
}

async fn clean_cache_dir(
    cache_dir: &Path,
    all: bool,
    state_db: &StateDb,
) -> stow_types::error::Result<usize> {
    // Handle `state-v3.sqlite3` before removing subdirectories so a concurrent
    // build holding a lock under `build-dir` can never leave an incompatible
    // state database behind blocking subsequent commands.
    if all {
        state_db.close().await;
        crate::state_db::remove_state_db_files(cache_dir).await?;
    } else {
        state_db.close_tiers().await;
        if crate::state_db::state_db_path(cache_dir).exists() {
            match state_db.pool(cache_dir).await {
                Ok(pool) => crate::state_db::clear_cached_entries(&pool).await?,
                Err(error) => {
                    tracing::info!(
                        %error,
                        "state database could not be opened under current schema; removing it"
                    );
                    crate::state_db::remove_state_db_files(cache_dir).await?;
                }
            }
        }
    }

    let mut skipped_build_dirs = 0usize;
    let mut entries = async_fs::read_dir(cache_dir)
        .await
        .wrap_err_with(|| format!("read cache dir {}", cache_dir.display()))?;
    while let Some(entry) = futures_lite::StreamExt::try_next(&mut entries)
        .await
        .wrap_err_with(|| format!("iterate cache dir {}", cache_dir.display()))?
    {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !all
            && (matches!(name_str.as_ref(), "index" | "stats.json")
                || crate::state_db::is_state_db_file(&name_str))
        {
            continue;
        }
        let path = entry.path();
        let kind = match entry.file_type().await {
            Ok(kind) => kind,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).wrap_err_with(|| format!("stat {}", path.display())),
        };
        if kind.is_dir() && name_str.as_ref() == BUILD_DIR_PARENT {
            skipped_build_dirs +=
                tokio::task::spawn_blocking(move || crate::build_dirs::clean_all(&path))
                    .await
                    .wrap_err("join build-dir clean task")??;
        } else if kind.is_dir() {
            remove_cache_subdir(&path).await?;
        } else {
            match async_fs::remove_file(&path).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).wrap_err_with(|| format!("remove {}", path.display()));
                }
            }
        }
    }

    if all {
        match async_fs::remove_dir(cache_dir).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::DirectoryNotEmpty
                    && skipped_build_dirs > 0 => {}
            Err(error) => {
                return Err(error)
                    .wrap_err_with(|| format!("remove cache dir {}", cache_dir.display()));
            }
        }
    }
    Ok(skipped_build_dirs)
}

/// Remove a cache subdirectory without racing against processes that recreate
/// entries under the original path: on Unix, atomically rename it aside first.
async fn remove_cache_subdir(path: &Path) -> stow_types::error::Result<()> {
    #[cfg(unix)]
    let target = {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name.starts_with(".clean-") {
            path.to_path_buf()
        } else {
            let aside = path.with_file_name(format!(".clean-{}-{name}", std::process::id()));
            match async_fs::rename(path, &aside).await {
                Ok(()) => aside,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => {
                    return Err(error).wrap_err_with(|| format!("move {} aside", path.display()));
                }
            }
        }
    };
    #[cfg(not(unix))]
    let target = path.to_path_buf();

    match async_fs::remove_dir_all(&target).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).wrap_err_with(|| format!("remove {}", target.display())),
    }
}

/// `stow check-artifact`: resolve `c_metadata` against the verified index
/// slice and report the bundle digest the index pins for it.
pub async fn check_artifact(
    args: CheckArtifactArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<()> {
    let config = StowConfig::load(state_db.clone())?;
    let slice = index::ensure_slice(&config, &args.target, &args.rustc_version).await?;

    match resolve::find_exact_artifact(&slice.index.rows, &args.c_metadata) {
        Some(row) => {
            write_stdout(&format!(
                "status: present\ncrate: {} {}\nbundle-digest: {}\nindex-manifest: {}\n",
                row.crate_name.as_str(),
                row.version.as_semver(),
                row.bundle_digest,
                slice.manifest_digest.as_deref().unwrap_or("none"),
            ))?;
        }
        None => {
            write_stdout(&format!(
                "status: absent\nc-metadata: {}\nindex-manifest: {}\n",
                args.c_metadata,
                slice.manifest_digest.as_deref().unwrap_or("none"),
            ))?;
        }
    }
    Ok(())
}

/// `stow fetch-artifact`: resolve `c_metadata` against the index slice,
/// stream the bundle through the edge byte path (digest-checked against
/// the index), and write it to disk.
pub async fn fetch_artifact(
    args: FetchArtifactArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<()> {
    let config = StowConfig::load(state_db.clone())?;
    let slice = index::ensure_slice(&config, &args.target, &args.rustc_version).await?;
    let row =
        resolve::find_exact_artifact(&slice.index.rows, &args.c_metadata).ok_or_else(|| {
            stow_types::stow_error!(
                "index slice for {} {} carries no artifact {}",
                args.target,
                args.rustc_version,
                args.c_metadata
            )
        })?;
    let bundle_ref = fetch::BundleRef::from_index_row(&args.target, &args.rustc_version, row);
    let bytes = fetch::download_bundle_bytes(&config, &bundle_ref)
        .await
        .map_err(|error| stow_types::stow_error!("download artifact bundle: {error}"))?;

    if let Some(parent) = args.output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        async_fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("create parent directory {}", parent.display()))?;
    }
    async_fs::write(&args.output_path, &bytes)
        .await
        .wrap_err_with(|| format!("write artifact to {}", args.output_path.display()))?;

    write_stdout(&format!(
        "downloaded {}\nbytes: {}\n",
        args.output_path.display(),
        bytes.len()
    ))?;
    Ok(())
}

/// `stow index refresh`: force-fetch and verify the index slice for one
/// toolchain — `--target`/`--rustc-version` override the `rustc` probe.
pub async fn index_refresh(
    args: IndexRefreshArgs,
    state_db: &StateDb,
) -> stow_types::error::Result<()> {
    let config = StowConfig::load(state_db.clone())?;
    let target = resolve_index_target(args.target).await?;
    let rustc_version = resolve_index_rustc_version(args.rustc_version).await?;
    let slice = index::refresh_slice(&config, &target, &rustc_version).await?;
    write_stdout(&format!(
        "index: {}\ntarget: {}\nrustc-version: {}\nrows: {}\nmanifest-digest: {}\n",
        stow_types::index::index_tag(&target, &rustc_version),
        target,
        rustc_version,
        slice.index.rows.len(),
        slice.manifest_digest.as_deref().unwrap_or("none"),
    ))?;
    Ok(())
}

/// `stow index status`: every verified index slice in the local cache.
pub async fn index_status(state_db: &StateDb) -> stow_types::error::Result<()> {
    let config = StowConfig::load(state_db.clone())?;
    let slices = index::cached_slices(&config).await?;
    if slices.is_empty() {
        write_stdout("no cached index slices\n")?;
        return Ok(());
    }
    let mut output = String::new();
    for slice in slices {
        let _ = writeln!(
            output,
            "index: {}\ntarget: {}\nrustc-version: {}\nrows: {}\nfetched-at: {}\nmanifest-digest: {}\n",
            stow_types::index::index_tag(&slice.target, &slice.rustc_version),
            slice.target,
            slice.rustc_version,
            slice.row_count,
            slice.fetched_at,
            slice.manifest_digest,
        );
    }
    write_stdout(&output)?;
    Ok(())
}

async fn resolve_index_target(overridden: Option<String>) -> stow_types::error::Result<String> {
    match overridden {
        Some(target) => Ok(target),
        None => detect_rustc_host_target(
            std::ffi::OsStr::new("rustc"),
            &SessionEnv::of_this_process()?,
        )
        .await
        .map_err(|error| stow_types::stow_error!("detect rustc host target: {error}")),
    }
}

async fn resolve_index_rustc_version(
    overridden: Option<String>,
) -> stow_types::error::Result<String> {
    match overridden {
        Some(rustc_version) => Ok(rustc_version),
        None => detect_rustc_version(
            std::ffi::OsStr::new("rustc"),
            &SessionEnv::of_this_process()?,
        )
        .await
        .map_err(|error| stow_types::stow_error!("detect rustc version: {error}")),
    }
}

/// `stow purge-cache-dir`: remove a list of cache directories.
pub async fn purge_cache_dirs(args: PurgeCacheDirArgs) -> stow_types::error::Result<()> {
    smol::unblock(move || {
        for path in args.paths {
            if !path.exists() {
                continue;
            }
            std::fs::remove_dir_all(&path)
                .wrap_err_with(|| format!("purge stale cache directory {}", path.display()))?;
        }
        Ok(())
    })
    .await
}

fn set_build_wrapper(document: &mut DocumentMut, wrapper_command: &str) {
    let build = ensure_table(document, "build");
    build["rustc-wrapper"] = Item::Value(Value::from(wrapper_command));
}

fn set_env_wrapper(document: &mut DocumentMut, key: &str, value: &str) {
    let env = ensure_table(document, "env");
    let mut table = Table::new();
    table["value"] = Item::Value(Value::from(value));
    table["force"] = Item::Value(Value::from(true));
    env[key] = Item::Table(table);
}

fn ensure_table<'a>(document: &'a mut DocumentMut, key: &str) -> &'a mut Table {
    if !document.get(key).is_some_and(Item::is_table) {
        document.insert(key, Item::Table(Table::new()));
    }
    document
        .get_mut(key)
        .expect("table inserted above must exist")
        .as_table_mut()
        .expect("table inserted above must exist")
}

fn env_value<'a>(document: &'a DocumentMut, key: &str) -> Option<&'a str> {
    document
        .get("env")
        .and_then(Item::as_table)
        .and_then(|table| table.get(key))
        .and_then(Item::as_table_like)
        .and_then(|entry| entry.get("value"))
        .and_then(Item::as_str)
}

pub struct WrapperCommands {
    pub(crate) rustc: String,
    /// Launcher-shaped; the program to run arrives as the first argument.
    pub(crate) cc_launcher: String,
    /// Compiler-shaped; invoked with compiler arguments only.
    pub(crate) cc_compiler: String,
    /// Compiler-shaped, for C++.
    pub(crate) cxx_compiler: String,
    /// The executable the shims resolve to — the path
    /// [`crate::config::shims_dir`] keyed on, and the binary the daemon's
    /// launch agent runs (stow#645).
    pub(crate) runtime_executable: PathBuf,
}

/// Resolved runtime/capture executables and shim directory prior to writing.
struct ResolvedWrapperPlan {
    shims_dir: PathBuf,
    runtime_executable: PathBuf,
    capture_executable: PathBuf,
}

fn resolve_wrapper_executables(
    cargo_home: &Path,
) -> stow_types::error::Result<ResolvedWrapperPlan> {
    let current_exe = std::env::current_exe().wrap_err("resolve current executable")?;
    let runtime_executable =
        std::env::var_os("STOW_WRAPPER_PATH").map_or_else(|| current_exe.clone(), PathBuf::from);
    let runtime_executable = if runtime_executable.exists() {
        runtime_executable
    } else {
        current_exe
    };
    let capture_exe = sibling_binary(&runtime_executable, "stow-build");
    let capture_exe = if capture_exe.exists() {
        capture_exe
    } else {
        runtime_executable.clone()
    };
    let file_name = runtime_executable
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    let runtime_executable = if matches!(file_name, "stow-cli" | "stow" | "cargo-stow") {
        runtime_executable
    } else {
        let sibling = sibling_binary(&runtime_executable, "stow-cli");
        if sibling.exists() {
            sibling
        } else {
            runtime_executable
        }
    };
    let capture_executable = {
        let sibling_capture = sibling_binary(&runtime_executable, "stow-build");
        if sibling_capture.exists() {
            sibling_capture
        } else {
            capture_exe
        }
    };
    // The shim dir is one per (cargo home, stow binary), so a second
    // install never re-points this binary's shims (stow#645). The old
    // per-user shim files under `stow/tools` are deliberately left alone:
    // another cargo home's `config.toml` may still name them.
    let shims_dir = config::shims_dir(cargo_home, &runtime_executable);
    Ok(ResolvedWrapperPlan {
        shims_dir,
        runtime_executable,
        capture_executable,
    })
}

fn materialize_wrappers(plan: &ResolvedWrapperPlan) -> stow_types::error::Result<WrapperCommands> {
    let shims = wrapper_shim::materialize_wrapper_shims(
        &plan.shims_dir,
        &plan.runtime_executable,
        &plan.capture_executable,
    )?;
    Ok(WrapperCommands {
        rustc: shim_path(&shims.rustc_wrapper, "rustc wrapper")?,
        cc_launcher: shim_path(&shims.cc_launcher, "cc launcher")?,
        cc_compiler: shim_path(&shims.cc_compiler, "cc compiler")?,
        cxx_compiler: shim_path(&shims.cxx_compiler, "cxx compiler")?,
        runtime_executable: plan.runtime_executable.clone(),
    })
}

pub fn detect_wrapper_commands() -> stow_types::error::Result<WrapperCommands> {
    let plan = resolve_wrapper_executables(&config::require_cargo_home()?)?;
    materialize_wrappers(&plan)
}

fn shim_path(path: &std::path::Path, what: &str) -> stow_types::error::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| stow_types::stow_error!("{what} path {} is not UTF-8", path.display()))
}

fn sibling_binary(current_exe: &Path, name: &str) -> PathBuf {
    // The on-disk name carries the platform suffix — `stow-build.exe`
    // beside `stow-cli.exe` on Windows — so a bare join never resolves
    // there and silently falls back to the runtime itself (stow#588).
    let name = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    current_exe
        .parent()
        .map_or_else(|| PathBuf::from(&name), |parent| parent.join(&name))
}

/// The compiler the caller configured for `target`, in the order the `cc`
/// crate consults the same variables: `STOW_REAL_*` (the value setup
/// recorded), then `<base>_<target>`, `<base>_<target_underscored>`,
/// `TARGET_<base>`, `HOST_<base>`, `<base>`. `None` means no toolchain was
/// configured — the shim then resolves the platform's compiler itself.
///
/// The environment is an injected lookup — `std::env::var_os` on the real
/// path — so a test answers it from a fixture instead of mutating the
/// process environment its siblings share.
fn configured_compiler(
    real_env: &str,
    base_env: &str,
    target: &str,
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<String> {
    let scoped = target.replace(['-', '.'], "_");
    let lookup = |key: &str| {
        env(key)
            .and_then(|value| value.into_string().ok())
            .filter(|value| !value.trim().is_empty() && !is_stow_owned_value(value))
    };
    lookup(real_env)
        .or_else(|| lookup(&format!("{base_env}_{target}")))
        .or_else(|| lookup(&format!("{base_env}_{scoped}")))
        .or_else(|| lookup(&format!("TARGET_{base_env}")))
        .or_else(|| lookup(&format!("HOST_{base_env}")))
        .or_else(|| lookup(base_env))
}

/// The C compiler the caller configured for `target`, or `None` when none
/// is — setup records it as `STOW_REAL_CC`; with no entry the shim
/// resolves per invocation the way the `cc` crate does.
pub fn configured_c_compiler(target: &str) -> Option<String> {
    configured_compiler("STOW_REAL_CC", "CC", target, |key| std::env::var_os(key))
}

/// The C++ compiler the caller configured for `target`; see
/// [`configured_c_compiler`].
pub fn configured_cxx_compiler(target: &str) -> Option<String> {
    configured_compiler("STOW_REAL_CXX", "CXX", target, |key| std::env::var_os(key))
}

/// `.cargo/config.toml` files in `dir`'s ancestors that still carry stow's
/// old per-project wiring — they shadow the global config. `cargo_home` is
/// passed explicitly so `cargo-config2` never falls back to the process
/// `CARGO_HOME` during tests, and `$CARGO_HOME/config.toml` itself is
/// excluded as the global write target. Returns every file holding a
/// stow-owned value.
fn stale_project_configs(dir: &Path, cargo_home: &Path) -> Vec<PathBuf> {
    let exclude = cargo_home.join("config.toml");
    let mut stale = Vec::new();
    for path in cargo_config2::Walk::with_cargo_home(dir, Some(cargo_home.to_path_buf())) {
        if path == exclude {
            continue;
        }
        let Ok(contents) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(document) = contents.parse::<DocumentMut>() else {
            continue;
        };
        if document_is_stow_wired(&document) || document_build_dir_is_stow(&document) {
            stale.push(path);
        }
    }
    stale
}

/// Remove stow's old per-project wiring from every ancestor
/// `.cargo/config.toml` of `dir`, returning the cleaned paths. Keys are
/// removed by value — only entries pointing at stow's shims or tools dir —
/// so a user's own `CC`, `COMPILER_PATH` or `rustc-wrapper` survives.
fn clean_stale_project_configs(
    dir: &Path,
    cargo_home: &Path,
) -> stow_types::error::Result<Vec<PathBuf>> {
    let mut cleaned = Vec::new();
    for path in stale_project_configs(dir, cargo_home) {
        let contents =
            std::fs::read_to_string(&path).wrap_err_with(|| format!("read {}", path.display()))?;
        let mut document = contents
            .parse::<DocumentMut>()
            .wrap_err_with(|| format!("parse {}", path.display()))?;
        clean_stow_owned_entries(&mut document, LinkerSelection::Strip);
        std::fs::write(&path, document.to_string())
            .wrap_err_with(|| format!("write {}", path.display()))?;
        cleaned.push(path);
    }
    Ok(cleaned)
}

/// Whether `document`'s own entries select mold — a `linker` naming it
/// or a rustflag mentioning it under `build`, any `target` table, or the
/// `[env]` `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS`. `stow setup`'s report
/// follows the file it wrote: a mold selected only by the ambient
/// environment is not the file's selection.
fn document_selects_mold(document: &DocumentMut) -> bool {
    fn flags_select(item: &Item) -> bool {
        (item.is_array() || item.is_str())
            && mold::rustflags_value(item)
                .iter()
                .any(|flag| mold::flag_mentions_mold(flag))
    }
    fn table_selects(table: &dyn toml_edit::TableLike) -> bool {
        table
            .get("linker")
            .and_then(Item::as_str)
            .is_some_and(|linker| linker.contains("mold"))
            || table.get("rustflags").is_some_and(flags_select)
    }
    if document
        .get("build")
        .and_then(Item::as_table_like)
        .is_some_and(table_selects)
    {
        return true;
    }
    if let Some(target) = document.get("target").and_then(Item::as_table_like) {
        for (_, table) in target.iter() {
            if table.as_table_like().is_some_and(table_selects) {
                return true;
            }
        }
    }
    document
        .get("env")
        .and_then(Item::as_table_like)
        .is_some_and(|env| {
            ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"].iter().any(|key| {
                env.get(key).and_then(env_item_value).is_some_and(|flags| {
                    flags
                        .split(['\u{1f}', ' ', '\t'])
                        .any(mold::flag_mentions_mold)
                })
            })
        })
}

/// Cargo's template for a per-workspace directory: a hash of the
/// workspace's path, so two workspaces never share a build directory
/// (cargo locks one whole).
const WORKSPACE_PATH_HASH: &str = "{workspace-path-hash}";

/// The `build.build-dir` value `stow setup` writes for `cache_dir`:
/// `<cache_dir>/build-dir/{workspace-path-hash}`, absolute, so the config
/// means the same thing from every directory.
fn stow_build_dir_template(cache_dir: &Path) -> stow_types::error::Result<String> {
    let root = std::path::absolute(cache_dir)
        .wrap_err_with(|| format!("resolve cache directory {}", cache_dir.display()))?;
    let template = root.join(BUILD_DIR_PARENT).join(WORKSPACE_PATH_HASH);
    template
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| stow_types::stow_error!("{} is not UTF-8", template.display()))
}

/// Whether `value` is a build directory stow placed: a per-workspace
/// directory under a `build-dir` directory, whichever cache root it names.
fn is_stow_build_dir(value: &str) -> bool {
    let mut components = Path::new(value.trim()).components().rev();
    components
        .next()
        .is_some_and(|leaf| leaf.as_os_str() == WORKSPACE_PATH_HASH)
        && components
            .next()
            .is_some_and(|parent| parent.as_os_str() == BUILD_DIR_PARENT)
}

fn document_build_dir_is_stow(document: &DocumentMut) -> bool {
    document
        .get("build")
        .and_then(Item::as_table_like)
        .and_then(|build| build.get("build-dir"))
        .and_then(Item::as_str)
        .is_some_and(is_stow_build_dir)
}

const BUNDLED_STOW_SKILL: &str = include_str!("../skills/stow/SKILL.md");
const DETECTED_AGENT_DIR_NAMES: [&str; 2] = [".agents", ".claude"];

/// Deduplicate skill file paths across detected agent homes without creating
/// directories, respecting symlinks that already point at the same target.
fn deduplicated_skill_paths(agent_homes: &[PathBuf]) -> Vec<PathBuf> {
    let mut seen = std::collections::BTreeSet::new();
    let mut paths = Vec::new();
    for agent_home in agent_homes {
        let skill_dir = agent_home.join("skills").join("stow");
        let key = std::fs::canonicalize(&skill_dir).unwrap_or_else(|_| {
            std::fs::canonicalize(agent_home)
                .unwrap_or_else(|_| agent_home.clone())
                .join("skills")
                .join("stow")
        });
        if seen.insert(key) {
            paths.push(skill_dir.join("SKILL.md"));
        }
    }
    paths
}

/// Compute the coding-agent skill targets `stow setup` plans to install or offer.
fn planned_skill_targets(
    args: &SetupArgs,
    interactive: bool,
) -> stow_types::error::Result<Vec<SkillTargetPlan>> {
    use crate::cli_args::SkillInstallPolicy;

    let policy = args.skill.policy();
    if policy == SkillInstallPolicy::Skip {
        return Ok(Vec::new());
    }
    let Some(home) = dirs::home_dir() else {
        if policy == SkillInstallPolicy::Install {
            return Err(stow_types::stow_error!(
                "resolve home directory for --install-skill"
            ));
        }
        return Ok(Vec::new());
    };
    let detected = detected_agent_homes(&home);
    if policy == SkillInstallPolicy::Install {
        let targets = if detected.is_empty() {
            vec![home.join(".agents")]
        } else {
            detected
        };
        return Ok(deduplicated_skill_paths(&targets)
            .into_iter()
            .map(|path| SkillTargetPlan {
                path,
                mode: SkillPlanMode::Install,
            })
            .collect());
    }
    if !interactive
        || detected.is_empty()
        || !agent_homes_need_skill_update(&detected, BUNDLED_STOW_SKILL)
    {
        return Ok(Vec::new());
    }
    Ok(deduplicated_skill_paths(&detected)
        .into_iter()
        .map(|path| SkillTargetPlan {
            path,
            mode: SkillPlanMode::Prompt,
        })
        .collect())
}

async fn maybe_setup_stow_skill(
    args: &SetupArgs,
    interactive: bool,
) -> stow_types::error::Result<Vec<PathBuf>> {
    use crate::cli_args::SkillInstallPolicy;

    let policy = args.skill.policy();
    if policy == SkillInstallPolicy::Skip {
        return Ok(Vec::new());
    }
    let Some(home) = dirs::home_dir() else {
        if policy == SkillInstallPolicy::Install {
            return Err(stow_types::stow_error!(
                "resolve home directory for --install-skill"
            ));
        }
        return Ok(Vec::new());
    };
    let detected = detected_agent_homes(&home);
    if policy == SkillInstallPolicy::Install {
        let targets = if detected.is_empty() {
            vec![home.join(".agents")]
        } else {
            detected
        };
        return install_bundled_stow_skill(&targets);
    }
    if !interactive
        || detected.is_empty()
        || !agent_homes_need_skill_update(&detected, BUNDLED_STOW_SKILL)
        || !std::io::stderr().is_terminal()
    {
        return Ok(Vec::new());
    }
    let labels = detected
        .iter()
        .filter_map(|dir| {
            dir.file_name()
                .map(|n| format!("~/{}", n.to_string_lossy()))
        })
        .collect::<Vec<_>>()
        .join(", ");
    let approved = smol::unblock(move || prompt_skill_install(&labels)).await?;
    if approved {
        install_bundled_stow_skill(&detected)
    } else {
        Ok(Vec::new())
    }
}

fn detected_agent_homes(home: &Path) -> Vec<PathBuf> {
    DETECTED_AGENT_DIR_NAMES
        .into_iter()
        .map(|name| home.join(name))
        .filter(|path| path.is_dir())
        .collect()
}

fn agent_homes_need_skill_update(agent_homes: &[PathBuf], expected: &str) -> bool {
    agent_homes.iter().any(|agent_home| {
        let skill_file = agent_home.join("skills/stow/SKILL.md");
        std::fs::read_to_string(&skill_file).map_or(true, |current| current != expected)
    })
}

fn prompt_skill_install(labels: &str) -> stow_types::error::Result<bool> {
    use std::io::Write as _;
    let mut stderr = std::io::stderr();
    write!(
        stderr,
        "Install the stow skill for coding agents ({labels})? [Y/n]: "
    )
    .wrap_err("write skill install prompt")?;
    stderr.flush().wrap_err("flush skill install prompt")?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .wrap_err("read skill install answer")?;
    let trimmed = answer.trim();
    Ok(trimmed.is_empty() || matches!(trimmed, "y" | "Y" | "yes" | "YES"))
}

fn install_bundled_stow_skill(agent_homes: &[PathBuf]) -> stow_types::error::Result<Vec<PathBuf>> {
    let mut seen_canonical_dirs = std::collections::BTreeSet::new();
    let mut written = Vec::new();
    for agent_home in agent_homes {
        let skill_dir = agent_home.join("skills").join("stow");
        if let Ok(canonical) = std::fs::canonicalize(&skill_dir)
            && !seen_canonical_dirs.insert(canonical)
        {
            continue;
        }
        std::fs::create_dir_all(&skill_dir)
            .wrap_err_with(|| format!("create {}", skill_dir.display()))?;
        if let Ok(canonical) = std::fs::canonicalize(&skill_dir) {
            seen_canonical_dirs.insert(canonical);
        }
        let skill_file = skill_dir.join("SKILL.md");
        std::fs::write(&skill_file, BUNDLED_STOW_SKILL)
            .wrap_err_with(|| format!("write {}", skill_file.display()))?;
        written.push(skill_file);
    }
    Ok(written)
}

/// Where setup left this machine's build directory.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BuildDirPlacement {
    /// Stow's own template, written by this setup.
    Stow(String),
    /// A build directory the user configured — a cargo config file in
    /// scope of the current directory or `CARGO_BUILD_BUILD_DIR` — which
    /// setup leaves alone.
    User(String),
    /// Explicitly skipped via `--no-build-dir`: Cargo keeps its standard
    /// `target/` layout and any previously stow-placed `build.build-dir`
    /// is removed.
    Disabled,
}

impl BuildDirPlacement {
    fn stow_template(&self) -> Option<&str> {
        match self {
            Self::Stow(template) => Some(template),
            Self::User(_) | Self::Disabled => None,
        }
    }

    fn value_text(&self) -> String {
        match self {
            Self::Stow(template) => template.clone(),
            Self::User(user) => format!("{user} (already configured, left alone)"),
            Self::Disabled => "target/ (--no-build-dir)".to_owned(),
        }
    }
}

/// The `build.build-dir` the user configured machine-wide — the
/// `CARGO_BUILD_BUILD_DIR` variable, which cargo ranks first, else a value
/// in `$CARGO_HOME/config.toml` — or `None` when there is none or it is one
/// stow placed. Project configs are not consulted: cargo ranks them above
/// the global file, so a project's own build directory wins for that
/// project without stopping setup from placing the global one.
fn user_build_dir(
    cargo_home: &Path,
    env: &SessionEnv,
) -> stow_types::error::Result<Option<String>> {
    if let Some(value) = env.var_os("CARGO_BUILD_BUILD_DIR") {
        return Ok(Some(value.to_string_lossy().into_owned()));
    }
    let path = cargo_home.join("config.toml");
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).wrap_err_with(|| format!("read {}", path.display())),
    };
    let document = contents
        .parse::<DocumentMut>()
        .wrap_err_with(|| format!("parse {}", path.display()))?;
    Ok(document
        .get("build")
        .and_then(Item::as_table_like)
        .and_then(|build| build.get("build-dir"))
        .and_then(Item::as_str)
        .filter(|dir| !is_stow_build_dir(dir))
        .map(str::to_owned))
}

/// Whether `document` holds any value stow's wiring owns — a
/// `rustc-wrapper` or an `[env]` entry pointing at a stow shim or the
/// tools dir.
fn document_is_stow_wired(document: &DocumentMut) -> bool {
    let rustc_wrapper_is_stow = document
        .get("build")
        .and_then(Item::as_table)
        .and_then(|build| build.get("rustc-wrapper"))
        .and_then(Item::as_str)
        .is_some_and(is_stow_owned_value);
    let env_has_stow_value = document
        .get("env")
        .and_then(Item::as_table)
        .is_some_and(|env| {
            env.iter()
                .any(|(_, item)| env_item_value(item).is_some_and(is_stow_owned_value))
        });
    rustc_wrapper_is_stow || env_has_stow_value
}

/// What `clean_stow_owned_entries` does with stow's linker selection —
/// the `target`-table rustflags and the stow-owned `env.COMPILER_PATH`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LinkerSelection {
    /// Leave it in the document: the caller either rewrites it in place
    /// through `mold::write_linker_selection` or — the configuration
    /// already selects a reachable mold — keeps it exactly as it stands.
    Keep,
    /// Strip it: a project-level config must not carry the wiring the
    /// global file owns.
    Strip,
}

/// Remove the entries older stow versions wrote into `document`, by value:
/// any `build.rustc-wrapper` or `[env]` entry pointing at a stow shim or
/// the tools dir, the `STOW_REAL_*` companion variables once the document
/// is proven stow-wired, the `PATH`/`LIB`/`LIBPATH`/`INCLUDE` MSVC
/// toolchain snapshot an earlier revision persisted, and — when
/// `linker_selection` is [`LinkerSelection::Strip`] — stow's mold
/// rustflags inside `target` tables and the stow-owned `env.COMPILER_PATH`.
/// Returns whether anything changed.
fn clean_stow_owned_entries(document: &mut DocumentMut, linker_selection: LinkerSelection) -> bool {
    let mut changed = false;
    let wired = document_is_stow_wired(document);

    if document_build_dir_is_stow(document)
        && let Some(build) = document.get_mut("build").and_then(Item::as_table_mut)
    {
        build.remove("build-dir");
        changed = true;
    }

    if wired
        && let Some(build) = document.get_mut("build").and_then(Item::as_table_mut)
        && build
            .get("rustc-wrapper")
            .is_some_and(|item| item.as_str().is_some_and(is_stow_owned_value))
    {
        build.remove("rustc-wrapper");
        changed = true;
    }

    if let Some(env) = document.get_mut("env").and_then(Item::as_table_like_mut) {
        let keys: Vec<String> = env.iter().map(|(key, _)| key.to_owned()).collect();
        for key in keys {
            let remove = match env.get(&key).and_then(env_item_value) {
                // `env.COMPILER_PATH` is half of the linker selection —
                // `Keep` leaves it for `write_linker_selection`, which
                // overwrites the key when a new selection is written.
                Some(value) if is_stow_owned_value(value) => {
                    linker_selection == LinkerSelection::Strip || key != "COMPILER_PATH"
                }
                Some(value)
                    if matches!(key.as_str(), "PATH" | "LIB" | "LIBPATH" | "INCLUDE")
                        && is_msvc_snapshot_value(value) =>
                {
                    true
                }
                Some(_) if wired && key.starts_with("STOW_REAL_") => true,
                _ => false,
            };
            if remove {
                env.remove(&key);
                changed = true;
            }
        }
    }

    // Stow's linker selection lives in `target` rustflags — strip it only
    // where the document already proved stow-wired by value, and only on
    // the caller that owns removal; the global config's copy is rewritten
    // in place by `write_linker_selection` or left standing.
    if linker_selection == LinkerSelection::Strip
        && wired
        && let Some(target) = document.get_mut("target").and_then(Item::as_table_mut)
    {
        for (_, table) in target.iter_mut() {
            let Some(table) = table.as_table_like_mut() else {
                continue;
            };
            let flags = match table.get("rustflags") {
                Some(item) if item.is_array() || item.is_str() => mold::rustflags_value(item),
                _ => continue,
            };
            let flag_count = flags.len();
            let kept = mold::strip_stow_linker_flags(flags);
            if kept.len() != flag_count {
                changed = true;
                if kept.is_empty() {
                    table.remove("rustflags");
                } else {
                    let mut array = toml_edit::Array::new();
                    array.extend(kept);
                    *table.get_mut("rustflags").expect("rustflags exists") =
                        Item::Value(Value::Array(array));
                }
            }
        }
    }
    changed
}

/// A value stow's wiring owns: a path to one of its shims, or anything
/// inside a directory stow installs into — the shims' home
/// (`<cargo home>/stow/shims`), the tools dir that hosts the mold install
/// (`<data>/stow/tools`), and the tools dir older releases used
/// (`/tmp/stow-tools`). The key holding a value never decides, so a
/// user's own `CC` or `COMPILER_PATH` survives.
pub fn is_stow_owned_value(value: &str) -> bool {
    const SHIM_STEMS: &[&str] = &[
        "stow-rustc-wrapper",
        "stow-cc",
        "stow-cxx",
        "stow-cc-launcher",
        "stow-runtime",
        "stow-capture",
    ];
    let path = Path::new(value.trim());
    if path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|stem| SHIM_STEMS.contains(&stem))
    {
        return true;
    }
    // Segment pairs stow installs under: "…/stow/tools/…", "…/stow/shims/…"
    // or "…/stow-tools/…".
    let mut previous_was_stow = false;
    for component in path.components() {
        let name = component.as_os_str().to_string_lossy();
        if name == "stow-tools" || (previous_was_stow && matches!(&*name, "tools" | "shims")) {
            return true;
        }
        previous_was_stow = name == "stow";
    }
    false
}

/// Whether an `[env]` value carries the MSVC toolchain snapshot an earlier
/// revision persisted under `PATH`/`LIB`/`LIBPATH`/`INCLUDE` — Visual
/// Studio's `MSVC` toolset or the Windows Kits SDK paths it recorded.
/// Identification is by content, so a user's own `PATH` entry survives.
fn is_msvc_snapshot_value(value: &str) -> bool {
    value.contains("MSVC") || value.contains("Windows Kits")
}

/// The string an `env` entry holds, accepting both cargo shapes —
/// `KEY = "…"` and `KEY = { value = "…", force = … }`.
fn env_item_value(item: &Item) -> Option<&str> {
    if let Some(value) = item.as_str() {
        return Some(value);
    }
    item.as_table_like()
        .and_then(|entry| entry.get("value"))
        .and_then(Item::as_str)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use super::{Restarted, WrapperCommands, setup_env_output};
    use crate::config::{StowConfig, VerifyMode};

    fn test_config(verify_mode: VerifyMode) -> StowConfig {
        StowConfig {
            cache: crate::config::CacheLayers::default(),
            edge_url: "https://stow.waterui.dev".to_owned(),
            registry_base_url: stow_types::registry::GHCR_REGISTRY_URL.to_owned(),
            cache_dir: PathBuf::from("/tmp/stow-cache"),
            request_timeout: Duration::from_mins(5),
            negative_cache_ttl: Duration::from_mins(5),
            circuit_reset_after: Duration::from_mins(1),
            circuit_trip_threshold: 5,
            artifact_cache_max_bytes: 1024,
            index_refresh_interval: Duration::from_mins(5),
            build_dir_idle: crate::config::DEFAULT_BUILD_DIR_IDLE,
            verify_mode,
            switches: crate::config::Switches::default(),
            state_db: crate::state_db::StateDb::default(),
            trust_material: std::sync::Arc::default(),
            registry_http: std::sync::Arc::default(),
            artifact_cache_staging: std::sync::Arc::default(),
            version_leases: crate::artifact_cache::SharedVersionLeases::default(),
        }
    }

    /// A tools-dir-shaped prefix for the wrapper fixtures; contents matter,
    /// not the platform spelling.
    const TEST_TOOLS_DIR: &str = "/home/user/.local/share/stow/tools";

    /// stow#1538 — the build directory setup writes is recognized as
    /// stow's whichever cache root it names, and removed with the rest of
    /// stow's wiring; a user's own is neither.
    #[test]
    fn the_build_dir_setup_writes_is_stows_to_write_and_to_remove() {
        let template =
            super::stow_build_dir_template(std::path::Path::new("/cache/stow")).expect("template");
        assert!(super::is_stow_build_dir(&template));
        assert!(super::is_stow_build_dir(
            "/elsewhere/build-dir/{workspace-path-hash}"
        ));
        assert!(!super::is_stow_build_dir("/home/user/mine"));
        assert!(!super::is_stow_build_dir(
            "/home/user/{workspace-path-hash}"
        ));

        let wrappers = test_wrappers();
        let mut document = toml_edit::DocumentMut::new();
        super::configure_document(&mut document, &wrappers, Vec::new(), None, Some(&template))
            .expect("configure");
        assert!(super::document_build_dir_is_stow(&document));
        // Re-running replaces the key in place.
        super::configure_document(&mut document, &wrappers, Vec::new(), None, Some(&template))
            .expect("configure again");
        assert_eq!(document.to_string().matches("build-dir =").count(), 1);

        super::clean_stow_owned_entries(&mut document, super::LinkerSelection::Strip);
        assert!(!document.to_string().contains("build-dir ="), "{document}");

        let mut user: toml_edit::DocumentMut = "[build]\nbuild-dir = \"/home/user/mine\"\n"
            .parse()
            .expect("parse");
        super::configure_document(&mut user, &wrappers, Vec::new(), None, None)
            .expect("configure user");
        super::clean_stow_owned_entries(&mut user, super::LinkerSelection::Strip);
        assert!(user.to_string().contains("/home/user/mine"));
    }

    fn test_wrappers() -> WrapperCommands {
        WrapperCommands {
            rustc: format!("{TEST_TOOLS_DIR}/stow-rustc-wrapper"),
            cc_launcher: format!("{TEST_TOOLS_DIR}/stow-cc-launcher"),
            cc_compiler: format!("{TEST_TOOLS_DIR}/stow-cc"),
            cxx_compiler: format!("{TEST_TOOLS_DIR}/stow-cxx"),
            runtime_executable: PathBuf::from("/usr/local/bin/stow-cli"),
        }
    }

    #[test]
    fn github_env_output_emits_every_wrapper_key() {
        let output = setup_env_output(
            &test_wrappers(),
            "x86_64-unknown-linux-gnu",
            Some("clang"),
            Some("clang++"),
            &test_config(VerifyMode::GithubCi),
        );
        let expected = String::from(
            "RUSTC_WRAPPER=/home/user/.local/share/stow/tools/stow-rustc-wrapper\n\
             STOW_REAL_CC=clang\n\
             STOW_REAL_CXX=clang++\n\
             CC_x86_64_unknown_linux_gnu=/home/user/.local/share/stow/tools/stow-cc\n\
             CXX_x86_64_unknown_linux_gnu=/home/user/.local/share/stow/tools/stow-cxx\n\
             CMAKE_C_COMPILER_LAUNCHER=/home/user/.local/share/stow/tools/stow-cc-launcher\n\
             CMAKE_CXX_COMPILER_LAUNCHER=/home/user/.local/share/stow/tools/stow-cc-launcher\n\
             STOW_EDGE_URL=https://stow.waterui.dev\n\
             STOW_VERIFY_MODE=github-ci\n",
        );
        assert_eq!(output, expected);
    }

    /// The shims ride the `cc` crate's target-scoped keys so other targets
    /// keep their own toolchain — no bare `CC`/`CXX` anywhere.
    #[test]
    fn env_entries_scope_the_shims_to_the_host_target() {
        let entries =
            super::compiler_env_entries(&test_wrappers(), "aarch64-pc-windows-msvc", None, None);
        let keys: Vec<&str> = entries.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "CC_aarch64_pc_windows_msvc",
                "CXX_aarch64_pc_windows_msvc",
                "CMAKE_C_COMPILER_LAUNCHER",
                "CMAKE_CXX_COMPILER_LAUNCHER",
            ],
            "entries: {entries:?}"
        );
        // No unconfigured-toolchain variables, and nothing unscoped.
        for (key, _) in &entries {
            assert!(!key.starts_with("STOW_REAL_"), "{key} leaked");
            assert_ne!(key, "CC");
            assert_ne!(key, "CXX");
        }
    }

    /// An explicit toolchain the caller configured is recorded, in the
    /// same precedence order the `cc` crate resolves it.
    #[test]
    fn configured_compiler_prefers_the_scoped_key() {
        let env = |key: &str| match key {
            "CC_armv7_unknown_linux_gnueabihf" => Some(std::ffi::OsString::from("arm-gcc")),
            "CC" => Some(std::ffi::OsString::from("cc")),
            _ => None,
        };
        let resolved =
            super::configured_compiler("STOW_REAL_CC", "CC", "armv7-unknown-linux-gnueabihf", env);
        assert_eq!(resolved.as_deref(), Some("arm-gcc"));
    }

    /// With nothing configured the answer is `None` — the shim resolves
    /// the platform toolchain per invocation instead of a stale snapshot.
    #[test]
    fn configured_compiler_is_none_without_any_cc_env() {
        assert_eq!(
            super::configured_compiler("STOW_REAL_CC", "CC", "riscv64gc-unknown-linux-gnu", |_| {
                None
            },),
            None
        );
    }

    /// Stow's own shims exported by an already-wired Cargo config must never
    /// be recorded as `STOW_REAL_CC` (which would cause `stow-cc` to exec
    /// itself recursively).
    #[test]
    fn configured_compiler_skips_stow_owned_shim_values() {
        let env = |key: &str| match key {
            "CC_aarch64_apple_darwin" => Some(std::ffi::OsString::from(
                "/Users/example/.cargo/stow/shims/abc123/stow-cc",
            )),
            "CC" => Some(std::ffi::OsString::from("/usr/bin/clang")),
            _ => None,
        };
        let resolved =
            super::configured_compiler("STOW_REAL_CC", "CC", "aarch64-apple-darwin", env);
        assert_eq!(resolved.as_deref(), Some("/usr/bin/clang"));

        let shim_only = |key: &str| match key {
            "CC_aarch64_apple_darwin" => Some(std::ffi::OsString::from(
                "/Users/example/.cargo/stow/shims/abc123/stow-cc",
            )),
            _ => None,
        };
        assert_eq!(
            super::configured_compiler("STOW_REAL_CC", "CC", "aarch64-apple-darwin", shim_only),
            None
        );
    }

    #[tokio::test]
    async fn setup_rewrites_stale_wrapper_entries_without_duplicating() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let cargo_dir = tempdir.path().join(".cargo");
        std::fs::create_dir_all(&cargo_dir).expect("create .cargo");
        std::fs::write(
            cargo_dir.join("config.toml"),
            "[build]\nrustc-wrapper = \"/tmp/stow-tools/stow-rustc-wrapper\"\n\
             \n[env]\n\
             CC = { value = \"/tmp/stow-tools/stow-cc\", force = true }\n",
        )
        .expect("seed stale cargo config");

        let wrappers = test_wrappers();
        let (config_path, _) = super::write_cargo_config(
            &cargo_dir,
            &wrappers,
            "x86_64-unknown-linux-gnu",
            Some("clang"),
            Some("clang++"),
            None,
            None,
        )
        .await
        .expect("first setup");
        let once = std::fs::read_to_string(&config_path).expect("read written config");

        super::write_cargo_config(
            &cargo_dir,
            &wrappers,
            "x86_64-unknown-linux-gnu",
            Some("clang"),
            Some("clang++"),
            None,
            None,
        )
        .await
        .expect("second setup");
        let twice = std::fs::read_to_string(&config_path).expect("read rewritten config");

        assert_eq!(once, twice, "re-running setup changed the file");
        assert!(
            !once.contains("/tmp/stow-tools"),
            "stale /tmp/stow-tools entry survived:\n{once}"
        );
        assert!(
            once.contains(&wrappers.rustc),
            "config does not point at {}:\n{once}",
            wrappers.rustc
        );
        assert_eq!(once.matches("rustc-wrapper =").count(), 1);
    }

    /// The cleanup identifies stow's wiring by value: a config whose `CC`
    /// points at the user's own compiler is untouched, while every entry
    /// pointing at a stow shim or the old tools dir goes.
    #[test]
    fn stale_cleanup_removes_only_stow_owned_values() {
        let mut document: toml_edit::DocumentMut = "[build]\n\
             rustc-wrapper = \"/tmp/stow-tools/stow-rustc-wrapper\"\n\
             \n[env]\n\
             CC = { value = \"/tmp/stow-tools/stow-cc\", force = true }\n\
             CXX = \"/tmp/stow-tools/stow-cxx\"\n\
             STOW_REAL_CC = \"cc\"\n\
             STOW_REAL_CXX = \"c++\"\n\
             PATH = { value = \"C:\\\\Program Files\\\\Microsoft Visual Studio\\\\2022\\\\VC\\\\Tools\\\\MSVC\\\\14.4\\\\bin\\\\HostX64\\\\x64\", force = true }\n\
             INCLUDE = \"C:\\\\Program Files (x86)\\\\Windows Kits\\\\10\\\\Include\"\n\
             CMAKE_C_COMPILER_LAUNCHER = \"/home/u/.local/share/stow/tools/stow-cc-launcher\"\n\
             OBJC = \"/usr/bin/clang\"\n\
             \n[target.'cfg(target_os = \"linux\")']\n\
             rustflags = [\"-C\", \"link-arg=-fuse-ld=mold\", \"-C\", \"debuginfo=2\", \"-C\", \"link-arg=-B/home/u/.local/share/stow/tools/mold/bin\"]\n\
             \n[target.'cfg(target_os = \"macos\")']\n\
             rustflags = [\"-C\", \"link-arg=-fuse-ld=mold\"]\n"
            .parse()
            .expect("parse fixture");

        assert!(super::clean_stow_owned_entries(
            &mut document,
            super::LinkerSelection::Strip
        ));
        let text = document.to_string();

        for gone in [
            "/tmp/stow-tools",
            "stow-cc-launcher",
            "STOW_REAL_CC",
            "STOW_REAL_CXX",
            "MSVC",
            "Windows Kits",
            "rustc-wrapper",
            "-fuse-ld=mold",
            "mold/bin",
        ] {
            assert!(!text.contains(gone), "{gone} survived:\n{text}");
        }
        // The user's own compiler and their non-stow rustflag stay.
        assert!(text.contains("OBJC"), "user env dropped:\n{text}");
        assert!(text.contains("debuginfo=2"), "user flag dropped:\n{text}");
    }

    /// Value-based identification means a project config the user wrote
    /// themselves — same keys, their own values — reports clean.
    #[test]
    fn user_wired_config_is_not_stale() {
        let mut document: toml_edit::DocumentMut = "[build]\n\
             rustc-wrapper = \"/usr/bin/sccache\"\n\
             \n[env]\n\
             CC = \"/usr/bin/clang\"\n\
             STOW_REAL_CC = \"not-a-path\"\n"
            .parse()
            .expect("parse fixture");
        assert!(!super::clean_stow_owned_entries(
            &mut document,
            super::LinkerSelection::Strip
        ));
    }

    /// Setup walking ancestors removes the stale project file and reports
    /// it; a config that is stow-wired by value in `cwd` is rewritten even
    /// though the global config is elsewhere.
    #[tokio::test]
    async fn clean_stale_project_configs_removes_only_stow_wiring() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let project = tempdir.path().join("proj");
        let cargo_dir = project.join(".cargo");
        std::fs::create_dir_all(&cargo_dir).expect("create .cargo");
        let stale = cargo_dir.join("config.toml");
        std::fs::write(
            &stale,
            "[env]\nCC = \"/tmp/stow-tools/stow-cc\"\nOBJC = \"/usr/bin/clang\"\n",
        )
        .expect("seed stale config");
        let untouched_dir = project.join("nested/.cargo");
        std::fs::create_dir_all(&untouched_dir).expect("create nested .cargo");
        let untouched = untouched_dir.join("config.toml");
        std::fs::write(&untouched, "[env]\nCC = \"/usr/bin/clang\"\n").expect("seed user config");

        let global_home = tempdir.path().join("elsewhere");
        std::fs::create_dir_all(&global_home).expect("create elsewhere cargo home");
        let global_config = global_home.join("config.toml");
        let global_contents = "[build]\nrustc-wrapper = \"/tmp/stow-tools/stow-rustc-wrapper\"\n";
        std::fs::write(&global_config, global_contents).expect("seed global config");

        let cleaned = super::clean_stale_project_configs(&project, &global_home).expect("clean");
        assert_eq!(cleaned, vec![stale.clone()]);
        assert_eq!(
            std::fs::read_to_string(&global_config).expect("read global config"),
            global_contents
        );
        let text = std::fs::read_to_string(&stale).expect("read cleaned");
        assert!(!text.contains("stow-cc"), "stow entry survived:\n{text}");
        assert!(text.contains("OBJC"), "user entry dropped:\n{text}");
        assert_eq!(
            std::fs::read_to_string(&untouched).expect("read user config"),
            "[env]\nCC = \"/usr/bin/clang\"\n"
        );
    }

    /// stow#623 — an "already configured" run (`prepare_global` answered
    /// `None`) must leave the document it wrote byte-identical, and a
    /// later provisioned run identical again: the selection is only ever
    /// rewritten on the path that writes a new one.
    #[test]
    fn configure_document_is_idempotent_across_mold_answers() {
        let wrappers = test_wrappers();
        let env_entries = || {
            super::compiler_env_entries(
                &wrappers,
                "x86_64-unknown-linux-gnu",
                Some("clang"),
                Some("clang++"),
            )
        };
        let bin_dir = std::path::Path::new("/home/user/.local/share/stow/tools/mold/bin");

        let mut document = toml_edit::DocumentMut::new();
        super::configure_document(&mut document, &wrappers, env_entries(), Some(bin_dir), None)
            .expect("first configure");
        let written = document.to_string();

        super::configure_document(&mut document, &wrappers, env_entries(), None, None)
            .expect("already-configured configure");
        assert_eq!(
            document.to_string(),
            written,
            "the already-reachable answer dropped the selection"
        );

        super::configure_document(&mut document, &wrappers, env_entries(), Some(bin_dir), None)
            .expect("provisioned configure");
        assert_eq!(document.to_string(), written, "rewriting drifted");
    }

    /// A document carrying the user's own rustflags beside stow's
    /// selection keeps both through an already-configured run.
    #[test]
    fn configure_document_keeps_user_rustflags_and_the_selection() {
        let mut document: toml_edit::DocumentMut = "[build]\n\
             rustc-wrapper = \"/home/user/.local/share/stow/tools/stow-rustc-wrapper\"\n\
             \n[env.COMPILER_PATH]\n\
             value = \"/home/user/.local/share/stow/tools/mold/bin\"\n\
             force = true\n\
             \n[target.'cfg(target_os = \"linux\")']\n\
             rustflags = [\"-C\", \"link-arg=-fuse-ld=mold\", \"-C\", \"debuginfo=2\"]\n"
            .parse()
            .expect("parse fixture");

        let wrappers = test_wrappers();
        super::configure_document(
            &mut document,
            &wrappers,
            super::compiler_env_entries(&wrappers, "x86_64-unknown-linux-gnu", None, None),
            None,
            None,
        )
        .expect("configure");
        let text = document.to_string();
        assert!(
            text.contains("link-arg=-fuse-ld=mold"),
            "selection dropped:\n{text}"
        );
        assert!(text.contains("debuginfo=2"), "user flag dropped:\n{text}");
        assert!(
            text.contains("COMPILER_PATH"),
            "compiler path dropped:\n{text}"
        );
    }

    /// The stale-config walk still strips stow's linker selection from a
    /// project config — the global file owns that wiring.
    #[test]
    fn clean_stale_project_configs_strips_the_linker_selection() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let cargo_dir = tempdir.path().join("proj/.cargo");
        std::fs::create_dir_all(&cargo_dir).expect("create .cargo");
        let stale = cargo_dir.join("config.toml");
        std::fs::write(
            &stale,
            "[env]\n\
             CC = \"/tmp/stow-tools/stow-cc\"\n\
             COMPILER_PATH = { value = \"/tmp/stow-tools/mold/bin\", force = true }\n\
             \n[target.'cfg(target_os = \"linux\")']\n\
             rustflags = [\"-C\", \"link-arg=-fuse-ld=mold\", \"-C\", \"debuginfo=2\"]\n",
        )
        .expect("seed stale config");

        let cleaned = super::clean_stale_project_configs(
            &tempdir.path().join("proj"),
            &tempdir.path().join("elsewhere"),
        )
        .expect("clean");
        assert_eq!(cleaned, vec![stale.clone()]);
        let text = std::fs::read_to_string(&stale).expect("read cleaned");
        assert!(
            !text.contains("fuse-ld=mold"),
            "linker selection survived:\n{text}"
        );
        assert!(
            !text.contains("COMPILER_PATH"),
            "compiler path survived:\n{text}"
        );
        assert!(text.contains("debuginfo=2"), "user flag dropped:\n{text}");
    }

    /// `stow update` refuses a receipt recorded for a different install
    /// prefix instead of reporting "already up to date". `set_install_dir`
    /// writes the field `load_receipt` fills from the receipt, so the test
    /// drives the same check without touching the environment axoupdater
    /// reads its search paths from.
    #[tokio::test]
    async fn update_refuses_a_receipt_from_another_prefix() {
        let mut updater = axoupdater::AxoUpdater::new_for("stow-cli");
        updater.set_install_dir("/elsewhere/bin");
        let error = super::update_with(updater).await.expect_err("must refuse");
        assert!(
            format!("{error}").contains("different install prefix"),
            "unexpected error: {error}"
        );
        assert!(
            format!("{error}").contains("/elsewhere"),
            "the refusal names the foreign prefix: {error}"
        );
    }

    /// The daemon is asked to retire onto the executable that was
    /// updated, only when the update installed something.
    #[tokio::test]
    async fn the_daemon_is_restarted_only_when_an_update_installed_something() {
        let exe = std::path::Path::new("/install/bin/stow");
        let asked = std::cell::RefCell::new(Vec::new());
        let retire = async |onto: &std::path::Path| {
            asked.borrow_mut().push(onto.to_owned());
            Ok(Some(Restarted {
                left: "0.16.0".to_owned(),
                now: "0.17.0".to_owned(),
            }))
        };

        assert_eq!(
            super::restart_daemon_after(None, exe, retire)
                .await
                .expect("up to date"),
            None
        );
        assert!(asked.borrow().is_empty(), "nothing was installed");

        let report = super::restart_daemon_after(Some("0.17.0"), exe, retire)
            .await
            .expect("restarted");
        assert_eq!(
            report.as_deref(),
            Some("restarted the stow daemon: 0.16.0 -> 0.17.0")
        );
        assert_eq!(*asked.borrow(), [exe.to_owned()]);
    }

    #[tokio::test]
    async fn a_daemon_that_is_not_running_is_not_started_by_an_update() {
        let report = super::restart_daemon_after(
            Some("0.17.0"),
            std::path::Path::new("/install/bin/stow"),
            async |_: &std::path::Path| Ok(None),
        )
        .await
        .expect("nothing to restart");
        assert_eq!(report, None);
    }

    #[tokio::test]
    async fn a_daemon_that_comes_back_older_than_the_install_is_named() {
        let error = super::restart_daemon_after(
            Some("0.17.0"),
            std::path::Path::new("/install/bin/stow"),
            async |_: &std::path::Path| {
                Ok(Some(Restarted {
                    left: "0.16.0".to_owned(),
                    now: "0.16.0".to_owned(),
                }))
            },
        )
        .await
        .expect_err("the daemon is not the installed stow");
        let error = error.to_string();
        assert!(
            error.contains("0.16.0") && error.contains("0.17.0"),
            "{error}"
        );
    }

    #[cfg(feature = "mock-verify")]
    #[test]
    fn github_env_output_serializes_verify_mode_as_wire_string() {
        let output = setup_env_output(
            &test_wrappers(),
            "x86_64-unknown-linux-gnu",
            None,
            None,
            &test_config(VerifyMode::MockKey {
                public_key_path: std::path::PathBuf::from("/keys/mock.pub"),
                public_key_sha256: "00".repeat(32),
            }),
        );
        assert!(output.contains("STOW_VERIFY_MODE=mock-key\n"));
    }

    #[tokio::test]
    async fn clean_preserves_index_slices_and_stats_unless_all_is_set() {
        let dir = tempfile::tempdir().expect("temp cache dir");
        let cache = dir.path();
        let slice_dir = cache.join("index/x86_64-unknown-linux-gnu/1.100.0");
        std::fs::create_dir_all(&slice_dir).expect("slice dir");
        std::fs::write(slice_dir.join("current.json"), b"{\"row_count\":42}").expect("pointer");
        std::fs::write(cache.join("stats.json"), b"{\"hits\":9}").expect("stats");
        std::fs::create_dir_all(cache.join("crates-io/1.100.0/entry")).expect("artifact dir");
        std::fs::create_dir_all(cache.join("local-crates-io/1.100.0/entry"))
            .expect("local-crates-io dir");
        std::fs::create_dir_all(cache.join("local/cc")).expect("cc dir");
        std::fs::create_dir_all(cache.join("build-dir/ws")).expect("build dir");

        let state_db = crate::state_db::StateDb::default();
        let pool = state_db.pool(cache).await.expect("open state db");
        sqlx::query(
            "INSERT INTO crate_stats (crate_name, hits, misses, errors) VALUES ('serde', 7, 1, 0)",
        )
        .execute(&pool)
        .await
        .expect("insert crate_stats");
        let local_pool = state_db
            .tier_pool(cache, crate::state_db::CacheTier::Local)
            .await
            .expect("open local tier db");
        sqlx::query(
            "INSERT INTO cc_cache_entries (cache_key, size_bytes, last_accessed_ms) VALUES ('k1', 128, 1)",
        )
        .execute(&local_pool)
        .await
        .expect("insert cc_cache_entries");
        drop(local_pool);

        super::clean_cache_dir(cache, false, &state_db)
            .await
            .expect("default clean");

        assert!(slice_dir.join("current.json").is_file());
        assert!(cache.join("stats.json").is_file());
        assert!(!cache.join("crates-io").exists());
        assert!(!cache.join("local-crates-io").exists());
        assert!(!cache.join("local").exists());
        assert!(!cache.join("build-dir").exists());
        let hits: (i64,) =
            sqlx::query_as("SELECT hits FROM crate_stats WHERE crate_name = 'serde'")
                .fetch_one(&pool)
                .await
                .expect("read preserved crate_stats");
        assert_eq!(hits.0, 7);
        state_db.close().await;

        let fresh_db = crate::state_db::StateDb::default();
        super::clean_cache_dir(cache, true, &fresh_db)
            .await
            .expect("clean --all");
        assert!(!cache.exists());
    }

    #[tokio::test]
    async fn clean_removes_schema_mismatched_state_db_without_touching_index() {
        let dir = tempfile::tempdir().expect("temp cache dir");
        let cache = dir.path();
        let slice_dir = cache.join("index/aarch64-apple-darwin/1.100.0");
        std::fs::create_dir_all(&slice_dir).expect("slice dir");
        std::fs::write(slice_dir.join("current.json"), b"{}").expect("pointer");
        std::fs::write(crate::state_db::state_db_path(cache), b"not-a-valid-sqlite")
            .expect("corrupt db");
        std::fs::write(cache.join("state-v3.sqlite3-wal"), b"wal").expect("wal");
        std::fs::write(cache.join("state-v3.sqlite3-shm"), b"shm").expect("shm");

        let state_db = crate::state_db::StateDb::default();
        super::clean_cache_dir(cache, false, &state_db)
            .await
            .expect("clean recovers broken state db");
        assert!(slice_dir.join("current.json").is_file());
        assert!(!crate::state_db::state_db_path(cache).exists());
        assert!(!cache.join("state-v3.sqlite3-wal").exists());
        assert!(!cache.join("state-v3.sqlite3-shm").exists());
        state_db.close().await;
    }

    #[tokio::test]
    async fn clean_skips_active_build_dir_and_still_removes_schema_mismatched_state_db() {
        let dir = tempfile::tempdir().expect("temp cache dir");
        let cache = dir.path();
        let slice_dir = cache.join("index/aarch64-apple-darwin/1.100.0");
        std::fs::create_dir_all(&slice_dir).expect("slice dir");
        std::fs::write(slice_dir.join("current.json"), b"{}").expect("pointer");
        std::fs::write(cache.join("stats.json"), b"{}").expect("stats");
        std::fs::create_dir_all(cache.join("crates-io/1.100.0/entry")).expect("crates-io");

        let state_path = crate::state_db::state_db_path(cache);
        let mut old_conn = <sqlx::sqlite::SqliteConnectOptions as std::str::FromStr>::from_str(
            &format!("sqlite://{}", state_path.display()),
        )
        .expect("connect options")
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        old_conn = old_conn.synchronous(sqlx::sqlite::SqliteSynchronous::Normal);
        let mut conn = sqlx::ConnectOptions::connect(&old_conn)
            .await
            .expect("open legacy state db");
        sqlx::query("CREATE TABLE old_shape (v TEXT)")
            .execute(&mut conn)
            .await
            .expect("create legacy table");
        sqlx::Connection::close(conn)
            .await
            .expect("close legacy state db");

        // Sharded cargo build-dir layout: `<shard>/<hash>/<triple>/<profile>/.cargo-build-lock`
        let active_ws = cache.join("build-dir/b3/dea7bd2fb461ea");
        let active_profile = active_ws.join("aarch64-apple-darwin/debug");
        std::fs::create_dir_all(&active_profile).expect("active profile");
        let active_lock_path = active_profile.join(".cargo-build-lock");
        let active_lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&active_lock_path)
            .expect("open active lock");
        let active_lock =
            crate::file_lock::FileLock::exclusive(active_lock_file).expect("hold cargo build lock");

        let idle_ws = cache.join("build-dir/b3/11111111111111");
        std::fs::create_dir_all(idle_ws.join("debug")).expect("idle profile");
        std::fs::write(idle_ws.join("debug/.cargo-build-lock"), b"").expect("idle lock");

        let state_db = crate::state_db::StateDb::default();
        let skipped = super::clean_cache_dir(cache, false, &state_db)
            .await
            .expect("default clean succeeds despite active build");
        assert_eq!(skipped, 1);
        assert!(!state_path.exists());
        assert!(!cache.join("state-v3.sqlite3-wal").exists());
        assert!(!cache.join("state-v3.sqlite3-shm").exists());
        assert!(!cache.join("crates-io").exists());
        assert!(!idle_ws.exists(), "idle sibling workspace must be cleaned");
        assert!(
            active_ws.exists(),
            "active locked workspace must be preserved"
        );
        assert!(slice_dir.join("current.json").is_file());
        state_db.close().await;

        let all_db = crate::state_db::StateDb::default();
        let skipped_all = super::clean_cache_dir(cache, true, &all_db)
            .await
            .expect("clean --all succeeds despite active build");
        assert_eq!(skipped_all, 1);
        assert!(!cache.join("index").exists());
        assert!(!cache.join("stats.json").exists());
        assert!(active_ws.exists());

        drop(active_lock);
        let final_db = crate::state_db::StateDb::default();
        let skipped_after = super::clean_cache_dir(cache, true, &final_db)
            .await
            .expect("clean --all removes root once lock is released");
        assert_eq!(skipped_after, 0);
        assert!(!cache.exists());
    }

    #[test]
    fn skill_detection_only_matches_existing_claude_or_agents_dirs_and_preserves_symlinks() {
        let home = tempfile::tempdir().expect("temp home");
        assert_eq!(
            super::detected_agent_homes(home.path()),
            Vec::<PathBuf>::new()
        );

        let agents = home.path().join(".agents");
        let claude = home.path().join(".claude");
        std::fs::create_dir_all(&agents).expect("create .agents");
        std::fs::create_dir_all(claude.join("skills")).expect("create .claude/skills");
        std::fs::create_dir_all(agents.join("skills/stow")).expect("create .agents/skills/stow");
        #[cfg(unix)]
        std::os::unix::fs::symlink(agents.join("skills/stow"), claude.join("skills/stow"))
            .expect("symlink claude skill to agents skill");

        let detected = super::detected_agent_homes(home.path());
        assert_eq!(detected, vec![agents.clone(), claude.clone()]);
        assert!(super::agent_homes_need_skill_update(
            &detected,
            super::BUNDLED_STOW_SKILL
        ));

        let written = super::install_bundled_stow_skill(&detected).expect("install bundled skill");
        #[cfg(unix)]
        {
            assert_eq!(written, vec![agents.join("skills/stow/SKILL.md")]);
            assert!(
                std::fs::symlink_metadata(claude.join("skills/stow"))
                    .expect("stat claude skill")
                    .file_type()
                    .is_symlink(),
                "existing symlink into ~/.agents/skills/stow must stay intact"
            );
        }
        assert_eq!(
            std::fs::read_to_string(claude.join("skills/stow/SKILL.md")).expect("read skill"),
            super::BUNDLED_STOW_SKILL
        );
        assert!(!super::agent_homes_need_skill_update(
            &detected,
            super::BUNDLED_STOW_SKILL
        ));
    }

    #[test]
    fn no_build_dir_placement_strips_stow_owned_build_dir_while_keeping_user_build_dir() {
        let wrappers = test_wrappers();
        let mut doc: toml_edit::DocumentMut =
            "[build]\nbuild-dir = \"/Users/u/.stow/build-dir/{workspace-path-hash}\"\n"
                .parse()
                .expect("parse stow build-dir");
        super::configure_document(
            &mut doc,
            &wrappers,
            Vec::new(),
            None,
            super::BuildDirPlacement::Disabled.stow_template(),
        )
        .expect("configure with --no-build-dir");
        assert!(!doc.to_string().contains("build-dir ="), "{doc}");

        let mut user_doc: toml_edit::DocumentMut = "[build]\nbuild-dir = \"/custom/build\"\n"
            .parse()
            .expect("parse user build-dir");
        super::configure_document(
            &mut user_doc,
            &wrappers,
            Vec::new(),
            None,
            super::BuildDirPlacement::Disabled.stow_template(),
        )
        .expect("configure keeping user build-dir");
        assert!(
            user_doc
                .to_string()
                .contains("build-dir = \"/custom/build\"")
        );
    }

    fn sample_setup_plan() -> super::SetupPlan {
        super::SetupPlan {
            cargo_config_path: PathBuf::from("/Users/u/.cargo/config.toml"),
            cargo_config_exists: true,
            shims_dir: PathBuf::from("/Users/u/.cargo/stow/shims/0123456789abcdef"),
            host_target: "x86_64-unknown-linux-gnu".to_owned(),
            rustc_version: "1.91.1".to_owned(),
            rustc_wrapper: "/Users/u/.cargo/stow/shims/0123456789abcdef/stow-rustc-wrapper"
                .to_owned(),
            cc_key: "CC_x86_64_unknown_linux_gnu".to_owned(),
            cc_compiler: "/Users/u/.cargo/stow/shims/0123456789abcdef/stow-cc".to_owned(),
            cxx_key: "CXX_x86_64_unknown_linux_gnu".to_owned(),
            cxx_compiler: "/Users/u/.cargo/stow/shims/0123456789abcdef/stow-cxx".to_owned(),
            cc_launcher: "/Users/u/.cargo/stow/shims/0123456789abcdef/stow-cc-launcher".to_owned(),
            real_cc: Some("clang".to_owned()),
            real_cxx: None,
            build_dir: super::BuildDirPlacement::Stow(
                "/Users/u/.stow/build-dir/{workspace-path-hash}".to_owned(),
            ),
            mold: crate::mold::GlobalMoldPlan::Managed {
                bin_dir: PathBuf::from("/Users/u/.local/share/stow/tools/mold/bin"),
                needs_download: true,
            },
            stale_project_configs: vec![PathBuf::from("/work/proj/.cargo/config.toml")],
            daemon_service: Some(super::DaemonServicePlan::LaunchAgent {
                plist: PathBuf::from("/Users/u/Library/LaunchAgents/dev.waterui.stow.plist"),
                label: "dev.waterui.stow".to_owned(),
            }),
            skill_targets: vec![super::SkillTargetPlan {
                path: PathBuf::from("/Users/u/.agents/skills/stow/SKILL.md"),
                mode: super::SkillPlanMode::Install,
            }],
            fetch_index_slice: true,
        }
    }

    #[test]
    fn setup_plan_renders_every_target_plain_and_colored() {
        let plan = sample_setup_plan();
        let uncolored = super::render_setup_plan(&plan, crate::term_style::Palette::plain());
        assert!(
            !uncolored.contains('\x1b'),
            "plain setup plan must not emit ANSI escapes:\n{uncolored}"
        );
        let expected_linker = format!(
            "linker: mold ({}) (will download)",
            PathBuf::from("/Users/u/.local/share/stow/tools/mold/bin")
                .join("mold")
                .display()
        );
        for expected in [
            "stow setup plan",
            "config: /Users/u/.cargo/config.toml (update)",
            "rustc-wrapper: /Users/u/.cargo/stow/shims/0123456789abcdef/stow-rustc-wrapper",
            "cc: /Users/u/.cargo/stow/shims/0123456789abcdef/stow-cc (CC_x86_64_unknown_linux_gnu)",
            "cxx: /Users/u/.cargo/stow/shims/0123456789abcdef/stow-cxx (CXX_x86_64_unknown_linux_gnu)",
            "cc-launcher: /Users/u/.cargo/stow/shims/0123456789abcdef/stow-cc-launcher",
            "STOW_REAL_CC: clang",
            "build-dir: /Users/u/.stow/build-dir/{workspace-path-hash}",
            expected_linker.as_str(),
            "shims: /Users/u/.cargo/stow/shims/0123456789abcdef",
            "launch agent: /Users/u/Library/LaunchAgents/dev.waterui.stow.plist (dev.waterui.stow)",
            "agent skill: /Users/u/.agents/skills/stow/SKILL.md (install)",
            "stale cleanup: /work/proj/.cargo/config.toml (strip stow keys)",
            "index slice: x86_64-unknown-linux-gnu / rustc 1.91.1",
        ] {
            assert!(
                uncolored.contains(expected),
                "missing `{expected}` in plain setup plan:\n{uncolored}"
            );
        }

        let colored = super::render_setup_plan(&plan, crate::term_style::Palette::colored());
        assert!(
            colored.contains("\x1b[1;36mstow setup plan\x1b[0m"),
            "colored setup plan must style heading:\n{colored}"
        );
        assert!(
            colored.contains("/Users/u/.cargo/config.toml"),
            "colored setup plan must preserve target paths:\n{colored}"
        );

        let mut win_plan = plan;
        win_plan.daemon_service = Some(super::DaemonServicePlan::ScheduledTask {
            name: "stow-daemon-0123456789abcdef".to_owned(),
        });
        let win_output = super::render_setup_plan(&win_plan, crate::term_style::Palette::plain());
        assert!(
            win_output.contains("scheduled task: stow-daemon-0123456789abcdef"),
            "missing scheduled task in Windows plan:\n{win_output}"
        );
    }

    #[test]
    fn setup_confirmation_skips_prompt_for_yes_ci_or_non_tty() {
        let prompt = |yes, stdin_tty, stdout_tty, ci_env| {
            super::SetupPromptContext {
                yes,
                ci_env,
                terminal: super::TerminalMode::from_stdio(stdin_tty, stdout_tty),
            }
            .should_prompt()
        };
        assert!(prompt(false, true, true, false));
        assert!(!prompt(true, true, true, false));
        assert!(!prompt(false, true, true, true));
        assert!(!prompt(false, false, true, false));
        assert!(!prompt(false, true, false, false));
        assert!(!prompt(false, false, false, false));
    }

    #[test]
    fn setup_confirmation_prompt_handles_accept_decline_and_eof() {
        let palette = crate::term_style::Palette::plain();
        for (input, expected) in [
            ("\n", true),
            ("y\n", true),
            ("Y\n", true),
            ("yes\n", true),
            ("YES\n", true),
            ("n\n", false),
            ("no\n", false),
            ("anything\n", false),
            ("", false),
        ] {
            let mut reader = std::io::Cursor::new(input.as_bytes());
            let mut writer = Vec::new();
            let confirmed = super::confirm_setup_with(&mut reader, &mut writer, palette)
                .expect("confirm prompt");
            assert_eq!(confirmed, expected, "unexpected result for input {input:?}");
            let prompt = String::from_utf8(writer).expect("utf-8 prompt");
            assert!(
                prompt.contains("Apply these changes? [Y/n]:"),
                "prompt text missing: {prompt:?}"
            );
        }
    }

    #[test]
    fn setup_plan_computes_shim_paths_without_creating_any_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cargo_home = dir.path().join("cargo-home");
        let resolved = super::resolve_wrapper_executables(&cargo_home).expect("resolve wrappers");
        let shims = crate::wrapper_shim::planned_wrapper_shims(&resolved.shims_dir);
        assert!(shims.rustc_wrapper.starts_with(&resolved.shims_dir));
        assert!(
            !cargo_home.exists(),
            "planning must not create CARGO_HOME or shims directory before confirmation"
        );
        assert!(!resolved.shims_dir.exists());
    }

    #[test]
    fn status_report_renders_grouped_summary_plain_and_colored() {
        let report = super::StatusReport {
            cargo: super::CargoWiringStatus::Configured {
                config_path: PathBuf::from("/Users/u/.cargo/config.toml"),
                rustc_wrapper: Some("/Users/u/.cargo/stow/shims/abc/stow-rustc-wrapper".to_owned()),
                cc_compiler: Some("/Users/u/.cargo/stow/shims/abc/stow-cc".to_owned()),
                cxx_compiler: Some("/Users/u/.cargo/stow/shims/abc/stow-cxx".to_owned()),
                cc_launcher: Some("/Users/u/.cargo/stow/shims/abc/stow-cc-launcher".to_owned()),
                build_dir: "/Users/u/.stow/build-dir/{workspace-path-hash}".to_owned(),
                linker_mold: true,
            },
            remote: super::RemoteDaemonStatus {
                edge_url: Some("https://stow.waterui.dev".to_owned()),
                remote_cache: Some(true),
                daemon: crate::daemon::DaemonProbe::Running(crate::daemon::StatusReply {
                    stow_version: "0.21.13".to_owned(),
                    protocol: 5,
                    floor: 4,
                }),
            },
            summary: crate::stats::StatsSummary {
                rust_hits: 412,
                rust_misses: 87,
                rust_errors: 2,
                rust_glibc_refusals: 0,
                rust_local_dependency_builds: 0,
                cc_hits: 11,
                cc_misses: 3,
                cc_errors: 0,
            },
            local: crate::stats::LocalStats {
                hits: 423,
                cpu_millis_saved: 852_000,
                bytes_served: 134_637_158,
                bytes_downloaded: 44_145_049,
            },
            stale_project_configs: vec![PathBuf::from("/work/old/.cargo/config.toml")],
        };

        let plain = super::render_status_report(&report, crate::term_style::Palette::plain());
        assert!(
            !plain.contains('\x1b'),
            "plain status must not emit ANSI escapes:\n{plain}"
        );
        for expected in [
            "Cargo wiring",
            "config: /Users/u/.cargo/config.toml",
            "rustc-wrapper: /Users/u/.cargo/stow/shims/abc/stow-rustc-wrapper",
            "cc: /Users/u/.cargo/stow/shims/abc/stow-cc",
            "cxx: /Users/u/.cargo/stow/shims/abc/stow-cxx",
            "cc-launcher: /Users/u/.cargo/stow/shims/abc/stow-cc-launcher",
            "build-dir: /Users/u/.stow/build-dir/{workspace-path-hash}",
            "linker: mold",
            "Remote & daemon",
            "edge-url: https://stow.waterui.dev",
            "remote-cache: on",
            "daemon: running (stow 0.21.13, protocol 5)",
            "Cache performance",
            "rust-cache: 412 hits, 87 misses (82.6% hit rate), 2 errors",
            "cc-cache: 11 hits, 3 misses (78.6% hit rate), 0 errors",
            "cpu-saved: 14.2 min",
            "bytes-served: 128.4 MiB",
            "bytes-downloaded: 42.1 MiB",
            "Warnings",
            "stale stow wiring: /work/old/.cargo/config.toml",
        ] {
            assert!(
                plain.contains(expected),
                "missing `{expected}` in plain status output:\n{plain}"
            );
        }

        let colored = super::render_status_report(&report, crate::term_style::Palette::colored());
        assert!(
            colored.contains("\x1b[1;36mCargo wiring\x1b[0m"),
            "colored status must style section headings:\n{colored}"
        );
        assert!(
            colored.contains("\x1b[32mon\x1b[0m"),
            "colored status must highlight remote-cache on:\n{colored}"
        );
        assert!(
            colored.contains("\x1b[31m2 errors\x1b[0m"),
            "colored status must highlight non-zero errors:\n{colored}"
        );
    }

    #[test]
    fn status_report_renders_unconfigured_and_zero_stats() {
        let unconfigured = super::StatusReport {
            cargo: super::CargoWiringStatus::NotConfigured {
                config_path: PathBuf::from("/Users/u/.cargo/config.toml"),
            },
            remote: super::RemoteDaemonStatus {
                edge_url: Some("https://stow.waterui.dev".to_owned()),
                remote_cache: Some(false),
                daemon: crate::daemon::DaemonProbe::NotRunning,
            },
            summary: crate::stats::StatsSummary::default(),
            local: crate::stats::LocalStats::default(),
            stale_project_configs: Vec::new(),
        };
        let unconf_plain =
            super::render_status_report(&unconfigured, crate::term_style::Palette::plain());
        assert!(unconf_plain.contains("not configured: /Users/u/.cargo/config.toml is missing"));
        assert!(unconf_plain.contains("remote-cache: off (local-only)"));
        assert!(unconf_plain.contains("daemon: not running"));
        assert!(unconf_plain.contains("rust-cache: 0 hits, 0 misses (—), 0 errors"));
        assert!(!unconf_plain.contains("Warnings"));
    }
}

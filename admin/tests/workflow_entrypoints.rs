//! Isolation regressions for the five `disabled_manually` workflow
//! entrypoints (stow#593): `preheat-cron.yml`, `preheat-admin.yml`,
//! `preheat-missed.yml`, `preheat-projects.yml`, `index-publish-cron.yml`.
//!
//! Every test parses the real YAML, runs its `run:` steps under bash
//! against a PATH of recording stubs, and asserts the recorded
//! invocations; Actions-side machinery (cache keys, concurrency,
//! `if:`, permissions, `uses:` actions) is asserted as declarations
//! parsed from the same file. No GitHub API, crates.io, Cloudflare, or
//! edge request leaves the machine — there is no network stub for any
//! of them to reach.
//!
//! The steps run under bash with the tools of their runner (GNU
//! userland, a `python3` with `tomllib`), exactly as their Linux runners
//! execute them; every job of the five entrypoints runs on
//! `ubuntu-latest` (`entrypoints_run_on_linux_runners`), so the suite
//! runs on Linux hosts only.
#![cfg(target_os = "linux")]

mod support;

use std::collections::BTreeMap;
use std::path::PathBuf;

use support::{
    Call, Outcome, Scenario, Status, Val, at, dispatch_inputs, field, job_steps, load_workflow,
    scalar, set_path, step_output, substitute,
};

/// The channel fixture `preheat-cron`/`preheat-missed` resolve —
/// `edge/tests/fixtures` carries the real manifest shape (decorated
/// `version = "1.98.1 (hash date)"` reduced to `1.98.1`).
const CHANNEL_FIXTURE_VERSION: &str = "1.98.1";
const CHANNEL_FIXTURE_DAY: &str = "2026-10-08";

fn channel_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../edge/tests/fixtures/channel-rust-stable.toml")
        .canonicalize()
        .expect("channel fixture exists")
}

/// Context an Actions run would carry — repo identity, a token, the
/// org `vars`/`secrets` the steps reference — with fake values only.
fn actions_ctx() -> Val {
    let mut ctx = Val::context();
    let pairs = [
        ("github.repository", "water-rs/stow"),
        ("github.token", "test-github-token"),
        ("vars.STOW_EDGE_URL", "https://edge.invalid"),
        ("vars.STOW_OIDC_AUDIENCE", "test-audience"),
        ("vars.CF_ACCOUNT_ID", "test-account"),
        ("secrets.CF_ANALYTICS_TOKEN", "test-cf-token"),
    ];
    for (k, v) in pairs {
        set_path(&mut ctx, k, Val::Str(v.to_owned()));
    }
    // A scheduled/manual run has no `workflow_run` payload; the
    // dispatch scenario sets one explicitly.
    set_path(
        &mut ctx,
        "github.event_name",
        Val::Str("schedule".to_owned()),
    );
    set_path(
        &mut ctx,
        "github.event.workflow_run.display_title",
        Val::Null,
    );
    ctx
}

fn with_inputs(mut ctx: Val, inputs: &[(&str, Val)]) -> Val {
    for (k, v) in inputs {
        set_path(&mut ctx, &format!("inputs.{k}"), v.clone());
    }
    ctx
}

/// Declared `workflow_dispatch` defaults poured into `ctx.inputs` —
/// what Actions hands a manual run when the operator leaves a field at
/// its default.
fn apply_dispatch_defaults(ctx: &mut Val, wf: &serde_yml::Value) {
    for (name, default) in dispatch_inputs(wf) {
        // A provided input wins over the declared default.
        if let Some(v) = default
            && !support::ctx_has(ctx, &format!("inputs.{name}"))
        {
            set_path(ctx, &format!("inputs.{name}"), v);
        }
    }
}

/// The `STUB_*` plan plus runner-level env every scenario needs.
fn base_env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut env = BTreeMap::from([
        ("GITHUB_REPOSITORY".to_owned(), "water-rs/stow".to_owned()),
        ("STUB_DATE".to_owned(), CHANNEL_FIXTURE_DAY.to_owned()),
        (
            "STUB_CHANNEL_TOML".to_owned(),
            channel_fixture().display().to_string(),
        ),
    ]);
    for (k, v) in pairs {
        env.insert((*k).to_owned(), (*v).to_owned());
    }
    env
}

fn run_job<'a>(
    scn: &'a Scenario,
    wf: &serde_yml::Value,
    job: &str,
    ctx: Val,
    env: BTreeMap<String, String>,
) -> support::Runner<'a> {
    let mut runner = support::Runner::new(scn, ctx, env);
    runner.run_job(wf, job);
    runner
}

fn gh_dispatch_args(call: &Call) -> Vec<String> {
    assert_eq!(call.tool, "gh");
    assert_eq!(
        call.argv.first().map(String::as_str),
        Some("workflow"),
        "gh invocation is not a workflow call: {call}"
    );
    assert_eq!(call.argv.get(1).map(String::as_str), Some("run"), "{call}");
    call.argv[2..].to_vec()
}

/// `-f name=value` entries of a `gh workflow run` argv tail.
fn input_fields(argv: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        if a == "-f" {
            let pair = it.next().expect("-f without value");
            let (k, v) = pair.split_once('=').expect("-f without `=`");
            out.insert(k.to_owned(), v.to_owned());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// preheat-cron.yml
// ---------------------------------------------------------------------------

fn preheat_cron() -> serde_yml::Value {
    load_workflow("preheat-cron.yml")
}

#[test]
fn cron_declarations() {
    let wf = preheat_cron();
    assert_eq!(
        at(&wf, "on.schedule")
            .and_then(|s| s.as_sequence())
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        at(&wf, "on.schedule")
            .and_then(|s| s.as_sequence())
            .and_then(|s| field(&s[0], "cron"))
            .map(scalar)
            .as_deref(),
        Some("0 */2 * * *")
    );
    // The tick both schedules and dispatches manually.
    assert!(at(&wf, "on.workflow_dispatch").is_some());
    // `gh workflow run` needs actions:write; nothing else is granted.
    assert_eq!(
        at(&wf, "permissions.contents").map(scalar).as_deref(),
        Some("read")
    );
    assert_eq!(
        at(&wf, "permissions.actions").map(scalar).as_deref(),
        Some("write")
    );
    // Ticks serialize — a group with no cancel-in-progress queues them.
    assert_eq!(
        at(&wf, "concurrency.group").map(scalar).as_deref(),
        Some("preheat-cron")
    );
    let cancel = at(&wf, "concurrency.cancel-in-progress");
    assert!(
        cancel.is_none()
            || matches!(cancel, Some(serde_yml::Value::Bool(false)))
            || cancel.map(scalar).as_deref() == Some("false"),
        "preheat-cron cancels in progress — concurrent ticks possible: {cancel:?}"
    );

    // The marker cache is keyed on resolved channel output — version
    // AND day — over the same file the save step writes.
    let steps = job_steps(&wf, "preheat");
    let marker = steps
        .iter()
        .find(|s| s.id.as_deref() == Some("marker"))
        .expect("marker step");
    assert_eq!(
        marker.uses.as_deref(),
        Some("actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9")
    );
    assert_eq!(
        marker.with.get("path").map(String::as_str),
        Some(".preheat-marker")
    );
    let key_template = marker.with.get("key").expect("marker key");
    assert_eq!(
        key_template,
        "preheat-${{ steps.channel.outputs.version }}-${{ steps.channel.outputs.day }}"
    );
    let save = steps
        .iter()
        .find(|s| {
            s.uses
                .as_deref()
                .is_some_and(|u| u.starts_with("actions/cache/save"))
        })
        .expect("save step");
    assert_eq!(save.with.get("key"), Some(key_template));
    assert_eq!(save.with.get("path"), marker.with.get("path"));
}

#[test]
fn cron_marker_key_binds_version_and_day() {
    let template = "preheat-${{ steps.channel.outputs.version }}-${{ steps.channel.outputs.day }}";
    let resolve = |version: &str, day: &str| {
        let mut ctx = Val::context();
        set_path(
            &mut ctx,
            "steps.channel.outputs.version",
            Val::Str(version.to_owned()),
        );
        set_path(
            &mut ctx,
            "steps.channel.outputs.day",
            Val::Str(day.to_owned()),
        );
        substitute(template, &ctx, Status::Ok)
    };
    let a = resolve("1.98.1", "2026-10-08");
    assert_eq!(a, "preheat-1.98.1-2026-10-08");
    // A moved stable channel or a new UTC day both produce a cache
    // miss — each re-dispatches.
    assert_ne!(a, resolve("1.99.0", "2026-10-08"));
    assert_ne!(a, resolve("1.98.1", "2026-10-09"));
}

#[test]
fn cron_cache_miss_dispatches_admin_once() {
    let wf = preheat_cron();
    let scn = Scenario::new();
    let mut runner = support::Runner::new(&scn, actions_ctx(), base_env(&[]));
    // The actions/cache restore step answered "miss" — what the engine
    // would have set `steps.marker.outputs.cache-hit` to.
    runner.seed_output("marker", "cache-hit", "false");
    runner.run_job(&wf, "preheat");

    assert_eq!(
        runner.outcome_of("Check whether this version already preheated today"),
        &Outcome::Declared
    );
    assert_eq!(runner.outcome_of("Already preheated"), &Outcome::Skipped);
    assert_eq!(
        runner.outcome_of("Dispatch the preheat wave"),
        &Outcome::Ran(0)
    );
    assert_eq!(
        runner.outcome_of("Record the wave marker"),
        &Outcome::Declared
    );
    assert_eq!(runner.status(), Status::Ok);

    // The channel step really ran: curl served the fixture, python
    // reduced `1.98.1 (hash date)` → `1.98.1`, and `date` was stubbed.
    assert_eq!(
        step_output(&runner.ctx, "channel", "version"),
        CHANNEL_FIXTURE_VERSION
    );
    assert_eq!(
        step_output(&runner.ctx, "channel", "day"),
        CHANNEL_FIXTURE_DAY
    );
    let curl = scn.calls_of("curl");
    assert_eq!(curl.len(), 1, "{curl:?}");
    assert!(
        curl[0]
            .argv
            .iter()
            .any(|a| a.contains("channel-rust-stable.toml")),
        "{:?}",
        curl[0]
    );

    // Exactly one dispatch: preheat-admin.yml with the same rustc and
    // both lanes enabled.
    let gh = scn.calls_of("gh");
    assert_eq!(gh.len(), 1, "{gh:?}");
    let args = gh_dispatch_args(&gh[0]);
    assert_eq!(args.first().map(String::as_str), Some("preheat-admin.yml"));
    let fields = input_fields(&args);
    assert_eq!(
        fields,
        BTreeMap::from([
            (
                "rustc_version".to_owned(),
                CHANNEL_FIXTURE_VERSION.to_owned()
            ),
            ("top_binaries".to_owned(), "true".to_owned()),
            ("projects".to_owned(), "true".to_owned()),
        ])
    );
    assert_eq!(
        gh[0].env.get("GH_REPO").map(String::as_str),
        Some("water-rs/stow")
    );
    assert_eq!(gh[0].env.get("GH_TOKEN").map(String::as_str), Some("<set>"));

    // The run step itself wrote the marker the cache save uploads.
    let marker = scn.workdir().join(".preheat-marker");
    let body = std::fs::read_to_string(&marker).expect(".preheat-marker written");
    assert_eq!(
        body.trim(),
        format!("{CHANNEL_FIXTURE_VERSION} {CHANNEL_FIXTURE_DAY}")
    );
}

#[test]
fn cron_cache_hit_skips_dispatch_and_save() {
    let wf = preheat_cron();
    let scn = Scenario::new();
    let mut runner = support::Runner::new(&scn, actions_ctx(), base_env(&[]));
    runner.seed_output("marker", "cache-hit", "true");
    runner.run_job(&wf, "preheat");

    assert_eq!(runner.outcome_of("Already preheated"), &Outcome::Ran(0));
    assert_eq!(
        runner.outcome_of("Dispatch the preheat wave"),
        &Outcome::Skipped
    );
    assert_eq!(
        runner.outcome_of("Record the wave marker"),
        &Outcome::Skipped
    );
    assert_eq!(runner.status(), Status::Ok);
    assert!(scn.calls_of("gh").is_empty(), "{:?}", scn.calls());
    assert!(
        !scn.workdir().join(".preheat-marker").exists(),
        "a cache hit wrote a marker"
    );
}

#[test]
fn cron_failed_dispatch_writes_no_marker() {
    let wf = preheat_cron();
    let scn = Scenario::new();
    let mut runner =
        support::Runner::new(&scn, actions_ctx(), base_env(&[("STUB_TOOL_EXIT", "1")]));
    runner.seed_output("marker", "cache-hit", "false");
    runner.run_job(&wf, "preheat");

    let outcome = runner.outcome_of("Dispatch the preheat wave");
    assert!(
        matches!(outcome, Outcome::Ran(code) if *code != 0),
        "{outcome:?}"
    );
    assert_eq!(runner.status(), Status::Failed);
    assert_eq!(scn.calls_of("gh").len(), 1);
    assert!(
        !scn.workdir().join(".preheat-marker").exists(),
        "a failed dispatch still wrote the success marker"
    );
}

// ---------------------------------------------------------------------------
// preheat-admin.yml
// ---------------------------------------------------------------------------

fn preheat_admin() -> serde_yml::Value {
    load_workflow("preheat-admin.yml")
}

fn admin_ctx(rustc: &str, extra: &[(&str, Val)]) -> Val {
    let mut ctx = actions_ctx();
    set_path(
        &mut ctx,
        "github.event_name",
        Val::Str("workflow_dispatch".to_owned()),
    );
    set_path(&mut ctx, "inputs.rustc_version", Val::Str(rustc.to_owned()));
    with_inputs(ctx, extra)
}

fn admin_runner(scn: &Scenario, ctx: Val, env: BTreeMap<String, String>) -> support::Runner<'_> {
    let wf = preheat_admin();
    let mut ctx = ctx;
    apply_dispatch_defaults(&mut ctx, &wf);
    run_job(scn, &wf, "preheat", ctx, env)
}

/// The admin lane's `preheat`/`preheat top-binaries`/`projects submit`
/// argv tails, grouped by subcommand.
fn admin_calls(scn: &Scenario, sub: &str) -> Vec<Vec<String>> {
    scn.calls_of("stow-admin")
        .into_iter()
        .filter(|c| {
            c.argv.first().map(String::as_str) == Some("preheat")
                && c.argv.get(1).map(String::as_str) == Some(sub)
        })
        .map(|c| c.argv[2..].to_vec())
        .collect()
}

fn flag_value(argv: &[String], flag: &str) -> Option<String> {
    let mut it = argv.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
    }
    None
}

/// The nine `CI_TARGET_TRIPLES`, space- then comma-joined the way the
/// step's `${TARGETS// /,}` produces.
fn expected_targets() -> String {
    stow_types::api::CI_TARGET_TRIPLES.join(",")
}

#[test]
fn admin_declarations() {
    let wf = preheat_admin();
    // workflow_dispatch-only — it never fires on its own.
    assert!(at(&wf, "on.workflow_dispatch.inputs").is_some());
    assert!(at(&wf, "on.schedule").is_none());
    // OIDC: the lane mints a token per edge request, so the job needs
    // id-token:write and nothing else privileged.
    assert_eq!(
        at(&wf, "permissions.contents").map(scalar).as_deref(),
        Some("read")
    );
    assert_eq!(
        at(&wf, "permissions.id-token").map(scalar).as_deref(),
        Some("write")
    );

    let inputs = dispatch_inputs(&wf);
    assert_eq!(inputs.get("limit"), Some(&Some(Val::Str("100".to_owned()))));
    assert_eq!(inputs.get("rustc_version"), Some(&None));
    assert_eq!(inputs.get("top_binaries"), Some(&Some(Val::Bool(true))));
    assert_eq!(inputs.get("projects"), Some(&Some(Val::Bool(true))));
    let targets_default = match inputs.get("targets") {
        Some(Some(Val::Str(s))) => s.clone(),
        other => panic!("targets default: {other:?}"),
    };
    // The declared default IS CI_TARGET_TRIPLES — all nine, no filter.
    let mut declared: Vec<_> = targets_default.split_whitespace().collect();
    declared.sort_unstable();
    let mut canonical: Vec<_> = stow_types::api::CI_TARGET_TRIPLES.to_vec();
    canonical.sort_unstable();
    assert_eq!(declared, canonical);

    // The toolchain installs the exact rustc the dispatch named — the
    // resolver probes this toolchain's `rustc -vV`, so a mismatch would
    // key every task wrong.
    let steps = job_steps(&wf, "preheat");
    let toolchain = steps
        .iter()
        .find(|s| {
            s.uses
                .as_deref()
                .is_some_and(|u| u.starts_with("dtolnay/rust-toolchain"))
        })
        .expect("toolchain step");
    assert_eq!(
        toolchain.with.get("toolchain").map(String::as_str),
        Some("${{ inputs.rustc_version }}")
    );
    let mut ctx = admin_ctx("1.98.1", &[]);
    apply_dispatch_defaults(&mut ctx, &wf);
    assert_eq!(
        substitute(
            toolchain.with.get("toolchain").expect("toolchain"),
            &ctx,
            Status::Ok
        ),
        "1.98.1"
    );
}

#[test]
fn admin_all_nine_targets_both_lanes() {
    let scn = Scenario::new();
    let runner = admin_runner(&scn, admin_ctx("1.98.1", &[]), base_env(&[]));
    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);

    let want = expected_targets();
    for sub in ["top", "top-binaries"] {
        let calls = admin_calls(&scn, sub);
        assert_eq!(calls.len(), 1, "{sub}: {calls:?}");
        let argv = &calls[0];
        assert_eq!(
            flag_value(argv, "--targets").as_deref(),
            Some(want.as_str()),
            "{sub}"
        );
        assert_eq!(
            flag_value(argv, "--rustc-version").as_deref(),
            Some("1.98.1")
        );
        assert_eq!(flag_value(argv, "--limit").as_deref(), Some("100"));
        assert!(argv.iter().any(|a| a == "--yes"));
    }
    let submits = admin_calls(&scn, "projects");
    assert_eq!(submits.len(), 1, "{submits:?}");
    assert_eq!(submits[0][0], "submit");
    assert_eq!(
        flag_value(&submits[0], "--file").as_deref(),
        Some("preheat/projects.toml")
    );
    assert_eq!(
        flag_value(&submits[0], "--targets").as_deref(),
        Some(want.as_str())
    );
    assert_eq!(
        flag_value(&submits[0], "--rustc-version").as_deref(),
        Some("1.98.1")
    );
}

#[test]
fn admin_explicit_target_override() {
    let scn = Scenario::new();
    let ctx = admin_ctx(
        "1.98.1",
        &[(
            "targets",
            Val::Str("x86_64-unknown-linux-gnu aarch64-apple-darwin".to_owned()),
        )],
    );
    let runner = admin_runner(&scn, ctx, base_env(&[]));
    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);
    for argv in admin_calls(&scn, "top") {
        assert_eq!(
            flag_value(&argv, "--targets").as_deref(),
            Some("x86_64-unknown-linux-gnu,aarch64-apple-darwin")
        );
    }
}

#[test]
fn admin_library_lane_failure_still_runs_binary_lane() {
    let scn = Scenario::new();
    // `preheat top ` (trailing space) fails the library lane only —
    // `preheat top-binaries` must still execute, and the step exits
    // nonzero because a lane failed.
    let env = base_env(&[("STUB_FAIL_RE", "preheat top ")]);
    let runner = admin_runner(&scn, admin_ctx("1.98.1", &[]), env);

    let outcome = runner.outcome_of("Enqueue the top crates and the top binaries");
    assert!(
        matches!(outcome, Outcome::Ran(code) if *code != 0),
        "{outcome:?}"
    );
    assert_eq!(runner.status(), Status::Failed);
    assert_eq!(admin_calls(&scn, "top").len(), 1);
    assert_eq!(admin_calls(&scn, "top-binaries").len(), 1);
    // A top-lane failure is not a reason to drop the projects lane —
    // only a real cancellation is (`!cancelled() && inputs.projects`).
    assert_eq!(
        runner.outcome_of("Enqueue the projects lane"),
        &Outcome::Ran(0)
    );
    assert_eq!(admin_calls(&scn, "projects").len(), 1);
}

#[test]
fn admin_top_binaries_off_skips_only_that_lane() {
    let scn = Scenario::new();
    let runner = admin_runner(
        &scn,
        admin_ctx("1.98.1", &[("top_binaries", Val::Bool(false))]),
        base_env(&[]),
    );
    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);
    assert_eq!(admin_calls(&scn, "top").len(), 1);
    assert_eq!(admin_calls(&scn, "top-binaries"), Vec::<Vec<String>>::new());
    assert_eq!(admin_calls(&scn, "projects").len(), 1);
}

#[test]
fn admin_projects_off_deselects_the_lane() {
    let scn = Scenario::new();
    let runner = admin_runner(
        &scn,
        admin_ctx("1.98.1", &[("projects", Val::Bool(false))]),
        base_env(&[]),
    );
    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);
    assert_eq!(
        runner.outcome_of("Enqueue the projects lane"),
        &Outcome::Skipped
    );
    assert_eq!(admin_calls(&scn, "projects"), Vec::<Vec<String>>::new());
}

// ---------------------------------------------------------------------------
// preheat-missed.yml
// ---------------------------------------------------------------------------

fn preheat_missed() -> serde_yml::Value {
    load_workflow("preheat-missed.yml")
}

#[test]
fn missed_declarations() {
    let wf = preheat_missed();
    assert_eq!(
        at(&wf, "on.schedule")
            .and_then(|s| s.as_sequence())
            .and_then(|s| field(&s[0], "cron"))
            .map(scalar)
            .as_deref(),
        Some("0 6 * * 1")
    );
    assert_eq!(
        at(&wf, "concurrency.group").map(scalar).as_deref(),
        Some("preheat-missed")
    );
    assert_eq!(
        at(&wf, "permissions.id-token").map(scalar).as_deref(),
        Some("write")
    );
    assert_eq!(
        at(&wf, "permissions.contents").map(scalar).as_deref(),
        Some("read")
    );
    let steps = job_steps(&wf, "preheat-missed");
    let toolchain = steps
        .iter()
        .find(|s| {
            s.uses
                .as_deref()
                .is_some_and(|u| u.starts_with("dtolnay/rust-toolchain"))
        })
        .expect("toolchain step");
    assert_eq!(
        toolchain.with.get("toolchain").map(String::as_str),
        Some("stable")
    );
}

fn missed_runner(scn: &Scenario, ctx: Val) -> support::Runner<'_> {
    let wf = preheat_missed();
    run_job(scn, &wf, "preheat-missed", ctx, base_env(&[]))
}

fn missed_calls(scn: &Scenario) -> Vec<Vec<String>> {
    scn.calls_of("stow-admin")
        .into_iter()
        .filter(|c| {
            c.argv.first().map(String::as_str) == Some("preheat")
                && c.argv.get(1).map(String::as_str) == Some("missed")
        })
        .map(|c| c.argv[2..].to_vec())
        .collect()
}

#[test]
fn missed_scheduled_run_uses_declared_defaults() {
    // A `schedule` run carries an empty `inputs` context — the `||`
    // fallbacks in the step env are what produce 50/7/"".
    let scn = Scenario::new();
    let ctx = actions_ctx(); // schedule; no inputs set
    let runner = missed_runner(&scn, ctx);
    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);

    let calls = missed_calls(&scn);
    assert_eq!(calls.len(), 1, "{calls:?}");
    let argv = &calls[0];
    assert_eq!(
        flag_value(argv, "--rustc-version").as_deref(),
        Some(CHANNEL_FIXTURE_VERSION),
        "the channel step's resolved rustc must reach the lane"
    );
    assert_eq!(flag_value(argv, "--limit").as_deref(), Some("50"));
    assert_eq!(flag_value(argv, "--since-days").as_deref(), Some("7"));
    assert!(flag_value(argv, "--targets").is_none(), "{argv:?}");
    assert!(argv.iter().any(|a| a == "--yes"));

    let call = scn.calls_of("stow-admin").pop().expect("call");
    assert_eq!(
        call.env.get("CF_ACCOUNT_ID").map(String::as_str),
        Some("test-account")
    );
    assert_eq!(
        call.env.get("CF_ANALYTICS_TOKEN").map(String::as_str),
        Some("<set>")
    );
    assert_eq!(
        call.env.get("STOW_EDGE_URL").map(String::as_str),
        Some("https://edge.invalid")
    );
    assert_eq!(
        call.env.get("STOW_OIDC_AUDIENCE").map(String::as_str),
        Some("test-audience")
    );
}

#[test]
fn missed_dispatch_forwards_explicit_inputs() {
    let scn = Scenario::new();
    let mut ctx = actions_ctx();
    set_path(
        &mut ctx,
        "github.event_name",
        Val::Str("workflow_dispatch".to_owned()),
    );
    let ctx = with_inputs(
        ctx,
        &[
            ("limit", Val::Str("5".to_owned())),
            ("since_days", Val::Str("2".to_owned())),
            (
                "targets",
                Val::Str("x86_64-unknown-linux-gnu,aarch64-apple-darwin".to_owned()),
            ),
        ],
    );
    let runner = missed_runner(&scn, ctx);
    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);
    let calls = missed_calls(&scn);
    assert_eq!(calls.len(), 1);
    assert_eq!(flag_value(&calls[0], "--limit").as_deref(), Some("5"));
    assert_eq!(flag_value(&calls[0], "--since-days").as_deref(), Some("2"));
    assert_eq!(
        flag_value(&calls[0], "--targets").as_deref(),
        Some("x86_64-unknown-linux-gnu,aarch64-apple-darwin")
    );
}

// ---------------------------------------------------------------------------
// preheat-projects.yml
// ---------------------------------------------------------------------------

fn preheat_projects() -> serde_yml::Value {
    load_workflow("preheat-projects.yml")
}

/// The `run:` steps of preheat-projects never speak git directly — the
/// signed commit + PR go through the declared create-pull-request
/// action, and no step may add an unsigned `git commit`/`git push`/`gh
/// pr`/`--force` path around it.
#[test]
fn projects_delegates_to_signed_action_only() {
    let wf = preheat_projects();
    assert_eq!(
        at(&wf, "on.schedule")
            .and_then(|s| s.as_sequence())
            .and_then(|s| field(&s[0], "cron"))
            .map(scalar)
            .as_deref(),
        Some("30 5 * * 1")
    );
    assert_eq!(
        at(&wf, "concurrency.group").map(scalar).as_deref(),
        Some("preheat-projects")
    );
    // The regeneration branch needs both grants — but only the action
    // uses them.
    assert_eq!(
        at(&wf, "permissions.contents").map(scalar).as_deref(),
        Some("write")
    );
    assert_eq!(
        at(&wf, "permissions.pull-requests").map(scalar).as_deref(),
        Some("write")
    );

    let steps = job_steps(&wf, "regenerate");
    let create = steps
        .iter()
        .find(|s| {
            s.uses
                .as_deref()
                .is_some_and(|u| u.starts_with("peter-evans/create-pull-request@"))
        })
        .expect("create-pull-request step");
    // Pin + sign-commits:true — `createCommitOnBranch` is signed by
    // GitHub itself, satisfying the signed-commits ruleset a
    // `github-actions[bot]` commit could not.
    assert_eq!(
        create.uses.as_deref(),
        Some("peter-evans/create-pull-request@5f6978faf089d4d20b00c7766989d076bb2fc7f1")
    );
    assert_eq!(
        create.with.get("sign-commits").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        create.with.get("branch").map(String::as_str),
        Some("preheat/projects-list")
    );
    assert_eq!(
        create.with.get("body-path").map(String::as_str),
        Some("/tmp/pr-body.md")
    );
    assert!(create.with.contains_key("commit-message"));
    // An empty diff no-ops inside the action (the declaration replaces
    // any hand-rolled "changed?" gate), so "no change → no PR" follows
    // the declared mechanism — and no second path may exist.
    for step in &steps {
        if let Some(run) = &step.run {
            for forbidden in [
                "git commit",
                "git push",
                "git config",
                "gh pr",
                "gh api",
                "--force",
                "-f ",
            ] {
                assert!(
                    !run.contains(forbidden),
                    "step {:?} bypasses the declared action with `{forbidden}`:\n{run}",
                    step.name
                );
            }
        }
    }
}

#[test]
fn projects_generate_feeds_the_pr_body() {
    let wf = preheat_projects();
    let scn = Scenario::new();
    // The generate lane's report is the PR's body; the project file is
    // written under --output inside the scenario workdir, never in the
    // checkout.
    let report = "accepted: water-rs/stow\nrejected: example/no-lockfile (no Cargo.lock)\n";
    let projects_toml = "[[projects]]\nrepo = \"water-rs/stow\"\n";
    let env = base_env(&[
        ("STUB_STDOUT", report),
        ("STUB_OUTPUT_CONTENT", projects_toml),
    ]);
    let mut runner = support::Runner::new(&scn, actions_ctx(), env);
    runner.run_job(&wf, "regenerate");
    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);

    let generate = scn
        .calls_of("stow-admin")
        .into_iter()
        .find(|c| {
            c.argv.first().map(String::as_str) == Some("preheat")
                && c.argv.get(1).map(String::as_str) == Some("projects")
                && c.argv.get(2).map(String::as_str) == Some("generate")
        })
        .expect("generate call");
    assert_eq!(
        flag_value(&generate.argv[3..], "--output").as_deref(),
        Some("preheat/projects.toml")
    );
    // GH_TOKEN authenticates the search/git-trees reads — present, and
    // masked in the log.
    assert_eq!(
        generate.env.get("GH_TOKEN").map(String::as_str),
        Some("<set>")
    );

    // The generated file landed in the workdir; the checked-out
    // `preheat/projects.toml` and the source tree are untouched.
    assert_eq!(
        std::fs::read_to_string(scn.workdir().join("preheat/projects.toml"))
            .expect("generated projects.toml"),
        projects_toml
    );

    // tee captured the stdout report; the body step embedded it
    // verbatim between the fences.
    let body = std::fs::read_to_string("/tmp/pr-body.md").expect("pr-body.md");
    assert!(body.contains(report.trim()), "{body}");
    assert!(body.contains("```"), "{body}");
    assert!(
        body.contains("_Regenerated by preheat-projects.yml"),
        "{body}"
    );
}

// ---------------------------------------------------------------------------
// index-publish-cron.yml
// ---------------------------------------------------------------------------

fn index_publish_cron() -> serde_yml::Value {
    load_workflow("index-publish-cron.yml")
}

#[test]
fn index_publish_declarations() {
    let wf = index_publish_cron();
    // Fires on a completed build-crate run, on the backstop schedule,
    // and manually.
    assert_eq!(
        at(&wf, "on.workflow_run.workflows")
            .and_then(|s| s.as_sequence())
            .map(|s| s.iter().map(scalar).collect::<Vec<_>>()),
        Some(vec!["build-crate".to_owned()])
    );
    assert_eq!(
        at(&wf, "on.workflow_run.types")
            .and_then(|s| s.as_sequence())
            .map(|s| s.iter().map(scalar).collect::<Vec<_>>()),
        Some(vec!["completed".to_owned()])
    );
    assert_eq!(
        at(&wf, "on.schedule")
            .and_then(|s| s.as_sequence())
            .and_then(|s| field(&s[0], "cron"))
            .map(scalar)
            .as_deref(),
        Some("*/10 * * * *")
    );
    assert!(at(&wf, "on.workflow_dispatch").is_some());
    // Tick/publisher concurrency: one pending tick, superseded freely.
    assert_eq!(
        at(&wf, "concurrency.group").map(scalar).as_deref(),
        Some("index-publish-cron")
    );
    assert_eq!(
        at(&wf, "concurrency.cancel-in-progress")
            .map(scalar)
            .as_deref(),
        Some("true")
    );
    assert_eq!(
        at(&wf, "permissions.actions").map(scalar).as_deref(),
        Some("write")
    );
    assert_eq!(
        at(&wf, "permissions.contents").map(scalar).as_deref(),
        Some("read")
    );
    assert_eq!(
        at(&wf, "jobs.dispatch.timeout-minutes")
            .map(scalar)
            .as_deref(),
        Some("5")
    );
}

fn index_runner<'a>(
    scn: &'a Scenario,
    event: &str,
    run_title: Option<&str>,
) -> support::Runner<'a> {
    let wf = index_publish_cron();
    let mut ctx = actions_ctx();
    set_path(&mut ctx, "github.event_name", Val::Str(event.to_owned()));
    set_path(
        &mut ctx,
        "github.event.workflow_run.display_title",
        run_title.map_or(Val::Null, |t| Val::Str(t.to_owned())),
    );
    run_job(scn, &wf, "dispatch", ctx, base_env(&[]))
}

#[test]
fn index_publish_completion_forwards_title_rustc() {
    let scn = Scenario::new();
    let runner = index_runner(&scn, "workflow_run", Some("1.98.1-a1b2c3d4e5f6"));
    assert_eq!(
        runner.outcome_of("Dispatch index-publish on main"),
        &Outcome::Ran(0)
    );
    let gh = scn.calls_of("gh");
    assert_eq!(gh.len(), 1, "{gh:?}");
    let args = gh_dispatch_args(&gh[0]);
    assert_eq!(args[0], "index-publish.yml");
    // Always --ref main: the signing identity lives on main only.
    let ref_idx = args.iter().position(|a| a == "--ref").expect("--ref");
    assert_eq!(args[ref_idx + 1], "main");
    assert!(
        !args.iter().any(|a| a == "dev"),
        "index-publish dispatched on dev: {args:?}"
    );
    let fields = input_fields(&args);
    assert_eq!(
        fields.get("stow_edge_url").map(String::as_str),
        Some("https://edge.invalid"),
        "the configured edge URL forwards verbatim — never probed"
    );
    assert_eq!(
        fields.get("rustc_version").map(String::as_str),
        Some("1.98.1"),
        "the `<rustc>-<task_id>` run title's rustc prefix"
    );
    assert_eq!(fields.len(), 2, "{fields:?}");
    // Nothing probed the URL — `gh` was the only outbound tool.
    assert!(scn.calls_of("curl").is_empty(), "{:?}", scn.calls());
    assert_eq!(gh[0].env.get("GH_TOKEN").map(String::as_str), Some("<set>"));
}

#[test]
fn index_publish_schedule_and_manual_carry_no_rustc() {
    for event in ["schedule", "workflow_dispatch"] {
        let scn = Scenario::new();
        let runner = index_runner(&scn, event, None);
        assert_eq!(
            runner.outcome_of("Dispatch index-publish on main"),
            &Outcome::Ran(0)
        );
        let gh = scn.calls_of("gh");
        assert_eq!(gh.len(), 1);
        let args = gh_dispatch_args(&gh[0]);
        let fields = input_fields(&args);
        assert!(
            !fields.contains_key("rustc_version"),
            "{event} forwarded a rustc: {fields:?}"
        );
        assert_eq!(
            fields.get("stow_edge_url").map(String::as_str),
            Some("https://edge.invalid")
        );
        let ref_idx = args.iter().position(|a| a == "--ref").expect("--ref");
        assert_eq!(args[ref_idx + 1], "main");
    }
}

#[test]
fn index_publish_title_with_extra_dashes_keeps_rustc_prefix() {
    // `${RUN_TITLE%%-*}` trims at the FIRST dash — a task id that is
    // itself dashed (`1.99.0-beta-…` never occurs, but any suffix at
    // all) must not bleed into the forwarded rustc.
    let scn = Scenario::new();
    let runner = index_runner(&scn, "workflow_run", Some("1.99.0-task-9f8e7d-extra"));
    assert_eq!(
        runner.outcome_of("Dispatch index-publish on main"),
        &Outcome::Ran(0)
    );
    let gh = scn.calls_of("gh");
    let fields = input_fields(&gh_dispatch_args(&gh[0]));
    assert_eq!(
        fields.get("rustc_version").map(String::as_str),
        Some("1.99.0")
    );
}

/// The five entrypoints' every job runs on a Linux runner — the
/// premise that confines this bash-driven suite to Linux hosts.
#[test]
fn entrypoints_run_on_linux_runners() {
    for file in [
        "preheat-cron.yml",
        "preheat-admin.yml",
        "preheat-missed.yml",
        "preheat-projects.yml",
        "index-publish-cron.yml",
    ] {
        let workflow = load_workflow(file);
        let jobs = field(&workflow, "jobs")
            .and_then(serde_yml::Value::as_mapping)
            .unwrap_or_else(|| panic!("{file} declares no jobs"));
        for (name, job) in jobs {
            let runner = field(job, "runs-on").map(scalar);
            assert_eq!(
                runner.as_deref(),
                Some("ubuntu-latest"),
                "{file} job {} runs on {runner:?}",
                scalar(name)
            );
        }
    }
}

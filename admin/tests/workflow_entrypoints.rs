//! Isolation regressions for the five `disabled_manually` workflow
//! entrypoints (stow#593): `preheat-cron.yml`, `preheat-admin.yml`,
//! `preheat-missed.yml`, `preheat-projects.yml`, `index-publish-cron.yml`
//! — and for `operations.yml`, the traced operator path (stow#955).
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
    // The cadence is the edge Cron Trigger's (stow#1100), pinned by
    // `periodic_schedule.rs`; GitHub's `schedule` stays only until that
    // trigger is deployed.
    // The edge's Cron Trigger and an operator both dispatch it.
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
    // the projects lane enabled.
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

/// `refresh` (a scheduler reset's refill) dispatches although the day's
/// marker exists, and saves nothing: the restored entry is the marker.
#[test]
fn cron_refresh_dispatches_on_a_cache_hit() {
    let wf = preheat_cron();
    let scn = Scenario::new();
    let ctx = with_inputs(actions_ctx(), &[("refresh", Val::Bool(true))]);
    let mut runner = support::Runner::new(&scn, ctx, base_env(&[]));
    runner.seed_output("marker", "cache-hit", "true");
    runner.run_job(&wf, "preheat");

    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);
    assert_eq!(runner.outcome_of("Already preheated"), &Outcome::Skipped);
    assert_eq!(
        runner.outcome_of("Dispatch the preheat wave"),
        &Outcome::Ran(0)
    );
    assert_eq!(
        runner.outcome_of("Record the wave marker"),
        &Outcome::Skipped
    );
    let gh = scn.calls_of("gh");
    assert_eq!(gh.len(), 1, "{gh:?}");
    assert_eq!(
        gh_dispatch_args(&gh[0]).first().map(String::as_str),
        Some("preheat-admin.yml")
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

/// The admin lane's `preheat top-binaries`/`projects submit` argv
/// tails, grouped by subcommand.
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
fn admin_all_nine_targets_every_lane() {
    let scn = Scenario::new();
    let runner = admin_runner(&scn, admin_ctx("1.98.1", &[]), base_env(&[]));
    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);

    let want = expected_targets();
    let calls = admin_calls(&scn, "top-binaries");
    assert_eq!(calls.len(), 1, "{calls:?}");
    let argv = &calls[0];
    assert_eq!(
        flag_value(argv, "--targets").as_deref(),
        Some(want.as_str())
    );
    assert_eq!(
        flag_value(argv, "--rustc-version").as_deref(),
        Some("1.98.1")
    );
    assert_eq!(flag_value(argv, "--limit").as_deref(), Some("100"));
    assert!(argv.iter().any(|a| a == "--yes"));
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
    for argv in admin_calls(&scn, "top-binaries") {
        assert_eq!(
            flag_value(&argv, "--targets").as_deref(),
            Some("x86_64-unknown-linux-gnu,aarch64-apple-darwin")
        );
    }
}

#[test]
fn admin_binary_lane_failure_still_runs_projects() {
    let scn = Scenario::new();
    // A top-binaries failure fails its step, but is not a reason to
    // drop the projects lane — only a real cancellation is
    // (`!cancelled() && inputs.projects`).
    let env = base_env(&[("STUB_FAIL_RE", "preheat top-binaries")]);
    let runner = admin_runner(&scn, admin_ctx("1.98.1", &[]), env);

    let outcome = runner.outcome_of("Enqueue the top binary crates");
    assert!(
        matches!(outcome, Outcome::Ran(code) if *code != 0),
        "{outcome:?}"
    );
    assert_eq!(runner.status(), Status::Failed);
    assert_eq!(admin_calls(&scn, "top-binaries").len(), 1);
    assert_eq!(
        runner.outcome_of("Enqueue the projects lane"),
        &Outcome::Ran(0)
    );
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
        fields.get("report").map(String::as_str),
        Some("true"),
        "a configured edge turns reporting on — never probed, never forwarded"
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
        assert_eq!(fields.get("report").map(String::as_str), Some("true"));
        let ref_idx = args.iter().position(|a| a == "--ref").expect("--ref");
        assert_eq!(args[ref_idx + 1], "main");
    }
}

#[test]
fn index_publish_title_with_extra_dashes_keeps_rustc_prefix() {
    // `${RUN_TITLE%%-*}` trims at the FIRST dash — the `<rustc>-<task_id>`
    // title's hex suffix never dashes, but any suffix at all must not
    // bleed into the forwarded rustc.
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

// ---------------------------------------------------------------------------
// build-crate.yml — the dispatched per-task build
// ---------------------------------------------------------------------------

/// The scheduler's deliveries-stopped bound (stow#860) is the sum of the
/// timeouts of the `build-crate.yml` jobs a task run executes; a timeout
/// change must move it. The operator's repack job never runs in a task
/// run, so its bound is not part of the scheduler's.
#[test]
fn build_crate_run_timeout_matches_the_jobs() {
    let wf = load_workflow("build-crate.yml");
    let jobs = field(&wf, "jobs")
        .and_then(serde_yml::Value::as_mapping)
        .expect("jobs mapping");
    let mut minutes = 0;
    for (name, job) in jobs {
        let condition = field(job, "if")
            .map(scalar)
            .expect("every build-crate.yml job states which run kind executes it");
        let timeout = field(job, "timeout-minutes")
            .map(scalar)
            .expect("every build-crate.yml job sets timeout-minutes")
            .parse::<i64>()
            .expect("timeout-minutes is an integer");
        if condition.starts_with("inputs.repack_rustc == ''") {
            minutes += timeout;
        } else {
            assert_eq!(
                condition,
                "inputs.repack_rustc != ''",
                "job {} runs in neither a task run nor a repack run",
                scalar(name)
            );
        }
    }
    assert_eq!(minutes, stow_types::api::BUILD_CRATE_RUN_TIMEOUT_MINUTES);
}

/// `build-crate.yml` is the dispatched per-task build: one
/// `workflow_dispatch` input `task` carries the whole `BuildTaskPayload`,
/// the run's `run-name` stamps `<rustc>-<task_id>` for the completion
/// webhook's `display_title`, and a per-task concurrency group keeps the
/// same task's re-dispatch from racing an earlier one (no cancel).
#[test]
fn build_crate_declarations() {
    let wf = load_workflow("build-crate.yml");
    let triggers: Vec<String> = field(&wf, "on")
        .and_then(serde_yml::Value::as_mapping)
        .expect("on mapping")
        .keys()
        .map(scalar)
        .collect();
    assert_eq!(
        triggers,
        ["workflow_dispatch"],
        "build-crate.yml is dispatched only: {triggers:?}"
    );
    // A task run carries the payload in `task`; a repack run names its
    // rustc in `repack_rustc` instead and leaves `task` at its default.
    assert_eq!(
        at(&wf, "on.workflow_dispatch.inputs.task.default")
            .map(scalar)
            .as_deref(),
        Some("{}")
    );
    assert_eq!(
        at(&wf, "on.workflow_dispatch.inputs.repack_rustc.default")
            .map(scalar)
            .as_deref(),
        Some("")
    );
    // Per-task run-name binds the `workflow_run` completion: the
    // scheduler's webhook parses `<rustc>-<task_id>` off `display_title`.
    // A repack run's `<rustc>-repack` names no task.
    assert_eq!(
        at(&wf, "run-name").map(scalar).as_deref(),
        Some(
            "${{ inputs.repack_rustc != '' && format('{0}-repack', inputs.repack_rustc) || format('{0}-{1}', fromJSON(inputs.task).rustc_version, fromJSON(inputs.task).task_id) }}"
        )
    );
    // Per-task concurrency, and one repack sweep per rustc, never
    // cancelling an earlier run.
    assert_eq!(
        at(&wf, "concurrency.group").map(scalar).as_deref(),
        Some(
            "${{ inputs.repack_rustc != '' && format('repack-{0}', inputs.repack_rustc) || format('build-crate-{0}', fromJSON(inputs.task).task_id) }}"
        )
    );
    assert_eq!(
        at(&wf, "concurrency.cancel-in-progress")
            .map(scalar)
            .as_deref(),
        Some("false")
    );
    // The untrusted build job and the trusted publish job.
    assert_eq!(
        at(&wf, "jobs.build.name").map(scalar).as_deref(),
        Some(
            "build ${{ fromJSON(inputs.task).crate_name }} ${{ fromJSON(inputs.task).version }} (${{ fromJSON(inputs.task).target }})"
        )
    );
    assert_eq!(
        at(&wf, "jobs.publish.name").map(scalar).as_deref(),
        Some("publish")
    );
    assert_eq!(
        at(&wf, "jobs.build.permissions.contents")
            .map(scalar)
            .as_deref(),
        Some("read")
    );
    assert_eq!(
        at(&wf, "jobs.build.permissions.packages")
            .map(scalar)
            .as_deref(),
        Some("read")
    );
    assert_eq!(
        at(&wf, "jobs.publish.permissions.contents")
            .map(scalar)
            .as_deref(),
        Some("read")
    );
    assert_eq!(
        at(&wf, "jobs.publish.permissions.packages")
            .map(scalar)
            .as_deref(),
        Some("write")
    );
    assert_eq!(
        at(&wf, "jobs.publish.permissions.id-token")
            .map(scalar)
            .as_deref(),
        Some("write")
    );
    assert_eq!(
        at(&wf, "jobs.publish.needs").map(scalar).as_deref(),
        Some("build")
    );
    assert_eq!(
        at(&wf, "jobs.publish.if").map(scalar).as_deref(),
        Some("inputs.repack_rustc == '' && needs.build.result == 'success'")
    );
}

/// The operator's repack job runs only in a repack run and republishes
/// under the builder identity, so it holds the publish job's rights.
#[test]
fn build_crate_repack_job() {
    let wf = load_workflow("build-crate.yml");
    assert_eq!(
        at(&wf, "jobs.repack.if").map(scalar).as_deref(),
        Some("inputs.repack_rustc != ''")
    );
    for (permission, level) in [
        ("contents", "read"),
        ("packages", "write"),
        ("id-token", "write"),
    ] {
        assert_eq!(
            at(&wf, &format!("jobs.repack.permissions.{permission}"))
                .map(scalar)
                .as_deref(),
            Some(level),
            "repack job permission {permission}"
        );
    }
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
        "operations.yml",
        "repack-followup.yml",
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

// ===========================================================================
// operations.yml (stow#955)
// ===========================================================================

fn operations() -> serde_yml::Value {
    load_workflow("operations.yml")
}

/// A dispatch of `operations.yml` with `argv` (and `files` when given),
/// carrying every secret and variable the workflow may hand a step.
fn operations_runner<'a>(
    scn: &'a Scenario,
    argv: &str,
    files: Option<&str>,
) -> support::Runner<'a> {
    operations_runner_env(scn, argv, files, &[])
}

fn operations_runner_with<'a>(
    scn: &'a Scenario,
    argv: &str,
    env: &[(&str, &str)],
) -> support::Runner<'a> {
    operations_runner_env(scn, argv, None, env)
}

fn operations_runner_env<'a>(
    scn: &'a Scenario,
    argv: &str,
    files: Option<&str>,
    env: &[(&str, &str)],
) -> support::Runner<'a> {
    let mut ctx = actions_ctx();
    set_path(
        &mut ctx,
        "github.event_name",
        Val::Str("workflow_dispatch".to_owned()),
    );
    for (key, value) in [
        ("github.actor", "octo-dispatcher"),
        ("secrets.GITHUB_TOKEN", "test-github-token"),
        ("secrets.CLOUDFLARE_API_TOKEN", "test-cloudflare-token"),
        ("vars.CF_ZONE_ID", "test-zone"),
    ] {
        set_path(&mut ctx, key, Val::Str(value.to_owned()));
    }
    let mut inputs = vec![("argv", Val::Str(argv.to_owned()))];
    if let Some(files) = files {
        inputs.push(("files", Val::Str(files.to_owned())));
    }
    let mut ctx = with_inputs(ctx, &inputs);
    let wf = operations();
    apply_dispatch_defaults(&mut ctx, &wf);
    run_job(scn, &wf, "run", ctx, base_env(env))
}

/// The `stow-admin` invocations of the run step (the toolchain step is a
/// declared `uses:`).
fn operations_calls(scn: &Scenario) -> Vec<Call> {
    scn.calls_of("stow-admin")
}

#[test]
fn operations_declarations() {
    let wf = operations();
    let triggers = field(&wf, "on")
        .and_then(serde_yml::Value::as_mapping)
        .expect("triggers");
    assert_eq!(
        triggers.keys().map(scalar).collect::<Vec<_>>(),
        vec!["workflow_dispatch".to_owned()],
        "dispatch is the only trigger — no other event may run it"
    );
    assert_eq!(
        at(&wf, "jobs.run.environment").map(scalar).as_deref(),
        Some("operations")
    );
    assert_eq!(
        at(&wf, "permissions.id-token").map(scalar).as_deref(),
        Some("write")
    );
    assert_eq!(
        at(&wf, "concurrency.group").map(scalar).as_deref(),
        Some("operations")
    );
}

/// The command line is data: an argument carrying shell syntax reaches
/// stow-admin as one literal argument, and an edge-class command sees
/// no Cloudflare credential and no GitHub token.
#[test]
fn operations_replays_argv_literally_without_secrets() {
    let scn = Scenario::new();
    let runner = operations_runner(
        &scn,
        r#"["queue","cancel","--crate","a b; $(touch pwned)","--yes"]"#,
        None,
    );
    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);
    let calls = operations_calls(&scn);
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(
        calls[0].argv,
        ["queue", "cancel", "--crate", "a b; $(touch pwned)", "--yes"]
    );
    assert!(!scn.workdir().join("pwned").exists(), "argv was evaluated");
    for secret in ["CLOUDFLARE_API_TOKEN", "CF_ANALYTICS_TOKEN", "GH_TOKEN"] {
        assert_eq!(
            calls[0].env.get(secret).map(String::as_str),
            Some("<empty>"),
            "{secret} leaked into an edge command"
        );
    }
    assert_eq!(
        calls[0].env.get("STOW_EDGE_URL").map(String::as_str),
        Some("https://edge.invalid")
    );
}

/// Each secret reaches only the command class that needs it.
#[test]
fn operations_scopes_secrets_by_command() {
    for (argv, cloudflare, analytics) in [
        (
            r#"["maintenance","on","--scope","lanes","--yes"]"#,
            "<set>",
            "<empty>",
        ),
        (r#"["watchdog","clear"]"#, "<set>", "<empty>"),
        (
            r#"["preheat","missed","--rustc-version","1.98.1","--yes"]"#,
            "<empty>",
            "<set>",
        ),
        (r#"["preheat","binary","--yes"]"#, "<empty>", "<empty>"),
    ] {
        let scn = Scenario::new();
        let runner = operations_runner(&scn, argv, None);
        assert_eq!(runner.status(), Status::Ok, "{argv}: {:?}", runner.outcomes);
        let calls = operations_calls(&scn);
        assert_eq!(calls.len(), 1, "{argv}: {calls:?}");
        assert_eq!(
            calls[0].env.get("CLOUDFLARE_API_TOKEN").map(String::as_str),
            Some(cloudflare),
            "{argv}"
        );
        assert_eq!(
            calls[0].env.get("GH_TOKEN").map(String::as_str),
            Some(cloudflare),
            "{argv}"
        );
        assert_eq!(
            calls[0].env.get("CF_ANALYTICS_TOKEN").map(String::as_str),
            Some(analytics),
            "{argv}"
        );
    }
}

/// Commands outside the operator set, malformed argv and file names
/// that leave the files directory never reach stow-admin.
#[test]
fn operations_refuses_what_it_does_not_run() {
    for (argv, files) in [
        (r#"["deploy","verdict","--phase","canary"]"#, None),
        (r#"["index","report"]"#, None),
        (r#""queue retry --yes""#, None),
        ("[]", None),
        (r#"["queue",1]"#, None),
        (
            r#"["preheat","manual","--yes"]"#,
            Some(r#"{"../escape":"x"}"#),
        ),
        (r#"["preheat","manual","--yes"]"#, Some(r#"{"a/b":"x"}"#)),
        (r#"["preheat","manual","--yes"]"#, Some(r#"{"..":"x"}"#)),
    ] {
        let scn = Scenario::new();
        let runner = operations_runner(&scn, argv, files);
        assert_eq!(runner.status(), Status::Failed, "{argv} {files:?}");
        assert!(
            operations_calls(&scn).is_empty(),
            "{argv} {files:?} reached stow-admin"
        );
    }
}

// ---------------------------------------------------------------------------
// operations.yml: the refill after a scheduler reset (stow#1094)
// ---------------------------------------------------------------------------

/// The `gh workflow run` calls of the refill step: workflow file, ref and
/// input fields.
fn refill_dispatches(scn: &Scenario) -> Vec<(String, String, BTreeMap<String, String>)> {
    scn.calls_of("gh")
        .iter()
        .filter(|call| call.argv.first().map(String::as_str) == Some("workflow"))
        .map(|call| {
            let args = gh_dispatch_args(call);
            let reference = args
                .iter()
                .position(|a| a == "--ref")
                .and_then(|i| args.get(i + 1))
                .cloned()
                .expect("dispatch names its ref");
            (args[0].clone(), reference, input_fields(&args))
        })
        .collect()
}

const RESET_ARGV: &str = r#"["scheduler","reset","--yes"]"#;

#[test]
fn operations_reset_refills_every_published_rustc_and_forces_a_preheat() {
    let scn = Scenario::new();
    let runner = operations_runner_with(&scn, RESET_ARGV, &[("STUB_STDOUT", "1.99.0\n1.99.1\n")]);
    assert_eq!(runner.status(), Status::Ok, "{:?}", runner.outcomes);
    assert_eq!(
        runner.outcome_of("Refill the index report and the queue after a reset"),
        &Outcome::Ran(0)
    );
    // The reset, then the enumeration of the published rustcs.
    let admin = operations_calls(&scn);
    assert_eq!(admin.len(), 2, "{admin:?}");
    assert_eq!(admin[0].argv, ["scheduler", "reset", "--yes"]);
    assert_eq!(admin[1].argv, ["index", "published-rustcs"]);

    let report = |rustc: &str| {
        (
            "index-publish.yml".to_owned(),
            "main".to_owned(),
            BTreeMap::from([
                ("report".to_owned(), "true".to_owned()),
                ("rustc_version".to_owned(), rustc.to_owned()),
            ]),
        )
    };
    assert_eq!(
        refill_dispatches(&scn),
        vec![
            report("1.99.0"),
            report("1.99.1"),
            (
                "preheat-cron.yml".to_owned(),
                "main".to_owned(),
                BTreeMap::from([("refresh".to_owned(), "true".to_owned())]),
            ),
        ]
    );
    let refill = scn
        .calls_of("gh")
        .into_iter()
        .find(|c| c.argv.first().map(String::as_str) == Some("workflow"))
        .expect("a dispatch");
    assert_eq!(
        refill.env.get("GH_TOKEN").map(String::as_str),
        Some("<set>")
    );
    assert_eq!(
        refill.env.get("GH_REPO").map(String::as_str),
        Some("water-rs/stow")
    );
}

/// Only a reset refills: every other command, and a reset that failed,
/// dispatches nothing.
#[test]
fn operations_refills_only_after_a_successful_reset() {
    for argv in [
        r#"["queue","purge","--yes"]"#,
        r#"["scheduler","demand-feed"]"#,
        r#"["preheat","binary","--yes"]"#,
    ] {
        let scn = Scenario::new();
        let runner = operations_runner_with(&scn, argv, &[("STUB_STDOUT", "1.99.0")]);
        assert_eq!(runner.status(), Status::Ok, "{argv}: {:?}", runner.outcomes);
        assert!(refill_dispatches(&scn).is_empty(), "{argv}");
    }
    let scn = Scenario::new();
    let runner = operations_runner_with(
        &scn,
        RESET_ARGV,
        &[("STUB_STDOUT", "1.99.0"), ("STUB_ADMIN_EXIT", "1")],
    );
    assert_eq!(runner.status(), Status::Failed);
    assert_eq!(
        runner.outcome_of("Refill the index report and the queue after a reset"),
        &Outcome::Skipped
    );
    assert!(
        refill_dispatches(&scn).is_empty(),
        "a failed reset refilled"
    );
}

/// A failed enumeration or dispatch fails the run, and an enumeration
/// that fails dispatches nothing at all.
#[test]
fn operations_refill_failure_fails_the_run() {
    for (fail, dispatched) in [
        ("published-rustcs", 0),
        ("index-publish", 1),
        ("preheat-cron", 3),
    ] {
        let scn = Scenario::new();
        let runner = operations_runner_with(
            &scn,
            RESET_ARGV,
            &[("STUB_STDOUT", "1.99.0\n1.99.1\n"), ("STUB_FAIL_RE", fail)],
        );
        assert_eq!(runner.status(), Status::Failed, "{fail}");
        assert_eq!(refill_dispatches(&scn).len(), dispatched, "{fail}");
    }
}

#[test]
fn operations_refill_and_preheat_cron_declare_what_they_dispatch() {
    let wf = operations();
    assert_eq!(
        at(&wf, "permissions.actions").map(scalar).as_deref(),
        Some("write")
    );
    let cron = preheat_cron();
    let dispatch = dispatch_inputs(&cron);
    assert!(dispatch.contains_key("refresh"), "{dispatch:?}");
}

/// The watchdog reads its history levels from the environment its two
/// entry points hand it (stow#1094).
#[test]
fn watchdog_entry_points_pass_the_history_levels() {
    let text = |file: &str| {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../.github/workflows")
                .join(file),
        )
        .expect("workflow file")
    };
    for file in ["watchdog.yml", "operations.yml"] {
        let text = text(file);
        for name in [
            "STOW_WATCHDOG_OPERATIONS_WINDOW_HOURS",
            "STOW_WATCHDOG_RUN_GAP_HOURS",
        ] {
            assert!(
                text.contains(&format!("{name}: ${{{{ vars.{name} }}}}")),
                "{file} does not pass {name}"
            );
        }
    }
}

// ===========================================================================
// index-publish.yml (stow#1104)
// ===========================================================================

/// Position of the step named `name` (exact) and its `if:` gate.
fn index_publish_step(steps: &[support::Step], name: &str) -> (usize, String) {
    let index = steps
        .iter()
        .position(|s| s.name == name)
        .unwrap_or_else(|| panic!("index-publish.yml has no step {name:?}"));
    (index, steps[index].if_cond.clone().unwrap_or_default())
}

/// Evaluate the `if:` gates of the reconcile steps for one dispatch
/// shape: the gates are the two conjunctions of `inputs.report` and
/// `inputs.full` the workflow declares.
fn gate_runs(gate: &str, report: bool, full: bool) -> bool {
    let gate = gate.replace("${{", "").replace("}}", "");
    match gate.trim() {
        "inputs.report && !inputs.full" => report && !full,
        "inputs.report && inputs.full" => report && full,
        other => panic!("unexpected reconcile gate {other:?}"),
    }
}

#[test]
fn index_publish_reconciles_after_the_publish_under_full() {
    let wf = load_workflow("index-publish.yml");
    let steps = job_steps(&wf, "publish");
    let reconcile_steps: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            s.run
                .as_deref()
                .is_some_and(|r| r.contains("stow-admin index reconcile"))
        })
        .collect();
    assert_eq!(
        reconcile_steps.len(),
        2,
        "one reconcile before the export, one after the publish"
    );
    let (export, _) = index_publish_step(&steps, "Export every index slice in one pass");
    let (publish, _) = index_publish_step(&steps, "Publish and sign each changed slice");
    assert!(export < publish);

    let (before, after) = (reconcile_steps[0], reconcile_steps[1]);
    assert!(before.0 < export, "the plain reconcile precedes the export");
    assert!(after.0 > publish, "the full reconcile follows the publish");
    let before_gate = before.1.if_cond.as_deref().unwrap_or_default();
    let after_gate = after.1.if_cond.as_deref().unwrap_or_default();
    assert_eq!(before.1.run, after.1.run, "both placements run one command");

    for (report, full) in [(false, false), (false, true), (true, false), (true, true)] {
        let ran_before = gate_runs(before_gate, report, full);
        let ran_after = gate_runs(after_gate, report, full);
        match (report, full) {
            (false, _) => assert!(!ran_before && !ran_after, "no reconcile without report"),
            (true, false) => assert!(
                ran_before && !ran_after,
                "report without full reconciles before the export"
            ),
            (true, true) => assert!(
                !ran_before && ran_after,
                "report with full reconciles after the publish"
            ),
        }
    }
}

// ===========================================================================
// repack-followup.yml
// ===========================================================================

fn repack_followup() -> serde_yml::Value {
    load_workflow("repack-followup.yml")
}

/// A completed `workflow_run` delivery for the follow-up's `job`.
fn followup_runner<'a>(
    scn: &'a Scenario,
    job: &str,
    title: &str,
    conclusion: &str,
    vars: &[(&str, &str)],
    env: &[(&str, &str)],
) -> support::Runner<'a> {
    let mut ctx = actions_ctx();
    set_path(
        &mut ctx,
        "github.event_name",
        Val::Str("workflow_run".to_owned()),
    );
    for (key, value) in [
        ("github.event.workflow_run.display_title", title),
        ("github.event.workflow_run.conclusion", conclusion),
        ("github.event.workflow_run.id", "4242"),
    ] {
        set_path(&mut ctx, key, Val::Str(value.to_owned()));
    }
    for (name, value) in vars {
        set_path(
            &mut ctx,
            &format!("vars.{name}"),
            Val::Str((*value).to_owned()),
        );
    }
    run_job(scn, &repack_followup(), job, ctx, base_env(env))
}

fn resume_runner<'a>(
    scn: &'a Scenario,
    title: &str,
    conclusion: &str,
    vars: &[(&str, &str)],
    env: &[(&str, &str)],
) -> support::Runner<'a> {
    followup_runner(scn, "resume", title, conclusion, vars, env)
}

const RESUME_STEP: &str = "Follow up the repack run";

/// The run list the per-day bound reads: `n` repack runs for 1.99.0 inside
/// the window (a far-future timestamp is always after the cutoff), the
/// last of them in progress when `active`.
fn runs_json(n: usize, active: bool) -> String {
    let runs: Vec<_> = (0..n)
        .map(|i| {
            let status = if active && i + 1 == n { "in_progress" } else { "completed" };
            format!(r#"{{"display_title":"1.99.0-repack","status":"{status}","created_at":"2099-01-01T00:00:00Z"}}"#)
        })
        .chain(std::iter::once(
            r#"{"display_title":"1.99.0-0123456789ab","status":"completed"}"#.to_owned(),
        ))
        .collect();
    format!(
        r#"{{"total_count":{},"workflow_runs":[{}]}}"#,
        runs.len(),
        runs.join(",")
    )
}

fn job_json(conclusion: &str, minutes: i64) -> String {
    let end = format!("2026-01-01T{:02}:{:02}:00Z", minutes / 60, minutes % 60);
    let start = "2026-01-01T00:00:00Z";
    format!(
        r#"{{"total_count":2,"jobs":[{{"name":"other","conclusion":"success","started_at":"{start}","completed_at":"{start}"}},{{"name":"repack 1.99.0","conclusion":"{conclusion}","started_at":"{start}","completed_at":"{end}"}}]}}"#,
    )
}

#[test]
fn followup_declarations() {
    let wf = repack_followup();
    assert_eq!(
        at(&wf, "on.workflow_run.workflows")
            .and_then(|s| s.as_sequence())
            .map(|s| s.iter().map(scalar).collect::<Vec<_>>()),
        Some(vec!["build-crate".to_owned(), "Index publish".to_owned()])
    );
    assert_eq!(
        at(&wf, "on.workflow_run.types")
            .and_then(|s| s.as_sequence())
            .map(|s| s.iter().map(scalar).collect::<Vec<_>>()),
        Some(vec!["completed".to_owned()])
    );
    assert!(at(&wf, "on.workflow_dispatch").is_none());
    assert_eq!(
        at(&wf, "permissions.actions").map(scalar).as_deref(),
        Some("write")
    );
    assert_eq!(
        at(&wf, "permissions.contents").map(scalar).as_deref(),
        Some("read")
    );
    // One group per completed run title; completions queue, never cancel.
    assert_eq!(
        at(&wf, "concurrency.group").map(scalar).as_deref(),
        Some("repack-followup-${{ github.event.workflow_run.display_title }}")
    );
    assert_eq!(
        at(&wf, "concurrency.cancel-in-progress")
            .map(scalar)
            .as_deref(),
        Some("false")
    );
    // The timeout the cancelled-job heuristic measures is the repack job's.
    let steps = job_steps(&wf, "resume");
    let env = &steps[0].env;
    let build = load_workflow("build-crate.yml");
    assert_eq!(
        env.get("REPACK_JOB_TIMEOUT_MINUTES").map(String::as_str),
        at(&build, "jobs.repack.timeout-minutes")
            .map(scalar)
            .as_deref()
    );
    // The retry follows the workflow `workflow_run` names, and the marker
    // reads the title `operations.yml` renders for the argv.
    let publish = load_workflow("index-publish.yml");
    assert_eq!(
        at(&publish, "name").map(scalar).as_deref(),
        Some("Index publish")
    );
    assert!(at(&publish, "on.workflow_dispatch.inputs.after_repack").is_none());
    let operations = load_workflow("operations.yml");
    assert_eq!(
        at(&operations, "run-name").map(scalar).as_deref(),
        Some("stow-admin ${{ inputs.argv }} (by ${{ github.actor }})")
    );
}

#[test]
fn followup_success_publishes_the_index_then_refreshes_the_preheat() {
    let scn = Scenario::new();
    let runner = resume_runner(&scn, "1.99.0-repack", "success", &[], &[]);
    assert_eq!(runner.outcome_of(RESUME_STEP), &Outcome::Ran(0));
    let dispatches = refill_dispatches(&scn);
    assert_eq!(
        dispatches,
        [
            (
                "index-publish.yml".to_owned(),
                "main".to_owned(),
                BTreeMap::from([
                    ("report".to_owned(), "true".to_owned()),
                    ("rustc_version".to_owned(), "1.99.0".to_owned()),
                ])
            ),
            (
                "preheat-cron.yml".to_owned(),
                "main".to_owned(),
                BTreeMap::from([("refresh".to_owned(), "true".to_owned())])
            ),
        ]
    );
}

const RETRY_STEP: &str = "Retry the failed nodes of repacked rustcs";
const REPACK_DONE: &str = "2026-03-01T10:00:00Z";
const RETRY_ARGV: &str = r#"["queue","retry","--status","failed","--rustc","1.99.0","--yes"]"#;

fn repack_run(title: &str, created: &str, conclusion: &str) -> String {
    format!(
        r#"{{"display_title":"{title}","created_at":"{created}","updated_at":"{REPACK_DONE}","status":"completed","conclusion":"{conclusion}"}}"#
    )
}

fn run_list(runs: &[String]) -> String {
    format!(r#"{{"workflow_runs":[{}]}}"#, runs.join(","))
}

/// A successful `Index publish` completion created at `index_created`,
/// with the given build-crate and operations run lists.
fn retry_runner<'a>(
    scn: &'a Scenario,
    index_created: &str,
    repacks: &[String],
    operations: &[String],
) -> support::Runner<'a> {
    let mut ctx = actions_ctx();
    set_path(
        &mut ctx,
        "github.event_name",
        Val::Str("workflow_run".to_owned()),
    );
    for (key, value) in [
        ("github.event.workflow_run.name", "Index publish"),
        ("github.event.workflow_run.conclusion", "success"),
        ("github.event.workflow_run.created_at", index_created),
    ] {
        set_path(&mut ctx, key, Val::Str(value.to_owned()));
    }
    let repacks = run_list(repacks);
    let operations = run_list(operations);
    let runner = run_job(
        scn,
        &repack_followup(),
        "retry",
        ctx,
        base_env(&[
            ("STUB_GH_RUNS", &repacks),
            ("STUB_GH_OPS_RUNS", &operations),
        ]),
    );
    assert_eq!(runner.outcome_of(RETRY_STEP), &Outcome::Ran(0));
    runner
}

fn retry_dispatches(scn: &Scenario) -> Vec<String> {
    let dispatches = refill_dispatches(scn);
    for (workflow, reference, _) in &dispatches {
        assert_eq!(
            (workflow.as_str(), reference.as_str()),
            ("operations.yml", "main")
        );
    }
    dispatches
        .into_iter()
        .map(|(_, _, fields)| fields["argv"].clone())
        .collect()
}

#[test]
fn followup_retry_fires_once_after_the_post_repack_fold() {
    let scn = Scenario::new();
    let repacks = [repack_run(
        "1.99.0-repack",
        "2026-03-01T06:00:00Z",
        "success",
    )];
    retry_runner(&scn, "2026-03-01T10:05:00Z", &repacks, &[]);
    assert_eq!(retry_dispatches(&scn), [RETRY_ARGV]);
    let gate = at(&repack_followup(), "jobs.retry.if")
        .map(scalar)
        .expect("retry gate");
    assert!(gate.contains("conclusion == 'success'"), "{gate}");
}

#[test]
fn followup_retry_waits_for_a_publish_created_after_the_repack() {
    let scn = Scenario::new();
    let repacks = [repack_run(
        "1.99.0-repack",
        "2026-03-01T06:00:00Z",
        "success",
    )];
    retry_runner(&scn, "2026-03-01T09:00:00Z", &repacks, &[]);
    assert!(retry_dispatches(&scn).is_empty(), "{:?}", scn.calls());
}

#[test]
fn followup_retry_is_one_shot() {
    let scn = Scenario::new();
    let repacks = [repack_run(
        "1.99.0-repack",
        "2026-03-01T06:00:00Z",
        "success",
    )];
    let operations = [
        r#"{"display_title":"stow-admin [\"scheduler\",\"reset\",\"--yes\"] (by a)"}"#.to_owned(),
        format!(
            r#"{{"display_title":{}}}"#,
            serde_json::to_string(&format!("stow-admin {RETRY_ARGV} (by github-actions[bot])"))
                .expect("json")
        ),
    ];
    retry_runner(&scn, "2026-03-01T10:30:00Z", &repacks, &operations);
    assert!(retry_dispatches(&scn).is_empty(), "{:?}", scn.calls());
}

#[test]
fn followup_retry_ignores_rustcs_without_a_successful_newest_repack() {
    let scn = Scenario::new();
    let repacks = [
        // 1.99.0: an older success, then a newer failure.
        repack_run("1.99.0-repack", "2026-03-01T01:00:00Z", "success"),
        repack_run("1.99.0-repack", "2026-03-01T06:00:00Z", "timed_out"),
        // A build run and a non-repack title never count.
        repack_run("1.99.1-0123456789ab", "2026-03-01T06:00:00Z", "success"),
        repack_run("1.99.2-repack-x", "2026-03-01T06:00:00Z", "success"),
    ];
    retry_runner(&scn, "2026-03-01T10:05:00Z", &repacks, &[]);
    assert!(retry_dispatches(&scn).is_empty(), "{:?}", scn.calls());
}

#[test]
fn followup_timeout_resumes_with_the_variable_concurrency() {
    // A `timed_out` run, and a `cancelled` run whose job ran to its limit
    // (GitHub may report the job timeout either way), each resume.
    for (conclusion, jobs) in [
        ("timed_out", String::new()),
        ("failure", String::new()),
        ("cancelled", job_json("cancelled", 350)),
        ("cancelled", job_json("timed_out", 350)),
    ] {
        let scn = Scenario::new();
        let runs = runs_json(2, false);
        let runner = resume_runner(
            &scn,
            "1.99.0-repack",
            conclusion,
            &[("STOW_REPACK_CONCURRENCY", "12")],
            &[("STUB_GH_JOBS", &jobs), ("STUB_GH_RUNS", &runs)],
        );
        assert_eq!(
            runner.outcome_of(RESUME_STEP),
            &Outcome::Ran(0),
            "{conclusion}"
        );
        let dispatches = refill_dispatches(&scn);
        assert_eq!(dispatches.len(), 1, "{conclusion}: {dispatches:?}");
        assert_eq!(dispatches[0].0, "build-crate.yml");
        assert_eq!(dispatches[0].1, "main");
        assert_eq!(
            dispatches[0].2,
            BTreeMap::from([
                ("repack_rustc".to_owned(), "1.99.0".to_owned()),
                ("repack_concurrency".to_owned(), "12".to_owned()),
            ])
        );
    }
}

#[test]
fn followup_unset_variables_default_to_32_and_8() {
    let scn = Scenario::new();
    let runs = runs_json(7, false);
    resume_runner(
        &scn,
        "1.99.0-repack",
        "failure",
        &[("STOW_REPACK_CONCURRENCY", "")],
        &[("STUB_GH_RUNS", &runs)],
    );
    let dispatches = refill_dispatches(&scn);
    assert_eq!(dispatches.len(), 1, "7 runs is under the default 8");
    assert_eq!(
        dispatches[0]
            .2
            .get("repack_concurrency")
            .map(String::as_str),
        Some("32")
    );
}

#[test]
fn followup_operator_cancel_is_not_resumed() {
    for jobs in [
        job_json("cancelled", 20),
        job_json("cancelled", 334),
        String::new(),
    ] {
        let scn = Scenario::new();
        let runs = runs_json(1, false);
        let runner = resume_runner(
            &scn,
            "1.99.0-repack",
            "cancelled",
            &[],
            &[("STUB_GH_JOBS", &jobs), ("STUB_GH_RUNS", &runs)],
        );
        assert_eq!(runner.outcome_of(RESUME_STEP), &Outcome::Ran(0));
        assert!(refill_dispatches(&scn).is_empty(), "{:?}", scn.calls());
    }
}

#[test]
fn followup_per_day_bound_fails_the_job() {
    let scn = Scenario::new();
    let runs = runs_json(3, false);
    let runner = resume_runner(
        &scn,
        "1.99.0-repack",
        "timed_out",
        &[("STOW_REPACK_MAX_RUNS_PER_DAY", "3")],
        &[("STUB_GH_RUNS", &runs)],
    );
    assert_eq!(runner.outcome_of(RESUME_STEP), &Outcome::Ran(1));
    assert!(refill_dispatches(&scn).is_empty(), "{:?}", scn.calls());
}

#[test]
fn followup_does_not_double_dispatch_an_active_resume() {
    let scn = Scenario::new();
    let runs = runs_json(2, true);
    let runner = resume_runner(
        &scn,
        "1.99.0-repack",
        "failure",
        &[],
        &[("STUB_GH_RUNS", &runs)],
    );
    assert_eq!(runner.outcome_of(RESUME_STEP), &Outcome::Ran(0));
    assert!(refill_dispatches(&scn).is_empty(), "{:?}", scn.calls());
}

#[test]
fn followup_ignores_non_repack_titles() {
    for title in [
        "1.99.0-0123456789ab",
        "1.99.0-repack-x",
        "x1.99.0-repack",
        "-repack",
        "Index publish",
    ] {
        let scn = Scenario::new();
        let runner = resume_runner(&scn, title, "success", &[], &[]);
        assert_eq!(runner.outcome_of(RESUME_STEP), &Outcome::Ran(0), "{title}");
        assert!(scn.calls_of("gh").is_empty(), "{title}: {:?}", scn.calls());
    }
}

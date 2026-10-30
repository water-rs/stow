//! The periodic workflows' cadence lives in the edge's Cron Trigger, not
//! in GitHub's `schedule` (stow#1100): the manifests' `crons` and the
//! `STOW_PERIODIC_WORKFLOWS` map that names the workflows each cron
//! drives must agree, and every workflow they name must accept
//! `workflow_dispatch`. Host-independent: it only parses files.

use std::collections::BTreeSet;
use std::path::Path;

use stow_types::periodic::{PeriodicSchedule, SCHEDULE_BINDING};

fn repo_file(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The manifest's `crons` and its parsed `STOW_PERIODIC_WORKFLOWS`.
fn manifest_schedule(manifest: &str) -> (BTreeSet<String>, PeriodicSchedule) {
    let document: toml::Table = repo_file(manifest).parse().expect("manifest is TOML");
    let cloudflare = document["cloudflare"].as_table().expect("[cloudflare]");
    let crons = cloudflare["triggers"]["crons"]
        .as_array()
        .expect("[cloudflare.triggers] crons")
        .iter()
        .map(|cron| cron.as_str().expect("cron string").to_owned())
        .collect();
    let schedule = cloudflare["vars"][SCHEDULE_BINDING]
        .as_str()
        .unwrap_or_else(|| panic!("{SCHEDULE_BINDING} var"))
        .parse()
        .expect("schedule parses");
    (crons, schedule)
}

#[test]
fn every_declared_cron_is_mapped_and_every_mapping_is_declared() {
    for manifest in ["edge/Skyzen.toml", "edge/Skyzen.mock.toml"] {
        let (crons, schedule) = manifest_schedule(manifest);
        let mapped: BTreeSet<String> = schedule.crons().map(str::to_owned).collect();
        assert_eq!(
            crons, mapped,
            "{manifest}: crons and {SCHEDULE_BINDING} disagree"
        );
    }
}

/// Every periodic workflow with its cadence and the branch it is
/// dispatched on: the six moved by stow#1121 keep the branch their
/// `schedule` ran on (`dev`), except `demand-feed.yml` and
/// `preheat-missed.yml`, whose OIDC identity the edge admits on `main`
/// only; the first two entries were already dispatched on `main`.
const PRODUCTION: [(&str, &str, &str); 8] = [
    ("*/15 * * * *", "watchdog.yml", "main"),
    ("17 0 * * *", "preheat-cron.yml", "main"),
    ("*/10 * * * *", "index-publish-cron.yml", "dev"),
    ("5 * * * *", "demand-feed.yml", "main"),
    ("0 13 * * *", "build-failure-digest.yml", "dev"),
    ("0 7 * * *", "test.yml", "dev"),
    ("30 5 * * 1", "preheat-projects.yml", "dev"),
    ("0 6 * * 1", "preheat-missed.yml", "main"),
];

#[test]
fn production_drives_every_periodic_workflow_at_its_cadence_and_branch() {
    for manifest in ["edge/Skyzen.toml", "edge/Skyzen.mock.toml"] {
        let (_, schedule) = manifest_schedule(manifest);
        for (cron, file, branch) in PRODUCTION {
            let due = schedule
                .due(cron)
                .unwrap_or_else(|error| panic!("{manifest}: {error}"));
            assert_eq!(due.len(), 1, "{manifest}: {cron} drives one workflow");
            assert_eq!(due[0].workflow.as_str(), file, "{manifest}: {cron}");
            assert_eq!(due[0].dispatch_ref.as_str(), branch, "{manifest}: {file}");
        }
        assert_eq!(
            schedule.crons().count(),
            PRODUCTION.len(),
            "{manifest}: no other workflow is driven"
        );
    }
}

#[test]
fn a_driven_workflow_accepts_dispatch() {
    for manifest in ["edge/Skyzen.toml", "edge/Skyzen.mock.toml"] {
        let (_, schedule) = manifest_schedule(manifest);
        for cron in schedule.crons() {
            for entry in schedule.due(cron).expect("mapped cron") {
                let workflow = &entry.workflow;
                let text = repo_file(&format!(".github/workflows/{}", workflow.as_str()));
                let document: serde_yml::Value = serde_yml::from_str(&text)
                    .unwrap_or_else(|error| panic!("{}: {error}", workflow.as_str()));
                let triggers = document
                    .get("on")
                    .and_then(serde_yml::Value::as_mapping)
                    .unwrap_or_else(|| panic!("{}: `on` mapping", workflow.as_str()));
                assert!(
                    triggers.contains_key("workflow_dispatch"),
                    "{}: the Cron Trigger dispatches it, so it needs workflow_dispatch",
                    workflow.as_str()
                );
                assert!(
                    !triggers.contains_key("schedule"),
                    "{}: the Cron Trigger is its only clock, so it carries no `schedule`",
                    workflow.as_str()
                );
            }
        }
    }
}

/// A workflow that is also a push / pull request / merge group workflow
/// ran its full legs on `github.event_name == 'schedule'`; once the edge
/// dispatches it, no job may still wait for an event that never comes.
#[test]
fn a_driven_workflow_never_branches_on_the_schedule_event() {
    let (_, schedule) = manifest_schedule("edge/Skyzen.toml");
    for cron in schedule.crons() {
        for entry in schedule.due(cron).expect("mapped cron") {
            let text = repo_file(&format!(".github/workflows/{}", entry.workflow.as_str()));
            assert!(
                !text.contains("event_name == 'schedule'")
                    && !text.contains("event_name != 'schedule'"),
                "{}: branches on the `schedule` event",
                entry.workflow.as_str()
            );
        }
    }
}

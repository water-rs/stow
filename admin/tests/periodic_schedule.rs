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

#[test]
fn production_drives_the_watchdog_every_fifteen_minutes_and_preheat_daily() {
    let (_, schedule) = manifest_schedule("edge/Skyzen.toml");
    let files = |cron: &str| -> Vec<String> {
        schedule
            .due(cron)
            .unwrap_or_else(|error| panic!("{error}"))
            .iter()
            .map(|workflow| workflow.as_str().to_owned())
            .collect()
    };
    assert_eq!(files("*/15 * * * *"), ["watchdog.yml"]);
    assert_eq!(files("17 0 * * *"), ["preheat-cron.yml"]);
    assert_eq!(schedule.crons().count(), 2, "no other workflow is driven");
}

#[test]
fn a_driven_workflow_accepts_dispatch() {
    for manifest in ["edge/Skyzen.toml", "edge/Skyzen.mock.toml"] {
        let (_, schedule) = manifest_schedule(manifest);
        for cron in schedule.crons() {
            for workflow in schedule.due(cron).expect("mapped cron") {
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
            }
        }
    }
}

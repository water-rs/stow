//! Workflow dependency deadlines shared with the scheduler.

/// The scheduler's deliveries-stopped bound (stow#860) is the longest
/// dependency path of `build-crate.yml` jobs a task run executes; a timeout
/// change must move it. The operator's repack job never runs in a task
/// run, so its bound is not part of the scheduler's.
#[test]
fn build_crate_run_timeout_matches_the_jobs() {
    fn path_minutes(
        name: &str,
        jobs: &std::collections::BTreeMap<String, (i64, Vec<String>)>,
    ) -> i64 {
        let (minutes, needs) = &jobs[name];
        minutes
            + needs
                .iter()
                .map(|need| path_minutes(need, jobs))
                .max()
                .unwrap_or(0)
    }

    let wf: serde_yml::Value =
        serde_yml::from_str(include_str!("../../.github/workflows/build-crate.yml"))
            .expect("workflow YAML");
    let jobs = wf
        .get("jobs")
        .and_then(serde_yml::Value::as_mapping)
        .expect("jobs mapping");
    let mut task_jobs = std::collections::BTreeMap::new();
    for (name, job) in jobs {
        let condition = job
            .get("if")
            .and_then(serde_yml::Value::as_str)
            .expect("every build-crate.yml job states which run kind executes it");
        let timeout = job
            .get("timeout-minutes")
            .and_then(serde_yml::Value::as_i64)
            .expect("every build-crate.yml job sets integer timeout-minutes");
        if condition.starts_with("inputs.repack_rustc == ''")
            || condition.starts_with("always() && inputs.repack_rustc == ''")
        {
            let needs = match job.get("needs") {
                None => Vec::new(),
                Some(serde_yml::Value::Sequence(needs)) => needs
                    .iter()
                    .map(|need| need.as_str().expect("job name").to_owned())
                    .collect(),
                Some(need) => vec![need.as_str().expect("job name").to_owned()],
            };
            task_jobs.insert(
                name.as_str().expect("job name").to_owned(),
                (timeout, needs),
            );
        } else {
            assert_eq!(
                condition,
                "inputs.repack_rustc != ''",
                "job {} runs in neither a task run nor a repack run",
                name.as_str().expect("job name").to_owned()
            );
        }
    }
    let minutes = task_jobs
        .keys()
        .map(|name| path_minutes(name, &task_jobs))
        .max()
        .expect("task jobs");
    assert_eq!(minutes, stow_types::api::BUILD_CRATE_RUN_TIMEOUT_MINUTES);
}

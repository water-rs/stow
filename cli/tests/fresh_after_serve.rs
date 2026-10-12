//! A served unit leaves cargo's own records alone, so the next build
//! finds everything fresh (stow#634).
//!
//! Serving used to leave three kinds of stale state in cargo's
//! bookkeeping: it overwrote `build/<pkg>-<hash>/output` with the
//! bundle's directives — which omit `cargo:rerun-if-*`, so the
//! build-script-run unit's local fingerprint changed shape and reran the
//! script every build — it wrote a dep-info naming the `.d` file itself,
//! whose stow-written mtime is newer than the invocation time cargo
//! rewinds the fingerprint dep-info to, and it materialized outputs with
//! the cache entry's mtime, which a reflink preserves — older than the
//! `output` files cargo's build-script runs wrote during this build, so
//! cargo's dependency-mtime check read every served unit as "a
//! dependency was rebuilt". All three are gone: stow writes nothing
//! under `target/<profile>/build/`, the dep-info names no path, and a
//! materialized output carries this invocation's mtime. This test builds
//! twice (fill, then serve), then proves a no-op build stays fully fresh
//! and that two touch-and-rebuild rounds recompile only the fixture's
//! own package.

mod build_fixture;
mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::SystemTime;

use build_fixture::{refused_url, stow_build_in, stow_setup_in, write_fixture};

/// Registry crates with build scripts that print `cargo:rerun-if-changed`
/// / `cargo:rerun-if-env-changed` lines (`anyhow`, `libc`, `serde` — and
/// `serde_core` rides along as serde's own dependency) beside crates
/// without a build script (`cfg-if`, `itoa`).
const FIXTURE_DEPENDENCIES: &str = "anyhow = \"1\"\n\
     cfg-if = \"1\"\n\
     itoa = \"1\"\n\
     libc = \"0.2\"\n\
     serde = \"1\"\n";

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A verbose cargo build writes `Compiling`/`Dirty`/`Running` to stderr;
/// assert none of them appear — the build found every unit fresh. On
/// failure print the offending lines.
fn assert_fully_fresh(output: &Output, label: &str) {
    let offending = offending_rebuild_lines(output);
    assert!(
        offending.is_empty(),
        "{label} re-ran work a served build should leave fresh:\n{}",
        offending.join("\n")
    );
}

/// After `src/main.rs` changed, exactly the fixture's own package may be
/// dirty and recompile — every other `Dirty`/`Compiling` line or a
/// build-script `Running` line is the stow#634 defect repeating.
fn assert_only_probe_rebuilt(output: &Output, label: &str) {
    let offending = offending_rebuild_lines(output);
    assert!(
        !offending.is_empty(),
        "{label} compiled nothing after src/main.rs was touched:\n{}",
        stderr_of(output)
    );
    let foreign: Vec<String> = offending
        .into_iter()
        .filter(|line| !line.contains("probe"))
        .collect();
    assert!(
        foreign.is_empty(),
        "{label} re-ran units other than the fixture's own package:\n{}",
        foreign.join("\n")
    );
}

/// The verbose lines that prove a unit re-ran: `Compiling`, `Dirty`, and
/// `Running` a path under cargo's `build/` dir (a build-script
/// executable). Cargo's own `Running` probes like `rustc --print` carry
/// no such path and stay legitimate on a fresh build.
fn offending_rebuild_lines(output: &Output) -> Vec<String> {
    stderr_of(output)
        .lines()
        .filter(|line| {
            line.contains("Compiling")
                || line.contains("Dirty")
                || (line.contains("Running") && line.contains("/build/"))
        })
        .map(str::to_owned)
        .collect()
}

/// The count `stow: served N of M cacheable dependencies` reports.
fn served_count(output: &Output) -> usize {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            line.strip_prefix("stow: served ")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .unwrap_or_else(|| {
            panic!(
                "no `stow: served` summary line in stdout:\n{}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
}

/// Rewrite `src/main.rs` until its mtime is strictly newer than
/// `reference`: cargo treats an input at-or-before the unit's recorded
/// invocation time as unchanged, so the touch must land a later tick —
/// comparing mtimes, never sleeping a fixed time.
fn touch_newer_than(path: &Path, reference: SystemTime) {
    let contents = std::fs::read(path).expect("read file to touch");
    for _ in 0..2000 {
        std::fs::write(path, &contents).expect("touch file");
        let mtime = std::fs::metadata(path)
            .expect("stat touched file")
            .modified()
            .expect("touched file mtime");
        if mtime > reference {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    panic!(
        "filesystem clock never moved past {reference:?} for {}",
        path.display()
    );
}

/// Copy `cargo_home/registry` into `other_home` so a plain cargo build
/// resolves offline without stow's `build.rustc-wrapper` config.
fn clone_registry_into(cargo_home: &Path, other_home: &Path) {
    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).expect("create copy target");
        for entry in std::fs::read_dir(from).expect("read registry dir") {
            let entry = entry.expect("registry entry");
            let dest = to.join(entry.file_name());
            if entry.file_type().expect("entry type").is_dir() {
                copy_tree(&entry.path(), &dest);
            } else {
                std::fs::copy(entry.path(), &dest).expect("copy registry file");
            }
        }
    }
    copy_tree(&cargo_home.join("registry"), &other_home.join("registry"));
}

/// `cargo build` with no stow wiring at all: a `CARGO_HOME` that never
/// saw `stow setup`, `RUSTC_WRAPPER` removed from the environment.
fn plain_cargo_build(dir: &Path, cargo_home: &Path, target_dir: &Path) -> Output {
    Command::new("cargo")
        .args(["build", "--offline"])
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home)
        .env("CARGO_TARGET_DIR", target_dir)
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_INCREMENTAL", "0")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .output()
        .expect("run cargo build")
}

/// The `build/<pkg>-<hash>/output` files under `target/debug`, keyed by
/// package name — only a build-script-run unit writes `output`.
fn build_script_outputs(target_dir: &Path) -> BTreeMap<String, PathBuf> {
    let mut found = BTreeMap::new();
    let build_root = target_dir.join("debug").join("build");
    for entry in std::fs::read_dir(&build_root)
        .unwrap_or_else(|error| panic!("read {}: {error}", build_root.display()))
    {
        let entry = entry.expect("build dir entry");
        let output = entry.path().join("output");
        if !output.is_file() {
            continue;
        }
        let dir_name = entry.file_name().to_string_lossy().into_owned();
        let (package, _hash) = dir_name
            .rsplit_once('-')
            .unwrap_or_else(|| panic!("build dir {dir_name} has no <pkg>-<hash> shape"));
        assert!(
            found.insert(package.to_owned(), output).is_none(),
            "two build-script output files for {package}"
        );
    }
    found
}

/// Byte-identical build-script `output` files, modulo the absolute
/// target-dir prefix embedded in paths the scripts printed.
fn assert_same_output(
    served_output: &Path,
    served_target: &Path,
    plain_output: &Path,
    plain_target: &Path,
    package: &str,
) {
    let normalize = |output_path: &Path, target_dir: &Path| {
        let text = std::fs::read_to_string(output_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", output_path.display()));
        let canonical = target_dir
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonicalize {}: {error}", target_dir.display()));
        text.replace(&*canonical.to_string_lossy(), "TARGET")
            .replace(&*target_dir.to_string_lossy(), "TARGET")
    };
    assert_eq!(
        normalize(served_output, served_target),
        normalize(plain_output, plain_target),
        "build-script output for {package} differs between served and plain builds"
    );
}

#[test]
fn a_served_build_stays_fresh_until_the_fixture_itself_changes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_fixture(dir.path(), cargo_home.path(), FIXTURE_DEPENDENCIES);
    stow_setup_in(dir.path(), cargo_home.path());
    let edge_url = refused_url();
    let registry_url = refused_url();
    let cache = tempfile::tempdir().expect("stow cache dir");
    let build = |args: &[&str], target: &Path, label: &str| {
        let output = stow_build_in(
            dir.path(),
            args,
            &edge_url,
            &registry_url,
            cache.path(),
            cargo_home.path(),
            target,
        );
        assert!(
            output.status.success(),
            "{label} failed:\n{}",
            stderr_of(&output)
        );
        output
    };

    // Build 1: fresh target, fresh cache — everything compiles and is
    // stored.
    let target1 = tempfile::tempdir().expect("target dir 1");
    build(&["build", "--offline"], target1.path(), "build 1 (fill)");

    // Build 2: a second fresh target dir against the same cache serves
    // the stored units. The summary line must report served units so the
    // test cannot pass by not serving.
    let target2 = tempfile::tempdir().expect("target dir 2");
    let output = build(&["build", "--offline"], target2.path(), "build 2 (serve)");
    assert!(served_count(&output) > 0, "build 2 served no units");

    // Build 3: nothing touched — a served build must come back fully
    // fresh: no `Compiling`, no `Dirty`, no build-script `Running`.
    let output = build(&["build", "--offline", "-v"], target2.path(), "build 3");
    assert_fully_fresh(&output, "build 3");

    // Builds 4 and 5: the defect repeated on every round, so assert two
    // touch-and-rebuild cycles. The clock marker is written after the
    // previous build returned, so an mtime past it is past everything
    // that build recorded.
    for round in 4..=5 {
        let marker = dir.path().join(format!(".clock-marker-{round}"));
        std::fs::write(&marker, b"").expect("write clock marker");
        let marker_mtime = std::fs::metadata(&marker)
            .expect("stat clock marker")
            .modified()
            .expect("clock marker mtime");
        touch_newer_than(&dir.path().join("src/main.rs"), marker_mtime);

        let output = build(
            &["build", "--offline", "-v"],
            target2.path(),
            &format!("build {round}"),
        );
        assert_only_probe_rebuilt(&output, &format!("build {round}"));
    }

    // Every build-script package's `output` file in the served target
    // dir must be what cargo's own build-script run produced — compare
    // against a plain `cargo build` in its own target dir with a
    // CARGO_HOME stow never configured.
    let plain_home = tempfile::tempdir().expect("plain cargo home");
    clone_registry_into(cargo_home.path(), plain_home.path());
    let plain_target = tempfile::tempdir().expect("plain target dir");
    let output = plain_cargo_build(dir.path(), plain_home.path(), plain_target.path());
    assert!(
        output.status.success(),
        "plain cargo build failed:\n{}",
        stderr_of(&output)
    );

    let served_outputs = build_script_outputs(target2.path());
    let plain_outputs = build_script_outputs(plain_target.path());
    assert!(
        !served_outputs.is_empty(),
        "the fixture must contain packages with build scripts"
    );
    assert_eq!(
        served_outputs.keys().collect::<Vec<_>>(),
        plain_outputs.keys().collect::<Vec<_>>(),
        "served and plain builds ran different build scripts"
    );
    for (package, served_path) in &served_outputs {
        assert_same_output(
            served_path,
            target2.path(),
            &plain_outputs[package],
            plain_target.path(),
            package,
        );
    }
}

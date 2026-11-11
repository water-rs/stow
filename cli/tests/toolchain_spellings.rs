//! The session takes every rustc fact from the build's own resolved
//! toolchain and only checks that a request names the build's rustc.
//!
//! A refusal fails the build, so a build that succeeds under each way a
//! rustc is spelled — `RUSTC` set to a bare name, to the toolchain's
//! `<sysroot>/bin/rustc`, and an explicit `--target` — never had a
//! legitimate request refused.

mod build_fixture;
mod support;

use std::process::Command;

use build_fixture::{refused_url, stow_build_in_with_env, stow_setup_in, write_fixture};

fn rustc_output(args: &[&str]) -> String {
    let output = Command::new("rustc")
        .args(args)
        .output()
        .expect("run rustc");
    assert!(output.status.success(), "rustc {args:?} failed");
    String::from_utf8(output.stdout).expect("rustc prints UTF-8")
}

/// Build the fixture once with `args` and `env` and assert it succeeded
/// without the session refusing anything.
fn build_without_refusals(args: &[&str], env: &[(&str, &str)]) {
    let dir = support::tempdir().expect("temp dir");
    let cargo_home = support::tempdir().expect("cargo home");
    write_fixture(dir.path(), cargo_home.path(), "cfg-if = \"1\"\n");
    stow_setup_in(dir.path(), cargo_home.path());
    let cache = support::tempdir().expect("cache dir");
    let target = support::tempdir().expect("target dir");
    let output = stow_build_in_with_env(
        dir.path(),
        args,
        &refused_url(),
        &refused_url(),
        cache.path(),
        cargo_home.path(),
        target.path(),
        env,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stow build {args:?} with {env:?} failed:\n{stderr}"
    );
    assert!(
        !stderr.contains("refused the request"),
        "a legitimate request was refused:\n{stderr}"
    );
}

#[test]
fn a_bare_rustc_spelling_is_the_builds_rustc() {
    build_without_refusals(&["build", "--offline"], &[("RUSTC", "rustc")]);
}

#[test]
fn a_sysroot_spelled_rustc_is_the_builds_rustc() {
    let sysroot = rustc_output(&["--print", "sysroot"]);
    let rustc = std::path::Path::new(sysroot.trim())
        .join("bin")
        .join(format!("rustc{}", std::env::consts::EXE_SUFFIX));
    let rustc = rustc.to_str().expect("sysroot path is UTF-8");
    build_without_refusals(&["build", "--offline"], &[("RUSTC", rustc)]);
}

#[test]
fn an_explicit_target_build_refuses_nothing() {
    let vv = rustc_output(&["-vV"]);
    let host = vv
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("rustc -vV names its host");
    build_without_refusals(&["build", "--offline", "--target", host], &[]);
}

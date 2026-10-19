//! A consumer whose linked dependency compiled locally in this build
//! compiles locally too — and the marker that sends it there names the
//! artifact cargo hands it, not the `--extern` alias or the crate name
//! (stow#733, stow#734).
//!
//! The fixture chains three path crates behind the `probe` binary:
//! `top` depends on `middle` under the rename `renamed`, and `middle`
//! depends on `inner`. Path crates are never served, so each compiles
//! locally — and `top` links `middle`'s output as
//! `--extern renamed=…/libmiddle-<hash>.rlib`. A marker keyed by the
//! `--extern` name looks for `renamed` and finds nothing, so a stale
//! cache could serve `top` an artifact compiled against a different
//! `middle` (stow#733); a marker keyed by crate name alone would
//! over-match every probe and variant of it (stow#734).
//!
//! A `[patch]` points `unicode-ident` at a path copy, so the covered
//! registry units above it — `proc-macro2`, then `quote` — are sent
//! local behind it on the second build. That is the unit the summary
//! line used to count nowhere (stow#734).

mod support;

// The shared fixture carries helpers this test does not call; each
// integration binary lints them per target.
#[allow(dead_code)]
mod build_fixture;

use std::path::Path;
use std::process::{Command, Output};

use build_fixture::{refused_url, stow_build_in_with_env, stow_setup_in};
use support::sealed_home_env;

/// The debug event `must_build_locally` emits when a linked `--extern`
/// artifact is already locally built — emitted in the supervisor, which
/// lives inside the `stow-cli` process this test drives.
fn compiled_behind_local_dependency(stderr: &str, crate_name: &str) -> bool {
    let crate_name = format!("crate_name={crate_name} ");
    stderr.lines().any(|line| {
        line.contains("dependency was compiled locally in this build") && line.contains(&crate_name)
    })
}

/// One tiny path lib at `dir` — the manifest's `[dependencies]` table
/// verbatim, so a rename or a nested path dep is spelled by the caller.
fn write_path_lib(dir: &Path, name: &str, dependencies: &str) {
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{dependencies}"
        ),
    )
    .expect("write manifest");
    std::fs::write(dir.join("src").join("lib.rs"), "pub fn leaf() {}\n").expect("write lib.rs");
}

/// The fixture root: a binary on the three-crate path chain plus `quote`
/// as the registry chain's top. The `unicode-ident` `[patch]` is applied
/// between the builds, once the registry copies have been stored.
fn write_fixture(dir: &Path, cargo_home: &Path) {
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\n\
         top = { path = \"top\" }\n\
         quote = \"1\"\n",
    )
    .expect("write manifest");
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");
    write_path_lib(
        &dir.join("top"),
        "top",
        "renamed = { package = \"middle\", path = \"../middle\" }\n",
    );
    write_path_lib(
        &dir.join("middle"),
        "middle",
        "inner = { path = \"../inner\" }\n",
    );
    write_path_lib(&dir.join("inner"), "inner", "");
    // Resolve `quote`'s chain now, so the builds under test are not also
    // network tests — the fetch shares the isolated CARGO_HOME the
    // builds use.
    let mut fetch = Command::new("cargo");
    fetch
        .arg("fetch")
        .current_dir(dir)
        .env("CARGO_HOME", cargo_home);
    sealed_home_env(&mut fetch, &dir.join("stow-home"));
    let fetched = fetch.output().expect("run cargo fetch");
    assert!(
        fetched.status.success(),
        "cargo fetch failed:\n{}",
        String::from_utf8_lossy(&fetched.stderr)
    );
}

/// Swap `unicode-ident` for a path copy of its registry source: it
/// compiles locally every build, and the covered registry units above
/// it — `proc-macro2`, then `quote` — are sent local behind it rather
/// than served artifacts linked against a different `unicode-ident`.
/// Applied between the builds so build 1 stores the chain's real
/// registry bookkeeping first; a unit behind a non-registry dep has no
/// resolvable bookkeeping and is never stored.
fn apply_unicode_ident_patch(dir: &Path, cargo_home: &Path) {
    let registry_src = cargo_home.join("registry").join("src");
    let mut copied = false;
    for index in std::fs::read_dir(&registry_src).expect("read registry src") {
        for entry in
            std::fs::read_dir(index.expect("index dir").path()).expect("read registry package dir")
        {
            let entry = entry.expect("package entry");
            if entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("unicode-ident-"))
            {
                copy_tree(&entry.path(), &dir.join("unicode-ident"));
                copied = true;
            }
        }
    }
    assert!(copied, "the fetched unicode-ident source was not found");
    let mut manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("read manifest");
    manifest.push_str("\n[patch.crates-io]\nunicode-ident = { path = \"unicode-ident\" }\n");
    std::fs::write(dir.join("Cargo.toml"), manifest).expect("write patched manifest");
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("create copy target");
    for entry in std::fs::read_dir(from).expect("read copy source") {
        let entry = entry.expect("copy source entry");
        let dest = to.join(entry.file_name());
        if entry.file_type().expect("entry type").is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), &dest).expect("copy file");
        }
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_renamed_dependency_compiled_locally_sends_its_consumer_local() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    write_fixture(dir.path(), cargo_home.path());
    stow_setup_in(dir.path(), cargo_home.path());
    let edge_url = refused_url();
    let registry_url = refused_url();
    let cache = tempfile::tempdir().expect("cache dir");
    // `stow_cli=debug` puts the supervisor's per-unit decisions on this
    // stderr, where the test can read which rule sent each unit local.
    let build = |target: &Path, label: &str| {
        let output = stow_build_in_with_env(
            dir.path(),
            &["build", "--offline"],
            &edge_url,
            &registry_url,
            cache.path(),
            cargo_home.path(),
            target,
            &[("RUST_LOG", "stow_cli=debug")],
        );
        assert!(
            output.status.success(),
            "{label} failed:\n{}",
            stderr_of(&output)
        );
        output
    };

    // Build 1: everything misses and compiles — `proc-macro2` and
    // `quote` are stored for build 2 to cover.
    let target_a = tempfile::tempdir().expect("target dir a");
    build(target_a.path(), "build 1");
    apply_unicode_ident_patch(dir.path(), cargo_home.path());

    // Build 2: a fresh target dir against the shared cache, with the
    // supervisor's per-unit decisions on stderr. The patched
    // `unicode-ident` compiles locally again — path crates are never
    // covered — and `proc-macro2`/`quote` are covered units that must
    // compile locally behind it rather than serve the cached copies
    // linked against a different `unicode-ident`.
    let target_b = tempfile::tempdir().expect("target dir b");
    let output = build(target_b.path(), "build 2");
    let stderr = stderr_of(&output);

    // `top` links `libmiddle-<hash>` under the alias `renamed`: an
    // alias-keyed marker misses it entirely (stow#733), so this event
    // firing is the regression being closed.
    assert!(
        compiled_behind_local_dependency(&stderr, "top"),
        "the consumer of the renamed local build was not sent local:\n{stderr}"
    );
    assert!(
        compiled_behind_local_dependency(&stderr, "middle"),
        "the consumer of a plainly-named local build was not sent local:\n{stderr}"
    );
    assert!(
        !compiled_behind_local_dependency(&stderr, "inner"),
        "the leaf compiles on a miss, never behind a dependency"
    );

    // The covered registry units behind the patched `unicode-ident`
    // reach the summary's counted outcome (stow#734).
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("compiled locally behind a local dependency"),
        "the summary line did not count units sent local behind a local dependency:\n{stdout}"
    );
}

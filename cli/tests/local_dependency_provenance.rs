//! A consumer whose linked dependency compiled locally in this build
//! compiles locally too, and the marker that sends it there names the
//! artifact cargo hands it, not the `--extern` alias or the crate name
//! (stow#733, stow#734).
//!
//! The fixture chains three crates of one local `file://` git repository
//! behind the `probe` binary: `top` depends on `middle` under the rename
//! `renamed`, `middle` depends on `inner`, and `inner` on the registry's
//! `unicode-ident`. Git units are keyed (stow#1006), so the second build
//! could serve them, until a `[patch]` points `unicode-ident` at a path
//! copy that compiles locally every build. `inner` is then compiled
//! behind it, `middle` behind `inner`, and `top` links `middle`'s output
//! as `--extern renamed=.../libmiddle-<hash>.rlib`. A marker keyed by the
//! `--extern` name looks for `renamed` and finds nothing, so a stale
//! cache could serve `top` an artifact compiled against a different
//! `middle` (stow#733); a marker keyed by crate name alone would
//! over-match every probe and variant of it (stow#734). The registry
//! units above `unicode-ident`, `proc-macro2` then `quote`, are sent
//! local behind it as well, which is the unit the summary line used to
//! count nowhere.

mod support;

// The shared fixture carries helpers this test does not call; each
// integration binary lints them per target.
#[allow(dead_code)]
mod build_fixture;

use std::path::Path;
use std::process::Output;

use build_fixture::{
    cargo_fetch, commit_git_repo, copy_registry_package, refused_url, stow_build_in_with_env,
    stow_setup_in,
};

/// The debug event `must_build_locally` emits when a linked `--extern`
/// artifact is already locally built, emitted in the supervisor, which
/// lives inside the `stow-cli` process this test drives.
fn compiled_behind_local_dependency(stderr: &str, crate_name: &str) -> bool {
    let crate_name = format!("crate_name={crate_name} ");
    stderr.lines().any(|line| {
        line.contains("dependency was compiled locally in this build") && line.contains(&crate_name)
    })
}

/// One tiny lib at `dir`, the manifest's `[dependencies]` table verbatim,
/// so a rename or a nested path dep is spelled by the caller.
fn write_lib(dir: &Path, name: &str, dependencies: &str) {
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

/// The fixture root: a binary on the git-hosted three-crate chain plus
/// `quote` as the registry chain's top. The `unicode-ident` `[patch]` is
/// applied between the builds, once the registry copies have been stored.
fn write_fixture(dir: &Path, cargo_home: &Path) {
    // The registry's own `unicode-ident` is fetched first: `inner`
    // depends on it, and the patch copies its extracted source.
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\nquote = \"1\"\nunicode-ident = \"1\"\n",
    )
    .expect("write manifest");
    cargo_fetch(dir, cargo_home);

    let repo = dir.join("chain-repo");
    write_lib(
        &repo.join("top"),
        "top",
        "renamed = { package = \"middle\", path = \"../middle\" }\n",
    );
    write_lib(
        &repo.join("middle"),
        "middle",
        "inner = { path = \"../inner\" }\n",
    );
    write_lib(&repo.join("inner"), "inner", "unicode-ident = \"1\"\n");
    let url = commit_git_repo(&repo, &dir.join("stow-home"));
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\ntop = {{ git = \"{url}\" }}\nquote = \"1\"\n"
        ),
    )
    .expect("write manifest");
    cargo_fetch(dir, cargo_home);
}

/// Swap `unicode-ident` for a path copy of its registry source: it
/// compiles locally every build, and the units above it (`inner`,
/// `middle`, `top`, then `proc-macro2` and `quote`) are sent local
/// rather than served artifacts linked against a different
/// `unicode-ident`. Applied between the builds so build 1 stores the
/// chain's real bookkeeping first.
fn apply_unicode_ident_patch(dir: &Path, cargo_home: &Path) {
    copy_registry_package(cargo_home, "unicode-ident", &dir.join("unicode-ident"));
    let mut manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("read manifest");
    manifest.push_str("\n[patch.crates-io]\nunicode-ident = { path = \"unicode-ident\" }\n");
    std::fs::write(dir.join("Cargo.toml"), manifest).expect("write patched manifest");
    cargo_fetch(dir, cargo_home);
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

    // Build 1: everything misses and compiles, so the git chain and the
    // `proc-macro2`/`quote` pair are stored for build 2 to cover.
    let target_a = tempfile::tempdir().expect("target dir a");
    build(target_a.path(), "build 1");
    apply_unicode_ident_patch(dir.path(), cargo_home.path());

    // Build 2: a fresh target dir against the shared cache. The patched
    // `unicode-ident` compiles locally again (path crates are never
    // covered) and every covered unit above it must compile locally
    // behind it rather than serve the cached copies linked against a
    // different `unicode-ident`.
    let target_b = tempfile::tempdir().expect("target dir b");
    let output = build(target_b.path(), "build 2");
    let stderr = stderr_of(&output);

    assert!(
        compiled_behind_local_dependency(&stderr, "inner"),
        "the git leaf over a local unicode-ident was not sent local:\n{stderr}"
    );
    assert!(
        compiled_behind_local_dependency(&stderr, "middle"),
        "the git unit over a locally built git unit was not sent local:\n{stderr}"
    );
    assert!(
        compiled_behind_local_dependency(&stderr, "top"),
        "the consumer of a renamed `--extern` on a locally built unit was not sent local:\n{stderr}"
    );

    // The covered registry units behind the patched `unicode-ident`
    // reach the summary's counted outcome (stow#734).
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("compiled locally behind a local dependency"),
        "the summary line did not count units sent local behind a local dependency:\n{stdout}"
    );
}

//! The local unit cache covers what sccache does, not only crates.io
//! units (stow#978): a path dependency compiled in one checkout is served
//! in another checkout of the same workspace in a different directory,
//! and an edited source or a changed `option_env!` variable is a miss.

mod build_fixture;
mod support;

use std::path::Path;

use build_fixture::{refused_url, stow_build_in_with_env, stow_setup_in};

/// The line the supervisor logs at `info` for a unit-cache serve.
const SERVED: &str = "served rustc invocation from the local unit cache";

/// A workspace whose root binary depends on the path member `mylib`,
/// which reads `STOW_UNIT_CACHE_FLAVOR` through `option_env!`.
fn write_workspace(dir: &Path, greeting: &str) {
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\nmylib = { path = \"mylib\" }\n\n[workspace]\n",
    )
    .expect("write manifest");
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(
        dir.join("src/main.rs"),
        "fn main() { let _ = (mylib::GREETING, mylib::FLAVOR); }\n",
    )
    .expect("write main.rs");
    std::fs::create_dir_all(dir.join("mylib/src")).expect("create mylib");
    std::fs::write(
        dir.join("mylib/Cargo.toml"),
        "[package]\nname = \"mylib\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write mylib manifest");
    write_lib(dir, greeting);
}

fn write_lib(dir: &Path, greeting: &str) {
    std::fs::write(
        dir.join("mylib/src/lib.rs"),
        format!(
            "pub const GREETING: &str = {greeting:?};\n\
             pub const FLAVOR: Option<&str> = option_env!(\"STOW_UNIT_CACHE_FLAVOR\");\n"
        ),
    )
    .expect("write lib.rs");
}

/// One build of `dir` into a fresh target directory against the shared
/// `cache`; the stderr it printed.
fn build(dir: &Path, cache: &Path, cargo_home: &Path, flavor: Option<&str>) -> String {
    let target = tempfile::tempdir().expect("target dir");
    let mut env = vec![("RUST_LOG", "info")];
    if let Some(flavor) = flavor {
        env.push(("STOW_UNIT_CACHE_FLAVOR", flavor));
    }
    let output = stow_build_in_with_env(
        dir,
        &["build", "--offline"],
        &refused_url(),
        &refused_url(),
        cache,
        cargo_home,
        target.path(),
        &env,
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "stow build failed:\n{stderr}");
    stderr
}

fn served_mylib(stderr: &str) -> bool {
    stderr
        .lines()
        .any(|line| line.contains(SERVED) && line.contains("mylib"))
}

#[test]
fn a_path_dependency_is_served_across_checkouts_until_an_input_changes() {
    let cache = tempfile::tempdir().expect("cache dir");
    let cargo_home = tempfile::tempdir().expect("cargo home");
    let first = tempfile::tempdir().expect("first checkout");
    let second = tempfile::tempdir().expect("second checkout");
    for checkout in [first.path(), second.path()] {
        write_workspace(checkout, "hello");
        stow_setup_in(checkout, cargo_home.path());
    }

    let cold = build(first.path(), cache.path(), cargo_home.path(), None);
    assert!(!served_mylib(&cold), "nothing is stored yet:\n{cold}");

    // Another directory, another target dir, the same sources.
    let warm = build(second.path(), cache.path(), cargo_home.path(), None);
    assert!(
        served_mylib(&warm),
        "the second checkout must be served the first one's mylib:\n{warm}"
    );

    // A variable the crate reads through `option_env!` is an input.
    let flavored = build(second.path(), cache.path(), cargo_home.path(), Some("a"));
    assert!(
        !served_mylib(&flavored),
        "a changed option_env! variable must miss:\n{flavored}"
    );
    let flavored_again = build(second.path(), cache.path(), cargo_home.path(), Some("a"));
    assert!(
        served_mylib(&flavored_again),
        "the same variable value is served again:\n{flavored_again}"
    );

    // An edited source is an input.
    write_lib(second.path(), "edited");
    let edited = build(second.path(), cache.path(), cargo_home.path(), None);
    assert!(
        !served_mylib(&edited),
        "an edited source file must miss:\n{edited}"
    );
}

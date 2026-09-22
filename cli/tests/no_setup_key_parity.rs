//! `stow build` works without `stow setup`: on Linux it provisions mold
//! itself and selects it through cargo `--config` overrides for that one
//! invocation. That selection must produce the same compile keys as the
//! file `stow setup` writes — the same rustflags and the same
//! `COMPILER_PATH` through a different delivery — or the no-setup path
//! would key its artifacts differently and miss everything the setup path
//! serves.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use stow_types::public_cache::stable_registry_artifact_identity_for_package;
use stow_types::rustc::ParsedRustcArgs;

/// The smallest registry unit that invokes the linker: a proc-macro with
/// no dependencies of its own, so the probe build stays cheap.
const PROBE_PACKAGE: &str = "paste-impl";
const PROBE_CRATE: &str = "paste_impl";
const PROBE_DEP_VERSION: &str = "0.1.18";

fn write_probe_project(dir: &Path) {
    std::fs::create_dir_all(dir.join("src")).expect("create src dir");
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{PROBE_PACKAGE} = \"={PROBE_DEP_VERSION}\"\n"
        ),
    )
    .expect("write manifest");
    std::fs::write(dir.join("src/lib.rs"), "pub fn probe() {}\n").expect("write lib.rs");
}

/// `stow build -v` in `project` against `cargo_home`, returning cargo's
/// stderr (where `-v` writes the `Running` lines).
fn verbose_build(project: &Path, cargo_home: &Path) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .args(["build", "-v"])
        .current_dir(project)
        .env("CARGO_HOME", cargo_home)
        .output()
        .expect("run stow-cli build -v");
    assert!(
        output.status.success(),
        "stow-cli build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stderr).expect("cargo stderr is utf-8")
}

/// The argv cargo handed rustc for `crate_name`, recovered from the
/// `Running` line of a `-v` build. When a rustc wrapper is configured it
/// appears ahead of the real rustc, so everything up to and including the
/// rustc binary is dropped.
fn rustc_argv_for(stderr: &str, crate_name: &str) -> Vec<OsString> {
    for line in stderr.lines() {
        let Some(inner) = line
            .strip_prefix("     Running `")
            .and_then(|rest| rest.strip_suffix('`'))
        else {
            continue;
        };
        let argv = shell_words::split(inner).expect("split rustc argv");
        let Some(rustc_at) = argv
            .iter()
            .position(|arg| Path::new(arg).file_stem().is_some_and(|s| s == "rustc"))
        else {
            continue;
        };
        let rest = &argv[rustc_at + 1..];
        if rest
            .windows(2)
            .any(|pair| pair == ["--crate-name", crate_name])
        {
            return rest.iter().map(OsString::from).collect();
        }
    }
    panic!("no rustc invocation for {crate_name} in:\n{stderr}");
}

fn compile_key_of(argv: &[OsString]) -> String {
    let parsed = ParsedRustcArgs::parse(argv).expect("parse rustc argv");
    stable_registry_artifact_identity_for_package(
        &parsed,
        PROBE_PACKAGE,
        PROBE_DEP_VERSION,
        parsed.target.as_deref().unwrap_or("host"),
        "test-rustc",
        "[]",
        "[]",
    )
    .expect("stable identity")
    .compile_key
}

/// Linux only — mold provisioning is the Linux half of the contract.
#[test]
fn a_setup_free_build_keys_like_the_setup_path() {
    if !cfg!(target_os = "linux") {
        return;
    }
    let root = tempfile::tempdir().expect("temp dir");
    let project = root.path().join("project");
    write_probe_project(&project);

    // The setup path: the written `$CARGO_HOME/config.toml` carries the
    // mold selection.
    let setup_home = root.path().join("setup-cargo-home");
    let status = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("setup")
        .current_dir(&project)
        .env("CARGO_HOME", &setup_home)
        .status()
        .expect("run stow-cli setup");
    assert!(status.success(), "stow-cli setup failed");
    let setup_argv = rustc_argv_for(&verbose_build(&project, &setup_home), PROBE_CRATE);

    // The no-setup path: an untouched CARGO_HOME, so `stow build` selects
    // the provisioned mold for the invocation alone.
    let bare_home: PathBuf = root.path().join("bare-cargo-home");
    let no_setup_argv = rustc_argv_for(&verbose_build(&project, &bare_home), PROBE_CRATE);

    // Vacuity guard: the probe unit must actually link with mold on both
    // sides, or the comparison below proves nothing.
    for (name, argv) in [("setup", &setup_argv), ("no-setup", &no_setup_argv)] {
        let parsed = ParsedRustcArgs::parse(argv).expect("parse rustc argv");
        let link_options = parsed.link_options_reaching_the_linker();
        assert!(
            link_options
                .iter()
                .any(|option| option.contains("fuse-ld=mold")),
            "{name} invocation reaches the linker without selecting mold: {link_options:?}"
        );
    }

    assert_eq!(
        compile_key_of(&setup_argv),
        compile_key_of(&no_setup_argv),
        "the no-setup `--config` selection keys differently from the written config"
    );
}

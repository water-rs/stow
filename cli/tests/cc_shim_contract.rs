//! `CC`/`CXX` are invoked with compiler arguments only, so the shim `stow setup`
//! installs behind them must supply the compiler itself. Pointing them at the
//! compiler-launcher shim (which expects the compiler as its first argument)
//! makes every cc-rs probe read a compiler flag as the program to run, and any
//! crate that builds C code fails before a single object is compiled.

use std::path::{Path, PathBuf};
use std::process::Command;

fn run_setup(project: &Path) -> toml::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("setup")
        .current_dir(project)
        .output()
        .expect("run stow setup");
    assert!(
        output.status.success(),
        "stow setup failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let config = std::fs::read_to_string(project.join(".cargo").join("config.toml"))
        .expect("read generated .cargo/config.toml");
    config.parse::<toml::Value>().expect("parse config.toml")
}

fn env_entry(config: &toml::Value, key: &str) -> String {
    config
        .get("env")
        .and_then(|env| env.get(key))
        .and_then(|entry| entry.get("value"))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("config.toml has no [env] entry for {key}"))
        .to_owned()
}

#[test]
fn the_shim_behind_cc_compiles_with_arguments_only() {
    let project = tempfile::tempdir().expect("create temp project");
    let config = run_setup(project.path());

    let source = project.path().join("probe.c");
    std::fs::write(&source, "int stow_probe(void) { return 0; }\n").expect("write probe source");
    let object = project.path().join("probe.o");

    let cc = env_entry(&config, "CC");
    let output = Command::new(&cc)
        .args(["-c", "-o"])
        .arg(&object)
        .arg(&source)
        .env(
            "STOW_REAL_CC",
            env_entry(&config, "STOW_REAL_CC"),
        )
        .output()
        .unwrap_or_else(|error| panic!("run CC shim {cc}: {error}"));

    assert!(
        output.status.success(),
        "CC shim {cc} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        object.exists(),
        "CC shim {cc} produced no object file at {}",
        object.display()
    );
}

#[test]
fn cc_and_the_cmake_launcher_use_different_shims() {
    let project = tempfile::tempdir().expect("create temp project");
    let config = run_setup(project.path());

    let cc = PathBuf::from(env_entry(&config, "CC"));
    let cxx = PathBuf::from(env_entry(&config, "CXX"));
    let launcher = PathBuf::from(env_entry(&config, "CMAKE_C_COMPILER_LAUNCHER"));

    assert_ne!(cc, launcher, "CC must not point at the launcher shim");
    assert_ne!(cxx, launcher, "CXX must not point at the launcher shim");
    assert_ne!(cc, cxx, "CC and CXX need separate shims");
}

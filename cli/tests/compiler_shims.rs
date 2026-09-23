//! `CC`/`CXX` and `CMAKE_*_COMPILER_LAUNCHER` have different calling
//! conventions, and using one shim for both breaks every C build.
//!
//! A *launcher* receives the program to run as its first argument. `CC` and
//! `CXX` do not — they are invoked with compiler arguments only, so a
//! launcher-shaped shim tries to execute the first compiler flag. Under `CC`
//! that turns every cc-rs probe into `configure: error: C compiler cannot
//! create executables`.

use std::path::Path;
use std::process::Command;

fn setup_in(dir: &Path) -> toml::Value {
    let cargo_home = dir.join("cargo-home");
    let status = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("setup")
        .current_dir(dir)
        .env("CARGO_HOME", &cargo_home)
        .status()
        .expect("run stow-cli setup");
    assert!(status.success(), "stow-cli setup failed");
    let config = std::fs::read_to_string(cargo_home.join("config.toml"))
        .expect("read generated cargo config.toml");
    toml::from_str(&config).expect("parse generated cargo config.toml")
}

/// Cargo's `[env]` entries are tables — the value lives under `.value`.
fn env_value<'a>(config: &'a toml::Value, key: &str) -> &'a str {
    config
        .get("env")
        .and_then(|env| env.get(key))
        .and_then(|entry| entry.get("value"))
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("generated config has no [env] entry for {key}"))
}

/// Hand `command` the `[env]` entries setup wrote that a compiler needs —
/// what cargo applies to build-script children before any shim runs. On
/// Windows that is the resolved MSVC toolchain's INCLUDE/LIB/PATH, which
/// `cl.exe` cannot run without; nothing extra exists on other platforms.
fn apply_toolchain_env(config: &toml::Value, command: &mut Command) {
    for key in ["INCLUDE", "LIB", "LIBPATH", "PATH"] {
        if let Some(value) = config
            .get("env")
            .and_then(|env| env.get(key))
            .and_then(|entry| entry.get("value"))
            .and_then(toml::Value::as_str)
        {
            command.env(key, value);
        }
    }
}

#[test]
fn cc_is_invoked_with_compiler_arguments_only() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = setup_in(dir.path());

    // The shim execs the compiler setup recorded; a host without one has
    // nothing to probe.
    let real_cc = env_value(&config, "STOW_REAL_CC");
    if let Err(error) = Command::new(real_cc).arg("--version").output() {
        if error.kind() == std::io::ErrorKind::NotFound {
            return;
        }
        panic!("spawn {real_cc} --version: {error}");
    }

    std::fs::write(dir.path().join("probe.c"), "int main(void) { return 0; }\n")
        .expect("write probe source");
    let object = dir.path().join("probe.o");

    // Exactly how cc-rs calls it: no leading executable positional, and the
    // flag shape its family detection emits — `-Fo` for an MSVC `cl`, `-o`
    // for anything GNU-shaped.
    let stem = Path::new(real_cc)
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_lowercase());
    let mut command = Command::new(env_value(&config, "CC"));
    if stem.is_some_and(|stem| stem == "cl" || stem.contains("clang-cl")) {
        command.arg(format!("-Fo{}", object.display()));
    } else {
        command.arg("-o").arg(&object);
    }
    command
        .arg("-c")
        .arg("probe.c")
        .current_dir(dir.path())
        .env("STOW_REAL_CC", real_cc);
    apply_toolchain_env(&config, &mut command);
    let status = command.status().expect("run the CC shim");

    assert!(status.success(), "the CC shim failed to compile a probe");
    assert!(object.exists(), "the CC shim produced no object file");
}

#[test]
fn the_launcher_and_the_compilers_are_three_different_shims() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = setup_in(dir.path());

    let cc = env_value(&config, "CC");
    let cxx = env_value(&config, "CXX");
    let launcher = env_value(&config, "CMAKE_C_COMPILER_LAUNCHER");

    assert_ne!(cc, launcher, "CC must not be the launcher-shaped shim");
    assert_ne!(cxx, launcher, "CXX must not be the launcher-shaped shim");
    assert_ne!(cc, cxx, "CC and CXX must exec different real compilers");
    assert_eq!(
        launcher,
        env_value(&config, "CMAKE_CXX_COMPILER_LAUNCHER"),
        "both CMake launcher variables take the same launcher shim"
    );
}

#[test]
fn an_explicit_toolchain_survives_setup() {
    let dir = tempfile::tempdir().expect("temp dir");
    let cargo_home = dir.path().join("cargo-home");
    let status = Command::new(env!("CARGO_BIN_EXE_stow-cli"))
        .arg("setup")
        .current_dir(dir.path())
        .env("CARGO_HOME", &cargo_home)
        .env("CC", "/usr/bin/clang")
        .env("CXX", "/usr/bin/clang++")
        // Setup runs inside a stow-wired build with these already exported;
        // the test asserts the *injected* toolchain is what gets recorded.
        .env_remove("STOW_REAL_CC")
        .env_remove("STOW_REAL_CXX")
        .status()
        .expect("run stow-cli setup");
    assert!(status.success(), "stow-cli setup failed");
    let config: toml::Value = toml::from_str(
        &std::fs::read_to_string(cargo_home.join("config.toml"))
            .expect("read generated cargo config.toml"),
    )
    .expect("parse generated cargo config.toml");

    // Overwriting CC/CXX without recording them would silently drop the
    // caller's compiler choice.
    assert_eq!(env_value(&config, "STOW_REAL_CC"), "/usr/bin/clang");
    assert_eq!(env_value(&config, "STOW_REAL_CXX"), "/usr/bin/clang++");
}

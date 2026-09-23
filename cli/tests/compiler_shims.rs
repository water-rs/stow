//! `CC_<target>`/`CXX_<target>` and `CMAKE_*_COMPILER_LAUNCHER` have
//! different calling conventions, and using one shim for both breaks every
//! C build.
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
fn env_value<'a>(config: &'a toml::Value, key: &str) -> Option<&'a str> {
    config
        .get("env")
        .and_then(|env| env.get(key))
        .and_then(|entry| entry.get("value"))
        .and_then(toml::Value::as_str)
}

/// The value of the `cc` crate's target-scoped `CC`/`CXX` key setup wrote —
/// exactly one `[env]` entry starts with `<base>_`, and a bare `<base>`
/// entry must never be written.
fn scoped_env_value<'a>(config: &'a toml::Value, base: &str) -> &'a str {
    let env = config.get("env").expect("generated config has no [env]");
    assert!(
        env.get(base).is_none(),
        "bare {base} entry must not be written — it hijacks every target"
    );
    let matches: Vec<&str> = env
        .as_table()
        .expect("[env] is a table")
        .iter()
        .filter(|(key, _)| key.starts_with(&format!("{base}_")))
        .filter_map(|(_, entry)| entry.get("value").and_then(toml::Value::as_str))
        .collect();
    match matches.as_slice() {
        [value] => value,
        _ => panic!("expected exactly one scoped {base}_* entry, got {matches:?}"),
    }
}

/// The compiler the `CC` shim will exec for this probe: the recorded
/// `STOW_REAL_CC` when setup saw one, else the per-invocation resolution —
/// `cl.exe` under an msvc toolchain, `cc` elsewhere.
fn resolved_cc(config: &toml::Value) -> String {
    if let Some(recorded) = env_value(config, "STOW_REAL_CC") {
        return recorded.to_owned();
    }
    if cfg!(windows) {
        "cl.exe".to_owned()
    } else {
        "cc".to_owned()
    }
}

#[test]
fn cc_is_invoked_with_compiler_arguments_only() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = setup_in(dir.path());

    let recorded = env_value(&config, "STOW_REAL_CC").map(str::to_owned);
    let real_cc = resolved_cc(&config);
    // A toolchain the runner does not have cannot be probed — but on
    // Windows the shim resolves `cl.exe` through find-msvc-tools, not
    // PATH, so an absent `cl.exe` there is exactly what the probe covers
    // rather than a reason to skip.
    let resolvable_on_path =
        cfg!(windows) || Command::new(&real_cc).arg("--version").output().is_ok();
    if !resolvable_on_path {
        return;
    }

    std::fs::write(dir.path().join("probe.c"), "int main(void) { return 0; }\n")
        .expect("write probe source");
    let object = dir.path().join(if cfg!(windows) {
        "probe.obj"
    } else {
        "probe.o"
    });

    // Exactly how cc-rs calls it: no leading executable positional, and the
    // flag shape its family detection emits — `-Fo` for an MSVC `cl`, `-o`
    // for anything GNU-shaped.
    let stem = Path::new(&real_cc)
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_lowercase());
    let msvc_family = stem.is_some_and(|stem| stem == "cl" || stem.contains("clang-cl"));
    let mut command = Command::new(scoped_env_value(&config, "CC"));
    if msvc_family {
        command.arg(format!("-Fo{}", object.display()));
    } else {
        command.arg("-o").arg(&object);
    }
    command
        .arg("-c")
        .arg("probe.c")
        .current_dir(dir.path())
        // The real build gets TARGET from cargo; without it the shim's msvc
        // resolution keys on the host arch — same answer on this runner.
        .env("TARGET", host_triple());
    if let Some(recorded) = &recorded {
        command.env("STOW_REAL_CC", recorded);
    } else {
        command.env_remove("STOW_REAL_CC");
    }
    let status = command.status().expect("run the CC shim");

    assert!(status.success(), "the CC shim failed to compile a probe");
    assert!(object.exists(), "the CC shim produced no object file");
}

#[test]
fn the_launcher_and_the_compilers_are_three_different_shims() {
    let dir = tempfile::tempdir().expect("temp dir");
    let config = setup_in(dir.path());

    let cc = scoped_env_value(&config, "CC");
    let cxx = scoped_env_value(&config, "CXX");
    let launcher = env_value(&config, "CMAKE_C_COMPILER_LAUNCHER").expect("launcher entry");

    assert_ne!(cc, launcher, "CC must not be the launcher-shaped shim");
    assert_ne!(cxx, launcher, "CXX must not be the launcher-shaped shim");
    assert_ne!(cc, cxx, "CC and CXX must exec different real compilers");
    assert_eq!(
        launcher,
        env_value(&config, "CMAKE_CXX_COMPILER_LAUNCHER").expect("cxx launcher entry"),
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
    assert_eq!(env_value(&config, "STOW_REAL_CC"), Some("/usr/bin/clang"));
    assert_eq!(
        env_value(&config, "STOW_REAL_CXX"),
        Some("/usr/bin/clang++")
    );
}

/// The rustc host triple, the same answer `stow setup` scopes `CC`/`CXX`
/// under — `TARGET` is what the shim reads to pick the msvc toolchain.
fn host_triple() -> String {
    let output = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .arg("-vV")
        .output()
        .expect("run rustc -vV");
    String::from_utf8(output.stdout)
        .expect("rustc -vV is utf8")
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("rustc -vV reports a host")
        .to_owned()
}

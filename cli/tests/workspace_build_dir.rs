//! `stow setup` places each workspace's build directory under stow's
//! cache root (stow#1538): a plain `cargo build` afterwards writes its
//! intermediates there and its final artifacts in the project's `target`,
//! and a build directory the user configured is left alone.

mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use support::{PrivateDaemon, denied_registry, hermetic_stow_env};

struct Machine {
    project: support::TempDir,
    cargo_home: PathBuf,
    home: PathBuf,
    cache: PathBuf,
}

impl Machine {
    fn new() -> Self {
        let project = support::tempdir().expect("project dir");
        let home = project.path().join("stow-home");
        let cache = home.join("stow-cache");
        let cargo_home = project.path().join("cargo-home");
        std::fs::create_dir_all(project.path().join("src")).expect("src dir");
        std::fs::write(
            project.path().join("Cargo.toml"),
            "[package]\nname = \"placed\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("manifest");
        std::fs::write(
            project.path().join("src").join("lib.rs"),
            "pub fn one() -> u8 { 1 }\n",
        )
        .expect("lib");
        // No remote: the build under test reaches nothing, and setup
        // fetches no index slice.
        support::write_global_config(&[&home], "[cache]\nremote = false\n");
        Self {
            project,
            cargo_home,
            home,
            cache,
        }
    }

    fn dir(&self) -> &Path {
        self.project.path()
    }

    fn hermetic(&self, command: &mut Command) {
        hermetic_stow_env(command, &denied_registry(), &self.cache, &self.home);
        command
            .current_dir(self.dir())
            .env("CARGO_HOME", &self.cargo_home)
            .env_remove("CARGO_BUILD_BUILD_DIR")
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("RUSTC_WRAPPER");
    }

    fn setup(&self, configure: impl FnOnce(&mut Command)) -> Output {
        let mut setup = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
        setup.arg("setup");
        self.hermetic(&mut setup);
        configure(&mut setup);
        let output = setup.output().expect("run stow-cli setup");
        assert!(
            output.status.success(),
            "stow setup failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// A plain `cargo build`: the wiring is only what setup wrote into
    /// the cargo home.
    fn cargo_build(&self) {
        let daemon = PrivateDaemon::in_home(&self.home);
        let mut build = support::cargo_command(&self.home);
        self.hermetic(&mut build);
        build.arg("build").env("CARGO_INCREMENTAL", "0");
        let output = support::output_after_session(&mut build, &self.home);
        drop(daemon);
        assert!(
            output.status.success(),
            "cargo build failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The build directory cargo reports for the workspace in `dir`, its
    /// template expanded.
    fn reported_build_dir(&self, dir: &Path) -> PathBuf {
        let mut metadata = support::cargo_command(&self.home);
        metadata.args(["metadata", "--format-version", "1", "--no-deps"]);
        self.hermetic(&mut metadata);
        let output = metadata
            .current_dir(dir)
            .output()
            .expect("run cargo metadata");
        assert!(
            output.status.success(),
            "cargo metadata failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let metadata: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("parse cargo metadata");
        PathBuf::from(
            metadata["build_directory"]
                .as_str()
                .expect("cargo reports build_directory"),
        )
    }

    fn global_config(&self) -> toml::Value {
        let text = std::fs::read_to_string(self.cargo_home.join("config.toml"))
            .expect("read the written cargo config");
        toml::from_str(&text).expect("parse the written cargo config")
    }
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

fn build_dir_of(config: &toml::Value) -> Option<&str> {
    config.get("build")?.get("build-dir")?.as_str()
}

#[test]
fn setup_places_intermediates_under_stows_cache_and_artifacts_in_target() {
    let machine = Machine::new();
    let output = machine.setup(|_| {});

    let config = machine.global_config();
    let written = build_dir_of(&config).expect("setup wrote build.build-dir");
    let expected = machine
        .cache
        .join("build-dir")
        .join("{workspace-path-hash}");
    assert_eq!(Path::new(written), expected);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&format!("build-dir: {written}")),
        "setup did not report the build directory:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    machine.cargo_build();

    let intermediates = files_under(&machine.cache.join("build-dir"));
    assert!(
        !intermediates.is_empty(),
        "no intermediates under {}",
        machine.cache.join("build-dir").display()
    );
    let target = machine.dir().join("target");
    let artifact = target.join("debug").join("libplaced.rlib");
    assert!(
        artifact.is_file(),
        "no final artifact {}",
        artifact.display()
    );
    let leaked: Vec<_> = files_under(&target)
        .into_iter()
        .filter(|path| path != &artifact)
        .filter(|path| {
            path.strip_prefix(target.join("debug"))
                .is_ok_and(|rest| rest.starts_with("build") || rest.starts_with("deps"))
        })
        .collect();
    assert!(
        leaked.is_empty(),
        "intermediates were written under target: {leaked:?}"
    );
}

#[test]
fn setup_run_again_keeps_one_stow_build_dir_entry() {
    let machine = Machine::new();
    machine.setup(|_| {});
    let once = std::fs::read_to_string(machine.cargo_home.join("config.toml")).expect("read");
    machine.setup(|_| {});
    let twice = std::fs::read_to_string(machine.cargo_home.join("config.toml")).expect("read");
    assert_eq!(once, twice);
    assert_eq!(twice.matches("build-dir =").count(), 1);
}

#[test]
fn a_project_build_directory_wins_for_that_project_and_not_for_setup() {
    let machine = Machine::new();
    let mine = machine.dir().join("my-build-dir");
    std::fs::create_dir_all(machine.dir().join(".cargo")).expect("project .cargo");
    std::fs::write(
        machine.dir().join(".cargo").join("config.toml"),
        format!(
            "[build]\nbuild-dir = {}\n",
            toml::Value::String(mine.to_str().expect("utf-8 path").to_owned())
        ),
    )
    .expect("project config");

    let output = machine.setup(|_| {});

    // A project's config ranks above the global one, so setup still
    // places the global key for every other project.
    let config = machine.global_config();
    assert!(
        build_dir_of(&config).is_some_and(|dir| dir.ends_with("{workspace-path-hash}")),
        "setup skipped the global key: {config:?}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("left alone"));

    machine.cargo_build();
    assert!(
        !files_under(&mine).is_empty(),
        "the project's build directory was not used"
    );
    assert!(
        files_under(&machine.cache.join("build-dir")).is_empty(),
        "stow's build directory was used despite the project's"
    );
}

#[test]
fn a_build_directory_in_the_global_config_is_kept_and_reported() {
    let machine = Machine::new();
    let mine = machine.dir().join("my-global-build-dir");
    std::fs::create_dir_all(&machine.cargo_home).expect("cargo home");
    std::fs::write(
        machine.cargo_home.join("config.toml"),
        format!(
            "[build]\nbuild-dir = {}\n",
            toml::Value::String(mine.to_str().expect("utf-8 path").to_owned())
        ),
    )
    .expect("global config");

    let output = machine.setup(|_| {});

    assert_eq!(
        build_dir_of(&machine.global_config()),
        mine.to_str(),
        "setup replaced the user's build directory"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("already configured, left alone") && stdout.contains("my-global-build-dir"),
        "setup did not report the user's build directory:\n{stdout}"
    );

    machine.cargo_build();
    assert_ne!(files_under(&mine), [] as [std::path::PathBuf; 0]);
    assert_eq!(
        files_under(&machine.cache.join("build-dir")),
        [] as [std::path::PathBuf; 0]
    );
}

/// `stow build` at the default isolation level grants the placed build
/// directory: a build script writes its `OUT_DIR` there and the crate
/// builds.
#[test]
fn a_sandboxed_stow_build_with_a_build_script_uses_the_placed_build_directory() {
    sandboxed_build_script_build(None);
}

/// Under `strict` the grant is exactly this workspace's build directory:
/// a build script cannot write another workspace's.
#[test]
fn a_strict_build_script_cannot_write_another_workspaces_build_directory() {
    let outcome = sandboxed_build_script_build(Some("strict"));
    assert_eq!(
        outcome, "denied",
        "the first workspace's build script could write the second's build directory"
    );
}

/// Set up a machine, build a crate with a build script through `stow
/// build` (at `isolation` when given), and return what the script's attempt
/// to write a second workspace's build directory came to — which a build
/// whose sandbox leaves the machine open does not restrict.
fn sandboxed_build_script_build(isolation: Option<&str>) -> String {
    let machine = Machine::new();
    machine.setup(|_| {});

    // A second workspace, whose build directory the first one's build
    // script must not be able to write: the grant is this workspace's own
    // directory, not the directory that holds every workspace's.
    let other = support::tempdir().expect("second workspace");
    std::fs::create_dir_all(other.path().join("src")).expect("src dir");
    std::fs::write(
        other.path().join("Cargo.toml"),
        "[package]\nname = \"other\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("manifest");
    std::fs::write(other.path().join("src").join("lib.rs"), "").expect("lib");
    let other_build_dir = machine.reported_build_dir(other.path());
    let first_build_dir = machine.reported_build_dir(machine.dir());
    assert_ne!(other_build_dir, first_build_dir);
    std::fs::create_dir_all(&other_build_dir).expect("create the second build dir");

    std::fs::write(
        machine.dir().join("build.rs"),
        format!(
            "fn main() {{\n\
             let out = std::env::var(\"OUT_DIR\").expect(\"OUT_DIR\");\n\
             std::fs::write(std::path::Path::new(&out).join(\"gen.rs\"), \"pub fn two() -> u8 {{ 2 }}\\n\").expect(\"write gen.rs\");\n\
             let intruder = std::path::Path::new({other:?}).join(\"intruder\");\n\
             let outcome = if std::fs::write(&intruder, \"x\").is_ok() {{ \"written\" }} else {{ \"denied\" }};\n\
             std::fs::write(std::path::Path::new(&out).join(\"intruder-outcome\"), outcome).expect(\"write the outcome\");\n\
             }}\n",
            other = other_build_dir.to_str().expect("utf-8 path"),
        ),
    )
    .expect("build script");
    std::fs::write(
        machine.dir().join("src").join("lib.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/gen.rs\"));\n",
    )
    .expect("lib");

    let mut build = Command::new(env!("CARGO_BIN_EXE_stow-cli"));
    build.arg("build");
    if let Some(isolation) = isolation {
        build.args(["--isolation", isolation]);
    }
    machine.hermetic(&mut build);
    let output = build.output().expect("run stow-cli build");
    assert!(
        output.status.success(),
        "stow build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        files_under(&machine.cache.join("build-dir"))
            .into_iter()
            .any(|path| path.file_name().is_some_and(|name| name == "gen.rs")),
        "the build script's OUT_DIR is not under the placed build directory"
    );
    assert!(
        machine
            .dir()
            .join("target")
            .join("debug")
            .join("libplaced.rlib")
            .is_file()
    );

    let outcome = files_under(&first_build_dir)
        .into_iter()
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name == "intruder-outcome")
        })
        .expect("the build script recorded its outcome in its own build directory");
    let outcome = std::fs::read_to_string(outcome).expect("read the outcome");
    assert_eq!(
        other_build_dir.join("intruder").exists(),
        outcome == "written"
    );
    outcome
}

#[test]
fn a_build_directory_in_the_environment_is_kept_and_reported() {
    let machine = Machine::new();
    let output = machine.setup(|setup| {
        setup.env("CARGO_BUILD_BUILD_DIR", machine.dir().join("env-build-dir"));
    });

    assert_eq!(build_dir_of(&machine.global_config()), None);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("already configured, left alone"),
        "setup did not report CARGO_BUILD_BUILD_DIR:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

//! The `[cache]` table of the global config and the per-run flags
//! (stow#1059, stow#1007).
//!
//! Each of the three layers (`remote`, `local_crates_io`, `local_git`) is
//! switched off from the config file and from its flag, and must turn off
//! exactly its own lookups and stores. Registry and edge both point at a
//! listener that counts the connections it is offered, so any request a build
//! makes with the remote layer off shows up as a nonzero count, and the
//! build's stderr must carry no warning for a network the user chose not to
//! have.

mod support;

// The shared fixture carries helpers this test does not call; each
// integration binary lints them per target.
#[allow(dead_code)]
mod build_fixture;

use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use build_fixture::{
    StoredEntry, cargo_fetch, commit_git_repo, copy_registry_package, journal_files,
    recording_edge, stored_entries, stow_build_in_with_env, stow_cli_in, stow_setup_in,
    tripwire_url, write_fixture, write_fixture_config,
};

/// Registry crates small enough to keep the fixture quick: two leaf crates
/// and the `proc-macro2`/`quote` pair with `unicode-ident`.
const FIXTURE_DEPENDENCIES: &str = "cfg-if = \"1\"\n\
     memchr = \"2\"\n\
     proc-macro2 = \"1\"\n\
     quote = \"1\"\n";

/// The units the fixture's all-miss build stores in the local cache.
const CACHEABLE_UNITS: usize = 5;

/// The info event a local-cache serve emits.
const SERVED_LOCALLY: &str = "served rustc invocation from local stow artifact cache";

/// The debug event a gated lookup emits when the layer is off for the entry.
const LAYER_OFF: &str = "cache layer off for this entry";

const REMOTE_OFF: &str = "[cache]\nremote = false\n";
const CRATES_IO_OFF: &str = "[cache]\nlocal_crates_io = false\n";
const GIT_OFF: &str = "[cache]\nlocal_git = false\n";
const EVERY_LAYER_OFF: &str =
    "[cache]\nremote = false\nlocal_crates_io = false\nlocal_git = false\n";

const NO_REMOTE: &str = "--no-remote-cache";
const NO_CRATES_IO: &str = "--no-local-crates-io-cache";
const NO_GIT: &str = "--no-local-git-cache";

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A line of `stderr` carrying both `event` and the field `crate_name=<name>`.
fn logged(stderr: &str, event: &str, crate_name: &str) -> bool {
    let field = format!("crate_name={crate_name}");
    stderr.lines().any(|line| {
        line.contains(event)
            && line
                .split(&field)
                .nth(1)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
    })
}

fn rustc_name(package: &str) -> String {
    package.replace('-', "_")
}

fn packages(entries: &[StoredEntry]) -> Vec<String> {
    let mut names: Vec<_> = entries
        .iter()
        .map(|entry| rustc_name(&entry.crate_name))
        .collect();
    names.sort();
    names
}

/// One project, one `CARGO_HOME`, one cache: the pieces every scenario
/// shares.
struct Project {
    dir: tempfile::TempDir,
    cargo_home: tempfile::TempDir,
    cache: tempfile::TempDir,
}

impl Project {
    fn registry(config: &str) -> Self {
        let project = Self {
            dir: tempfile::tempdir().expect("temp dir"),
            cargo_home: tempfile::tempdir().expect("cargo home"),
            cache: tempfile::tempdir().expect("cache dir"),
        };
        write_fixture(
            project.dir.path(),
            project.cargo_home.path(),
            FIXTURE_DEPENDENCIES,
        );
        project.configure(config);
        stow_setup_in(project.dir.path(), project.cargo_home.path());
        project
    }

    fn configure(&self, config: &str) {
        write_fixture_config(self.dir.path(), config);
    }

    fn db(&self) -> PathBuf {
        self.cache.path().join("state-v3.sqlite3")
    }

    fn entries(&self) -> Vec<StoredEntry> {
        stored_entries(&self.db())
    }

    /// One `stow build` with a fresh target directory, so the cache is the
    /// only thing that carries over. `flags` come right after the
    /// subcommand; stow hands everything from the first cargo argument on to
    /// cargo.
    fn build(&self, edge: &str, flags: &[&str], label: &str) -> Built {
        build_in(
            self.dir.path(),
            self.cargo_home.path(),
            self.cache.path(),
            edge,
            flags,
            label,
        )
    }
}

struct Built {
    output: Output,
    target: tempfile::TempDir,
}

fn build_in(
    dir: &Path,
    cargo_home: &Path,
    cache: &Path,
    edge: &str,
    flags: &[&str],
    label: &str,
) -> Built {
    let target = tempfile::tempdir().expect("target dir");
    let mut args = vec!["build"];
    args.extend_from_slice(flags);
    args.push("--offline");
    let output = stow_build_in_with_env(
        dir,
        &args,
        edge,
        edge,
        cache,
        cargo_home,
        target.path(),
        &[("RUST_LOG", "stow_cli=debug")],
    );
    assert!(
        output.status.success(),
        "{label} failed:\n{}",
        stderr_of(&output)
    );
    Built { output, target }
}

fn assert_no_network_and_no_warning(built: &Built, connections: &Arc<AtomicUsize>, label: &str) {
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "{label} made a network request"
    );
    assert_eq!(
        journal_files(built.target.path()),
        Vec::<String>::new(),
        "{label} journaled misses with the remote cache off"
    );
    // Only the network path's warnings count: an unrelated warning, such as
    // SQLite reporting a slow statement on a loaded runner, says nothing about
    // whether the switch kept the build off the network.
    let stderr = stderr_of(&built.output);
    assert!(
        !stderr.lines().any(|line| {
            let line = line.to_ascii_lowercase();
            line.contains("unreachable")
                || (line.contains("warn")
                    && ["registry", "index", "edge", "network", "public cache"]
                        .iter()
                        .any(|word| line.contains(word)))
        }),
        "{label} warned about a network it was told not to use:\n{stderr}"
    );
}

/// What `stow stats --json` reports: served hits and the compile time they
/// saved, in milliseconds.
fn stats(project: &Project) -> (u64, u64) {
    let output = stow_cli_in(
        project.dir.path(),
        &["stats", "--json"],
        project.cache.path(),
        project.cargo_home.path(),
    );
    assert!(
        output.status.success(),
        "stow stats failed:\n{}",
        stderr_of(&output)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stats --json is JSON");
    (
        report["hits"].as_u64().expect("hits"),
        report["cpu_millis_saved"]
            .as_u64()
            .expect("cpu_millis_saved"),
    )
}

/// A build with the remote layer off, from `config` or from the flag,
/// makes no network attempt, journals nothing, prints no warning, and
/// `stow stats` reports the compile time its local hits saved.
fn remote_off_builds_offline_and_serves_locally(config: &str, flags: &[&str]) {
    let project = Project::registry(config);
    let (tripwire, connections) = tripwire_url();

    let fill = project.build(&tripwire, flags, "fill build");
    assert_no_network_and_no_warning(&fill, &connections, "the fill build");
    assert_eq!(
        project.entries().len(),
        CACHEABLE_UNITS,
        "the fill build stores every cacheable unit locally"
    );
    assert_eq!(stats(&project).0, 0, "nothing was served yet");

    let serve = project.build(&tripwire, flags, "serve build");
    assert_no_network_and_no_warning(&serve, &connections, "the serve build");
    let (hits, saved_millis) = stats(&project);
    assert!(
        hits >= u64::try_from(CACHEABLE_UNITS).expect("count fits"),
        "the serve build must hit the local cache for every unit, got {hits} hits:\n{}",
        stderr_of(&serve.output)
    );
    assert!(
        saved_millis > 0,
        "local hits must report the compile time they saved"
    );
}

#[test]
fn remote_off_in_the_config_builds_offline_and_serves_locally() {
    remote_off_builds_offline_and_serves_locally(REMOTE_OFF, &[]);
}

#[test]
fn the_no_remote_cache_flag_builds_offline_and_serves_locally() {
    remote_off_builds_offline_and_serves_locally("", &[NO_REMOTE]);
}

/// Entries downloaded from the remote earlier are not served with the
/// remote layer off: the units compile locally and are stored as local
/// entries.
fn remote_off_does_not_serve_downloaded_entries(config: &str, flags: &[&str]) {
    let project = Project::registry(config);
    let (tripwire, connections) = tripwire_url();
    project.build(&tripwire, flags, "fill build");
    let filled = project.entries();
    assert_eq!(filled.len(), CACHEABLE_UNITS);

    // Make every stored entry look downloaded.
    rewrite_provenance(&project.db(), "remote");
    let before = stats(&project).0;

    let rebuilt = project.build(&tripwire, flags, "rebuild over downloaded entries");
    assert_no_network_and_no_warning(&rebuilt, &connections, "the rebuild");
    let stderr = stderr_of(&rebuilt.output);
    for package in ["cfg_if", "memchr", "proc_macro2", "quote", "unicode_ident"] {
        assert!(
            !logged(&stderr, SERVED_LOCALLY, package),
            "the downloaded {package} entry was served:\n{stderr}"
        );
    }
    // A unit over a dependency that compiled here compiles here too, without
    // a lookup; the leaves are looked up and refused by the layer gate.
    for package in ["cfg_if", "memchr", "unicode_ident", "proc_macro2"] {
        assert!(
            logged(&stderr, LAYER_OFF, package),
            "the downloaded {package} entry was not refused by the layer gate:\n{stderr}"
        );
    }
    assert_eq!(
        stats(&project).0,
        before,
        "a downloaded entry counted as a hit"
    );
    let after = project.entries();
    assert_eq!(packages(&after), packages(&filled));
    assert!(
        after.iter().all(|entry| entry.provenance == "local"),
        "the recompiled units must be stored as local entries: {after:#?}"
    );
}

#[test]
fn remote_off_in_the_config_does_not_serve_downloaded_entries() {
    remote_off_does_not_serve_downloaded_entries(REMOTE_OFF, &[]);
}

#[test]
fn the_no_remote_cache_flag_does_not_serve_downloaded_entries() {
    remote_off_does_not_serve_downloaded_entries("", &[NO_REMOTE]);
}

fn rewrite_provenance(db: &Path, provenance: &str) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let options = sqlx::sqlite::SqliteConnectOptions::new().filename(db);
            let pool = sqlx::SqlitePool::connect_with(options)
                .await
                .expect("open the state db");
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "UPDATE artifact_cache_entries SET provenance = '{provenance}'"
            )))
            .execute(&pool)
            .await
            .expect("rewrite the provenance column");
            pool.close().await;
        });
}

/// With every layer off a build reads and writes no cache and makes no
/// network attempt. (Isolation under it is covered by the sandbox suite,
/// which runs its boundary probes with every layer off.)
fn every_layer_off_reads_and_writes_no_cache(config: &str, flags: &[&str]) {
    let project = Project::registry(config);
    let (tripwire, connections) = tripwire_url();
    for run in ["first build", "second build"] {
        let built = project.build(&tripwire, flags, run);
        assert_no_network_and_no_warning(&built, &connections, run);
        assert_eq!(
            project.entries().len(),
            0,
            "{run}: with every layer off no cache entry is written"
        );
    }
    assert_eq!(stats(&project), (0, 0), "every layer off serves nothing");
}

#[test]
fn every_layer_off_in_the_config_reads_and_writes_no_cache() {
    every_layer_off_reads_and_writes_no_cache(EVERY_LAYER_OFF, &[]);
}

#[test]
fn the_three_flags_together_read_and_write_no_cache() {
    every_layer_off_reads_and_writes_no_cache("", &[NO_REMOTE, NO_CRATES_IO, NO_GIT]);
}

/// The crates.io layer off: no crates.io unit is stored or looked up, while
/// the remote layer is still asked (a recording edge answers 404).
fn crates_io_off_stores_and_serves_nothing(config: &str, flags: &[&str]) {
    let project = Project::registry("");
    let (edge, requests) = recording_edge();

    // Fill with the layer on: the entries a later lookup could serve.
    project.build(&edge, &[], "fill build");
    assert_eq!(project.entries().len(), CACHEABLE_UNITS);

    project.configure(config);
    let served = project.build(&edge, flags, "build with the layer off");
    let stderr = stderr_of(&served.output);
    for package in ["cfg_if", "memchr", "proc_macro2", "quote", "unicode_ident"] {
        assert!(
            !logged(&stderr, SERVED_LOCALLY, package),
            "{package} was served from the local cache with the layer off:\n{stderr}"
        );
    }
    assert!(
        requests
            .lock()
            .expect("requests lock")
            .iter()
            .any(|line| line.contains("/v2/") || line.contains("/index")),
        "the remote layer stayed on, so the build still asks it"
    );

    // And stores nothing: a fresh cache stays empty.
    let empty = tempfile::tempdir().expect("empty cache");
    build_in(
        project.dir.path(),
        project.cargo_home.path(),
        empty.path(),
        &edge,
        flags,
        "build into an empty cache",
    );
    assert_eq!(
        stored_entries(&empty.path().join("state-v3.sqlite3")).len(),
        0,
        "no crates.io unit is stored with the layer off"
    );
}

#[test]
fn local_crates_io_off_in_the_config_stores_and_serves_nothing() {
    crates_io_off_stores_and_serves_nothing(CRATES_IO_OFF, &[]);
}

#[test]
fn the_no_local_crates_io_cache_flag_stores_and_serves_nothing() {
    crates_io_off_stores_and_serves_nothing("", &[NO_CRATES_IO]);
}

/// The git layer off leaves crates.io units alone: a registry-only project
/// stores and serves exactly as with every layer on.
#[test]
fn the_git_layer_off_leaves_crates_io_units_cached() {
    for (config, flags) in [(GIT_OFF, &[][..]), ("", &[NO_GIT][..])] {
        let project = Project::registry(config);
        let (edge, _requests) = recording_edge();
        project.build(&edge, flags, "fill build");
        assert_eq!(
            project.entries().len(),
            CACHEABLE_UNITS,
            "{config:?} {flags:?}: crates.io units are stored"
        );
        let served = project.build(&edge, flags, "serve build");
        let stderr = stderr_of(&served.output);
        for package in ["cfg_if", "memchr", "proc_macro2", "quote", "unicode_ident"] {
            assert!(
                logged(&stderr, SERVED_LOCALLY, package),
                "{package} was not served with only the git layer off:\n{stderr}"
            );
        }
    }
}

/// The remote layer off leaves both local layers on: a build stores every
/// crates.io unit.
#[test]
fn a_remote_off_build_still_stores_every_local_kind() {
    let project = Project::registry(REMOTE_OFF);
    let (tripwire, _connections) = tripwire_url();
    project.build(&tripwire, &[], "build");
    assert_eq!(project.entries().len(), CACHEABLE_UNITS);
}

/// A scenario with a git dependency: `unicode-ident` patched to a
/// `file://` repository, under `quote` and `proc-macro2`.
struct GitProject {
    root: tempfile::TempDir,
    cargo_home: tempfile::TempDir,
    patch: String,
}

impl GitProject {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("root");
        let cargo_home = tempfile::tempdir().expect("cargo home");
        let home = root.path().join("git-home");
        std::fs::create_dir_all(&home).expect("create git home");
        // The registry copy of `unicode-ident` must be extracted before the
        // repository can be made from it.
        let seed = root.path().join("seed");
        write_project(&seed, cargo_home.path(), "seed", "");
        let repo = root.path().join("unicode-ident-repo");
        copy_registry_package(cargo_home.path(), "unicode-ident", &repo);
        let url = commit_git_repo(&repo, &home);
        let patch = format!("[patch.crates-io]\nunicode-ident = {{ git = \"{url}\" }}\n");
        Self {
            root,
            cargo_home,
            patch,
        }
    }

    /// A project named `name` over the git unit, with `config` as the global
    /// config its builds read.
    fn project(&self, name: &str, config: &str) -> PathBuf {
        let dir = self.root.path().join(name);
        write_project(&dir, self.cargo_home.path(), name, &self.patch);
        write_fixture_config(&dir, config);
        dir
    }

    fn build(&self, dir: &Path, cache: &Path, flags: &[&str], label: &str) -> Built {
        let (edge, _requests) = recording_edge();
        build_in(dir, self.cargo_home.path(), cache, &edge, flags, label)
    }
}

fn write_project(dir: &Path, cargo_home: &Path, name: &str, patch: &str) {
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\nquote = \"1\"\n\n{patch}"
        ),
    )
    .expect("write manifest");
    cargo_fetch(dir, cargo_home);
    stow_setup_in(dir, cargo_home);
}

/// One switch setting and what it leaves: the units a fresh cache holds after
/// one build, and the units a second project at the same commit is served.
struct Case {
    config: &'static str,
    flags: &'static [&'static str],
    stored: &'static [&'static str],
    served: &'static [&'static str],
}

/// What a fresh cache holds after one build, and which of its units a second
/// project at the same commit is served, per switch.
#[test]
fn each_local_switch_gates_only_its_source_kind() {
    let git = GitProject::new();
    let case = |config, flags, stored, served| Case {
        config,
        flags,
        stored,
        served,
    };
    let cases = [
        case(
            "",
            &[][..],
            &["proc_macro2", "quote", "unicode_ident"][..],
            &["proc_macro2", "quote", "unicode_ident"][..],
        ),
        // The git unit is the only entry: the crates.io units compiled over
        // it follow the crates.io layer.
        case(CRATES_IO_OFF, &[], &["unicode_ident"], &["unicode_ident"]),
        case("", &[NO_CRATES_IO], &["unicode_ident"], &["unicode_ident"]),
        // No git entry: a crates.io unit over it cannot bind its dependency,
        // so none is stored either.
        case(GIT_OFF, &[], &[], &[]),
        case("", &[NO_GIT], &[], &[]),
    ];
    for Case {
        config,
        flags,
        stored,
        served,
    } in cases
    {
        let label = format!("config {config:?} flags {flags:?}");
        let cache = tempfile::tempdir().expect("cache");
        let first = git.project("first", config);
        git.build(&first, cache.path(), flags, "first build");
        let entries = stored_entries(&cache.path().join("state-v3.sqlite3"));
        assert_eq!(packages(&entries), stored, "{label}: stored units");

        let second = git.project("second", config);
        let built = git.build(&second, cache.path(), flags, "second build");
        let stderr = stderr_of(&built.output);
        for package in ["proc_macro2", "quote", "unicode_ident"] {
            assert_eq!(
                logged(&stderr, SERVED_LOCALLY, package),
                served.contains(&package),
                "{label}: {package} served from the local cache:\n{stderr}"
            );
        }
    }
}

/// A layer off refuses the lookups of its source kind even though another run
/// stored the entries.
#[test]
fn a_layer_off_does_not_serve_entries_another_run_stored() {
    let git = GitProject::new();
    let cache = tempfile::tempdir().expect("cache");
    let first = git.project("first", "");
    git.build(&first, cache.path(), &[], "fill build");
    assert_eq!(
        packages(&stored_entries(&cache.path().join("state-v3.sqlite3"))),
        ["proc_macro2", "quote", "unicode_ident"]
    );

    let second = git.project("second", "");
    let no_git = git.build(
        &second,
        cache.path(),
        &[NO_GIT],
        "build without the git layer",
    );
    let stderr = stderr_of(&no_git.output);
    assert!(
        !logged(&stderr, SERVED_LOCALLY, "unicode_ident"),
        "the git unit was served with the git layer off:\n{stderr}"
    );
    assert!(
        logged(&stderr, LAYER_OFF, "unicode_ident"),
        "the git lookup was not refused by the layer gate:\n{stderr}"
    );
}

/// A key the config does not model, such as the removed `cache_mode`, fails
/// the command instead of silently leaving every layer on.
#[test]
fn an_unknown_config_key_is_rejected() {
    let project = Project::registry("");
    project.configure("cache_mode = \"off\"\n");
    let output = stow_cli_in(
        project.dir.path(),
        &["stats", "--json"],
        project.cache.path(),
        project.cargo_home.path(),
    );
    assert!(!output.status.success(), "stats accepted `cache_mode`");
    assert!(
        stderr_of(&output).contains("unknown field `cache_mode`"),
        "the error does not name the unknown key:\n{}",
        stderr_of(&output)
    );
}

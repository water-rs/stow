//! Units the public cache cannot carry still earn the local cache, and
//! nothing about them leaves the machine (stow#1006).
//!
//! A git dependency is keyed by the commit its checkout resolves to, a
//! crates.io unit compiled under extra codegen flags by those flags. Both
//! are served to a second project from the local cache, are never looked
//! up remotely, and are never journaled as misses, and neither is a
//! crates.io unit compiled over one of them. A path dependency, a
//! workspace member and the package named by `-p` are never stored.

mod support;

// The shared fixture carries helpers this test does not call; each
// integration binary lints them per target.
#[allow(dead_code)]
mod build_fixture;

use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use build_fixture::{
    RecordedRequests, StoredEntry, cargo_fetch, commit_git_repo, copy_registry_package,
    journal_files, recording_edge, resolved_packages, rustc_host_and_release, seed_index_slice,
    stored_entries, stow_build_in_with_env, stow_setup_in,
};

/// The info event a local-cache serve emits.
const SERVED_LOCALLY: &str = "served rustc invocation from local stow artifact cache";

/// The debug event a journal skip emits for a local-only unit.
const NOT_JOURNALED: &str = "local-only unit; not journaled";

/// The two reach values `artifact_cache_entries.reach` stores.
const PUBLIC: i64 = 0;
const LOCAL_ONLY: i64 = 1;

/// How long the detached miss drain is given to show itself after a
/// build returns. A drain that has anything to admit claims the journal
/// within moments; a build with nothing to report spawns none.
const DRAIN_GRACE: Duration = Duration::from_secs(5);

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

/// The rustc spelling of a package name.
fn rustc_name(package: &str) -> String {
    package.replace('-', "_")
}

/// The entries stored for `package`, whichever spelling the store keys
/// the crate by.
fn entries_for<'a>(entries: &'a [StoredEntry], package: &str) -> Vec<&'a StoredEntry> {
    entries
        .iter()
        .filter(|entry| rustc_name(&entry.crate_name) == rustc_name(package))
        .collect()
}

/// A project in its own directory: `dependencies` and `extra` are the
/// manifest's `[dependencies]` body and any further tables, resolved now
/// so the builds under test are not also network tests.
fn write_project(dir: &Path, cargo_home: &Path, name: &str, dependencies: &str, extra: &str) {
    std::fs::create_dir_all(dir.join("src")).expect("create src");
    std::fs::write(dir.join("src").join("main.rs"), "fn main() {}\n").expect("write main.rs");
    std::fs::write(
        dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{dependencies}\n{extra}"
        ),
    )
    .expect("write manifest");
    cargo_fetch(dir, cargo_home);
    stow_setup_in(dir, cargo_home);
}

/// The shared environment of one scenario: one cache, one `CARGO_HOME`,
/// one edge that records what the builds ask the remote for.
struct Scenario {
    root: tempfile::TempDir,
    cargo_home: tempfile::TempDir,
    cache: tempfile::TempDir,
    edge_url: String,
    requests: RecordedRequests,
    /// How many builds ran, naming each one's target dir.
    builds: std::cell::Cell<usize>,
}

impl Scenario {
    fn new() -> Self {
        let (edge_url, requests) = recording_edge();
        Self {
            root: tempfile::tempdir().expect("scenario root"),
            cargo_home: tempfile::tempdir().expect("cargo home"),
            cache: tempfile::tempdir().expect("cache dir"),
            edge_url,
            requests,
            builds: std::cell::Cell::new(0),
        }
    }

    fn project_dir(&self, name: &str) -> PathBuf {
        let dir = self.root.path().join(name);
        std::fs::create_dir_all(&dir).expect("create project dir");
        dir
    }

    /// One `stow build` of `project` into a fresh target dir, returning
    /// the output and the target dir (which holds the miss journal).
    fn build(&self, project: &Path, args: &[&str], env: &[(&str, &str)]) -> (Output, PathBuf) {
        self.build_against(self.cache.path(), project, args, env)
    }

    /// [`build`] against a caller's cache directory instead of the
    /// scenario's shared one.
    fn build_against(
        &self,
        cache: &Path,
        project: &Path,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> (Output, PathBuf) {
        let build_number = self.builds.get() + 1;
        self.builds.set(build_number);
        let target = self.root.path().join(format!("target-{build_number}"));
        std::fs::create_dir_all(&target).expect("create target dir");
        let mut env = env.to_vec();
        env.push(("RUST_LOG", "stow_cli=debug"));
        let output = stow_build_in_with_env(
            project,
            args,
            &self.edge_url,
            &self.edge_url,
            cache,
            self.cargo_home.path(),
            &target,
            &env,
        );
        assert!(
            output.status.success(),
            "stow build {args:?} failed:\n{}",
            stderr_of(&output)
        );
        (output, target)
    }

    /// `project` built against a fresh cache whose index slice names
    /// every `entries` key: a remote lookup of one of those units would
    /// fetch its row's bundle, and the request line would carry the
    /// compile key — so `assert_nothing_reported` can fail on a
    /// local-only unit that reaches the remote stage, rather than on
    /// nothing ever looking remotely.
    fn remote_index_build(
        &self,
        project: &Path,
        entries: &[StoredEntry],
        env: &[(&str, &str)],
    ) -> (Output, PathBuf) {
        let cache = tempfile::tempdir().expect("remote index cache");
        let (host, release) = rustc_host_and_release();
        let resolved = resolved_packages(project, self.cargo_home.path());
        seed_index_slice(cache.path(), &host, &release, entries, &resolved);
        let mut env = env.to_vec();
        env.push(("STOW_ENABLE_SEMANTIC_FALLBACK", "1"));
        self.build_against(cache.path(), project, &["build", "--offline"], &env)
    }

    fn entries(&self) -> Vec<StoredEntry> {
        stored_entries(&self.cache.path().join("state-v3.sqlite3"))
    }

    /// Nothing about the local-only `entries` left the machine: no
    /// request carries one of their keys, and the builds that stored
    /// them (`targets`) left no miss journal or admission behind.
    fn assert_nothing_reported(&self, entries: &[StoredEntry], targets: &[&Path]) {
        std::thread::sleep(DRAIN_GRACE);
        let requests = self.requests.lock().expect("requests lock").clone();
        for entry in entries {
            for key in [&entry.compile_key, &entry.c_metadata] {
                assert!(
                    !requests
                        .iter()
                        .any(|request| request.contains(key.as_str())),
                    "a remote request carried the local-only key {key} of {}:\n{requests:#?}",
                    entry.crate_name
                );
            }
        }
        assert!(
            !requests
                .iter()
                .any(|request| request.contains("/admissions") || request.contains("/enqueue")),
            "a local-only build posted an admission:\n{requests:#?}"
        );
        for target in targets {
            assert_eq!(
                journal_files(target),
                Vec::<String>::new(),
                "a local-only build left a miss journal in {}",
                target.display()
            );
        }
    }
}

/// A `file://` git repository holding a copy of the registry's
/// `unicode-ident`, and the manifest tail that patches crates.io to it.
fn unicode_ident_git_repo(scenario: &Scenario, home: &Path) -> (PathBuf, String) {
    let repo = scenario.root.path().join("unicode-ident-repo");
    copy_registry_package(scenario.cargo_home.path(), "unicode-ident", &repo);
    let url = commit_git_repo(&repo, home);
    let patch = format!("[patch.crates-io]\nunicode-ident = {{ git = \"{url}\" }}\n");
    (repo, patch)
}

/// Commit a change to the repository's library so it resolves to a new
/// commit.
fn commit_change(repo: &Path, home: &Path) {
    let lib = repo.join("src").join("lib.rs");
    let mut source = std::fs::read_to_string(&lib).expect("read lib.rs");
    source.push_str("\n// a second commit\n");
    std::fs::write(&lib, source).expect("write lib.rs");
    for args in [
        &["add", "--all"][..],
        &[
            "-c",
            "user.name=stow-test",
            "-c",
            "user.email=stow-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--message=second",
        ],
    ] {
        let mut git = std::process::Command::new("git");
        git.args(args).current_dir(repo);
        support::sealed_home_env(&mut git, home);
        let output = git.output().expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

/// A consumer the cache has not seen, compiled over the served git
/// unit, is local-only too: serving a local-only entry must not launder
/// its reach into the consumers' bookkeeping. Returns the build's target
/// dir.
fn assert_featured_consumers_local_only(scenario: &Scenario, patch: &str) -> PathBuf {
    let featured = scenario.project_dir("featured");
    write_project(
        &featured,
        scenario.cargo_home.path(),
        "featured",
        "quote = \"1\"\nproc-macro2 = { version = \"1\", features = [\"span-locations\"] }",
        patch,
    );
    let (build, target) = scenario.build(&featured, &["build", "--offline"], &[]);
    let stderr = stderr_of(&build);
    assert!(
        logged(&stderr, SERVED_LOCALLY, "unicode_ident"),
        "the git unit was not served to the featured project:\n{stderr}"
    );
    for package in ["proc_macro2", "quote"] {
        assert!(
            logged(&stderr, NOT_JOURNALED, package),
            "{package} compiled over a served git unit was journaled:\n{stderr}"
        );
    }
    target
}

/// A git dependency (`[patch.crates-io]` to a `file://` repository) is
/// stored local-only, served to a second project at the same commit and
/// missed at another; the crates.io `proc-macro2`/`quote` compiled over
/// it follow it, and none of it is looked up remotely or journaled.
#[test]
fn a_git_unit_and_its_crates_io_consumers_are_local_only() {
    let scenario = Scenario::new();
    let home = scenario.root.path().join("git-home");
    std::fs::create_dir_all(&home).expect("create git home");

    // The registry copy of `unicode-ident` must be extracted before the
    // repository can be made from it.
    let first = scenario.project_dir("first");
    write_project(
        &first,
        scenario.cargo_home.path(),
        "first",
        "quote = \"1\"",
        "",
    );
    let (repo, patch) = unicode_ident_git_repo(&scenario, &home);
    write_project(
        &first,
        scenario.cargo_home.path(),
        "first",
        "quote = \"1\"",
        &patch,
    );

    let (first_build, first_target) = scenario.build(&first, &["build", "--offline"], &[]);
    let first_stderr = stderr_of(&first_build);
    let stored = scenario.entries();
    for package in ["unicode-ident", "proc-macro2", "quote"] {
        let rows = entries_for(&stored, package);
        assert_eq!(rows.len(), 1, "{package} was not stored once: {stored:#?}");
        assert_eq!(
            rows[0].reach, LOCAL_ONLY,
            "{package} over a git unit must be local-only"
        );
    }
    assert!(
        logged(&first_stderr, NOT_JOURNALED, "quote"),
        "the crates.io consumer of a git unit was journaled:\n{first_stderr}"
    );

    // A second project at the same commit is served all three.
    let second = scenario.project_dir("second");
    write_project(
        &second,
        scenario.cargo_home.path(),
        "second",
        "quote = \"1\"",
        &patch,
    );
    let (second_build, second_target) = scenario.build(&second, &["build", "--offline"], &[]);
    let second_stderr = stderr_of(&second_build);
    for package in ["unicode_ident", "proc_macro2", "quote"] {
        assert!(
            logged(&second_stderr, SERVED_LOCALLY, package),
            "{package} was not served from the local cache at the same commit:\n{second_stderr}"
        );
    }
    assert_eq!(
        scenario.entries().len(),
        stored.len(),
        "the served build stored entries of its own"
    );

    let featured_target = assert_featured_consumers_local_only(&scenario, &patch);

    // A different commit is a different identity: a miss that stores a
    // second `unicode-ident` entry.
    commit_change(&repo, &home);
    let third = scenario.project_dir("third");
    write_project(
        &third,
        scenario.cargo_home.path(),
        "third",
        "quote = \"1\"",
        &patch,
    );
    let (third_build, third_target) = scenario.build(&third, &["build", "--offline"], &[]);
    let third_stderr = stderr_of(&third_build);
    assert!(
        !logged(&third_stderr, SERVED_LOCALLY, "unicode_ident"),
        "a different commit was served the first commit's entry:\n{third_stderr}"
    );
    let after = scenario.entries();
    let keys = entries_for(&after, "unicode-ident")
        .into_iter()
        .map(|entry| entry.compile_key.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(keys.len(), 2, "two commits share one key: {after:#?}");

    assert!(
        after.iter().all(|entry| entry.reach == LOCAL_ONLY),
        "an entry over a git unit is public: {after:#?}"
    );

    // A remote index that names the stored keys: a local-only unit
    // reaching the remote stage would fetch its row's bundle, and the
    // request line would carry the compile key.
    let (_remote, remote_target) = scenario.remote_index_build(&second, &after, &[]);
    scenario.assert_nothing_reported(
        &after,
        &[
            first_target.as_path(),
            second_target.as_path(),
            featured_target.as_path(),
            third_target.as_path(),
            remote_target.as_path(),
        ],
    );
}

/// A crates.io unit compiled under `RUSTFLAGS="-C target-cpu=<named>"`
/// is stored under a key apart from the stock one, served to a second
/// project under the same flags, and never looked up remotely or
/// journaled. The stock build of the same crates keeps its own entries.
#[test]
fn a_crates_io_unit_under_extra_codegen_is_local_only() {
    let scenario = Scenario::new();
    let dependencies = "cfg-if = \"1\"\nmemchr = \"2\"";
    let flags = [("RUSTFLAGS", "-C target-cpu=generic")];

    let first = scenario.project_dir("first");
    write_project(
        &first,
        scenario.cargo_home.path(),
        "first",
        dependencies,
        "",
    );
    let (first_build, first_target) = scenario.build(&first, &["build", "--offline"], &flags);
    let first_stderr = stderr_of(&first_build);
    let stored = scenario.entries();
    for package in ["cfg-if", "memchr"] {
        let rows = entries_for(&stored, package);
        assert_eq!(rows.len(), 1, "{package} was not stored once: {stored:#?}");
        assert_eq!(rows[0].reach, LOCAL_ONLY, "{package} under flags is public");
        assert!(
            logged(&first_stderr, NOT_JOURNALED, &rustc_name(package)),
            "{package} under extra flags was journaled:\n{first_stderr}"
        );
    }

    let second = scenario.project_dir("second");
    write_project(
        &second,
        scenario.cargo_home.path(),
        "second",
        dependencies,
        "",
    );
    let (second_build, second_target) = scenario.build(&second, &["build", "--offline"], &flags);
    let second_stderr = stderr_of(&second_build);
    for package in ["cfg_if", "memchr"] {
        assert!(
            logged(&second_stderr, SERVED_LOCALLY, package),
            "{package} was not served to the second project:\n{second_stderr}"
        );
    }
    assert_eq!(
        scenario.entries().len(),
        stored.len(),
        "the served build stored entries of its own"
    );

    scenario.assert_nothing_reported(&stored, &[first_target.as_path(), second_target.as_path()]);

    // The stock build keys apart: a second, public entry per crate.
    scenario.build(&first, &["build", "--offline"], &[]);
    let both = scenario.entries();
    for package in ["cfg-if", "memchr"] {
        let rows = entries_for(&both, package);
        assert_eq!(rows.len(), 2, "{package} did not key apart: {both:#?}");
        assert_ne!(rows[0].compile_key, rows[1].compile_key);
        assert!(
            rows.iter().any(|row| row.reach == PUBLIC)
                && rows.iter().any(|row| row.reach == LOCAL_ONLY),
            "{package} lost a reach: {both:#?}"
        );
    }
}

/// A path dependency, a workspace member and the package `-p` names (the
/// primary package of its build) are never stored.
#[test]
fn path_members_and_primary_packages_are_never_stored() {
    let mut scenario = Scenario::new();
    let project = scenario.project_dir("probe");
    let outside = scenario.project_dir("pathdep");
    std::fs::create_dir_all(outside.join("src")).expect("create src");
    std::fs::write(
        outside.join("Cargo.toml"),
        "[package]\nname = \"pathdep\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write manifest");
    std::fs::write(outside.join("src").join("lib.rs"), "pub fn leaf() {}\n").expect("write lib");
    let member = project.join("member");
    std::fs::create_dir_all(member.join("src")).expect("create src");
    std::fs::write(
        member.join("Cargo.toml"),
        "[package]\nname = \"member\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write manifest");
    std::fs::write(member.join("src").join("lib.rs"), "pub fn leaf() {}\n").expect("write lib");
    write_project(
        &project,
        scenario.cargo_home.path(),
        "probe",
        "cfg-if = \"1\"\nmember = { path = \"member\" }\npathdep = { path = \"../pathdep\" }",
        "[workspace]\nmembers = [\"member\"]\n",
    );

    scenario.build(&project, &["build", "--offline", "--workspace"], &[]);
    let stored = scenario.entries();
    let names = stored
        .iter()
        .map(|entry| rustc_name(&entry.crate_name))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        names,
        std::collections::BTreeSet::from(["cfg_if".to_owned()]),
        "only the registry dependency may be stored: {stored:#?}"
    );

    // `-p cfg-if` makes the registry package the build's primary
    // package: a fresh cache holds nothing afterwards.
    scenario.cache = tempfile::tempdir().expect("fresh cache dir");
    scenario.build(&project, &["build", "--offline", "-p", "cfg-if"], &[]);
    assert_eq!(
        scenario.entries(),
        Vec::<StoredEntry>::new(),
        "the primary package was stored"
    );
}

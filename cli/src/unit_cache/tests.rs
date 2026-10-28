use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use super::{
    DigestMemo, InvocationEnv, Keying, Toolchain, UnitInputs, UnitPlan, build_script_inputs,
    invocation_key, out_dir_reaches_output, parse_dep_info, prepare_store, refusal, unit_key,
};
use crate::rustc_args::ParsedRustcArgs;

const TARGET: &str = "x86_64-unknown-linux-gnu";
const LIB_RS: &str = "pub const FLAVOR: Option<&str> = option_env!(\"FLAVOR\");\n";

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn write(path: &Path, contents: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
    std::fs::write(path, contents).expect("write file");
}

fn set_mtime(path: &Path, time: SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .expect("open for mtime")
        .set_modified(time)
        .expect("set mtime");
}

/// One checkout of a workspace whose member `mylib` depends on `dep`: the
/// sources, the dependency's rmeta, a toolchain, and the argv and
/// environment cargo hands rustc for `mylib` there.
struct Checkout {
    _dir: tempfile::TempDir,
    root: PathBuf,
    sysroot: PathBuf,
    extra_args: Vec<String>,
    crate_type: &'static str,
    out_dir: Option<String>,
}

impl Checkout {
    fn new(lib_rs: &str, dep_rmeta: &[u8]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("ws");
        write(&root.join("mylib/src/lib.rs"), lib_rs);
        write(&root.join("target/deps/libdep-1.rmeta"), dep_rmeta);
        let sysroot = dir.path().join("sysroot");
        write(&sysroot.join("bin/rustc"), b"rustc");
        write(&sysroot.join("lib/librustc_driver-1.so"), b"driver");
        write(
            &sysroot.join(format!("lib/rustlib/{TARGET}/lib/libstd-1.rlib")),
            b"std",
        );
        Self {
            _dir: dir,
            root,
            sysroot,
            extra_args: Vec::new(),
            crate_type: "lib",
            out_dir: None,
        }
    }

    fn args(&self) -> Vec<OsString> {
        let root = self.root.display();
        let mut args = vec![
            "--crate-name".to_owned(),
            "mylib".to_owned(),
            "--edition=2021".to_owned(),
            "mylib/src/lib.rs".to_owned(),
            "--crate-type".to_owned(),
            self.crate_type.to_owned(),
            "--emit=dep-info,metadata,link".to_owned(),
            "-C".to_owned(),
            "metadata=0123abcd".to_owned(),
            "-C".to_owned(),
            "extra-filename=-0123abcd".to_owned(),
            "--out-dir".to_owned(),
            self.out_dir
                .clone()
                .unwrap_or_else(|| format!("{root}/target/deps")),
            "--target".to_owned(),
            TARGET.to_owned(),
            "-L".to_owned(),
            format!("dependency={root}/target/deps"),
            "--extern".to_owned(),
            format!("dep={root}/target/deps/libdep-1.rmeta"),
            format!("--remap-path-prefix={root}=stow-ci://workspace"),
        ];
        args.extend(self.extra_args.iter().cloned());
        args.into_iter().map(OsString::from).collect()
    }

    fn env(&self, extra: &[(&str, &str)]) -> InvocationEnv {
        let mut vars = BTreeMap::new();
        vars.insert(
            OsString::from("CARGO_MANIFEST_DIR"),
            OsString::from(self.root.join("mylib")),
        );
        vars.insert(OsString::from("CARGO_PKG_NAME"), OsString::from("mylib"));
        // Cargo's own configuration reaches rustc only through argv.
        vars.insert(
            OsString::from("CARGO_TARGET_DIR"),
            OsString::from(self.root.join("target")),
        );
        for (name, value) in extra {
            vars.insert(OsString::from(name), OsString::from(value));
        }
        InvocationEnv {
            cwd: self.root.clone(),
            vars,
        }
    }

    fn toolchain(&self) -> Toolchain {
        Toolchain {
            verbose_version: "rustc 1.91.1 (ed61e7d7e 2025-11-07)".to_owned(),
            sysroot: self.sysroot.clone(),
        }
    }

    fn parsed(&self) -> ParsedRustcArgs {
        ParsedRustcArgs::parse(&self.args()).expect("parse argv")
    }

    fn try_invocation_key(&self, env: &InvocationEnv) -> Result<String, String> {
        let args = self.args();
        let parsed = self.parsed();
        assert_eq!(refusal(&parsed, &args), None);
        invocation_key(
            &args,
            &parsed,
            env,
            &self.toolchain(),
            TARGET,
            &DigestMemo::default(),
        )
    }

    fn invocation_key(&self, env: &InvocationEnv) -> String {
        self.try_invocation_key(env)
            .unwrap_or_else(|reason| panic!("uncacheable: {reason}"))
    }

    fn unit_key_over(&self, env: &InvocationEnv, files: &[&str], env_deps: &[&str]) -> String {
        let inputs = UnitInputs {
            files: files.iter().map(|file| (*file).to_owned()).collect(),
            env: env_deps.iter().map(|name| (*name).to_owned()).collect(),
        };
        let memo = DigestMemo::default();
        let build_script = build_script_inputs(env, &memo)
            .unwrap_or_else(|(path, error)| panic!("unreadable {}: {error}", path.display()));
        unit_key(
            &self.invocation_key(env),
            &inputs,
            env,
            build_script.as_ref(),
            &memo,
        )
        .unwrap_or_else(|(path, error)| panic!("unreadable {}: {error}", path.display()))
        .key
    }

    fn unit_key(&self, env: &InvocationEnv, env_deps: &[&str]) -> String {
        self.unit_key_over(env, &["mylib/src/lib.rs"], env_deps)
    }

    fn plan(&self, started: SystemTime) -> UnitPlan {
        let env = self.env(&[]);
        UnitPlan {
            invocation_key: self.invocation_key(&env),
            target: TARGET.to_owned(),
            rustc_version: "1.91.1".to_owned(),
            env,
            started,
        }
    }

    /// What a compile of `mylib` leaves in `--out-dir`, stamped `written`.
    fn write_outputs(&self, written: SystemTime) {
        let deps = self.root.join("target/deps");
        let dep_info = format!(
            "{d}/libmylib-0123abcd.rmeta: mylib/src/lib.rs\n{d}/mylib-0123abcd.d: mylib/src/lib.rs\n\nmylib/src/lib.rs:\n",
            d = deps.display()
        );
        for (name, contents) in [
            ("mylib-0123abcd.d", dep_info.into_bytes()),
            ("libmylib-0123abcd.rmeta", b"rmeta".to_vec()),
            ("libmylib-0123abcd.rlib", b"rlib".to_vec()),
        ] {
            let path = deps.join(name);
            write(&path, contents);
            set_mtime(&path, written);
        }
    }
}

#[test]
fn an_edited_source_file_changes_the_key() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    let before = checkout.unit_key(&checkout.env(&[]), &["FLAVOR"]);
    write(
        &checkout.root.join("mylib/src/lib.rs"),
        "pub const FLAVOR: Option<&str> = None;\n",
    );
    assert_ne!(before, checkout.unit_key(&checkout.env(&[]), &["FLAVOR"]));
}

#[test]
fn an_env_read_variable_change_changes_the_key() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    let unset = checkout.unit_key(&checkout.env(&[]), &["FLAVOR"]);
    let set = checkout.unit_key(&checkout.env(&[("FLAVOR", "a")]), &["FLAVOR"]);
    let other = checkout.unit_key(&checkout.env(&[("FLAVOR", "b")]), &["FLAVOR"]);
    assert_ne!(unset, set);
    assert_ne!(set, other);
}

#[test]
fn a_rebuilt_dependency_changes_the_invocation_key() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    let before = checkout.invocation_key(&checkout.env(&[]));
    write(&checkout.root.join("target/deps/libdep-1.rmeta"), b"other");
    assert_ne!(before, checkout.invocation_key(&checkout.env(&[])));
}

/// stow#978 review 1.1: a proc macro reads `CARGO_MANIFEST_DIR` through
/// `std::env` and embeds it unremapped, so two checkouts never share a
/// key however the argv remaps them.
#[test]
fn checkouts_in_two_directories_never_share_a_key() {
    let first = Checkout::new(LIB_RS, b"rmeta");
    let second = Checkout::new(LIB_RS, b"rmeta");
    assert_ne!(first.root, second.root);
    assert_ne!(
        first.invocation_key(&first.env(&[])),
        second.invocation_key(&second.env(&[]))
    );
    // The manifest directory alone, the one path every proc macro sees.
    let moved = first.env(&[("CARGO_MANIFEST_DIR", "/elsewhere/mylib")]);
    assert_ne!(
        first.invocation_key(&first.env(&[])),
        first.invocation_key(&moved)
    );
}

/// stow#978 review 1.2: two remap rules sharing a `TO` once collapsed
/// their files into one spelling, and the key hashed the other rule's
/// file. Every input is now keyed under its own path.
#[test]
fn remap_rules_sharing_a_target_key_each_file_by_its_own_path() {
    let mut checkout = Checkout::new(LIB_RS, b"rmeta");
    let registry = checkout.root.join("home/registry");
    let git = checkout.root.join("home/git");
    write(&registry.join("foo/src/lib.rs"), "registry");
    write(&git.join("foo/src/lib.rs"), "git");
    checkout.extra_args = vec![
        format!("--remap-path-prefix={}=/deps", registry.display()),
        format!("--remap-path-prefix={}=/deps", git.display()),
    ];
    let git_input = git.join("foo/src/lib.rs");
    let git_input = git_input.to_str().expect("utf-8");
    let env = checkout.env(&[]);
    let before = checkout.unit_key_over(&env, &["mylib/src/lib.rs", git_input], &[]);
    write(&registry.join("foo/src/lib.rs"), "registry, edited");
    assert_eq!(
        before,
        checkout.unit_key_over(&env, &["mylib/src/lib.rs", git_input], &[]),
        "a file the compile did not read is not an input"
    );
    write(&git.join("foo/src/lib.rs"), "git, edited");
    assert_ne!(
        before,
        checkout.unit_key_over(&env, &["mylib/src/lib.rs", git_input], &[]),
        "an edit to the file the compile read must miss"
    );
}

/// stow#978 review 1.3: rustc bundles a `#[link(kind = "static")]`
/// library it finds on the native search path into the rlib, though no
/// `-l` names it.
#[test]
fn a_bundled_native_library_is_keyed_by_contents() {
    let mut checkout = Checkout::new(LIB_RS, b"rmeta");
    let out = checkout.root.join("target/build/foo-sys-1/out");
    write(&out.join("libfoo.a"), b"objects v1");
    write(&out.join("libfoo.so"), b"shared v1");
    checkout.extra_args = vec!["-L".to_owned(), format!("native={}", out.display())];
    let env = checkout.env(&[]);
    let before = checkout.invocation_key(&env);
    write(&out.join("libfoo.so"), b"shared v2");
    assert_eq!(
        before,
        checkout.invocation_key(&env),
        "producing an rlib never reads a dynamic library"
    );
    write(&out.join("libfoo.a"), b"objects v2");
    assert_ne!(before, checkout.invocation_key(&env));
}

/// stow#978 review 1.3: a staticlib archives the objects of its whole
/// dependency closure; a rebuilt transitive `-sys` rlib leaves the direct
/// externs untouched.
#[test]
fn a_staticlib_keys_every_rlib_on_its_crate_search_path() {
    let mut checkout = Checkout::new(LIB_RS, b"rmeta");
    let transitive = checkout.root.join("target/deps/libzstd_sys-9.rlib");
    write(&transitive, b"objects v1");
    let env = checkout.env(&[]);
    let rlib_before = checkout.invocation_key(&env);
    checkout.crate_type = "staticlib";
    let staticlib_before = checkout.invocation_key(&env);
    write(&transitive, b"objects v2");
    assert_ne!(staticlib_before, checkout.invocation_key(&env));
    checkout.crate_type = "lib";
    assert_eq!(
        rlib_before,
        checkout.invocation_key(&env),
        "an rlib reads transitive rmeta, which its externs' contents pin"
    );
}

/// stow#978 review 1.3: linking reads files no key here sees.
#[test]
fn linked_crate_types_are_refused() {
    for crate_type in ["proc-macro", "dylib", "bin", "cdylib"] {
        let mut checkout = Checkout::new(LIB_RS, b"rmeta");
        checkout.crate_type = crate_type;
        let reason = refusal(&checkout.parsed(), &checkout.args());
        assert!(
            reason
                .as_deref()
                .is_some_and(|reason| reason.contains(crate_type)),
            "{crate_type}: {reason:?}"
        );
    }
}

/// stow#978 review 1.7: two toolchains with one `rustc -vV` differ in
/// their sysroot's files.
#[test]
fn a_rewritten_sysroot_file_changes_the_key() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    let env = checkout.env(&[]);
    let before = checkout.invocation_key(&env);
    write(
        &checkout
            .sysroot
            .join(format!("lib/rustlib/{TARGET}/lib/libstd-1.rlib")),
        b"another std",
    );
    let after_std = checkout.invocation_key(&env);
    assert_ne!(before, after_std);
    write(
        &checkout.sysroot.join("lib/librustc_driver-1.so"),
        b"another driver",
    );
    assert_ne!(after_std, checkout.invocation_key(&env));
}

/// stow#978 review 1.5: a bare `--target` name can resolve to a spec file
/// on `RUST_TARGET_PATH`.
#[test]
fn a_target_spec_on_rust_target_path_is_not_keyed() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    let specs = checkout.root.join("specs");
    let path = specs.to_str().expect("utf-8").to_owned();
    let env = checkout.env(&[("RUST_TARGET_PATH", &path)]);
    assert!(checkout.try_invocation_key(&env).is_ok());
    write(&specs.join(format!("{TARGET}.json")), "{}");
    assert!(
        checkout
            .try_invocation_key(&env)
            .is_err_and(|reason| reason.contains("RUST_TARGET_PATH"))
    );
}

/// stow#978 review 2.1: rustc exits 0 without writing outputs for a
/// `--print` request or `-Zunpretty`, leaving an earlier compile's files.
#[test]
fn invocations_that_write_no_outputs_are_refused() {
    for extra in [
        &["--print", "cfg"][..],
        &["--print=cfg"],
        &["-Zunpretty=expanded"],
        &["-Z", "unpretty=expanded"],
        &["-Zls=root"],
        &["-Zprint-type-sizes"],
        &["-Zno-codegen"],
        &["--codegen", "profile-use=/p.profdata"],
        &["--codegen=incremental=/t/incremental"],
        &["-C", "incremental=/t/incremental"],
    ] {
        let mut checkout = Checkout::new(LIB_RS, b"rmeta");
        checkout.extra_args = extra.iter().map(|arg| (*arg).to_owned()).collect();
        assert!(
            refusal(&checkout.parsed(), &checkout.args()).is_some(),
            "{extra:?} must be refused"
        );
    }
    let mut checkout = Checkout::new(LIB_RS, b"rmeta");
    checkout.extra_args = vec!["--print=native-static-libs".to_owned()];
    assert_eq!(refusal(&checkout.parsed(), &checkout.args()), None);
}

/// stow#978 review 2.1: an output older than the compile is an earlier
/// compile's, and storing it is a failure, not a skip.
#[test]
fn stale_dep_info_or_outputs_fail_the_store() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    let hour_ago = SystemTime::now() - Duration::from_secs(3600);
    checkout.write_outputs(hour_ago);
    let plan = checkout.plan(SystemTime::now());
    let error = prepare_store(
        &checkout.parsed(),
        &plan,
        "aarch64-apple-darwin",
        &DigestMemo::default(),
    )
    .expect_err("a stale dep-info must fail the store");
    assert!(
        error.to_string().contains("predates the compile"),
        "{error}"
    );

    // Fresh dep-info beside a stale rlib.
    let deps = checkout.root.join("target/deps");
    set_mtime(&deps.join("mylib-0123abcd.d"), SystemTime::now());
    set_mtime(&deps.join("libmylib-0123abcd.rmeta"), SystemTime::now());
    let error = prepare_store(
        &checkout.parsed(),
        &plan,
        "aarch64-apple-darwin",
        &DigestMemo::default(),
    )
    .expect_err("a stale rlib must fail the store");
    assert!(
        error.to_string().contains("libmylib-0123abcd.rlib"),
        "{error}"
    );
}

/// stow#978 review 2.2: a write during the compile that restores an old
/// mtime — `cp -p`, `rsync -t`, `tar x` — still moves the change time.
#[test]
fn an_input_rewritten_during_the_compile_with_an_old_mtime_is_not_stored() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    // The compile starts a second from now, after the sources were written.
    let started = SystemTime::now() + Duration::from_secs(1);
    checkout.write_outputs(started + Duration::from_secs(1));
    let plan = checkout.plan(started);
    let stored = prepare_store(
        &checkout.parsed(),
        &plan,
        "aarch64-apple-darwin",
        &DigestMemo::default(),
    )
    .expect("prepare store");
    assert!(matches!(stored, Keying::Keyed(_)), "{stored:?}");

    let plan = checkout.plan(SystemTime::now());
    let input = checkout.root.join("mylib/src/lib.rs");
    write(&input, "pub const FLAVOR: Option<&str> = None;\n");
    set_mtime(&input, SystemTime::now() - Duration::from_secs(3600));
    let stored = prepare_store(
        &checkout.parsed(),
        &plan,
        "aarch64-apple-darwin",
        &DigestMemo::default(),
    )
    .expect("prepare store");
    assert!(
        matches!(&stored, Keying::Uncacheable(reason) if reason.contains("changed while rustc ran")),
        "{stored:?}"
    );
}

/// stow#978 review 1.4: rustc's module search reads candidates dep-info
/// never lists — `foo/mod.rs` beside `foo.rs` fails with E0761.
#[test]
fn a_competing_module_file_changes_the_unit_key() {
    let checkout = Checkout::new("mod foo;\n", b"rmeta");
    write(&checkout.root.join("mylib/src/foo.rs"), "");
    let env = checkout.env(&[]);
    let files = ["mylib/src/foo.rs", "mylib/src/lib.rs"];
    let before = checkout.unit_key_over(&env, &files, &[]);
    for junk in [".foo.rs.swp", "foo.rs~", "notes.txt"] {
        write(&checkout.root.join("mylib/src").join(junk), "");
    }
    assert_eq!(
        before,
        checkout.unit_key_over(&env, &files, &[]),
        "no module search finds an editor's files"
    );
    write(&checkout.root.join("mylib/src/foo/README"), "");
    let with_dir = checkout.unit_key_over(&env, &files, &[]);
    assert_ne!(before, with_dir);
    write(&checkout.root.join("mylib/src/foo/mod.rs"), "");
    assert_ne!(with_dir, checkout.unit_key_over(&env, &files, &[]));
}

/// stow#978 P1 option 2: a package with a build script declares the
/// inputs its script and proc macros read; an edit to a
/// `cargo:rerun-if-changed` file is a miss.
#[test]
fn a_rerun_if_changed_file_is_keyed_by_contents() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    let build = checkout.root.join("target/build/mylib-1");
    let out_dir = build.join("out");
    write(
        &build.join("output"),
        "cargo:rustc-link-search=native=lib\n\
         cargo:rerun-if-changed=data/input.txt\n\
         cargo:warning=compiled fine\n",
    );
    write(&checkout.root.join("mylib/data/input.txt"), "v1");
    let env = checkout.env(&[("OUT_DIR", out_dir.to_str().expect("utf-8"))]);
    let before = checkout.unit_key(&env, &[]);
    write(&checkout.root.join("mylib/data/input.txt"), "v2");
    assert_ne!(before, checkout.unit_key(&env, &[]));
}

/// stow#978 P1 option 2, the sqlx shape: `rerun-if-changed=migrations`
/// watches a directory, and a file added under it is a miss though no
/// dep-info lists it.
#[test]
fn a_new_file_in_a_rerun_if_changed_directory_changes_the_key() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    let build = checkout.root.join("target/build/mylib-1");
    let out_dir = build.join("out");
    write(
        &build.join("output"),
        "cargo::rerun-if-changed=migrations\n",
    );
    write(
        &checkout.root.join("mylib/migrations/0001_init.sql"),
        "create table t(x int);\n",
    );
    let env = checkout.env(&[("OUT_DIR", out_dir.to_str().expect("utf-8"))]);
    let before = checkout.unit_key(&env, &[]);
    write(
        &checkout.root.join("mylib/migrations/0002_more.sql"),
        "alter table t add column y int;\n",
    );
    assert_ne!(before, checkout.unit_key(&env, &[]));
}

/// stow#978 P1 option 2: a `cargo:rerun-if-env-changed` variable's value
/// in the unit's environment is keyed, set or unset.
#[test]
fn a_rerun_if_env_changed_variable_changes_the_key() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    let build = checkout.root.join("target/build/mylib-1");
    let out_dir = build.join("out");
    write(
        &build.join("output"),
        "cargo:rerun-if-env-changed=DATABASE_URL\n",
    );
    let out_dir = out_dir.to_str().expect("utf-8");
    let unset = checkout.unit_key(&checkout.env(&[("OUT_DIR", out_dir)]), &[]);
    let sqlite = checkout.unit_key(
        &checkout.env(&[("OUT_DIR", out_dir), ("DATABASE_URL", "sqlite://a.db")]),
        &[],
    );
    let postgres = checkout.unit_key(
        &checkout.env(&[("OUT_DIR", out_dir), ("DATABASE_URL", "postgres://h/db")]),
        &[],
    );
    assert_ne!(unset, sqlite);
    assert_ne!(sqlite, postgres);
}

/// stow#978 P1 option 2: `OUT_DIR` set means the package's build script
/// ran, and cargo always writes its `output` beside it — a missing one
/// fails the invocation, it is not an absent input.
#[test]
fn a_missing_build_script_output_is_an_error() {
    let checkout = Checkout::new(LIB_RS, b"rmeta");
    let out_dir = checkout.root.join("target/build/mylib-1/out");
    let env = checkout.env(&[("OUT_DIR", out_dir.to_str().expect("utf-8"))]);
    let (path, error) = build_script_inputs(&env, &DigestMemo::default())
        .expect_err("a missing output file must not be skipped");
    assert!(path.ends_with("output"));
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

/// stow#978 review 3.1, as measured: debuginfo on an MSVC target, and
/// split DWARF on an ELF one, record `--out-dir` in the artifact; an Apple
/// target's never does.
#[test]
fn out_dir_is_keyed_exactly_when_the_artifact_embeds_it() {
    let reaches = |target: &str, args: &[&str]| out_dir_reaches_output(&os(args), target);
    assert!(!reaches(TARGET, &[]));
    assert!(!reaches(TARGET, &["-C", "debuginfo=2"]));
    assert!(reaches(
        TARGET,
        &["-C", "debuginfo=2", "-C", "split-debuginfo=unpacked"]
    ));
    assert!(reaches(TARGET, &["-g", "-Csplit-debuginfo=packed"]));
    assert!(!reaches(
        TARGET,
        &["-g", "-C", "debuginfo=0", "-C", "split-debuginfo=unpacked"]
    ));
    assert!(!reaches(
        "aarch64-apple-darwin",
        &["-g", "-C", "split-debuginfo=unpacked"]
    ));
    assert!(reaches("x86_64-pc-windows-msvc", &["-C", "debuginfo=2"]));
    assert!(reaches(
        "x86_64-unknown-uefi",
        &["-C", "debuginfo=line-tables-only"]
    ));

    let mut checkout = Checkout::new(LIB_RS, b"rmeta");
    checkout.extra_args = vec!["-g".to_owned(), "-Csplit-debuginfo=unpacked".to_owned()];
    let env = checkout.env(&[]);
    let keyed = checkout.invocation_key(&env);
    checkout.out_dir = Some(format!("{}/other", checkout.root.display()));
    assert_ne!(keyed, checkout.invocation_key(&env));
    checkout.extra_args.clear();
    let unkeyed = checkout.invocation_key(&env);
    checkout.out_dir = None;
    assert_eq!(unkeyed, checkout.invocation_key(&env));
}

#[test]
fn dep_info_lists_files_and_env_deps() {
    let text = "/t/deps/libmylib-1.rmeta: mylib/src/lib.rs /w/with\\ space.rs\n\
                /t/deps/mylib-1.d: mylib/src/lib.rs /w/with\\ space.rs\n\n\
                mylib/src/lib.rs:\n/w/with\\ space.rs:\n\n\
                # env-dep:FLAVOR=a\n# env-dep:UNSET\n";
    let dep_info = parse_dep_info(text).expect("parse");
    assert_eq!(dep_info.files, vec!["mylib/src/lib.rs", "/w/with space.rs"]);
    assert_eq!(dep_info.env_names(), vec!["FLAVOR", "UNSET"]);
    assert!(parse_dep_info("# checksum:blake3=00 file_len:1 a.rs\n").is_err());
}

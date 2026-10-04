//! Offline resolves: a `local-registry` directory stands in for
//! crates.io, a local git dir for a git host. Covers the
//! dropped-lockfile semantics (yanked admission, git-pin locking, pin
//! never preferred over a newer non-yanked release) and the host/target
//! unit split.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use stow_resolver::{ResolveOptions, Resolver, StowSide, StowUnit};
use stow_types::identity::WireRustcVersion;

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// One fixture crate in the local registry.
struct Fixture {
    name: &'static str,
    version: &'static str,
    /// `(name, req, features)` registry deps.
    deps: Vec<(&'static str, &'static str, &'static [&'static str])>,
    features: &'static [(&'static str, &'static [&'static str])],
    yanked: bool,
    proc_macro: bool,
}

/// `value` serialized as a TOML document.
fn toml_document(value: &Value) -> String {
    toml::to_string(value).unwrap()
}

/// Pack `fixture` into `{reg}/{name}-{version}.crate` and append its
/// index line, returning the sha256 the index records.
fn publish(reg: &Path, fixture: &Fixture) -> String {
    let features: serde_json::Map<String, Value> = fixture
        .features
        .iter()
        .map(|(name, members)| ((*name).to_owned(), json!(members)))
        .collect();
    let mut manifest = json!({
        "package": { "name": fixture.name, "version": fixture.version, "edition": "2021" },
        "features": features,
        "dependencies": fixture
            .deps
            .iter()
            .map(|(name, req, features)| {
                ((*name).to_owned(), json!({ "version": req, "features": features }))
            })
            .collect::<serde_json::Map<_, _>>(),
    });
    if fixture.proc_macro {
        manifest["lib"] = json!({ "proc-macro": true });
    }
    let lib = if fixture.proc_macro {
        "extern crate proc_macro;\n"
    } else {
        ""
    };

    let tarball = reg.join(format!("{}-{}.crate", fixture.name, fixture.version));
    let file = std::fs::File::create(&tarball).unwrap();
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
        file,
        flate2::Compression::fast(),
    ));
    for (path, contents) in [
        (
            format!("{}-{}/Cargo.toml", fixture.name, fixture.version),
            toml_document(&manifest),
        ),
        (
            format!("{}-{}/src/lib.rs", fixture.name, fixture.version),
            lib.to_owned(),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(contents.len()).unwrap());
        header.set_cksum();
        tar.append_data(&mut header, path, contents.as_bytes())
            .unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap();
    let cksum = format!("{:x}", Sha256::digest(std::fs::read(&tarball).unwrap()));

    let deps: Vec<Value> = fixture
        .deps
        .iter()
        .map(|(name, req, features)| {
            json!({
                "name": name,
                "req": format!("^{req}"),
                "features": features,
                "optional": false,
                "default_features": true,
                "target": null,
                "kind": "normal",
            })
        })
        .collect();
    let mut line = serde_json::to_string(&json!({
        "name": fixture.name,
        "vers": fixture.version,
        "deps": deps,
        "cksum": cksum,
        "features": features,
        "yanked": fixture.yanked,
    }))
    .unwrap();
    line.push('\n');
    // Sparse-index shard layout: 1 → `1/n`, 2 → `2/na`,
    // 3 → `3/a/abc`, else `ab/cd/name` — all lowercase.
    let lower = fixture.name.to_lowercase();
    let entry = match lower.len() {
        1 => reg.join("index/1").join(&lower),
        2 => reg.join("index/2").join(&lower),
        3 => reg.join("index/3").join(&lower[..1]).join(&lower),
        _ => reg
            .join("index")
            .join(&lower[..2])
            .join(&lower[2..4])
            .join(&lower),
    };
    std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
    let mut index = std::fs::read_to_string(&entry).unwrap_or_default();
    index.push_str(&line);
    std::fs::write(&entry, index).unwrap();
    cksum
}

/// The release the test binary's own toolchain reports — the version
/// the session is asked to pin. rustup resolves `--toolchain <release>`
/// to the dir named `<release>-<host>` under `RUSTUP_HOME`, so the env
/// var is pointed at a harness home linking that name to the real
/// toolchain: the pin works whichever channel cargo ran the tests under
/// (CI's `stable`, a maintainer's default, an explicit `+1.98.1`).
fn pinned_rustc_version() -> &'static WireRustcVersion {
    static PINNED: OnceLock<(WireRustcVersion, tempfile::TempDir)> = OnceLock::new();
    &PINNED
        .get_or_init(|| {
            let rustc = PathBuf::from(
                String::from_utf8(
                    std::process::Command::new("rustup")
                        .args(["which", "rustc"])
                        .output()
                        .expect("rustup which rustc")
                        .stdout,
                )
                .expect("rustup which output is utf8")
                .trim()
                .to_owned(),
            );
            let toolchain_dir = rustc
                .parent()
                .and_then(Path::parent)
                .expect("rustc sits in <toolchain>/bin")
                .to_path_buf();
            let verbose = String::from_utf8(
                std::process::Command::new(&rustc)
                    .arg("-vV")
                    .output()
                    .expect("rustc -vV")
                    .stdout,
            )
            .expect("rustc -vV is utf8");
            let release = verbose
                .lines()
                .find_map(|line| line.strip_prefix("release: "))
                .map(str::trim)
                .expect("rustc -vV reports a release");
            let host = verbose
                .lines()
                .find_map(|line| line.strip_prefix("host: "))
                .map(str::trim)
                .expect("rustc -vV reports a host");

            let home = tempfile::tempdir().expect("rustup home");
            let link = home
                .path()
                .join("toolchains")
                .join(format!("{release}-{host}"));
            std::fs::create_dir_all(link.parent().unwrap()).unwrap();
            link_dir(&toolchain_dir, &link);
            // SAFETY: inside `OnceLock::get_or_init` this runs exactly
            // once and strictly before the first `Resolver` exists, so
            // before any code in this process reads the environment or
            // inherits it into a spawned rustup/cargo.
            unsafe { std::env::set_var("RUSTUP_HOME", home.path()) };
            (
                WireRustcVersion::parse(release).expect("release is a wire version"),
                home,
            )
        })
        .0
}

#[cfg(unix)]
fn link_dir(toolchain_dir: &Path, link: &Path) {
    std::os::unix::fs::symlink(toolchain_dir, link).expect("link the toolchain dir");
}

/// A directory junction needs no privilege on Windows, where a symlink
/// does.
#[cfg(windows)]
fn link_dir(toolchain_dir: &Path, link: &Path) {
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(toolchain_dir)
        .status()
        .expect("mklink /J runs");
    assert!(
        status.success(),
        "mklink /J {} -> {}",
        link.display(),
        toolchain_dir.display()
    );
}

/// A resolver whose isolated `CARGO_HOME` replaces crates.io with `reg`.
fn resolver_at(reg: &Path) -> (tempfile::TempDir, Resolver) {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        toml_document(&json!({
            "source": {
                "crates-io": { "replace-with": "local" },
                "local": { "local-registry": reg },
            },
        })),
    )
    .unwrap();
    let resolver = Resolver::with_cargo_home(
        home.path().to_path_buf(),
        pinned_rustc_version(),
        PathBuf::from(env!("CARGO_BIN_EXE_stow-rustc-shim")),
    )
    .unwrap();
    (home, resolver)
}

/// Pinning a version rustup has no toolchain for fails naming the
/// install command — never probing whichever rustc is active instead.
#[test]
fn an_uninstalled_rustc_names_its_install_command() {
    let _pinned = pinned_rustc_version();
    let home = tempfile::tempdir().unwrap();
    let requested = WireRustcVersion::parse("9.99.9").expect("wire version");
    let error = Resolver::with_cargo_home(
        home.path().to_path_buf(),
        &requested,
        PathBuf::from(env!("CARGO_BIN_EXE_stow-rustc-shim")),
    )
    .expect_err("9.99.9 has no installed toolchain");
    let message = format!("{error:#}");
    assert!(
        message.contains("rustup toolchain install 9.99.9"),
        "the error names the install command: {message}"
    );
}

/// A single-member project tree on disk; returns its manifest path.
fn project(dir: &Path, dependencies: &Value) -> PathBuf {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/lib.rs"), "").unwrap();
    let manifest = dir.join("Cargo.toml");
    std::fs::write(
        &manifest,
        toml_document(&json!({
            "package": { "name": "root", "version": "0.0.0", "edition": "2021" },
            "dependencies": dependencies,
        })),
    )
    .unwrap();
    manifest
}

fn lock_entry(name: &str, version: &str, source: &str) -> Value {
    json!({ "name": name, "version": version, "source": source })
}

fn dropped_lockfile(entries: Vec<Value>, deps: &[&str]) -> String {
    let root = json!({ "name": "root", "version": "0.0.0", "dependencies": deps });
    toml_document(&json!({
        "version": 4,
        "package": std::iter::once(root).chain(entries).collect::<Vec<_>>(),
    }))
}

/// Every `name` unit in the one requested target's output.
fn units_named<'a>(
    output: &'a [(String, stow_resolver::StowResolveOutput)],
    name: &str,
) -> Vec<&'a StowUnit> {
    output
        .iter()
        .flat_map(|(_target, out)| out.units.iter())
        .filter(|unit| unit.name == name)
        .collect()
}

/// `1.0.0` is the only release and it is yanked — the dropped lockfile
/// admits it anyway.
#[test]
fn yanked_pin_is_admitted() {
    let work = tempfile::tempdir().unwrap();
    let reg = work.path().join("registry");
    std::fs::create_dir_all(&reg).unwrap();
    publish(
        &reg,
        &Fixture {
            name: "dep",
            version: "1.0.0",
            deps: vec![],
            features: &[],
            yanked: true,
            proc_macro: false,
        },
    );
    let manifest = project(&work.path().join("root"), &json!({ "dep": "1" }));
    let (_home, resolver) = resolver_at(&reg);
    let lock = dropped_lockfile(
        vec![lock_entry("dep", "1.0.0", CRATES_IO)],
        &["dep 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
    );
    let out = resolver
        .resolve(
            &manifest,
            &ResolveOptions {
                dropped_lockfile: Some(lock),
                ..ResolveOptions::default()
            },
            &["x86_64-unknown-linux-gnu".to_owned()],
        )
        .unwrap();
    assert_eq!(units_named(&out, "dep")[0].version, "1.0.0");
}

/// The pin is admission, never preference: `1.0.1` is not yanked, so it
/// wins over the locked `1.0.0`.
#[test]
fn newer_release_beats_the_pin() {
    let work = tempfile::tempdir().unwrap();
    let reg = work.path().join("registry");
    std::fs::create_dir_all(&reg).unwrap();
    for (version, yanked) in [("1.0.0", true), ("1.0.1", false)] {
        publish(
            &reg,
            &Fixture {
                name: "dep",
                version,
                deps: vec![],
                features: &[],
                yanked,
                proc_macro: false,
            },
        );
    }
    let manifest = project(&work.path().join("root"), &json!({ "dep": "1" }));
    let (_home, resolver) = resolver_at(&reg);
    let lock = dropped_lockfile(
        vec![lock_entry("dep", "1.0.0", CRATES_IO)],
        &["dep 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
    );
    let out = resolver
        .resolve(
            &manifest,
            &ResolveOptions {
                dropped_lockfile: Some(lock),
                ..ResolveOptions::default()
            },
            &["x86_64-unknown-linux-gnu".to_owned()],
        )
        .unwrap();
    assert_eq!(units_named(&out, "dep")[0].version, "1.0.1");
}

/// The crate lane drops the tarball's bundled `Cargo.lock` like every
/// other lane — the `dep` pin is admission, never preference, so the
/// resolve lands on the index's newest compatible `1.0.1`, not the
/// locked `1.0.0`. (The `.crate` package dir stands in for
/// `fetch_crate`'s unpacked tree; `resolve_package_dir` is the shared
/// post-fetch half.)
#[test]
fn crate_lane_drops_bundled_lockfile() {
    let work = tempfile::tempdir().unwrap();
    let reg = work.path().join("registry");
    std::fs::create_dir_all(&reg).unwrap();
    for version in ["1.0.0", "1.0.1"] {
        publish(
            &reg,
            &Fixture {
                name: "dep",
                version,
                deps: vec![],
                features: &[],
                yanked: false,
                proc_macro: false,
            },
        );
    }
    // An unpacked `.crate` root: manifest, sources, and the bundled
    // lockfile pinning `dep` a patch behind the index's newest.
    let package_dir = work.path().join("crate-root-0.0.0");
    project(&package_dir, &json!({ "dep": "1" }));
    std::fs::write(
        package_dir.join("Cargo.lock"),
        dropped_lockfile(
            vec![lock_entry("dep", "1.0.0", CRATES_IO)],
            &["dep 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
        ),
    )
    .unwrap();
    let (_home, resolver) = resolver_at(&reg);
    let out = resolver
        .resolve_package_dir(
            &package_dir,
            &ResolveOptions::default(),
            &["x86_64-unknown-linux-gnu".to_owned()],
        )
        .unwrap();
    // (Cargo regenerates a lockfile in the tree after resolving — the
    // bundled one's pins are what the resolve must not honor.)
    assert_eq!(units_named(&out, "dep")[0].version, "1.0.1");
}

/// A git dep resolves to the sha the dropped lockfile pinned, not the
/// branch's head.
#[test]
fn git_pin_locks_the_sha() {
    let work = tempfile::tempdir().unwrap();
    let repo = work.path().join("gitdep");
    let run = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .current_dir(&repo)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    };
    let sha_of = |rev: &str| -> String {
        let output = std::process::Command::new("git")
            .current_dir(&repo)
            .args(["rev-parse", rev])
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    std::fs::create_dir_all(repo.join("src")).unwrap();
    run(&["init"]);
    run(&["config", "user.email", "stow@test"]);
    run(&["config", "user.name", "stow"]);
    let write_manifest = |version: &str| {
        std::fs::write(
            repo.join("Cargo.toml"),
            toml_document(&json!({
                "package": { "name": "gitdep", "version": version, "edition": "2021" },
            })),
        )
        .unwrap();
        std::fs::write(repo.join("src/lib.rs"), "").unwrap();
        run(&["add", "-A"]);
        run(&["commit", "-m", version]);
    };
    write_manifest("0.1.0");
    let pinned = sha_of("HEAD");
    write_manifest("0.2.0");

    let url = url::Url::from_file_path(&repo).unwrap();
    let manifest = project(
        &work.path().join("root"),
        &json!({ "gitdep": { "git": url.as_str() } }),
    );
    let (_home, resolver) = resolver_at(&work.path().join("registry"));
    let source = format!("git+{url}#{pinned}");
    let lock = dropped_lockfile(
        vec![lock_entry("gitdep", "0.1.0", &source)],
        &[&format!("gitdep 0.1.0 ({source})")],
    );
    let out = resolver
        .resolve(
            &manifest,
            &ResolveOptions {
                dropped_lockfile: Some(lock),
                ..ResolveOptions::default()
            },
            &["x86_64-unknown-linux-gnu".to_owned()],
        )
        .unwrap();
    assert_eq!(units_named(&out, "gitdep")[0].version, "0.1.0");
}

/// `shared` is a normal dep of the root (feature `a`) and a dep of a
/// proc-macro (feature `b`): two units, one per side, each keeping its
/// own feature set.
#[test]
fn normal_and_proc_macro_sides_split() {
    let work = tempfile::tempdir().unwrap();
    let reg = work.path().join("registry");
    std::fs::create_dir_all(&reg).unwrap();
    publish(
        &reg,
        &Fixture {
            name: "shared",
            version: "1.0.0",
            deps: vec![],
            features: &[("a", &[]), ("b", &[])],
            yanked: false,
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "pm",
            version: "1.0.0",
            deps: vec![("shared", "1", &["b"])],
            features: &[],
            yanked: false,
            proc_macro: true,
        },
    );
    let manifest = project(
        &work.path().join("root"),
        &json!({ "shared": { "version": "1", "features": ["a"] }, "pm": "1" }),
    );
    let (_home, resolver) = resolver_at(&reg);
    let out = resolver
        .resolve(
            &manifest,
            &ResolveOptions::default(),
            &["aarch64-unknown-linux-gnu".to_owned()],
        )
        .unwrap();

    let mut libs: Vec<&StowUnit> = units_named(&out, "shared")
        .into_iter()
        .filter(|unit| unit.unit_kind == stow_resolver::StowUnitKind::Lib)
        .collect();
    libs.sort_by_key(|unit| unit.key.side);
    assert_eq!(libs.len(), 2, "shared emits one lib unit per side");
    let host = libs[1];
    let target = libs[0];
    assert_eq!(host.key.side, StowSide::Host);
    assert_eq!(host.key.platform, "x86_64-unknown-linux-gnu");
    assert_eq!(host.features, ["b"]);
    assert_eq!(target.key.side, StowSide::Target);
    assert_eq!(target.key.platform, "aarch64-unknown-linux-gnu");
    assert_eq!(target.features, ["a"]);
}

/// `leaf` is a normal dep of the root and a normal dep of the proc-macro
/// `pm`, at the same features: a native `cargo build` dedups it into one
/// unit — the normal one — and `pm`'s extern resolves to that artifact.
/// The emitted edge mirrors cargo: `pm`'s host unit names `leaf` at both
/// sides — the host unit for the `--target` spelling under which the
/// split stands, and the deduped normal unit the native spelling links
/// (stow#506).
#[test]
fn a_host_dep_shared_with_a_normal_one_emits_the_deduped_edge() {
    let work = tempfile::tempdir().unwrap();
    let reg = work.path().join("registry");
    std::fs::create_dir_all(&reg).unwrap();
    publish(
        &reg,
        &Fixture {
            name: "leaf",
            version: "1.0.0",
            deps: vec![],
            features: &[("a", &[])],
            yanked: false,
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "pm",
            version: "1.0.0",
            deps: vec![("leaf", "1", &["a"])],
            features: &[],
            yanked: false,
            proc_macro: true,
        },
    );
    let manifest = project(
        &work.path().join("root"),
        &json!({ "leaf": { "version": "1", "features": ["a"] }, "pm": "1" }),
    );
    let (_home, resolver) = resolver_at(&reg);
    let out = resolver
        .resolve(
            &manifest,
            &ResolveOptions::default(),
            &["x86_64-unknown-linux-gnu".to_owned()],
        )
        .unwrap();

    let pm = units_named(&out, "pm")
        .into_iter()
        .find(|unit| unit.unit_kind == stow_resolver::StowUnitKind::Lib)
        .expect("pm's host lib unit");
    assert_eq!(pm.key.side, StowSide::Host);
    let leaf_sides: Vec<StowSide> = pm
        .deps
        .iter()
        .filter(|dep| dep.name == "leaf")
        .map(|dep| dep.key.side)
        .collect();
    assert!(
        leaf_sides.contains(&StowSide::Target),
        "the native spelling dedups `leaf` to the normal unit: {leaf_sides:?}"
    );
    assert!(
        leaf_sides.contains(&StowSide::Host),
        "the `--target` spelling keeps the host unit's edge: {leaf_sides:?}"
    );
}

/// The dedup is exact: `leaf`'s host and normal feature sets differ, so
/// the pair compiles as two units under every spelling and the host
/// unit's edge stays host-only.
#[test]
fn a_host_dep_with_different_features_keeps_its_own_edge() {
    let work = tempfile::tempdir().unwrap();
    let reg = work.path().join("registry");
    std::fs::create_dir_all(&reg).unwrap();
    publish(
        &reg,
        &Fixture {
            name: "leaf",
            version: "1.0.0",
            deps: vec![],
            features: &[("a", &[]), ("b", &[])],
            yanked: false,
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "pm",
            version: "1.0.0",
            deps: vec![("leaf", "1", &["b"])],
            features: &[],
            yanked: false,
            proc_macro: true,
        },
    );
    let manifest = project(
        &work.path().join("root"),
        &json!({ "leaf": { "version": "1", "features": ["a"] }, "pm": "1" }),
    );
    let (_home, resolver) = resolver_at(&reg);
    let out = resolver
        .resolve(
            &manifest,
            &ResolveOptions::default(),
            &["x86_64-unknown-linux-gnu".to_owned()],
        )
        .unwrap();

    let pm = units_named(&out, "pm")
        .into_iter()
        .find(|unit| unit.unit_kind == stow_resolver::StowUnitKind::Lib)
        .expect("pm's host lib unit");
    let leaf_sides: Vec<StowSide> = pm
        .deps
        .iter()
        .filter(|dep| dep.name == "leaf")
        .map(|dep| dep.key.side)
        .collect();
    assert_eq!(
        leaf_sides,
        vec![StowSide::Host],
        "feature sets differ — no dedup, the edge stays host-only"
    );
}

/// `deep`'s task reaches `leaf` only through `pm`'s host edge, yet a
/// consumer's native build still dedups `leaf` against the root's normal
/// unit — the dep is in the task's host-side transitive closure and has
/// a target-side unit. The task therefore carries `leaf`'s target unit
/// as a normal dep edge so the generated wrapper pins it under
/// `[dependencies]`, reproducing the consumer's dedup inside the task's
/// own resolve (stow#506). The same closure gives `pm` target-side
/// `deep` and `leaf` pins.
#[test]
fn a_host_tasks_closure_pins_deduped_packages_at_target_sides() {
    let work = tempfile::tempdir().unwrap();
    let reg = work.path().join("registry");
    std::fs::create_dir_all(&reg).unwrap();
    publish(
        &reg,
        &Fixture {
            name: "leaf",
            version: "1.0.0",
            deps: vec![],
            features: &[("a", &[])],
            yanked: false,
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "deep",
            version: "1.0.0",
            deps: vec![("leaf", "1", &["a"])],
            features: &[],
            yanked: false,
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "pm",
            version: "1.0.0",
            deps: vec![("deep", "1", &[])],
            features: &[],
            yanked: false,
            proc_macro: true,
        },
    );
    let manifest = project(
        &work.path().join("root"),
        &json!({ "leaf": { "version": "1", "features": ["a"] }, "pm": "1" }),
    );
    let (_home, resolver) = resolver_at(&reg);
    let out = resolver
        .resolve(
            &manifest,
            &ResolveOptions::default(),
            &["x86_64-unknown-linux-gnu".to_owned()],
        )
        .unwrap();
    let units: Vec<StowUnit> = out
        .iter()
        .flat_map(|(_target, out)| out.units.iter().cloned())
        .collect();
    let (requests, _nodes) = stow_resolver::enqueue_requests_from_output(
        &units,
        pinned_rustc_version(),
        stow_types::api::EnqueueSource::CrateUpdate,
        0,
    )
    .unwrap();

    let sides_of = |request_crate: &str, dep_crate: &str| -> Vec<bool> {
        requests
            .iter()
            .find(|request| request.crate_name.as_str() == request_crate)
            .unwrap_or_else(|| panic!("{request_crate} has an enqueue request"))
            .depends_on
            .iter()
            .filter(|dep| dep.crate_name.as_str() == dep_crate)
            .map(|dep| dep.host_side)
            .collect()
    };
    let deep_leaf = sides_of("deep", "leaf");
    assert!(
        deep_leaf.contains(&false),
        "deep's task pins `leaf` as a normal dep for the deduped spelling: {deep_leaf:?}"
    );
    assert!(
        deep_leaf.contains(&true),
        "deep's task keeps the host-side `leaf` dep: {deep_leaf:?}"
    );
    let pm_leaf = sides_of("pm", "leaf");
    assert_eq!(
        pm_leaf,
        vec![false],
        "pm reaches `leaf` only through deep's subtree — its task carries \
         the dedup pin, not a direct edge: {pm_leaf:?}"
    );
    let pm_deep = sides_of("pm", "deep");
    assert_eq!(
        pm_deep,
        vec![true],
        "deep has no target-side unit — no normal pin to mirror cargo's dedup onto"
    );
}

/// `git` inside `dir`, asserting success.
fn git_in(dir: &Path, args: &[&str]) {
    let status = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} in {}", dir.display());
}

/// `stow-src-*` dirs currently under the process temp dir.
fn stow_src_dirs() -> std::collections::BTreeSet<PathBuf> {
    std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("stow-src-"))
        })
        .collect()
}

/// Run `body` so its `stow-src-*` count can only see its own case
/// (stow#540): the parent spawns a copy of this test binary that runs
/// just `case`, with `TMPDIR` aimed at a fresh parent-owned `TempDir` —
/// every fixture, fetched tree, and scratch dir the case makes then
/// lives under that root. `STOW_TEST_SCRATCH_ISOLATED` marks the child
/// so it runs `body` directly. The child's exit status is the
/// outcome; nothing reads its output.
fn isolated_scratch(case: &str, body: impl FnOnce()) {
    if std::env::var_os("STOW_TEST_SCRATCH_ISOLATED").is_some() {
        body();
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", case])
        .env("TMPDIR", root.path())
        .env("STOW_TEST_SCRATCH_ISOLATED", "1")
        .status()
        .expect("the test binary spawns");
    assert!(status.success(), "isolated case `{case}` failed");
}

/// The crate names a `SourceResolve` enqueues, deduped and sorted.
fn requested_crates(source: &stow_resolver::SourceResolve) -> Vec<String> {
    let mut names: Vec<String> = source
        .targets
        .iter()
        .flat_map(|(_target, requests)| requests.iter())
        .map(|request| request.crate_name.as_str().to_owned())
        .collect();
    names.sort();
    names.dedup();
    names
}

/// A local git repo whose `main` and `side` refs carry manifests
/// depending on `dep_a` and `dep_b` respectively; its `file://` URL.
fn two_ref_project(repo: &Path) -> url::Url {
    std::fs::create_dir_all(repo.join("src")).unwrap();
    git_in(repo, &["init", "-b", "main"]);
    git_in(repo, &["config", "user.email", "stow@test"]);
    git_in(repo, &["config", "user.name", "stow"]);
    let write_manifest = |dep: &str| {
        std::fs::write(
            repo.join("Cargo.toml"),
            toml_document(&json!({
                "package": { "name": "gitproj", "version": "0.0.0", "edition": "2021" },
                "dependencies": { dep: "1" },
            })),
        )
        .unwrap();
        std::fs::write(repo.join("src/lib.rs"), "").unwrap();
        git_in(repo, &["add", "-A"]);
        git_in(repo, &["commit", "-qm", dep]);
    };
    write_manifest("dep_a");
    git_in(repo, &["checkout", "-qb", "side"]);
    write_manifest("dep_b");
    url::Url::from_file_path(repo).unwrap()
}

/// `dep_a` and `dep_b` 1.0.0 in a fresh local registry under `work`.
fn publish_deps(reg: &Path) {
    std::fs::create_dir_all(reg).unwrap();
    for name in ["dep_a", "dep_b"] {
        publish(
            reg,
            &Fixture {
                name,
                version: "1.0.0",
                deps: vec![],
                features: &[],
                yanked: false,
                proc_macro: false,
            },
        );
    }
}

/// stow#540: a fetched source tree lives only for its own resolve.
/// Repeated and concurrent fetches of the same URL get independent
/// checkouts — the old scheme put every fetch at one deterministic
/// `git-<fnv>` dir under the session tempdir, where same-URL resolves
/// collided — and every return releases the scratch it fetched into.
#[test]
fn repeated_and_concurrent_fetches_resolve_independent_trees() {
    isolated_scratch(
        "repeated_and_concurrent_fetches_resolve_independent_trees",
        || {
            let work = tempfile::tempdir().unwrap();
            let reg = work.path().join("registry");
            publish_deps(&reg);
            let url = two_ref_project(&work.path().join("gitproj"));
            let (_home, resolver) = resolver_at(&reg);
            let targets = vec!["x86_64-unknown-linux-gnu".to_owned()];
            let rustc = pinned_rustc_version();
            let baseline = stow_src_dirs();

            // Repeated fetches at different refs resolve their own
            // trees: each ref's dep set is what lands in the requests,
            // the lib target is still reported — semantics intact.
            let main = resolver
                .resolve_git(url.as_str(), "main", &targets, rustc, 0)
                .unwrap();
            assert!(main.has_library);
            assert!(!main.has_binary);
            assert_eq!(requested_crates(&main), vec!["dep_a".to_owned()]);
            let side = resolver
                .resolve_git(url.as_str(), "side", &targets, rustc, 0)
                .unwrap();
            assert_eq!(requested_crates(&side), vec!["dep_b".to_owned()]);
            assert_eq!(
                stow_src_dirs(),
                baseline,
                "returned resolves release their scratch"
            );

            // The same URL fetched twice concurrently gets two
            // independent checkouts — each ref's output reflects its
            // own manifest.
            std::thread::scope(|scope| {
                let a =
                    scope.spawn(|| resolver.resolve_git(url.as_str(), "main", &targets, rustc, 0));
                let b =
                    scope.spawn(|| resolver.resolve_git(url.as_str(), "side", &targets, rustc, 0));
                let main = a.join().unwrap().unwrap();
                let side = b.join().unwrap().unwrap();
                assert_eq!(requested_crates(&main), vec!["dep_a".to_owned()]);
                assert_eq!(requested_crates(&side), vec!["dep_b".to_owned()]);
            });
            assert_eq!(
                stow_src_dirs(),
                baseline,
                "concurrent resolves release their scratch"
            );
        },
    );
}

/// Failure paths release scratch too: an unfetchable remote and a
/// fetched tree with no manifest both return the error — failures are
/// not swallowed — and neither leaves its checkout behind (stow#540).
#[test]
fn failed_fetches_release_their_scratch() {
    isolated_scratch("failed_fetches_release_their_scratch", || {
        let work = tempfile::tempdir().unwrap();
        let reg = work.path().join("registry");
        std::fs::create_dir_all(&reg).unwrap();
        let (_home, resolver) = resolver_at(&reg);
        let targets = vec!["x86_64-unknown-linux-gnu".to_owned()];
        let rustc = pinned_rustc_version();
        let baseline = stow_src_dirs();

        assert!(
            resolver
                .resolve_git("file:///stow-540-no-such-repo", "main", &targets, rustc, 0)
                .is_err(),
            "an unfetchable remote still errors"
        );
        let empty = work.path().join("nopkg");
        std::fs::create_dir_all(&empty).unwrap();
        git_in(&empty, &["init", "-b", "main"]);
        git_in(&empty, &["config", "user.email", "stow@test"]);
        git_in(&empty, &["config", "user.name", "stow"]);
        std::fs::write(empty.join("README"), "no manifest").unwrap();
        git_in(&empty, &["add", "-A"]);
        git_in(&empty, &["commit", "-qm", "readme"]);
        let empty_url = url::Url::from_file_path(&empty).unwrap();
        assert!(
            resolver
                .resolve_git(empty_url.as_str(), "main", &targets, rustc, 0)
                .is_err(),
            "a tree with no manifest errors at prepare"
        );
        assert_eq!(
            stow_src_dirs(),
            baseline,
            "fetch and resolve failures release their scratch"
        );
    });
}

/// Caller-owned inputs stay caller-owned (stow#540):
/// `resolve_package_dir` reads the package tree and drops only its
/// bundled `Cargo.lock` — the lane's existing contract — while the
/// manifest and sources the caller provided survive verbatim, and the
/// semantic output is unchanged.
#[test]
fn resolve_package_dir_preserves_the_callers_tree() {
    let work = tempfile::tempdir().unwrap();
    let reg = work.path().join("registry");
    publish_deps(&reg);
    let (_home, resolver) = resolver_at(&reg);
    let targets = vec!["x86_64-unknown-linux-gnu".to_owned()];

    let package_dir = work.path().join("crate-src-0.0.0");
    let manifest = project(&package_dir, &json!({ "dep_a": "1" }));
    let manifest_before = std::fs::read_to_string(&manifest).unwrap();
    let lib_before = std::fs::read_to_string(package_dir.join("src/lib.rs")).unwrap();
    let out = resolver
        .resolve_package_dir(&package_dir, &ResolveOptions::default(), &targets)
        .unwrap();
    assert_eq!(units_named(&out, "dep_a")[0].version, "1.0.0");
    assert!(package_dir.is_dir(), "the caller's tree survives");
    assert_eq!(
        std::fs::read_to_string(&manifest).unwrap(),
        manifest_before,
        "the caller's manifest is untouched"
    );
    assert_eq!(
        std::fs::read_to_string(package_dir.join("src/lib.rs")).unwrap(),
        lib_before,
        "the caller's sources are untouched"
    );
}

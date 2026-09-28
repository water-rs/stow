//! Offline resolves: a `local-registry` directory stands in for
//! crates.io, a local git dir for a git host. Covers the
//! dropped-lockfile semantics (yanked admission, git-pin locking, pin
//! never preferred over a newer non-yanked release) and the host/target
//! unit split.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use stow_resolver::{ResolveOptions, Resolver, StowSide, StowUnit};

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
        PathBuf::from(env!("CARGO_BIN_EXE_stow-rustc-shim")),
    )
    .unwrap();
    (home, resolver)
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

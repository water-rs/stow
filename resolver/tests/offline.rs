//! Offline resolves: a `local-registry` directory stands in for
//! crates.io, a local git dir for a git host. Covers the
//! dropped-lockfile semantics (yanked admission, git-pin locking, pin
//! never preferred over a newer non-yanked release) and the host/target
//! unit split.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

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

/// Pack `fixture` into `{reg}/{name}-{version}.crate` and append its
/// index line, returning the sha256 the index records.
#[allow(clippy::too_many_lines)] // manifest, tarball and index line in one builder
fn publish(reg: &Path, fixture: &Fixture) -> String {
    let mut manifest = format!(
        "[package]\nname = \"{}\"\nversion = \"{}\"\nedition = \"2021\"\n",
        fixture.name, fixture.version
    );
    if fixture.proc_macro {
        manifest.push_str("\n[lib]\nproc-macro = true\n");
    }
    if !fixture.features.is_empty() {
        manifest.push_str("\n[features]\n");
        for (name, members) in fixture.features {
            writeln!(
                manifest,
                "{name} = [{}]",
                members
                    .iter()
                    .map(|member| format!("\"{member}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .unwrap();
        }
    }
    for (name, req, features) in &fixture.deps {
        write!(
            manifest,
            "\n[dependencies.{name}]\nversion = \"{req}\"\nfeatures = [{}]",
            features
                .iter()
                .map(|feature| format!("\"{feature}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .unwrap();
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
            manifest,
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

    let mut deps_json = String::new();
    for (name, req, features) in &fixture.deps {
        write!(
            deps_json,
            "{{\"name\":\"{name}\",\"req\":\"^{req}\",\"features\":{},\"optional\":false,\"default_features\":true,\"target\":null,\"kind\":\"normal\"}},",
            serde_json::to_string(&features).unwrap(),
        )
        .unwrap();
    }
    let line = format!(
        "{{\"name\":\"{}\",\"vers\":\"{}\",\"deps\":[{}],\"cksum\":\"{}\",\"features\":{},\"yanked\":{}}}\n",
        fixture.name,
        fixture.version,
        deps_json.trim_end_matches(','),
        cksum,
        serde_json::Value::Object(
            fixture
                .features
                .iter()
                .map(|(name, members)| {
                    ((*name).to_owned(), serde_json::to_value(members).unwrap())
                })
                .collect(),
        ),
        fixture.yanked,
    );
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
        format!(
            "[source.crates-io]\nreplace-with = \"local\"\n\n[source.local]\nlocal-registry = \"{}\"\n",
            reg.display()
        ),
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
fn project(dir: &Path, dependencies: &str) -> PathBuf {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/lib.rs"), "").unwrap();
    let manifest = dir.join("Cargo.toml");
    std::fs::write(
        &manifest,
        format!(
            "[package]\nname = \"root\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n{dependencies}"
        ),
    )
    .unwrap();
    manifest
}

fn lock_entry(name: &str, version: &str, source: &str) -> String {
    format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = \"{source}\"\n")
}

fn dropped_lockfile(entries: &[String], deps: &[&str]) -> String {
    format!(
        "version = 4\n\n[[package]]\nname = \"root\"\nversion = \"0.0.0\"\ndependencies = [{}]\n\n{}",
        deps.iter()
            .map(|dep| format!("\"{dep}\""))
            .collect::<Vec<_>>()
            .join(", "),
        entries.join("\n"),
    )
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
    let manifest = project(&work.path().join("root"), "[dependencies]\ndep = \"1\"\n");
    let (_home, resolver) = resolver_at(&reg);
    let lock = dropped_lockfile(
        &[lock_entry("dep", "1.0.0", CRATES_IO)],
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
    let manifest = project(&work.path().join("root"), "[dependencies]\ndep = \"1\"\n");
    let (_home, resolver) = resolver_at(&reg);
    let lock = dropped_lockfile(
        &[lock_entry("dep", "1.0.0", CRATES_IO)],
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
            format!("[package]\nname = \"gitdep\"\nversion = \"{version}\"\nedition = \"2021\"\n"),
        )
        .unwrap();
        std::fs::write(repo.join("src/lib.rs"), "").unwrap();
        run(&["add", "-A"]);
        run(&["commit", "-m", version]);
    };
    write_manifest("0.1.0");
    let pinned = sha_of("HEAD");
    write_manifest("0.2.0");

    let manifest = project(
        &work.path().join("root"),
        &format!(
            "[dependencies]\ngitdep = {{ git = \"file://{}\" }}\n",
            repo.display()
        ),
    );
    let (_home, resolver) = resolver_at(&work.path().join("registry"));
    let lock = dropped_lockfile(
        &[lock_entry(
            "gitdep",
            "0.1.0",
            &format!("git+file://{}#{pinned}", repo.display()),
        )],
        &[&format!(
            "gitdep 0.1.0 (git+file://{}#{pinned})",
            repo.display()
        )],
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
        "[dependencies]\nshared = { version = \"1\", features = [\"a\"] }\npm = \"1\"\n",
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

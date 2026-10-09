//! stow#588 stage 4: the dependency-context machinery end to end,
//! offline — a `local-registry` directory stands in for crates.io (the
//! `resolver/tests/offline.rs` harness shape), the wrapper package is
//! the real `write_wrapper_package` output, and the verification is the
//! real `cargo <phase> --unit-graph` + `verify_dependency_context`
//! chain.
//!
//! The toolchain pin is the test binary's own rustc release:
/// `RUSTUP_TOOLCHAIN=<release>` resolves it through the real rustup
/// home the sandbox already grants.
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use stow_types::api::{BuildTaskPayload, EnqueueRequest};
use stow_types::identity::WireRustcVersion;
use tempfile::TempDir;

use crate::capture::CaptureCollector;
use crate::task::{
    self, BuildWorkspace, CargoSubcommand, PhaseRun, PhaseSetup, phase_sandbox, run_sandboxed_phase,
};

/// One fixture crate in the local registry. `deps` are normal
/// dependencies, `build_deps` `[build-dependencies]` entries — both as
/// `(name, req, features)`.
struct Fixture {
    name: &'static str,
    version: &'static str,
    deps: Vec<(&'static str, &'static str, &'static [&'static str])>,
    build_deps: Vec<(&'static str, &'static str, &'static [&'static str])>,
    features: &'static [(&'static str, &'static [&'static str])],
    proc_macro: bool,
}

fn toml_document(value: &Value) -> String {
    toml::to_string(value).expect("fixture toml")
}

/// Pack `fixture` into `{reg}/{name}-{version}.crate` and append its
/// sparse-index line — the same shape `resolver/tests/offline.rs`
/// publishes.
fn publish(reg: &Path, fixture: &Fixture) -> String {
    let features: serde_json::Map<String, Value> = fixture
        .features
        .iter()
        .map(|(name, members)| ((*name).to_owned(), json!(members)))
        .collect();
    let dep_spec = |(name, req, feats): &(&'static str, &'static str, &'static [&'static str])| {
        (
            (*name).to_owned(),
            json!({ "version": req, "features": feats }),
        )
    };
    let mut manifest = json!({
        "package": { "name": fixture.name, "version": fixture.version, "edition": "2021" },
        "features": features,
        "dependencies": fixture.deps.iter().map(dep_spec).collect::<serde_json::Map<_,_>>(),
    });
    if !fixture.build_deps.is_empty() {
        manifest["build-dependencies"] = json!(
            fixture
                .build_deps
                .iter()
                .map(dep_spec)
                .collect::<serde_json::Map<_, _>>()
        );
    }
    let mut lib = String::new();
    if fixture.proc_macro {
        manifest["lib"] = json!({ "proc-macro": true });
        lib.push_str("extern crate proc_macro;\n");
    }
    let cksum = write_crate_tarball(reg, fixture, &manifest, &lib);

    let dep_line = |deps: &[(&'static str, &'static str, &'static [&'static str])], kind: &str| {
        deps.iter()
            .map(|(name, req, feats)| {
                json!({
                    "name": name,
                    "req": format!("^{req}"),
                    "features": feats,
                    "optional": false,
                    "default_features": true,
                    "target": null,
                    "kind": kind,
                })
            })
            .collect::<Vec<_>>()
    };
    let deps = dep_line(&fixture.deps, "normal")
        .into_iter()
        .chain(dep_line(&fixture.build_deps, "build"))
        .collect::<Vec<_>>();
    let mut line = serde_json::to_string(&json!({
        "name": fixture.name,
        "vers": fixture.version,
        "deps": deps,
        "cksum": cksum,
        "features": features,
        "yanked": false,
    }))
    .expect("index line");
    line.push('\n');
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
    std::fs::write(&entry, index).expect("write index line");
    cksum
}

/// Write `<name>-<version>.crate` under `reg` with the given manifest and
/// lib source, returning its sha256 hex (the index line's `cksum`). A
/// crate with build-dependencies also carries the build script cargo
/// needs to compile them.
fn write_crate_tarball(reg: &Path, fixture: &Fixture, manifest: &Value, lib: &str) -> String {
    let tarball = reg.join(format!("{}-{}.crate", fixture.name, fixture.version));
    let file = std::fs::File::create(&tarball).expect("create crate tarball");
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
        file,
        flate2::Compression::fast(),
    ));
    let mut append = |path: String, contents: String| {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(u64::try_from(contents.len()).unwrap());
        header.set_cksum();
        tar.append_data(&mut header, path, contents.as_bytes())
            .expect("append tarball entry");
    };
    append(
        format!("{}-{}/Cargo.toml", fixture.name, fixture.version),
        toml_document(manifest),
    );
    append(
        format!("{}-{}/src/lib.rs", fixture.name, fixture.version),
        lib.to_owned(),
    );
    if !fixture.build_deps.is_empty() {
        append(
            format!("{}-{}/build.rs", fixture.name, fixture.version),
            "fn main() {}\n".to_owned(),
        );
    }
    tar.into_inner().unwrap().finish().expect("finish tarball");
    hex::encode(Sha256::digest(std::fs::read(&tarball).unwrap()))
}

/// Process-global env mutations — every spawned `cargo`/`rustup` sees
/// them — serialize every test that touches them.
fn env_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    // Poisoned guards mean an earlier test panicked while holding env —
    // the mutations it made are still valid, so keep going.
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The `CARGO_HOME` the test process started with — captured before any
/// test points it at a local registry, so spawned `cargo build`/`cargo
/// resolve` commands for test binaries still see the real toolchain home.
fn original_cargo_home() -> Option<PathBuf> {
    static ORIGINAL: OnceLock<Option<PathBuf>> = OnceLock::new();
    ORIGINAL
        .get_or_init(|| std::env::var_os("CARGO_HOME").map(PathBuf::from))
        .clone()
}

/// The rustc release this test binary's toolchain reports —
/// `RUSTUP_TOOLCHAIN=<release>` resolves it through the real rustup
/// home, so no `RUSTUP_HOME` override is needed anywhere (the sandbox
/// grants the real home; a symlinked stand-in reads its own toolchain
/// tree through a path landlock never granted).
fn pinned_rustc_version() -> &'static WireRustcVersion {
    static PINNED: OnceLock<WireRustcVersion> = OnceLock::new();
    PINNED.get_or_init(|| {
        let verbose = String::from_utf8(
            std::process::Command::new("rustc")
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
        WireRustcVersion::parse(release).expect("release is a wire version")
    })
}
/// A cargo home serving as the whole toolchain home: `config.toml`
/// replaces crates.io with the local registry AT `<home>/registry` —
/// the same directory the phase sandbox grants read-only as the
/// registry sources tree, so the sandboxed phases read the fixtures
/// through a path the grant set already covers.
fn registry_home() -> (TempDir, PathBuf) {
    let home = tempfile::tempdir().expect("cargo home");
    let reg = home.path().join("registry");
    std::fs::create_dir_all(&reg).unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        toml_document(&json!({
            "source": {
                "crates-io": { "replace-with": "local" },
                "local": { "local-registry": reg },
            },
        })),
    )
    .expect("write cargo home config");
    (home, reg)
}

/// The rustup name of the toolchain running this test binary —
/// `RUSTUP_TOOLCHAIN` when the cargo proxy set it (`cargo +stable
/// test`), else `rustup show active-toolchain`'s answer. The resolver
/// is asked for this toolchain *by name*; `pinned_rustc_version` is the
/// release that toolchain's rustc reports, so the probe's
/// release-equals-pin check still holds when the name is a channel —
/// CI runs only `stable`, where no toolchain literally named `1.99.0`
/// exists.
fn active_toolchain() -> &'static str {
    static ACTIVE: OnceLock<String> = OnceLock::new();
    ACTIVE.get_or_init(|| {
        if let Ok(name) = std::env::var("RUSTUP_TOOLCHAIN") {
            return name;
        }
        String::from_utf8(
            std::process::Command::new("rustup")
                .args(["show", "active-toolchain"])
                .output()
                .expect("rustup show active-toolchain")
                .stdout,
        )
        .expect("active-toolchain is utf8")
        .split_whitespace()
        .next()
        .expect("rustup reports a toolchain name")
        .to_owned()
    })
}

/// `Resolver` over the local registry, rustc pinned to the test
/// toolchain's release, probed under [`active_toolchain`]'s rustup
/// name. `stow-rustc-shim` is a `stow-resolver` binary — a test in
/// this package gets no `CARGO_BIN_EXE_` for it, so build it once.
/// `Resolver` over the same cargo home `fetch` and the sandbox use —
/// its `local-registry` source names the registry under the home, the
/// only registry path the phase grants cover.
fn resolver_at(cargo_home: &Path) -> stow_resolver::Resolver {
    stow_resolver::Resolver::with_cargo_home_and_toolchain(
        cargo_home.to_path_buf(),
        active_toolchain(),
        pinned_rustc_version(),
        shim_binary(),
    )
    .expect("resolver")
}

fn shim_binary() -> PathBuf {
    static SHIM: OnceLock<PathBuf> = OnceLock::new();
    SHIM.get_or_init(|| {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate dir has a parent")
            .to_path_buf();
        let mut build = std::process::Command::new("cargo");
        build
            .args(["build", "-p", "stow-resolver", "--bin", "stow-rustc-shim"])
            .current_dir(&workspace);
        if let Some(home) = original_cargo_home() {
            build.env("CARGO_HOME", home);
        } else {
            build.env_remove("CARGO_HOME");
        }
        let status = build.status().expect("build the resolve shim");
        assert!(status.success(), "cargo build stow-rustc-shim failed");
        workspace.join(format!(
            "target/debug/stow-rustc-shim{}",
            std::env::consts::EXE_SUFFIX
        ))
    })
    .clone()
}

/// `(runtime, capture)` — the two binaries the wrapper shims link:
/// `stow-cli` is the runtime cargo invokes as `RUSTC_WRAPPER`, and it
/// re-invokes `stow-build` with `rustc` as argv[1], which is the shape
/// `is_rustc_wrapper_invocation` dispatches on. A test binary cannot
/// stand in for either — the roles live behind the binaries' argv0.
fn build_binaries() -> (PathBuf, PathBuf) {
    static BINS: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
    BINS.get_or_init(|| {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate dir has a parent")
            .to_path_buf();
        let mut build = std::process::Command::new("cargo");
        build
            .args(["build", "-p", "stow-build", "-p", "stow-cli"])
            .current_dir(&workspace);
        if let Some(home) = original_cargo_home() {
            build.env("CARGO_HOME", home);
        } else {
            build.env_remove("CARGO_HOME");
        }
        let status = build.status().expect("build stow-build and stow-cli");
        assert!(status.success(), "cargo build stow-build failed");
        (
            workspace.join("target/debug/stow-cli"),
            workspace.join("target/debug/stow-build"),
        )
    })
    .clone()
}

/// A consumer project manifest: `deps` under `[dependencies]`,
/// `build_deps` under `[build-dependencies]`; empty `src/lib.rs`, and
/// a `build.rs` whenever build deps exist (cargo compiles them only for
/// a package with a build script).
fn consumer_project(dir: &Path, deps: &Value, build_deps: &Value) -> PathBuf {
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/lib.rs"), "").unwrap();
    if build_deps
        .as_object()
        .is_some_and(|table| !table.is_empty())
    {
        std::fs::write(dir.join("build.rs"), "fn main() {}\n").unwrap();
    }
    let manifest = dir.join("Cargo.toml");
    std::fs::write(
        &manifest,
        toml_document(&json!({
            "package": { "name": "root", "version": "0.0.0", "edition": "2021" },
            "dependencies": deps,
            "build-dependencies": build_deps,
        })),
    )
    .unwrap();
    manifest
}

/// Resolve `manifest` on the host triple and return the minted
/// `EnqueueRequest`s — the resolver path's task ids.
fn resolve_requests(cargo_home: &Path, manifest: &Path) -> Vec<EnqueueRequest> {
    let resolver = resolver_at(cargo_home);
    let host = host_triple();
    let out = resolver
        .resolve(
            manifest,
            &stow_resolver::ResolveOptions::default(),
            std::slice::from_ref(&host),
        )
        .expect("resolve consumer project");
    let units = &out
        .iter()
        .find(|(target, _)| *target == host)
        .expect("host triple resolve")
        .1
        .units;
    stow_resolver::resolved_task_graph(units, pinned_rustc_version())
        .and_then(|graph| {
            stow_resolver::enqueue_requests_inner(
                &graph,
                &std::collections::BTreeSet::new(),
                stow_types::api::EnqueueSource::CacheMiss,
                0,
            )
        })
        .map(|(requests, _uncovered)| requests)
        .expect("enqueue requests")
}

/// The host triple this test binary runs on — the native target.
fn host_triple() -> String {
    static HOST: OnceLock<String> = OnceLock::new();
    HOST.get_or_init(|| {
        let verbose = String::from_utf8(
            std::process::Command::new("rustc")
                .arg("-vV")
                .output()
                .expect("rustc -vV")
                .stdout,
        )
        .expect("rustc -vV is utf8");
        verbose
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .expect("host triple")
            .to_owned()
    })
    .clone()
}

/// The `EnqueueRequest` for `name` — each test names the node it is
/// verifying.
fn request_for(requests: &[EnqueueRequest], name: &str) -> EnqueueRequest {
    requests
        .iter()
        .find(|request| request.crate_name.as_str() == name)
        .unwrap_or_else(|| {
            panic!(
                "no request for {name} among [{}]",
                requests
                    .iter()
                    .map(|request| request.crate_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
        .clone()
}

/// The payload a dispatch would carry — `manual.rs::task_payload`'s
/// construction, attempt 1.
fn payload_for(request: &EnqueueRequest) -> BuildTaskPayload {
    BuildTaskPayload {
        task_id: request.task_id().expect("request task id"),
        attempt: 1,
        crate_name: request.crate_name.clone(),
        version: request.version.clone(),
        features_json: request.features_json.clone(),
        target: request.target.clone(),
        rustc_version: request.rustc_version.clone(),
        preserve_lockfile: request.preserve_lockfile,
        host_side: request.host_side,
        dependency_subgraph: request.dependency_subgraph.clone(),
    }
}

/// The real wrapper workspace for `task`: its crate's `.crate` archive
/// unpacked under `root`, `write_wrapper_package`'s manifest and
/// lockfile, `BuildWorkspace` as the build job sees it.
async fn wrapper_workspace(reg: &Path, task: &BuildTaskPayload) -> (TempDir, BuildWorkspace) {
    let root = tempfile::tempdir().expect("workspace root");
    let archive = std::fs::read(reg.join(format!("{}-{}.crate", task.crate_name, task.version)))
        .expect("crate archive in local registry");
    let crate_name = task.crate_name.as_str().to_owned();
    let crate_version = task.version.to_string();
    let unpack_root = root.path().to_path_buf();
    let (manifest_path, checksum) = smol::unblock(move || {
        task::unpack_crate_archive(&unpack_root, &crate_name, &crate_version, &archive)
            .map(|manifest| (manifest, hex::encode(sha2::Sha256::digest(&archive))))
    })
    .await
    .expect("unpack crate archive");
    let source_root = manifest_path
        .parent()
        .expect("unpacked manifest has a parent")
        .to_path_buf();
    let wrapper_root = root.path().join("wrapper");
    let (manifest_path, _) =
        task::write_wrapper_package(task, &wrapper_root, &checksum, &source_root)
            .await
            .expect("write wrapper package");
    let workspace = task::resolution_build_workspace(
        manifest_path.clone(),
        manifest_path.parent().expect("wrapper dir").to_path_buf(),
    );
    (root, workspace)
}

/// The real build-stage check: fetch the wrapper's deps out of the
/// local registry, then every `check`-phase unit graph must mint
/// `task.task_id` — `verify_dependency_context` verbatim.
async fn verify(
    task: &BuildTaskPayload,
    workspace: &BuildWorkspace,
) -> stow_types::error::Result<()> {
    task::fetch_workspace_dependencies(task, workspace).await?;
    let graphs = task::phase_unit_graphs(task, workspace, CargoSubcommand::Check).await?;
    task::verify_dependency_context(task, &graphs)
}

/// Fixture: the `alloc-stdlib` shape — `a-stdlib` needs `a-nostd`, and
/// whether `a-nostd` gets its `unsafe` feature depends on which consumer
/// resolves it. Two consumer projects mint two different task ids for
/// the same `a-stdlib` tuple, and each one's wrapper reproduces the
/// child context it was dispatched for.
#[test]
fn the_alloc_stdlib_shape_mints_two_ids_and_each_wrapper_verifies() {
    let _env = env_guard();
    let (cargo_home, reg) = registry_home();
    let scratch = tempfile::tempdir().unwrap();
    publish(
        &reg,
        &Fixture {
            name: "a-nostd",
            version: "3.0.0",
            deps: vec![],
            build_deps: vec![],
            features: &[("unsafe", &[])],
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "a-stdlib",
            version: "0.3.0",
            deps: vec![("a-nostd", "3", &[])],
            build_deps: vec![],
            features: &[],
            proc_macro: false,
        },
    );
    // Consumer A resolves a-nostd plain; consumer B widens it with
    // `unsafe` — the two `a-stdlib` contexts differ in the child
    // feature set alone.
    let manifest_a = consumer_project(
        &scratch.path().join("consumer-a"),
        &json!({ "a-stdlib": "0.3", "a-nostd": "3" }),
        &json!({}),
    );
    let manifest_b = consumer_project(
        &scratch.path().join("consumer-b"),
        &json!({
            "a-stdlib": "0.3",
            "a-nostd": { "version": "3", "features": ["unsafe"] },
        }),
        &json!({}),
    );
    let requests_a = resolve_requests(cargo_home.path(), &manifest_a);
    let requests_b = resolve_requests(cargo_home.path(), &manifest_b);
    let task_a = payload_for(&request_for(&requests_a, "a-stdlib"));
    let task_b = payload_for(&request_for(&requests_b, "a-stdlib"));
    assert_ne!(
        task_a.task_id, task_b.task_id,
        "the same parent tuple over different child features is two tasks"
    );

    unsafe { std::env::set_var("CARGO_HOME", cargo_home.path()) };
    smol::block_on(async {
        for task in [&task_a, &task_b] {
            let (_root, workspace) = wrapper_workspace(&reg, task).await;
            verify(task, &workspace).await.unwrap_or_else(|error| {
                panic!("wrapper for {} did not verify: {error:#}", task.task_id)
            });
        }
    });
}

/// A grandchild widened by another consumer must reproduce inside the
/// wrapper: `mid` asks for `leaf[]`, `other` asks for `leaf["wide"]`,
/// the resolve unifies `leaf` at `["wide"]`, and `mid`'s task carries
/// that transitive context — the pin a direct-deps-only dispatch could
/// never express.
#[test]
fn a_grandchild_widened_by_another_consumer_reproduces() {
    let _env = env_guard();
    let (cargo_home, reg) = registry_home();
    let scratch = tempfile::tempdir().unwrap();
    publish(
        &reg,
        &Fixture {
            name: "leaf",
            version: "1.0.0",
            deps: vec![],
            build_deps: vec![],
            features: &[("wide", &[])],
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "mid",
            version: "1.0.0",
            deps: vec![("leaf", "1", &[])],
            build_deps: vec![],
            features: &[],
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "other",
            version: "1.0.0",
            deps: vec![("leaf", "1", &["wide"])],
            build_deps: vec![],
            features: &[],
            proc_macro: false,
        },
    );
    let manifest = consumer_project(
        &scratch.path().join("consumer"),
        &json!({ "mid": "1", "other": "1" }),
        &json!({}),
    );
    let requests = resolve_requests(cargo_home.path(), &manifest);
    let mid = request_for(&requests, "mid");
    let leaf_node = mid
        .dependency_subgraph
        .nodes
        .iter()
        .find(|node| node.crate_name.as_str() == "leaf")
        .expect("mid's subgraph carries leaf");
    assert_eq!(
        leaf_node.features_json.raw(),
        "[\"wide\"]",
        "mid's subgraph pins the widened leaf feature set"
    );

    unsafe { std::env::set_var("CARGO_HOME", cargo_home.path()) };
    let task = payload_for(&mid);
    smol::block_on(async {
        let (_root, workspace) = wrapper_workspace(&reg, &task).await;
        verify(&task, &workspace)
            .await
            .expect("widened grandchild context verifies");
    });
}

/// A crate consumed as both a build-dependency and a normal
/// dependency at different feature sets mints a host-side and a
/// target-side node; both wrapper shapes verify.
#[test]
fn a_build_dep_and_a_normal_dep_at_different_features_verify() {
    let _env = env_guard();
    let (cargo_home, reg) = registry_home();
    let scratch = tempfile::tempdir().unwrap();
    publish(
        &reg,
        &Fixture {
            name: "shared",
            version: "1.0.0",
            deps: vec![],
            build_deps: vec![],
            features: &[("norm", &[]), ("bs", &[])],
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "consumer-lib",
            version: "1.0.0",
            deps: vec![("shared", "1", &["norm"])],
            build_deps: vec![("shared", "1", &["bs"])],
            features: &[],
            proc_macro: false,
        },
    );
    let manifest = consumer_project(
        &scratch.path().join("consumer"),
        &json!({ "consumer-lib": "1" }),
        &json!({}),
    );
    let requests = resolve_requests(cargo_home.path(), &manifest);
    let target_side = request_for(&requests, "consumer-lib");
    let subgraph = &target_side.dependency_subgraph;
    let host_shared = subgraph
        .nodes
        .iter()
        .filter(|node| node.crate_name.as_str() == "shared" && node.host_side)
        .collect::<Vec<_>>();
    let target_shared = subgraph
        .nodes
        .iter()
        .filter(|node| node.crate_name.as_str() == "shared" && !node.host_side)
        .collect::<Vec<_>>();
    assert_eq!(
        host_shared.len(),
        1,
        "one host-side shared node: {subgraph:?}"
    );
    assert_eq!(host_shared[0].features_json.raw(), "[\"bs\"]");
    assert_eq!(target_shared[0].features_json.raw(), "[\"norm\"]");

    unsafe { std::env::set_var("CARGO_HOME", cargo_home.path()) };
    let task = payload_for(&target_side);
    smol::block_on(async {
        let (_root, workspace) = wrapper_workspace(&reg, &task).await;
        verify(&task, &workspace)
            .await
            .expect("split-side context verifies");
    });
}

/// A proc-macro's subtree lives host-side: the macro crate's task is
/// host-side and its dependencies pin under `[build-dependencies]`.
#[test]
fn a_proc_macro_subtree_verifies() {
    let _env = env_guard();
    let (cargo_home, reg) = registry_home();
    let scratch = tempfile::tempdir().unwrap();
    publish(
        &reg,
        &Fixture {
            name: "pm-dep",
            version: "1.0.0",
            deps: vec![],
            build_deps: vec![],
            features: &[],
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "pm",
            version: "1.0.0",
            deps: vec![("pm-dep", "1", &[])],
            build_deps: vec![],
            features: &[],
            proc_macro: true,
        },
    );
    let manifest = consumer_project(
        &scratch.path().join("consumer"),
        &json!({ "pm": "1" }),
        &json!({}),
    );
    let requests = resolve_requests(cargo_home.path(), &manifest);
    let pm = request_for(&requests, "pm");
    assert!(pm.host_side, "a proc-macro task is host-side");
    let task = payload_for(&pm);

    unsafe { std::env::set_var("CARGO_HOME", cargo_home.path()) };
    smol::block_on(async {
        let (_root, workspace) = wrapper_workspace(&reg, &task).await;
        verify(&task, &workspace)
            .await
            .expect("proc-macro subtree verifies");
    });
}

/// Review item 1's proof: on a host-equals-target triple the native
/// spelling dedups a shared unit into one cargo unit — the conversion
/// re-splits it into the resolver's twin shape, so the resolver's task
/// id, the native `--unit-graph` task id and the explicit `--target`
/// task id all agree for both sides of `shared`.
#[test]
fn native_dedup_shadow_mints_the_resolver_ids() {
    let _env = env_guard();
    let (cargo_home, reg) = registry_home();
    let scratch = tempfile::tempdir().unwrap();
    publish(
        &reg,
        &Fixture {
            name: "shared",
            version: "1.0.0",
            deps: vec![],
            build_deps: vec![],
            features: &[],
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "pm",
            version: "1.0.0",
            deps: vec![("shared", "1", &[])],
            build_deps: vec![],
            features: &[],
            proc_macro: true,
        },
    );
    let host = host_triple();
    let manifest = consumer_project(
        &scratch.path().join("consumer"),
        &json!({ "shared": "1", "pm": "1" }),
        &json!({}),
    );
    let requests = resolve_requests(cargo_home.path(), &manifest);
    let shared_target = requests
        .iter()
        .find(|request| request.crate_name.as_str() == "shared" && !request.host_side)
        .expect("target-side shared request");
    let shared_host = requests
        .iter()
        .find(|request| request.crate_name.as_str() == "shared" && request.host_side)
        .expect("host-side shared request");

    // The cargo home must carry a Cargo.lock and the fetched sources —
    // run the real fetch path first.
    unsafe { std::env::set_var("CARGO_HOME", cargo_home.path()) };
    let rustc = pinned_rustc_version();
    smol::block_on(async {
        let status = async_process::Command::new("cargo")
            .args(["fetch", "--manifest-path"])
            .arg(&manifest)
            .env("RUSTUP_TOOLCHAIN", active_toolchain())
            .status()
            .await
            .expect("cargo fetch");
        assert!(status.success(), "cargo fetch on the consumer failed");

        // Native spelling: no `--target` — cargo dedups `shared` into
        // one unit; the conversion must re-split the resolver's twins.
        let native = stow_cli::resolve_exact_dependency_graph(
            &manifest,
            "check",
            &[],
            None,
            manifest.parent().unwrap(),
            host.as_str(),
            rustc,
        )
        .await
        .expect("native unit graph");
        // Explicit spelling: `--target <host triple>` — cargo keeps the
        // two sides distinct; the conversion must agree anyway.
        // `--target` rides in `cargo_args` — `resolve_exact`'s `target`
        // parameter only names the triple cargo was given, it does not
        // spell the flag itself.
        let explicit = stow_cli::resolve_exact_dependency_graph(
            &manifest,
            "check",
            &[
                std::ffi::OsString::from("--target"),
                std::ffi::OsString::from(host.as_str()),
            ],
            Some(host.as_str()),
            manifest.parent().unwrap(),
            host.as_str(),
            rustc,
        )
        .await
        .expect("explicit-target unit graph");

        for (label, graph, target) in [
            ("native", &native, None),
            ("explicit", &explicit, Some(host.as_str())),
        ] {
            let units = graph
                .task_units(target, &host)
                .unwrap_or_else(|error| panic!("{label} unit graph converts: {error}"));
            let resolved = stow_types::unit_graph::resolved_task_graph(&units, rustc)
                .unwrap_or_else(|error| panic!("{label} unit graph resolves: {error}"));
            for (request, side) in [(&shared_target, false), (&shared_host, true)] {
                let identity = request.task_node_identity();
                let index = resolved
                    .nodes()
                    .iter()
                    .position(|node| node.identity == identity)
                    .unwrap_or_else(|| panic!("{label} graph mints {side}-side shared: {units:?}"));
                assert_eq!(
                    resolved.task_id(index).map(str::to_owned).as_deref(),
                    Some(request.task_id().expect("request task id").as_str()),
                    "{label} --unit-graph mints a different id for shared (host_side={side})"
                );
            }
        }
    });
}

/// An altered payload — one feature added on a grandchild node — fails
/// the build-stage check naming that node, and publish rejects a plan
/// claiming a different dependency identity than the closure verified.
#[test]
fn an_altered_subgraph_fails_the_context_check() {
    let _env = env_guard();
    let (cargo_home, reg) = registry_home();
    let scratch = tempfile::tempdir().unwrap();
    publish(
        &reg,
        &Fixture {
            name: "leaf",
            version: "1.0.0",
            deps: vec![],
            build_deps: vec![],
            features: &[("extra", &[])],
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "taskcrate",
            version: "1.0.0",
            deps: vec![("leaf", "1", &[])],
            build_deps: vec![],
            features: &[],
            proc_macro: false,
        },
    );
    let manifest = consumer_project(
        &scratch.path().join("consumer"),
        &json!({ "taskcrate": "1" }),
        &json!({}),
    );
    let requests = resolve_requests(cargo_home.path(), &manifest);
    let mut task = payload_for(&request_for(&requests, "taskcrate"));

    unsafe { std::env::set_var("CARGO_HOME", cargo_home.path()) };
    smol::block_on(async {
        let (_root, workspace) = wrapper_workspace(&reg, &task).await;
        verify(&task, &workspace)
            .await
            .expect("unaltered payload verifies");

        // One feature added to the grandchild: the dispatched context no
        // longer matches what the wrapper compiles, and the error names
        // the differing node.
        // One feature added to the grandchild, task_id re-derived so the
        // payload stays self-consistent — the dispatched context no
        // longer matches what the wrapper compiles, and the check must
        // name the node whose children diverged (the root's children ids
        // carry `leaf`'s identity).
        let mut altered = task.dependency_subgraph.clone();
        for node in &mut altered.nodes {
            if node.crate_name.as_str() == "leaf" {
                node.features_json =
                    stow_types::identity::FeaturesJson::canonicalize(vec!["extra".to_owned()])
                        .expect("features");
            }
        }
        task.dependency_subgraph = altered;
        task.task_id = task
            .dependency_subgraph
            .resolve(&task.task_node_identity())
            .expect("altered subgraph resolves")
            .task_id(0)
            .expect("resolved root")
            .to_owned();
        let error = verify(&task, &workspace)
            .await
            .expect_err("altered subgraph fails");
        assert!(
            format!("{error:#}").contains("leaf"),
            "the failure names the differing node: {error:#}"
        );
    });
}

/// Two contexts differing only in a build-dependency's features mint
/// different task ids — and the real sandboxed compile keys differ too,
/// so storage and lookup never merge them.
#[test]
fn differing_build_dep_features_change_the_compile_key() {
    let _env = env_guard();
    let (cargo_home, reg) = registry_home();
    let scratch = tempfile::tempdir().unwrap();
    publish(
        &reg,
        &Fixture {
            name: "bd",
            version: "1.0.0",
            deps: vec![],
            build_deps: vec![],
            features: &[("on", &[])],
            proc_macro: false,
        },
    );
    publish(
        &reg,
        &Fixture {
            name: "taskcrate",
            version: "1.0.0",
            deps: vec![],
            build_deps: vec![("bd", "1", &[])],
            features: &[],
            proc_macro: false,
        },
    );
    // Two consumers: one resolves bd plain, one widened — taskcrate's
    // build-dep context differs between them.
    let manifest_a = consumer_project(
        &scratch.path().join("consumer-a"),
        &json!({ "taskcrate": "1" }),
        &json!({}),
    );
    let requests_a = resolve_requests(cargo_home.path(), &manifest_a);
    // For the widened context, resolve a consumer whose OWN build-dep
    // also pulls bd["on"] — simplest: a second consumer crate in the
    // registry that build-depends on bd with the feature.
    publish(
        &reg,
        &Fixture {
            name: "widen",
            version: "1.0.0",
            deps: vec![],
            build_deps: vec![("bd", "1", &["on"])],
            features: &[],
            proc_macro: false,
        },
    );
    let manifest_b = consumer_project(
        &scratch.path().join("consumer-b"),
        &json!({ "taskcrate": "1", "widen": "1" }),
        &json!({}),
    );
    let requests_b = resolve_requests(cargo_home.path(), &manifest_b);
    let task_a = payload_for(&request_for(&requests_a, "taskcrate"));
    let task_b = payload_for(&request_for(&requests_b, "taskcrate"));
    assert_ne!(
        task_a.task_id, task_b.task_id,
        "differing build-dep contexts mint different task ids"
    );

    unsafe { std::env::set_var("CARGO_HOME", cargo_home.path()) };
    let (runtime, capture) = build_binaries();
    smol::block_on(async {
        let mut metadata: Vec<(String, String)> = Vec::new();
        for task in [&task_a, &task_b] {
            metadata.push(capture_build_dep_keys(&reg, task, &runtime, &capture).await);
        }
        assert_ne!(
            metadata[0].0, metadata[1].0,
            "different build-dep contexts give the task crate's build-script unit different compile keys"
        );
        assert_ne!(
            metadata[0].1, metadata[1].1,
            "the dep itself keys differently at a different feature set"
        );
    });
}

/// Run `task`'s sandboxed check phase under its real wrapper workspace
/// and the real capture chain, returning `(build-script compile key, bd
/// c_metadata)` as the captured rustc invocations record them.
///
/// `bd` is a build-dependency: it feeds the build script's rustc
/// invocation, never the lib's `--extern` set. The task crate's
/// build-script unit is where the build-dep context lands — its compile
/// key hashes the dep identities it was given.
async fn capture_build_dep_keys(
    reg: &Path,
    task: &BuildTaskPayload,
    runtime: &Path,
    capture: &Path,
) -> (String, String) {
    let (root, workspace) = wrapper_workspace(reg, task).await;
    let capture_dir = root.path().join(".stow-rustc-capture");
    std::fs::create_dir_all(&capture_dir).expect("capture dir");
    let workspace = workspace.with_capture_dir(capture_dir);
    task::fetch_workspace_dependencies(task, &workspace)
        .await
        .expect("fetch deps");
    let target_dir = TempDir::new().expect("target dir");
    let tools_dir = TempDir::new().expect("tools dir");
    let wrappers = stow_shim::materialize_wrapper_shims(tools_dir.path(), runtime, capture)
        .expect("materialize wrapper shims");
    let (mut collector, capture_command) = CaptureCollector::channel();
    let audit_log =
        heel::NetworkAuditLog::file(root.path().join("network-audit.jsonl")).expect("audit log");
    let setup = PhaseSetup {
        workspace: &workspace,
        wrappers: &wrappers,
        runtime_wrapper: runtime,
        capture_wrapper: capture,
        capture_command: &capture_command,
        audit_log: &audit_log,
        rustflags: "",
        consume_store: None,
    };
    let msvc = task::MsvcToolchain::resolve();
    let sandbox = phase_sandbox(&setup, target_dir.path(), &msvc)
        .await
        .expect("phase sandbox");
    let ipc_endpoint = sandbox
        .ipc_endpoint()
        .expect("sandbox ipc endpoint")
        .to_path_buf();
    let run = PhaseRun {
        setup: &setup,
        sandbox: &sandbox,
        ipc_endpoint: &ipc_endpoint,
        msvc: &msvc,
    };
    run_sandboxed_phase(
        &run,
        task,
        CargoSubcommand::Check,
        task::CargoInvocation::Task,
        &target_dir.path().join("target"),
        &mut collector,
    )
    .await
    .expect("sandboxed check phase");
    let records = collector.into_records().expect("capture records");
    let build_script = records
        .iter()
        .find(|record| record.crate_name == "build_script_build")
        .expect("build-script rustc invocation recorded");
    let bd = records
        .iter()
        .find(|record| record.crate_name == "bd")
        .expect("bd rustc invocation recorded");
    (build_script.compile_key.clone(), bd.c_metadata.clone())
}

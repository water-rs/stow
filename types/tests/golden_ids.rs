//! Golden task ids and compile keys for the dev profile (stow#1008).
//!
//! Every dev node's id and every dev unit's compile key were minted before
//! the profile became a field of the node identity. The literals below were
//! produced by that code; a change that moves one is a change to every
//! published record, and fails here.

use stow_types::artifact::{ArtifactKind, RustCrateType};
use stow_types::identity::{
    CrateName, CrateVersion, DependencyIdentity, FeaturesJson, TargetTriple, WireRustcVersion,
};
use stow_types::node_profile::NodeProfile;
use stow_types::platform::{PanicStrategy, Profile, StripLevel};
use stow_types::task_graph::{ResolvedTaskGraph, ResolvedTaskNode, TaskNodeIdentity};
use stow_types::upload_plan::{CompileKeyInputs, compute_compile_key};

fn identity(name: &str, features: &[&str], target: &str, host_side: bool) -> TaskNodeIdentity {
    TaskNodeIdentity {
        crate_name: CrateName::parse(name).unwrap(),
        version: CrateVersion::new(semver::Version::new(1, 2, 3)),
        features_json: FeaturesJson::canonicalize(
            features
                .iter()
                .map(|feature| (*feature).to_owned())
                .collect(),
        )
        .unwrap(),
        target: TargetTriple::parse(target).unwrap(),
        rustc_version: WireRustcVersion::parse("1.91.1").unwrap(),
        host_side,
        profile: NodeProfile::Dev,
    }
}

const fn node(identity: TaskNodeIdentity, dependencies: Vec<usize>) -> ResolvedTaskNode {
    ResolvedTaskNode {
        identity,
        explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
        dependencies,
    }
}

fn dev_profile() -> Profile {
    Profile {
        opt_level: "0".to_owned(),
        debuginfo: 2,
        debug_assertions: true,
        overflow_checks: true,
        panic: PanicStrategy::Unwind,
        strip: StripLevel::None,
    }
}

#[test]
fn dev_task_ids_keep_their_published_shapes() {
    let leaf = DependencyIdentity::from_task_ids(Vec::<&str>::new()).unwrap();
    let target = "x86_64-unknown-linux-gnu";
    let cases = [
        (identity("itoa", &[], target, false), GOLDEN_TARGET_LEAF),
        (
            identity("serde", &["derive", "std"], target, false),
            GOLDEN_TARGET_FEATURES,
        ),
        (
            identity("proc-macro2", &["proc-macro"], target, true),
            GOLDEN_HOST,
        ),
        (
            identity("itoa", &[], "aarch64-apple-darwin", false),
            GOLDEN_CROSS,
        ),
    ];
    for (identity, golden) in cases {
        assert_eq!(identity.task_id(&leaf), golden, "{}", identity.crate_name);
    }
}

#[test]
fn dev_task_ids_over_a_dependency_chain_keep_their_published_shapes() {
    let target = "x86_64-unknown-linux-gnu";
    let graph = ResolvedTaskGraph::resolve(vec![
        node(identity("serde", &["derive"], target, false), vec![1, 2]),
        node(identity("serde_derive", &[], target, true), vec![2]),
        node(identity("proc-macro2", &[], target, true), vec![]),
    ])
    .unwrap();
    let ids: Vec<&str> = (0..3).map(|index| graph.task_id(index).unwrap()).collect();
    assert_eq!(ids, GOLDEN_CHAIN);
}

#[test]
fn dev_compile_keys_keep_their_published_values() {
    let profile = dev_profile();
    let key = compute_compile_key(&CompileKeyInputs {
        crate_name: "itoa",
        crate_version: "1.0.15",
        target: "x86_64-unknown-linux-gnu",
        rustc_version: "1.91.1",
        profile: &profile,
        crate_types: &[RustCrateType::Lib],
        emit: &[
            "dep-info".to_owned(),
            "link".to_owned(),
            "metadata".to_owned(),
        ],
        features_json: "[]",
        dependency_c_metadata_json: "[]",
        kind: &ArtifactKind::Rlib,
        embed_metadata: None,
        cfgs: &[],
        embed_bitcode: false,
        link_options: &[],
        git_source: None,
        extra_codegen: &[],
    })
    .unwrap();
    assert_eq!(key, GOLDEN_COMPILE_KEY);
}

const GOLDEN_TARGET_LEAF: &str = "itoa-1.2.3-d53d18c23212ea7b6300594bb89bce60218f6eff2b9d628b8cc42d3e79bbd5ab-x86_64_unknown_linux_gnu-1.91.1-dff949149c544832f5c9c33f5d66d9580315b37862ddea7df01ba2c678d988f0d";
const GOLDEN_TARGET_FEATURES: &str = "serde-1.2.3-46d4660bc866f88867e00ed8433b7170c29b00c9779e2618e99aaea015bc8a38-x86_64_unknown_linux_gnu-1.91.1-dff949149c544832f5c9c33f5d66d9580315b37862ddea7df01ba2c678d988f0d";
const GOLDEN_HOST: &str = "proc-macro2-1.2.3-229265bccdfcb5914073a8c224051eae87fb33874abfac39858364ba1a0ec74b-x86_64_unknown_linux_gnu-1.91.1-dff949149c544832f5c9c33f5d66d9580315b37862ddea7df01ba2c678d988f0d-host";
const GOLDEN_CROSS: &str = "itoa-1.2.3-d53d18c23212ea7b6300594bb89bce60218f6eff2b9d628b8cc42d3e79bbd5ab-aarch64_apple_darwin-1.91.1-dff949149c544832f5c9c33f5d66d9580315b37862ddea7df01ba2c678d988f0d";
const GOLDEN_CHAIN: [&str; 3] = [
    "serde-1.2.3-b22c699b82ec5a88f13ef34e19a13e435db5771b7310bd3767773779e3e1af88-x86_64_unknown_linux_gnu-1.91.1-df78ff2bd9ac2daa9870e76847469cf7c8448fcebaa59a000450c58a1ad0be530",
    "serde_derive-1.2.3-d53d18c23212ea7b6300594bb89bce60218f6eff2b9d628b8cc42d3e79bbd5ab-x86_64_unknown_linux_gnu-1.91.1-da3653d90966b7abb800118b88723cf4a7b343afae610d09c348fc4912adc871d-host",
    "proc-macro2-1.2.3-d53d18c23212ea7b6300594bb89bce60218f6eff2b9d628b8cc42d3e79bbd5ab-x86_64_unknown_linux_gnu-1.91.1-dff949149c544832f5c9c33f5d66d9580315b37862ddea7df01ba2c678d988f0d-host",
];
const GOLDEN_COMPILE_KEY: &str = "952d127eb4f18a1bcef780f6be8fdefbed8591b2f3766175607d7d33e61dded4";

/// A non-dev profile mints a distinct id: the profile is part of the
/// identity, so the same unit under it is a different node.
#[test]
fn another_profile_is_a_different_node() {
    let leaf = DependencyIdentity::from_task_ids(Vec::<&str>::new()).unwrap();
    let target = "x86_64-unknown-linux-gnu";
    let dev = identity("itoa", &[], target, false);
    assert_eq!(dev.task_id(&leaf), GOLDEN_TARGET_LEAF);
    let mut seen = std::collections::BTreeSet::new();
    for profile in NodeProfile::ALL {
        for host_side in [false, true] {
            let mut node = identity("itoa", &[], target, host_side);
            node.profile = profile;
            let id = node.task_id(&leaf);
            assert_eq!(id.ends_with(profile.name()), !profile.is_dev(), "{id}");
            assert!(seen.insert(id));
        }
    }
}

/// A node's profile rides the compact subgraph wire and re-derives the
/// same ids; a dev node writes nothing for it.
#[test]
fn the_profile_survives_the_subgraph_wire() {
    let target = "x86_64-unknown-linux-gnu";
    let mut release_dep = identity("itoa", &[], target, false);
    release_dep.profile = NodeProfile::Release;
    let graph = ResolvedTaskGraph::resolve(vec![
        node(identity("serde", &[], target, false), vec![1, 2]),
        node(release_dep, vec![]),
        node(identity("ryu", &[], target, false), vec![]),
    ])
    .unwrap();
    let subgraph = stow_types::api::TaskSubgraph::from_resolved(&graph, 0).unwrap();
    let wire = serde_json::to_string(&subgraph).unwrap();
    assert_eq!(wire.matches("\"p\":\"release\"").count(), 1, "{wire}");
    assert_eq!(wire.matches("\"p\":").count(), 1, "{wire}");
    let back: stow_types::api::TaskSubgraph = serde_json::from_str(&wire).unwrap();
    let resolved = back
        .resolve(
            &graph.nodes()[0].identity,
            stow_types::public_cache::ExplicitSpelling::KeysAsNative,
        )
        .unwrap();
    assert_eq!(resolved.task_id(0), graph.task_id(0));
}

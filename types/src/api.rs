//! HTTP wire types exchanged between the CLI, the edge worker, the
//! scheduler Durable Object, and trusted CI.
//!
//! Field docs describe the wire meaning of each payload; the validated
//! identity newtypes from [`crate::identity`] carry the invariants.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

use crate::artifact::{ArtifactKind, RustCrateType};
use crate::glibc::GlibcVersion;
use crate::identity::{
    CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, DependencyIdentity, FeaturesJson,
    TargetTriple, WireRustcVersion,
};
use crate::index::ArtifactIndexRow;
use crate::platform::Profile;
use crate::stow_error;
use crate::task_graph::{ResolvedTaskGraph, ResolvedTaskNode, TaskNodeIdentity};
use std::collections::BTreeSet;

/// The compilation target triples the trusted CI build fleet covers.
///
/// The runner map in `build-crate.yml` builds for exactly this set, so
/// `POST /api/v1/requests` expands every requested crate onto each of
/// them. The set is `WaterUI`'s shipping matrix (water-rs/stow#90);
/// the ESP32 `*-espidf` triples stay out because they need a forked
/// toolchain. Discontinued platforms stay out too — Intel Macs
/// (`x86_64-apple-darwin`, dropped by macOS 27), x86 Android, and
/// 32-bit ARM Android.
pub const CI_TARGET_TRIPLES: &[&str] = &[
    "aarch64-apple-darwin",
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "aarch64-linux-android",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "wasm32-unknown-unknown",
];

/// Whether trusted CI has a runner that can build this target.
///
/// A target outside the set resolves to an empty `runs-on` in
/// `build-crate.yml`, and the dispatched run then dies before any job
/// starts — no job, no log, no completion report, and the queue slot spent
/// until the stale-dispatch sweep reclaims it. Every path that can put a
/// task in the queue checks this first.
#[must_use]
pub fn is_ci_target(target: &str) -> bool {
    CI_TARGET_TRIPLES.contains(&target)
}

/// The GitHub Actions runner pool a CI target builds on.
///
/// Mirrors the `runs-on` map in `build-crate.yml`: `macos-14` for the
/// Apple targets, `windows-latest` for the MSVC targets, `ubuntu-latest`
/// for the rest. The scheduler caps dispatches per family because the
/// pools are sized very differently — the org's macOS pool is the
/// smallest — and starts the slow Windows legs of a wave first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RunnerFamily {
    /// `ubuntu-latest` — also hosts the Android and wasm builds.
    Linux,
    /// `macos-14` — the smallest pool in the org's runner fleet.
    MacOs,
    /// `windows-latest` — the slowest legs of a full wave.
    Windows,
}

impl RunnerFamily {
    /// Every family, for iteration.
    pub const ALL: [Self; 3] = [Self::Linux, Self::MacOs, Self::Windows];

    /// The [`CI_TARGET_TRIPLES`] members that build on this family's
    /// runner.
    #[must_use]
    pub const fn targets(self) -> &'static [&'static str] {
        match self {
            Self::Linux => &[
                "aarch64-linux-android",
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "wasm32-unknown-unknown",
            ],
            Self::MacOs => &[
                "aarch64-apple-darwin",
                "aarch64-apple-ios",
                "aarch64-apple-ios-sim",
            ],
            Self::Windows => &["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"],
        }
    }

    /// The triple host-gated units (`proc-macro`, `build-dependencies`,
    /// `build.rs`) compile on for builds dispatched to this family's runner —
    /// the runner's own platform. macOS runners are arm64.
    #[must_use]
    pub const fn host_triple(self) -> &'static str {
        match self {
            Self::Linux => "x86_64-unknown-linux-gnu",
            Self::MacOs => "aarch64-apple-darwin",
            Self::Windows => "x86_64-pc-windows-msvc",
        }
    }
}

/// Which runner family `build-crate.yml` dispatches this target to, or
/// `None` for a target its `runs-on` map does not name.
#[must_use]
pub fn runner_family(target: &str) -> Option<RunnerFamily> {
    RunnerFamily::ALL
        .into_iter()
        .find(|family| family.targets().contains(&target))
}

/// The task the scheduler dispatches to `stow-build`, carried verbatim as the
/// `workflow_dispatch` input of the trusted build workflow.
///
/// Simple: just crate + target. CI figures out features/deps via `cargo metadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BuildTaskPayload {
    /// Opaque scheduler task identifier (blake3 of identity tuple).
    pub task_id: String,
    /// Which queue attempt this dispatch carries. The scheduler bumps a
    /// row's attempt every time a re-request resurrects it out of
    /// failed/completed, and the completion path only applies a report
    /// whose attempt matches the row's live one — a stale or duplicate
    /// report is a conflict, never a silent overwrite of a newer
    /// attempt's state.
    /// Defaults to 0 so a payload serialized before the field existed still
    /// decodes; attempt 0 matches no row (attempts start at 1), so such a
    /// report is rejected rather than applied blindly.
    #[serde(default)]
    pub attempt: u32,
    /// Crate name as known to crates.io.
    pub crate_name: CrateName,
    /// Exact crate version to build.
    pub version: CrateVersion,
    /// Canonicalized features list (sorted, deduplicated).
    pub features_json: FeaturesJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version (e.g. `"1.83.0"`).
    pub rustc_version: WireRustcVersion,
    /// When true, the trusted build runner keeps the bundled `Cargo.lock` from
    /// the crates.io tarball instead of removing it — an operator escape
    /// hatch on hand-submitted tasks; every resolver-emitted task carries
    /// false. Defaults to false to preserve the "build against
    /// latest semver-compatible deps" behavior.
    #[serde(default)]
    pub preserve_lockfile: bool,
    /// Whether the task builds the crate as a host-side unit — the shape a
    /// consumer's build compiles a proc-macro or build dependency at
    /// (`EnqueueRequest::host_side`). Host-side tasks declare the crate as
    /// a build dependency of the generated wrapper package and build every
    /// consumer shape (native and `--target` invocations). Defaults to
    /// false so payloads serialized before the field existed still decode
    /// as target-side tasks.
    #[serde(default)]
    pub host_side: bool,
    /// The task's whole dependency subgraph: the graph inputs of every
    /// transitive dependency node plus the root's direct-dependency
    /// indexes (stow#588). The generated wrapper package pins every node
    /// (`=<version>`, the node's own feature set, in the manifest section
    /// matching its side) so the wrapper's resolve reproduces the
    /// dispatched context exactly — a direct-pin-only manifest would let
    /// a transitively widened dep resolve narrower than its published
    /// identity.
    ///
    /// The wire form carries inputs only; identities are always
    /// re-derived by [`ResolvedTaskGraph::resolve`], and
    /// [`Self::verified_dependency_graph`] fails unless the derived root
    /// id equals `task_id`.
    pub dependency_subgraph: TaskSubgraph,
}

/// GitHub caps every `workflow_dispatch` call's inputs at 65,535
/// characters together.
///
/// The serialized [`BuildTaskPayload`] is by far the largest input, so
/// producers encode through [`BuildTaskPayload::encode_dispatch_task`]
/// and fail before GitHub does.
pub const DISPATCH_INPUT_LIMIT: usize = 65_535;

/// A build task's dependency subgraph in compact wire form (stow#588).
///
/// Carries only the graph inputs a [`ResolvedTaskGraph::resolve`] needs:
/// crate, version, features and side per node, plus dep-edge indexes —
/// rustc and target are derived, never carried. rustc is the task's own
/// `rustc_version`; a node's target is the task's `target` for a
/// target-side node and the runner family's host triple
/// (`runner_family(task.target).host_triple()`) for a host-side node.
/// That matches the resolver, which keys every host unit's
/// `platform` at `CompileKind::Host` mapped to the runner family's host
/// triple (`resolver/src/emit.rs`), and `EnqueueDependency::target`,
/// which carries the dep node's platform verbatim.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TaskSubgraph {
    /// The indexes into `nodes` of the task node's direct dependencies.
    /// Field renames keep the wire small: the payload rides one
    /// `workflow_dispatch` input and the cap above is shared.
    #[serde(rename = "r", default, skip_serializing_if = "Vec::is_empty")]
    pub root_deps: Vec<u32>,
    /// Every transitive dependency node, in a stable order (the
    /// dependency's own nodes; the task's node itself is implicit — its
    /// identity comes from the [`BuildTaskPayload`] fields).
    #[serde(rename = "n")]
    pub nodes: Vec<SubgraphNode>,
}

/// One transitive dependency node's graph inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SubgraphNode {
    /// The dependency's crate name as known to crates.io.
    #[serde(rename = "n")]
    pub crate_name: CrateName,
    /// The version its task published at.
    #[serde(rename = "v")]
    pub version: CrateVersion,
    /// The resolved feature set the node compiles with.
    #[serde(rename = "f")]
    pub features_json: FeaturesJson,
    /// Whether the node lives on the host side of the consumer's unit
    /// graph.
    #[serde(rename = "h", default, skip_serializing_if = "std::ops::Not::not")]
    pub host_side: bool,
    /// Indexes into [`TaskSubgraph::nodes`] naming this node's direct
    /// dependencies.
    #[serde(rename = "d", default, skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<u32>,
}

impl TaskSubgraph {
    /// Build the wire form from a resolved task graph: `root` is the
    /// index of the task's own node in `graph.nodes()`; the subgraph is
    /// the root's whole transitive dependency closure — covered nodes
    /// included, since the builder's pins must reproduce them too.
    ///
    /// Wire node order is the resolved graph's canonical order
    /// restricted to the reachable set, so `resolve` reproduces the same
    /// indexes.
    ///
    /// # Errors
    /// `root` out of range, or a dep index that does not fit the wire's
    /// `u32` (a graph that large cannot ride a dispatch input anyway).
    pub fn from_resolved(graph: &ResolvedTaskGraph, root: usize) -> crate::error::Result<Self> {
        let nodes = graph.nodes();
        if root >= nodes.len() {
            return Err(stow_error!(
                "task subgraph root index {root} out of range ({} nodes)",
                nodes.len()
            ));
        }
        // The task's dependency closure, minus the root itself, in graph
        // order. Wire index = rank inside this list.
        let mut reachable = BTreeSet::new();
        let mut frontier = nodes[root].dependencies.clone();
        while let Some(next) = frontier.pop() {
            if reachable.insert(next) {
                frontier.extend(nodes[next].dependencies.iter().copied());
            }
        }
        // Graph index → wire rank — one lookup per edge, not a scan of
        // the reachable set per edge.
        let wire_ranks: BTreeMap<usize, u32> = reachable
            .iter()
            .enumerate()
            .map(|(rank, &index)| {
                u32::try_from(rank)
                    .map(|rank| (index, rank))
                    .map_err(|_| stow_error!("task subgraph edge index {rank} does not fit u32"))
            })
            .collect::<crate::error::Result<BTreeMap<usize, u32>>>()?;
        let wire_index = |graph_index: usize| -> crate::error::Result<u32> {
            wire_ranks.get(&graph_index).copied().ok_or_else(|| {
                stow_error!(
                    "task subgraph edge {graph_index} escapes the root's dependency closure"
                )
            })
        };
        let root_deps = nodes[root]
            .dependencies
            .iter()
            .map(|&dep| wire_index(dep))
            .collect::<crate::error::Result<Vec<u32>>>()?;
        let mut out = Vec::with_capacity(reachable.len());
        for index in &reachable {
            let node = &nodes[*index];
            out.push(SubgraphNode {
                crate_name: node.identity.crate_name.clone(),
                version: node.identity.version.clone(),
                features_json: node.identity.features_json.clone(),
                host_side: node.identity.host_side,
                deps: node
                    .dependencies
                    .iter()
                    .map(|&dep| wire_index(dep))
                    .collect::<crate::error::Result<Vec<u32>>>()?,
            });
        }
        Ok(Self {
            root_deps,
            nodes: out,
        })
    }

    /// Expand the wire inputs into the node list
    /// [`ResolvedTaskGraph::resolve`] consumes: index 0 is the task's own
    /// node (`root`), then every [`SubgraphNode`] in wire order.
    ///
    /// # Errors
    /// `runner_family(root.target)` returning `None` — the subgraph's
    /// host-side nodes key at the family's host triple — or a wire
    /// index past the node list.
    pub fn resolve(&self, root: &TaskNodeIdentity) -> crate::error::Result<ResolvedTaskGraph> {
        let host_triple = runner_family(root.target.as_str())
            .ok_or_else(|| {
                stow_error!(
                    "task target `{}` maps to no runner family — host-side subgraph nodes have no host triple to key on",
                    root.target
                )
            })?
            .host_triple();
        let mut nodes = Vec::with_capacity(self.nodes.len() + 1);
        nodes.push(ResolvedTaskNode {
            identity: root.clone(),
            dependencies: self
                .root_deps
                .iter()
                .map(|&dep| {
                    // Wire index → resolved index: `resolve` inserts the
                    // root first, so every wire node lands at index + 1,
                    // the same shift a `SubgraphNode::deps` entry gets.
                    let index = usize::try_from(dep).map_err(|error| stow_error!("{error}"))?;
                    Ok(index + 1)
                })
                .collect::<crate::error::Result<Vec<usize>>>()?,
        });
        for node in &self.nodes {
            nodes.push(ResolvedTaskNode {
                identity: TaskNodeIdentity {
                    crate_name: node.crate_name.clone(),
                    version: node.version.clone(),
                    features_json: node.features_json.clone(),
                    target: TargetTriple::parse(if node.host_side {
                        host_triple
                    } else {
                        root.target.as_str()
                    })?,
                    rustc_version: root.rustc_version.clone(),
                    host_side: node.host_side,
                },
                dependencies: node
                    .deps
                    .iter()
                    .map(|&dep| {
                        let index = usize::try_from(dep).map_err(|error| stow_error!("{error}"))?;
                        Ok(index + 1)
                    })
                    .collect::<crate::error::Result<Vec<usize>>>()?,
            });
        }
        ResolvedTaskGraph::resolve(nodes)
    }
}

impl BuildTaskPayload {
    /// The task's own node identity, the fields `task_id` commits to.
    #[must_use]
    pub fn task_node_identity(&self) -> TaskNodeIdentity {
        TaskNodeIdentity {
            crate_name: self.crate_name.clone(),
            version: self.version.clone(),
            features_json: self.features_json.clone(),
            target: self.target.clone(),
            rustc_version: self.rustc_version.clone(),
            host_side: self.host_side,
        }
    }

    /// Re-derive the task's dependency graph from the carried subgraph.
    ///
    /// # Errors
    /// Fails when the subgraph cannot resolve, and unless the derived
    /// root's task id equals `task_id` — the payload's own digest check.
    pub fn verified_dependency_graph(&self) -> crate::error::Result<ResolvedTaskGraph> {
        let graph = self
            .dependency_subgraph
            .resolve(&self.task_node_identity())?;
        let derived = graph
            .task_id(0)
            .ok_or_else(|| stow_error!("resolved dependency subgraph has no root node"))?;
        if derived != self.task_id {
            return Err(stow_error!(
                "task {} {} ({}): payload task_id `{}` does not match the derived root id `{derived}` of its dependency subgraph",
                self.crate_name,
                self.version,
                self.target,
                self.task_id,
            ));
        }
        Ok(graph)
    }

    /// Serialize the payload for dispatch, failing before GitHub's
    /// per-invocation inputs cap does.
    ///
    /// # Errors
    /// Serialization failure, or an encoded payload over
    /// [`DISPATCH_INPUT_LIMIT`] — the error names the crate, version,
    /// target, node count and encoded length.
    pub fn encode_dispatch_task(&self) -> crate::error::Result<String> {
        let encoded = serde_json::to_string(self)
            .map_err(|error| stow_error!("serialize build task payload: {error}"))?;
        if encoded.len() > DISPATCH_INPUT_LIMIT {
            return Err(stow_error!(
                "build task {} {} on {} encodes to {} characters across {} dependency nodes — over the {}-character workflow_dispatch input cap",
                self.crate_name,
                self.version,
                self.target,
                encoded.len(),
                self.dependency_subgraph.nodes.len(),
                DISPATCH_INPUT_LIMIT,
            ));
        }
        Ok(encoded)
    }
}

/// One artifact a trusted build published.
///
/// The element of the `Vec<ArtifactRecord>` the publish stage serializes
/// into the signed `records-<rustc>-<task_id hash>` GHCR artifact once the
/// build, re-hash, validation, sign, and push have all succeeded. Nothing
/// POSTs it anywhere — `index sync` mirrors the verified records into the
/// edge's D1 `artifacts` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactRecord {
    /// Stable hash of the trusted build's exact rustc invocation identity.
    pub compile_key: String,
    /// Cargo's `-C metadata` value — part of the composite cache lookup key.
    pub c_metadata: CMetadata,
    /// Cargo's `-C extra-filename` suffix from the trusted build.
    pub extra_filename: String,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Rustc version string (e.g., "1.83.0").
    pub rustc_version: WireRustcVersion,
    /// Exact profile observed from the captured rustc invocation.
    pub profile: Profile,
    /// Exact `--emit` modes observed from the captured rustc invocation.
    /// Must be strictly sorted and deduplicated.
    pub emit: Vec<String>,
    /// Crate name (for analytics/display).
    pub crate_name: CrateName,
    /// Crate version.
    pub version: CrateVersion,
    /// JSON-encoded feature set; canonicalized (sorted + deduplicated).
    pub features_json: FeaturesJson,
    /// JSON-encoded dependency `c_metadata` identities captured from rustc
    /// --extern inputs; sorted by `(crate_name, c_metadata)`.
    pub dependency_c_metadata_json: DependencyCMetadataJson,
    /// The Merkle dependency digest the artifact was built under
    /// (stow#588). `None` on archive rows recorded before the digest
    /// existed — `None` answers no contextual coverage query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_identity: Option<DependencyIdentity>,
    /// OCI reference (e.g., "ghcr.io/water-rs/stow-cache:serde.1.0.0-...").
    pub oci_reference: String,
    /// OCI manifest digest (e.g., "sha256:...").
    pub oci_digest: String,
    /// Whether this artifact has native (C/C++) components.
    pub has_native: bool,
    /// Primary artifact kind for OCI naming and analytics.
    pub artifact_kind: ArtifactKind,
    /// Declared Rust crate types from cargo metadata / rustc args.
    pub crate_types: Vec<RustCrateType>,
    /// Artifact size in bytes: the sum of the uncompressed output files.
    pub artifact_size: u64,
    /// Digest (`sha256:…`) of the assembled bundle tar the trusted publish
    /// stage pushed as the `<tag>.bundle` layer. The edge streams exactly
    /// this blob to CLIs; it is what the byte path is keyed and fetched by.
    pub bundle_digest: String,
    /// Size in bytes of the bundle tar — the exact `content-length` of a
    /// bundle GET and the input to the Cache API size gate.
    pub bundle_size: u64,
    /// Wall-clock milliseconds the captured rustc invocation took — what a
    /// served hit on this artifact is credited as CPU time saved.
    pub compile_millis: u64,
    /// The unit shape the builder recorded for this artifact — which side
    /// of the host/target boundary it serves, the cargo invocation
    /// spelling that produced it, and whether it links. `None` only on
    /// records serialized before the field existed; the coverage checks
    /// and the dependency gate treat shapeless rows as covering nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_shape: Option<crate::public_cache::UnitShape>,
    /// Lowest glibc the artifact's ELF members can `dlopen` against — the
    /// highest `GLIBC_x.y` in their version-needed entries, measured at
    /// publish. `None` for non-ELF payloads and for artifacts with no glibc
    /// dependency; only an ELF built for a newer glibc carries `Some`, and
    /// that is exactly the case a client must refuse before downloading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub min_glibc: Option<GlibcVersion>,
}

/// Request body for scheduler task submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnqueueRequest {
    /// Crate name to build.
    pub crate_name: CrateName,
    /// Crate version to build.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Total download count from crates.io (used for priority calculation).
    pub downloads: u64,
    /// Source of the enqueue request.
    pub source: EnqueueSource,
    /// The node's whole transitive dependency closure in compact wire
    /// form — the request's single context source (stow#588). The
    /// direct-dependency edges [`EnqueueRequest::depends_on`] derives
    /// are only the first hop: a covered dep's own children still have
    /// to resolve at the same identities inside the builder's generated
    /// package, and covered nodes are never enqueued, so the scheduler
    /// cannot rebuild this closure from its own stored edges. No
    /// default: the subgraph is derived from an actual resolved graph.
    pub dependency_subgraph: TaskSubgraph,
    /// Whether the node compiles for the build host (a proc-macro, build
    /// dependency, or build-script unit) rather than for the consumer's
    /// target. Host-side tasks mint on the runner family's host triple and
    /// are built the way a consumer compiles them as host units. Defaults
    /// to false so requests serialized before the field existed still
    /// decode as target-side tasks.
    #[serde(default)]
    pub host_side: bool,
    /// Mirrors `BuildTaskPayload::preserve_lockfile`. Set to true for binary-
    /// derived overlay enqueues so the trusted build resolves transitive deps
    /// against the binary's published `Cargo.lock`.
    #[serde(default)]
    pub preserve_lockfile: bool,
}

/// One dependency a task must wait on: the dep's own node identity,
/// at the platform the dep's task mints on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnqueueDependency {
    /// Dependency crate name.
    pub crate_name: CrateName,
    /// Dependency crate version.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Whether the dependent needs this dep as a host-side unit
    /// (`EnqueueRequest::host_side`). The dep's node mints on the runner
    /// family's host triple and must publish the unit shapes consumers
    /// compile host units at. Defaults to false — a target-side dep.
    #[serde(default)]
    pub host_side: bool,
    /// The dep's own dependency digest — the Merkle context its task id
    /// commits to (stow#588). No default: the digest is derived from the
    /// dep's actual resolved subgraph.
    pub dependency_identity: DependencyIdentity,
}

impl EnqueueDependency {
    /// The dep node's canonical task id — its identity tuple plus its
    /// own dependency-context digest.
    #[must_use]
    pub fn task_id(&self) -> String {
        TaskNodeIdentity {
            crate_name: self.crate_name.clone(),
            version: self.version.clone(),
            features_json: self.features_json.clone(),
            target: self.target.clone(),
            rustc_version: self.rustc_version.clone(),
            host_side: self.host_side,
        }
        .task_id(&self.dependency_identity)
    }
}

impl EnqueueRequest {
    /// The node's own task identity, the fields `task_id` commits to.
    #[must_use]
    pub fn task_node_identity(&self) -> TaskNodeIdentity {
        TaskNodeIdentity {
            crate_name: self.crate_name.clone(),
            version: self.version.clone(),
            features_json: self.features_json.clone(),
            target: self.target.clone(),
            rustc_version: self.rustc_version.clone(),
            host_side: self.host_side,
        }
    }

    /// The node's resolved dependency graph, derived from the carried
    /// subgraph — the request's single context source (stow#588).
    ///
    /// # Errors
    /// The subgraph cannot resolve (bad index, cycle, unmapped target).
    pub fn resolved_dependency_graph(&self) -> crate::error::Result<ResolvedTaskGraph> {
        self.dependency_subgraph.resolve(&self.task_node_identity())
    }

    /// The Merkle digest committing to this node's dependency subgraph —
    /// the segment its canonical task id carries, re-derived from the
    /// carried subgraph rather than stored (stow#588).
    ///
    /// # Errors
    /// The subgraph cannot resolve, or yields no root digest.
    pub fn dependency_identity(&self) -> crate::error::Result<DependencyIdentity> {
        self.resolved_dependency_graph()?
            .dependency_identity(0)
            .cloned()
            .ok_or_else(|| stow_error!("resolved dependency graph yields no root digest"))
    }

    /// The node's canonical task id — the identity tuple plus the
    /// derived dependency-context digest (stow#588).
    ///
    /// # Errors
    /// The subgraph cannot resolve.
    pub fn task_id(&self) -> crate::error::Result<String> {
        Ok(self
            .task_node_identity()
            .task_id(&self.dependency_identity()?))
    }

    /// The task's own dependencies — the root node's direct-dependency
    /// edges, each named at the dep's own (target, rustc) identity and
    /// carrying the dep's derived digest. Derived from the carried
    /// subgraph, never stored (stow#588).
    ///
    /// # Errors
    /// The subgraph cannot resolve.
    pub fn depends_on(&self) -> crate::error::Result<Vec<EnqueueDependency>> {
        let graph = self.resolved_dependency_graph()?;
        let nodes = graph.nodes();
        nodes[0]
            .dependencies
            .iter()
            .map(|&dep| {
                let node = &nodes[dep];
                Ok(EnqueueDependency {
                    crate_name: node.identity.crate_name.clone(),
                    version: node.identity.version.clone(),
                    features_json: node.identity.features_json.clone(),
                    target: node.identity.target.clone(),
                    rustc_version: node.identity.rustc_version.clone(),
                    host_side: node.identity.host_side,
                    dependency_identity: graph.dependency_identity(dep).cloned().ok_or_else(
                        || stow_error!("resolved dependency graph yields no digest for node {dep}"),
                    )?,
                })
            })
            .collect()
    }
}

/// Where an enqueue request originated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum EnqueueSource {
    /// Watcher detected a crate version update.
    CrateUpdate,
    /// Watcher detected a new rustc stable release.
    RustcUpdate,
    /// Edge reported a cache miss.
    CacheMiss,
    /// A Turnstile-verified human submitted `POST /api/v1/requests`. Tasks
    /// enqueued with this source land in the scheduler's human lane.
    HumanRequest,
}

/// Admission ticket the edge mints for one canonical enqueue task when a
/// public request misses the cache.
///
/// Returned by `POST /api/v1/admissions` for each node the catalog does
/// not cover — the fetch path stays cheap. The client redeems the
/// ticket by solving its proof-of-work and posting an [`EnqueueTicket`]
/// to `POST /api/v1/enqueue`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct EnqueueAdmission {
    /// Canonical scheduler task id (blake3-derived identity string).
    pub task_id: String,
    /// Server-issued challenge — the hex HMAC-SHA256 over
    /// `task_id ‖ canonical request JSON ‖ issue_minute` under the edge's
    /// `STOW_POW_CHALLENGE_SECRET`. Opaque to clients; accepted during its
    /// issue minute and the minute after it.
    pub challenge: String,
    /// Leading zero bits the client's
    /// `blake3(task_id ‖ challenge ‖ nonce)` digest must show for
    /// `/enqueue` to accept the ticket. `0` means the queue is shallow
    /// enough that admission is free.
    pub difficulty: u32,
    /// The canonical enqueue request this admission authorizes. The edge is
    /// stateless: the client echoes `request` back in its ticket and
    /// `/api/v1/enqueue` forwards it to the scheduler after verifying the
    /// challenge binds it.
    pub request: EnqueueRequest,
}

/// Request body for `POST /api/v1/enqueue`: the redemption of an
/// [`EnqueueAdmission`].
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EnqueueTicket {
    /// Canonical task id carried by the admission.
    pub task_id: String,
    /// The admission's server-issued challenge.
    pub challenge: String,
    /// Client-computed nonce such that
    /// `blake3(task_id ‖ challenge ‖ nonce)` has at least the required
    /// number of leading zero bits.
    pub nonce: u64,
    /// The canonical enqueue request from the admission. The edge
    /// recomputes the challenge HMAC over this payload and forwards it to
    /// the scheduler — no server-side request lookup.
    pub request: EnqueueRequest,
}

/// Request body for `POST /api/v1/admissions`: the misses a client's
/// local index resolution found, plus the resolved graph the edge
/// expands into enqueue tasks.
///
/// The client's dependency graph never leaves the machine in raw form for
/// *coverage* — this call happens only when the local resolver already
/// decided entries are uncovered, and the edge re-checks coverage against
/// the catalog before minting anything.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdmissionRequest {
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Direct-dep entries the local resolver found uncovered.
    pub entries: Vec<DependencyGraphEntry>,
    /// The client's resolved transitive graph.
    #[serde(default)]
    pub expanded_entries: Vec<ResolvedDependencyGraphEntry>,
}

/// Canonical scheduler task identity — the blake3-derived id `enqueue`
/// deduplicates on and `build-crate.yml`'s `run-name` carries.
///
/// The workflow-run webhook maps a finished run back to the task by this
/// id. It lives in this crate so `stow-admin`'s manual driver mints
/// exactly the ids the scheduler queue assigns.
///
/// `host_side` carries the unit's compile side: the same crate
/// legitimately exists as both a target-side node and a host-side node at
/// the host triple — a `-host` suffix distinguishes them while leaving
/// every pre-existing target-side id spelled exactly as before.
#[must_use]
pub fn task_id(
    crate_name: &str,
    version: &str,
    features_json: &str,
    target: &str,
    rustc_version: &str,
    host_side: bool,
) -> String {
    let base = task_id_prefix(crate_name, version, features_json, target, rustc_version);
    if host_side {
        format!("{base}-host")
    } else {
        base
    }
}

/// The `<crate>-<version>-<features hash>-<target>-<rustc>` prefix every
/// task id shares — [`task_id`] appends `-host`,
/// [`crate::task_graph::TaskNodeIdentity::task_id`] inserts the
/// dependency digest before it.
pub(crate) fn task_id_prefix(
    crate_name: &str,
    version: &str,
    features_json: &str,
    target: &str,
    rustc_version: &str,
) -> String {
    let features_hash = blake3::hash(features_json.as_bytes()).to_hex().to_string();
    format!(
        "{}-{}-{}-{}-{}",
        crate_name,
        version,
        features_hash,
        target.replace('-', "_"),
        rustc_version.replace('-', "_")
    )
}

/// Completion the edge's `POST /api/v1/github/workflow-run` handler sends
/// the scheduler Durable Object for a finished `build-crate.yml` run.
///
/// The webhook answer carries no `attempt`, so the object resolves the
/// row's live attempt at apply time.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkflowRunComplete {
    /// The run's `display_title` — `build-crate.yml` sets `run-name` to
    /// the task id, so this string IS `BuildTaskPayload::task_id`.
    pub task_id: String,
    /// The run's `conclusion` mapped onto success: only a run that
    /// finished green *and* whose records artifact exists in GHCR counts
    /// as a completed build.
    pub success: bool,
    /// Failure description when `success` is false — the conclusion and,
    /// on a missing records artifact, which tag the edge looked for.
    pub error: Option<String>,
    /// The GitHub Actions run id, stamped onto the queue row so
    /// `stow-admin status` surfaces the run URL.
    #[serde(default)]
    pub github_run_id: Option<String>,
}

/// A normalized dependency entry from a resolved Cargo dependency graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct DependencyGraphEntry {
    /// Crate name.
    pub crate_name: CrateName,
    /// Crate version.
    #[schema(value_type = String)]
    pub version: semver::Version,
    /// Sorted, deduplicated features (raw list — wire form is JSON array).
    pub features: Vec<String>,
}

/// One exact dependency edge in a client-resolved Cargo graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct ResolvedDependencyGraphDependency {
    /// Dependency crate name.
    pub crate_name: CrateName,
    /// Dependency crate version.
    #[schema(value_type = String)]
    pub version: semver::Version,
    /// Whether this edge's target compiles for the build host —
    /// proc-macros and build dependencies, and everything only they
    /// reach. Defaults to the target side so clients predating the flag
    /// keep minting the shape they always did.
    #[serde(default)]
    pub host_side: bool,
}

/// One exact crates.io package node resolved from the client's current lockfile graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ResolvedDependencyGraphEntry {
    /// Package crate name.
    pub crate_name: CrateName,
    /// Package crate version.
    #[schema(value_type = String)]
    pub version: semver::Version,
    /// Sorted, deduplicated features for this side (raw list — wire form
    /// is JSON array). Cargo compiles each side with its own feature set
    /// (resolver version 2+ semantics), so a package present on both
    /// sides may carry different features on each.
    pub features: Vec<String>,
    /// Whether this node compiles for the build host — proc-macros and
    /// build dependencies, and everything only they reach. A package
    /// needed on both sides appears twice, once per flag.
    /// Defaults to the target side for clients predating the flag.
    #[serde(default)]
    pub host_side: bool,
    /// Direct dependencies of this package.
    pub dependencies: Vec<ResolvedDependencyGraphDependency>,
    /// This node's dependency subgraph, projected from the build's own
    /// `cargo --unit-graph` — the wire `resolve` re-derives the node's
    /// task id from, so a forged or leaf-shaped context is refused
    /// (stow#588).
    pub dependency_subgraph: TaskSubgraph,
}

/// The dispatch freeze — the scheduler's "builds are failing
/// systematically" / "usage is over budget" circuit breaker.
///
/// Held by the scheduler Durable Object in its `settings` table under
/// `dispatch_freeze`. Unlike the zone's WAF maintenance rules, which shed
/// anonymous edge traffic to protect the worker, an engaged freeze stops the Durable
/// Object from handing queue rows to CI runners so a systematic breakage
/// cannot burn the org's Actions allowance; untrusted enqueues keep
/// flowing. Wire shape of `GET`/`POST /api/v1/admin/dispatch-freeze`
/// and of the scheduler object's `/dispatch-freeze` routes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DispatchFreeze {
    /// Whether dispatch is frozen.
    pub enabled: bool,
    /// The stored freeze record — present only while `enabled` holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<DispatchFreezeRecord>,
    /// The recent freeze transitions — newest first, bounded. The
    /// watchdog (#450, Actions, `issues: write`) reads these through
    /// `stow-admin dispatch-freeze status` / the admin route to write
    /// the `incident` issue record the edge deliberately cannot write.
    #[serde(default)]
    pub transitions: Vec<DispatchFreezeTransition>,
}

/// The incident dedup key the freeze's `incident` issue lives under —
/// `[incident] dispatch-freeze:` on the title. Shared so the watchdog
/// (#450) and the edge agree.
pub const DISPATCH_FREEZE_INCIDENT_KEY: &str = "dispatch-freeze";

/// One line of the dispatch-freeze transition log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DispatchFreezeTransition {
    /// ISO 8601 timestamp of the transition.
    pub at: String,
    /// Which way the flag moved.
    pub event: FreezeTransitionEvent,
    /// The trigger that engaged the freeze — present on `engaged`
    /// lines; on `cleared` lines it echoes the trigger the cleared
    /// record held.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<DispatchFreezeTrigger>,
}

/// A freeze flag transition kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreezeTransitionEvent {
    /// Not frozen → frozen.
    Engaged,
    /// Frozen → not frozen.
    Cleared,
}

/// The record stored while a dispatch freeze is engaged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DispatchFreezeRecord {
    /// ISO 8601 timestamp the freeze engaged.
    pub frozen_at: String,
    /// What engaged the freeze.
    pub trigger: DispatchFreezeTrigger,
    /// What happened to the freeze alert — Email Sending's outcome, or
    /// why none went out. Persisted so a freeze nobody was told about
    /// is visible to whoever eventually reads it — the exact failure
    /// this feature exists to prevent. The `incident` issue record is
    /// the watchdog's (#450): the edge's App token has no `issues`
    /// grant, deliberately — the edge is untrusted serving
    /// infrastructure.
    pub notify: ChannelOutcome,
}

/// What engaged a dispatch freeze.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DispatchFreezeTrigger {
    /// An operator froze dispatch by hand (`POST /dispatch-freeze`).
    Manual,
    /// The systematic-failure trip condition fired on a completion
    /// report: enough outcomes inside the window *and* a failure ratio
    /// over them, both required.
    Tripped(DispatchFreezeTrip),
    /// The scheduler object's own SQL meter crossed a daily budget.
    Cost(DispatchFreezeCost),
}

/// The observed window that tripped a dispatch freeze — the numbers the
/// freeze alert names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DispatchFreezeTrip {
    /// Configured window the outcomes were counted over.
    pub window_minutes: u32,
    /// Configured minimum sample: no stream trips below it however bad
    /// its ratio.
    pub min_outcomes: u32,
    /// Configured failure ratio (percent) a sufficiently-sampled stream
    /// must reach to trip.
    pub fail_percent: u32,
    /// Completed attempts observed across the fleet inside the window.
    pub outcomes: u32,
    /// Failed attempts across the fleet inside the window.
    pub failures: u32,
    /// `failures / outcomes` as a whole percent.
    pub failure_percent: u32,
    /// Whether the fleet-wide stream tripped on its own (the per-target
    /// streams may trip independently of it — either is enough).
    pub fleet_tripped: bool,
    /// Per-target tallies for every target that recorded a failure in
    /// the window; `tripped` marks the ones that individually met the
    /// sample-and-ratio condition.
    pub targets: Vec<DispatchFreezeTarget>,
    /// The dominant failure classes of the window — `step: error-prefix`
    /// with counts, descending.
    #[serde(default)]
    pub classes: Vec<DispatchFreezeClass>,
    /// GitHub Actions URLs of recent runs that failed inside the window.
    #[serde(default)]
    pub example_run_urls: Vec<String>,
}

/// One target's contribution to a tripped freeze window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DispatchFreezeTarget {
    /// Compilation target.
    pub target: TargetTriple,
    /// Completed attempts observed for this target in the window.
    pub outcomes: u32,
    /// Failed attempts for this target in the window.
    pub failures: u32,
    /// Whether this target alone met the sample-and-ratio trip
    /// condition.
    pub tripped: bool,
}

/// One failure class's share of a tripped window — `build-crate 500`-
/// style labels: the failure's error first line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DispatchFreezeClass {
    /// The label the failed attempt was recorded under — its error's
    /// first line (`unknown` when the report carried none).
    pub class: String,
    /// Failed attempts in the window carrying this class.
    pub count: u32,
}

/// The metered dimension a cost trip crossed — the DO's SQL meter
/// reports the `DurableObject*` variants; the rest exist for the
/// watchdog's (#450) account-wide view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CostMetric {
    /// Scheduler Durable Object `SQLite` rows read.
    DurableObjectRowsRead,
    /// Scheduler Durable Object `SQLite` rows written.
    DurableObjectRowsWritten,
    /// Durable Object invocations (requests + alarms).
    DurableObjectRequests,
    /// Durable Object billed duration, GB-seconds.
    DurableObjectDurationGbS,
    /// Worker invocations of `stow-edge`.
    WorkerRequests,
    /// Worker CPU milliseconds consumed by `stow-edge`.
    WorkerCpuMs,
    /// D1 `stow-prod` rows read.
    D1RowsRead,
    /// D1 `stow-prod` rows written.
    D1RowsWritten,
}

/// One route family's share of the day's Worker requests — the "top
/// routes" the cost-trip email names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TopRouteCount {
    /// The dimension the count groups on — `scriptName` unless a path
    /// dimension is available.
    pub label: String,
    /// Requests this group saw.
    pub requests: f64,
}

/// The cost-trip evidence stored on the freeze record: which metered
/// dimension crossed, today's usage, the daily budget it is checked
/// against, and the day's top request groups.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DispatchFreezeCost {
    /// The first metric found over budget.
    pub metric: CostMetric,
    /// Usage so far today (UTC) in the metric's unit.
    pub used: f64,
    /// The daily budget the usage is compared against — the monthly
    /// Workers Paid allowance divided by 30, times
    /// `STOW_COST_BUDGET_MULTIPLIER`.
    pub budget: f64,
    /// Every metric over budget (the trip names `metric`, this lists
    /// all of them).
    #[serde(default)]
    pub over: Vec<DispatchFreezeCostEntry>,
    /// Today's top request groups — populated by the watchdog's
    /// account view; the DO sees statements, not URLs, so an
    /// edge-fired trip carries an empty list.
    #[serde(default)]
    pub top_routes: Vec<TopRouteCount>,
}

/// One over-budget metric line inside [`DispatchFreezeCost::over`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct DispatchFreezeCostEntry {
    /// The metric.
    pub metric: CostMetric,
    /// Usage since 00:00 UTC.
    pub used: f64,
    /// Its daily budget.
    pub budget: f64,
}

/// One alert channel's delivery result.
///
/// The edge alerts by email only (Email Sending) — its App token has
/// no `issues` grant by design; the `Opened`/`Commented`/`Resolved`
/// variants are what a caller-side recorder (the #450 watchdog,
/// `issues: write` in Actions) reports when it turns a transition into
/// the `incident` issue record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ChannelOutcome {
    /// Email Sending accepted the message.
    Sent {
        /// Provider `message_id`, when Cloudflare returned one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message_id: Option<String>,
    },
    /// A new incident issue was created.
    Opened {
        /// The issue's `html_url`.
        url: String,
    },
    /// A comment landed on an already-open incident issue (a re-opened
    /// dedup or an hourly digest).
    Commented {
        /// The issue's `html_url`.
        url: String,
    },
    /// The incident issue got its resolve comment and was closed.
    Resolved {
        /// The issue's `html_url`.
        url: String,
    },
    /// The channel's call failed — the transition still landed; this
    /// channel simply went nowhere.
    Failed {
        /// What the call returned or how it failed to decode.
        message: String,
        /// Actionable hint — a known `E_*` Email Sending code's fix, or
        /// the `issues: write` grant a GitHub 403 points at.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hint: Option<String>,
    },
    /// No call was attempted — the channel's binding/credentials are
    /// unconfigured.
    Disabled {
        /// Why the channel is off (names the missing binding/var).
        reason: String,
    },
}

/// Scheduler DO queue status for monitoring.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SchedulerStatus {
    /// Tasks waiting to become dispatchable.
    pub pending: u32,
    /// Pending tasks in the human lane — a subset of `pending` counted
    /// separately so operators can see human-requested work.
    pub human_pending: u32,
    /// Tasks whose `workflow_dispatch` was sent but not yet picked up.
    pub dispatched: u32,
    /// Tasks a CI run has claimed but not yet reported complete.
    pub running: u32,
    /// Tasks that completed successfully.
    pub completed: u32,
    /// Tasks whose CI run reported failure.
    pub failed: u32,
    /// Pending tasks parked behind a terminally failed dependency —
    /// a subset of `pending` counted so operators can tell "waiting for
    /// a publish" from "waiting on something that will never come".
    #[serde(default)]
    pub blocked: u32,
}

/// Request body for `POST /api/v1/requests`: a human asking for one crate
/// to be built into the public cache.
///
/// The endpoint is the submission path behind the request form on
/// `stow.waterui.dev`; the Turnstile token is the admission check and every
/// accepted request lands in the scheduler's human lane ahead of the
/// cache-miss queue.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CrateRequest {
    /// Crate name as published on crates.io.
    pub crate_name: CrateName,
    /// Exact version to request. When `None` the edge resolves the newest
    /// non-prerelease, non-yanked crates.io version.
    #[serde(default)]
    pub version: Option<CrateVersion>,
    /// Features to enable for the requested crate, in the canonical
    /// [`FeaturesJson`] representation. The list is taken literally:
    /// `["default", ...]` builds with default features on, and an empty
    /// list is `--no-default-features` with nothing added.
    pub features_json: FeaturesJson,
    /// Cloudflare Turnstile token produced by the invisible widget. Verified
    /// against siteverify before the edge does any resolution work.
    pub turnstile_token: String,
}

/// One crate in a `GET /api/v1/crates/search` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateSearchHit {
    /// Crate name as published on crates.io.
    pub crate_name: CrateName,
    /// The crate's one-line description, when it has one.
    #[serde(default)]
    pub description: Option<String>,
    /// Newest version crates.io lists for the crate.
    pub max_version: CrateVersion,
    /// All-time download count, the ordering crates.io search returns.
    pub downloads: u64,
}

/// Response body for `GET /api/v1/crates/search`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateSearchResponse {
    /// Matching crates, most downloaded first, capped by the `limit` query
    /// parameter.
    pub crates: Vec<CrateSearchHit>,
}

/// Response body for `GET /api/v1/crates/{crate_name}/versions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateVersionsResponse {
    /// Published, non-yanked versions, newest first.
    pub versions: Vec<CrateVersion>,
}

/// One feature a crate version declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateFeature {
    /// The feature name, as written in the crate's `[features]` table or
    /// implied by an optional dependency.
    pub name: String,
    /// The features and optional dependencies this one turns on. Empty for
    /// an implicit optional-dependency feature.
    pub implies: Vec<String>,
    /// Whether the crate's `default` feature set enables this feature,
    /// directly or transitively.
    pub default: bool,
}

/// Response body for `GET /api/v1/crates/{crate_name}/versions/{version}/features`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateFeaturesResponse {
    /// Every selectable feature of the version, `default` first and the
    /// rest alphabetical.
    pub features: Vec<CrateFeature>,
}

/// Which scheduler lane a queue row belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskLane {
    /// Filled by the cache-miss path and watchers; subject to
    /// `STOW_DISPATCH_MIN_AGE_MINUTES` before dispatch.
    Miss,
    /// Filled by the Turnstile-verified human request API. Dispatches ahead
    /// of the miss lane and bypasses the minimum-age hold.
    Human,
}

impl TaskLane {
    /// The stable string persisted in the scheduler's `lane` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Miss => "miss",
            Self::Human => "human",
        }
    }

    /// Inverse of [`Self::as_str`] for values read back from queue rows.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "miss" => Some(Self::Miss),
            "human" => Some(Self::Human),
            _ => None,
        }
    }
}

/// Lifecycle of one scheduler queue row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueueTaskStatus {
    /// Waiting for dependencies or dispatch eligibility.
    Pending,
    /// Parked behind a terminally failed dependency: every dependency
    /// edge is still unserved and at least one names a `failed` task.
    /// Never stored — the scheduler derives it from a `pending`
    /// row at read time, so retrying the dependency returns the row to
    /// `pending` with nothing to reconcile.
    Blocked,
    /// `workflow_dispatch` sent, awaiting the CI job to claim it.
    Dispatched,
    /// A CI run claimed the task but has not reported completion.
    Running,
    /// Build, signing, push, and registration all succeeded.
    Completed,
    /// The CI run reported failure.
    Failed,
}

impl QueueTaskStatus {
    /// The stable string a queue row's `status` carries on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Blocked => "blocked",
            Self::Dispatched => "dispatched",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// Inverse of [`Self::as_str`] for values read back from queue rows.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "blocked" => Some(Self::Blocked),
            "dispatched" => Some(Self::Dispatched),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Per-target state reported inside [`CrateRequestTarget`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CrateRequestState {
    /// The artifact already exists in the public cache for this target.
    Cached,
    /// This request enqueued the task into the human lane.
    Queued,
    /// The task was already in the queue (re-requesting promoted or
    /// refreshed it) when this request arrived.
    AlreadyQueued,
    /// The task has been dispatched or is actively building.
    Building,
    /// The requested crate publishes no library target — a name source,
    /// never a task. Its dependency closure is what the request enqueued.
    ClosureQueued,
}

/// Per-target outcome inside a [`CrateRequestStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateRequestTarget {
    /// Compilation target triple — one of [`CI_TARGET_TRIPLES`].
    pub target: TargetTriple,
    /// Where this target's task stands after the request.
    pub state: CrateRequestState,
    /// Scheduler task id for the requested crate on this target. Absent
    /// when `state` is [`CrateRequestState::Cached`].
    #[serde(default)]
    pub task_id: Option<String>,
    /// 1-based position among pending human-lane tasks in dispatch order;
    /// `None` unless the task is still pending in the human lane.
    #[serde(default)]
    pub human_lane_position: Option<u32>,
}

/// Deterministic human-request id — `req-<crate>-<version>-<blake3
/// (features_json)>-<rustc>`.
///
/// The request record's primary key and the `resolve-request.yml`
/// run-name's correlation tail. Unlike a task id it carries no target:
/// a request asks for every CI target's outcome and dedupes by
/// identity alone.
#[must_use]
pub fn request_id(
    crate_name: &str,
    version: &str,
    features_json: &str,
    rustc_version: &str,
) -> String {
    let features_hash = blake3::hash(features_json.as_bytes()).to_hex().to_string();
    format!(
        "req-{}-{}-{}-{}",
        crate_name,
        version,
        features_hash,
        rustc_version.replace('-', "_")
    )
}

/// The request record's lifecycle — `POST /api/v1/requests` returns it
/// `accepted`, and `GET /api/v1/requests/{request_id}` tracks it to
/// `enqueued` or `failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CrateRequestPhase {
    /// Turnstile admission and the daily-budget probe passed and the
    /// `resolve-request.yml` run was dispatched.
    Accepted,
    /// The run reported `in_progress` — the resolve is executing.
    Resolving,
    /// The job's outcome report landed: `targets` carries the per-target
    /// outcome the request lane used to answer inline.
    Enqueued,
    /// Dispatch, resolve or submission failed — `error` says which.
    Failed,
}

/// `POST /api/v1/requests` response and `GET /api/v1/requests/{id}` for a
/// `req-` id — the request record's point-in-time state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateRequestStatus {
    /// The request's deterministic id ([`request_id`]).
    pub request_id: String,
    /// Echoed crate name.
    pub crate_name: CrateName,
    /// The resolved version.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Stable rustc the resolve targets.
    pub rustc_version: WireRustcVersion,
    /// Where the request stands.
    pub status: CrateRequestPhase,
    /// Per-target outcomes in [`CI_TARGET_TRIPLES`] order — populated
    /// once `status` is [`CrateRequestPhase::Enqueued`].
    pub targets: Vec<CrateRequestTarget>,
    /// What failed when `status` is [`CrateRequestPhase::Failed`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The Actions run id serving the record's live attempt, once the
    /// run's `workflow_run` event has reported it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_run_id: Option<String>,
    /// The run's URL, reported on the same event — the status page
    /// links it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_run_url: Option<String>,
}

/// The edge's admission → the scheduler Durable Object's `POST /requests`
/// route, which checks the human budget, deduplicates and dispatches the
/// resolve run in one call.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestAdmission {
    /// Deterministic request id ([`request_id`]).
    pub request_id: String,
    /// The requested crate.
    pub crate_name: CrateName,
    /// The resolved version.
    pub version: CrateVersion,
    /// Canonical features JSON.
    pub features_json: FeaturesJson,
    /// Stable rustc the resolve targets.
    pub rustc_version: WireRustcVersion,
    /// The `STOW_HUMAN_MAX_CLOSURE` the edge admitted under — the job's
    /// closure cap.
    pub max_closure: u32,
}

/// The `request` `workflow_dispatch` input `resolve-request.yml` reads
/// (`stow-admin request resolve --request` parses it verbatim).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestDispatch {
    /// The request record's id — also the webhook's run correlation.
    pub request_id: String,
    /// The record's dispatch epoch — a failed record's re-request bumps
    /// it, and the run-name carries it so a stale run's webhook events
    /// cannot land on the live attempt.
    pub attempt: u32,
    /// The GitHub run-name to stamp — `resolve-a{attempt}-{request_id}`,
    /// built here so the title format has a single owner (the webhook
    /// parses it back).
    pub run_title: String,
    /// The requested crate.
    pub crate_name: CrateName,
    /// The resolved version.
    pub version: CrateVersion,
    /// Canonical features JSON the seed set resolves from.
    pub features_json: FeaturesJson,
    /// Stable rustc the resolve targets.
    pub rustc_version: WireRustcVersion,
    /// The closure cap the edge admitted under.
    pub max_closure: u32,
    /// Unix seconds at which the edge dispatched the run — the job's
    /// dispatch-to-submit timing baseline.
    pub dispatched_at: i64,
}

/// One CI target's root facts in the resolve job's outcome report.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestRootOutcome {
    /// The CI target the entry describes.
    pub target: TargetTriple,
    /// The lib-root task id; `None` when the crate publishes no library —
    /// the target's outcome then reads
    /// [`CrateRequestState::ClosureQueued`].
    pub task_id: Option<String>,
    /// The published `index.<target>.<rustc>` slice already serves the
    /// lib root — the target reads [`CrateRequestState::Cached`] and its
    /// closure was not enqueued.
    pub cached: bool,
}

/// `POST /api/v1/scheduler/requests/{request_id}/outcome` — the resolve
/// job's report.
///
/// Either the resolved batch plus the per-target roots the record's
/// outcome table is assembled from, or the failure it hit — exclusive
/// by type: a failed resolve submits no tasks, and a resolve that
/// produced tasks is not a failure.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestOutcomeReport {
    /// The record attempt this report serves — the DO refuses reports
    /// naming a superseded attempt.
    pub attempt: u32,
    /// What the resolve produced.
    pub outcome: RequestOutcome,
}

/// One arm of a [`RequestOutcomeReport`].
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RequestOutcome {
    /// The resolve completed: the batch of uncovered tasks across every
    /// target's closure — forwarded to the trusted enqueue verbatim —
    /// plus the per-target root facts in [`CI_TARGET_TRIPLES`] order.
    Resolved {
        /// The uncovered human-lane tasks across every target's closure.
        tasks: Vec<EnqueueRequest>,
        /// Per-target root facts in [`CI_TARGET_TRIPLES`] order.
        roots: Vec<RequestRootOutcome>,
    },
    /// The resolve failed — `error` names the step, and the record is
    /// marked `failed` with it.
    Failed {
        /// What the resolve died on.
        error: String,
    },
}

/// The `workflow_run` lifecycle event the webhook forwards to the DO's
/// `/requests/{id}/run-update` route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RequestRunAction {
    /// `in_progress` — the resolve run started.
    InProgress,
    /// `completed` — the run finished; the record fails unless the job's
    /// outcome report already marked it `enqueued`.
    Completed,
}

/// The `workflow_run` webhook's delivery for a `resolve-request.yml` run
/// → the DO's `/requests/{id}/run-update` route, correlated by
/// `request_id` + `attempt` parsed from the run-name.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RequestRunUpdate {
    /// The attempt the run serves, from the `a{attempt}` run-name leg.
    pub attempt: u32,
    /// Which lifecycle event the delivery carries.
    pub action: RequestRunAction,
    /// `workflow_run.conclusion` on a `completed` delivery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conclusion: Option<String>,
    /// The Actions run id — recorded on the record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// The run's `html_url` — carried into `error` on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_url: Option<String>,
}

/// Point-in-time view of one scheduler task — what the DO's `tasks_status`
/// query returns for a request record's re-probe and for task-row
/// inspection inside the object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RequestStatus {
    /// Canonical scheduler task id (blake3-derived identity string).
    pub task_id: String,
    /// Crate name.
    pub crate_name: CrateName,
    /// Exact crate version.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Which scheduler lane the task is queued in.
    pub lane: TaskLane,
    /// Current task lifecycle state.
    pub status: QueueTaskStatus,
    /// 1-based position among pending human-lane tasks in dispatch order;
    /// `None` unless the task is a pending human-lane task.
    #[serde(default)]
    pub human_lane_position: Option<u32>,
    /// Whether the task builds against the bundled `Cargo.lock`
    /// (`EnqueueRequest::preserve_lockfile`), which decides whether the
    /// task's dependency closure is reproducible from crates.io metadata.
    #[serde(default)]
    pub preserve_lockfile: bool,
    /// What holds this task — the failed dependency's task id, or
    /// `unknown dependency identity` when an edge's identity was never
    /// resolved. Set only when `status` is [`QueueTaskStatus::Blocked`].
    #[serde(default)]
    pub blocked_by: Option<String>,
}

/// Response body for `GET /api/v1/admin/index/{target}/{rustc_version}`.
///
/// One keyset page of the slice's servable artifact rows — the data
/// `stow-admin index export` assembles into the published
/// [`crate::index::ArtifactIndex`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactIndexPage {
    /// Rows ordered by `c_metadata`, every one strictly after the
    /// request's `after` cursor and carrying a published bundle.
    pub rows: Vec<ArtifactIndexRow>,
    /// The `after` cursor for the next page — the last row's `c_metadata`
    /// when this page was full, `None` once the slice is exhausted.
    pub next_after: Option<String>,
}

/// The index-publish path's report of what a slice serves.
///
/// Request body for `POST /api/v1/admin/index/{target}/{rustc_version}`,
/// sent after the slice goes live. The scheduler stores the set as the
/// membership the dependency gate checks a dependent's edges against —
/// a dependent dispatches only when every dependency resolves to a row
/// the latest report for that dependency's own `(target, rustc_version)`
/// covers.
///
/// Two report shapes share the wire:
///
/// - **Delta** — `base_generation` is the index generation the report's
///   base was taken from; `added`/`retired` carry only what moved. The
///   scheduler 409s when its live generation moved past the base — the
///   reporter must then resync with a full report, never retry a stale
///   delta.
/// - **Full** — `base_generation` is `None`, `added` carries the slice's
///   whole membership and `retired` is empty; the scheduler computes the
///   delta itself. This is the first-publish path and the
///   `stow-admin index report --full` resync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PublishedSliceReport {
    /// The index generation this report's delta is based on — `None`
    /// marks the explicit full report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_generation: Option<i64>,
    /// The generation of the index this report publishes — the value
    /// stamped in the index header. Present on every report the
    /// current reporter sends; absent from older reporters. The
    /// scheduler records it as the slice's applied generation so a
    /// full resync brings the optimistic-lock counter back into sync
    /// with the index sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    /// Rows entering the slice (a delta's additions, or the whole
    /// membership on a full report).
    pub added: Vec<PublishedSliceRow>,
    /// Rows leaving the slice — always empty on a full report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired: Vec<PublishedSliceRow>,
}

/// One servable identity inside a [`PublishedSliceReport`]: the semantic
/// identity a dependency edge names plus the unit shape that row serves.
///
/// The same semantic identity legitimately appears once per unit shape —
/// a crate compiled as a host-side unit has a different compile key than
/// the same crate compiled as a target unit — so the stored
/// `unit_shape` distinguishes rows the edge's servable gate compares
/// separately. Rows reported without one carry no shape and satisfy no
/// coverage clause: a dependent gated on such a dependency stays gated
/// until the node republishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PublishedSliceRow {
    /// Crate name as published on crates.io.
    pub crate_name: CrateName,
    /// Exact crate version.
    pub version: CrateVersion,
    /// Canonicalized features list.
    pub features_json: FeaturesJson,
    /// The unit shape the builder recorded for the row — its side, the
    /// cargo invocation spelling that produced it, and whether it links.
    /// `None` only on reports serialized before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit_shape: Option<crate::public_cache::UnitShape>,
    /// The Merkle dependency digest the row was built under (stow#588).
    /// `None` on reports serialized before the field existed — such
    /// rows satisfy no contextual coverage clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_identity: Option<DependencyIdentity>,
}

/// Body the edge forwards to the scheduler's `/index/published` — one
/// [`PublishedSliceReport`] plus the `(target, rustc_version)` slice it
/// describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PublishedSlice {
    /// The slice's compilation target triple.
    pub target: TargetTriple,
    /// The slice's stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// The index generation this report's delta is based on — `None`
    /// marks the explicit full report (`added` = whole membership,
    /// `retired` empty).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_generation: Option<i64>,
    /// The generation of the index this report publishes — the value
    /// stamped in the index header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    /// Rows entering the slice.
    pub added: Vec<PublishedSliceRow>,
    /// Rows leaving the slice — always empty on a full report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retired: Vec<PublishedSliceRow>,
}

// ===== Operations API (`stow-admin` under `/api/v1/admin/*`) =====

/// Selector for `GET /api/v1/admin/queue` and
/// `POST /api/v1/admin/queue/{retry,cancel,promote,purge}`.
///
/// One flat struct on purpose: the same shape has to decode from a JSON
/// body and from a query string, and a nested or `#[serde(flatten)]`ed
/// half forces serde to buffer the query's values as strings, which no
/// numeric field can then deserialize from. So `{"task_ids": […],
/// "status": "failed"}` and `?task_ids=a&task_ids=b&status=failed&limit=5`
/// decode identically, and the mutation preview lists exactly the rows a
/// selector names.
///
/// Every predicate is optional; a selector with none of them selects
/// every row (and is rejected for mutations — an operator mutation must
/// name either explicit task ids or at least one predicate).
///
/// A non-empty `task_ids` selects exactly those rows and the predicates
/// are ignored; otherwise the predicates select. Either way the verb's
/// own status/lane predicates still apply — a mutation never touches a
/// row outside its transition domain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QueueSelector {
    /// Explicit task ids.
    #[serde(default)]
    pub task_ids: Vec<String>,
    /// Lifecycle status to match.
    #[serde(default)]
    pub status: Option<QueueTaskStatus>,
    /// Compilation target to match.
    #[serde(default)]
    pub target: Option<TargetTriple>,
    /// Rustc version to match (`rustc` on the wire).
    #[serde(default, rename = "rustc", alias = "rustc_version")]
    pub rustc_version: Option<WireRustcVersion>,
    /// Crate name to match (`crate` on the wire).
    #[serde(default, rename = "crate", alias = "crate_name")]
    pub crate_name: Option<CrateName>,
    /// Only rows whose `updated_at` is at least this many seconds old
    /// (`older_than` on the wire).
    #[serde(default, rename = "older_than", alias = "older_than_secs")]
    pub older_than_secs: Option<u64>,
    /// Most rows a listing returns (bounded server-side); mutations
    /// ignore it — a mutation selector either matches everything its
    /// predicates describe or is rejected.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Response of the `queue retry|cancel|promote|purge` endpoints:
/// how many rows the transition touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QueueMutationResult {
    /// Rows the transition affected.
    pub affected: u32,
}

/// What `POST /api/v1/admin/scheduler/migrate` reports — the stored
/// scheduler schema version before and after the migration pass ran.
/// `before == after` means the queue was already current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchemaMigrationReport {
    /// Schema version the queue carried coming in — `0` on a
    /// pre-versioned queue whose `scheduler_schema_version` row did not
    /// exist yet.
    pub before: i64,
    /// Schema version the queue carries now — the build's own
    /// `SCHEMA_VERSION`, since a successful pass always ends stamped.
    pub after: i64,
}

/// Body of `POST /api/v1/admin/scheduler/budget/seed`.
///
/// The workerd budget harness's fixture load. Only deploys that set
/// `STOW_SCHEDULER_BUDGET` answer it; production has no such binding and
/// the route 404s.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerSeedRequest {
    /// Queue rows to seed; absent means the production-shaped 100k.
    #[serde(default)]
    pub queue_rows: Option<u32>,
    /// Clear the seeded tables first — the probe re-runs against a
    /// persistent local DO store without an operator cleanup in between.
    /// Restarting clears chunk by chunk, so the first `reset` call only
    /// begins the wipe; keep calling until `done`.
    #[serde(default)]
    pub reset: Option<bool>,
    /// Rows one call may seed at most; absent means the server's
    /// bounded default.
    #[serde(default)]
    pub batch: Option<u32>,
}

/// What the seed reports back. A request carries one chunk of work, so
/// the caller loops until `done` — `seeded` says whether this call
/// wrote fixture rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerSeedReport {
    /// Rows `queue` holds now.
    pub queue_rows: u64,
    /// Rows `queue_dependencies` holds now.
    pub dependency_rows: u64,
    /// Rows `published_slice_rows` holds now.
    pub slice_rows: u64,
    /// Whether this call wrote fixture rows (false once the seed is
    /// already `done` and no `reset` was passed).
    pub seeded: bool,
    /// Whether the fixture is fully seeded (or was already populated).
    pub done: bool,
}

/// One statement's real Durable Object cursor counters — the units
/// Cloudflare bills on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerBudgetStatement {
    /// The SQL the drive issued.
    pub sql: String,
    /// Rows the statement returned to its caller.
    pub rows_returned: u64,
    /// `cursor.rowsRead` — every row the statement touched, index
    /// entries and probe rows included.
    pub rows_read: u64,
    /// `cursor.rowsWritten` — table rows plus index entries and
    /// trigger-made writes.
    pub rows_written: u64,
    /// Wall milliseconds the statement's own `query`/`execute` awaited
    /// in local workerd — measured around the inner call by the
    /// metered backend, so a hot drive's wall can be decomposed per
    /// statement rather than attributed as one lump. Always `0` on
    /// host builds (the host lane gates SQL counts, not timing) and
    /// on statements issued through the uncounted backend.
    pub elapsed_ms: u64,
}

/// One drive's workerd measurement against its budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerBudgetRow {
    /// The route or pass the drive exercises.
    pub name: String,
    /// Statements the drive issued.
    pub statements: u64,
    /// Σ `rowsRead` over the drive's statements.
    pub rows_read: u64,
    /// Σ `rowsWritten` over the drive's statements.
    pub rows_written: u64,
    /// Wall-clock milliseconds the drive's queue calls took — the
    /// serialized-Duration number the launch gate projects (stow#452).
    pub wall_ms: u64,
    /// Budgeted statement count.
    pub statement_budget: u64,
    /// Budgeted `rowsRead` total.
    pub read_budget: u64,
    /// Budgeted `rowsWritten` total.
    pub write_budget: u64,
    /// Budgeted wall milliseconds.
    pub wall_budget: u64,
    /// Σ D1 `meta.rowsRead` over statements the drive issued through
    /// the counted catalog backend — the coverage lookups a claim pays
    /// per page, carried separately because D1 bills a different
    /// product than the object's own rows.
    pub d1_rows_read: u64,
    /// Σ D1 `meta.rowsWritten` over the same statements.
    pub d1_rows_written: u64,
    /// Σ of the awaited durations of the counted catalog backend's
    /// own calls. A sum of operation spans, not a share of drive
    /// wall: concurrent calls overlap in real time but add up here,
    /// so it can exceed the drive's measured window. `0` on host and
    /// on drives that never touch the catalog.
    pub d1_elapsed_ms: u64,
    /// `true` when any of the three row budgets is exceeded —
    /// statements, `rowsRead`, `rowsWritten`. Wall time is not in this
    /// set; see `over_wall`.
    pub over_budget: bool,
    /// `true` when `wall_ms` exceeded `wall_budget` — reported but
    /// never gated: the local workerd lane's wall clock includes the
    /// runner's storage latency (the in-window `db.sync()` durability
    /// barrier on its SQLite), which is not the code's cost.
    pub over_wall: bool,
    /// The per-statement log the totals are summed over.
    pub log: Vec<SchedulerBudgetStatement>,
}

/// `POST /api/v1/admin/scheduler/budget` request — the knobs the
/// probe's own pass needs that the deploy's bindings do not already
/// set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerBudgetRequest {
    /// The dispatch cap the pass drives claim against, overriding the
    /// deploy's `STOW_MAX_CONCURRENT_JOBS`. The mock deploys a tiny cap
    /// for its own stability, so the harness passes the production cap
    /// here — a pass that cannot claim measures nothing the gate can
    /// price. `0` pauses dispatch; absent uses the deploy's setting.
    #[serde(default)]
    pub dispatch_limit: Option<u32>,
}

/// What `POST /api/v1/admin/scheduler/budget` returns: every route and
/// the alarm pass measured on the production-shaped fixture with the
/// real cursor counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerBudgetReport {
    /// Queue rows the fixture holds.
    pub queue_rows: u64,
    /// The schema version the queue reports.
    pub schema_version: i64,
    /// The dispatch cap the pass ran under — the run's own setting
    /// after any request override, so the per-claim marginal price
    /// divides by what the pass could actually claim.
    pub dispatch_limit: u64,
    /// Tasks the pass drives claimed (the hot pass under the dispatch
    /// cap; the idle pass claims none). The launch gate divides the
    /// hot-minus-idle marginal cost by this — never by a checked-in
    /// assumption — and refuses a report that claims nothing while
    /// build traffic is nonzero.
    pub claimed_tasks: u64,
    /// Per-drive measurements, in drive order.
    pub rows: Vec<SchedulerBudgetRow>,
    /// `true` when any row is over budget — `stow-admin scheduler
    /// budget` exits nonzero on it.
    pub over_budget: bool,
}

/// One node identity a demand batch reports demand for (stow#522).
///
/// The Analytics Engine source omits `host_side`, so an entry names
/// every compile side of the identity at once: all matching unbuilt
/// queue rows are roots of the demand walk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerDemandEntry {
    /// Crate name the observed demand names.
    pub crate_name: CrateName,
    /// Crate version.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Compilation target triple.
    pub target: TargetTriple,
    /// Stable rustc version.
    pub rustc_version: WireRustcVersion,
    /// Demand increment this entry contributes once to every task its
    /// closure touches.
    pub demand: u64,
}

/// `POST /api/v1/admin/scheduler/demand` request — one durable demand
/// batch.
///
/// `batch_id` is the replay contract the hourly feed (#523) reuses:
/// staged contributions fold into `queue.demand` inside the single
/// `prepared → accepted` acceptance statement, so an accepted batch
/// has no remainder — a delivery interrupted before acceptance
/// (`prepared`) recomputes the current graph on retry, and an
/// accepted-batch replay answers from the stored record and writes
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerDemandRequest {
    /// The batch's durable identity — the feed's hour window.
    pub batch_id: String,
    /// Observed-demand entries. Distinct identities contribute their
    /// own deltas to a shared closure; an identical entry repeated in
    /// one batch sums before touching tasks.
    pub entries: Vec<SchedulerDemandEntry>,
}

/// What `POST /api/v1/admin/scheduler/demand` returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerDemandReport {
    /// The applied batch's identity, echoed.
    pub batch_id: String,
    /// Distinct input identities the batch carried.
    pub entries: u64,
    /// Queue tasks the batch's closures named — each took its share of
    /// every entry whose walk reached it.
    pub touched_tasks: u64,
    /// `true` when this call performed the batch's acceptance
    /// transition — including an empty closure, which accepts like
    /// any other; `false` on an exact accepted-batch replay, which
    /// reports the stored count and writes nothing.
    pub applied: bool,
}

// ----- Hourly demand feed (stow#523) -----

/// One closed hour of the demand feed — the canonical `YYYY-MM-DDTHH`
/// (UTC) the hour header, the page keys and every batch identity
/// derive from. `DEMAND_FEED_HOUR_LEN` is its fixed length.
pub const DEMAND_FEED_HOUR_LEN: usize = 13;

/// The `YYYY-MM-DDTHH` shape `time` parses and re-emits — the
/// canonical literal every feed key carries.
const DEMAND_FEED_HOUR_FORMAT: &[time::format_description::FormatItem<'static>] =
    time::macros::format_description!("[year]-[month]-[day]T[hour]");

/// A validated `YYYY-MM-DDTHH` UTC hour literal (stow#523).
///
/// Parsing goes through `time`'s real calendar — February 31,
/// month 13, or a mis-shaped literal can never reach a feed write or
/// an Analytics Engine query — and the stored form is the re-emitted
/// canonical shape, so `Ord` on it sorts chronologically. The shared
/// parser serves the Durable Object's writes, the edge's query proxy
/// and `stow-admin`'s resume/backfill arithmetic; `parse_closed`
/// additionally requires the hour to be fully over.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, ToSchema)]
#[serde(transparent)]
pub struct DemandFeedHour(String);

impl DemandFeedHour {
    /// Parse shape + calendar — rejects February 31 and any
    /// non-canonical padding. Does not check whether the hour has
    /// closed; callers writing or querying use
    /// [`parse_closed`](Self::parse_closed).
    ///
    /// # Errors
    /// The literal is not a canonical `YYYY-MM-DDTHH` calendar hour.
    pub fn parse(hour: &str) -> Result<Self, String> {
        if hour.len() != DEMAND_FEED_HOUR_LEN {
            return Err(format!("demand feed hour {hour:?} is not YYYY-MM-DDTHH"));
        }
        let parsed = time::PrimitiveDateTime::parse(hour, DEMAND_FEED_HOUR_FORMAT)
            .map_err(|_| format!("demand feed hour {hour:?} is not a calendar hour"))?;
        let canonical = parsed
            .format(DEMAND_FEED_HOUR_FORMAT)
            .map_err(|error| format!("reformat demand feed hour {hour:?}: {error}"))?;
        if canonical != hour {
            return Err(format!(
                "demand feed hour {hour:?} is not the canonical {canonical:?}"
            ));
        }
        Ok(Self(canonical))
    }

    /// [`parse`](Self::parse) plus require the hour fully closed at
    /// `now_unix_secs` — every feed write and Analytics Engine query
    /// goes through this.
    ///
    /// # Errors
    /// The literal is not canonical, or the hour is not fully closed
    /// at `now_unix_secs`.
    pub fn parse_closed(hour: &str, now_unix_secs: i64) -> Result<Self, String> {
        let this = Self::parse(hour)?;
        this.ensure_closed(now_unix_secs)?;
        Ok(this)
    }

    /// Require this hour fully closed at `now_unix_secs` — the check
    /// feed writes and queries apply to an already-parsed hour. An
    /// hour whose end is outside the representable calendar range
    /// refuses rather than panicking on the arithmetic.
    ///
    /// # Errors
    /// The hour is not fully closed at `now_unix_secs`, or its end is
    /// outside the representable calendar range.
    pub fn ensure_closed(&self, now_unix_secs: i64) -> Result<(), String> {
        let Some(end) = self.end_unix_secs() else {
            return Err(format!("demand feed hour {} is not closed", self.0));
        };
        if end > now_unix_secs {
            return Err(format!("demand feed hour {} is not closed", self.0));
        }
        Ok(())
    }

    /// The canonical `YYYY-MM-DDTHH` literal.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `YYYY-MM-DD HH` form the `demand_feed.sql` askama
    /// template renders into the Analytics Engine query.
    #[must_use]
    pub fn sql_literal(&self) -> String {
        self.0.replacen('T', " ", 1)
    }

    /// The hour after this one (calendar arithmetic — it may not be
    /// closed; that check happens at use).
    ///
    /// # Errors
    /// The result is outside `time`'s representable calendar range —
    /// the final representable hour has no successor.
    pub fn next(&self) -> Result<Self, String> {
        self.shift(time::Duration::hours(1))
    }

    /// The hour before this one — the watermark contiguity check
    /// compares the stored cursor against `prev()` of the hour being
    /// marked delivered.
    ///
    /// # Errors
    /// The result is outside `time`'s representable calendar range —
    /// the first representable hour has no predecessor.
    pub fn prev(&self) -> Result<Self, String> {
        self.shift(-time::Duration::hours(1))
    }

    /// Calendar shift that keeps the stored value inside the canonical
    /// domain: checked arithmetic, canonical re-emit, and the full
    /// [`parse`](Self::parse) validation round-trip.
    fn shift(&self, duration: time::Duration) -> Result<Self, String> {
        let moved = self
            .parsed()
            .checked_add(duration)
            .ok_or_else(|| format!("demand feed hour {} has no representable neighbor", self.0))?;
        let canonical = moved
            .format(DEMAND_FEED_HOUR_FORMAT)
            .map_err(|error| format!("format demand feed hour neighbor: {error}"))?;
        Self::parse(&canonical)
    }

    /// The first second after this hour — the closure boundary, or
    /// `None` when the end is outside the representable range.
    fn end_unix_secs(&self) -> Option<i64> {
        Some(
            self.parsed()
                .checked_add(time::Duration::hours(1))?
                .assume_utc()
                .unix_timestamp(),
        )
    }

    fn parsed(&self) -> time::PrimitiveDateTime {
        time::PrimitiveDateTime::parse(&self.0, DEMAND_FEED_HOUR_FORMAT)
            .unwrap_or_else(|_| unreachable!("stored hour was validated"))
    }

    /// The newest fully closed hour at `now_unix_secs` — the feed's
    /// bootstrap choice when the watermark is empty. Floors `now` to
    /// the hour boundary and steps back one hour, so the answer is
    /// always closed by construction. Checked arithmetic throughout:
    /// an out-of-range `now` returns `None`, never panics.
    #[must_use]
    pub fn latest_closed(now_unix_secs: i64) -> Option<Self> {
        let floor = now_unix_secs.checked_sub(now_unix_secs.rem_euclid(3_600))?;
        let start = time::OffsetDateTime::from_unix_timestamp(floor.checked_sub(3_600)?).ok()?;
        let canonical = start
            .format(DEMAND_FEED_HOUR_FORMAT)
            .map(|canonical| Self::parse(&canonical))
            .ok()?
            .ok()?;
        Some(canonical)
    }
}

impl std::fmt::Display for DemandFeedHour {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One link of the demand-feed manifest chain.
///
/// `blake3(chain(p-1) || page_hash(p))`. The Durable Object's staged
/// `chain_hash`, the materializer's page builder, and the admin
/// parser's manifest proof all go through this one function so the
/// encoding can never drift between writer and verifier.
#[must_use]
pub fn demand_feed_chain(previous: &blake3::Hash, page_hash: &blake3::Hash) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(previous.as_bytes());
    hasher.update(page_hash.as_bytes());
    hasher.finalize()
}

/// The canonical page payload — the entries' verbatim serialization.
///
/// The serde encoding of the entry list the Durable Object stores
/// verbatim and hashes into the page manifest. The materializer and
/// the verifier share this one function so the encoding can never
/// drift between them.
///
/// # Errors
/// The serialization fails.
pub fn demand_feed_page_payload(
    entries: &[SchedulerDemandEntry],
) -> Result<String, serde_json::Error> {
    serde_json::to_string(entries)
}

/// blake3 of [`demand_feed_page_payload`]: the `page_hash` a staged
/// page stores and the materializer's manifest chains on.
///
/// # Errors
/// The payload serialization fails.
#[must_use = "the hash is the page's manifest link"]
pub fn demand_feed_page_hash(entries: &[SchedulerDemandEntry]) -> Result<blake3::Hash, String> {
    let payload = demand_feed_page_payload(entries)
        .map_err(|error| format!("serialize demand feed page payload: {error}"))?;
    Ok(blake3::hash(payload.as_bytes()))
}

/// The canonical demand-feed manifest: `chain(0) = page_hash(0)`, then
/// `chain(p) = demand_feed_chain(chain(p-1), page_hash(p))` over the
/// ordered page hashes — `None` for an empty attempt.
#[must_use]
pub fn demand_feed_manifest(page_hashes: &[blake3::Hash]) -> Option<blake3::Hash> {
    let mut chain = *page_hashes.first()?;
    for page_hash in &page_hashes[1..] {
        chain = demand_feed_chain(&chain, page_hash);
    }
    Some(chain)
}

impl<'de> Deserialize<'de> for DemandFeedHour {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// `POST /api/v1/admin/scheduler/demand-feed/query` request.
///
/// Runs the closed-hour Analytics Engine miss query for `hour` and
/// streams the `FORMAT JSON` document back unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedQueryRequest {
    /// UTC hour, already closed.
    pub hour: DemandFeedHour,
}

/// `POST /api/v1/admin/scheduler/demand-feed/begin` request.
///
/// Opens (or resumes) the staging attempt for `hour`. Once an hour
/// froze (`complete`/`delivered`) a begin refuses: a complete hour
/// never re-queries Analytics Engine.
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedBeginRequest {
    /// UTC hour, already closed.
    pub hour: DemandFeedHour,
}

/// What `begin` returns: the attempt's generation. A resume rotates
/// to a fresh generation — the restarted materialization is a new
/// attempt, never a merge into the abandoned one's staged pages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedBeginReport {
    /// The hour, echoed.
    pub hour: DemandFeedHour,
    /// The staging attempt's generation — pages and `complete` bind
    /// to it, so bytes from a different attempt cannot mix in.
    pub generation: i64,
    /// `true` when abandoned-generation page rows still await
    /// retirement — the caller drains them through
    /// `POST …/demand-feed/cleanup` before finishing, so obsolete
    /// payloads never become an unbounded archive.
    pub stale_pages_pending: bool,
}

/// `POST /api/v1/admin/scheduler/demand-feed/cleanup` request.
///
/// Retires up to a bounded chunk of page rows for `hour`: obsolete
/// generations (a rotated staging attempt's leftovers) or a
/// `delivered` hour's acknowledged payloads. Explicit event work;
/// nothing runs on a timer.
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedCleanupRequest {
    /// UTC hour, already closed.
    pub hour: DemandFeedHour,
}

/// What `cleanup` reports per bounded call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedCleanupReport {
    /// The hour, echoed.
    pub hour: DemandFeedHour,
    /// Page rows this call physically retired.
    pub retired: u64,
    /// `true` while further rows remain — the caller keeps calling
    /// until `false`.
    pub remaining: bool,
}

/// `POST /api/v1/admin/scheduler/demand-feed/page` request.
///
/// Stages one bounded page of the hour's materialized entries. The
/// payload serializes at most `DEMAND_FEED_PAGE_MAX_ENTRIES` entries
/// below `DEMAND_FEED_PAGE_MAX_BYTES` on the wire.
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedPageRequest {
    /// UTC hour, already closed.
    pub hour: DemandFeedHour,
    /// The `begin` generation this page belongs to.
    pub generation: i64,
    /// Zero-based page index — every page in `[0, page_count)` must be
    /// staged before `complete` accepts.
    pub page_no: u32,
    /// The page's entries — non-empty, bounded.
    pub entries: Vec<SchedulerDemandEntry>,
}

/// Streams entries into wire-bounded [`DemandFeedPageRequest`]s.
///
/// The pages fit the bounds exactly — `DEMAND_FEED_PAGE_MAX_ENTRIES`
/// entries *and* a whole-envelope `serde_json` encoding of at most
/// [`DEMAND_FEED_PAGE_MAX_BYTES`], framing (`hour`, `generation`,
/// `page_no`) included. The byte accounting is derived from the same
/// serialization the Durable Object validates on receipt: the
/// empty-request envelope is measured once per page and each entry's
/// serialized length once per push, so a page that fits the exact
/// bound is never refused for slack and one that cannot fit is never
/// sent.
///
#[derive(Debug)]
pub struct DemandFeedPageBuilder {
    hour: DemandFeedHour,
    generation: i64,
    page_no: u32,
    entries: Vec<SchedulerDemandEntry>,
    /// Bytes the open page's entries occupy inside the framing's
    /// `[]`: each entry's serialized length plus its separating
    /// comma — the exact delta over the empty envelope.
    entries_bytes: usize,
    /// `serde_json::to_vec` length of the open page's request with
    /// `entries` empty — the framing the entries land inside.
    framing_bytes: usize,
}

impl DemandFeedPageBuilder {
    /// A builder staging `generation` of `hour`, open at page 0.
    ///
    /// # Errors
    /// The request framing fails to serialize.
    pub fn new(hour: DemandFeedHour, generation: i64) -> Result<Self, String> {
        let mut this = Self {
            hour,
            generation,
            page_no: 0,
            entries: Vec::new(),
            entries_bytes: 0,
            framing_bytes: 0,
        };
        this.reframe()?;
        Ok(this)
    }

    /// Re-measure the empty envelope — `page_no` advances and its
    /// digits change the framing's own length.
    fn reframe(&mut self) -> Result<(), String> {
        let framing = DemandFeedPageRequest {
            hour: self.hour.clone(),
            generation: self.generation,
            page_no: self.page_no,
            entries: Vec::new(),
        };
        self.framing_bytes = serde_json::to_vec(&framing)
            .map_err(|error| format!("encode demand feed page framing: {error}"))?
            .len();
        Ok(())
    }

    /// Whole-envelope bytes the request would carry if an entry of
    /// `entry_json_len` serialized bytes joined the open page — the
    /// empty framing, the entries already inside, the separating
    /// comma, and the entry itself.
    fn envelope_with(&self, entry_json_len: usize) -> usize {
        self.framing_bytes
            + self.entries_bytes
            + usize::from(!self.entries.is_empty())
            + entry_json_len
    }

    /// `true` when an entry of `entry_json_len` serialized bytes fits
    /// the open page under both bounds — the 256-entry cap and the
    /// exact whole-envelope byte bound.
    fn fits(&self, entry_json_len: usize) -> bool {
        self.entries.len() < DEMAND_FEED_PAGE_MAX_ENTRIES
            && self.envelope_with(entry_json_len) <= DEMAND_FEED_PAGE_MAX_BYTES
    }

    /// Append `entry` to the stream. When the open page cannot hold
    /// it, the page closes first and the entry opens the next — the
    /// completed page is returned for the caller's bounded handoff;
    /// `None` means the open page grew and nothing completed. A page
    /// boundary can only ever produce one finished page per push, so
    /// the return value is the whole backlog.
    ///
    /// # Errors
    /// The entry or framing fails to serialize, or the single entry
    /// cannot fit an *empty* page — an oversized identity no page can
    /// carry.
    pub fn push(
        &mut self,
        entry: SchedulerDemandEntry,
    ) -> Result<Option<DemandFeedPageRequest>, String> {
        let entry_json_len = serde_json::to_vec(&entry)
            .map_err(|error| format!("encode demand feed entry: {error}"))?
            .len();
        let completed = if !self.fits(entry_json_len) && !self.entries.is_empty() {
            self.finish_page()?
        } else {
            None
        };
        // One check covers both landing spots: the entry stayed on the
        // open page, or `finish_page` reframed a fresh one (its
        // `page_no` digits may have grown). An entry that overflows an
        // *empty* page is the oversized singleton, refused wherever it
        // lands.
        if !self.fits(entry_json_len) {
            return Err(format!(
                "demand feed identity for {} {} encodes to {entry_json_len} \
                 bytes — over the {}-byte page bound",
                entry.crate_name, entry.version, DEMAND_FEED_PAGE_MAX_BYTES
            ));
        }
        self.entries_bytes += usize::from(!self.entries.is_empty()) + entry_json_len;
        self.entries.push(entry);
        Ok(completed)
    }

    /// Close the open page into the exact request for the wire and
    /// open the next page; `None` when nothing is staged. Called by
    /// [`push`](Self::push) at a boundary and once by the caller for
    /// the final remainder.
    ///
    /// # Errors
    /// `page_no` overflows, or the framing fails to serialize.
    pub fn finish_page(&mut self) -> Result<Option<DemandFeedPageRequest>, String> {
        if self.entries.is_empty() {
            return Ok(None);
        }
        let request = DemandFeedPageRequest {
            hour: self.hour.clone(),
            generation: self.generation,
            page_no: self.page_no,
            entries: std::mem::take(&mut self.entries),
        };
        self.entries_bytes = 0;
        self.page_no = self
            .page_no
            .checked_add(1)
            .ok_or_else(|| "demand feed page count overflow".to_owned())?;
        self.reframe()?;
        Ok(Some(request))
    }
}

/// `POST /api/v1/admin/scheduler/demand-feed/complete` request.
///
/// Freezes the hour when every page of this generation is staged. The
/// scheduler verifies the staged counters and the ordered page-hash
/// manifest atomically in the same statement that freezes; after it
/// succeeds the hour's payload is frozen and never re-materialized.
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedCompleteRequest {
    /// UTC hour, already closed.
    pub hour: DemandFeedHour,
    /// The attempt generation the pages were staged under.
    pub generation: i64,
    /// Pages the materializer posted — `0` completes a zero-entry
    /// hour, which then delivers with no demand calls at all.
    pub page_count: u32,
    /// Total entries across all pages.
    pub entry_count: u64,
    /// blake3 rolling hash of the ordered page hashes —
    /// [`demand_feed_manifest`]: `chain(0) = page_hash(0)`, then
    /// `chain(p) = blake3(chain(p-1) || page_hash(p))` — proving every
    /// staged page of this attempt, in order. Ignored when
    /// `page_count` is `0`.
    pub manifest_hash: String,
}

/// `POST /api/v1/admin/scheduler/demand-feed/deliver` request.
///
/// Delivers the next undelivered page of a `complete` hour as one
/// #522 demand batch (`demand-feed/{hour}/{page_no}`). A call is
/// bounded work: one page at a time, the durable `applied` mark
/// advancing only after the batch reports.
///
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedDeliverRequest {
    /// UTC hour, already closed.
    pub hour: DemandFeedHour,
}

/// What `deliver` reports per call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedDeliverReport {
    /// The hour, echoed.
    pub hour: String,
    /// `delivered` when no page remained; `complete` while pages are
    /// still outstanding.
    pub state: String,
    /// The page this call applied, when one remained.
    pub delivered_page: Option<u32>,
    /// Whether the page's batch performed its acceptance transition —
    /// `false` on a lost-ack replay, which still marks the page.
    pub applied: bool,
    /// Queue tasks the delivered page's closures touched.
    pub touched_tasks: u64,
    /// Pages still awaiting delivery after this call.
    pub remaining_pages: u64,
}

/// `GET /api/v1/admin/scheduler/demand-feed/status` answer — the
/// durable resume cursor: the oldest unfinished hour (if any) plus
/// the watermark every hour at or below has fully delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedStatus {
    /// Newest fully delivered hour, `YYYY-MM-DDTHH`.
    pub watermark: Option<String>,
    /// The unfinished hour's header, when the partial index holds one.
    pub unfinished: Option<DemandFeedUnfinished>,
}

/// One unfinished hour header from [`DemandFeedStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandFeedUnfinished {
    /// UTC hour, `YYYY-MM-DDTHH`.
    pub hour: String,
    /// `staging` (materialization in flight) or `complete` (frozen,
    /// pages awaiting delivery).
    pub state: String,
    /// The staging attempt's generation.
    pub generation: i64,
    /// Pages staged so far (staging) or frozen at complete.
    pub staged_pages: i64,
    /// Entries staged so far.
    pub staged_entries: i64,
}

/// Page bounds the feed's wire and Durable Object enforce: the
/// request stays below the 100-bound-parameter / statement-size
/// native limits and the existing 512 KiB operand cap.
pub const DEMAND_FEED_PAGE_MAX_ENTRIES: usize = 256;
/// Serialized `entries` byte ceiling per page.
pub const DEMAND_FEED_PAGE_MAX_BYTES: usize = 512 * 1024;
/// Page rows one `cleanup` call physically retires — payload
/// retirement is bounded indexed event work, never a one-statement
/// wipe of a huge hour (stow#523).
pub const DEMAND_FEED_RETIRE_CHUNK: i64 = 256;
/// `batch_id` prefix the feed derives per page —
/// `demand-feed/{hour}/{page_no}` — so a page's delivery replays the
/// same frozen payload under a stable identity.
pub const DEMAND_FEED_BATCH_PREFIX: &str = "demand-feed/";

/// One queue row as `GET /api/v1/admin/queue` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QueueTask {
    /// Scheduler task identifier.
    pub task_id: String,
    /// Crate name to build.
    pub crate_name: CrateName,
    /// Crate version to build.
    pub version: CrateVersion,
    /// Canonical features list.
    pub features_json: FeaturesJson,
    /// Compilation target.
    pub target: TargetTriple,
    /// Rustc version the row builds for.
    pub rustc_version: WireRustcVersion,
    /// Dispatch lane the row is queued in.
    pub lane: TaskLane,
    /// Lifecycle status.
    pub status: QueueTaskStatus,
    /// Live enqueue epoch — completion reports only apply to this attempt.
    pub attempt: u32,
    /// Last dispatch/build error, empty when none.
    pub error: String,
    /// crates.io download count captured at enqueue time.
    pub downloads: u64,
    /// Cache misses this row is responsible for.
    pub miss_count: u32,
    /// Cache-hit requests this row has served demand for.
    pub request_count: u32,
    /// Dispatches attempted against this row.
    pub dispatch_attempts: u32,
    /// Whether the row builds against its checked-in lockfile.
    pub preserve_lockfile: bool,
    /// GitHub Actions run id the `workflow_run` webhook completion
    /// stamped onto the row.
    #[serde(default)]
    pub github_run_id: Option<String>,
    /// First request timestamp (`YYYY-MM-DD HH:MM:SS` UTC).
    pub first_requested_at: String,
    /// Row creation timestamp.
    pub created_at: String,
    /// Last state-transition timestamp.
    pub updated_at: String,
    /// What holds this row — the failed dependency's task id, or
    /// `unknown dependency identity` when an edge's identity was never
    /// resolved. Set only when `status` is [`QueueTaskStatus::Blocked`].
    #[serde(default)]
    pub blocked_by: Option<String>,
    /// Whether the task builds the crate as a host-side unit
    /// (`EnqueueRequest::host_side`).
    #[serde(default)]
    pub host_side: bool,
    /// The persisted raw value as an exact decimal string: precedence
    /// bands over `MAX(0, priority) + MAX(0, demand)` — the undivided
    /// operand `dispatch_key`'s exact-cost rank divides. The integer
    /// column legitimately outgrows the JavaScript-safe range
    /// (human-lane values sit above 2^53), so the Durable Object
    /// projects `CAST(value AS TEXT)` and this field carries the text
    /// unchanged — parsing or rounding it would corrupt adjacent
    /// values (stow#525 I10).
    pub value: String,
}

/// One in-flight (dispatched/running) queue row in [`AdminStatus`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminInFlight {
    /// Scheduler task identifier.
    pub task_id: String,
    /// Crate name to build.
    pub crate_name: CrateName,
    /// Crate version to build.
    pub version: CrateVersion,
    /// Compilation target.
    pub target: TargetTriple,
    /// Rustc version the row builds for.
    pub rustc_version: WireRustcVersion,
    /// Lifecycle status (`dispatched` or `running`).
    pub status: QueueTaskStatus,
    /// Live enqueue epoch.
    pub attempt: u32,
    /// Dispatches attempted against this row.
    pub dispatch_attempts: u32,
    /// Last state-transition timestamp — the stale-dispatch lease clock.
    pub updated_at: String,
    /// GitHub Actions run id, once the run has reported back.
    #[serde(default)]
    pub github_run_id: Option<String>,
}

/// Per-target completion tallies over the trailing 24 hours.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminTargetStats {
    /// Compilation target.
    pub target: TargetTriple,
    /// Rows that completed in the window.
    pub completed_24h: u32,
    /// Rows that failed in the window.
    pub failed_24h: u32,
}

/// Response of `GET /api/v1/admin/status` — the scheduler's operator view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AdminStatus {
    /// Pending rows in the cache-miss lane.
    pub pending_miss: u32,
    /// Pending rows in the human lane.
    pub pending_human: u32,
    /// Pending rows parked behind a terminally failed dependency.
    #[serde(default)]
    pub blocked: u32,
    /// Age in seconds of the oldest pending row (`first_requested_at`).
    #[serde(default)]
    pub oldest_pending_seconds: Option<u64>,
    /// Dispatched/running rows, oldest transition first.
    pub in_flight: Vec<AdminInFlight>,
    /// Per-target completion tallies over the trailing 24 hours.
    pub targets: Vec<AdminTargetStats>,
    /// Whether the dispatch-freeze breaker is engaged — dispatch stopped,
    /// enqueue still open.
    pub dispatch_frozen: bool,
}

/// Response of `POST /api/v1/scheduler/tasks/submit` — what a request batch
/// became after canonicalization and enqueue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerSubmitResponse {
    /// Requests that canonicalized and were handed to the scheduler.
    pub submitted: u32,
    /// Brand-new queue rows inserted; the rest of `submitted` updated or
    /// merged into existing rows.
    pub inserted: u32,
    /// Requests dropped during canonicalization (unpublished version or
    /// unresolvable `depends_on`).
    pub dropped: u32,
}

/// Response of `GET /api/v1/admin/coverage/{crate}` — per-CI-target
/// servable identities for one crate (one version when `version` was given).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CrateCoverage {
    /// Crate the coverage describes.
    pub crate_name: CrateName,
    /// Version the coverage is scoped to (`None` = every published version).
    #[serde(default)]
    pub version: Option<CrateVersion>,
    /// One entry per [`CI_TARGET_TRIPLES`] target — or just the requested
    /// target — in canonical order; an empty `artifacts` list means the
    /// target has nothing servable.
    pub targets: Vec<CoverageTarget>,
}

/// One target's servable identities inside [`CrateCoverage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CoverageTarget {
    /// Compilation target.
    pub target: TargetTriple,
    /// Servable identities (published bundle rows) for this target.
    pub artifacts: Vec<CoverageArtifact>,
}

/// One servable artifact identity inside [`CoverageTarget`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CoverageArtifact {
    /// Crate version the artifact serves.
    pub version: CrateVersion,
    /// Canonical features list the artifact was built with.
    pub features_json: FeaturesJson,
    /// Rustc version the artifact was built by.
    pub rustc_version: WireRustcVersion,
    /// Cargo `-C metadata` identity.
    pub c_metadata: CMetadata,
    /// Bundle tar size in bytes.
    pub bundle_size: u64,
}

/// Output of `stow-admin preheat plan` — the dry-run enqueue plan for one
/// crate request, computed in-process by `stow-resolver`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreheatPlanResponse {
    /// Crate the plan was computed for.
    pub crate_name: CrateName,
    /// Version the request resolved to.
    pub version: CrateVersion,
    /// Rustc version the plan was computed for.
    pub rustc_version: WireRustcVersion,
    /// One plan per resolved target, in [`CI_TARGET_TRIPLES`] order.
    pub targets: Vec<PreheatPlanTarget>,
}

/// One target's enqueue plan inside [`PreheatPlanResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreheatPlanTarget {
    /// Compilation target.
    pub target: TargetTriple,
    /// Whether the requested crate already has a servable artifact here.
    pub root_cached: bool,
    /// Tasks the dispatch wave would enqueue. A task's `depends_on`
    /// names its own dependencies — the row dispatches once every dep is
    /// servable — so tasks with an empty `depends_on` are the wave's
    /// roots.
    pub tasks: Vec<EnqueueRequest>,
}

/// Response of `GET /api/v1/admin/artifacts/{target}/{rustc_version}/{c_metadata}`:
/// the D1 catalog row plus the bundle image's OCI manifest read from GHCR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactInspection {
    /// The D1 catalog row.
    pub record: ArtifactRecord,
    /// The bundle image's OCI manifest (`manifests/<tag>.bundle`).
    pub manifest: OciManifest,
}

/// OCI image manifest — the document a `manifests/<reference>` GET serves.
/// Wire field names are camelCase (`schemaVersion`, `mediaType`), the
/// OCI distribution spec's casing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OciManifest {
    /// Manifest schema version (`2` for every served document).
    pub schema_version: u32,
    /// Manifest media type.
    #[serde(default)]
    pub media_type: Option<String>,
    /// Config blob descriptor.
    pub config: OciDescriptor,
    /// Layer blob descriptors.
    #[serde(default)]
    pub layers: Vec<OciDescriptor>,
    /// Manifest annotations.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

/// One blob descriptor inside an [`OciManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OciDescriptor {
    /// Blob media type.
    pub media_type: String,
    /// `sha256:…` content digest.
    pub digest: String,
    /// Blob size in bytes.
    pub size: u64,
    /// Descriptor annotations.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

/// Query for `GET /api/v1/admin/artifacts` — a bounded catalog listing
/// used to preview a prune and for ad-hoc inspection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactListQuery {
    /// Only rows built by this rustc version.
    #[serde(default)]
    pub rustc_version: Option<WireRustcVersion>,
    /// Only rows for this compilation target.
    #[serde(default)]
    pub target: Option<TargetTriple>,
    /// Only rows for this crate (`crate` on the wire).
    #[serde(default, rename = "crate", alias = "crate_name")]
    pub crate_name: Option<CrateName>,
    /// Most rows to return (bounded server-side).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Request body for `POST /api/v1/admin/artifacts/prune`.
///
/// Deletes every catalog row built by `rustc_version` — the retired
/// toolchain. GHCR image tags
/// are not deleted; they age out under the package's own retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactPruneRequest {
    /// Retired toolchain whose rows are pruned.
    pub rustc_version: WireRustcVersion,
}

/// Response of `POST /api/v1/admin/artifacts/prune`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactPruneResponse {
    /// Catalog rows deleted.
    pub deleted: u32,
}

#[cfg(test)]
mod tests {
    use super::{
        CI_TARGET_TRIPLES, DEMAND_FEED_PAGE_MAX_BYTES, DEMAND_FEED_PAGE_MAX_ENTRIES,
        DemandFeedHour, DemandFeedPageBuilder, RunnerFamily, SchedulerDemandEntry, runner_family,
    };
    use crate::identity::FeaturesJson;

    /// Every CI target must land in exactly one family, and the families'
    /// `targets()` lists together must be exactly `CI_TARGET_TRIPLES` —
    /// drift between this mapping and the `runs-on` map in
    /// `build-crate.yml` would let the scheduler cap and order the wrong
    /// rows.
    #[test]
    fn runner_families_partition_ci_target_triples() {
        let mut mapped: Vec<&str> = Vec::new();
        for family in RunnerFamily::ALL {
            mapped.extend_from_slice(family.targets());
        }
        mapped.sort_unstable();
        let mut all = CI_TARGET_TRIPLES.to_vec();
        all.sort_unstable();
        assert_eq!(mapped, all);
        for target in CI_TARGET_TRIPLES {
            assert!(
                runner_family(target).is_some(),
                "{target} maps to no runner family"
            );
        }
        assert_eq!(runner_family("aarch64-unknown-linux-musl"), None);
    }

    fn hour(raw: &str) -> DemandFeedHour {
        DemandFeedHour::parse(raw).expect("test hour")
    }

    fn entry(crate_name: &str, features: usize) -> SchedulerDemandEntry {
        SchedulerDemandEntry {
            crate_name: crate_name.parse().expect("demand crate"),
            version: "1.0.0".parse().expect("demand version"),
            features_json: FeaturesJson::canonicalize(
                (0..features)
                    .map(|index| format!("feat{index:0124}"))
                    .collect(),
            )
            .expect("features"),
            target: "x86_64-unknown-linux-gnu".parse().expect("demand target"),
            rustc_version: "1.85.0".parse().expect("demand rustc"),
            demand: 1,
        }
    }

    /// An entry whose `serde_json` length is exactly `target` bytes —
    /// real features carry the size (feature names cap at 128 chars,
    /// so bulk comes from many max-length names and the trailing
    /// "z"-name tunes the last byte). `features_json` serializes its
    /// raw list as one JSON string, so the inner quotes escape: a name
    /// of length L contributes `L + 5` bytes (`\"name\"` plus the
    /// separating comma) and a non-empty list costs `Σ(L+5) + 3` over
    /// the bare `"[]"`.
    /// Build an entry whose serialized length is exactly `target`
    /// bytes: a `crate_name`/`version`/… skeleton plus a feature list
    /// sized through the serializer's own accounting. `FeaturesJson`
    /// serializes as a JSON *string* holding the inner array, so each
    /// name's quotes escape — a name of `len` chars contributes
    /// `len + 5` bytes (`\"name\"` plus the separating comma), and a
    /// non-empty list adds `3` over the bare `"[]"`. 128-char bulk
    /// names contribute 133 apiece; a final tuned `"z"`-name closes
    /// the remainder (and, when the remainder is under one name's
    /// minimum, the last bulk name shrinks to make room). Verified by
    /// measuring — the assertion is the test's own proof.
    fn sized_entry(crate_name: &str, target: usize) -> SchedulerDemandEntry {
        let bare = entry(crate_name, 0);
        let bare_len = serde_json::to_vec(&bare).expect("measure").len();
        assert!(
            target > bare_len,
            "target {target} is below a one-name entry"
        );
        // `need` is what the feature list must contribute over the
        // bare `"[]"`: Σ(len + 5) - 1 with the +3 list overhead.
        let need = target - bare_len + 1;
        assert!(need >= 6, "target {target} leaves no room for a name");
        let count = need / 133;
        let rest = need - count * 133; // the tuned name's len+5
        let mut features: Vec<String> = (0..count).map(|index| format!("f{index:0127}")).collect();
        match rest {
            // Shrink the last bulk name by `6 - rest` chars and add a
            // one-char "z" name: `-(6 - rest) + 1 + 5 = rest`.
            1..=5 => {
                let last = features.pop().expect("a bulk name");
                features.push(last[..last.len() - (6 - rest)].to_owned());
                features.push("z".to_owned());
            }
            // The tuned name alone covers `rest - 5` chars.
            _ => features.push("z".repeat(rest - 5)),
        }
        let mut sized = bare;
        sized.features_json = FeaturesJson::canonicalize(features).expect("features");
        let measured = serde_json::to_vec(&sized).expect("measure").len();
        assert_eq!(measured, target, "sized entry must land exactly");
        sized
    }

    /// The bound is the *whole* serialized request envelope —
    /// `hour`/`generation`/`page_no` framing plus the entries array —
    /// and the builder's accounting must land exactly on it: an entry
    /// that fills the envelope to the byte stays inside the page, and
    /// the same entry one byte longer splits the page — no slack band,
    /// no early rejection of what legitimately fits.
    #[test]
    fn page_builder_accounts_the_exact_envelope() {
        let hour = hour("2020-01-01T00");
        let plain = entry("crate-a", 0);
        let plain_len = serde_json::to_vec(&plain).expect("measure").len();
        for delta in [0_usize, 1] {
            let mut builder = DemandFeedPageBuilder::new(hour.clone(), 7).expect("builder");
            assert!(builder.push(plain.clone()).expect("push").is_none());
            // The empty framing plus `plain` plus the separating
            // comma is already committed; the second entry must fill
            // the remaining room exactly (delta 0) or overflow by one
            // byte (delta 1).
            let framing = serde_json::to_vec(&super::DemandFeedPageRequest {
                hour: hour.clone(),
                generation: 7,
                page_no: 0,
                entries: Vec::new(),
            })
            .expect("framing")
            .len();
            let fat = sized_entry(
                "crate-b",
                DEMAND_FEED_PAGE_MAX_BYTES - framing - plain_len - 1 + delta,
            );
            let boundary = builder.push(fat).expect("push");
            if delta == 0 {
                assert!(boundary.is_none(), "exact-fit entry stays in the page");
                let page = builder.finish_page().expect("page").expect("staged");
                assert_eq!(page.entries.len(), 2);
                let encoded = serde_json::to_vec(&page).expect("encode").len();
                assert_eq!(encoded, DEMAND_FEED_PAGE_MAX_BYTES);
            } else {
                // One byte over: the push must close a page holding
                // `plain` alone and open a fresh one for `fat`.
                let completed = boundary.expect("boundary page");
                assert_eq!(completed.page_no, 0);
                assert_eq!(completed.entries, vec![plain.clone()]);
            }
        }
    }

    /// An entry whose own encoding cannot fit an empty envelope is a
    /// hard failure — no page can carry it.
    #[test]
    fn page_builder_refuses_a_singleton_overrun() {
        let hour = hour("2020-01-01T00");
        let mut builder = DemandFeedPageBuilder::new(hour, 1).expect("builder");
        let fat = sized_entry("crate-b", DEMAND_FEED_PAGE_MAX_BYTES);
        let error = builder.push(fat).expect_err("oversized singleton");
        assert!(error.contains("over the"), "{error}");
        assert!(builder.finish_page().expect("page").is_none());
    }

    /// Pages split at the byte boundary with real feature payloads:
    /// a large entry fills most of an envelope, the next large entry
    /// cannot share it, and the boundary the push returns carries the
    /// full first page while `page_no` advances — its own digits are
    /// part of the measured framing.
    #[test]
    fn page_builder_splits_on_the_byte_boundary() {
        let hour = hour("2020-01-01T00");
        let mut builder = DemandFeedPageBuilder::new(hour, 1).expect("builder");
        // ~400 KiB of real feature names — a page holds one, never two.
        let fat = || sized_entry("crate-a", 400_000);
        assert!(builder.push(fat()).expect("push").is_none());
        let first = builder.push(fat()).expect("push").expect("boundary");
        assert_eq!(first.page_no, 0);
        assert_eq!(first.entries.len(), 1);
        assert!(serde_json::to_vec(&first).expect("encode").len() <= DEMAND_FEED_PAGE_MAX_BYTES);
        // A third entry splits again — the fresh page measures its own
        // `page_no = 1` framing.
        let second = builder.push(fat()).expect("push").expect("boundary");
        assert_eq!(second.page_no, 1);
        // A small entry shares the open page with the third fat one.
        assert!(builder.push(entry("crate-b", 0)).expect("push").is_none());
        let remainder = builder.finish_page().expect("page").expect("staged");
        assert_eq!(remainder.page_no, 2);
        assert_eq!(remainder.entries.len(), 2);
        assert!(builder.finish_page().expect("page").is_none());
    }

    /// An oversized entry behind a small staged one is still refused:
    /// the boundary completes the small page, then the post-reframe
    /// check fails the entry on the fresh page — no append slips
    /// through behind the completed page.
    #[test]
    fn page_builder_refuses_an_oversized_entry_after_a_boundary() {
        let hour = hour("2020-01-01T00");
        let mut builder = DemandFeedPageBuilder::new(hour, 1).expect("builder");
        assert!(builder.push(entry("crate-a", 0)).expect("push").is_none());
        let fat = sized_entry("crate-b", DEMAND_FEED_PAGE_MAX_BYTES);
        let error = builder.push(fat).expect_err("oversized after boundary");
        assert!(error.contains("over the"), "{error}");
        assert!(builder.finish_page().expect("page").is_none());
    }

    /// `page_no` 9 → 10 grows the framing by a digit: an entry sized
    /// to fill the old page's empty envelope exactly is one byte over
    /// the new page's — the post-reframe check catches what the first
    /// check could not have known.
    #[test]
    fn page_builder_rechecks_the_fresh_page_no_framing() {
        let hour = hour("2020-01-01T00");
        let mut builder = DemandFeedPageBuilder::new(hour.clone(), 1).expect("builder");
        // Two large entries never share a page, so every push after
        // the first completes a page — ten pushes leave one staged
        // entry on `page_no` 9.
        let fat = || sized_entry("crate-f", 300_000);
        for _ in 0..10 {
            builder.push(fat()).expect("push");
        }
        let framing_9 = serde_json::to_vec(&crate::api::DemandFeedPageRequest {
            hour,
            generation: 1,
            page_no: 9,
            entries: Vec::new(),
        })
        .expect("frame")
        .len();
        let boundary = sized_entry("crate-x", DEMAND_FEED_PAGE_MAX_BYTES - framing_9);
        let error = builder.push(boundary).expect_err("digit boundary refusal");
        assert!(error.contains("over the"), "{error}");
    }

    /// The 256-entry cap is unchanged: entry 257 splits the page at
    /// the count bound even with bytes to spare.
    #[test]
    fn page_builder_keeps_the_entry_cap() {
        let hour = hour("2020-01-01T00");
        let mut builder = DemandFeedPageBuilder::new(hour, 1).expect("builder");
        let small = entry("crate-a", 0);
        for _ in 0..DEMAND_FEED_PAGE_MAX_ENTRIES {
            assert!(builder.push(small.clone()).expect("push").is_none());
        }
        let completed = builder.push(small).expect("push").expect("boundary");
        assert_eq!(completed.entries.len(), DEMAND_FEED_PAGE_MAX_ENTRIES);
    }

    /// `latest_closed` must return `None` — never panic — at and below
    /// the i64 floor, where the unchecked `floor - 3600` overflowed.
    #[test]
    fn latest_closed_is_checked_at_the_range_boundary() {
        for now in [i64::MIN, i64::MIN + 1] {
            assert_eq!(DemandFeedHour::latest_closed(now), None);
        }
        // The hour ending at the epoch boundary: closed at 3600s,
        // still open at 3599 — the previous hour answers there.
        assert_eq!(
            DemandFeedHour::latest_closed(3_600).map(|h| h.as_str().to_owned()),
            Some("1970-01-01T00".to_owned())
        );
        assert_eq!(
            DemandFeedHour::latest_closed(3_599).map(|h| h.as_str().to_owned()),
            Some("1969-12-31T23".to_owned())
        );
    }
}
/// Public aggregate usage statistics served by `GET /api/v1/stats`.
///
/// Every count is derived from anonymized Analytics Engine events: hit
/// events are sampled at one in ten and their published counts are scaled
/// by the stored sample weight, so the numbers are approximate by design.
/// Fields that could publish a dangerously small count are suppressed
/// (`None`) rather than reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct UsageStats {
    /// Average number of distinct installs served a cache hit per day over
    /// the last 7 days, counted by daily-salted unlinkable install hash (a
    /// hash cannot be joined across days, so the figure is per-day, and
    /// hits are sampled, so it is a lower bound). `None` below the minimum
    /// publication threshold — stow never reports small counts.
    pub daily_active_installs_7d: Option<u64>,
    /// Cache hits served in the last 24 hours (sample-scaled estimate).
    pub hits_24h: u64,
    /// Cache misses served in the last 24 hours.
    pub misses_24h: u64,
    /// `hits_24h / (hits_24h + misses_24h)`; `0.0` when nothing was served.
    pub hit_rate_24h: f64,
    /// CPU-hours of rustc compilation saved in the last 30 days: the
    /// recorded compile time of every artifact served, sample-scaled.
    pub cpu_hours_saved_30d: f64,
    /// Most-served crates over the last 30 days.
    pub top_crates_30d: Vec<UsageStatEntry>,
    /// Hits per compilation target over the last 30 days.
    pub targets_30d: Vec<UsageStatEntry>,
    /// Hits per CLI version over the last 30 days; requests that sent no
    /// `stow-cli` user agent are not counted under any version.
    pub cli_versions_30d: Vec<UsageStatEntry>,
}

/// One `(name, hits)` bucket of a [`UsageStats`] leaderboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct UsageStatEntry {
    /// Bucket label: crate name, target triple, or CLI version.
    pub name: String,
    /// Sample-scaled hit count for the bucket.
    pub hits: u64,
}

/// The public routes whose handlers reach the scheduler Durable Object —
/// the "scheduler lanes".
///
/// The edge router mounts these paths verbatim and the zone's
/// `stow maintenance: scheduler lanes` WAF rule turns the same list into
/// `starts_with` clauses (stow#453), so this is the one place a lane is
/// added or removed. The index routes are deliberately absent: they
/// reach the DO only to resolve `rustc_version=stable`, and blocking
/// them would shed the bundle byte path the lanes scope exists to keep
/// serving.
pub mod scheduler_lanes {
    /// `POST /api/v1/admissions` — miss-admission minting drains to the
    /// scheduler's enqueue path.
    pub const ADMISSIONS: &str = "/api/v1/admissions";
    /// `POST /api/v1/enqueue` — admission redemption enqueues on the DO.
    pub const ENQUEUE: &str = "/api/v1/enqueue";
    /// `POST /api/v1/requests` — the human request lane submits to the DO.
    pub const REQUESTS: &str = "/api/v1/requests";
    /// `GET /api/v1/requests/{request_id}` — the JSON status read hits the DO.
    pub const REQUEST: &str = "/api/v1/requests/{request_id}";
    /// `GET /requests/{request_id}` — the request-status page reads the DO.
    pub const REQUEST_PAGE: &str = "/requests/{request_id}";

    /// Every scheduler-lane path — the router's mount list and the WAF
    /// rule's block list are both built from this.
    pub const ALL: &[&str] = &[ADMISSIONS, ENQUEUE, REQUESTS, REQUEST, REQUEST_PAGE];
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    /// Whether this node keys differently under the explicit
    /// `--target <host>` spelling — `KeysApart` exactly when a proc-macro
    /// sits in its `--extern` closure (stow#736). A target-side task at
    /// the runner's host triple runs and publishes both invocation
    /// spellings under it. Semantic graph data, never task identity: no
    /// default — the flag is derived from the resolved graph.
    pub explicit_spelling: crate::public_cache::ExplicitSpelling,
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
    /// Whether the node keys differently under the explicit `--target`
    /// spelling — `ExplicitSpelling::KeysApart` (stow#736). Absent on the
    /// wire means `KeysAsNative`: the compact encoding writes only `true`.
    #[serde(rename = "x", default, skip_serializing_if = "std::ops::Not::not")]
    pub keys_apart: bool,
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
                keys_apart: node.explicit_spelling
                    == crate::public_cache::ExplicitSpelling::KeysApart,
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
    /// index past the node list. `root_spelling` is the task node's own
    /// `ExplicitSpelling`: the root's identity comes from the payload's
    /// fields, so the flag rides beside them rather than in the node
    /// list.
    pub fn resolve(
        &self,
        root: &TaskNodeIdentity,
        root_spelling: crate::public_cache::ExplicitSpelling,
    ) -> crate::error::Result<ResolvedTaskGraph> {
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
            explicit_spelling: root_spelling,
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
                explicit_spelling: if node.keys_apart {
                    crate::public_cache::ExplicitSpelling::KeysApart
                } else {
                    crate::public_cache::ExplicitSpelling::KeysAsNative
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
            .resolve(&self.task_node_identity(), self.explicit_spelling)?;
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
            return Err(self.oversize_dispatch_error(encoded.len()));
        }
        Ok(encoded)
    }

    /// The error raised when this task's encoding cannot ride a
    /// `workflow_dispatch` input.
    fn oversize_dispatch_error(&self, encoded_len: usize) -> crate::error::Error {
        stow_error!(
            "build task {} {} on {} encodes to {} characters across {} dependency nodes — over the {}-character workflow_dispatch input cap",
            self.crate_name,
            self.version,
            self.target,
            encoded_len,
            self.dependency_subgraph.nodes.len(),
            DISPATCH_INPUT_LIMIT,
        )
    }
}

/// `value` is exactly `len` lowercase ASCII hex digits.
fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// A validated hex id on the wire: construction runs only through
/// [`FromStr`](std::str::FromStr)/`TryFrom<String>`, and serde
/// deserializes through the same check so a malformed wire value fails
/// at the boundary.
macro_rules! hex_newtype {
    (
        $(#[$meta:meta])*
        $name:ident, $len:literal, $what:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Borrow the hex string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = crate::error::Error;

            fn from_str(value: &str) -> crate::error::Result<Self> {
                if is_lower_hex(value, $len) {
                    Ok(Self(value.to_owned()))
                } else {
                    Err(stow_error!(
                        concat!(
                            "invalid ",
                            $what,
                            " `{0}`: must be exactly ",
                            stringify!($len),
                            " lowercase hex"
                        ),
                        value
                    ))
                }
            }
        }

        impl TryFrom<String> for $name {
            type Error = crate::error::Error;

            fn try_from(value: String) -> crate::error::Result<Self> {
                value.parse()
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

hex_newtype!(
    /// The first 16 hex of blake3(`task_id`) — the task-id digest the
    /// `records-<rustc>-<task hash>-<run id>-<attempt>` artifact tag
    /// carries.
    TaskHash,
    16,
    "task hash"
);

impl TaskHash {
    /// The task hash `task_id` carries — `blake3(task_id)`'s first 16
    /// hex.
    #[must_use]
    pub fn of(task_id: &str) -> Self {
        Self(blake3::hash(task_id.as_bytes()).to_hex()[..16].to_owned())
    }
}

/// One artifact a trusted build published.
///
/// The element of the `Vec<ArtifactRecord>` the publish stage serializes
/// into the signed `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>`
/// GHCR artifact once the build, re-hash, validation, sign, and push have
/// all succeeded. Nothing
/// POSTs it anywhere else — `index export` folds the verified records
/// into the signed index slices in GHCR every reader resolves against.
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
    /// The node's direct child task ids — the sorted, deduplicated
    /// preimage [`Self::dependency_identity`] hashes (stow#919). They
    /// are the node's task-graph edges: build-dependency libs and shadow
    /// twins included, which the `--extern` list never names.
    pub dependency_task_ids: Vec<String>,
    /// OCI reference (e.g., "ghcr.io/water-rs/stow-cache-<rustc>:serde.1.0.0-...").
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
    /// spelling that produced it, and whether it links. The coverage
    /// checks and the dependency gate compare it.
    pub unit_shape: crate::public_cache::UnitShape,
    /// Lowest glibc the artifact's ELF members can `dlopen` against — the
    /// highest `GLIBC_x.y` in their version-needed entries, measured at
    /// publish. `None` for non-ELF payloads and for artifacts with no glibc
    /// dependency; only an ELF built for a newer glibc carries `Some`, and
    /// that is exactly the case a client must refuse before downloading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<String>)]
    pub min_glibc: Option<GlibcVersion>,
}

impl ArtifactRecord {
    /// The Merkle dependency digest of the dependency subgraph the
    /// artifact was built under (stow#588) — the node's context key,
    /// derived from the carried child task ids so a record can never
    /// hold a digest disagreeing with its edges (stow#919).
    ///
    /// # Errors
    /// Mirrors [`DependencyIdentity::from_task_ids`].
    pub fn dependency_identity(&self) -> crate::error::Result<DependencyIdentity> {
        DependencyIdentity::from_task_ids(self.dependency_task_ids.iter().map(String::as_str))
    }
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
    /// Whether this node keys differently under the explicit
    /// `--target <host>` spelling — `KeysApart` exactly when a proc-macro
    /// sits in its `--extern` closure (stow#736). A target-side task at
    /// the runner's host triple runs and publishes both invocation
    /// spellings under it. Semantic graph data, never task identity: no
    /// default — the flag is derived from the resolved graph a request
    /// carries.
    pub explicit_spelling: crate::public_cache::ExplicitSpelling,
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
    /// Whether the dep node keys differently under the explicit
    /// `--target <host>` spelling (stow#736). The edge's shape gate
    /// requires the dep's four-shape set under it.
    pub explicit_spelling: crate::public_cache::ExplicitSpelling,
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
        self.dependency_subgraph
            .resolve(&self.task_node_identity(), self.explicit_spelling)
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
                    explicit_spelling: node.explicit_spelling,
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
    /// The submission tree this admission authorizes (stow#878). The
    /// edge is stateless: the client echoes `tree` back in its ticket
    /// and `/api/v1/enqueue` forwards it to the scheduler after
    /// verifying the challenge binds it.
    pub tree: SubmissionTree,
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
    /// The submission tree from the admission (stow#878). The edge
    /// recomputes the challenge HMAC over this payload and forwards it
    /// to the scheduler — no server-side tree lookup.
    pub tree: SubmissionTree,
}

/// Request body for `POST /api/v1/build-report`: the install's usage
/// deltas accumulated since its last report (stow#889).
///
/// The CLI posts at most one report per UTC day per install; every
/// counter is a delta, not a total. The body carries no crate names,
/// digests, dependency graph or lockfile — identity dimensions arrive
/// on headers (`User-Agent`, `x-stow-ci`) and the edge's cf metadata.
/// Under `STOW_NO_ANALYTICS=1` the CLI posts no report at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BuildReport {
    /// Builds the install ran since the last report — supervised runs
    /// plus drained plain-cargo builds.
    pub builds: u64,
    /// Artifacts served from the cache (local or downloaded).
    pub hits: u64,
    /// Artifacts compiled locally.
    pub misses: u64,
    /// Recorded compile time of every served artifact — the rustc CPU
    /// time this install skipped.
    pub cpu_millis_saved: u64,
}

/// The submission kinds a CLI may claim through `/api/v1/admissions`
/// (stow#882): a two-variant wire type *is* the validation — a CLI can
/// never claim an operations, human or preheat source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CliAdmissionSource {
    /// A cache miss — the node's chain is uncovered.
    CacheMiss,
    /// An inexact superset-hit report — the exact chain the cache
    /// should build next at very low priority.
    InexactHit,
}

impl CliAdmissionSource {
    /// The scheduler source the admission's tree carries.
    #[must_use]
    pub const fn submission_source(self) -> SubmissionSource {
        match self {
            Self::CacheMiss => SubmissionSource::CacheMiss,
            Self::InexactHit => SubmissionSource::InexactHit,
        }
    }
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
    /// What the report is — a miss or an inexact superset-hit report
    /// (stow#882), the only kinds a CLI may claim.
    pub source: CliAdmissionSource,
    /// Direct-dep entries the local resolver found uncovered.
    pub entries: Vec<DependencyGraphEntry>,
    /// The client's resolved transitive graph.
    #[serde(default)]
    pub expanded_entries: Vec<ResolvedDependencyGraphEntry>,
}

/// How `-` is spelled inside a record id's segment: `_`.
///
/// `-` is the segment separator, so a value's own dashes are written
/// `_`. Task ids ([`task_id_prefix`]) spell target and rustc this way,
/// request ids ([`request_id`]) spell rustc this way; the segment
/// cannot be decoded by reversing the spelling because a value may
/// itself carry `_` (`x86_64`), so readers match a known set against
/// this encoding.
#[must_use]
pub fn task_id_segment(value: &str) -> String {
    value.replace('-', "_")
}

/// The `<crate>-<version>-<features hash>-<target>-<rustc>` prefix every
/// task id shares — [`crate::task_graph::TaskNodeIdentity::task_id`]
/// inserts the `-d<dependency digest>` segment and appends `-host` —
/// there is no digest-less spelling of a task id (stow#588).
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
        task_id_segment(target),
        task_id_segment(rustc_version)
    )
}

/// Completion the edge's `POST /api/v1/github/workflow-run` handler
/// forwards to the scheduler Durable Object's `POST /tasks/complete-run`
/// for a finished `build-crate.yml` run.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WorkflowRunComplete {
    /// The task id the run's `<rustc>-<task_id>` title named.
    pub task_id: String,
    /// The run's `conclusion` mapped onto success: only a run that
    /// finished green *and* whose run's records artifact exists in GHCR
    /// counts as a completed build.
    pub success: bool,
    /// Failure description when `success` is false — the conclusion and,
    /// on a missing records artifact, which tag the edge looked for.
    pub error: Option<String>,
    /// Not a build verdict — the scheduler re-queues the task without
    /// recording a failure or bumping the attempt: the run's `conclusion`
    /// was `cancelled` on a superseded duplicate of the task's concurrency
    /// group (stow#877), or the edge could not verify the successful run's
    /// records artifact in GHCR — a transient check failure, not a build
    /// verdict (stow#944).
    #[serde(default)]
    pub cancelled: bool,
    /// The GitHub Actions run id, stamped onto the queue row so
    /// `stow-admin status` surfaces the run URL. Required — the
    /// `workflow_run` delivery always carries the run's `id`, so a
    /// report without one is not the webhook's shape.
    pub github_run_id: String,
}

/// The `workflow_run` `in_progress` delivery for a `build-crate.yml`
/// run → the DO's `POST /tasks/run-update`, which moves the bound
/// row `dispatched` → `running` (stow#876).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TaskRunUpdate {
    /// The task id the run's `<rustc>-<task_id>` title named.
    pub task_id: String,
    /// The Actions run id the row's generation is bound to.
    pub github_run_id: String,
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
    /// Whether this node keys differently under the explicit
    /// `--target <host>` spelling (stow#736) — the flag its
    /// `EnqueueRequest` mints with.
    pub explicit_spelling: crate::public_cache::ExplicitSpelling,
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

/// The longest a started `build-crate.yml` run lasts.
///
/// Its `build` job's `timeout-minutes` plus its `publish` job's, both
/// enforced by GitHub, so the run's `completed` delivery lands within
/// it. The scheduler's
/// health check (stow#860) calls deliveries stopped past it; the admin
/// workflow tests pin it to the workflow file.
pub const BUILD_CRATE_RUN_TIMEOUT_MINUTES: i64 = 120 + 60;

/// How often, at most, the scheduler reconciles its run set against the
/// CI listing.
///
/// It reconciles only while the graph holds work: at most 2 listing
/// calls each, at most 12 calls an hour (stow#877). The completion's inline pass skips it and leaves it to the alarm, so
/// it is also the floor on the alarm's timer wakes under steady build
/// traffic, which the traffic projection prices from it (stow#940).
pub const STATUS_RECONCILE_MS: i64 = 10 * 60 * 1000;

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

impl DispatchFreezeTrigger {
    /// The one-word trigger summary — the serde `kind` tag the stored
    /// record serializes under, which `GET /api/v1/scheduler/health`'s
    /// `freeze_trigger` echoes (stow#860).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Tripped(_) => "tripped",
            Self::Cost(_) => "cost",
        }
    }
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
    /// Scheduler Durable Object SQL rows read.
    SqlRowsRead,
    /// Scheduler Durable Object SQL rows written.
    SqlRowsWritten,
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
    /// The daily budget the usage is compared against — 80% of the
    /// monthly Workers Paid allowance divided by 30, times
    /// `STOW_COST_BUDGET_MULTIPLIER` (stow#883).
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

/// One component's health as `GET /api/v1/scheduler/health` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// Serving within its contract.
    Ok,
    /// Outside its contract — the route answers 503 so a plain HTTP
    /// uptime check sees it without parsing the body.
    Unhealthy,
}

/// The uncached health answer of `GET /api/v1/scheduler/health`
/// (stow#860) — one scheduler request reading state it already holds:
/// no D1, no GHCR, no GitHub call.
///
/// The serving Worker is `ok` by construction (answering the request
/// is the proof); the scheduler is `unhealthy` while the dispatch
/// freeze is engaged or while a run is `running` with no
/// `workflow_run` delivery accepted inside `build-crate.yml`'s
/// job-timeout bound.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SchedulerHealth {
    /// The serving Worker — always `ok`.
    pub worker: HealthState,
    /// The scheduler Durable Object's verdict on itself.
    pub scheduler: HealthState,
    /// Whether the dispatch freeze is engaged.
    pub dispatch_frozen: bool,
    /// One-word summary of the freeze's trigger as the freeze already
    /// records it (`manual` / `tripped` / `cost`) — `null` while not
    /// frozen.
    pub freeze_trigger: Option<String>,
    /// Seconds since the scheduler last accepted a `workflow_run`
    /// delivery — `null` before the first one.
    pub last_run_update_age_seconds: Option<u64>,
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
        task_id_segment(rustc_version)
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
        /// The uncovered human-lane dependency trees across every
        /// target's closure (stow#878) — one tree per source graph.
        trees: Vec<SubmissionTree>,
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

/// The index-publish path's report of what a slice serves.
///
/// One slice of a [`PublishedRunReport`], the body of
/// `POST /api/v1/admin/index/published`, sent after the run's slices go
/// live. The scheduler stores the set as the
/// membership the dependency gate checks a dependent's edges against —
/// a dependent dispatches only when every dependency resolves to a row
/// the latest report for that dependency's own `(target, rustc_version)`
/// covers.
///
/// Two report shapes share the wire:
///
/// - **Delta** — `base_generation` is the index generation the report's
///   base was taken from; `added`/`retired` carry only what moved. The
///   scheduler 409s when its live generation moved past the base —
///   `index report` then resyncs once with a full report; a stale
///   delta is never retried.
/// - **Full** — `base_generation` is `None`, `added` carries the slice's
///   whole membership and `retired` is empty; the scheduler computes the
///   delta itself. This is the first-publish path, the
///   `stow-admin index report --full` resync, and the resync a refused
///   delta triggers.
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
/// separately.
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
    pub unit_shape: crate::public_cache::UnitShape,
    /// The Merkle dependency digest the row was built under (stow#588) —
    /// the dependency context the gate's coverage clause joins on.
    pub dependency_identity: DependencyIdentity,
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
/// A publish run's one report: every slice the run published, carried
/// in a single `POST /api/v1/admin/index/published` so the scheduler
/// applies them in one append and one inline pass (stow#940).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PublishedRunReport {
    /// The run's slices — each a [`PublishedSlice`]: the
    /// `(target, rustc_version)` pair, the delta or full membership.
    pub slices: Vec<PublishedSlice>,
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

/// What `POST /api/v1/admin/scheduler/reset` reports — the operator
/// reset dropped every store object and re-executed `schema.sql`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerResetReport {
    /// Schema objects (tables, indexes, triggers, views) the reset
    /// dropped before recreating the schema.
    pub dropped: u64,
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
}

/// What the seed reports back: the graph the call built, snapshotted
/// and installed. One call seeds the whole fixture — the store wipe,
/// the snapshot chunks and the log tail run inside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerSeedReport {
    /// Nodes the graph holds now.
    pub nodes: u64,
    /// Dependency edges the graph holds now.
    pub edges: u64,
    /// Published identities the graph holds now.
    pub published: u64,
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
    /// Σ `meta.rowsRead` over statements the drive issued through
    /// the counted catalog backend — the coverage lookups a claim pays
    /// per page, carried separately because the counted backend bills a different
    /// product than the object's own rows.
    pub sql_rows_read: u64,
    /// Σ `meta.rowsWritten` over the same statements.
    pub sql_rows_written: u64,
    /// Σ of the awaited durations of the counted catalog backend's
    /// own calls. A sum of operation spans, not a share of drive
    /// wall: concurrent calls overlap in real time but add up here,
    /// so it can exceed the drive's measured window. `0` on host and
    /// on drives that never touch the catalog.
    pub sql_elapsed_ms: u64,
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

/// Body of `POST /api/v1/admin/scheduler/budget/rearm`.
///
/// The traffic-cost callback lane's refill: re-arm the seeded fixture's
/// in-flight runs its deliveries resolved, so every delivery it fires
/// is a first delivery. Only deploys that set `STOW_SCHEDULER_BUDGET`
/// answer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerRearmRequest {
    /// Queue rows of the fixture the caller derives its runs from —
    /// refused unless it is the size the store was last seeded at, so
    /// the caller's run ids are the store's.
    pub queue_rows: u32,
}

/// What `POST /api/v1/admin/scheduler/budget/rearm` answers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerRearmReport {
    /// Every armed in-flight index `k` after the re-arm, ascending —
    /// each run is `crate::fixture::FixtureShape::in_flight_run(k)`,
    /// bound to its own run with no completion recorded. The whole set,
    /// not the call's increment: a caller replaces what it holds with it.
    pub armed: Vec<u32>,
}

/// What `GET /api/v1/admin/scheduler/budget/ledger` returns.
///
/// The scheduler Durable Object's billed `rowsRead`/`rowsWritten` booked
/// per operation since the store was reset — the per-event view of the
/// cost the one-row `meter` checkpoint holds per day. The object books it only on deploys
/// carrying `STOW_SCHEDULER_BUDGET=1` (the mock stack); the `Preheat
/// cost` lane (stow#773) snapshots it between layers and diffs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerLedger {
    /// When the object last loaded its graph, unix ms. The ledger lives
    /// on that graph and persists only through its snapshot, so a
    /// reload drops every booking since the snapshot: two reads that
    /// answer different values are not comparable.
    pub woken_at_ms: i64,
    /// One row per operation the object ran, in `op` order.
    pub ops: Vec<SchedulerLedgerOp>,
}

/// One operation's accumulated cost in a [`SchedulerLedger`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SchedulerLedgerOp {
    /// The operation: `<METHOD> <route>` for a request (a request id
    /// segment collapses to `{id}`), or
    /// [`crate::do_budgets::LEDGER_OP_ALARM`] for an alarm pass.
    pub op: String,
    /// How many times the operation ran.
    pub events: u64,
    /// `rowsRead` the operation's statements were billed, summed.
    pub rows_read: u64,
    /// `rowsWritten` the operation's statements were billed, summed.
    pub rows_written: u64,
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
    /// The node's rank operand — its priority — as a decimal
    /// string (stow#879): what `priority × time waited` multiplies.
    /// Carried as text so a listing never loses precision however the
    /// operand's units evolve.
    pub value: String,
    /// The demand the hourly feed has folded into the node. It does
    /// not enter the rank.
    pub demand: i64,
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
    /// The live generation's claim instant — the stale-dispatch lease
    /// clock. Immutable for the generation; a re-request bumping
    /// `updated_at` cannot postpone recovery (stow#786).
    pub claimed_at: String,
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

/// One task the submit-by-id lane promotes: a task id whose nodes are
/// already in the scheduler's node store, with the miss demand the
/// promoted row keeps for ranking (stow#588).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SubmitTaskIdEntry {
    /// The full contextual task id the node store holds.
    pub task_id: String,
    /// The demand the queue row records (`downloads` on the minted
    /// request).
    pub downloads: u64,
}

/// Body of `POST /api/v1/scheduler/tasks/submit-ids`.
///
/// The scheduler resolves each id's subgraph from its node store; an id
/// the store does not hold is reported as unknown and never re-minted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SubmitTaskIdsRequest {
    /// The task ids to promote, in submit order.
    pub tasks: Vec<SubmitTaskIdEntry>,
}

/// Response of `POST /api/v1/scheduler/tasks/submit-ids`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SubmitTaskIdsResponse {
    /// Ids accepted for submission.
    pub submitted: u32,
    /// Ids the graph held and promoted in place (this lane creates no
    /// node).
    pub inserted: u32,
    /// Ids the graph does not hold — reported, never re-minted.
    pub unknown: Vec<String>,
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

/// The verified newreleases.io delivery the edge forwards to the
/// scheduler (stow#880).
///
/// The release's claimed rustc version. The scheduler dispatches
/// `preheat-admin.yml` for it; the workflow's own manifest check is the
/// authority, so the payload is only a hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PreheatReleaseRequest {
    /// The rustc version the delivery claims went stable.
    pub rustc_version: WireRustcVersion,
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
/// the catalog row plus the bundle image's OCI manifest read from GHCR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ArtifactInspection {
    /// The catalog row.
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
    use crate::artifact::ArtifactKind;
    use crate::identity::{DependencyCMetadataJson, FeaturesJson};
    use crate::index::ArtifactIndexRow;

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

    /// A hand-built submission node: synthetic task ids are fine as
    /// inputs — substitution picks representatives by them — and
    /// [`SubmissionTree::substitute_contained_sets`] recomputes real
    /// ones on the way out.
    fn submission_node(
        crate_name: &str,
        features: &[&str],
        deps: &[u32],
        task_id: &str,
    ) -> crate::api::SubmissionNode {
        crate::api::SubmissionNode {
            task_id: task_id.to_owned(),
            crate_name: crate_name.parse().expect("crate name"),
            version: "1.0.0".parse().expect("version"),
            features_json: FeaturesJson::canonicalize(
                features
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
            )
            .expect("features"),
            target: "x86_64-unknown-linux-gnu".parse().expect("target"),
            rustc_version: "1.85.0".parse().expect("rustc"),
            host_side: false,
            explicit_spelling: crate::public_cache::ExplicitSpelling::KeysAsNative,
            preserve_lockfile: false,
            dependency_identity: crate::identity::DependencyIdentity::leaf().expect("leaf digest"),
            deps: deps.to_vec(),
            downloads: 0,
        }
    }

    fn tree(nodes: Vec<crate::api::SubmissionNode>) -> crate::api::SubmissionTree {
        crate::api::SubmissionTree {
            source: crate::api::SubmissionSource::Preheat,
            roots: vec![0],
            nodes,
        }
    }

    /// The stow#881 rule across one batch: `app`'s dep on `dep@{a}` is
    /// rewritten to the batch's `dep@{a,b}` node — the subset node
    /// leaves the tree and the splice lands the two trees on one task
    /// id, so the scheduler merge builds it once.
    #[test]
    fn substitution_serves_a_contained_set_from_its_superset() {
        let mut trees = vec![
            tree(vec![
                submission_node("app", &[], &[1], "app-1.0.0-[]"),
                submission_node("dep", &["a"], &[], "dep-1.0.0-a"),
            ]),
            tree(vec![submission_node(
                "dep",
                &["a", "b"],
                &[],
                "dep-1.0.0-ab",
            )]),
        ];
        crate::api::SubmissionTree::substitute_contained_sets(&mut trees, &[])
            .expect("substitution");
        let dep = trees[0]
            .nodes
            .iter()
            .find(|node| node.crate_name.as_str() == "dep")
            .expect("dep node");
        assert_eq!(
            dep.features_json.features(),
            &["a".to_owned(), "b".to_owned()]
        );
        assert_eq!(
            dep.task_id, trees[1].nodes[0].task_id,
            "the spliced node is the superset node's task"
        );
        let root = &trees[0].nodes[trees[0].roots[0] as usize];
        assert_eq!(root.crate_name.as_str(), "app");
        assert_eq!(root.deps.len(), 1);
        assert!(
            root.task_id.starts_with("app-"),
            "root id recomputed: {}",
            root.task_id
        );
        assert_ne!(root.task_id, "app-1.0.0-[]");
    }

    /// `{a,d}` beside `{a,b,c}` — neither contains the other, so both
    /// are built as themselves and nothing is rewritten.
    #[test]
    fn substitution_leaves_uncontained_sets_alone() {
        let mut trees = vec![
            tree(vec![submission_node("dep", &["a", "b", "c"], &[], "abc")]),
            tree(vec![submission_node("dep", &["a", "d"], &[], "ad")]),
        ];
        crate::api::SubmissionTree::substitute_contained_sets(&mut trees, &[])
            .expect("substitution");
        assert_eq!(
            trees[1].nodes[0].features_json.features(),
            &["a".to_owned(), "d".to_owned()]
        );
        assert_eq!(trees[1].nodes[0].task_id, "ad");
    }

    /// A published index row — the fields substitution reads, the rest
    /// inert. `dependency_task_ids` is the row's task-graph edge list:
    /// the sorted direct child task ids its dependency digest commits
    /// to (stow#919).
    fn published_row(
        crate_name: &str,
        features: &[&str],
        deps: &[(&str, &str)],
        dependency_task_ids: Vec<String>,
        c_metadata: &str,
        host_side: bool,
    ) -> ArtifactIndexRow {
        ArtifactIndexRow {
            crate_name: crate_name.parse().expect("crate name"),
            version: "1.0.0".parse().expect("version"),
            features_json: FeaturesJson::canonicalize(
                features
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
            )
            .expect("features"),
            dependency_c_metadata_json: DependencyCMetadataJson::canonicalize(
                deps.iter()
                    .map(
                        |(name, meta)| crate::identity::DependencyCMetadataIdentity {
                            crate_name: name.parse().expect("dep name"),
                            c_metadata: meta.parse().expect("c_metadata"),
                        },
                    )
                    .collect(),
            )
            .expect("dep c_metadata"),
            dependency_task_ids,
            c_metadata: c_metadata.parse().expect("c_metadata"),
            compile_key: format!("{c_metadata}{c_metadata}"),
            bundle_digest: format!("sha256:{c_metadata:0>64}"),
            bundle_size: 0,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![crate::artifact::RustCrateType::Rlib],
            profile: crate::platform::Profile {
                opt_level: "3".to_owned(),
                debuginfo: 0,
                debug_assertions: false,
                overflow_checks: false,
                panic: crate::platform::PanicStrategy::Unwind,
                strip: crate::platform::StripLevel::None,
            },
            emit: vec!["link".to_owned()],
            unit_shape: crate::public_cache::UnitShape {
                side: if host_side {
                    crate::public_cache::UnitSide::Host
                } else {
                    crate::public_cache::UnitSide::Target
                },
                invocation: crate::public_cache::UnitInvocation::Native,
                kind: crate::public_cache::UnitKind::Linked,
            },
            min_glibc: None,
        }
    }

    /// The published pool (stow#881, second half of the rule): `dep`'s
    /// smallest containing set lives only in a signed index slice. The
    /// batch's `dep@{a}` node leaves the tree, the published subtree —
    /// `dep@{a,b}` and its own dep `d` — lands carrying the rows'
    /// published identities, and `app`'s task id recomputes against
    /// `dep@{a,b}`'s published `dependency_identity`.
    #[test]
    fn substitution_serves_from_a_published_only_container() {
        use crate::identity::DependencyIdentity;
        use crate::task_graph::TaskNodeIdentity;

        let identity = |name: &str, features: &[&str]| TaskNodeIdentity {
            crate_name: name.parse().expect("crate name"),
            version: "1.0.0".parse().expect("version"),
            features_json: FeaturesJson::canonicalize(
                features.iter().map(|f| (*f).to_owned()).collect(),
            )
            .expect("features"),
            target: "x86_64-unknown-linux-gnu".parse().expect("target"),
            rustc_version: "1.85.0".parse().expect("rustc"),
            host_side: false,
        };
        // The published slice: leaf `d` and `dep@{a,b}` built against it.
        let leaf = DependencyIdentity::leaf().expect("leaf digest");
        let d_task_id = identity("d", &[]).task_id(&leaf);
        let t_dep_identity =
            DependencyIdentity::from_task_ids([d_task_id.as_str()]).expect("digest");
        let t_task_id = identity("dep", &["a", "b"]).task_id(&t_dep_identity);
        let published = vec![crate::api::PublishedIndexSlice {
            target: "x86_64-unknown-linux-gnu".parse().expect("target"),
            rustc_version: "1.85.0".parse().expect("rustc"),
            rows: vec![
                published_row("d", &[], &[], Vec::new(), "11", false),
                published_row(
                    "dep",
                    &["a", "b"],
                    &[("d", "11")],
                    vec![d_task_id.clone()],
                    "22",
                    false,
                ),
            ],
        }];
        let mut trees = vec![tree(vec![
            submission_node("app", &[], &[1], "app-sub"),
            submission_node("dep", &["a"], &[], "dep-a-sub"),
        ])];
        crate::api::SubmissionTree::substitute_contained_sets(&mut trees, &published)
            .expect("substitution");
        let tree = &trees[0];
        // The contained set left the batch entirely.
        assert!(
            tree.nodes
                .iter()
                .all(|node| node.crate_name.as_str() != "dep"
                    || node.features_json.features() != ["a".to_owned()]),
            "dep@{{a}} must leave the tree: {:?}",
            tree.nodes
                .iter()
                .map(|node| node.task_id.clone())
                .collect::<Vec<_>>()
        );
        // The published container and its dep land as nodes carrying
        // their published ids — never roots, so the merge marks them
        // satisfied instead of dispatching them.
        let t = tree
            .nodes
            .iter()
            .find(|node| node.task_id == t_task_id)
            .expect("published dep@{a,b} node");
        assert_eq!(t.dependency_identity, t_dep_identity);
        let d = tree
            .nodes
            .iter()
            .find(|node| node.task_id == d_task_id)
            .expect("reconstructed dep d");
        assert_eq!(t.deps.len(), 1);
        let d_index = u32::try_from(
            tree.nodes
                .iter()
                .position(|node| node.task_id == d_task_id)
                .expect("d index"),
        )
        .expect("index fits u32");
        assert_eq!(t.deps, vec![d_index]);
        assert_eq!(d.deps, Vec::<u32>::new());
        // The parent's task id is the one computed against T's
        // published dependency identity.
        let app = &tree.nodes[tree.roots[0] as usize];
        let app_digest = DependencyIdentity::from_task_ids([t_task_id.as_str()]).expect("digest");
        assert_eq!(app.task_id, identity("app", &[]).task_id(&app_digest));
        assert_eq!(
            app.deps,
            vec![
                u32::try_from(
                    tree.nodes
                        .iter()
                        .position(|node| node.task_id == t_task_id)
                        .expect("t index"),
                )
                .expect("index fits u32")
            ]
        );
    }

    /// A published row's task-graph edges name a build-dependency lib —
    /// a host-side child no `--extern` list of the parent ever carries
    /// (stow#919). The row's `dependency_c_metadata_json` names only
    /// `lib`; its `dependency_task_ids` names `lib` and the host
    /// slice's `version_check`. The task-id join finds both, where the
    /// `--extern` reconstruction minted a digest the row never
    /// recorded.
    #[test]
    fn substitution_joins_a_build_dependency_from_the_host_slice() {
        use crate::identity::DependencyIdentity;
        use crate::task_graph::TaskNodeIdentity;

        const TARGET: &str = "wasm32-unknown-unknown";
        const HOST: &str = "aarch64-apple-darwin";
        let identity = |name: &str, features: &[&str], host_side: bool| TaskNodeIdentity {
            crate_name: name.parse().expect("crate name"),
            version: "1.0.0".parse().expect("version"),
            features_json: FeaturesJson::canonicalize(
                features.iter().map(|f| (*f).to_owned()).collect(),
            )
            .expect("features"),
            target: if host_side {
                HOST.parse().expect("host")
            } else {
                TARGET.parse().expect("target")
            },
            rustc_version: "1.85.0".parse().expect("rustc"),
            host_side,
        };
        let leaf = DependencyIdentity::leaf().expect("leaf digest");
        let lib_task_id = identity("lib", &[], false).task_id(&leaf);
        let vc_task_id = identity("version_check", &[], true).task_id(&leaf);
        let dep_identity =
            DependencyIdentity::from_task_ids([lib_task_id.as_str(), vc_task_id.as_str()])
                .expect("digest");
        let dep_task_id = identity("dep", &["a", "b"], false).task_id(&dep_identity);
        let published = vec![
            crate::api::PublishedIndexSlice {
                target: TARGET.parse().expect("target"),
                rustc_version: "1.85.0".parse().expect("rustc"),
                rows: vec![
                    published_row("lib", &[], &[], Vec::new(), "11", false),
                    published_row(
                        "dep",
                        &["a", "b"],
                        &[("lib", "11")],
                        vec![lib_task_id.clone(), vc_task_id.clone()],
                        "22",
                        false,
                    ),
                ],
            },
            crate::api::PublishedIndexSlice {
                target: HOST.parse().expect("host"),
                rustc_version: "1.85.0".parse().expect("rustc"),
                rows: vec![published_row(
                    "version_check",
                    &[],
                    &[],
                    Vec::new(),
                    "33",
                    true,
                )],
            },
        ];
        let mut tree = tree(vec![
            submission_node("app", &[], &[1], "app-sub"),
            submission_node("dep", &["a"], &[], "dep-a-sub"),
        ]);
        for node in &mut tree.nodes {
            node.target = TARGET.parse().expect("target");
        }
        let mut trees = vec![tree];
        crate::api::SubmissionTree::substitute_contained_sets(&mut trees, &published)
            .expect("substitution");
        let tree = &trees[0];
        for task_id in [&dep_task_id, &lib_task_id, &vc_task_id] {
            assert!(
                tree.nodes.iter().any(|node| node.task_id == *task_id),
                "reconstructed node {task_id} lands in the tree"
            );
        }
    }

    /// A shadow twin edge (stow#506/#722): the row's children include
    /// the host lib and its same-features target twin — two tasks no
    /// `--extern` list names together (stow#919). The task-id join
    /// reconstructs both.
    #[test]
    fn substitution_joins_a_shadow_twin_edge() {
        use crate::identity::DependencyIdentity;
        use crate::task_graph::TaskNodeIdentity;

        const TARGET: &str = "wasm32-unknown-unknown";
        const HOST: &str = "aarch64-apple-darwin";
        let identity = |name: &str, features: &[&str], host_side: bool| TaskNodeIdentity {
            crate_name: name.parse().expect("crate name"),
            version: "1.0.0".parse().expect("version"),
            features_json: FeaturesJson::canonicalize(
                features.iter().map(|f| (*f).to_owned()).collect(),
            )
            .expect("features"),
            target: if host_side {
                HOST.parse().expect("host")
            } else {
                TARGET.parse().expect("target")
            },
            rustc_version: "1.85.0".parse().expect("rustc"),
            host_side,
        };
        let leaf = DependencyIdentity::leaf().expect("leaf digest");
        let helper_host_id = identity("helper", &[], true).task_id(&leaf);
        let helper_twin_id = identity("helper", &[], false).task_id(&leaf);
        let dep_identity =
            DependencyIdentity::from_task_ids([helper_host_id.as_str(), helper_twin_id.as_str()])
                .expect("digest");
        let dep_task_id = identity("dep", &["a", "b"], false).task_id(&dep_identity);
        let published = vec![
            crate::api::PublishedIndexSlice {
                target: TARGET.parse().expect("target"),
                rustc_version: "1.85.0".parse().expect("rustc"),
                rows: vec![
                    published_row("helper", &[], &[], Vec::new(), "33", false),
                    published_row(
                        "dep",
                        &["a", "b"],
                        &[("helper", "33")],
                        vec![helper_host_id.clone(), helper_twin_id.clone()],
                        "22",
                        false,
                    ),
                ],
            },
            crate::api::PublishedIndexSlice {
                target: HOST.parse().expect("host"),
                rustc_version: "1.85.0".parse().expect("rustc"),
                rows: vec![published_row("helper", &[], &[], Vec::new(), "33", true)],
            },
        ];
        let mut tree = tree(vec![
            submission_node("app", &[], &[1], "app-sub"),
            submission_node("dep", &["a"], &[], "dep-a-sub"),
        ]);
        for node in &mut tree.nodes {
            node.target = TARGET.parse().expect("target");
        }
        let mut trees = vec![tree];
        crate::api::SubmissionTree::substitute_contained_sets(&mut trees, &published)
            .expect("substitution");
        let tree = &trees[0];
        for task_id in [&dep_task_id, &helper_host_id, &helper_twin_id] {
            assert!(
                tree.nodes.iter().any(|node| node.task_id == *task_id),
                "reconstructed node {task_id} lands in the tree"
            );
        }
    }

    /// One `c_metadata` carried by a host row and a target row at once
    /// (stow#919): the `--extern` join picked whichever row sorted
    /// first — here the wrong one — while the task-id join names the
    /// host child the row's digest actually commits to.
    #[test]
    fn substitution_joins_the_row_the_task_id_names() {
        use crate::identity::DependencyIdentity;
        use crate::task_graph::TaskNodeIdentity;

        const TARGET: &str = "wasm32-unknown-unknown";
        const HOST: &str = "aarch64-apple-darwin";
        let identity = |name: &str, features: &[&str], host_side: bool| TaskNodeIdentity {
            crate_name: name.parse().expect("crate name"),
            version: "1.0.0".parse().expect("version"),
            features_json: FeaturesJson::canonicalize(
                features.iter().map(|f| (*f).to_owned()).collect(),
            )
            .expect("features"),
            target: if host_side {
                HOST.parse().expect("host")
            } else {
                TARGET.parse().expect("target")
            },
            rustc_version: "1.85.0".parse().expect("rustc"),
            host_side,
        };
        let leaf = DependencyIdentity::leaf().expect("leaf digest");
        let helper_host_id = identity("helper", &[], true).task_id(&leaf);
        let helper_target_id = identity("helper", &[], false).task_id(&leaf);
        let dep_identity =
            DependencyIdentity::from_task_ids([helper_host_id.as_str()]).expect("digest");
        let dep_task_id = identity("dep", &["a", "b"], false).task_id(&dep_identity);
        // The ambiguous row orders first in the pulled slices: a
        // `c_metadata` join binds it, the task-id join cannot.
        let published = vec![
            crate::api::PublishedIndexSlice {
                target: TARGET.parse().expect("target"),
                rustc_version: "1.85.0".parse().expect("rustc"),
                rows: vec![
                    published_row("helper", &[], &[], Vec::new(), "33", false),
                    published_row(
                        "dep",
                        &["a", "b"],
                        &[("helper", "33")],
                        vec![helper_host_id.clone()],
                        "22",
                        false,
                    ),
                ],
            },
            crate::api::PublishedIndexSlice {
                target: HOST.parse().expect("host"),
                rustc_version: "1.85.0".parse().expect("rustc"),
                rows: vec![published_row("helper", &[], &[], Vec::new(), "33", true)],
            },
        ];
        let mut tree = tree(vec![
            submission_node("app", &[], &[1], "app-sub"),
            submission_node("dep", &["a"], &[], "dep-a-sub"),
        ]);
        for node in &mut tree.nodes {
            node.target = TARGET.parse().expect("target");
        }
        let mut trees = vec![tree];
        crate::api::SubmissionTree::substitute_contained_sets(&mut trees, &published)
            .expect("substitution");
        let tree = &trees[0];
        for task_id in [&dep_task_id, &helper_host_id] {
            assert!(
                tree.nodes.iter().any(|node| node.task_id == *task_id),
                "reconstructed node {task_id} lands in the tree"
            );
        }
        assert!(
            tree.nodes
                .iter()
                .all(|node| node.task_id != helper_target_id),
            "the ambiguous target row is not the named child"
        );
    }

    /// stow#723: the self-twin edge — a host node deping on its
    /// same-feature target twin — pins both endpoints. A published
    /// superset on the host side alone serves neither.
    #[test]
    fn a_self_twin_pair_moves_together_or_not_at_all() {
        use crate::identity::DependencyIdentity;
        use crate::task_graph::TaskNodeIdentity;

        let mut x_h = submission_node("x", &[], &[1], "x-h");
        x_h.host_side = true;
        let x_t = submission_node("x", &[], &[], "x-t");
        let published = vec![crate::api::PublishedIndexSlice {
            target: "x86_64-unknown-linux-gnu".parse().expect("target"),
            rustc_version: "1.85.0".parse().expect("rustc"),
            rows: vec![published_row("x", &["std"], &[], Vec::new(), "33", true)],
        }];
        let mut trees = vec![tree(vec![x_h, x_t])];
        crate::api::SubmissionTree::substitute_contained_sets(&mut trees, &published)
            .expect("substitution");
        for (index, side) in [(0usize, "host"), (1usize, "target")] {
            let node = &trees[0].nodes[index];
            assert!(
                node.features_json.features().is_empty(),
                "the {side} endpoint stays at its own set when only one side has a superset"
            );
        }

        // A serving set published on both sides is a real superset the
        // pair can move to — both endpoints land on it.
        let identity = |host_side: bool| TaskNodeIdentity {
            crate_name: "x".parse().expect("crate name"),
            version: "1.0.0".parse().expect("version"),
            features_json: FeaturesJson::canonicalize(vec!["std".to_owned()]).expect("features"),
            target: "x86_64-unknown-linux-gnu".parse().expect("target"),
            rustc_version: "1.85.0".parse().expect("rustc"),
            host_side,
        };
        let leaf = DependencyIdentity::leaf().expect("leaf digest");
        let target_id = identity(false).task_id(&leaf);
        let host_dep_identity =
            DependencyIdentity::from_task_ids([target_id.as_str()]).expect("host dep digest");
        let host_id = identity(true).task_id(&host_dep_identity);
        let published = vec![crate::api::PublishedIndexSlice {
            target: "x86_64-unknown-linux-gnu".parse().expect("target"),
            rustc_version: "1.85.0".parse().expect("rustc"),
            rows: vec![
                // The host row's own chain names its target twin —
                // a real published superset carries its real dep list.
                published_row("x", &["std"], &[], vec![target_id.clone()], "44", true),
                published_row("x", &["std"], &[], Vec::new(), "55", false),
            ],
        }];
        let mut x_h = submission_node("x", &[], &[1], "x-h");
        x_h.host_side = true;
        let mut trees = vec![tree(vec![x_h, submission_node("x", &[], &[], "x-t")])];
        crate::api::SubmissionTree::substitute_contained_sets(&mut trees, &published)
            .expect("substitution");
        let host = trees[0]
            .nodes
            .iter()
            .find(|node| node.crate_name.as_str() == "x" && node.host_side)
            .expect("host endpoint");
        let target = trees[0]
            .nodes
            .iter()
            .find(|node| node.crate_name.as_str() == "x" && !node.host_side)
            .expect("target endpoint");
        assert_eq!(host.features_json.features(), &["std".to_owned()]);
        assert_eq!(target.features_json.features(), &["std".to_owned()]);
        assert_eq!(
            host.task_id, host_id,
            "host endpoint serves the published set"
        );
        assert_eq!(
            target.task_id, target_id,
            "target endpoint serves the same published set"
        );
    }

    /// stow#723: the shadow pair — a dependent holding the same-feature
    /// host and target units of one package as two children — is bound
    /// by the same rule: one side's published superset moves neither.
    #[test]
    fn a_shadow_pair_moves_together_or_not_at_all() {
        let mut x_h = submission_node("x", &[], &[], "x-h");
        x_h.host_side = true;
        let x_t = submission_node("x", &[], &[], "x-t");
        let parent = submission_node("p", &[], &[1, 2], "p");
        let published = vec![crate::api::PublishedIndexSlice {
            target: "x86_64-unknown-linux-gnu".parse().expect("target"),
            rustc_version: "1.85.0".parse().expect("rustc"),
            rows: vec![published_row("x", &["std"], &[], Vec::new(), "66", false)],
        }];
        let mut trees = vec![tree(vec![parent, x_h, x_t])];
        crate::api::SubmissionTree::substitute_contained_sets(&mut trees, &published)
            .expect("substitution");
        let target = trees[0]
            .nodes
            .iter()
            .find(|node| node.crate_name.as_str() == "x" && !node.host_side)
            .expect("target endpoint");
        assert!(
            target.features_json.features().is_empty(),
            "the target endpoint cannot move alone to the superset"
        );
        let host = trees[0]
            .nodes
            .iter()
            .find(|node| node.crate_name.as_str() == "x" && node.host_side)
            .expect("host endpoint");
        assert!(
            host.features_json.features().is_empty(),
            "the host endpoint stays too"
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
    /// Builds the installs' CLIs counted in the last 24 hours, from the
    /// daily build reports.
    pub builds_24h: u64,
    /// Artifacts served from the cache in the last 24 hours, from the
    /// daily build reports.
    pub hits_24h: u64,
    /// Artifacts compiled locally in the last 24 hours, from the daily
    /// build reports.
    pub misses_24h: u64,
    /// `hits_24h / (hits_24h + misses_24h)`; `0.0` when nothing was served.
    pub hit_rate_24h: f64,
    /// CPU-hours of rustc compilation saved in the last 30 days: the
    /// recorded compile time of every artifact served, as the installs'
    /// CLIs reported it.
    pub cpu_hours_saved_30d: f64,
    /// Most-served bundle digests over the last 30 days, edge-observed —
    /// an undercount of real usage, since the platform cache answers most
    /// fetches before the Worker runs. The digest carries no identity;
    /// `stow-admin` resolves each to a crate from the public signed
    /// index.
    pub top_digests_30d: Vec<UsageStatEntry>,
    /// Hits per rustc version over the last 30 days, edge-observed.
    pub rustc_versions_30d: Vec<UsageStatEntry>,
    /// Reported activity per `stow-cli` version over the last 30 days;
    /// requests that sent no `stow-cli` user agent are not counted under
    /// any version.
    pub cli_versions_30d: Vec<UsageStatEntry>,
    /// Reported activity per operating system over the last 30 days.
    pub operating_systems_30d: Vec<UsageStatEntry>,
    /// Reported activity per request country over the last 30 days —
    /// Cloudflare's country code only.
    pub countries_30d: Vec<UsageStatEntry>,
    /// Reported activity split between CI and local builds over the
    /// last 30 days.
    pub environments_30d: Vec<UsageStatEntry>,
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

/// The admission class a submission tree arrives under (stow#878).
///
/// Each entry point the scheduler's rank prices separately (#879).
/// Priority is a property of the entry point, not the node: operations
/// carries the caller's choice, every other source is the scheduler's
/// default for that lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SubmissionSource {
    /// An operations submission (`stow-admin`) — the caller sets the
    /// priority the tree's nodes enter the rank with.
    Operations {
        /// The caller-chosen priority operand.
        priority: i64,
    },
    /// A CLI cache miss — proof-of-work admission.
    CacheMiss,
    /// An #882 inexact superset-hit report — the same proof-of-work
    /// admission as a miss, queued at very low priority.
    InexactHit,
    /// A Turnstile-admitted `stow.waterui.dev` request — the human lane.
    HumanRequest,
    /// A trusted preheat lane (top, binaries, projects, missed, dirs).
    Preheat,
}

/// One node of a [`SubmissionTree`].
///
/// The queue identity columns of the retired `EnqueueRequest` plus the
/// node's direct-dependency edges, sent once per source instead of
/// embedded under every dependent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SubmissionNode {
    /// The node's canonical task id — the submitter computes it and the
    /// merge verifies its identity columns re-derive it.
    pub task_id: String,
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
    /// Whether the node compiles for the build host.
    #[serde(default)]
    pub host_side: bool,
    /// The explicit `--target` spelling flag (stow#736).
    pub explicit_spelling: crate::public_cache::ExplicitSpelling,
    /// Build against the binary's published `Cargo.lock` (overlay lane).
    #[serde(default)]
    pub preserve_lockfile: bool,
    /// The Merkle dependency digest the task id commits to (stow#588).
    pub dependency_identity: crate::identity::DependencyIdentity,
    /// Indexes into [`SubmissionTree::nodes`] naming this node's
    /// direct dependencies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<u32>,
    /// The source's demand signal for this node (crates.io downloads
    /// for preheat, 0 for misses).
    #[serde(default)]
    pub downloads: u64,
}

/// One dependency tree from one source (stow#878).
///
/// The unit every submitter posts once — a project, a crate, a miss —
/// each node once, merged into the scheduler's graph by task id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SubmissionTree {
    /// The entry point this tree arrives under.
    pub source: SubmissionSource,
    /// Indexes into `nodes` of the submissions' roots — the crates the
    /// source actually asked for.
    pub roots: Vec<u32>,
    /// Every node in the tree, each once, in the resolved graph's
    /// canonical order.
    pub nodes: Vec<SubmissionNode>,
}

impl SubmissionTree {
    /// One dependency tree from an enqueue batch — the converter every
    /// submitter runs at its submission boundary: each request's own
    /// resolved subgraph unfolds into `nodes`, unioned by task id, and
    /// `deps` re-point at tree indexes. Nodes a request names only as
    /// dependencies (already published) still enter the tree so their
    /// edges carry a real node; `roots` keeps one index per request,
    /// in request order.
    ///
    /// # Errors
    /// `Error` when a request's subgraph cannot resolve or a dep index
    /// is unmapped — resolver bugs, never accepted data.
    pub fn from_enqueue_requests(
        source: SubmissionSource,
        requests: &[EnqueueRequest],
    ) -> crate::error::Result<Self> {
        let mut nodes = Vec::new();
        let mut index = std::collections::HashMap::new();
        let mut roots = Vec::with_capacity(requests.len());
        for request in requests {
            let graph = request.resolved_dependency_graph()?;
            let graph_nodes = graph.nodes();
            let mut map = vec![0u32; graph_nodes.len()];
            for (ix, node) in graph_nodes.iter().enumerate() {
                let dependency_identity =
                    graph.dependency_identity(ix).cloned().ok_or_else(|| {
                        stow_error!("resolved dependency graph yields no digest for node {ix}")
                    })?;
                let task_id = node.identity.task_id(&dependency_identity);
                if let Some(&existing) = index.get(&task_id) {
                    map[ix] = existing;
                    continue;
                }
                let next = u32::try_from(nodes.len())
                    .map_err(|_| stow_error!("submission node count overflows u32"))?;
                index.insert(task_id.clone(), next);
                map[ix] = next;
                nodes.push(SubmissionNode {
                    task_id,
                    crate_name: node.identity.crate_name.clone(),
                    version: node.identity.version.clone(),
                    features_json: node.identity.features_json.clone(),
                    target: node.identity.target.clone(),
                    rustc_version: node.identity.rustc_version.clone(),
                    host_side: node.identity.host_side,
                    explicit_spelling: node.explicit_spelling,
                    preserve_lockfile: request.preserve_lockfile && ix == 0,
                    dependency_identity,
                    deps: Vec::new(),
                    downloads: if ix == 0 { request.downloads } else { 0 },
                });
            }
            for (ix, node) in graph_nodes.iter().enumerate() {
                nodes[map[ix] as usize].deps =
                    node.dependencies.iter().map(|&dep| map[dep]).collect();
            }
            roots.push(map[0]);
        }
        Ok(Self {
            source,
            roots,
            nodes,
        })
    }

    /// Apply the superset-serving rule (stow#881): a feature set
    /// contained in another set of the same `(crate, version, target,
    /// rustc, side)` is never built — its node is replaced by the
    /// containing set's node, subtree included, and every task id is
    /// recomputed bottom-up.
    ///
    /// The pool is the submit call's batch **and** the published sets
    /// in `published` — the signed `index.<target>.<rustc>` slices the
    /// caller already pulls for coverage. A serving set present only
    /// in the published pool is reconstructed from its rows: the
    /// subtree is rebuilt by following each row's `dependency_task_ids`
    /// edges through the pulled slices (stow#919 — the `--extern` list
    /// is a different relation and cannot rebuild them), and every
    /// reconstructed node carries the row's published dependency
    /// digest, so a dependent's task id commits to the exact identity
    /// the builder published. The scheduler's merge
    /// then treats the spliced nodes as already satisfied — they are
    /// never dispatched — while their edges keep every dependent's
    /// dispatch payload pinning the full closure.
    ///
    /// Batch-side the pool rule is unchanged: for each `(group, serving
    /// set)` the replacement node is the smallest pre-substitution
    /// `task_id` among the batch's nodes carrying that set. The rewrite
    /// runs over a shared interned arena of [`ResolvedTaskNode`]s;
    /// [`ResolvedTaskGraph::resolve`] recomputes every
    /// `dependency_identity` and `task_id` bottom-up, each tree is
    /// re-emitted from its substituted roots' reach, and every
    /// reconstructed published node is checked to reproduce its
    /// published task id — a mismatch means the pulled slices disagree
    /// with the rows' recorded dep closures.
    ///
    /// # Errors
    /// Fails as [`ResolvedTaskGraph::resolve`] does, and fails fast when
    /// a reconstructed published subtree resolves to an id other than
    /// the row's published one.
    ///
    /// # Panics
    /// The internal lookups are inhabited by construction: every node's
    /// group and serving set were computed from the pool itself.
    #[allow(clippy::too_many_lines)] // the rewrite orchestrates one pass; splitting hides it
    pub fn substitute_contained_sets(
        trees: &mut [Self],
        published: &[PublishedIndexSlice],
    ) -> crate::error::Result<()> {
        // Each group's distinct feature sets over the batch ∪ the
        // published slices, and the serving map over them: a set
        // contained in no other is built; every other set is served by
        // the smallest built set containing it.
        let mut families = BTreeMap::<SubstitutionGroupKey, BTreeSet<Vec<String>>>::new();
        for tree in trees.iter() {
            for node in &tree.nodes {
                families
                    .entry(substitution_group_key(node))
                    .or_default()
                    .insert(node.features_json.features().to_vec());
            }
        }
        for slice in published {
            for row in &slice.rows {
                families
                    .entry(substitution_row_key(slice, row))
                    .or_default()
                    .insert(row.features_json.features().to_vec());
            }
        }
        let mut serving = families
            .iter()
            .map(|(key, family)| (key.clone(), crate::feature_sets::serving_map(family)))
            .collect::<BTreeMap<_, _>>();
        // Every pulled row's own minted task id — the join a row's
        // `dependency_task_ids` edges name (stow#919) — is needed here to
        // find twin pairs in the published pool.
        let mut row_task_ids = Vec::with_capacity(published.len());
        for slice in published {
            let mut ids = Vec::with_capacity(slice.rows.len());
            for row in &slice.rows {
                ids.push(published_row_identity(slice, row).task_id(&row.dependency_identity()?));
            }
            row_task_ids.push(ids);
        }
        let mut by_task_id = std::collections::HashMap::new();
        for (slice_index, ids) in row_task_ids.iter().enumerate() {
            for (row_index, id) in ids.iter().enumerate() {
                by_task_id
                    .entry(id.as_str())
                    .or_insert((slice_index, row_index));
            }
        }
        patch_twin_pair_serving(trees, published, &by_task_id, &mut serving);
        if serving
            .values()
            .all(|map| map.iter().all(|(set, serve)| set == serve))
        {
            return Ok(());
        }

        // The canonical node a contained set is replaced by: among the
        // batch's nodes carrying the serving set, the smallest existing
        // task id — deterministic on both sides of the submit.
        let mut representatives =
            BTreeMap::<(SubstitutionGroupKey, Vec<String>), (usize, usize)>::new();
        for (tree_index, tree) in trees.iter().enumerate() {
            for (node_index, node) in tree.nodes.iter().enumerate() {
                let key = substitution_group_key(node);
                let serve = &serving[&key][node.features_json.features()];
                if serve.as_slice() != node.features_json.features() {
                    continue;
                }
                representatives
                    .entry((key, serve.clone()))
                    .and_modify(|rep| {
                        if node.task_id < trees[rep.0].nodes[rep.1].task_id {
                            *rep = (tree_index, node_index);
                        }
                    })
                    .or_insert((tree_index, node_index));
            }
        }
        let (published_reps, row_task_ids) = published_pool_index(published, &serving)?;

        let mut substitution = Substitution {
            trees,
            published,
            serving: &serving,
            representatives: &representatives,
            published_reps: &published_reps,
            row_task_ids: &row_task_ids,
            by_task_id: &by_task_id,
            arena: Vec::new(),
            closure_pm: Vec::new(),
            interned: std::collections::HashMap::new(),
            memo: std::collections::HashMap::new(),
            published_memo: std::collections::HashMap::new(),
            pinned: std::collections::HashMap::new(),
        };
        // Substituting a node into another node's dep position can never
        // close a cycle: the spliced subtree is the dependency closure
        // of a real resolved node (batch) or of a published artifact's
        // recorded chain (index), and a build graph is acyclic.
        for (tree_index, tree) in trees.iter().enumerate() {
            for node_index in 0..tree.nodes.len() {
                substitution.substitute(tree_index, node_index);
            }
        }
        let Substitution {
            arena,
            memo,
            pinned,
            ..
        } = substitution;
        let resolved = ResolvedTaskGraph::resolve(arena)?;
        // A reconstructed published node is pinned to the id its row
        // records — recompute reproducing it proves the pulled slices
        // carry the row's whole dep chain verbatim.
        for (index, expected) in &pinned {
            let actual = resolved
                .task_id(*index)
                .ok_or_else(|| stow_error!("arena node {index} has no task id"))?;
            if actual != *expected {
                return Err(stow_error!(
                    "published subtree reconstructed to {actual}, index records {expected}"
                ));
            }
        }
        for (tree_index, tree) in trees.iter_mut().enumerate() {
            *tree = reemit_substituted_tree(tree, tree_index, &memo, &resolved)?;
        }
        Ok(())
    }
}

/// One verified `index.<target>.<rustc>` slice as the superset
/// substitution pool sees it (stow#881): the published rows plus the
/// slice's coordinates, which rows do not themselves carry.
#[derive(Debug, Clone)]
pub struct PublishedIndexSlice {
    /// The slice's target triple — every row's `TaskNodeIdentity.target`.
    pub target: TargetTriple,
    /// The slice's rustc — every row's `TaskNodeIdentity.rustc_version`.
    pub rustc_version: WireRustcVersion,
    /// The verified rows.
    pub rows: Vec<ArtifactIndexRow>,
}

/// The identity group the superset-serving rule keys on (stow#881) —
/// every field of a node's task identity except its feature set.
type SubstitutionGroupKey = (
    CrateName,
    CrateVersion,
    TargetTriple,
    WireRustcVersion,
    bool,
);

fn substitution_group_key(node: &SubmissionNode) -> SubstitutionGroupKey {
    (
        node.crate_name.clone(),
        node.version.clone(),
        node.target.clone(),
        node.rustc_version.clone(),
        node.host_side,
    )
}

/// The `(crate, version, target, rustc)` a twin pair shares — the
/// group key with the side stripped (stow#723).
type TwinPairKey = (CrateName, CrateVersion, TargetTriple, WireRustcVersion);

/// stow#723: the two endpoints of a twin pair move to the same serving
/// set or neither. A pair is named wherever an edge binds the
/// same-feature host and target units of one package — a host node's
/// self-twin edge, or a dependent holding both as children (the shadow
/// pair the dedup pin emits). Moving one side alone would hand a
/// dependent's pins `X_h[F]` and `X_t[S]` with `F ≠ S`, breaking the
/// equal-features premise cargo's sharing probe needs — and minting
/// wrong ids, as a substituted shadow edge already did.
///
/// For each paired feature set `F` the joint serve is the smallest
/// strictly-containing set that is itself unserved (a *built* set) on
/// BOTH sides; with none, both endpoints stay at `F`. The answer is
/// written back into `serving` on both side-keys, so every later
/// serve lookup — batch representatives, published reps and the
/// substitution walk — sees it.
#[allow(clippy::too_many_lines)] // one pass over both pools; split hurts the shape
fn patch_twin_pair_serving(
    trees: &[SubmissionTree],
    published: &[PublishedIndexSlice],
    by_task_id: &std::collections::HashMap<&str, (usize, usize)>,
    serving: &mut BTreeMap<SubstitutionGroupKey, BTreeMap<Vec<String>, Vec<String>>>,
) {
    type PairKeyAndSet = (TwinPairKey, Vec<String>);
    let mut paired = BTreeSet::<PairKeyAndSet>::new();
    // `deps` is a parent identity plus its dep identities — the two
    // shapes a twin reference takes, on either pool.
    let mut record = |parent: &TaskNodeIdentity, deps: &[TaskNodeIdentity]| {
        let parent_key = (
            parent.crate_name.clone(),
            parent.version.clone(),
            parent.target.clone(),
            parent.rustc_version.clone(),
        );
        if parent.host_side {
            for dep in deps {
                if !dep.host_side
                    && dep.crate_name == parent.crate_name
                    && dep.version == parent.version
                    && dep.target == parent.target
                    && dep.rustc_version == parent.rustc_version
                    && dep.features_json == parent.features_json
                {
                    paired.insert((parent_key.clone(), parent.features_json.features().to_vec()));
                }
            }
        }
        // The shadow pair: one parent's two children at the same
        // features, one per side.
        let mut by_set = BTreeMap::<PairKeyAndSet, (bool, bool)>::new();
        for dep in deps {
            let entry = by_set
                .entry((
                    (
                        dep.crate_name.clone(),
                        dep.version.clone(),
                        dep.target.clone(),
                        dep.rustc_version.clone(),
                    ),
                    dep.features_json.features().to_vec(),
                ))
                .or_default();
            if dep.host_side {
                entry.0 = true;
            } else {
                entry.1 = true;
            }
        }
        paired.extend(
            by_set
                .into_iter()
                .filter(|(_, sides)| sides.0 && sides.1)
                .map(|(key, _)| key),
        );
    };
    for tree in trees {
        for node in &tree.nodes {
            let parent = TaskNodeIdentity {
                crate_name: node.crate_name.clone(),
                version: node.version.clone(),
                features_json: node.features_json.clone(),
                target: node.target.clone(),
                rustc_version: node.rustc_version.clone(),
                host_side: node.host_side,
            };
            let deps: Vec<TaskNodeIdentity> = node
                .deps
                .iter()
                .map(|&dep| {
                    let dep = &tree.nodes[dep as usize];
                    TaskNodeIdentity {
                        crate_name: dep.crate_name.clone(),
                        version: dep.version.clone(),
                        features_json: dep.features_json.clone(),
                        target: dep.target.clone(),
                        rustc_version: dep.rustc_version.clone(),
                        host_side: dep.host_side,
                    }
                })
                .collect();
            record(&parent, &deps);
        }
    }
    for (slice_index, slice) in published.iter().enumerate() {
        for (row_index, row) in slice.rows.iter().enumerate() {
            let parent = published_row_identity(slice, row);
            let mut deps = Vec::with_capacity(row.dependency_task_ids.len());
            for child_id in &row.dependency_task_ids {
                // A dep chain the pulled slices do not fully carry
                // never reconstructs; its edges name no pair either.
                let Some(&(dep_slice, dep_row)) = by_task_id.get(child_id.as_str()) else {
                    continue;
                };
                deps.push(published_row_identity(
                    &published[dep_slice],
                    &published[dep_slice].rows[dep_row],
                ));
            }
            let _ = (slice_index, row_index);
            record(&parent, &deps);
        }
    }

    for (key, features) in paired {
        // The sets each side would serve, restricted to built sets —
        // moving an endpoint must land it on a set that stays.
        let built = |host_side: bool| -> BTreeSet<Vec<String>> {
            serving
                .get(&(
                    key.0.clone(),
                    key.1.clone(),
                    key.2.clone(),
                    key.3.clone(),
                    host_side,
                ))
                .map(|map| {
                    map.iter()
                        .filter(|(set, serve)| set == serve)
                        .map(|(set, _)| set.clone())
                        .collect()
                })
                .unwrap_or_default()
        };
        let joint = built(true)
            .intersection(&built(false))
            .filter(|set| **set != features && crate::feature_sets::contains_all(set, &features))
            .min()
            .cloned()
            .unwrap_or_else(|| features.clone());
        for host_side in [true, false] {
            if let Some(map) = serving.get_mut(&(
                key.0.clone(),
                key.1.clone(),
                key.2.clone(),
                key.3.clone(),
                host_side,
            )) && map.contains_key(&features)
            {
                map.insert(features.clone(), joint.clone());
            }
        }
    }
}

/// A published row's identity group — the slice supplies the two
/// identity columns a row does not carry.
fn substitution_row_key(
    slice: &PublishedIndexSlice,
    row: &ArtifactIndexRow,
) -> SubstitutionGroupKey {
    (
        row.crate_name.clone(),
        row.version.clone(),
        slice.target.clone(),
        slice.rustc_version.clone(),
        row.unit_shape.side == crate::public_cache::UnitSide::Host,
    )
}

/// A published row's task identity — same field split as
/// [`substitution_row_key`].
fn published_row_identity(slice: &PublishedIndexSlice, row: &ArtifactIndexRow) -> TaskNodeIdentity {
    TaskNodeIdentity {
        crate_name: row.crate_name.clone(),
        version: row.version.clone(),
        features_json: row.features_json.clone(),
        target: slice.target.clone(),
        rustc_version: slice.rustc_version.clone(),
        host_side: row.unit_shape.side == crate::public_cache::UnitSide::Host,
    }
}

/// The published side of the serving-pool pick (stow#881): among the
/// rows carrying each serving set, the smallest published task id —
/// a published row wins over a batch node because its artifact already
/// exists, so serving from it never waits on this wave. Also every
/// row's own minted task id — the join key a row's
/// `dependency_task_ids` edges name (stow#919).
#[allow(clippy::type_complexity)]
fn published_pool_index(
    published: &[PublishedIndexSlice],
    serving: &BTreeMap<SubstitutionGroupKey, BTreeMap<Vec<String>, Vec<String>>>,
) -> crate::error::Result<(
    BTreeMap<(SubstitutionGroupKey, Vec<String>), (usize, usize, String)>,
    Vec<Vec<String>>,
)> {
    let mut reps = BTreeMap::new();
    let mut task_ids = Vec::with_capacity(published.len());
    for (slice_index, slice) in published.iter().enumerate() {
        let mut slice_ids = Vec::with_capacity(slice.rows.len());
        for (row_index, row) in slice.rows.iter().enumerate() {
            let task_id = published_row_identity(slice, row).task_id(&row.dependency_identity()?);
            slice_ids.push(task_id.clone());
            let key = substitution_row_key(slice, row);
            let serve = &serving[&key][row.features_json.features()];
            if serve.as_slice() != row.features_json.features() {
                continue;
            }
            reps.entry((key, serve.clone()))
                .and_modify(|rep: &mut (usize, usize, String)| {
                    if task_id < rep.2 {
                        *rep = (slice_index, row_index, task_id.clone());
                    }
                })
                .or_insert((slice_index, row_index, task_id));
        }
        task_ids.push(slice_ids);
    }
    Ok((reps, task_ids))
}

/// One batch's shared rewrite state for
/// [`SubmissionTree::substitute_contained_sets`]: the group serving
/// maps, each serving set's canonical batch node and published row,
/// the interned [`ResolvedTaskNode`] arena every tree re-emits from,
/// and the memoized per-occurrence answers.
struct Substitution<'a> {
    trees: &'a [SubmissionTree],
    published: &'a [PublishedIndexSlice],
    serving: &'a BTreeMap<SubstitutionGroupKey, BTreeMap<Vec<String>, Vec<String>>>,
    representatives: &'a BTreeMap<(SubstitutionGroupKey, Vec<String>), (usize, usize)>,
    /// `(slice, row, task id)` of each serving set's published pick.
    published_reps: &'a BTreeMap<(SubstitutionGroupKey, Vec<String>), (usize, usize, String)>,
    /// Every pulled row's own minted task id, indexed `(slice, row)` —
    /// the id a reconstructed node is pinned to reproduce.
    row_task_ids: &'a [Vec<String>],
    /// `task id` → `(slice, row)` across every pulled slice — the
    /// dep-edge join a row's `dependency_task_ids` names (stow#919).
    by_task_id: &'a std::collections::HashMap<&'a str, (usize, usize)>,
    arena: Vec<ResolvedTaskNode>,
    /// Parallel to `arena`: a proc-macro reaches this node's dep
    /// closure, or the node is one itself. Only published
    /// reconstructions read it — a published node's `KeysApart` flag is
    /// recomputed from it.
    closure_pm: Vec<bool>,
    interned: std::collections::HashMap<
        (
            TaskNodeIdentity,
            crate::public_cache::ExplicitSpelling,
            Vec<usize>,
        ),
        usize,
    >,
    memo: std::collections::HashMap<(usize, usize), usize>,
    /// `(slice, row)` → reconstructed arena index; `None` when the row's
    /// dep chain is not fully present in the pulled slices.
    published_memo: std::collections::HashMap<(usize, usize), Option<usize>>,
    /// Arena index → the task id its published row records — checked
    /// against the recompute before any tree re-emits.
    pinned: std::collections::HashMap<usize, &'a str>,
}

impl Substitution<'_> {
    /// The arena node one `(tree, node)` occurrence maps to —
    /// memoized. A node whose set is served by a containing set
    /// resolves to that set's published row when one exists — its
    /// artifact is already built — else to the set's canonical batch
    /// node; a published pick whose dep chain the pulled slices do not
    /// fully carry, or a serve with no node or row at all, leaves the
    /// node on the chain it has.
    fn substitute(&mut self, tree_index: usize, node_index: usize) -> usize {
        if let Some(&index) = self.memo.get(&(tree_index, node_index)) {
            return index;
        }
        let node = &self.trees[tree_index].nodes[node_index];
        let key = substitution_group_key(node);
        let serve = &self.serving[&key][node.features_json.features()];
        let index = if serve.as_slice() == node.features_json.features() {
            self.intern(tree_index, node)
        } else {
            let published = self
                .published_reps
                .get(&(key.clone(), serve.clone()))
                .map(|&(slice_index, row_index, _)| (slice_index, row_index))
                .and_then(|(slice_index, row_index)| self.published_node(slice_index, row_index));
            match published {
                Some(index) => index,
                None => match self.representatives.get(&(key, serve.clone())) {
                    Some(&(rep_tree, rep_node)) => self.substitute(rep_tree, rep_node),
                    None => self.intern(tree_index, node),
                },
            }
        };
        self.memo.insert((tree_index, node_index), index);
        index
    }

    /// Intern one uncontained node's post-substitution form — same
    /// identity, dep positions repointed at substituted children.
    fn intern(&mut self, tree_index: usize, node: &SubmissionNode) -> usize {
        let mut dependencies = node
            .deps
            .iter()
            .map(|&dep| self.substitute(tree_index, dep as usize))
            .collect::<Vec<usize>>();
        dependencies.sort_unstable();
        dependencies.dedup();
        let intern_key = (
            TaskNodeIdentity {
                crate_name: node.crate_name.clone(),
                version: node.version.clone(),
                features_json: node.features_json.clone(),
                target: node.target.clone(),
                rustc_version: node.rustc_version.clone(),
                host_side: node.host_side,
            },
            node.explicit_spelling,
            dependencies,
        );
        if let Some(&index) = self.interned.get(&intern_key) {
            return index;
        }
        let index = self.arena.len();
        self.arena.push(ResolvedTaskNode {
            identity: intern_key.0.clone(),
            explicit_spelling: intern_key.1,
            dependencies: intern_key.2.clone(),
        });
        self.closure_pm
            .push(intern_key.1 == crate::public_cache::ExplicitSpelling::KeysApart);
        self.interned.insert(intern_key, index);
        index
    }

    /// The arena node reconstructing one published row's subtree —
    /// memoized per `(slice, row)`. Dep edges follow
    /// `dependency_task_ids`' child task ids through every pulled
    /// slice, so a target-side row's host deps land on the host slice
    /// they publish to (stow#919). `None` when an edge names a task no
    /// pulled row mints — the chain is not fully published, and the
    /// dependent stays on its own chain.
    fn published_node(&mut self, slice_index: usize, row_index: usize) -> Option<usize> {
        if let Some(&index) = self.published_memo.get(&(slice_index, row_index)) {
            return index;
        }
        let slice = &self.published[slice_index];
        let row = &slice.rows[row_index];
        let mut dependencies = Vec::new();
        for child_id in &row.dependency_task_ids {
            let Some(&(dep_slice, dep_row)) = self.by_task_id.get(child_id.as_str()) else {
                self.published_memo.insert((slice_index, row_index), None);
                return None;
            };
            let Some(dep_index) = self.published_node(dep_slice, dep_row) else {
                self.published_memo.insert((slice_index, row_index), None);
                return None;
            };
            dependencies.push(dep_index);
        }
        dependencies.sort_unstable();
        dependencies.dedup();
        // A proc-macro in the `--extern` closure keys a node apart —
        // recomputed from the reconstructed children, the published
        // rows carry no spelling flag of their own.
        let keys_apart = dependencies.iter().any(|&dep| self.closure_pm[dep]);
        let explicit_spelling = if keys_apart {
            crate::public_cache::ExplicitSpelling::KeysApart
        } else {
            crate::public_cache::ExplicitSpelling::KeysAsNative
        };
        let identity = published_row_identity(slice, row);
        let expected_task_id = self.row_task_ids[slice_index][row_index].as_str();
        let intern_key = (identity, explicit_spelling, dependencies);
        let index = if let Some(&index) = self.interned.get(&intern_key) {
            index
        } else {
            let index = self.arena.len();
            self.arena.push(ResolvedTaskNode {
                identity: intern_key.0.clone(),
                explicit_spelling: intern_key.1,
                dependencies: intern_key.2.clone(),
            });
            self.closure_pm
                .push(row.artifact_kind == ArtifactKind::ProcMacro || keys_apart);
            self.interned.insert(intern_key, index);
            index
        };
        self.pinned.insert(index, expected_task_id);
        self.published_memo
            .insert((slice_index, row_index), Some(index));
        Some(index)
    }
}

/// Re-emit one tree from its substituted roots' arena reach (stow#881):
/// contained-node subtrees no root still reaches leave the batch, and
/// each surviving node carries a post-substitution `task_id` and
/// `dependency_identity`.
///
/// A node's `downloads`/`preserve_lockfile` survive on its substituted
/// image inside this tree — several originals collapsing to one image
/// merge `max`/`or`; nodes no original maps to (a spliced or
/// reconstructed interior) carry neither.
fn reemit_substituted_tree(
    tree: &SubmissionTree,
    tree_index: usize,
    memo: &std::collections::HashMap<(usize, usize), usize>,
    resolved: &ResolvedTaskGraph,
) -> crate::error::Result<SubmissionTree> {
    let resolved_nodes = resolved.nodes();
    let image_of = |index: usize| memo[&(tree_index, index)];
    let reachable = {
        let mut seen = BTreeSet::new();
        let mut frontier: Vec<usize> = tree
            .roots
            .iter()
            .map(|&root| image_of(root as usize))
            .collect();
        while let Some(index) = frontier.pop() {
            if seen.insert(index) {
                frontier.extend(resolved_nodes[index].dependencies.iter().copied());
            }
        }
        seen
    };
    let local: BTreeMap<usize, u32> = reachable
        .iter()
        .enumerate()
        .map(|(rank, &index)| {
            (
                index,
                u32::try_from(rank).expect("submission node count fits u32"),
            )
        })
        .collect();
    let mut carried = BTreeMap::<usize, (u64, bool)>::new();
    for (node_index, node) in tree.nodes.iter().enumerate() {
        let image = image_of(node_index);
        if !reachable.contains(&image) {
            continue;
        }
        carried
            .entry(image)
            .and_modify(|(downloads, lockfile)| {
                *downloads = (*downloads).max(node.downloads);
                *lockfile |= node.preserve_lockfile;
            })
            .or_insert((node.downloads, node.preserve_lockfile));
    }
    let mut nodes = Vec::with_capacity(reachable.len());
    for &index in &reachable {
        let node = &resolved_nodes[index];
        let dependency_identity = resolved
            .dependency_identity(index)
            .cloned()
            .ok_or_else(|| stow_error!("resolved node {index} has no digest"))?;
        let (downloads, preserve_lockfile) = carried.get(&index).copied().unwrap_or_default();
        nodes.push(SubmissionNode {
            task_id: resolved
                .task_id(index)
                .ok_or_else(|| stow_error!("resolved node {index} has no task id"))?
                .to_owned(),
            crate_name: node.identity.crate_name.clone(),
            version: node.identity.version.clone(),
            features_json: node.identity.features_json.clone(),
            target: node.identity.target.clone(),
            rustc_version: node.identity.rustc_version.clone(),
            host_side: node.identity.host_side,
            explicit_spelling: node.explicit_spelling,
            preserve_lockfile,
            dependency_identity,
            deps: node.dependencies.iter().map(|dep| local[dep]).collect(),
            downloads,
        });
    }
    let mut roots = Vec::with_capacity(tree.roots.len());
    for &root in &tree.roots {
        let image = local[&image_of(root as usize)];
        if !roots.contains(&image) {
            roots.push(image);
        }
    }
    Ok(SubmissionTree {
        source: tree.source,
        roots,
        nodes,
    })
}

/// One dispatch pass's claim on one task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DispatchClaim {
    /// The claimed task.
    pub task_id: String,
    /// The generation minted for this claim.
    pub generation: u64,
    /// The attempt cycle the claim runs under.
    pub attempt: u32,
}

/// One dispatch response binding.
///
/// The run a claim's `workflow_dispatch` returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DispatchBinding {
    /// The claimed task.
    pub task_id: String,
    /// The generation this binding fences to.
    pub generation: u64,
    /// The GitHub Actions run id the dispatch returned.
    pub run_id: String,
}

/// The operator mutations `Mutate` records.
///
/// The selector is resolved to ids before the event is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    /// Re-queue a terminal task.
    Retry,
    /// Drop a pending task.
    Cancel,
    /// Move a task to the human lane.
    Promote,
    /// Remove aged rows outright.
    Purge,
}

/// One demand-batch contribution to one task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DemandEntry {
    /// The task the batch's closure reached.
    pub task_id: String,
    /// This batch's total contribution.
    pub delta: i64,
}

/// The human request lane's lifecycle events.
///
/// The `requests` record state machine carried as log entries.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RequestEvent {
    /// The record was admitted and a resolve run dispatched.
    Admitted {
        /// The admission's fields.
        admission: Box<RequestAdmission>,
        /// The dispatched attempt.
        attempt: u32,
        /// The unix-second dispatch stamp.
        dispatched_at: i64,
    },
    /// A `workflow_run` lifecycle event for the resolve run.
    RunUpdated {
        /// The update payload.
        update: Box<RequestRunUpdate>,
    },
    /// The resolve job's outcome report landed.
    Outcome {
        /// The reported attempt.
        attempt: u32,
        /// `enqueued` or `failed`.
        state: String,
        /// The serialized stored roots (present when enqueued).
        outcome_json: Option<String>,
        /// The failure reason (present when failed).
        error: Option<String>,
    },
}

/// One `Feed` event's payload — the `demand_feed_hours` /
/// `demand_feed_pages` rows' lifecycle (stow#878 stage 7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeedEvent {
    /// `feed_begin`: open a staging generation (or rotate an abandoned
    /// one — the monotonically bumped generation is the attempt's id).
    Begin {
        /// The generation stamp.
        generation: i64,
    },
    /// `feed_page`: one staged page — the wire request's bounded entry
    /// list, carried verbatim so replay restages it.
    Page {
        /// The generation the page lands under.
        generation: i64,
        /// In-order page number (`= staged_pages`).
        page_no: u32,
        /// The page's demand contributions.
        entries: Vec<SchedulerDemandEntry>,
    },
    /// `feed_complete`: the staged manifest verified — the hour
    /// accepts for delivery.
    Complete {
        /// The generation being accepted.
        generation: i64,
    },
    /// `feed_deliver`: one staged page's `Demand` batch acknowledged
    /// — `applied_pages` advances; the fold itself rides the paired
    /// `Demand` event.
    ApplyPage {
        /// The page this ack covered.
        page_no: u32,
    },
    /// `feed_deliver`: the terminal transition — `applied_pages ==
    /// page_count`, the hour becomes the new watermark.
    Deliver {
        /// The generation being delivered.
        generation: i64,
    },
    /// `feed_cleanup` expiry — the session is retired; a staging
    /// session's pages go with it.
    Expire,
}

/// One accepted event in the scheduler's flat append-only log (stow#878).
///
/// Every state change the in-memory graph survives a forced eviction
/// by is one of these, appended before the request or pass that
/// produced it is acknowledged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event")]
pub enum SchedulerEvent {
    /// One chunk of a multi-row submission: a `SubmissionTree` split at
    /// ~1 MiB so no row nears the platform's row-size bound, appended
    /// inside one transaction before the submit is acknowledged. `roots`
    /// rides part 0; `nodes` carries this part's slice of the tree.
    Submit {
        /// The entry point the whole tree arrives under.
        source: SubmissionSource,
        /// This part's index.
        part: u32,
        /// Total parts the tree was split into.
        parts: u32,
        /// Tree roots — set on part 0 only.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        roots: Vec<u32>,
        /// This part's nodes.
        nodes: Vec<SubmissionNode>,
    },
    /// An index-publish report: the unit shapes a live slice serves.
    SliceReport {
        /// The slice's compilation target.
        target: TargetTriple,
        /// The slice's rustc.
        rustc_version: WireRustcVersion,
        /// The report's declared base (delta reports).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        base_generation: Option<i64>,
        /// The index generation this report publishes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        generation: Option<i64>,
        /// Membership rows the report adds.
        added: Vec<PublishedSliceRow>,
        /// Membership rows the report retires.
        retired: Vec<PublishedSliceRow>,
    },
    /// One dispatch pass's whole claim set — one row for every claim of
    /// the pass, appended before the first `workflow_dispatch` posts.
    Claims {
        /// The pass's claims, in claim order.
        claims: Vec<DispatchClaim>,
    },
    /// One dispatch pass's whole binding set — one row after the
    /// concurrent dispatch POSTs return.
    Bindings {
        /// The pass's bindings.
        bindings: Vec<DispatchBinding>,
    },
    /// A `workflow_run` `in_progress` delivery for a run the scheduler
    /// did not dispatch — external occupancy only; the scheduler's own
    /// `in_progress` deliveries persist nothing.
    ExternalRunStarted {
        /// The Actions run id.
        run_id: String,
        /// The run's runner family.
        family: RunnerFamily,
    },
    /// A `workflow_run` delivery the scheduler accepted that appended
    /// nothing else — the `in_progress` channel's own-run and stale
    /// outcomes (stow#860). The log row's `at` is the acceptance
    /// instant the health check's last-delivery age reads; deliveries
    /// that already append an event (`RunFinished`,
    /// `ExternalRunStarted`, `Request` `RunUpdated`) mark it from
    /// their own rows instead.
    RunUpdate,
    /// A `workflow_run` `completed` delivery — applies to a bound run,
    /// parks until the binding lands, or just consumes an external run.
    RunFinished {
        /// The Actions run id.
        run_id: String,
        /// The task the run's title named.
        task_id: String,
        /// The mapped conclusion.
        success: bool,
        /// The conclusion was `cancelled`.
        #[serde(default)]
        cancelled: bool,
        /// Failure description.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    /// An operator mutation, selector already resolved to ids.
    Mutate {
        /// The mutation applied.
        op: MutationKind,
        /// The tasks it applied to.
        task_ids: Vec<String>,
    },
    /// A submit-by-id promotion: the missed lane re-requests tasks the
    /// graph already holds, raising their downloads and priority.
    SubmitIds {
        /// The promoted tasks.
        entries: Vec<SubmitTaskIdEntry>,
    },
    /// A human request lane lifecycle step.
    Request {
        /// The record the step applies to.
        request_id: String,
        /// The lifecycle event.
        kind: RequestEvent,
    },
    /// An accepted demand batch folded into the graph.
    Demand {
        /// The batch's durable identity (replays dedupe on it).
        batch_id: String,
        /// The canonical fingerprint the replay guard compares —
        /// the `demand_batches` row's `input_hash` (stow#878 stage 7).
        input_hash: String,
        /// The folded contributions.
        entries: Vec<DemandEntry>,
    },
    /// One demand-feed hour's lifecycle step — staging, completion,
    /// delivery and expiry replay identically (stow#878 stage 7).
    Feed {
        /// The hour the step belongs to (`YYYY-MM-DDTHH`).
        hour: String,
        /// The step.
        kind: FeedEvent,
    },
    /// The dispatch freeze's transition record (`None` = cleared).
    Freeze {
        /// The serialized record while engaged.
        record: Option<Box<crate::api::DispatchFreezeRecord>>,
        /// When the transition happened — the log carries it so the
        /// transition history survives a cleared record (stow#878).
        at: String,
        /// What triggered it — on clears it echoes the cleared
        /// record's trigger for the history read.
        trigger: crate::api::DispatchFreezeTrigger,
    },
}

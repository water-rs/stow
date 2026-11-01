//! Evidence linking a failed cached compilation to its cache-free replay.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::api::BuildTaskPayload;

/// Exact GitHub job name whose successful conclusion certifies a replay.
pub const VERIFICATION_JOB_NAME: &str = "verify source failure";

/// A compiler diagnostic stripped of presentation and machine-local paths.
/// The producer takes these fields from compiler output, never Cargo's
/// generic nonzero-exit message.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SourceDiagnostic {
    /// Registry package containing the failing source.
    pub package: String,
    /// Source path relative to that package's root.
    pub source: String,
    /// Source line reported by the compiler.
    pub line: u64,
    /// Compiler diagnostic code, when the compiler supplies one.
    pub code: Option<String>,
    /// Diagnostic text, without rendered colors or source excerpts.
    pub message: String,
}

/// Exact inputs shared by the original phase and its clean replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationInputs {
    /// The complete dispatched identity, including its dependency graph.
    pub task: BuildTaskPayload,
    /// SHA-256 of the frozen Cargo.lock bytes.
    pub lock_sha256: String,
    /// SHA-256 of the generated wrapper manifest bytes.
    pub manifest_sha256: String,
    /// Cargo argv used by the phase, excluding the output directory.
    pub cargo_args: Vec<String>,
    /// Rust flags with workspace and output paths normalized.
    pub rustflags: String,
}

/// A failed phase's compiler evidence. An empty diagnostic set is not
/// proof of a source failure: process, wrapper and infrastructure errors
/// remain infrastructure failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilationFailure {
    /// Inputs observed by the supervisor before executing Cargo.
    pub inputs: CompilationInputs,
    /// Compiler diagnostics observed for this failed phase.
    pub diagnostics: BTreeSet<SourceDiagnostic>,
}

/// A failure independently reproduced without cached artifacts.
///
/// This witness cannot be deserialized from untrusted build output. The
/// trusted verifier constructs it only after running the clean replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedSourceFailure {
    failure: CompilationFailure,
}

impl CompilationFailure {
    /// Match this failed phase against an independently observed replay.
    /// A successful replay is represented by `None`.
    #[must_use]
    pub fn verify_replay(self, replay: Option<&Self>) -> Option<VerifiedSourceFailure> {
        if self.diagnostics.is_empty() || replay != Some(&self) {
            return None;
        }
        Some(VerifiedSourceFailure { failure: self })
    }
}

#[cfg(test)]
mod tests {
    use super::{CompilationFailure, CompilationInputs, SourceDiagnostic};
    use crate::api::{BuildTaskPayload, TaskSubgraph};

    fn failure() -> CompilationFailure {
        CompilationFailure {
            inputs: CompilationInputs {
                task: BuildTaskPayload {
                    task_id: "fixture-task".to_owned(),
                    attempt: 1,
                    crate_name: "uuid".parse().expect("crate name"),
                    version: "1.29.0".parse().expect("version"),
                    features_json: crate::identity::FeaturesJson::canonicalize(vec![
                        "rng".to_owned(),
                        "v4".to_owned(),
                    ])
                    .expect("features"),
                    target: "wasm32-unknown-unknown".parse().expect("target"),
                    rustc_version: "1.99.1".parse().expect("rustc"),
                    preserve_lockfile: false,
                    host_side: false,
                    explicit_spelling: crate::public_cache::ExplicitSpelling::KeysAsNative,
                    dependency_subgraph: TaskSubgraph {
                        root_deps: Vec::new(),
                        nodes: Vec::new(),
                    },
                    profile: crate::node_profile::NodeProfile::Dev,
                },
                lock_sha256: "ab".repeat(32),
                manifest_sha256: "ef".repeat(32),
                cargo_args: vec!["check".to_owned(), "--frozen".to_owned()],
                rustflags: String::new(),
            },
            diagnostics: [SourceDiagnostic {
                package: "uuid@1.29.0".to_owned(),
                source: "src/rng.rs".to_owned(),
                line: 104,
                code: None,
                message: "specify a source of randomness".to_owned(),
            }]
            .into(),
        }
    }

    #[test]
    fn identical_source_failure_produces_a_verified_witness() {
        let original = failure();
        let witness = original
            .clone()
            .verify_replay(Some(&original))
            .expect("verified");
        assert_eq!(witness.failure(), &original);
    }

    #[test]
    fn success_and_empty_diagnostics_never_exempt_a_failure() {
        assert!(failure().verify_replay(None).is_none());
        let mut original = failure();
        original.diagnostics.clear();
        assert!(original.clone().verify_replay(Some(&original)).is_none());
    }

    #[test]
    fn changed_inputs_or_diagnostics_do_not_verify() {
        let original = failure();
        let mut changed = original.clone();
        changed.inputs.lock_sha256 = "cd".repeat(32);
        assert!(original.clone().verify_replay(Some(&changed)).is_none());
        changed = original.clone();
        changed.inputs.manifest_sha256 = "12".repeat(32);
        assert!(original.clone().verify_replay(Some(&changed)).is_none());
        changed = original.clone();
        changed.inputs.rustflags = "--cfg changed".to_owned();
        assert!(original.clone().verify_replay(Some(&changed)).is_none());
        changed = original.clone();
        changed.inputs.task.attempt += 1;
        assert!(original.clone().verify_replay(Some(&changed)).is_none());
        changed = original.clone();
        changed.inputs.cargo_args.push("--release".to_owned());
        assert!(original.clone().verify_replay(Some(&changed)).is_none());
        changed = original.clone();
        let mut diagnostic = changed.diagnostics.pop_first().expect("diagnostic");
        diagnostic.message = "different compiler failure".to_owned();
        changed.diagnostics.insert(diagnostic);
        assert!(original.verify_replay(Some(&changed)).is_none());
    }
}

impl VerifiedSourceFailure {
    /// The exact failed compilation the verifier reproduced.
    #[must_use]
    pub const fn failure(&self) -> &CompilationFailure {
        &self.failure
    }
}

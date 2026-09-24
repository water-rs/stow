//! Task binding for `POST /api/v1/admin/artifacts/register`.
//!
//! A trusted artifact write is not "any caller holding a `build-crate.yml`
//! OIDC token may write any row" — it is "this run may write the rows the
//! task it was dispatched for can produce". The wasm handler resolves the
//! caller and expands the named task's dependency closure; this module is
//! the pure decision over the result, so the whole policy stays
//! host-testable.

use std::collections::BTreeSet;

use stow_types::api::{ArtifactRecord, QueueTaskStatus};
use stow_types::identity::{CrateName, CrateVersion, TargetTriple, WireRustcVersion};

use crate::github_auth::TrustedCaller;

/// The scheduler task a register request binds to, reduced to what the
/// record check needs.
#[derive(Debug)]
pub struct TaskScope {
    /// The queue row's `task_id`.
    pub task_id: String,
    /// Queue lifecycle state — only `dispatched`/`running` rows accept
    /// records.
    pub status: QueueTaskStatus,
    /// Task crate name.
    pub crate_name: CrateName,
    /// Task crate version.
    pub version: CrateVersion,
    /// Task target triple.
    pub target: TargetTriple,
    /// Task rustc version.
    pub rustc_version: WireRustcVersion,
    /// `(crate_name, version)` packages the task's build may produce — the
    /// task crate plus its dependency closure
    /// (`dependency_resolver::expand_task_closure`). `None` when the task
    /// resolves a lockfile the edge cannot reproduce — a
    /// `preserve_lockfile` overlay — which narrows the binding to the
    /// target/rustc identity.
    pub closure: Option<BTreeSet<(CrateName, CrateVersion)>>,
}

/// What a register request's `task_id` resolved to against the scheduler
/// queue.
#[derive(Debug)]
pub enum TaskBinding {
    /// No `task_id` was supplied — legitimate only for push-user callers,
    /// the backfill and operator path that runs outside a dispatched task.
    Unbound,
    /// The named id has no queue row — never enqueued or already reaped.
    Unknown(String),
    /// The named task resolved to a live queue row.
    Bound(TaskScope),
}

/// The HTTP rejection class a [`RegisterViolation`] maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationKind {
    /// Malformed request — 400.
    BadRequest,
    /// The record set escapes the caller's authority — 403.
    Forbidden,
    /// The named task cannot accept records in its current state — 409.
    Conflict,
}

/// The first reason a register request is refused. The handler maps each
/// variant through [`RegisterViolation::kind`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegisterViolation {
    /// An Actions OIDC caller named no task. A dispatched run always
    /// knows its task id, so omission is a malformed request — not the
    /// operator backfill path.
    #[error("Actions callers must name the scheduler task the run was dispatched for (`task_id`)")]
    MissingTaskId,
    /// The named id is not in the scheduler queue.
    #[error("task `{task_id}` is unknown to the scheduler")]
    UnknownTask {
        /// The id the request named.
        task_id: String,
    },
    /// The named task is not in flight; only `dispatched`/`running` rows
    /// accept records.
    #[error(
        "task `{task_id}` is `{}` — records are accepted only while the task is dispatched or running",
        .status.as_str()
    )]
    TaskNotInFlight {
        /// The named task.
        task_id: String,
        /// Its queue status.
        status: QueueTaskStatus,
    },
    /// A record's target differs from the task's.
    #[error(
        "record `{crate_name} {version}` targets `{record_target}` but task `{task_id}` builds `{task_target}`"
    )]
    ForeignTarget {
        /// The offending record's crate.
        crate_name: CrateName,
        /// The offending record's version.
        version: CrateVersion,
        /// The target the record claims.
        record_target: TargetTriple,
        /// The named task.
        task_id: String,
        /// The target the task builds.
        task_target: TargetTriple,
    },
    /// A record's rustc version differs from the task's.
    #[error(
        "record `{crate_name} {version}` was built with rustc `{record_rustc_version}` but task `{task_id}` builds `{task_rustc_version}`"
    )]
    ForeignRustcVersion {
        /// The offending record's crate.
        crate_name: CrateName,
        /// The offending record's version.
        version: CrateVersion,
        /// The rustc version the record claims.
        record_rustc_version: WireRustcVersion,
        /// The named task.
        task_id: String,
        /// The rustc version the task builds.
        task_rustc_version: WireRustcVersion,
    },
    /// A record without a unit shape. The builder stamps the shape by
    /// construction, so `None` means the record came from a writer that
    /// predates the column — admissible only when it re-registers a row
    /// that is still shapeless (the legacy-row backfill paths); anything
    /// else would mint a new row the coverage gate can never match.
    #[error(
        "record `{crate_name} {version}` (compile key {compile_key}) carries no unit shape — only a row that predates the shape columns may be registered shapeless"
    )]
    MissingUnitShape {
        /// The offending record's crate.
        crate_name: CrateName,
        /// The offending record's version.
        version: CrateVersion,
        /// The offending record's compile key.
        compile_key: String,
    },
    /// A record's `(crate_name, version)` is neither the task crate nor a
    /// member of its dependency closure — the containment check this
    /// binding exists for.
    #[error(
        "record `{crate_name} {version}` is outside the dependency closure of task `{task_id}`"
    )]
    OutsideClosure {
        /// The offending record's crate.
        crate_name: CrateName,
        /// The offending record's version.
        version: CrateVersion,
        /// The named task.
        task_id: String,
    },
}

impl RegisterViolation {
    /// The HTTP rejection class of this violation.
    pub const fn kind(&self) -> ViolationKind {
        match self {
            Self::MissingTaskId | Self::MissingUnitShape { .. } => ViolationKind::BadRequest,
            Self::UnknownTask { .. } | Self::TaskNotInFlight { .. } => ViolationKind::Conflict,
            Self::ForeignTarget { .. }
            | Self::ForeignRustcVersion { .. }
            | Self::OutsideClosure { .. } => ViolationKind::Forbidden,
        }
    }
}

/// First reason `records` may not register under `caller`'s claimed
/// `binding`, if any. Every record is examined before the caller writes a
/// single row — a request registers whole or not at all.
///
/// `existing_shapeless` is the set of `(c_metadata, target, rustc)` keys
/// whose rows already exist as pre-column shapeless rows — fetched by the
/// handler for the request's shapeless records. A shapeless record naming
/// any other key is refused: nothing new may land shapeless.
pub fn first_violation(
    caller: &TrustedCaller,
    binding: &TaskBinding,
    records: &[ArtifactRecord],
    existing_shapeless: &BTreeSet<(String, String, String)>,
) -> Option<RegisterViolation> {
    if let Some(record) = records.iter().find(|record| {
        record.unit_shape.is_none()
            && !existing_shapeless.contains(&(
                record.c_metadata.as_str().to_owned(),
                record.target.as_str().to_owned(),
                record.rustc_version.as_str().to_owned(),
            ))
    }) {
        return Some(RegisterViolation::MissingUnitShape {
            crate_name: record.crate_name.clone(),
            version: record.version.clone(),
            compile_key: record.compile_key.clone(),
        });
    }
    let scope = match binding {
        TaskBinding::Unbound => {
            return match caller {
                // A dispatched run always knows the task it serves; an
                // OIDC caller without one is a malformed CI request, not
                // a backfill.
                TrustedCaller::Actions { .. } => Some(RegisterViolation::MissingTaskId),
                TrustedCaller::Push { .. } => None,
            };
        }
        TaskBinding::Unknown(task_id) => {
            return Some(RegisterViolation::UnknownTask {
                task_id: task_id.clone(),
            });
        }
        TaskBinding::Bound(scope) => scope,
    };
    if !matches!(
        scope.status,
        QueueTaskStatus::Dispatched | QueueTaskStatus::Running
    ) {
        return Some(RegisterViolation::TaskNotInFlight {
            task_id: scope.task_id.clone(),
            status: scope.status,
        });
    }
    records
        .iter()
        .find_map(|record| record_violation(scope, record))
}

/// First reason `record` falls outside `scope`, if any.
fn record_violation(scope: &TaskScope, record: &ArtifactRecord) -> Option<RegisterViolation> {
    if record.target != scope.target {
        return Some(RegisterViolation::ForeignTarget {
            crate_name: record.crate_name.clone(),
            version: record.version.clone(),
            record_target: record.target.clone(),
            task_id: scope.task_id.clone(),
            task_target: scope.target.clone(),
        });
    }
    if record.rustc_version != scope.rustc_version {
        return Some(RegisterViolation::ForeignRustcVersion {
            crate_name: record.crate_name.clone(),
            version: record.version.clone(),
            record_rustc_version: record.rustc_version.clone(),
            task_id: scope.task_id.clone(),
            task_rustc_version: scope.rustc_version.clone(),
        });
    }
    if let Some(closure) = &scope.closure {
        let is_task_crate =
            record.crate_name == scope.crate_name && record.version == scope.version;
        let key = (record.crate_name.clone(), record.version.clone());
        if !is_task_crate && !closure.contains(&key) {
            return Some(RegisterViolation::OutsideClosure {
                crate_name: record.crate_name.clone(),
                version: record.version.clone(),
                task_id: scope.task_id.clone(),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use stow_types::artifact::{ArtifactKind, RustCrateType};
    use stow_types::identity::{
        CMetadata, DependencyCMetadataIdentity, DependencyCMetadataJson, FeaturesJson,
    };
    use stow_types::platform::{PanicStrategy, Profile, StripLevel};

    use super::*;

    const TARGET: &str = "x86_64-unknown-linux-gnu";
    const OTHER_TARGET: &str = "aarch64-apple-darwin";
    const RUSTC: &str = "1.85.0";
    const OTHER_RUSTC: &str = "1.86.0";

    fn actions() -> TrustedCaller {
        TrustedCaller::Actions {
            job_workflow_ref: "water-rs/stow/.github/workflows/build-crate.yml@refs/heads/main"
                .to_owned(),
            run_id: "123".to_owned(),
        }
    }

    fn push() -> TrustedCaller {
        TrustedCaller::Push {
            label: "operator".to_owned(),
        }
    }

    fn record(crate_name: &str, version: &str) -> ArtifactRecord {
        ArtifactRecord {
            compile_key: "aabbccddee112233".to_owned(),
            c_metadata: CMetadata::parse("aabbccdd").expect("c_metadata"),
            extra_filename: "-aabbccdd".to_owned(),
            target: TARGET.parse().expect("target"),
            rustc_version: RUSTC.parse().expect("rustc"),
            unit_shape: Some(stow_types::public_cache::UnitShape {
                side: stow_types::public_cache::UnitSide::Target,
                invocation: stow_types::public_cache::UnitInvocation::Native,
                kind: stow_types::public_cache::UnitKind::Linked,
            }),
            profile: Profile {
                opt_level: "0".to_owned(),
                debuginfo: 0,
                debug_assertions: true,
                overflow_checks: true,
                panic: PanicStrategy::Unwind,
                strip: StripLevel::None,
            },
            emit: vec!["link".to_owned()],
            crate_name: CrateName::parse(crate_name).expect("crate name"),
            version: CrateVersion::new(semver::Version::parse(version).expect("version")),
            features_json: FeaturesJson::default(),
            dependency_c_metadata_json: DependencyCMetadataJson::canonicalize(Vec::<
                DependencyCMetadataIdentity,
            >::new())
            .expect("deps"),
            oci_reference: "ghcr.io/water-rs/stow-cache:test".to_owned(),
            oci_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            has_native: false,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            artifact_size: 1,
            bundle_digest:
                "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            bundle_size: 1,
            compile_millis: 0,
            min_glibc: None,
        }
    }

    /// A `dispatched` task scope for `root 1.0.0` whose crates.io closure
    /// is `{dep-a 1.0.0, dep-b 2.0.0}`.
    fn scope() -> TaskScope {
        TaskScope {
            task_id: "root-1.0.0-abc-x86_64-unknown-linux-gnu-1.85.0".to_owned(),
            status: QueueTaskStatus::Dispatched,
            crate_name: CrateName::parse("root").expect("crate name"),
            version: CrateVersion::new(semver::Version::parse("1.0.0").expect("version")),
            target: TARGET.parse().expect("target"),
            rustc_version: RUSTC.parse().expect("rustc"),
            closure: Some(BTreeSet::from([
                (
                    CrateName::parse("dep-a").expect("crate name"),
                    CrateVersion::new(semver::Version::parse("1.0.0").expect("version")),
                ),
                (
                    CrateName::parse("dep-b").expect("crate name"),
                    CrateVersion::new(semver::Version::parse("2.0.0").expect("version")),
                ),
            ])),
        }
    }

    fn bound() -> TaskBinding {
        TaskBinding::Bound(scope())
    }

    #[test]
    fn record_for_the_task_crate_is_accepted() {
        assert_eq!(
            first_violation(
                &actions(),
                &bound(),
                &[record("root", "1.0.0")],
                &BTreeSet::new()
            ),
            None
        );
    }

    #[test]
    fn record_for_a_closure_member_is_accepted() {
        let records = [record("dep-a", "1.0.0"), record("dep-b", "2.0.0")];
        assert_eq!(
            first_violation(&actions(), &bound(), &records, &BTreeSet::new()),
            None
        );
    }

    #[test]
    fn record_outside_the_closure_is_forbidden() {
        let violation = first_violation(
            &actions(),
            &bound(),
            &[record("dep-a", "1.0.0"), record("stranger", "9.9.9")],
            &BTreeSet::new(),
        )
        .expect("a crate outside the closure must violate");
        assert_eq!(
            violation,
            RegisterViolation::OutsideClosure {
                crate_name: CrateName::parse("stranger").expect("crate name"),
                version: CrateVersion::new(semver::Version::parse("9.9.9").expect("version")),
                task_id: scope().task_id,
            }
        );
        assert_eq!(violation.kind(), ViolationKind::Forbidden);
    }

    /// A version the closure does not pin is as foreign as a name it does
    /// not contain.
    #[test]
    fn closure_member_at_the_wrong_version_is_forbidden() {
        let violation = first_violation(
            &actions(),
            &bound(),
            &[record("dep-a", "9.9.9")],
            &BTreeSet::new(),
        )
        .expect("an unpinned version must violate");
        assert!(matches!(
            violation,
            RegisterViolation::OutsideClosure { .. }
        ));
        assert_eq!(violation.kind(), ViolationKind::Forbidden);
    }

    #[test]
    fn record_with_a_foreign_target_is_forbidden() {
        let mut record = record("root", "1.0.0");
        record.target = OTHER_TARGET.parse().expect("target");
        let violation = first_violation(&actions(), &bound(), &[record], &BTreeSet::new())
            .expect("a foreign target must violate");
        assert!(matches!(violation, RegisterViolation::ForeignTarget { .. }));
        assert_eq!(violation.kind(), ViolationKind::Forbidden);
    }

    #[test]
    fn record_with_a_foreign_rustc_is_forbidden() {
        let mut record = record("dep-a", "1.0.0");
        record.rustc_version = OTHER_RUSTC.parse().expect("rustc");
        let violation = first_violation(&actions(), &bound(), &[record], &BTreeSet::new())
            .expect("a foreign rustc must violate");
        assert!(matches!(
            violation,
            RegisterViolation::ForeignRustcVersion { .. }
        ));
        assert_eq!(violation.kind(), ViolationKind::Forbidden);
    }

    /// The task crate at the task's own identity is the root, not a
    /// closure member — a wrong version is still outside the closure.
    #[test]
    fn task_crate_at_another_version_is_forbidden() {
        let violation = first_violation(
            &actions(),
            &bound(),
            &[record("root", "2.0.0")],
            &BTreeSet::new(),
        )
        .expect("the task crate at another version must violate");
        assert!(matches!(
            violation,
            RegisterViolation::OutsideClosure { .. }
        ));
    }

    #[test]
    fn oidc_caller_without_task_id_is_a_bad_request() {
        let violation = first_violation(
            &actions(),
            &TaskBinding::Unbound,
            &[record("x", "1.0.0")],
            &BTreeSet::new(),
        )
        .expect("an unbound Actions write must violate");
        assert_eq!(violation, RegisterViolation::MissingTaskId);
        assert_eq!(violation.kind(), ViolationKind::BadRequest);
    }

    #[test]
    fn push_user_without_task_id_is_accepted() {
        assert_eq!(
            first_violation(
                &push(),
                &TaskBinding::Unbound,
                &[record("x", "1.0.0")],
                &BTreeSet::new()
            ),
            None
        );
    }

    /// The backfill path may omit `task_id`, but when an operator names a
    /// task the same checks apply.
    #[test]
    fn push_user_with_task_id_is_still_bound() {
        let violation = first_violation(
            &push(),
            &bound(),
            &[record("stranger", "1.0.0")],
            &BTreeSet::new(),
        )
        .expect("a named task binds push users too");
        assert!(matches!(
            violation,
            RegisterViolation::OutsideClosure { .. }
        ));
    }

    #[test]
    fn unknown_task_id_conflicts() {
        let binding = TaskBinding::Unknown("nope".to_owned());
        let violation = first_violation(
            &actions(),
            &binding,
            &[record("root", "1.0.0")],
            &BTreeSet::new(),
        )
        .expect("an unknown task must violate");
        assert_eq!(
            violation,
            RegisterViolation::UnknownTask {
                task_id: "nope".to_owned()
            }
        );
        assert_eq!(violation.kind(), ViolationKind::Conflict);
    }

    #[test]
    fn pending_task_conflicts() {
        let mut scope = scope();
        scope.status = QueueTaskStatus::Pending;
        let binding = TaskBinding::Bound(scope);
        let violation = first_violation(
            &actions(),
            &binding,
            &[record("root", "1.0.0")],
            &BTreeSet::new(),
        )
        .expect("a pending task must violate");
        assert!(matches!(
            violation,
            RegisterViolation::TaskNotInFlight { .. }
        ));
        assert_eq!(violation.kind(), ViolationKind::Conflict);
    }

    #[test]
    fn completed_task_conflicts() {
        let mut scope = scope();
        scope.status = QueueTaskStatus::Completed;
        let binding = TaskBinding::Bound(scope);
        let violation = first_violation(
            &actions(),
            &binding,
            &[record("root", "1.0.0")],
            &BTreeSet::new(),
        )
        .expect("a completed task must violate");
        assert_eq!(violation.kind(), ViolationKind::Conflict);
    }

    #[test]
    fn running_task_is_accepted() {
        let mut scope = scope();
        scope.status = QueueTaskStatus::Running;
        let binding = TaskBinding::Bound(scope);
        assert_eq!(
            first_violation(
                &actions(),
                &binding,
                &[record("dep-a", "1.0.0")],
                &BTreeSet::new()
            ),
            None
        );
    }

    /// A lockfile-bound task carries `closure: None`: the edge cannot
    /// reproduce its resolution, so any crate name is admissible while
    /// target and rustc still pin the write.
    #[test]
    fn lockfile_task_skips_the_closure_check_but_not_identity() {
        let mut scope = scope();
        scope.closure = None;
        let binding = TaskBinding::Bound(scope);
        assert_eq!(
            first_violation(
                &actions(),
                &binding,
                &[record("stranger", "9.9.9")],
                &BTreeSet::new()
            ),
            None,
            "an unresolvable closure admits any crate name"
        );

        let mut foreign = record("stranger", "9.9.9");
        foreign.target = OTHER_TARGET.parse().expect("target");
        let violation = first_violation(&actions(), &binding, &[foreign], &BTreeSet::new())
            .expect("target identity still binds lockfile tasks");
        assert!(matches!(violation, RegisterViolation::ForeignTarget { .. }));
    }

    /// The builder stamps every record's shape by construction — a
    /// shapeless record names no dispatched task's row and a brand-new
    /// shapeless row is refused on every caller path.
    #[test]
    fn new_shapeless_records_are_a_bad_request() {
        let mut record = record("root", "1.0.0");
        record.unit_shape = None;
        let violation = first_violation(&actions(), &bound(), &[record.clone()], &BTreeSet::new())
            .expect("a new shapeless row must violate");
        assert_eq!(
            violation,
            RegisterViolation::MissingUnitShape {
                crate_name: record.crate_name.clone(),
                version: record.version.clone(),
                compile_key: record.compile_key.clone(),
            }
        );
        assert_eq!(violation.kind(), ViolationKind::BadRequest);

        // The refusal does not wait on the task binding — the backfill
        // (unbound push) path may not mint a shapeless row either.
        let violation =
            first_violation(&push(), &TaskBinding::Unbound, &[record], &BTreeSet::new())
                .expect("a shapeless record must violate even unbound");
        assert_eq!(violation.kind(), ViolationKind::BadRequest);
    }

    /// A row registered before the shape columns existed is still
    /// shapeless — re-registering it (the min-glibc backfill) keeps it
    /// that way and stays admissible.
    #[test]
    fn shapeless_re_register_of_a_pre_column_row_is_accepted() {
        let mut record = record("root", "1.0.0");
        record.unit_shape = None;
        let key = (
            record.c_metadata.as_str().to_owned(),
            record.target.as_str().to_owned(),
            record.rustc_version.as_str().to_owned(),
        );
        assert_eq!(
            first_violation(
                &push(),
                &TaskBinding::Unbound,
                &[record],
                &BTreeSet::from([key])
            ),
            None
        );
    }
}

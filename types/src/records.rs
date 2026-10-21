//! The per-build artifact records as a signed OCI artifact (stow#455).
//!
//! The trusted publish stage pushes each build's `Vec<ArtifactRecord>` as
//! one signed artifact — the `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>`
//! tag in the same `water-rs/stow-cache-<rustc>` namespace the bundles use —
//! instead of posting records to the edge. The tag names the Actions run
//! that published it, so a second build of the same task lands on a new
//! tag rather than overwriting the first's rows (stow#655). The index
//! export and the D1 catalog sync both read that artifact back from GHCR,
//! so the registry plus cosign is the only record store and no
//! `STOW_EDGE_URL` reaches `build-crate.yml`.

use crate::api::{ArtifactRecord, BatchId};
use crate::index::ArtifactIndexRow;
use crate::registry::MAX_OCI_TAG_LEN;

/// `artifactType` (and single-layer media type) of a records artifact: a
/// JSON array of [`ArtifactRecord`] — the full set of rows one
/// `build-crate.yml` run published.
pub const RECORDS_ARTIFACT_TYPE: &str = "application/vnd.stow.records.v1+json";

/// Media type of the records artifact's empty OCI config blob.
pub const RECORDS_CONFIG_MEDIA_TYPE: &str = "application/vnd.stow.records.config.v1+json";

/// Manifest annotation carrying the task id the artifact belongs to —
/// readers never parse the tag for it.
pub const RECORDS_TASK_ID_ANNOTATION: &str = "dev.stow.records.task-id";

/// The `run-name` `build-crate.yml` stamps on its run — the full
/// `<rustc>-<task_id>`, unhashed.
///
/// `WireRustcVersion` is numeric (`1.99.0`) and never contains `-`, so
/// the title splits at the first `-`: the rustc version selects which
/// records an export pass considers, the task id identifies the run.
#[must_use]
pub fn run_title(rustc_version: &str, task_id: &str) -> String {
    debug_assert!(
        !rustc_version.is_empty() && !rustc_version.contains('-'),
        "rustc version {rustc_version:?} cannot lead a run title"
    );
    format!("{rustc_version}-{task_id}")
}

/// The `(rustc_version, task_id)` a run title names — the inverse of
/// [`run_title`]. `None` when the title is not `<rustc>-<task_id>`: the
/// run is not one ours could have made, or its name was hand-edited.
#[must_use]
pub fn parse_run_title(title: &str) -> Option<(&str, &str)> {
    let (rustc_version, task_id) = title.split_once('-')?;
    (!rustc_version.is_empty() && !task_id.is_empty()).then_some((rustc_version, task_id))
}

/// The `run-name` `build-batch.yml` stamps on its run (stow#833).
///
/// The full `<rustc>-b<batch_id>`. `batch_id` is the 32-lowercase-hex
/// [`BatchId`] the scheduler minted at claim (`lower(hex(randomblob(16)))`,
/// like `generation_id`). The `b` marker keeps batch titles disjoint
/// from `build-crate.yml`'s `<rustc>-<task_id>`: a task id can never
/// be exactly `b` + 32 hex. `index-publish-cron.yml`'s
/// `${RUN_TITLE%%-*}` still yields the rustc.
#[must_use]
pub fn batch_run_title(rustc_version: &str, batch_id: &BatchId) -> String {
    debug_assert!(
        !rustc_version.is_empty() && !rustc_version.contains('-'),
        "rustc version {rustc_version:?} cannot lead a run title"
    );
    format!("{rustc_version}-b{batch_id}")
}

/// The `(rustc_version, batch_id)` a batch run title names.
///
/// The inverse of [`batch_run_title`], returning the [`BatchId`]
/// without its `b` marker. `None` when the title is not
/// `<rustc>-b<32 lowercase hex>`: the run is not one ours could have
/// made.
#[must_use]
pub fn parse_batch_run_title(title: &str) -> Option<(&str, BatchId)> {
    let (rustc_version, rest) = title.split_once('-')?;
    let batch_id = rest.strip_prefix('b')?.parse().ok()?;
    (!rustc_version.is_empty()).then_some((rustc_version, batch_id))
}

/// The `run-name` `resolve-request.yml` stamps on its run —
/// `resolve-a<attempt>-<request_id>`.
///
/// The `a<attempt>` leg pins the record's dispatch epoch so a stale
/// run's `workflow_run` events cannot land on a re-request's live
/// attempt, and the `resolve-` leg keeps the title's first-dash split
/// disjoint from `build-crate.yml`'s `<rustc>-<task_id>`.
#[must_use]
pub fn resolve_run_title(attempt: u32, request_id: &str) -> String {
    format!("resolve-a{attempt}-{request_id}")
}

/// The `(attempt, request_id)` a resolve run title names — the inverse
/// of [`resolve_run_title`].
///
/// `None` when the title is not `resolve-a<attempt>-<request_id>`: not
/// one of our resolve runs, or its name was hand-edited.
#[must_use]
pub fn parse_resolve_run_title(title: &str) -> Option<(u32, &str)> {
    let (attempt, request_id) = title.strip_prefix("resolve-")?.split_once('-')?;
    let attempt = attempt.strip_prefix('a')?.parse().ok()?;
    (!request_id.is_empty()).then_some((attempt, request_id))
}

/// The GitHub Actions run a records artifact published under.
///
/// `run_id` is the run's `GITHUB_RUN_ID` and `run_attempt` its
/// `GITHUB_RUN_ATTEMPT`. Every build publishes under its own tag —
/// `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>` — so nothing
/// overwrites a records tag and a rebuilt task's rows always reach the
/// index (stow#655).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BuildRun {
    /// The Actions workflow run id.
    pub run_id: u64,
    /// The run's attempt number — `1` on the first run.
    pub run_attempt: u32,
}

/// Tag prefix a records artifact publishes under:
/// `records-<rustc>-<task_id hash>-<run_id>-<run_attempt>`.
///
/// The leading `records-` keeps the tag namespace disjoint from bundle
/// and index tags, and starts with a letter so it always satisfies the
/// OCI tag grammar. The embedded rustc lets an export pass select its
/// records by tag alone.
pub const RECORDS_TAG_PREFIX: &str = "records-";

/// The OCI tag of `task_id`'s records artifact as `build` published it
/// at `rustc_version`.
///
/// A task id is the full `<crate>-<version>-<features>-<target>-<rustc>`
/// string — well past OCI's tag limit at long crate names — so the tag
/// carries its blake3 hash instead: `records-<rustc>-<task_id
/// hash>-<run_id>-<run_attempt>` is 8 + ≤10 + 1 + 64 + 1 + ≤20 + 1 +
/// ≤10 characters, always under [`MAX_OCI_TAG_LEN`]. The full task id
/// rides on the manifest's [`RECORDS_TASK_ID_ANNOTATION`].
///
/// # Panics
///
/// When the produced tag exceeds [`MAX_OCI_TAG_LEN`].
#[must_use]
pub fn records_tag(rustc_version: &str, task_id: &str, build: BuildRun) -> String {
    let digest = blake3::hash(task_id.as_bytes()).to_hex();
    let tag = format!(
        "{RECORDS_TAG_PREFIX}{rustc_version}-{digest}-{}-{}",
        build.run_id, build.run_attempt
    );
    assert!(
        tag.len() <= MAX_OCI_TAG_LEN,
        "records tag {tag:?} exceeds {MAX_OCI_TAG_LEN} chars"
    );
    tag
}

/// Whether `field` is a decimal literal — non-empty ASCII digits, so no
/// sign and no leading `+` pass.
fn is_decimal(field: &str) -> bool {
    !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit())
}

/// What a `records-*` tag names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordsTag<'a> {
    /// The rustc the build ran under.
    pub rustc_version: &'a str,
    /// The blake3 of the task id, as 64 hex digits.
    pub task_hash: &'a str,
    /// The run that published the artifact. `None` on a tag with no
    /// build suffix — the shape every build published before tags named
    /// their build (stow#655). Such a tag was shared by every build of
    /// its task, so what it holds is older than any named build of that
    /// task, and `None` orders first.
    pub build: Option<BuildRun>,
}

/// The parts of a `records-*` tag — the inverse of [`records_tag`], and
/// the reader of the suffix-less tags still in the registry.
///
/// `None` when the tag is not a records tag. The task id the tag names
/// is the blake3 the digest hashes, so it can never be read back out; a
/// caller needing it takes the manifest's
/// [`RECORDS_TASK_ID_ANNOTATION`].
#[must_use]
pub fn parse_records_tag(tag: &str) -> Option<RecordsTag<'_>> {
    let (rustc_version, rest) = tag.strip_prefix(RECORDS_TAG_PREFIX)?.split_once('-')?;
    let (task_hash, build) = match rest.split_once('-') {
        Some((task_hash, build)) => {
            let (run_id, run_attempt) = build.split_once('-')?;
            if !is_decimal(run_id) || !is_decimal(run_attempt) {
                return None;
            }
            let build = BuildRun {
                run_id: run_id.parse().ok()?,
                run_attempt: run_attempt.parse().ok()?,
            };
            (task_hash, Some(build))
        }
        None => (rest, None),
    };
    (!rustc_version.is_empty()
        && task_hash.len() == 64
        && task_hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some(RecordsTag {
        rustc_version,
        task_hash,
        build,
    })
}

/// Whether `tag` names a records artifact — the tag-space selector the
/// admin export lists and pulls.
#[must_use]
pub fn is_records_tag(tag: &str) -> bool {
    tag.starts_with(RECORDS_TAG_PREFIX)
}

/// The failure a `success`-concluded build earns when its records
/// artifact is not in GHCR.
///
/// The claim is not the record, so a task is done only once the
/// artifact exists (stow#655). The webhook's per-task path and a
/// batch leg's resolution report the wording verbatim (stow#833 §4.1).
#[must_use]
pub fn missing_records_error(task_id: &str) -> String {
    format!("GitHub reports success but the records artifact for task {task_id} is not in GHCR")
}

/// One record as one index row. A record always carries its pushed
/// bundle's digest — the publish writes it — so every record maps.
#[must_use]
pub fn record_to_index_row(record: &ArtifactRecord) -> ArtifactIndexRow {
    ArtifactIndexRow {
        crate_name: record.crate_name.clone(),
        version: record.version.clone(),
        features_json: record.features_json.clone(),
        dependency_c_metadata_json: record.dependency_c_metadata_json.clone(),
        dependency_identity: record.dependency_identity.clone(),
        c_metadata: record.c_metadata.clone(),
        compile_key: record.compile_key.clone(),
        bundle_digest: record.bundle_digest.clone(),
        bundle_size: record.bundle_size,
        artifact_kind: record.artifact_kind.clone(),
        crate_types: record.crate_types.clone(),
        profile: record.profile.clone(),
        emit: record.emit.clone(),
        min_glibc: record.min_glibc,
        unit_shape: record.unit_shape,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_title_round_trips() {
        assert_eq!(run_title("1.99.0", "abc123"), "1.99.0-abc123");
        assert_eq!(parse_run_title("1.99.0-abc123"), Some(("1.99.0", "abc123")));
        assert_eq!(
            parse_run_title("1.99.0-a-task-id-with-dashes"),
            Some(("1.99.0", "a-task-id-with-dashes"))
        );
        assert_eq!(parse_run_title("nodash"), None);
        assert_eq!(parse_run_title("-missingrustc"), None);
        assert_eq!(parse_run_title("1.99.0-"), None);
    }

    #[test]
    fn batch_run_title_round_trips() {
        let batch_id: BatchId = "0123456789abcdef0123456789abcdef"
            .parse()
            .expect("batch id");
        assert_eq!(
            batch_run_title("1.99.0", &batch_id),
            "1.99.0-b0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            parse_batch_run_title("1.99.0-b0123456789abcdef0123456789abcdef"),
            Some(("1.99.0", batch_id))
        );
    }

    /// A batch title parses only as `<rustc>-b<32 lowercase hex>` — a
    /// `build-crate.yml` task title, a resolve title, a short or long
    /// or mis-cased batch id, or a trailing suffix are all refused.
    #[test]
    fn parse_batch_run_title_refuses_malformed_titles() {
        for title in [
            // Not a `<rustc>-<id>` split at all.
            "nodash",
            "1.99.0-",
            "-b0123456789abcdef0123456789abcdef",
            // The `b` marker missing.
            "1.99.0-0123456789abcdef0123456789abcdef",
            // Wrong length.
            "1.99.0-b0123456789abcdef0123456789abcde",
            "1.99.0-b0123456789abcdef0123456789abcdef0",
            // Uppercase hex and non-hex characters.
            "1.99.0-b0123456789ABCDEF0123456789abcdef",
            "1.99.0-b0123456789abcdef0123456789abcdeg",
            // A trailing suffix is not part of the id.
            "1.99.0-b0123456789abcdef0123456789abcdef-extra",
            // A task run title and a resolve run title.
            "1.99.0-serde-1.0.0-deadbeef-x86_64_unknown-linux-gnu-1_99_0",
            "resolve-a1-req-serde-1.0.0",
        ] {
            assert_eq!(parse_batch_run_title(title), None, "{title}");
        }
        // `run_title` output never parses as a batch title.
        assert_eq!(
            parse_batch_run_title(&run_title("1.99.0", "some-task-id")),
            None
        );
    }

    const BUILD: BuildRun = BuildRun {
        run_id: 9,
        run_attempt: 1,
    };

    #[test]
    fn records_tag_round_trips() {
        let tag = records_tag("1.99.0", "serde-1.0.0-abc", BUILD);
        assert!(is_records_tag(&tag));
        let parsed = parse_records_tag(&tag).expect("per-build tag parses");
        assert_eq!(parsed.rustc_version, "1.99.0");
        assert_eq!(
            parsed.task_hash,
            blake3::hash(b"serde-1.0.0-abc").to_hex().as_str()
        );
        assert_eq!(parsed.build, Some(BUILD));
    }

    /// A tag parses only as one of the two shapes a records artifact
    /// was ever published under: a malformed build suffix or task hash
    /// is not a records tag, never a tag with part of its name ignored.
    #[test]
    fn parse_records_tag_refuses_malformed_tags() {
        let digest = blake3::hash(b"serde-1.0.0-abc").to_hex();
        for tag in [
            // A non-numeric run id.
            format!("records-1.99.0-{digest}-abc-1"),
            // A missing run attempt.
            format!("records-1.99.0-{digest}-9"),
            // A signed or empty field is not a decimal.
            format!("records-1.99.0-{digest}-+9-1"),
            format!("records-1.99.0-{digest}--1"),
            // A wrong-length task hash, with and without a build.
            "records-1.99.0-deadbeef-9-1".to_owned(),
            "records-1.99.0-deadbeef".to_owned(),
            // Not ours at all.
            "index.x86_64-unknown-linux-gnu.1.91.1".to_owned(),
            "records-1.99.0-serde-1.0.0-abc".to_owned(),
        ] {
            assert_eq!(parse_records_tag(&tag), None, "{tag}");
        }
    }

    /// The suffix-less tags in the registry still parse, as a build
    /// older than every named build of the same task.
    #[test]
    fn a_tag_without_a_build_is_its_tasks_oldest() {
        let digest = blake3::hash(b"serde-1.0.0-abc").to_hex();
        let tag = format!("records-1.99.0-{digest}");
        let unnamed = parse_records_tag(&tag).expect("suffix-less tag parses");
        assert_eq!(unnamed.rustc_version, "1.99.0");
        assert_eq!(unnamed.task_hash, digest.as_str());
        assert_eq!(unnamed.build, None);
        let first = BuildRun {
            run_id: 0,
            run_attempt: 0,
        };
        assert!(unnamed.build < Some(first));
    }

    /// `BuildRun` orders numerically on run id, then attempt — a
    /// run-9 build folds before a run-10 build regardless of how the
    /// tag strings would sort.
    #[test]
    fn build_run_orders_numerically() {
        let run9 = BuildRun {
            run_id: 9,
            run_attempt: 1,
        };
        let run10 = BuildRun {
            run_id: 10,
            run_attempt: 1,
        };
        assert!(run9 < run10, "run id 9 sorts before run id 10");
        assert!(
            BuildRun {
                run_id: 9,
                run_attempt: 2
            } < run10,
            "attempt orders within one run id"
        );
    }

    /// The gate mock-e2e ran into: a real task id — `<crate>-<version>
    /// with prerelease>-<features>-<target>-<rustc>` — blows past OCI's
    /// 128-character tag limit at a 64-character crate name, so the tag
    /// carries the task id's blake3 and stays legal by construction.
    /// The webhook computes the same tag off the run's `display_title`
    /// and run identity, which is exactly what `push_records` signed
    /// the artifact under.
    #[test]
    fn a_long_task_id_still_produces_a_legal_tag() {
        let task_id = format!(
            "{}-{}-{}-{}-{}",
            "x".repeat(64),
            "1.0.0-alpha.1+build.metadata",
            "deadbeefcafe",
            "x86_64-unknown-linux-gnu",
            "1.99.0"
        );
        assert!(task_id.len() > MAX_OCI_TAG_LEN - "records-".len());
        let tag = records_tag("1.99.0", &task_id, BUILD);
        assert!(tag.len() <= MAX_OCI_TAG_LEN, "tag {tag:?} overflows");
        assert_eq!(
            parse_records_tag(&tag).map(|parsed| parsed.rustc_version),
            Some("1.99.0")
        );
        // The webhook path: parse the run title, hash the task id.
        let title = run_title("1.99.0", &task_id);
        let (title_rustc, title_task_id) = parse_run_title(&title).expect("run title");
        assert_eq!(records_tag(title_rustc, title_task_id, BUILD), tag);
    }

    #[test]
    fn is_records_tag_matches_only_the_prefix() {
        assert!(is_records_tag("records-anything"));
        assert!(!is_records_tag("index.x86_64-unknown-linux-gnu.1.91.1"));
        assert!(!is_records_tag("serde.1.0.0.bundle"));
    }
}

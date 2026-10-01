//! The per-task artifact records as a signed OCI artifact (stow#455).
//!
//! The trusted publish stage pushes each task's `Vec<ArtifactRecord>` as
//! one signed artifact — the `records-<rustc>-<task_id hash>` tag in the
//! same `water-rs/stow-cache` namespace the bundles use — instead of
//! posting records to the edge. The index export and the D1 catalog sync both
//! read that artifact back from GHCR, so the registry plus cosign is the
//! only record store and no `STOW_EDGE_URL` reaches `build-crate.yml`.

use std::collections::BTreeMap;

use crate::api::ArtifactRecord;
use crate::identity::{TargetTriple, WireRustcVersion};
use crate::index::ArtifactIndexRow;
use crate::public_cache::UnitShape;
use crate::registry::MAX_OCI_TAG_LEN;

/// `artifactType` (and single-layer media type) of a records artifact: a
/// JSON array of [`ArtifactRecord`] — the full set of rows one
/// `build-crate.yml` task published.
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

/// Tag prefix a records artifact publishes under: `records-<rustc>-<task_id hash>`.
///
/// The leading `records-` keeps the tag namespace disjoint from bundle
/// and index tags, and starts with a letter so it always satisfies the
/// OCI tag grammar. The embedded rustc lets an export pass select its
/// records by tag alone.
pub const RECORDS_TAG_PREFIX: &str = "records-";

/// The OCI tag of `task_id`'s records artifact at `rustc_version`.
///
/// A task id is the full `<crate>-<version>-<features>-<target>-<rustc>`
/// string — well past OCI's tag limit at long crate names — so the tag
/// carries its blake3 hash instead: `records-<rustc>-<task_id hash>` is
/// 8 + ≤10 + 1 + 64 characters, always under [`MAX_OCI_TAG_LEN`]. The
/// full task id rides on the manifest's
/// [`RECORDS_TASK_ID_ANNOTATION`].
///
/// # Panics
///
/// When the produced tag exceeds [`MAX_OCI_TAG_LEN`].
#[must_use]
pub fn records_tag(rustc_version: &str, task_id: &str) -> String {
    let digest = blake3::hash(task_id.as_bytes()).to_hex();
    let tag = format!("{RECORDS_TAG_PREFIX}{rustc_version}-{digest}");
    assert!(
        tag.len() <= MAX_OCI_TAG_LEN,
        "records tag {tag:?} exceeds {MAX_OCI_TAG_LEN} chars"
    );
    tag
}

/// The rustc version a `records-*` tag selects.
///
/// `None` when the tag is not one of ours (wrong digest shape or missing
/// prefix). The task id the tag names is the blake3 the digest hashes,
/// so it can never be read back out; a caller needing it takes the
/// manifest's [`RECORDS_TASK_ID_ANNOTATION`].
#[must_use]
pub fn records_tag_rustc(tag: &str) -> Option<&str> {
    let (rustc_version, digest) = tag.strip_prefix(RECORDS_TAG_PREFIX)?.split_once('-')?;
    (!rustc_version.is_empty()
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some(rustc_version)
}

/// Whether `tag` names a records artifact — the tag-space selector the
/// admin export lists and pulls.
#[must_use]
pub fn is_records_tag(tag: &str) -> bool {
    tag.starts_with(RECORDS_TAG_PREFIX)
}

/// One record as one index row, or `None` when the record carries no
/// pushed bundle — an unbundled row is not servable and never enters the
/// index.
#[must_use]
pub fn record_to_index_row(record: &ArtifactRecord) -> Option<ArtifactIndexRow> {
    if record.bundle_digest.is_empty() {
        return None;
    }
    Some(ArtifactIndexRow {
        crate_name: record.crate_name.clone(),
        version: record.version.clone(),
        features_json: record.features_json.clone(),
        dependency_c_metadata_json: record.dependency_c_metadata_json.clone(),
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
    })
}

type RowsByIdentity = BTreeMap<(String, Option<UnitShape>), ArtifactIndexRow>;

/// Group records into `(target, rustc_version)` slices of index rows,
/// ordered by `c_metadata` — the shape `index export` writes and the D1
/// catalog's `SELECT … ORDER BY c_metadata` produces.
///
/// A `(c_metadata, unit_shape)` pair carried by more than one records
/// artifact (a re-run task that rebuilt the same unit) collapses to the
/// record later in iteration order; feed records in tag order to keep
/// the outcome deterministic. The same `c_metadata` under a second
/// `unit_shape` is not a duplicate: one artifact serves every shape a
/// real consumer's build computes it under, so each shape keeps its
/// row (stow#506).
#[must_use]
pub fn records_into_slices(
    records: impl IntoIterator<Item = ArtifactRecord>,
) -> BTreeMap<(TargetTriple, WireRustcVersion), Vec<ArtifactIndexRow>> {
    let mut slices: BTreeMap<(TargetTriple, WireRustcVersion), RowsByIdentity> = BTreeMap::new();
    for record in records {
        let Some(row) = record_to_index_row(&record) else {
            continue;
        };
        slices
            .entry((record.target, record.rustc_version))
            .or_default()
            .insert((row.c_metadata.as_str().to_owned(), row.unit_shape), row);
    }
    slices
        .into_iter()
        .map(|(key, rows)| (key, rows.into_values().collect()))
        .collect()
}

#[cfg(test)]
mod tests {
    use semver::Version;

    use super::*;
    use crate::artifact::{ArtifactKind, RustCrateType};
    use crate::identity::{
        CMetadata, CrateName, CrateVersion, DependencyCMetadataJson, FeaturesJson,
    };
    use crate::platform::{PanicStrategy, Profile, StripLevel};

    fn record(target: &str, rustc: &str, c_metadata: &str, bundle_digest: &str) -> ArtifactRecord {
        ArtifactRecord {
            compile_key: format!("{c_metadata}{c_metadata}"),
            c_metadata: CMetadata::parse(c_metadata).expect("c_metadata"),
            extra_filename: String::new(),
            target: TargetTriple::parse(target).expect("target"),
            rustc_version: WireRustcVersion::parse(rustc).expect("rustc"),
            profile: Profile {
                opt_level: "3".to_owned(),
                debuginfo: 0,
                debug_assertions: false,
                overflow_checks: false,
                panic: PanicStrategy::Unwind,
                strip: StripLevel::None,
            },
            emit: vec!["link".to_owned()],
            crate_name: CrateName::parse("serde").expect("crate name"),
            version: CrateVersion::new(Version::new(1, 0, 219)),
            features_json: FeaturesJson::canonicalize(vec![]).expect("features"),
            dependency_c_metadata_json: DependencyCMetadataJson::default(),
            oci_reference: "ghcr.io/water-rs/stow-cache:serde.1.0.219-x86_64-unknown-linux-gnu"
                .to_owned(),
            oci_digest: "sha256:deadbeef".to_owned(),
            has_native: false,
            artifact_kind: ArtifactKind::Rlib,
            crate_types: vec![RustCrateType::Rlib],
            artifact_size: 10,
            bundle_digest: bundle_digest.to_owned(),
            bundle_size: 100,
            compile_millis: 5,
            unit_shape: None,
            min_glibc: None,
        }
    }

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
    fn records_tag_stays_legal() {
        let tag = records_tag("1.99.0", "serde-1.0.0-abc");
        assert!(is_records_tag(&tag));
        assert_eq!(records_tag_rustc(&tag), Some("1.99.0"));
        assert_eq!(
            records_tag_rustc("index.x86_64-unknown-linux-gnu.1.91.1"),
            None
        );
        // An unhashed task id in the tag's tail is not our format.
        assert_eq!(records_tag_rustc("records-1.99.0-serde-1.0.0-abc"), None);
    }

    /// The gate mock-e2e ran into: a real task id — `<crate>-<version>
    /// with prerelease>-<features>-<target>-<rustc>` — blows past OCI's
    /// 128-character tag limit at a 64-character crate name, so the tag
    /// carries the task id's blake3 and stays legal by construction.
    /// The webhook computes the same tag off the run's `display_title`,
    /// which is exactly what `push_records` signed the artifact under.
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
        let tag = records_tag("1.99.0", &task_id);
        assert!(tag.len() <= MAX_OCI_TAG_LEN, "tag {tag:?} overflows");
        assert_eq!(records_tag_rustc(&tag), Some("1.99.0"));
        // The webhook path: parse the run title, hash the task id.
        let title = run_title("1.99.0", &task_id);
        let (title_rustc, title_task_id) = parse_run_title(&title).expect("run title");
        assert_eq!(records_tag(title_rustc, title_task_id), tag);
    }

    #[test]
    fn is_records_tag_matches_only_the_prefix() {
        assert!(is_records_tag("records-anything"));
        assert!(!is_records_tag("index.x86_64-unknown-linux-gnu.1.91.1"));
        assert!(!is_records_tag("serde.1.0.0.bundle"));
    }

    #[test]
    fn slices_group_sort_and_drop_unbundled() {
        let records = vec![
            record("x86_64-unknown-linux-gnu", "1.98.1", "bbbb", "sha256:b"),
            record("aarch64-apple-darwin", "1.98.1", "cccc", "sha256:c"),
            record("x86_64-unknown-linux-gnu", "1.98.1", "aaaa", "sha256:a"),
            record("x86_64-unknown-linux-gnu", "1.98.1", "dddd", ""),
        ];
        let slices = records_into_slices(records);
        assert_eq!(slices.len(), 2);
        let linux = slices
            .get(&(
                TargetTriple::parse("x86_64-unknown-linux-gnu").expect("t"),
                WireRustcVersion::parse("1.98.1").expect("r"),
            ))
            .expect("linux slice");
        assert_eq!(linux.len(), 2);
        assert_eq!(linux[0].c_metadata.as_str(), "aaaa");
        assert_eq!(linux[1].c_metadata.as_str(), "bbbb");
    }

    #[test]
    fn duplicate_c_metadata_collapses_to_the_later_record() {
        let mut first = record("x86_64-unknown-linux-gnu", "1.98.1", "aa11", "sha256:1");
        first.bundle_size = 1;
        let mut second = record("x86_64-unknown-linux-gnu", "1.98.1", "aa11", "sha256:2");
        second.bundle_size = 2;
        let slices = records_into_slices(vec![first, second]);
        let rows = slices.values().next().expect("slice");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bundle_size, 2);
    }
}

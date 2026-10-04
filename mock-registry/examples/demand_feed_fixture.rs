//! stow#523 mock-e2e fixture generator.
//!
//! Writes, under the output directory given as the first argument:
//!   enqueue.json
//!       Vec<EnqueueRequest>: 5 unpublished base deps plus 520 consumers
//!       that share them (round-robin DAG closures), with feature,
//!       target, rustc and host-side variation — ordinary node
//!       identities the authenticated `tasks/submit` route accepts.
//!       Because the base deps are never published, every consumer's
//!       `deps_met` stays 0 and nothing in the fixture can dispatch.
//!   hours/YYYY-MM-DDTHH.json
//!       Analytics Engine `FORMAT JSON` provider documents, verbatim
//!       file bodies the mock registry serves per queried hour.
//!   pages/<hour>-page-<n>.json / <hour>-complete.json
//!       Typed `DemandFeedPageRequest`/`DemandFeedCompleteRequest`
//!       bodies for the direct-route freeze legs, built through the
//!       shared `DemandFeedPageBuilder` + `demand_feed_page_hash` +
//!       `demand_feed_manifest` serializers (generation is the fixed
//!       placeholder the harness patches to the real `begin` answer).
//!   boundary/under-page.json / boundary/over-page.json
//!       Page requests whose wire envelope sits just below and just
//!       above `DEMAND_FEED_PAGE_MAX_BYTES`.
//!
//! Every wire body is produced by the same `stow_types` serializers
//! and hash helpers the shipping path uses — nothing is concatenated
//! by hand.

use std::path::PathBuf;

use stow_types::api::{
    DemandFeedCompleteRequest, DemandFeedHour, DemandFeedPageBuilder, DemandFeedPageRequest,
    EnqueueDependency, EnqueueRequest, EnqueueSource, SchedulerDemandEntry, demand_feed_manifest,
    demand_feed_page_hash,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};

/// The fixed placeholder generation inside emitted wire bodies — the
/// harness substitutes the real `begin` answer before POSTing.
const GEN_PLACEHOLDER: i64 = 7;

/// Five shared base dependencies + 520 consumer identities.
const BASE_DEPS: usize = 5;
const CONSUMERS: usize = 520;

const TARGET: &str = "x86_64-unknown-linux-gnu";
const ALT_TARGET: &str = "aarch64-apple-darwin";
const RUSTC: &str = "1.85.0";
const ALT_RUSTC: &str = "1.86.0";

fn crate_name(name: &str) -> CrateName {
    serde_json::from_value(serde_json::json!(name)).expect("crate name")
}
fn crate_version(version: &str) -> CrateVersion {
    serde_json::from_value(serde_json::json!(version)).expect("version")
}
fn target(triple: &str) -> TargetTriple {
    serde_json::from_value(serde_json::json!(triple)).expect("target")
}
fn rustc(version: &str) -> WireRustcVersion {
    serde_json::from_value(serde_json::json!(version)).expect("rustc")
}

/// One node's identity as both an [`EnqueueRequest`] row and the
/// matching [`SchedulerDemandEntry`] the provider document carries.
fn identity(
    n: usize,
) -> (
    String,
    String,
    Vec<String>,
    &'static str,
    &'static str,
    bool,
) {
    (
        format!("fixture-node-{n:04}"),
        format!("1.{}.0", n % 9),
        match n % 4 {
            0 => vec![],
            1 => vec!["default".to_owned()],
            2 => vec!["serde".to_owned(), "derive-extra".to_owned()],
            _ => vec![format!("feat-{n:04}")],
        },
        if n % 11 == 10 { ALT_TARGET } else { TARGET },
        if n % 7 == 6 { ALT_RUSTC } else { RUSTC },
        n.is_multiple_of(5),
    )
}

fn enqueue_request(n: usize) -> EnqueueRequest {
    let (name, version, feats, triple, version_rustc, host_side) = identity(n);
    // Every consumer waits on one shared unpublished base dep — the
    // dependency row is the legitimate "never dispatch" configuration:
    // `deps_met` stays 0 until that dep publishes, and it never does
    // inside the harness.
    let dep_index = n % BASE_DEPS;
    EnqueueRequest {
        crate_name: crate_name(&name),
        version: crate_version(&version),
        features_json: FeaturesJson::canonicalize(feats).expect("features"),
        target: target(triple),
        rustc_version: rustc(version_rustc),
        downloads: 1_000_000 - u64::try_from(n).unwrap_or(0),
        source: EnqueueSource::CacheMiss,
        depends_on: vec![EnqueueDependency {
            crate_name: crate_name(&format!("fixture-dep-{dep_index:02}")),
            version: crate_version("1.0.0"),
            features_json: FeaturesJson::default(),
            target: target(triple),
            rustc_version: rustc(version_rustc),
            host_side,
        }],
        host_side,
        preserve_lockfile: false,
    }
}

fn base_dep_request(dep: usize) -> EnqueueRequest {
    EnqueueRequest {
        crate_name: crate_name(&format!("fixture-dep-{dep:02}")),
        version: crate_version("1.0.0"),
        features_json: FeaturesJson::default(),
        target: target(TARGET),
        rustc_version: rustc(RUSTC),
        downloads: 2_000_000 - u64::try_from(dep).unwrap_or(0),
        source: EnqueueSource::CacheMiss,
        depends_on: vec![],
        host_side: false,
        preserve_lockfile: false,
    }
}

fn demand_entry(n: usize) -> SchedulerDemandEntry {
    let (name, version, feats, triple, version_rustc, _) = identity(n);
    SchedulerDemandEntry {
        crate_name: crate_name(&name),
        version: crate_version(&version),
        features_json: FeaturesJson::canonicalize(feats).expect("features"),
        target: target(triple),
        rustc_version: rustc(version_rustc),
        demand: u64::try_from(n % 7 + 1).unwrap_or(1),
    }
}

/// Analytics Engine's legacy `FORMAT JSON` document over the six
/// columns the materializer's meta contract names.
fn provider_document(entries: &[SchedulerDemandEntry]) -> serde_json::Value {
    let data: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "crate_name": entry.crate_name,
                "version": entry.version,
                "features_json": entry.features_json,
                "target": entry.target,
                "rustc_version": entry.rustc_version,
                "demand": entry.demand,
            })
        })
        .collect();
    serde_json::json!({
        "meta": [
            {"name": "crate_name", "type": "String"},
            {"name": "version", "type": "String"},
            {"name": "features_json", "type": "String"},
            {"name": "target", "type": "String"},
            {"name": "rustc_version", "type": "String"},
            {"name": "demand", "type": "Float64"}
        ],
        "data": data,
        "rows": data.len()
    })
}

/// One freeze leg's wire bodies: the staged pages plus the complete
/// manifest request, all through the shared builder/hash helpers.
fn freeze_bodies(
    hour: &str,
    entries: &[SchedulerDemandEntry],
) -> (Vec<DemandFeedPageRequest>, DemandFeedCompleteRequest) {
    let hour = DemandFeedHour::parse(hour).expect("fixture hour");
    let mut builder =
        DemandFeedPageBuilder::new(hour.clone(), GEN_PLACEHOLDER).expect("builder opens");
    let mut pages: Vec<DemandFeedPageRequest> = Vec::new();
    for entry in entries {
        if let Some(page) = builder.push(entry.clone()).expect("entry fits") {
            pages.push(page);
        }
    }
    if let Some(page) = builder.finish_page().expect("last page") {
        pages.push(page);
    }
    let hashes: Vec<blake3::Hash> = pages
        .iter()
        .map(|page| demand_feed_page_hash(&page.entries).expect("page hash"))
        .collect();
    let entry_count: u64 = pages
        .iter()
        .map(|page| u64::try_from(page.entries.len()).unwrap_or(0))
        .sum();
    let complete = DemandFeedCompleteRequest {
        hour,
        generation: GEN_PLACEHOLDER,
        page_count: u32::try_from(pages.len()).expect("page count"),
        entry_count,
        manifest_hash: demand_feed_manifest(&hashes)
            .map(|hash| hash.to_hex().to_string())
            .unwrap_or_default(),
    };
    (pages, complete)
}

/// A page request padded to a target envelope size with a single
/// long-but-valid feature name — real serializer, real bytes.
fn boundary_page(hour: &str, feature_count: usize) -> serde_json::Value {
    let hour = DemandFeedHour::parse(hour).expect("boundary hour");
    // Long but valid feature names (<=128 chars) — the envelope bound
    // is measured on the serialized request, never on hand-built text.
    let features: Vec<String> = (0..feature_count)
        .map(|index| format!("f{index:05}-{}", "x".repeat(110)))
        .collect();
    let entry = SchedulerDemandEntry {
        crate_name: crate_name("fixture-boundary"),
        version: crate_version("1.0.0"),
        features_json: FeaturesJson::canonicalize(features).expect("features"),
        target: target(TARGET),
        rustc_version: rustc(RUSTC),
        demand: 1,
    };
    let request = DemandFeedPageRequest {
        hour,
        generation: GEN_PLACEHOLDER,
        page_no: 0,
        entries: vec![entry],
    };
    serde_json::to_value(&request).expect("page body")
}

fn write_json(path: &std::path::Path, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec_pretty(value).expect("json"))
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("demand-fixtures"));
    let hours = out.join("hours");
    let pages_dir = out.join("pages");
    let boundary = out.join("boundary");
    std::fs::create_dir_all(&hours).expect("hours dir");
    std::fs::create_dir_all(&pages_dir).expect("pages dir");
    std::fs::create_dir_all(&boundary).expect("boundary dir");

    // Ordinary node identities: the 5 never-published base deps plus
    // 520 consumers waiting on them.
    let mut enqueues: Vec<EnqueueRequest> = (0..BASE_DEPS).map(base_dep_request).collect();
    enqueues.extend((0..CONSUMERS).map(enqueue_request));
    write_json(
        &out.join("enqueue.json"),
        &serde_json::to_value(&enqueues).expect("enqueue bodies"),
    );

    // Provider documents for the CLI-materialize legs: T01 carries
    // every fixture consumer (the 520-row multi-page hour), T02 a
    // small document, T03/T07/T08 empty hours, T06 the canonical
    // failure-then-retry document (the harness derives truncated and
    // late-invalid variants from this valid one), T09 the recovered
    // provider answer after a missing file.
    let consumers: Vec<SchedulerDemandEntry> = (0..CONSUMERS).map(demand_entry).collect();
    write_json(
        &hours.join("2020-01-01T01.json"),
        &provider_document(&consumers),
    );
    write_json(
        &hours.join("2020-01-01T02.json"),
        &provider_document(&consumers[..10]),
    );
    write_json(
        &hours.join("2020-01-01T05.json"),
        &provider_document(&consumers[100..200]),
    );
    for empty in ["2020-01-01T03", "2020-01-01T07", "2020-01-01T08"] {
        write_json(
            &hours.join(format!("{empty}.json")),
            &provider_document(&[]),
        );
    }
    write_json(
        &hours.join("2020-01-01T06-valid.json"),
        &provider_document(&consumers[..600 - 80]),
    );
    write_json(
        &hours.join("2020-01-01T09.json"),
        &provider_document(&consumers[..20]),
    );

    // Direct-route freeze legs: T00 (one small page, delivers to set
    // the watermark), T04 (three pages, the bootstrap frozen future),
    // T10 (three pages, the lost-ACK resume hour). The harness patches
    // GEN_PLACEHOLDER to each `begin` answer's generation.
    let three_page: Vec<SchedulerDemandEntry> = consumers[..CONSUMERS]
        .iter()
        .chain(consumers[..10].iter())
        .cloned()
        .collect();
    for (hour, entries) in [
        ("2020-01-01T00", consumers[..5].to_vec()),
        ("2020-01-01T04", three_page.clone()),
        ("2020-01-01T10", three_page.clone()),
    ] {
        let entries: &[SchedulerDemandEntry] = &entries;
        let (pages, complete) = freeze_bodies(hour, entries);
        for (index, page) in pages.iter().enumerate() {
            write_json(
                &pages_dir.join(format!("{hour}-page-{index}.json")),
                &serde_json::to_value(page).expect("page body"),
            );
        }
        write_json(
            &pages_dir.join(format!("{hour}-complete.json")),
            &serde_json::to_value(&complete).expect("complete body"),
        );
    }

    // Whole-envelope boundary: one request just under the 512KiB cap
    // (must stage), one just over (must refuse before any write).
    write_json(
        &boundary.join("under-page.json"),
        &boundary_page("2020-01-01T05", 4_200),
    );
    write_json(
        &boundary.join("over-page.json"),
        &boundary_page("2020-01-01T05", 4_700),
    );

    println!("demand feed fixtures written under {}", out.display());
}

//! stow#523 mock-e2e fixture generator.
//!
//! Writes, under the output directory given as the first argument:
//!   enqueue.json
//!       Vec<EnqueueRequest>: every distinct base dep the consumers
//!       actually reference (one per realized (target, rustc,
//!       host-side) combination) plus 520 consumers sharing them as a
//!       real DAG. Every base itself waits on a `fixture-anchor-*`
//!       identity that is never enqueued — a legitimate unresolved
//!       dependency, so every base and consumer holds `deps_met`=0 and
//!       nothing in the fixture can dispatch under the ordinary gate.
//!   expectations.json
//!       Per submitted task: `{task_id, crate_name, expected_delta}` —
//!       the demand delta each queue row must show after every
//!       delivered document and page, computed from the same entry
//!       schedule the documents carry (each entry touches its named
//!       node plus that node's unmet dependency chain).
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
    DEMAND_FEED_BATCH_PREFIX, DemandFeedCompleteRequest, DemandFeedHour, DemandFeedPageBuilder,
    DemandFeedPageRequest, EnqueueRequest, EnqueueSource, QueueSelector, SchedulerDemandEntry,
    SchedulerDemandRequest, demand_feed_manifest, demand_feed_page_hash,
};
use stow_types::identity::{CrateName, CrateVersion, FeaturesJson, TargetTriple, WireRustcVersion};

/// The fixed placeholder generation inside emitted wire bodies — the
/// harness substitutes the real `begin` answer before POSTing.
const GEN_PLACEHOLDER: i64 = 7;

/// The (target, rustc, host-side) tuple one base dep is keyed by —
/// every distinct combination the consumers actually reference gets
/// its own enqueued base row.
type DepCombo = (&'static str, &'static str, bool);

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

/// The dep combos consumers realize, in a deterministic order.
fn base_combos() -> Vec<DepCombo> {
    let mut combos: Vec<DepCombo> = (0..CONSUMERS)
        .map(|n| {
            let (_, _, _, triple, version_rustc, host_side) = identity(n);
            (triple, version_rustc, host_side)
        })
        .collect();
    combos.sort();
    combos.dedup();
    combos
}

fn base_name(combo_index: usize) -> String {
    format!("fixture-dep-{combo_index:02}")
}

fn anchor_name(combo_index: usize) -> String {
    format!("fixture-anchor-{combo_index:02}")
}

/// One consumer's queue task key — the id its own `EnqueueRequest`
/// derives from the subgraph it carries, the single task_id
/// computation every expectation/readback file shares (stow#588: the
/// id commits to the dependency digest).
fn consumer_task_id(n: usize, combos: &[DepCombo]) -> String {
    enqueue_request(n, combos)
        .task_id()
        .expect("consumer task id")
}

/// One base row's queue task key — the id its own request derives.
fn base_task_id(combo_index: usize, combo: DepCombo) -> String {
    base_dep_request(combo_index, combo)
        .task_id()
        .expect("base task id")
}

fn enqueue_request(n: usize, combos: &[DepCombo]) -> EnqueueRequest {
    let (name, version, feats, triple, version_rustc, host_side) = identity(n);
    // Every consumer waits on the base row keyed by its own (target,
    // rustc, host-side) combination — a real shared DAG where many
    // consumers collapse onto the same dep identity.
    let dep_index = combos
        .iter()
        .position(|combo| *combo == (triple, version_rustc, host_side))
        .expect("own combo is always in the base set");
    EnqueueRequest {
        crate_name: crate_name(&name),
        version: crate_version(&version),
        features_json: FeaturesJson::canonicalize(feats).expect("features"),
        target: target(triple),
        rustc_version: rustc(version_rustc),
        downloads: 1_000_000 - u64::try_from(n).expect("consumer index fits u64"),
        source: EnqueueSource::CacheMiss,
        // The subgraph must carry the base's real subtree: the edge's
        // `depends_on_task_id` commits to the dep's digest, and the
        // base row's own id digests {anchor} — an empty `deps` here
        // would mint a different dep id, miss the queue join, and the
        // demand walk would never reach the base row (stow#588).
        dependency_subgraph: stow_types::api::TaskSubgraph {
            root_deps: vec![0],
            nodes: vec![
                stow_types::api::SubgraphNode {
                    crate_name: crate_name(&base_name(dep_index)),
                    version: crate_version("1.0.0"),
                    features_json: FeaturesJson::default(),
                    host_side,
                    deps: vec![1],
                },
                stow_types::api::SubgraphNode {
                    crate_name: crate_name(&anchor_name(dep_index)),
                    version: crate_version("1.0.0"),
                    features_json: FeaturesJson::default(),
                    host_side,
                    deps: Vec::new(),
                },
            ],
        },
        host_side,
        preserve_lockfile: false,
    }
}

/// One base row: it waits on `fixture-anchor-*` — an identity that is
/// never enqueued, so the base's `deps_met` stays 0 forever under the
/// ordinary dependency gate and the whole fixture stays
/// non-dispatchable without touching any dispatch setting.
fn base_dep_request(combo_index: usize, combo: DepCombo) -> EnqueueRequest {
    let (triple, version_rustc, host_side) = combo;
    EnqueueRequest {
        crate_name: crate_name(&base_name(combo_index)),
        version: crate_version("1.0.0"),
        features_json: FeaturesJson::default(),
        target: target(triple),
        rustc_version: rustc(version_rustc),
        downloads: 2_000_000 - u64::try_from(combo_index).expect("combo index fits u64"),
        source: EnqueueSource::CacheMiss,
        dependency_subgraph: stow_types::api::TaskSubgraph {
            root_deps: vec![0],
            nodes: vec![stow_types::api::SubgraphNode {
                crate_name: crate_name(&anchor_name(combo_index)),
                version: crate_version("1.0.0"),
                features_json: FeaturesJson::default(),
                host_side,
                deps: Vec::new(),
            }],
        },
        host_side,
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
        demand: u64::try_from(n % 7 + 1).expect("demand fits u64"),
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
        .map(|page| u64::try_from(page.entries.len()).expect("entry count fits u64"))
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

/// Per-entry demand deltas over one entry schedule: each entry adds
/// its demand once to its own consumer row and once to the base row
/// its dep combo keys — the shared-closure shape of the real walk.
fn deltas_for(schedule: &[(usize, &SchedulerDemandEntry)]) -> (Vec<u64>, Vec<u64>) {
    let combos = base_combos();
    let mut consumer_delta = vec![0u64; CONSUMERS];
    let mut base_delta = vec![0u64; combos.len()];
    for (index, entry) in schedule {
        consumer_delta[*index] += entry.demand;
        let (_, _, _, triple, version_rustc, host_side) = identity(*index);
        let dep_index = combos
            .iter()
            .position(|combo| *combo == (triple, version_rustc, host_side))
            .expect("dep combo");
        base_delta[dep_index] += entry.demand;
    }
    (consumer_delta, base_delta)
}

/// `{task_id, crate_name, expected_delta}` for EVERY submitted task
/// (zero included), bases first then consumers — the same ordering
/// and task_id helpers `queue-selector-queries.json` uses.
fn expectations_json(
    combos: &[DepCombo],
    consumer_delta: &[u64],
    base_delta: &[u64],
) -> Vec<serde_json::Value> {
    let mut expectations: Vec<serde_json::Value> = Vec::new();
    for (index, combo) in combos.iter().enumerate() {
        expectations.push(serde_json::json!({
            "task_id": base_task_id(index, *combo),
            "crate_name": base_name(index),
            "expected_delta": base_delta[index],
        }));
    }
    for (n, delta) in consumer_delta.iter().enumerate() {
        let (name, ..) = identity(n);
        expectations.push(serde_json::json!({
            "task_id": consumer_task_id(n, combos),
            "crate_name": name,
            "expected_delta": delta,
        }));
    }
    expectations
}

fn main() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // stderr, never stdout: keep diagnostics off the data stream.
        .with_writer(std::io::stderr)
        .init();
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

    // Ordinary node identities: every distinct base dep the consumers
    // actually reference — each itself parked on an absent anchor —
    // plus the 520 consumers waiting on them.
    let combos = base_combos();
    let mut enqueues: Vec<EnqueueRequest> = combos
        .iter()
        .enumerate()
        .map(|(index, combo)| base_dep_request(index, *combo))
        .collect();
    enqueues.extend((0..CONSUMERS).map(|n| enqueue_request(n, &combos)));
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

    // Whole-envelope boundary: one 1-entry request just under the
    // 512KiB cap (must stage) and one just over (must refuse), plus a
    // 257-entry page the entry bound alone refuses. Compact serde
    // bodies — the DO measures the posted envelope bytes.
    for (name, features) in [("under-page.json", 4_200), ("over-page.json", 4_700)] {
        let body = boundary_page("2020-01-01T05", features);
        let bytes = serde_json::to_vec(&body).expect("boundary body");
        std::fs::write(boundary.join(name), &bytes)
            .unwrap_or_else(|error| panic!("write {name}: {error}"));
        tracing::info!(%name, bytes = bytes.len(), "boundary page written");
    }
    let under_len = std::fs::metadata(boundary.join("under-page.json"))
        .expect("under page")
        .len();
    let over_len = std::fs::metadata(boundary.join("over-page.json"))
        .expect("over page")
        .len();
    assert!(
        under_len < stow_types::api::DEMAND_FEED_PAGE_MAX_BYTES as u64
            && over_len > stow_types::api::DEMAND_FEED_PAGE_MAX_BYTES as u64,
        "boundary pages must straddle DEMAND_FEED_PAGE_MAX_BYTES: under={under_len} over={over_len}"
    );
    // One entry past DEMAND_FEED_PAGE_MAX_ENTRIES: same hour as the
    // byte pair so the harness can refuse it on the entry bound alone
    // (the serialized body is far under the byte cap).
    let over_entries = DemandFeedPageRequest {
        hour: DemandFeedHour::parse("2020-01-01T05").expect("hour"),
        generation: GEN_PLACEHOLDER,
        page_no: 1,
        entries: three_page[..257].to_vec(),
    };
    write_json(
        &boundary.join("over-entries-page.json"),
        &serde_json::to_value(&over_entries).expect("entries page"),
    );

    // The deterministic #522 replay: the same SchedulerDemandRequest
    // the first delivered T10 page derived — `demand-feed/{hour}/{no}`
    // — which the accepted batch must answer `applied=false`.
    let (t10_pages, _) = freeze_bodies("2020-01-01T10", &three_page);
    let replay = SchedulerDemandRequest {
        batch_id: format!("{DEMAND_FEED_BATCH_PREFIX}2020-01-01T10/0"),
        entries: t10_pages[0].entries.clone(),
    };
    write_json(
        &pages_dir.join("2020-01-01T10-demand-replay.json"),
        &serde_json::to_value(&replay).expect("replay body"),
    );

    // expectations.json: {task_id, crate_name, expected_delta} for
    // every submitted task. One entry's closure touches its named node
    // and that node's unmet deps — here {consumer_i, base_of_i} — so
    // each entry adds its demand to both once, and a task reached by N
    // entries (across any number of batches) sums N contributions.
    // Every count below comes from the same Vecs the files carry.
    let mut schedule: Vec<(usize, &SchedulerDemandEntry)> = Vec::new();
    let mut add = |indices: &[usize]| {
        schedule.extend(indices.iter().map(|index| (*index, &consumers[*index])));
    };
    add(&(0..5).collect::<Vec<_>>()); // T00 frozen page
    add(&(0..CONSUMERS).collect::<Vec<_>>()); // T01
    add(&(0..10).collect::<Vec<_>>()); // T02
    add(&(0..CONSUMERS).collect::<Vec<_>>()); // T04 page set
    add(&(0..10).collect::<Vec<_>>()); // T04 duplicated tail
    add(&(100..200).collect::<Vec<_>>()); // T05
    add(&(0..CONSUMERS).collect::<Vec<_>>()); // T06 retry
    add(&(0..20).collect::<Vec<_>>()); // T09 retry
    add(&(0..CONSUMERS).collect::<Vec<_>>()); // T10 page set
    add(&(0..10).collect::<Vec<_>>()); // T10 duplicated tail
    let (consumer_delta, base_delta) = deltas_for(&schedule);
    write_json(
        &out.join("expectations.json"),
        &serde_json::Value::Array(expectations_json(&combos, &consumer_delta, &base_delta)),
    );

    // t10-page0-expectations.json: the exact prefix effect the first
    // delivered T10 page applies — its entries are three_page's
    // leading slice, which the builder took from consumers[..256].
    let page0_len = t10_pages[0].entries.len();
    assert!(
        page0_len <= CONSUMERS,
        "T10 page 0 must slice the consumer prefix"
    );
    let page0_schedule: Vec<(usize, &SchedulerDemandEntry)> = (0..page0_len)
        .map(|index| (index, &consumers[index]))
        .collect();
    let (page0_consumer, page0_base) = deltas_for(&page0_schedule);
    write_json(
        &out.join("t10-page0-expectations.json"),
        &serde_json::Value::Array(expectations_json(&combos, &page0_consumer, &page0_base)),
    );

    // queue-selector-queries.json: typed QueueSelector task-id lists
    // in bounded chunks, serialized by the same serde_html_form
    // contract the real admin list reads — never hand-joined text.
    const SELECTOR_CHUNK: usize = 60;
    let task_ids: Vec<String> = combos
        .iter()
        .enumerate()
        .map(|(index, combo)| base_task_id(index, *combo))
        .chain((0..CONSUMERS).map(|n| consumer_task_id(n, &combos)))
        .collect();
    let queries: Vec<String> = task_ids
        .chunks(SELECTOR_CHUNK)
        .map(|chunk| {
            serde_html_form::to_string(&QueueSelector {
                task_ids: chunk.to_vec(),
                ..QueueSelector::default()
            })
            .expect("selector encodes")
        })
        .collect();
    write_json(
        &out.join("queue-selector-queries.json"),
        &serde_json::Value::Array(queries.into_iter().map(Into::into).collect()),
    );

    tracing::info!(dir = %out.display(), "demand feed fixtures written");
}

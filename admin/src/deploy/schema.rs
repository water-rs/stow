//! The GraphQL Analytics API field lists the deploy verdict queries.
//!
//! Introspected against the production schema on 2026-09-27 (issue #436
//! review). A query that selects a field outside these lists fails every
//! deploy — Cloudflare answers unknown fields with a GraphQL error and the
//! verdict fails closed — so the tests assert every field each query names
//! is in here.

/// `workersInvocationsAdaptive` (account scope) — one group per
/// `scriptVersion`, the dimension the canary verdict pivots on.
pub const WORKERS_SUM: &[&str] = &["errors", "requests"];
pub const WORKERS_QUANTILES: &[&str] = &[
    "cpuTimeP50",
    "cpuTimeP99",
    "memoryUsageBytesP99",
    "wallTimeP50",
    "wallTimeP99",
];
/// Confirmed members of `AccountWorkersInvocationsAdaptiveDimensions`.
pub const WORKERS_DIMENSIONS: &[&str] = &["scriptName", "scriptVersion", "status"];

/// `durableObjectsInvocationsAdaptiveGroups` — per-invocation DO metrics.
/// `scriptVersion` IS a dimension here, so phase 1 compares per version.
pub const DO_INVOCATIONS_SUM: &[&str] = &["errors", "requests", "responseBodySize", "wallTime"];
/// Confirmed members of its dimensions.
pub const DO_INVOCATIONS_DIMENSIONS: &[&str] = &["scriptVersion"];

/// `durableObjectsPeriodicGroups` — account-total DO usage. Carries no
/// `scriptVersion`, so these metrics compare the observation window against
/// the pre-deploy window outright (phase 2).
pub const DO_PERIODIC_SUM: &[&str] = &[
    "activeTime",
    "cpuTime",
    "duration",
    "exceededCpuErrors",
    "exceededMemoryErrors",
    "fatalInternalErrors",
    "inboundWebsocketMsgCount",
    "outboundWebsocketMsgCount",
    "rowsRead",
    "rowsWritten",
    "storageDeletes",
    "storageReadUnits",
    "storageWriteUnits",
    "subrequests",
];
/// `AccountDurableObjectsPeriodicGroupsDimensions`, verbatim from the
/// introspection — note the absence of `scriptVersion`. No query selects
/// dimensions from this dataset; the list is kept as the reference the
/// next field addition is checked against.
#[expect(dead_code)]
pub const DO_PERIODIC_DIMENSIONS: &[&str] = &[
    "coloCode",
    "date",
    "datetime",
    "datetimeFifteenMinutes",
    "datetimeFiveMinutes",
    "datetimeHour",
    "datetimeMinute",
    "datetimeSixHours",
    "name",
    "namespaceId",
    "objectId",
];

/// `d1AnalyticsAdaptiveGroups` — D1 usage totals (no `scriptVersion`; the
/// phase-2 window comparison again). Its dimension list was not
/// introspected, so the query selects none.
pub const D1_SUM: &[&str] = &[
    "queryBatchResponseBytes",
    "readQueries",
    "rowsRead",
    "rowsWritten",
    "writeQueries",
];

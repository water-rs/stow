//! What the whole build knows, loaded once before cargo starts.
//!
//! stow#347: every rustc invocation used to re-load inputs that cannot
//! change inside one build — the verified index slice, the circuit row,
//! the negative cache, the expanded graph, the prefetch candidates, the
//! cache policy and the local-build provenance — and every read queued
//! on the one pooled `SQLite` connection the post-compile bookkeeping
//! writes through. The supervisor owns this state: lookups answer from
//! memory, and the bookkeeping that has to run runs off the request
//! path, drained once cargo exits.
//!
//! It also replaces the environment variables the supervisor could never
//! see: `STOW_EXPANDED_GRAPH_JSON`, `STOW_PREFETCH_ARTIFACTS_JSON`,
//! `STOW_ENABLE_SEMANTIC_FALLBACK` and `STOW_DISABLE_PUBLIC_CACHE` are set
//! on the spawned cargo's environment, which the in-process supervisor
//! does not share — under `stow build` those reads silently settled to
//! their defaults. [`BuildState::prepare`] takes the same values from the
//! launch plan instead.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use stow_types::api::DependencyGraphEntry;
use stow_types::error::Context;
use stow_types::rustc::ParsedExternCrate;

use crate::config::StowConfig;
use crate::index::{self, IndexSlice};
use crate::prefetch::PrefetchArtifact;
use crate::state_db::{db_int, duration_millis, now_millis};
use crate::{provenance, stats};

/// The build's one copy of every per-invocation input.
///
/// `Debug` is manual: `StowConfig` derives it and carries an `Arc<Self>`.
impl std::fmt::Debug for BuildState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildState")
            .field("public_cache_enabled", &self.public_cache_enabled)
            .field("semantic_fallback_enabled", &self.semantic_fallback_enabled)
            .finish_non_exhaustive()
    }
}

/// The build's one copy of every per-invocation input.
pub struct BuildState {
    /// Whether the public edge is in scope for this build — the launch
    /// plan's `STOW_DISABLE_PUBLIC_CACHE` setting, seen here because the
    /// supervisor's own process environment never carries the variable.
    public_cache_enabled: bool,
    /// Whether the semantic fallback may run — the plan's
    /// `STOW_ENABLE_SEMANTIC_FALLBACK` setting, for the same reason.
    semantic_fallback_enabled: bool,
    /// The `circuit_state` row, seeded once and kept in memory. Failure
    /// and success updates land here instantly and persist on [`flush`].
    circuit: Mutex<CircuitSnapshot>,
    /// Live `negative_cache_entries` keys (`target/rustc/c_metadata`).
    negative_cache: RwLock<HashSet<String>>,
    /// Negative-cache keys recorded this build, for `flush` to persist.
    negative_cache_pending: Mutex<BTreeSet<String>>,
    /// `(target, crate_name)` pairs compiled locally this build —
    /// the in-memory form of the `local-build` provenance markers, so a
    /// dependent's plan never stats the policy directory. Markers are
    /// still written through to the directory for standalone wrappers.
    locally_built: RwLock<HashSet<(String, String)>>,
    /// `(target, crate_name)` pairs the cache policy allows — `None` when
    /// this build carries no policy directory at all, which is the same
    /// "allowed" the file probe reports for it.
    policy_allowed: Option<HashSet<(String, String)>>,
    /// `materialized_outputs` rows this build has written, read first by
    /// dependency-identity resolution. Rows it does not hold are still
    /// asked of the database — they belong to older builds.
    materialized: RwLock<HashMap<String, String>>,
    /// `(crate_name, version)` → its expanded-graph feature sets, small
    /// first — the graph the wrapper used to re-parse from
    /// `STOW_EXPANDED_GRAPH_JSON` once per invocation.
    expanded_features: Option<ExpandedFeatureMap>,
    /// Canonical crate name → prefetched `c_metadata` candidates — the
    /// `STOW_PREFETCH_ARTIFACTS_JSON` payload, parsed once.
    prefetch_candidates: BTreeMap<String, Vec<String>>,
    /// `(target, rustc_version)` → decoded index slice, resolved on first
    /// use rather than re-read and re-decoded per invocation.
    slices: tokio::sync::Mutex<SliceCacheMap>,
    /// Per-build stats buffer, flushed once at drain — the counters used
    /// to be one locked JSON read-modify-write or `SQLite` upsert each.
    stats: Mutex<StatsBuffer>,
    /// Bookkeeping work reported by facades and queued behind the
    /// request path; drained by [`drain`].
    bookkeeping_in_flight: AtomicUsize,
    bookkeeping_idle: tokio::sync::Notify,
}

#[derive(Default)]
struct CircuitSnapshot {
    consecutive_failures: u64,
    tripped_at_ms: Option<u64>,
}

/// `(crate_name, version)` → the expanded graph's feature sets for it.
type ExpandedFeatureMap = BTreeMap<(String, String), Vec<BTreeSet<String>>>;

/// `(target, rustc_version)` → the decoded index slice memo.
type SliceCacheMap = BTreeMap<(String, String), Option<Arc<IndexSlice>>>;

#[derive(Default)]
struct StatsBuffer {
    /// `crate_stats` deltas per crate: `[hits, misses, errors]`.
    crates: BTreeMap<String, [u64; 3]>,
    /// `stats.json` aggregate for served bundles.
    served_hits: u64,
    served_cpu_millis: u64,
    served_bytes: u64,
    served_bytes_downloaded: u64,
    /// `profile_divergence` events: `(cached, wanted)` → count.
    divergences: BTreeMap<(String, String), u64>,
}

impl BuildState {
    /// Load every input the per-invocation path used to read, once.
    ///
    /// `cache_policy_dir` is the plan's policy directory — read by the
    /// caller because the supervisor never sees the `STOW_CACHE_POLICY_PATH`
    /// env the facade would consult, exactly like the other plan values.
    ///
    /// Seeding failures degrade to empty state rather than failing the
    /// build: an unseeded circuit or negative cache costs retries, never
    /// correctness.
    pub async fn prepare(
        config: &StowConfig,
        expanded_entries: Option<&[DependencyGraphEntry]>,
        prefetch_artifacts: Option<&[PrefetchArtifact]>,
        public_cache_enabled: bool,
        semantic_fallback_enabled: bool,
        cache_policy_dir: Option<&std::path::Path>,
    ) -> Arc<Self> {
        let (circuit, negative_cache) = Self::seed_persisted_state(config).await;

        let expanded_features = expanded_entries.map(|entries| {
            let mut map: BTreeMap<(String, String), Vec<BTreeSet<String>>> = BTreeMap::new();
            for entry in entries {
                map.entry((
                    crate::canonical_crate_name(entry.crate_name.as_str()),
                    entry.version.to_string(),
                ))
                .or_default()
                .push(entry.features.iter().cloned().collect());
            }
            for sets in map.values_mut() {
                sets.sort_by_key(BTreeSet::len);
                sets.dedup();
            }
            map
        });

        let mut prefetch_candidates: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for row in prefetch_artifacts.unwrap_or_default() {
            prefetch_candidates
                .entry(crate::canonical_crate_name(row.crate_name.as_str()))
                .or_default()
                .push(row.c_metadata.clone());
        }

        let policy_allowed = cache_policy_dir.map(|dir| {
            let mut allowed = HashSet::new();
            let allow_root = dir.join("allow");
            if let Ok(targets) = std::fs::read_dir(&allow_root) {
                for target in targets.flatten() {
                    let Some(target_name) = target.file_name().to_str().map(str::to_owned) else {
                        continue;
                    };
                    if let Ok(crates) = std::fs::read_dir(target.path()) {
                        for krate in crates.flatten() {
                            if let Some(crate_name) = krate.file_name().to_str() {
                                allowed.insert((target_name.clone(), crate_name.to_owned()));
                            }
                        }
                    }
                }
            }
            allowed
        });

        Arc::new(Self {
            public_cache_enabled,
            semantic_fallback_enabled,
            circuit: Mutex::new(circuit),
            negative_cache: RwLock::new(negative_cache),
            negative_cache_pending: Mutex::new(BTreeSet::new()),
            locally_built: RwLock::new(HashSet::new()),
            policy_allowed,
            materialized: RwLock::new(HashMap::new()),
            expanded_features,
            prefetch_candidates,
            slices: tokio::sync::Mutex::new(SliceCacheMap::new()),
            stats: Mutex::new(StatsBuffer::default()),
            bookkeeping_in_flight: AtomicUsize::new(0),
            bookkeeping_idle: tokio::sync::Notify::new(),
        })
    }

    /// Whether the public cache is enabled for this build — the launch
    /// plan's word for the `STOW_DISABLE_PUBLIC_CACHE` marker the wrapper
    /// process would have carried.
    pub const fn public_cache_enabled(&self) -> bool {
        self.public_cache_enabled
    }

    /// Whether the semantic fallback may run — the plan's
    /// `STOW_ENABLE_SEMANTIC_FALLBACK` setting.
    pub const fn semantic_fallback_enabled(&self) -> bool {
        self.semantic_fallback_enabled
    }

    /// The breaker state: `true` while tripped inside the reset window,
    /// resetting in memory exactly as the row once did.
    pub fn circuit_tripped(&self, reset_after: std::time::Duration) -> bool {
        let mut circuit = self.circuit.lock().expect("circuit mutex");
        let Some(tripped_at_ms) = circuit.tripped_at_ms else {
            return false;
        };
        if now_millis().saturating_sub(tripped_at_ms) < duration_millis(reset_after) {
            return true;
        }
        circuit.consecutive_failures = 0;
        circuit.tripped_at_ms = None;
        false
    }

    /// One remote-cache failure against the breaker, in memory — same
    /// write the row took: a sub-threshold failure clears a stale trip.
    pub fn circuit_failed(&self, trip_threshold: u32) {
        let mut circuit = self.circuit.lock().expect("circuit mutex");
        circuit.consecutive_failures = circuit.consecutive_failures.saturating_add(1);
        circuit.tripped_at_ms =
            (circuit.consecutive_failures >= u64::from(trip_threshold)).then(now_millis);
    }

    /// A remote-cache success: the breaker resets, in memory.
    pub fn circuit_succeeded(&self) {
        let mut circuit = self.circuit.lock().expect("circuit mutex");
        circuit.consecutive_failures = 0;
        circuit.tripped_at_ms = None;
    }

    /// Whether `cache_key` is negative-cached — pure memory.
    pub fn negative_cache_contains(&self, key: &str) -> bool {
        self.negative_cache
            .read()
            .expect("negative cache lock")
            .contains(key)
    }

    /// Negative-cache `key`, in memory now and persisted at `flush`.
    pub fn record_negative_cache(&self, key: String) {
        self.negative_cache
            .write()
            .expect("negative cache lock")
            .insert(key.clone());
        self.negative_cache_pending
            .lock()
            .expect("negative cache pending lock")
            .insert(key);
    }

    /// The first extern dependency this build already compiled locally —
    /// the answer `provenance::locally_built_dependency` would give, from
    /// the in-memory mirror rather than a directory stat per extern.
    pub fn locally_built_dependency(
        &self,
        target: &str,
        extern_crates: &[ParsedExternCrate],
    ) -> Option<String> {
        let built = self.locally_built.read().expect("local build set");
        extern_crates
            .iter()
            .find(|dependency| built.contains(&(target.to_owned(), dependency.crate_name.clone())))
            .map(|dependency| dependency.crate_name.clone())
    }

    /// Record `crate_name` as locally compiled for `target`: in memory
    /// for this build's lookups, and through the queued write for the
    /// marker file standalone wrappers consult.
    pub fn mark_locally_built(self: &Arc<Self>, target: String, crate_name: String) {
        self.locally_built
            .write()
            .expect("local build set")
            .insert((target.clone(), crate_name.clone()));
        self.enqueue(async move {
            if let Err(error) = provenance::record_local_build(&target, &crate_name).await {
                tracing::warn!(error = %error, "failed to write the local-build marker");
            }
        });
    }

    /// The `c_metadata` recorded for a materialized output, if this build
    /// wrote or has seen the row.
    pub fn materialized_c_metadata(&self, output_path: &str) -> Option<String> {
        self.materialized
            .read()
            .expect("materialized outputs lock")
            .get(output_path)
            .cloned()
    }

    /// Remember a `materialized_outputs` write so the lookup never has to
    /// re-read what this build wrote.
    pub fn note_materialized(&self, output_path: String, c_metadata: String) {
        self.materialized
            .write()
            .expect("materialized outputs lock")
            .insert(output_path, c_metadata);
    }

    /// What `lookup_expanded_graph_features_json` answers, without
    /// re-parsing the env var: the smallest expanded feature set covering
    /// `parsed_features`, or the same error when two minimal sets tie.
    ///
    /// `expanded_features` is `None` exactly when the env var is unset,
    /// so the caller's fallback semantics are unchanged.
    pub fn expanded_features_json(
        &self,
        crate_name: &str,
        version: &str,
        parsed_features: &BTreeSet<String>,
    ) -> stow_types::error::Result<Option<String>> {
        let Some(map) = &self.expanded_features else {
            return Ok(None);
        };
        let key = (crate::canonical_crate_name(crate_name), version.to_owned());
        let Some(sets) = map.get(&key) else {
            return Ok(None);
        };
        let mut covering: Vec<&BTreeSet<String>> = sets
            .iter()
            .filter(|set| parsed_features.iter().all(|feature| set.contains(feature)))
            .collect();
        covering.sort_by_key(|set| set.len());
        match covering.first() {
            None => Ok(None),
            Some(best) => {
                if covering
                    .iter()
                    .filter(|set| set.len() == best.len())
                    .count()
                    > 1
                {
                    return Err(stow_types::stow_error!(
                        "expanded dependency graph contains duplicate exact feature sets for {} {}",
                        crate_name,
                        version
                    ));
                }
                let features: Vec<String> = best.iter().cloned().collect();
                serde_json::to_string(&features)
                    .wrap_err("serialize expanded graph semantic features")
                    .map(Some)
            }
        }
    }

    /// The prefetched `c_metadata` candidates for `crate_name` — the
    /// `STOW_PREFETCH_ARTIFACTS_JSON` payload, filtered once at prepare.
    pub fn prefetch_candidate_c_metadatas(&self, crate_name: &str) -> Vec<String> {
        self.prefetch_candidates
            .get(&crate::canonical_crate_name(crate_name))
            .cloned()
            .unwrap_or_default()
    }

    /// What `cache_policy::public_cache_allowed` answers: `None` when the
    /// build carries no policy directory (allowed), else whether the
    /// crate is marked allowed for `target`.
    pub fn public_cache_allowed(&self, target: Option<String>, crate_name: &str) -> Option<bool> {
        let policy = self.policy_allowed.as_ref()?;
        let target = target?;
        Some(policy.contains(&(target, crate_name.replace('-', "_"))))
    }

    /// The verified index slice for `(target, rustc_version)`, decoded
    /// once and shared by every invocation afterwards.
    ///
    /// # Errors
    ///
    /// Whatever [`index::cached_slice`] fails with — corruption is an
    /// error, absence is `Ok(None)`.
    pub async fn slice(
        &self,
        config: &StowConfig,
        target: &str,
        rustc_version: &str,
    ) -> stow_types::error::Result<Option<Arc<IndexSlice>>> {
        let key = (target.to_owned(), rustc_version.to_owned());
        {
            let slices = self.slices.lock().await;
            if let Some(slice) = slices.get(&key) {
                return Ok(slice.clone());
            }
        }
        let slice = index::load_cached_slice(config, target, rustc_version)
            .await?
            .map(Arc::new);
        // Absence is not memoized: a build whose slice fetch was still in
        // flight when it started reads the pointer the moment the
        // background refresh lands it (stow#347).
        let Some(slice) = slice else {
            return Ok(None);
        };
        let mut slices = self.slices.lock().await;
        Ok(slices
            .entry(key)
            .or_insert_with(|| Some(slice))
            .clone())
    }

    /// Buffer a `crate_stats` counter; flushed once at [`flush`].
    pub fn stats_hit(&self, crate_name: &str) {
        self.bump(crate_name, 0);
    }

    /// Buffer a `crate_stats` miss counter; flushed once at [`flush`].
    pub fn stats_miss(&self, crate_name: &str) {
        self.bump(crate_name, 1);
    }

    /// Buffer a `crate_stats` error counter; flushed once at [`flush`].
    pub fn stats_error(&self, crate_name: &str) {
        self.bump(crate_name, 2);
    }

    fn bump(&self, crate_name: &str, field: usize) {
        self.stats
            .lock()
            .expect("stats buffer lock")
            .crates
            .entry(crate_name.to_owned())
            .or_default()[field] += 1;
    }

    /// Buffer a served-bundle aggregate for `stats.json`.
    pub fn stats_served(&self, compile_millis: u64, bytes: u64, downloaded: bool) {
        let mut stats = self.stats.lock().expect("stats buffer lock");
        stats.served_hits += 1;
        stats.served_cpu_millis += compile_millis;
        stats.served_bytes += bytes;
        if downloaded {
            stats.served_bytes_downloaded += bytes;
        }
    }

    /// Buffer one profile divergence, keyed like the metadata row's value.
    pub fn stats_divergence(&self, cached: String, wanted: String) {
        *self
            .stats
            .lock()
            .expect("stats buffer lock")
            .divergences
            .entry((cached, wanted))
            .or_default() += 1;
    }

    /// Queue post-compile bookkeeping off the request path. The work is
    /// done by the time [`drain`] returns; a facade that reported and saw
    /// its ack can trust the bookkeeping is queued.
    pub fn enqueue(self: &Arc<Self>, work: impl std::future::Future<Output = ()> + Send + 'static) {
        self.bookkeeping_in_flight.fetch_add(1, Ordering::SeqCst);
        let state = Arc::clone(self);
        tokio::spawn(async move {
            work.await;
            if state.bookkeeping_in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
                state.bookkeeping_idle.notify_waiters();
            }
        });
    }

    /// Wait until every queued bookkeeping task has finished.
    pub async fn drain(&self) {
        loop {
            if self.bookkeeping_in_flight.load(Ordering::SeqCst) == 0 {
                return;
            }
            let notified = self.bookkeeping_idle.notified();
            if self.bookkeeping_in_flight.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Persist everything the buffers held: the `crate_stats` deltas, the
    /// `stats.json` aggregates, the profile divergences, the negative
    /// cache keys and the circuit row — each in one write at build end,
    /// not one per invocation.
    pub async fn flush(&self, config: &StowConfig) -> stow_types::error::Result<()> {
        let connection = config.state_db_pool().await?;
        let stats = {
            let mut guard = self.stats.lock().expect("stats buffer lock");
            std::mem::take(&mut *guard)
        };

        let mut tx = connection.begin().await?;
        for (crate_name, [hits, misses, errors]) in &stats.crates {
            sqlx::query(
                "INSERT INTO crate_stats (crate_name, hits, misses, errors) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT(crate_name) DO UPDATE SET \
                     hits = crate_stats.hits + excluded.hits, \
                     misses = crate_stats.misses + excluded.misses, \
                     errors = crate_stats.errors + excluded.errors",
            )
            .bind(crate_name)
            .bind(db_int::<_, i64>(*hits, "crate stats hits")?)
            .bind(db_int::<_, i64>(*misses, "crate stats misses")?)
            .bind(db_int::<_, i64>(*errors, "crate stats errors")?)
            .execute(&mut *tx)
            .await?;
        }
        self.flush_negative_cache(&mut tx).await?;
        self.flush_circuit(&mut tx).await?;
        // `metadata_values` holds one profile_divergence row, so the
        // buffered map folds into the single most-seen (cached, wanted)
        // pair — the same latest-write-wins semantics the per-event
        // writer had, with `seen` carried over the whole build.
        if let Some(((cached, wanted), seen)) = stats
            .divergences
            .iter()
            .max_by_key(|(_, seen)| *seen)
            .map(|(key, seen)| (key, *seen))
        {
            // Read inside this transaction: the pool hands out one
            // connection, so a helper that takes its own would wait for
            // the connection this transaction is holding.
            let previous =
                sqlx::query_as::<_, (String,)>("SELECT value FROM metadata_values WHERE key = ?")
                    .bind(stats::PROFILE_DIVERGENCE_KEY)
                    .fetch_optional(&mut *tx)
                    .await?
                    .map(|(value,)| {
                        serde_json::from_str::<stats::ProfileDivergence>(&value)
                            .wrap_err("parse the recorded profile divergence")
                    })
                    .transpose()?;
            let divergence = stats::ProfileDivergence {
                cached: cached.clone(),
                wanted: wanted.clone(),
                seen: previous.map_or(seen, |d| d.seen.saturating_add(seen)),
            };
            let value =
                serde_json::to_string(&divergence).wrap_err("serialize the profile divergence")?;
            sqlx::query(
                "INSERT INTO metadata_values (key, value) VALUES (?, ?) \
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .bind(stats::PROFILE_DIVERGENCE_KEY)
            .bind(value)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        if stats.served_hits > 0 {
            stats::add_served_totals(
                config,
                stats.served_hits,
                stats.served_cpu_millis,
                stats.served_bytes,
                stats.served_bytes_downloaded,
            )
            .await?;
        }
        Ok(())
    }

    /// The pending negative-cache keys, in one transaction's writes.
    async fn flush_negative_cache(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> stow_types::error::Result<()> {
        let pending = {
            let mut guard = self
                .negative_cache_pending
                .lock()
                .expect("negative cache pending lock");
            std::mem::take(&mut *guard)
        };
        let now_ms: i64 = db_int(now_millis(), "negative cache write time")?;
        for key in &pending {
            sqlx::query(
                "INSERT INTO negative_cache_entries (cache_key, inserted_at_ms) \
                 VALUES (?, ?) \
                 ON CONFLICT(cache_key) DO UPDATE SET inserted_at_ms = excluded.inserted_at_ms",
            )
            .bind(key)
            .bind(now_ms)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    /// The circuit snapshot, in one transaction's write. The guard's
    /// scope ends before the `await` — `std::sync::MutexGuard` is not
    /// `Send`, so it never crosses a yield point.
    async fn flush_circuit(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> stow_types::error::Result<()> {
        let (failures, tripped_at_ms) = {
            let circuit = self.circuit.lock().expect("circuit mutex");
            (circuit.consecutive_failures, circuit.tripped_at_ms)
        };
        sqlx::query(
            "INSERT INTO circuit_state (singleton, consecutive_failures, tripped_at_ms) \
             VALUES (1, ?, ?) \
             ON CONFLICT(singleton) DO UPDATE SET \
                 consecutive_failures = excluded.consecutive_failures, \
                 tripped_at_ms = excluded.tripped_at_ms",
        )
        .bind(db_int::<_, i64>(failures, "circuit failures")?)
        .bind(
            tripped_at_ms
                .map(|ms| db_int::<_, i64>(ms, "circuit tripped_at_ms"))
                .transpose()?,
        )
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// The persisted inputs `prepare` copies into memory: the circuit
    /// row and the live negative-cache keys, both reads degrading to
    /// empty on failure.
    async fn seed_persisted_state(config: &StowConfig) -> (CircuitSnapshot, HashSet<String>) {
        match config.state_db_pool().await {
            Ok(connection) => {
                let circuit = sqlx::query_as::<_, (i64, Option<i64>)>(
                    "SELECT consecutive_failures, tripped_at_ms \
                     FROM circuit_state WHERE singleton = 1",
                )
                .fetch_optional(&connection)
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(error = %error, "failed to seed the build circuit state");
                    None
                });
                let now_ms: i64 = db_int(now_millis(), "negative cache seed time").unwrap_or(0);
                let ttl_ms: i64 = db_int(
                    duration_millis(config.negative_cache_ttl),
                    "negative cache TTL",
                )
                .unwrap_or(0);
                let negative = sqlx::query_scalar::<_, String>(
                    "SELECT cache_key FROM negative_cache_entries \
                     WHERE ? - inserted_at_ms < ?",
                )
                .bind(now_ms)
                .bind(ttl_ms)
                .fetch_all(&connection)
                .await
                .unwrap_or_else(|error| {
                    tracing::warn!(error = %error, "failed to seed the build negative cache");
                    Vec::new()
                });
                (
                    circuit.map_or_else(CircuitSnapshot::default, |(failures, tripped)| {
                        CircuitSnapshot {
                            consecutive_failures: u64::try_from(failures).unwrap_or(0),
                            tripped_at_ms: tripped.and_then(|ms| u64::try_from(ms).ok()),
                        }
                    }),
                    negative.into_iter().collect(),
                )
            }
            Err(error) => {
                tracing::warn!(error = %error, "failed to connect the state db for build seeding");
                (CircuitSnapshot::default(), HashSet::new())
            }
        }
    }
}

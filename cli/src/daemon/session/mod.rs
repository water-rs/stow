//! One build's session: the state that decides its units.
//!
//! A driver opens a session with [`SessionFacts`] before it starts cargo.
//! The session answers every rustc and C/C++ wrapper of that build: it
//! holds the build's toolchain, config, serve map, allow set, in-flight
//! units and the observations that become the build's miss journal. The
//! analysis that used to run in the driver while cargo builds runs here, as
//! a task of the session.
//!
//! Facts are set only when the session opens. A request can neither change
//! them nor name another session's paths, and the session's own derived
//! state is written only by the session's tasks.

mod facts;
mod id;
mod resources;

use std::path::Path;
use std::sync::Arc;

use stow_types::error::{Context, Result};
use tracing::Instrument as _;

pub use facts::{Seed, SessionFacts};
pub use id::{SessionDir, SessionId};
pub use resources::{CacheDirHandles, Resources};

use crate::cache_policy;
use crate::config::StowConfig;
use crate::session_env::SessionEnv;
use crate::supervisor::invocation::{Refusal, VerifiedInvocation};
use crate::supervisor::protocol::InvocationEnv;
use crate::supervisor::server::{
    CONNECTION_DRAIN_BUDGET, Decision, Handler, InFlightUnits, Reports,
};
use crate::toolchain::BuildToolchain;
use crate::{
    AnalysisFacts, BuildContext, Outcome, PostCompile, ResolutionDone, UnitOutcome,
    WrapperEnvCache, artifact_cache, classify_invocation, classify_or_log, decide_rustc_invocation,
    describes_compile_unit, detect_unit_source, finish_rustc_compile, miss_journal,
    record_local_build_mark, record_unit_outcome, registry_unit_identity,
    resolve_native_target_cpu, rustc_args,
};

/// What a session reports when its build ends.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionEnd {
    /// Every request the session refused under
    /// [`crate::supervisor::invocation::RefusalPolicy::FailBuild`], in the
    /// order they arrived. The driver fails the build on any.
    pub refusals: Vec<String>,
    /// The build's miss journal was written.
    pub journal_written: bool,
}

/// A build's session.
#[derive(Debug)]
pub struct Session {
    id: SessionId,
    /// Everything the session's tasks and requests record is recorded
    /// under this span, which names the session: the daemon routes those
    /// events to the driver that owns it.
    span: tracing::Span,
    facts: Arc<SessionFacts>,
    dir: SessionDir,
    /// The bookkeeping tasks the build's reports spawned, drained when the
    /// session ends (stow#618, stow#1431).
    reports: Reports,
    /// The build-scoped wrapper environment memo: one config, rustc probe
    /// pair and cache lease for the whole build.
    env_cache: WrapperEnvCache,
    /// The build's facts as the decision path reads them.
    ctx: BuildContext,
    /// Completed by the first request that describes a real compile unit —
    /// the boundary after which the enrichment's own cargo may take the
    /// package-cache lock without holding the real cargo back (stow#608).
    resolution_done: ResolutionDone,
    observations: std::sync::Mutex<Vec<artifact_cache::ObservedUnit>>,
    refusals: std::sync::Mutex<Vec<Refusal>>,
    /// The background analysis, stopped when the build's cargo exits.
    enrichment: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Session {
    /// Open the session `facts` describe, with its directory under
    /// `sessions`. The config gets `handles` of its cache directory; the
    /// background analysis and the wrapper environment start as tasks of
    /// the session and this returns before they finish.
    ///
    /// # Errors
    ///
    /// The toolchain's files cannot be reopened, or the session directory
    /// cannot be created.
    pub(crate) async fn open(
        id: SessionId,
        facts: SessionFacts,
        handles: &CacheDirHandles,
        sessions: &Path,
    ) -> Result<Arc<Self>> {
        let span = tracing::info_span!(crate::daemon::events::SESSION_SPAN, session = %id);
        let env = SessionEnv::new(facts.environ.clone(), facts.cwd.clone());
        let toolchain = BuildToolchain::from_facts(facts.toolchain.clone(), &env)
            .await
            .map(Arc::new)
            .map_err(stow_types::error::Error::msg)
            .wrap_err("reopen the build's toolchain")?;
        let dir = SessionDir::create(sessions, id)?;
        let mut config = facts.config.clone();
        if let Some(config) = &mut config {
            handles.install(config);
        }
        let seed = &facts.seed;
        let has_policy = seed.cache_policy_entries.is_some();
        let (allow_writer, allowed) = seed.cache_policy_entries.as_ref().map_or_else(
            || (None, None),
            |entries| {
                let (writer, set) = cache_policy::allow_cell(entries);
                (Some(writer), Some(set))
            },
        );
        // A map still `pending` arms the waiters' signal alongside: plans
        // for units it cannot cover hold until the final write lands
        // rather than compiling what the in-flight fetch may cover.
        let serve_map_ready = Arc::new(crate::facade::ServeMapSignal::pending());
        let mut serve_waiters = seed
            .serve_map
            .as_ref()
            .filter(|map| map.pending)
            .map(|_| crate::facade::ServeMapWaiters::new(Arc::clone(&serve_map_ready)));
        let (serve_map_writer, serve_map) = {
            let (writer, view) = crate::facade::serve_map_cell(seed.serve_map.clone());
            (seed.serve_map.as_ref().map(|_| writer), view)
        };
        arm_or_settle_serve_map_ready(seed, config.is_some(), &serve_map_ready, &mut serve_waiters);
        let policy_ready = policy_ready_signal(has_policy && seed.deferred);
        let analysis = seeded_analysis(seed);
        let in_flight = InFlightUnits::default();
        let resolution_done = ResolutionDone::pending();
        let ctx = BuildContext {
            marks_dir: has_policy.then(|| dir.path().to_owned()),
            allowed,
            public_cache_target: Some(facts.project.target.clone()),
            public_cache_disabled: facts.public_cache_disabled,
            cache: config
                .as_ref()
                .map_or_else(crate::config::CacheLayers::default, |config| config.cache),
            analysis: Arc::clone(&analysis),
            serve_map,
            serve_map_ready: Arc::clone(&serve_map_ready),
            policy_ready: Arc::clone(&policy_ready),
            in_flight,
            registry_sources: std::sync::OnceLock::from(facts.registry_sources.clone()),
        };
        let env_cache = WrapperEnvCache::for_session(config.clone(), toolchain);
        let enrichment = if seed.deferred
            && let Some(config) = config
        {
            // Aborted when the build's cargo exits: what the analysis
            // commits for this build lands while cargo runs, and whatever
            // is still running afterwards is warming a build that is
            // over; the plan path fetches on demand.
            Some(crate::cargo_cmd::spawn_build_enrichment(
                span.clone(),
                crate::cargo_cmd::BuildEnrichment {
                    project: facts.project.clone(),
                    env,
                    config,
                    circuit: env_cache.circuit.clone(),
                    cell: analysis,
                    map: serve_map_writer,
                    allow: allow_writer,
                    readiness: serve_waiters,
                    policy_ready: (!policy_ready.has_completed())
                        .then(|| crate::facade::ServeMapWaiters::new(Arc::clone(&policy_ready))),
                    resolution_done: resolution_done.clone(),
                    slices: handles.slice_fetches(),
                },
            ))
        } else {
            // No enrichment, so no fetch will ever land a slice: release
            // whatever waits on one now, not when the build ends
            // (stow#735).
            drop(serve_waiters);
            None
        };
        let session = Arc::new(Self {
            id,
            span: span.clone(),
            facts: Arc::new(facts),
            dir,
            reports: Reports::default(),
            env_cache,
            ctx,
            resolution_done,
            observations: std::sync::Mutex::default(),
            refusals: std::sync::Mutex::default(),
            enrichment: std::sync::Mutex::new(enrichment),
        });
        // The probes and the cache lease overlap the build's start instead
        // of waiting for its first unit (stow#608).
        let warm = Arc::clone(&session);
        tokio::spawn(
            async move {
                warm.env_cache.base().await;
            }
            .instrument(span),
        );
        Ok(session)
    }

    /// The session's id.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// The span everything done for this session is recorded under.
    #[must_use]
    pub const fn span(&self) -> &tracing::Span {
        &self.span
    }

    /// The bookkeeping tasks this session's reports spawn.
    #[must_use]
    pub const fn reports(&self) -> &Reports {
        &self.reports
    }

    /// The signal that cargo's resolution is over: the first request that
    /// describes a compile unit completes it.
    #[must_use]
    pub(crate) fn resolution_done(&self) -> ResolutionDone {
        self.resolution_done.clone()
    }

    /// Stop the background analysis and wait until its future is gone, so
    /// nothing of it outlives the build: no write into the session, no
    /// cargo child (stow#624). A panic inside it is the session's panic.
    pub(crate) async fn stop_enrichment(&self) {
        let task = self.enrichment.lock().expect("enrichment mutex").take();
        if let Some(task) = task {
            crate::cargo_cmd::stop_build_task(task).await;
        }
    }

    /// End the build: stop the analysis, drain the wrappers' bookkeeping —
    /// the last unit's store and miss observation are inside that tail
    /// (stow#618) — write the miss journal and remove the session's
    /// directory.
    ///
    /// # Errors
    ///
    /// The session directory cannot be removed.
    pub(crate) async fn end(&self) -> Result<SessionEnd> {
        self.stop_enrichment().await;
        self.reports.drain(CONNECTION_DRAIN_BUDGET).await;
        let journal_written = self.write_journal();
        let refusals = self
            .refusals
            .lock()
            .expect("refusals mutex")
            .iter()
            .map(ToString::to_string)
            .collect();
        self.remove_dir().await?;
        Ok(SessionEnd {
            refusals,
            journal_written,
        })
    }

    async fn remove_dir(&self) -> Result<()> {
        let dir = self.dir.path().to_owned();
        smol::unblock(move || {
            std::fs::remove_dir_all(&dir)
                .wrap_err_with(|| format!("remove the session directory {}", dir.display()))
        })
        .await
    }

    /// End a session whose driver went away: stop the analysis, let the
    /// bookkeeping already running finish and remove the directory. No
    /// journal is written — nothing is left to admit it.
    ///
    /// # Errors
    ///
    /// The session directory cannot be removed.
    pub(crate) async fn abort(&self) -> Result<()> {
        self.stop_enrichment().await;
        self.reports.drain(CONNECTION_DRAIN_BUDGET).await;
        self.remove_dir().await
    }

    /// The build's compile observations are its miss list (stow#317) — a
    /// failed build's units are real misses too, whatever its last unit
    /// did. They land in the same journal a plain-cargo wrapper writes;
    /// only a build that reaches the network has anything to admit.
    fn write_journal(&self) -> bool {
        let Some(config) = &self.facts.config else {
            return false;
        };
        if !config.cache.reaches_network() {
            return false;
        }
        let facts = &self.facts.project;
        let env = SessionEnv::new(self.facts.environ.clone(), self.facts.cwd.clone());
        let target_dir = self
            .facts
            .roots
            .dirs()
            .first()
            .expect("a build's output roots start with its target directory");
        // The drain mints each miss's dependency subgraph off the build's
        // persisted expanded graph when it can load it, and off the
        // journal's context sidecar when it cannot (stow#588).
        let expanded_cache_key = crate::lockfile_graph_cache::cache_key(facts, &env)
            .unwrap_or_else(|error| {
                tracing::warn!(error = %error, "could not key the expanded graph for the miss journal");
                String::new()
            });
        let key_inputs = crate::lockfile_graph_cache::KeyInputs {
            action: &facts.action,
            cargo_args: &facts.cargo_args,
            current_dir: &facts.current_dir,
            manifest_path: &facts.manifest_path,
            workspace_root: &facts.workspace_root,
            target: &facts.target,
            target_given: facts.target_given,
            rustc_version: &facts.rustc_version,
            env: &env,
        };
        let consumer = miss_journal::JournalConsumer {
            manifest_dir: facts
                .manifest_path
                .parent()
                .unwrap_or(facts.current_dir.as_path()),
            key: &key_inputs,
        };
        let observations = self.observations();
        miss_journal::journal_supervised(
            &self.facts.build_rustc,
            &consumer,
            &observations,
            target_dir,
            &expanded_cache_key,
            &self.facts.seed.inexact_entries,
        );
        !(observations.is_empty() && self.facts.seed.inexact_entries.is_empty())
    }

    /// The build's registry of units whose bookkeeping has not finished.
    pub(crate) const fn in_flight(&self) -> &InFlightUnits {
        &self.ctx.in_flight
    }

    /// Every unit this build compiled locally, in compile order.
    pub(crate) fn observations(&self) -> Vec<artifact_cache::ObservedUnit> {
        self.observations
            .lock()
            .expect("observations mutex")
            .clone()
    }

    /// `compiled` and the observed report finish the same way: resolve the
    /// build's own outputs, then mint its miss observation.
    async fn finish_and_observe(
        &self,
        post: &PostCompile,
        success: bool,
        local_base: Option<&crate::WrapperEnvBase>,
    ) {
        if let Ok(Some(build)) =
            finish_rustc_compile(post, success, local_base, &self.env_cache, &self.ctx).await
            && let Some(parsed) = post.parsed.as_ref()
            && let Some(unit) = miss_journal::observed_unit(parsed, &build)
        {
            // The unit compiled locally: it is a cache miss by
            // definition, so the build records it for the post-build
            // admissions post (stow#317).
            self.observations
                .lock()
                .expect("observations mutex")
                .push(unit);
        }
    }

    /// Whether the build's serve map rules `parsed` out before any lookup:
    /// a registry unit nothing in the build could serve. A pending map's
    /// "not covered" is provisional while the build's fetch is in flight,
    /// so the plan holds, bounded, for the final map rather than compile a
    /// unit the fetch is about to cover (stow#347, stow#788). A build with
    /// no map, every cache layer off and the identity trace — which wants
    /// the full decision's probes — never rule a unit out.
    async fn serve_map_rules_out(&self, parsed: &rustc_args::ParsedRustcArgs) -> bool {
        if self.ctx.cache.is_off()
            || self
                .env_cache
                .config()
                .is_some_and(|config| config.switches.identity_trace.is_some())
        {
            return false;
        }
        let Some(mut map) = self.ctx.serve_map.current() else {
            return false;
        };
        let Some((crate_name, version)) = registry_unit_identity(parsed) else {
            return false;
        };
        let Ok(version) = semver::Version::parse(&version) else {
            return false;
        };
        let name = crate::canonical_crate_name(&crate_name);
        let version = version.to_string();
        let covered =
            |map: &crate::facade::ServeMap| map.covers(parsed.target.is_some(), &name, &version);
        if covered(&map) {
            return false;
        }
        if map.pending {
            if tokio::time::timeout(
                crate::facade::SERVE_MAP_WAIT_TIMEOUT,
                self.ctx.serve_map_ready.wait(),
            )
            .await
            .is_err()
            {
                // A driver that is alive but stuck: decide on the map in
                // hand.
                tracing::warn!(
                    crate_name = %parsed.crate_name,
                    "the pending serve map did not settle in time; deciding on the map in hand"
                );
            }
            let Some(settled) = self.ctx.serve_map.current() else {
                return false;
            };
            map = settled;
            if covered(&map) {
                return false;
            }
        }
        true
    }

    /// The bookkeeping of a compile the serve map ruled out: the miss
    /// outcome a lookup would have recorded, then the same resolution of
    /// the unit's own outputs every local compile gets.
    async fn report_uncovered(&self, mut post: Box<PostCompile>, success: bool) {
        let Some(local_base) = self.env_cache.base().await else {
            return;
        };
        let Some(mut parsed) = post.parsed.take() else {
            return;
        };
        // The mark's key is the target decide computes: the unit's own
        // spelled `--target`, else this build's rustc host triple — the
        // key a dependent's `must_build_locally` checks under.
        let target = parsed
            .target
            .clone()
            .unwrap_or_else(|| self.env_cache.toolchain.host_target().to_owned());
        resolve_native_target_cpu(&mut parsed, &self.env_cache).await;
        let source = match post.env.manifest_dir() {
            Ok(manifest_dir) => {
                detect_unit_source(&parsed, manifest_dir.as_deref(), &self.env_cache, &self.ctx)
                    .await
                    .map_err(|error| error.to_string())
            }
            Err(error) => Err(error),
        };
        match source {
            Ok(source) => {
                let class = parsed.unit_class(source, post.env.primary_package, &target);
                // Only a publicly-missable unit counts: a git source or
                // extra codegen could never have been served remotely,
                // so its local compile is not a cache miss (stow#1006).
                record_unit_outcome(
                    &local_base.config,
                    &parsed,
                    &target,
                    local_base.rustc_version(),
                    UnitOutcome::Miss,
                    class.remote_missable(),
                )
                .await;
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    crate_name = %parsed.crate_name,
                    "failed to detect an uncovered unit's source; miss outcome skipped"
                );
            }
        }
        post.parsed = Some(parsed);
        self.finish_and_observe(&post, success, Some(&local_base))
            .await;
    }
}

impl Handler for Session {
    type Pending = Box<PostCompile>;

    fn cc_config(self: &Arc<Self>) -> Option<&StowConfig> {
        self.env_cache.config()
    }

    fn output_roots(self: &Arc<Self>) -> Option<&crate::supervisor::invocation::OutputRoots> {
        Some(&self.facts.roots)
    }

    fn plan_args(
        self: &Arc<Self>,
        mut args: Vec<std::ffi::OsString>,
        env: &InvocationEnv,
    ) -> std::result::Result<Vec<std::ffi::OsString>, String> {
        // The build's extra rustc arguments (workspace path remap and any
        // flags it selected) go after the argv so the user's own rustflags
        // sources — env or config — keep their cargo semantics.
        args.extend(
            self.facts
                .rustc_extra_args
                .iter()
                .map(std::ffi::OsString::from),
        );
        let out_dir = env.out_dir()?;
        stow_types::rustc::remap_build_output(&mut args, out_dir.as_deref().map(Path::as_os_str));
        Ok(args)
    }

    async fn plan(
        self: &Arc<Self>,
        invocation: VerifiedInvocation,
        invocation_env: InvocationEnv,
    ) -> Decision<Self::Pending> {
        let args = invocation.into_args();
        let classified = classify_invocation(&args);
        if !self.resolution_done.has_completed() && describes_compile_unit(&classified) {
            self.resolution_done.complete();
        }
        let Some(parsed) = classify_or_log(classified, &args) else {
            return Decision::Compile(Box::new(PostCompile::raw()));
        };
        if self.serve_map_rules_out(&parsed).await {
            // The map ruled the unit out: no lookup runs, so nothing
            // before the compile waits on a dependency's records either.
            // The marker is the one a `Compile` decision writes before
            // rustc runs, for the reason `compile` states.
            let target = parsed
                .target
                .clone()
                .unwrap_or_else(|| self.env_cache.toolchain.host_target().to_owned());
            record_local_build_mark(&parsed, &target, self.ctx.marks_dir.as_deref()).await;
            return Decision::Compile(Box::new(PostCompile {
                parsed: Some(parsed),
                env: invocation_env,
                compile_time: std::time::Duration::ZERO,
                owes_miss: true,
            }));
        }
        // Every lookup the decision makes reads the `--extern`
        // dependencies' `materialized_outputs` rows, and a facade exits
        // with its rustc: a dependency cargo finished before starting
        // this unit may still be writing them. Wait for the ones whose
        // rustc has exited — not for one still compiling, which a
        // pipelined unit plans against unrecorded, as it always did
        // (stow#1431). The dependency's flight also spans its store,
        // which `load_cached_bundle_by_compile_key` in the serve binding
        // reads from the dependent's plan.
        self.ctx.in_flight.wait_for_exited_externs(&parsed).await;
        match decide_rustc_invocation(parsed, &self.env_cache, &self.ctx, &invocation_env).await {
            Outcome::Served(notifications) => Decision::Served(notifications),
            Outcome::Compile(post) => Decision::Compile(post),
        }
    }

    async fn compiled(
        self: &Arc<Self>,
        mut pending: Self::Pending,
        success: bool,
        compile_time: std::time::Duration,
    ) {
        pending.compile_time = compile_time;
        if pending.owes_miss {
            self.report_uncovered(pending, success).await;
            return;
        }
        let local_base = self.env_cache.base().await;
        self.finish_and_observe(&pending, success, local_base.as_deref())
            .await;
    }

    fn toolchain(self: &Arc<Self>) -> &Arc<BuildToolchain> {
        &self.env_cache.toolchain
    }

    fn refusal_policy(self: &Arc<Self>) -> crate::supervisor::invocation::RefusalPolicy {
        self.facts.refusal_policy
    }

    fn refused(self: &Arc<Self>, refusal: Refusal) {
        self.refusals.lock().expect("refusals mutex").push(refusal);
    }
}

/// The analysis cell, written now when the driver's analysis was complete
/// and left for the enrichment otherwise.
fn seeded_analysis(seed: &Seed) -> Arc<std::sync::OnceLock<AnalysisFacts>> {
    let analysis = Arc::new(std::sync::OnceLock::new());
    if !seed.deferred {
        analysis
            .set(AnalysisFacts {
                semantic_fallback_enabled: seed.semantic_fallback_enabled,
                unit_nodes: seed.unit_nodes.clone(),
                prefetch_candidates: seed.prefetch_artifacts.as_deref().map_or_else(
                    std::collections::BTreeMap::new,
                    |artifacts| {
                        crate::prefetch_candidate_c_metadatas(artifacts.iter().map(|artifact| {
                            (artifact.crate_name.clone(), artifact.c_metadata.clone())
                        }))
                    },
                ),
            })
            .expect("a new cell is written once; this is its only writer when the analysis is not deferred");
    }
    analysis
}

/// A missing slice is final only once the build's fetch has settled — the
/// same settling a pending serve map's plans wait on — so `serve_map_ready`
/// must complete in lockstep with that fetch or a lookup waits forever
/// (stow#735). When the lite pass produced no map the enrichment still
/// fetches the consumer slices mid-build, so the guard rides with it; when
/// nothing in this build can land a slice the signal settles now — a build
/// that cannot serve must not hold a lookup for a fetch that is never
/// coming.
fn arm_or_settle_serve_map_ready(
    seed: &Seed,
    has_config: bool,
    serve_map_ready: &Arc<crate::facade::ServeMapSignal>,
    serve_waiters: &mut Option<crate::facade::ServeMapWaiters>,
) {
    if serve_waiters.is_some() {
        return;
    }
    if seed.deferred && has_config && seed.serve_map.as_ref().is_none_or(|map| map.pending) {
        *serve_waiters = Some(crate::facade::ServeMapWaiters::new(Arc::clone(
            serve_map_ready,
        )));
    } else {
        serve_map_ready.complete();
    }
}

/// The policy gate's readiness latch for this build: pending only while a
/// deferred build's enrichment still owes the allow set its coarse commit
/// — released by the commit or by the guard dropping with the task; every
/// other build answers a missing entry at once (stow#788).
fn policy_ready_signal(commit_pending: bool) -> Arc<crate::facade::ServeMapSignal> {
    Arc::new(if commit_pending {
        crate::facade::ServeMapSignal::pending()
    } else {
        crate::facade::ServeMapSignal::settled()
    })
}

#[cfg(test)]
impl Session {
    /// A session a test assembles from the parts its decisions read, with
    /// its directory under `sessions`. Nothing starts: no analysis, no
    /// warm-up.
    pub(crate) fn from_parts_for_tests(parts: TestParts, sessions: &Path) -> Arc<Self> {
        let id = SessionId::mint();
        let facts = SessionFacts::for_tests(
            parts.env_cache.toolchain.facts(),
            parts.roots,
            parts.refusal_policy,
        );
        Arc::new(Self {
            id,
            span: tracing::Span::none(),
            facts: Arc::new(facts),
            dir: SessionDir::create(sessions, id).expect("create the session directory"),
            reports: Reports::default(),
            env_cache: parts.env_cache,
            ctx: parts.ctx,
            resolution_done: parts.resolution_done,
            observations: std::sync::Mutex::default(),
            refusals: std::sync::Mutex::default(),
            enrichment: std::sync::Mutex::new(None),
        })
    }
}

/// What [`Session::from_parts_for_tests`] assembles a session from.
#[cfg(test)]
pub struct TestParts {
    pub(crate) ctx: BuildContext,
    pub(crate) env_cache: WrapperEnvCache,
    pub(crate) roots: crate::supervisor::invocation::OutputRoots,
    pub(crate) refusal_policy: crate::supervisor::invocation::RefusalPolicy,
    pub(crate) resolution_done: ResolutionDone,
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use super::*;
    use crate::supervisor::invocation::{OutputRoots, RefusalPolicy};

    const HOST_TARGET: &str = "aarch64-apple-darwin";

    /// A config with its own cache directory, nothing reaching the
    /// network.
    fn config_in(cache_dir: &Path) -> StowConfig {
        StowConfig {
            cache: crate::config::CacheLayers {
                remote: false,
                local_crates_io: true,
                local_git: true,
            },
            edge_url: "http://127.0.0.1:9".to_owned(),
            registry_base_url: "http://127.0.0.1:9".to_owned(),
            cache_dir: cache_dir.to_owned(),
            request_timeout: Duration::from_millis(200),
            negative_cache_ttl: Duration::from_mins(10),
            circuit_reset_after: Duration::ZERO,
            circuit_trip_threshold: 1,
            artifact_cache_max_bytes: u64::MAX,
            index_refresh_interval: Duration::ZERO,
            verify_mode: crate::config::VerifyMode::GithubCi,
            switches: crate::config::Switches::default(),
            state_db: crate::state_db::StateDb::default(),
            trust_material: Arc::default(),
            registry_http: Arc::default(),
            artifact_cache_staging: Arc::default(),
        }
    }

    /// Facts over the test machine's own rustc, with a serve map that
    /// covers no crate the unit below names.
    async fn facts(config: Option<StowConfig>) -> SessionFacts {
        let toolchain = BuildToolchain::for_tests().await.facts();
        let mut facts = SessionFacts::for_tests(
            toolchain,
            OutputRoots::new(PathBuf::from(std::path::MAIN_SEPARATOR_STR), None),
            RefusalPolicy::FailBuild,
        );
        facts.config = config;
        facts.rustc_extra_args =
            vec!["--remap-path-prefix=/workspace=stow-ci://workspace".to_owned()];
        facts.seed.serve_map = Some(crate::facade::ServeMap {
            target: vec![("covered".to_owned(), "*".to_owned())],
            host: Vec::new(),
            pending: false,
        });
        facts
    }

    /// One registry lib unit the serve map above does not cover.
    fn uncovered_unit() -> Vec<OsString> {
        [
            "--crate-name",
            "demo",
            "--crate-type",
            "lib",
            "--emit",
            "dep-info,metadata,link",
            "--out-dir",
            "/tmp/out",
            "-C",
            "metadata=abc123",
            "-C",
            "extra-filename=-abc123",
            "--target",
            HOST_TARGET,
            "/cargo/registry/src/index.crates.io-0123abcd/demo-1.0.0/src/lib.rs",
        ]
        .map(OsString::from)
        .to_vec()
    }

    /// What a session decided about the unit: whether it compiles, the
    /// crate it parsed and whether it owes a miss, plus the arguments the
    /// wrapper would run rustc with.
    async fn decide(session: &Arc<Session>) -> (Option<(String, bool)>, Vec<OsString>) {
        let env = InvocationEnv::for_tests();
        let args = session
            .plan_args(uncovered_unit(), &env)
            .expect("plan the arguments");
        let verified = VerifiedInvocation::verify(
            &session.env_cache.toolchain,
            Some(&session.facts.roots),
            session.env_cache.toolchain.rustc().as_os_str().to_owned(),
            uncovered_unit(),
            &env,
        )
        .await
        .expect("the session's own rustc passes verification");
        let decision = match session.plan(verified, env).await {
            Decision::Compile(post) => Some((
                post.parsed
                    .as_ref()
                    .map(|parsed| parsed.crate_name.clone())
                    .expect("the unit parses"),
                post.owes_miss,
            )),
            Decision::Served(_) => None,
        };
        (decision, args)
    }

    /// Facts cross a process boundary as JSON; a session opened from the
    /// received copy decides exactly as one opened from the facts the
    /// driver built.
    #[tokio::test]
    async fn a_session_from_round_tripped_facts_decides_like_the_driver_built_one() {
        let sessions = tempfile::tempdir().expect("sessions directory");
        let built = facts(None).await;
        let received: SessionFacts =
            serde_json::from_slice(&serde_json::to_vec(&built).expect("encode the facts"))
                .expect("decode the facts");

        let handles = CacheDirHandles::default();
        let driver = Session::open(SessionId::mint(), built, &handles, sessions.path())
            .await
            .expect("open the driver-built session");
        let remote = Session::open(SessionId::mint(), received, &handles, sessions.path())
            .await
            .expect("open the session from the received facts");

        let driver_decision = decide(&driver).await;
        assert_eq!(
            driver_decision.0,
            Some(("demo".to_owned(), true)),
            "the serve map rules the unit out"
        );
        assert!(
            driver_decision
                .1
                .iter()
                .any(|arg| arg == "--remap-path-prefix=/workspace=stow-ci://workspace"),
            "the session appends the build's extra arguments: {:?}",
            driver_decision.1
        );
        assert_eq!(decide(&remote).await, driver_decision);
        driver.end().await.expect("end the driver-built session");
        remote.end().await.expect("end the received session");
    }

    /// Two sessions whose configs name different cache directories each
    /// open the state database of their own.
    #[tokio::test]
    async fn two_sessions_with_different_cache_dirs_open_their_own_state_databases() {
        let sessions = tempfile::tempdir().expect("sessions directory");
        let first_dir = tempfile::tempdir().expect("first cache dir");
        let second_dir = tempfile::tempdir().expect("second cache dir");
        let mut resources = Resources::default();

        let mut opened = Vec::new();
        for cache_dir in [first_dir.path(), second_dir.path()] {
            let handles = resources.handles_for(cache_dir);
            let session = Session::open(
                SessionId::mint(),
                facts(Some(config_in(cache_dir))).await,
                &handles,
                sessions.path(),
            )
            .await
            .expect("open the session");
            opened.push(session);
        }
        for session in &opened {
            session
                .env_cache
                .config()
                .expect("the session's config")
                .state_db_pool()
                .await
                .expect("open the session's state database");
        }
        assert!(crate::state_db::state_db_path(first_dir.path()).is_file());
        assert!(crate::state_db::state_db_path(second_dir.path()).is_file());
        for session in opened {
            session.end().await.expect("end the session");
        }
    }
}

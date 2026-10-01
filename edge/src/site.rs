//! The two HTML pages: the landing page at `GET /` — what stow is, the
//! measured numbers, how it works, and the crate request form that is its
//! primary action — and the per-task status page at `GET /requests/{id}`
//! the form's result table links to.
//!
//! All HTML lives in `templates/index.html` (askama); the stylesheet and
//! client script are `include_str!` payloads embedded into the `<style>` and
//! `<script>` blocks the template declares, so the worker bundle stays
//! self-contained — no static-asset routes, no extra requests beyond the
//! Turnstile API script.

use askama::Template;
use stow_types::api::CI_TARGET_TRIPLES;

/// Page stylesheet, embedded into the template's `<style>` block.
const SITE_CSS: &str = include_str!("../templates/site.css");

/// Client-side form handler, embedded into the template's `<script>` block.
const SITE_JS: &str = include_str!("../templates/site.js");

/// The POSIX one-line installer, embedded so the worker serves it
/// verbatim — no static asset layer.
const INSTALL_SH: &str = include_str!("../templates/install.sh");

/// The PowerShell one-line installer, embedded the same way.
const INSTALL_PS1: &str = include_str!("../templates/install.ps1");

/// The project repository every documentation link points into.
const REPOSITORY_URL: &str = "https://github.com/water-rs/stow";

/// `Cache-Control` on the rendered pages: semi-static markup Workers
/// Cache may replay between deploys (a new Worker version keys its own
/// cache entries, so nothing stale survives a deploy).
const PAGE_MAX_AGE: &str = "public, max-age=300";

/// `Cache-Control` on the embedded installers — effectively static.
const SCRIPT_MAX_AGE: &str = "public, max-age=3600";

/// `Cache-Control` on the task-status page: a point-in-time answer that
/// Workers Cache must never replay — without it the platform's heuristic
/// would hold even an error answer for minutes.
const STATUS_NO_STORE: &str = "no-store";

/// The audit the numbers section cites, pinned to `main`.
const AUDIT_URL: &str = "https://github.com/water-rs/stow/blob/main/docs/acceleration-audit.md";

/// The target the cache lookup picker selects by default — a visitor's
/// own platform cannot be guessed reliably, so the picker defaults to
/// the most common CI leg.
const DEFAULT_LOOKUP_TARGET: &str = "x86_64-unknown-linux-gnu";

/// Page configuration probed once at worker startup.
#[derive(Debug, Clone)]
pub struct SiteConfig {
    /// Public Turnstile site key rendered into the widget's `data-sitekey`.
    pub turnstile_site_key: String,
}

/// Askama context for `templates/index.html`.
#[derive(Debug, Template)]
#[template(path = "index.html")]
pub struct IndexPage {
    turnstile_site_key: String,
    targets: &'static [&'static str],
    /// Position of the lookup picker's default target inside `targets`
    /// (`loop.index0` comparisons — askama cannot compare `&&str` to a
    /// literal).
    default_target_index: usize,
    repository_url: &'static str,
    audit_url: &'static str,
    version: &'static str,
    css: &'static str,
    js: &'static str,
}

impl IndexPage {
    /// Build the render context from the startup-probed configuration.
    fn new(config: &SiteConfig) -> Self {
        Self {
            turnstile_site_key: config.turnstile_site_key.clone(),
            targets: CI_TARGET_TRIPLES,
            default_target_index: CI_TARGET_TRIPLES
                .iter()
                .position(|target| *target == DEFAULT_LOOKUP_TARGET)
                .expect("default lookup target is a CI target"),
            repository_url: REPOSITORY_URL,
            audit_url: AUDIT_URL,
            version: env!("CARGO_PKG_VERSION"),
            css: SITE_CSS,
            js: SITE_JS,
        }
    }
}

/// One row of a [`RequestStatusPage`]'s per-target table: the wire
/// [`CrateRequestTarget`] flattened to the strings the template prints.
#[derive(Debug)]
pub struct RequestTargetView {
    target: String,
    state: &'static str,
    queue_position: Option<u32>,
    /// The root task's queue id, printed so an operator can match it
    /// against the scheduler's admin listing.
    task_id: Option<String>,
    /// `false` while the task is still moving — queued or building.
    settled: bool,
}

impl RequestTargetView {
    fn new(target: &stow_types::api::CrateRequestTarget) -> Self {
        let (state, settled) = match target.state {
            stow_types::api::CrateRequestState::Cached => ("cached", true),
            stow_types::api::CrateRequestState::Queued => ("queued", false),
            stow_types::api::CrateRequestState::AlreadyQueued => ("already queued", false),
            stow_types::api::CrateRequestState::Building => ("building", false),
            // No library task exists — nothing more can move.
            stow_types::api::CrateRequestState::ClosureQueued => ("deps queued (no library)", true),
        };
        Self {
            target: target.target.as_str().to_owned(),
            state,
            queue_position: target.human_lane_position,
            task_id: target.task_id.clone(),
            settled,
        }
    }
}

/// Render context for one request record on [`RequestStatusPage`]: the
/// wire [`CrateRequestStatus`] flattened to what the template prints —
/// the phase badge, whether the page keeps refreshing, and the sentence
/// under the badge.
#[derive(Debug)]
pub struct RequestView {
    request_id: String,
    crate_name: String,
    version: String,
    /// Comma-separated canonical feature list, or the
    /// `--no-default-features` shorthand when the request asked for a
    /// bare build.
    features: String,
    rustc_version: String,
    status: &'static str,
    /// Whether the record reached a state nothing moves past — a
    /// `failed` record, or an `enqueued` one whose every target is
    /// terminal. An unsettled page refreshes itself.
    settled: bool,
    /// One sentence saying what the phase means for the person waiting.
    summary: &'static str,
    /// The Actions run's URL once `workflow_run` has reported it —
    /// linked when present.
    github_run_url: Option<String>,
    /// The failure reason on a `failed` record.
    error: Option<String>,
    targets: Vec<RequestTargetView>,
}

impl RequestView {
    fn new(status: stow_types::api::CrateRequestStatus) -> Self {
        let features = status.features_json.features().join(", ");
        let targets: Vec<RequestTargetView> =
            status.targets.iter().map(RequestTargetView::new).collect();
        let (phase, settled, summary) = match status.status {
            stow_types::api::CrateRequestPhase::Accepted => (
                "accepted",
                false,
                "Accepted — a CI job is dispatching to resolve its dependency closure; this page refreshes itself.",
            ),
            stow_types::api::CrateRequestPhase::Resolving => (
                "resolving",
                false,
                "Resolving the dependency closure on CI now; this page refreshes itself.",
            ),
            stow_types::api::CrateRequestPhase::Enqueued => {
                let settled = targets.iter().all(|target| target.settled);
                (
                    "enqueued",
                    settled,
                    "Resolved — the tasks are in the human lane, ahead of the miss queue. Each target below lands on its own.",
                )
            }
            stow_types::api::CrateRequestPhase::Failed => (
                "failed",
                true,
                "The resolve failed before any task was queued. Requesting the same crate again re-attempts it.",
            ),
        };
        Self {
            request_id: status.request_id,
            crate_name: status.crate_name.as_str().to_owned(),
            version: status.version.to_string(),
            features: if features.is_empty() {
                "--no-default-features".to_owned()
            } else {
                features
            },
            rustc_version: status.rustc_version.as_str().to_owned(),
            status: phase,
            settled,
            summary,
            github_run_url: status.github_run_url,
            error: status.error,
            targets,
        }
    }
}

/// Askama context for `templates/request.html`.
#[derive(Debug, Template)]
#[template(path = "request.html")]
pub struct RequestStatusPage {
    request_id: String,
    request: Option<RequestView>,
    repository_url: &'static str,
    version: &'static str,
    css: &'static str,
}

impl RequestStatusPage {
    /// Build the render context; `request` is `None` for an id the
    /// scheduler has no record of.
    fn new(request_id: String, request: Option<stow_types::api::CrateRequestStatus>) -> Self {
        Self {
            request_id,
            request: request.map(RequestView::new),
            repository_url: REPOSITORY_URL,
            version: env!("CARGO_PKG_VERSION"),
            css: SITE_CSS,
        }
    }
}

/// `GET /requests/{request_id}` — the human-readable view of one human
/// request's record.
///
/// The same state `GET /api/v1/requests/{request_id}` returns as JSON:
/// that route is for programs, this page is what the request form's
/// result table links to.
#[cfg(target_arch = "wasm32")]
pub async fn request_status(
    params: skyzen::routing::Params,
    skyzen::utils::State(scheduler): skyzen::utils::State<skyzen_cloudflare::CfDurableNamespace>,
) -> Result<skyzen::Response, crate::errors::GetArtifactError> {
    use skyzen::{Body, Response, StatusCode};

    let request_id = params
        .get("request_id")
        .map_err(|_| crate::errors::GetArtifactError::BadRequest)?
        .to_owned();
    let request = crate::scheduler_client::get_request(&scheduler, &request_id).await?;
    let found = request.is_some();
    let html = RequestStatusPage::new(request_id, request)
        .render()
        .map_err(|error| crate::errors::GetArtifactError::InternalWithMessage(error.to_string()))?;

    let mut response = Response::new(Body::from(html));
    if !found {
        *response.status_mut() = StatusCode::NOT_FOUND;
    }
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        skyzen::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        skyzen::header::CACHE_CONTROL,
        skyzen::header::HeaderValue::from_static(STATUS_NO_STORE),
    );
    Ok(response)
}

/// `GET /install.sh` — the POSIX one-line installer, verbatim.
#[cfg(target_arch = "wasm32")]
pub async fn install_sh() -> skyzen::Response {
    script_response(INSTALL_SH)
}

/// `GET /install.ps1` — the PowerShell one-line installer, verbatim.
#[cfg(target_arch = "wasm32")]
pub async fn install_ps1() -> skyzen::Response {
    script_response(INSTALL_PS1)
}

/// `text/plain` so a saved or inspected download shows the script, not a
/// render attempt; piping into a shell reads the bytes either way.
#[cfg(target_arch = "wasm32")]
fn script_response(body: &'static str) -> skyzen::Response {
    let mut response = skyzen::Response::new(skyzen::Body::from(body));
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        skyzen::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        skyzen::header::CACHE_CONTROL,
        skyzen::header::HeaderValue::from_static(SCRIPT_MAX_AGE),
    );
    response
}

/// `GET /` — render the landing page.
#[cfg(target_arch = "wasm32")]
pub async fn index(
    skyzen::utils::State(site): skyzen::utils::State<SiteConfig>,
) -> Result<skyzen::Response, crate::errors::GetArtifactError> {
    let html = IndexPage::new(&site)
        .render()
        .map_err(|error| crate::errors::GetArtifactError::InternalWithMessage(error.to_string()))?;
    Ok(html_response(html, PAGE_MAX_AGE))
}

/// One rendered leaderboard row — the name plus its formatted count.
#[derive(Debug)]
pub struct StatsLeaderboardEntry {
    name: String,
    hits: String,
}

/// Askama context for `templates/stats.html`. Every number arrives
/// pre-formatted — the template prints strings, never arithmetic.
#[derive(Debug, Template)]
#[template(path = "stats.html")]
pub struct StatsPage {
    /// Suppressed below the publication threshold — the template hides
    /// the figure entirely.
    daily_active_installs_7d: Option<String>,
    hits_24h: String,
    misses_24h: String,
    hit_rate_24h: String,
    cpu_hours_saved_30d: String,
    top_crates: Vec<StatsLeaderboardEntry>,
    targets: Vec<StatsLeaderboardEntry>,
    cli_versions: Vec<StatsLeaderboardEntry>,
    repository_url: &'static str,
    version: &'static str,
    css: &'static str,
}

/// `12_345_678` → `"12,345,678"`.
fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// CPU hours for the page: one decimal under 10, a grouped integer above.
#[expect(
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    reason = "the aggregate is a sum of non-negative durations far below 2^53"
)]
fn format_cpu_hours(hours: f64) -> String {
    if hours >= 10.0 {
        grouped(hours.round() as u64)
    } else {
        format!("{hours:.1}")
    }
}

impl StatsPage {
    /// Build the render context from the published aggregates.
    fn new(stats: &stow_types::api::UsageStats) -> Self {
        let entries = |rows: &[stow_types::api::UsageStatEntry]| {
            rows.iter()
                .map(|row| StatsLeaderboardEntry {
                    name: row.name.clone(),
                    hits: grouped(row.hits),
                })
                .collect()
        };
        Self {
            daily_active_installs_7d: stats.daily_active_installs_7d.map(grouped),
            hits_24h: grouped(stats.hits_24h),
            misses_24h: grouped(stats.misses_24h),
            hit_rate_24h: format!("{:.0}%", stats.hit_rate_24h * 100.0),
            cpu_hours_saved_30d: format_cpu_hours(stats.cpu_hours_saved_30d),
            top_crates: entries(&stats.top_crates_30d),
            targets: entries(&stats.targets_30d),
            cli_versions: entries(&stats.cli_versions_30d),
            repository_url: REPOSITORY_URL,
            version: env!("CARGO_PKG_VERSION"),
            css: SITE_CSS,
        }
    }
}

/// `GET /stats` — the public usage-statistics page, rendered from the same
/// aggregate `GET /api/v1/stats` serves as JSON, cached by Workers Cache
/// on the same staleness budget the figures carry.
#[cfg(target_arch = "wasm32")]
pub async fn stats_page(
    skyzen::utils::State(stats_ctx): skyzen::utils::State<crate::stats::StatsContext>,
) -> Result<skyzen::Response, crate::errors::GetArtifactError> {
    let usage = crate::stats::compute_usage_stats(&stats_ctx).await?;
    let html = StatsPage::new(&usage)
        .render()
        .map_err(|error| crate::errors::GetArtifactError::InternalWithMessage(error.to_string()))?;
    Ok(html_response(html, PAGE_MAX_AGE))
}

/// A rendered page as a response body: HTML plus the `Cache-Control`
/// Workers Cache keys off.
#[cfg(target_arch = "wasm32")]
fn html_response(html: String, cache_control: &'static str) -> skyzen::Response {
    let mut response = skyzen::Response::new(skyzen::Body::from(html));
    response.headers_mut().insert(
        skyzen::header::CONTENT_TYPE,
        skyzen::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        skyzen::header::CACHE_CONTROL,
        skyzen::header::HeaderValue::from_static(cache_control),
    );
    response
}

#[cfg(test)]
mod tests {
    use askama::Template;
    use stow_types::api::CI_TARGET_TRIPLES;

    use super::{AUDIT_URL, IndexPage, SiteConfig};

    fn render() -> String {
        IndexPage::new(&SiteConfig {
            turnstile_site_key: "1x00000000000000000000AA".to_owned(),
        })
        .render()
        .expect("index page renders")
    }

    #[test]
    fn index_page_renders_site_key_and_targets() {
        let html = render();
        assert!(html.contains(r#"data-sitekey="1x00000000000000000000AA""#));
        for target in CI_TARGET_TRIPLES {
            assert!(html.contains(target), "rendered page lists {target}");
        }
    }

    #[test]
    fn index_page_cites_the_audit_for_its_numbers() {
        let html = render();
        assert!(html.contains(AUDIT_URL));
        for figure in ["2.88×", "4.76×", "234 s", "433 s", "61 s floor"] {
            assert!(html.contains(figure), "rendered page shows {figure}");
        }
    }

    #[test]
    fn index_page_offers_search_version_and_feature_controls() {
        let html = render();
        // The crate field is a combobox over the search endpoint, the
        // version field a select, and features a checkbox set — none of the
        // three is free text any more.
        assert!(html.contains(r#"role="combobox""#));
        assert!(html.contains(r#"<ul id="crate-options" class="combobox-list" role="listbox""#));
        assert!(html.contains(r#"<select id="crate-version" name="version" disabled>"#));
        assert!(
            html.contains(r#"<fieldset class="field feature-set" id="feature-field" disabled>"#)
        );
        assert!(!html.contains(r#"id="crate-features""#));
        for endpoint in ["/api/v1/crates/search", "/versions", "/features"] {
            assert!(html.contains(endpoint), "script calls {endpoint}");
        }
    }

    #[test]
    fn index_page_links_results_to_the_status_page_not_the_json_route() {
        let html = render();
        // The result table's request row links to the status page —
        // request ids, not task ids, are what the route now serves.
        assert!(html.contains("`/requests/${encodeURIComponent(outcome.request_id)}`"));
        assert!(!html.contains("`/api/v1/requests/${encodeURIComponent(entry.task_id)}`"));
    }

    #[test]
    fn index_page_carries_the_cache_lookup_controls() {
        let html = render();
        // Target picker lists every CI target, defaulting to
        // x86_64-unknown-linux-gnu.
        assert!(html.contains(r#"<select id="lookup-target">"#));
        for target in CI_TARGET_TRIPLES {
            assert!(
                html.contains(&format!(r#"<option value="{target}""#)),
                "lookup picker lists {target}"
            );
        }
        assert!(html.contains(
            r#"<option value="x86_64-unknown-linux-gnu" selected>x86_64-unknown-linux-gnu</option>"#
        ));
        // Exactly one option carries `selected`.
        assert_eq!(html.matches(" selected>").count(), 1);
        // The crate field completes from the slice through the same
        // combobox component the request form points at crates.io —
        // defined once, instantiated per field.
        assert!(html.contains(r#"<input id="lookup-crate""#));
        assert!(html.contains(r#"aria-controls="lookup-crate-options""#));
        assert!(
            html.contains(r#"<ul id="lookup-crate-options" class="combobox-list" role="listbox""#)
        );
        assert_eq!(html.matches("createCombobox({").count(), 2);
        assert_eq!(html.matches("const createCombobox").count(), 1);
        assert!(
            html.contains(
                r#"<p id="lookup-note" class="status" role="status" aria-live="polite">"#
            )
        );
        assert!(html.contains(r#"<div id="lookup-result" class="result" hidden>"#));
        assert!(html.contains(r#"<tbody id="lookup-result-body">"#));
        // The page states plainly that it does not verify signatures.
        assert!(html.contains("The page does not verify signatures"));
        // The script talks to the slice routes — the tag-addressed
        // pointer first, then the digest-addressed blob.
        assert!(html.contains("/api/v1/index/"));
        assert!(html.contains("/stable"));
    }

    #[test]
    fn index_page_embeds_the_stylesheet_and_script_inline() {
        let html = render();
        assert!(html.contains("<style>:root {"));
        assert!(html.contains("<script>\"use strict\";"));
        assert!(html.contains("/api/v1/requests"));
    }

    #[test]
    fn index_page_offers_both_install_lines_with_posix_as_the_default() {
        let html = render();
        // Both commands ship in the markup: POSIX visible as the no-JS
        // default, Windows hidden until detection or the toggle selects it.
        assert!(html.contains(r#"<code id="install-posix-command">curl -fsSL https://stow.waterui.dev/install.sh | sh"#));
        assert!(html.contains(r#"<code id="install-windows-command" hidden>irm https://stow.waterui.dev/install.ps1 | iex"#));
        assert!(html.contains(r#"id="install-posix""#));
        assert!(html.contains(r#"id="install-windows""#));
        assert!(html.contains("navigator.userAgentData?.platform ?? navigator.userAgent"));
    }

    #[test]
    fn index_page_claims_the_clone_storage_advantage_exactly() {
        let html = render();
        // The claim names the filesystems where sharing holds and states
        // that everywhere else the hit is a plain copy — no exaggeration.
        assert!(html.contains("copy-on-write clone"));
        assert!(html.contains("plain copy"));
        assert!(html.contains("sccache"));
    }
}

#[cfg(test)]
mod stats_page_tests {
    use askama::Template;
    use stow_types::api::{UsageStatEntry, UsageStats};

    use super::StatsPage;

    fn render(stats: &UsageStats) -> String {
        StatsPage::new(stats).render().expect("stats page renders")
    }

    fn stats(daily_active_installs_7d: Option<u64>) -> UsageStats {
        UsageStats {
            daily_active_installs_7d,
            hits_24h: 1_234_567,
            misses_24h: 42,
            hit_rate_24h: 0.9667,
            cpu_hours_saved_30d: 123.4,
            top_crates_30d: vec![UsageStatEntry {
                name: "serde".to_owned(),
                hits: 9_999,
            }],
            targets_30d: vec![UsageStatEntry {
                name: "x86_64-unknown-linux-gnu".to_owned(),
                hits: 5_000,
            }],
            cli_versions_30d: vec![UsageStatEntry {
                name: "0.5.0".to_owned(),
                hits: 500,
            }],
        }
    }

    #[test]
    fn stats_page_renders_grouped_figures_and_leaderboards() {
        let html = render(&stats(Some(123_456)));
        assert!(html.contains("1,234,567"));
        assert!(html.contains("123,456"));
        assert!(html.contains("97%"));
        assert!(html.contains("serde"));
        assert!(html.contains("9,999"));
        assert!(html.contains("x86_64-unknown-linux-gnu"));
        assert!(html.contains("0.5.0"));
        assert!(html.contains("/api/v1/stats"));
        assert!(html.contains("PRIVACY.md"));
    }

    #[test]
    fn stats_page_hides_the_install_count_when_suppressed() {
        let html = render(&stats(None));
        assert!(!html.contains("active installs"));
    }

    #[test]
    fn stats_page_says_no_hits_when_leaderboards_are_empty() {
        let mut empty = stats(Some(100));
        empty.top_crates_30d.clear();
        let html = render(&empty);
        assert!(html.contains("no hits yet"));
    }
}

#[cfg(test)]
mod request_status_tests {
    use askama::Template as _;
    use stow_types::api::{CrateRequestPhase, CrateRequestState, CrateRequestTarget};

    use super::RequestStatusPage;

    fn status(
        phase: CrateRequestPhase,
        features: &[&str],
        targets: Vec<CrateRequestTarget>,
    ) -> stow_types::api::CrateRequestStatus {
        stow_types::api::CrateRequestStatus {
            request_id: "req-serde-1.0.219-ab12-1_98_1".to_owned(),
            crate_name: "serde".parse().expect("crate name"),
            version: "1.0.219".parse().expect("version"),
            features_json: stow_types::identity::FeaturesJson::canonicalize(
                features
                    .iter()
                    .map(|feature| (*feature).to_owned())
                    .collect(),
            )
            .expect("features"),
            rustc_version: "1.98.1".parse().expect("rustc version"),
            status: phase,
            targets,
            error: None,
            github_run_id: None,
            github_run_url: None,
        }
    }

    fn target(state: CrateRequestState, position: Option<u32>) -> CrateRequestTarget {
        CrateRequestTarget {
            target: "x86_64-unknown-linux-gnu".parse().expect("target"),
            state,
            task_id: Some("serde-1.0.219-abc-x86_64-unknown-linux-gnu-1.98.1".to_owned()),
            human_lane_position: position,
        }
    }

    fn render(
        phase: CrateRequestPhase,
        features: &[&str],
        targets: Vec<CrateRequestTarget>,
    ) -> String {
        RequestStatusPage::new(
            "req-serde-1.0.219-ab12-1_98_1".to_owned(),
            Some(status(phase, features, targets)),
        )
        .render()
        .expect("status page renders")
    }

    #[test]
    fn a_resolving_request_renders_its_identity_and_keeps_refreshing() {
        let html = render(
            CrateRequestPhase::Resolving,
            &["default", "std"],
            Vec::new(),
        );
        assert!(html.contains(r#"<meta http-equiv="refresh" content="20">"#));
        assert!(html.contains(r#"<span class="badge" data-state="resolving">resolving</span>"#));
        assert!(html.contains("serde"));
        assert!(html.contains("default, std"));
    }

    #[test]
    fn an_enqueued_request_lists_its_targets_and_keeps_refreshing() {
        let html = render(
            CrateRequestPhase::Enqueued,
            &["default"],
            vec![
                target(CrateRequestState::Queued, Some(3)),
                CrateRequestTarget {
                    state: CrateRequestState::Building,
                    ..target(CrateRequestState::Queued, None)
                },
            ],
        );
        assert!(html.contains(r#"<span class="badge" data-state="enqueued">enqueued</span>"#));
        assert!(html.contains("x86_64-unknown-linux-gnu"));
        assert!(html.contains("queued"));
        assert!(html.contains("building"));
        assert!(html.contains("#3"));
        assert!(html.contains("http-equiv=\"refresh\""));
    }

    #[test]
    fn a_settled_request_stops_refreshing() {
        let cached = render(
            CrateRequestPhase::Enqueued,
            &["default"],
            vec![CrateRequestTarget {
                state: CrateRequestState::Cached,
                task_id: None,
                ..target(CrateRequestState::Queued, None)
            }],
        );
        assert!(!cached.contains("http-equiv=\"refresh\""));
        let failed = render(CrateRequestPhase::Failed, &["default"], Vec::new());
        assert!(!failed.contains("http-equiv=\"refresh\""));
        assert!(failed.contains(r#"<span class="badge" data-state="failed">failed</span>"#));
    }

    #[test]
    fn an_empty_feature_list_reads_as_no_default_features() {
        let html = render(CrateRequestPhase::Accepted, &[], Vec::new());
        assert!(html.contains("--no-default-features"));
    }

    #[test]
    fn an_unknown_request_says_so_instead_of_rendering_a_blank_record() {
        let html = RequestStatusPage::new("req-nope".to_owned(), None)
            .render()
            .expect("status page renders");
        assert!(html.contains("Unknown request"));
        assert!(html.contains("req-nope"));
        assert!(!html.contains("http-equiv=\"refresh\""));
    }
}

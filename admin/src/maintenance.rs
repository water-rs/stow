//! `stow-admin maintenance` — the zone-level breaker of stow#453.
//!
//! Three Cloudflare WAF custom rules in the zone's
//! `http_request_firewall_custom` phase stop traffic in the security
//! phase, before the Worker runs: a blocked request never invokes the
//! Worker and never reaches the Durable Object — the properties the
//! Durable-Object panic switch (#189) could not have. `maintenance
//! ensure` (what `deploy-edge.yml` runs) creates them disabled and
//! matches them by description, so they exist before anyone needs them
//! and redeploys never stomp a live toggle:
//!
//! - `stow maintenance: anonymous` blocks the anonymous route families
//!   on the edge hostname; the trusted `/api/v1/admin/*`,
//!   `/api/v1/scheduler/*` and `/api/v1/github/*` prefixes keep working —
//!   what the panic switch was for.
//! - `stow maintenance: scheduler lanes` blocks exactly the public
//!   routes whose handlers reach the scheduler Durable Object
//!   (`stow_types::api::scheduler_lanes`), leaving the bundle byte path
//!   and catalog reads serving — the partial reopening.
//! - `stow maintenance: all` blocks every path on the hostname — the
//!   whole site is down at zero Worker/Durable-Object usage.
//!
//! `stow-admin maintenance on|off --scope anonymous|lanes|all` flips
//! `enabled` through the Rulesets API; the watchdog (#450) trips by
//! enabling `anonymous`, so a broken edge cannot silence the breaker —
//! the flag lives on the zone, not inside it. The rules' `http.host`
//! term comes from `STOW_EDGE_URL`, never a hardcoded hostname.

use clap::{Args, ValueEnum};
use stow_types::api::scheduler_lanes;
use zenwave::Client;

use crate::STOW_EDGE_URL_ENV;
use crate::cloudflare::{self, API_BASE};
use crate::render::{self, Output};

/// The zone the rules live on — a repository variable, resolved once
/// here and in `deploy-edge.yml`.
pub const CF_ZONE_ID_ENV: &str = "CF_ZONE_ID";
/// The zone phase the custom rules live in — runs before Workers.
const WAF_PHASE: &str = "http_request_firewall_custom";

/// `stow-admin maintenance ensure|on|off|status [--scope …]`.
#[derive(Args)]
pub struct MaintenanceArgs {
    /// `ensure` creates the ruleset and any missing rule (disabled);
    /// `on`/`off` write one rule's `enabled` flag (under `--yes`);
    /// `status` reads all three.
    #[arg(value_enum)]
    action: MaintenanceAction,
    /// Which maintenance rule — `anonymous` sheds public traffic while
    /// the trusted lanes keep working, `lanes` sheds just the
    /// scheduler-backed routes, `all` stops the whole site. Required
    /// for `on`/`off`; `ensure` and `status` cover all scopes.
    #[arg(long)]
    scope: Option<MaintenanceScope>,
    /// Apply the mutation. `status` never mutates; `ensure`, `on` and
    /// `off` without `--yes` print the plan and exit 0.
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MaintenanceAction {
    Ensure,
    On,
    Off,
    Status,
}

/// Which zone rule a toggle addresses. The description is the stable
/// identity — rule ids are per-zone and never hard-coded, so the deploy
/// step and this CLI agree on the name alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceScope {
    /// Anonymous routes only; the trusted admin and scheduler prefixes
    /// stay up. What the panic switch used to do, and what the watchdog
    /// trips on.
    Anonymous,
    /// Only the public routes whose handlers reach the scheduler
    /// Durable Object (`scheduler_lanes::ALL`) — the partial reopening:
    /// bundle bytes and catalog reads keep serving while queue-mutating
    /// traffic is shed at the zone. Free-plan zones allow five custom
    /// rules; this is the third.
    Lanes,
    /// Every path on the hostname.
    All,
}

/// Every scope, in deploy order — `ensure` creates all of them.
const ALL_SCOPES: [MaintenanceScope; 3] = [
    MaintenanceScope::Anonymous,
    MaintenanceScope::Lanes,
    MaintenanceScope::All,
];

impl MaintenanceScope {
    /// The zone rule's `description` — its stable identity.
    pub const fn description(self) -> &'static str {
        match self {
            Self::Anonymous => "stow maintenance: anonymous",
            Self::Lanes => "stow maintenance: scheduler lanes",
            Self::All => "stow maintenance: all",
        }
    }

    /// The rule's WAF expression for the edge's hostname (from
    /// `STOW_EDGE_URL` — never a hardcoded name). `anonymous` blocks
    /// every route the old panic gate wrapped — everything on the edge
    /// hostname except the trusted prefixes, `/api/v1/github` included
    /// so GitHub's webhook keeps draining completions while the public
    /// surface is shed — so the expression is a carve-out, not a path
    /// enumeration that would drift as routes change. `lanes` is the
    /// opposite shape: exactly the `scheduler_lanes` paths the router
    /// mounts.
    pub fn expression(self, host: &str) -> String {
        match self {
            Self::Anonymous => format!(
                "http.host eq \"{host}\" and not starts_with(http.request.uri.path, \"/api/v1/admin\") and not starts_with(http.request.uri.path, \"/api/v1/scheduler\") and not starts_with(http.request.uri.path, \"/api/v1/github\")"
            ),
            Self::Lanes => {
                let clauses = lane_prefixes()
                    .iter()
                    .map(|prefix| format!("starts_with(http.request.uri.path, \"{prefix}\")"))
                    .collect::<Vec<_>>()
                    .join(" or ");
                format!("http.host eq \"{host}\" and ({clauses})")
            }
            Self::All => format!("http.host eq \"{host}\""),
        }
    }
}

/// The WAF prefix a lane path blocks under `starts_with` — the literal
/// path itself, or for a `{param}` route the path through the slash the
/// parameter hangs off (`/requests/{task_id}` → `/requests/`).
fn lane_prefix(path: &str) -> &str {
    path.find('{').map_or(path, |param| {
        path[..param]
            .rfind('/')
            .map_or_else(|| &path[..param], |slash| &path[..=slash])
    })
}

/// The deduplicated clause prefixes for `lanes`: a lane constant that
/// already extends another lane's prefix (e.g. `/api/v1/requests/…`
/// under `/api/v1/requests`) contributes nothing new and is dropped.
fn lane_prefixes() -> Vec<&'static str> {
    let mut prefixes = Vec::new();
    for path in scheduler_lanes::ALL {
        let prefix = lane_prefix(path);
        if !prefixes.iter().any(|shorter| prefix.starts_with(shorter)) {
            prefixes.push(prefix);
        }
    }
    prefixes
}

// ===== Rulesets API wire types =====

/// The `errors`/`result` envelope every Cloudflare v4 call answers.
/// `errors` is a hard error regardless of `success` — a 404 entrypoint
/// read is `errors: [{code: 10003}]`, which `entrypoint` turns into
/// `None`.
#[derive(Debug, serde::Deserialize)]
struct CfResponse {
    #[serde(default)]
    errors: Vec<CfError>,
    result: Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
struct CfError {
    code: u32,
    message: String,
}

/// The phase entrypoint — a ruleset with its rules.
#[derive(Debug, serde::Deserialize)]
struct Ruleset {
    id: String,
    #[serde(default)]
    rules: Vec<ZoneRule>,
}

#[derive(Debug, serde::Deserialize)]
struct ZoneRule {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    enabled: bool,
}

/// The rule body `maintenance ensure` creates and a `PATCH` toggle
/// sends — full fields, so a toggle never depends on PATCH's
/// omitted-field semantics.
#[derive(Debug, serde::Serialize)]
struct RuleBody<'a> {
    description: &'a str,
    expression: &'a str,
    action: &'a str,
    enabled: bool,
}

/// The `POST /zones/{zone}/rulesets` body `ensure` sends when the phase
/// has no entrypoint yet — `kind: zone` plus every maintenance rule,
/// disabled.
#[derive(Debug, serde::Serialize)]
struct RulesetBody<'a> {
    name: &'a str,
    kind: &'a str,
    phase: &'a str,
    rules: Vec<RuleBody<'a>>,
}

/// The hostname the rules' `http.host` term names — the host of
/// `STOW_EDGE_URL`, parsed leniently (`scheme://` prefix optional, port
/// and path dropped). The rules must name the host the CLI actually
/// talks to, so a staging edge gets staging rules.
pub fn host_from_url(url: &str) -> Result<String, String> {
    let rest = url.split_once("://").map_or(url, |(_scheme, rest)| rest);
    let host_port = rest.split('/').next().unwrap_or_default();
    let host = host_port.split(':').next().unwrap_or_default();
    if host.is_empty() {
        return Err(format!("no host in edge url `{url}`"));
    }
    Ok(host.to_lowercase())
}

/// `STOW_EDGE_URL`'s host — required by `ensure`, `on` and `off`, the
/// actions that build rule expressions.
fn edge_host() -> stow_types::error::Result<String> {
    let url = std::env::var(STOW_EDGE_URL_ENV)
        .map_err(|_| stow_types::stow_error!("missing {STOW_EDGE_URL_ENV}"))?;
    host_from_url(&url).map_err(|error| stow_types::stow_error!("{error}"))
}

/// `GET` or `PATCH` a zone path and answer `(status, envelope)` — the
/// caller, not a blanket `error_for_status`, decides what a non-2xx
/// means: a 404 entrypoint read is a normal "absent" answer, while the
/// envelope's `errors` array is always a hard error.
async fn cf_request(
    token: &str,
    method: zenwave::Method,
    url: &str,
    body: Option<&(impl serde::Serialize + Sync)>,
) -> Result<(u16, CfResponse), String> {
    let mut client = zenwave::client();
    let builder = client
        .method(method, url)
        .and_then(|request| request.header("Authorization", format!("Bearer {token}")))
        .and_then(|request| match body {
            Some(body) => request.json_body(body),
            None => Ok(request),
        })
        .map_err(|error| format!("build {url}: {error}"))?;
    let response = builder.await.map_err(|error| format!("{url}: {error}"))?;
    let status = response.status().as_u16();
    let text = zenwave::ResponseExt::into_string(response)
        .await
        .map_err(|error| format!("read {url} body: {error}"))?;
    let envelope: CfResponse = serde_json::from_str(text.as_ref())
        .map_err(|error| format!("decode {url} ({status}): {error} — {text}"))?;
    if let Some(error) = envelope.errors.first() {
        // 10003 is "could not find entrypoint ruleset for phase" — the
        // one error a reader legitimately meets; everything else is a
        // hard failure.
        if !(status == 404 && error.code == 10003) {
            return Err(format!("{url}: API error {} {}", error.code, error.message));
        }
    }
    Ok((status, envelope))
}

/// The zone's `http_request_firewall_custom` entrypoint, or `None` when
/// the phase has never had a ruleset (API error 10003). The deploy step
/// creates it; a missing entrypoint here means `deploy-edge.yml` has
/// not run its WAF step yet.
async fn entrypoint(token: &str, zone_id: &str) -> Result<Option<Ruleset>, String> {
    let url = format!("{API_BASE}/zones/{zone_id}/rulesets/phases/{WAF_PHASE}/entrypoint");
    let (status, envelope) = cf_request(token, zenwave::Method::GET, &url, None::<&u8>).await?;
    if status == 404 {
        return Ok(None);
    }
    if !(200..300).contains(&status) {
        return Err(format!("{url}: HTTP {status}"));
    }
    let result = envelope
        .result
        .ok_or_else(|| format!("{url}: empty result"))?;
    serde_json::from_value::<Ruleset>(result)
        .map(Some)
        .map_err(|error| format!("decode ruleset: {error}"))
}

/// One rule's current enabled state, looked up by its description.
fn find_rule<'a>(ruleset: &'a Ruleset, description: &str) -> Option<&'a ZoneRule> {
    ruleset
        .rules
        .iter()
        .find(|rule| rule.description == description)
}

/// The three disabled rules `ensure` wants the zone to carry, built
/// against `host`. Owned bodies — the expressions are computed, not
/// constants, because the host comes from `STOW_EDGE_URL`.
fn wanted_rules(host: &str) -> Vec<(MaintenanceScope, String)> {
    ALL_SCOPES
        .iter()
        .map(|scope| (*scope, scope.expression(host)))
        .collect()
}

/// What `ensure` read or wrote: the entrypoint's id when one exists (or
/// was just created), and which rules it had to add. `apply == false`
/// reads only — a plan.
#[derive(Debug, serde::Serialize)]
pub struct EnsureOutcome {
    /// `false` when the phase had no entrypoint and the create carries
    /// all three rules at once.
    pub appended_to_existing: bool,
    /// Descriptions of the rules created (`all` when the entrypoint
    /// itself is new). Empty means the zone already matches — `ensure`
    /// is a no-op.
    pub created: Vec<String>,
}

/// Create the phase's entrypoint carrying every maintenance rule
/// (disabled) when it is absent, or append the rules a present
/// entrypoint is missing. A rule that already exists is untouched —
/// its `enabled` state is never rewritten — and the match is on
/// `description` alone. `apply == false` performs the same read and
/// answers what a real run would create, without writing.
pub async fn ensure(
    token: &str,
    zone_id: &str,
    host: &str,
    apply: bool,
) -> Result<EnsureOutcome, String> {
    let wanted = wanted_rules(host);
    match entrypoint(token, zone_id).await? {
        None => {
            if apply {
                let body = RulesetBody {
                    name: "stow maintenance",
                    kind: "zone",
                    phase: WAF_PHASE,
                    rules: wanted
                        .iter()
                        .map(|(scope, expression)| RuleBody {
                            description: scope.description(),
                            expression,
                            action: "block",
                            enabled: false,
                        })
                        .collect(),
                };
                let url = format!("{API_BASE}/zones/{zone_id}/rulesets");
                let (status, _) =
                    cf_request(token, zenwave::Method::POST, &url, Some(&body)).await?;
                if !(200..300).contains(&status) {
                    return Err(format!("{url}: HTTP {status}"));
                }
            }
            Ok(EnsureOutcome {
                appended_to_existing: false,
                created: wanted
                    .iter()
                    .map(|(scope, _)| scope.description().to_owned())
                    .collect(),
            })
        }
        Some(ruleset) => {
            let missing: Vec<&(MaintenanceScope, String)> = wanted
                .iter()
                .filter(|(scope, _)| find_rule(&ruleset, scope.description()).is_none())
                .collect();
            if apply {
                for (scope, expression) in &missing {
                    let url = format!("{API_BASE}/zones/{zone_id}/rulesets/{}/rules", ruleset.id);
                    let body = RuleBody {
                        description: scope.description(),
                        expression,
                        action: "block",
                        enabled: false,
                    };
                    let (status, _) =
                        cf_request(token, zenwave::Method::POST, &url, Some(&body)).await?;
                    if !(200..300).contains(&status) {
                        return Err(format!("{url}: HTTP {status}"));
                    }
                }
            }
            Ok(EnsureOutcome {
                appended_to_existing: true,
                created: missing
                    .iter()
                    .map(|(scope, _)| scope.description().to_owned())
                    .collect(),
            })
        }
    }
}

/// Flip `enabled` on a maintenance rule; answers the rule's state after
/// the write. A missing rule is a hard error — the deploy step owns
/// creation, and a breaker that is not deployed must not be reported as
/// thrown.
pub async fn set_scope(
    token: &str,
    zone_id: &str,
    scope: MaintenanceScope,
    enabled: bool,
    host: &str,
) -> Result<bool, String> {
    let Some(ruleset) = entrypoint(token, zone_id).await? else {
        return Err(format!(
            "zone {zone_id} has no {WAF_PHASE} entrypoint — run the WAF step in deploy-edge.yml first"
        ));
    };
    let description = scope.description();
    let Some(rule) = find_rule(&ruleset, description) else {
        return Err(format!(
            "rule `{description}` is absent from zone ruleset {} — the deploy step creates it",
            ruleset.id
        ));
    };
    if rule.enabled == enabled {
        return Ok(enabled);
    }
    let url = format!(
        "{API_BASE}/zones/{zone_id}/rulesets/{}/rules/{}",
        ruleset.id, rule.id
    );
    let body = RuleBody {
        description,
        expression: &scope.expression(host),
        action: "block",
        enabled,
    };
    let (status, _) = cf_request(token, zenwave::Method::PATCH, &url, Some(&body)).await?;
    if !(200..300).contains(&status) {
        return Err(format!("{url}: HTTP {status}"));
    }
    Ok(enabled)
}

/// Read a scope's current `enabled` without touching it.
pub async fn scope_enabled(
    token: &str,
    zone_id: &str,
    scope: MaintenanceScope,
) -> Result<bool, String> {
    let Some(ruleset) = entrypoint(token, zone_id).await? else {
        return Ok(false);
    };
    Ok(find_rule(&ruleset, scope.description()).is_some_and(|rule| rule.enabled))
}

/// The zone id from [`CF_ZONE_ID_ENV`].
///
/// # Errors
/// The variable is unset.
pub fn zone_id() -> stow_types::error::Result<String> {
    std::env::var(CF_ZONE_ID_ENV).map_err(|_| stow_types::stow_error!("missing {CF_ZONE_ID_ENV}"))
}

/// The mutation plan `render::mutation` emits.
#[derive(Debug, serde::Serialize)]
struct MaintenancePlan {
    /// The rule's stable identity.
    rule: String,
    /// What the toggle writes.
    enabled: bool,
}

/// What an applied toggle reported back.
#[derive(Debug, serde::Serialize)]
struct MaintenanceResult {
    rule: String,
    enabled: bool,
}

/// `status` output — one row per scope.
#[derive(Debug, serde::Serialize)]
struct MaintenanceStatus {
    anonymous: bool,
    lanes: bool,
    all: bool,
}

/// `stow-admin maintenance …` — pure Cloudflare; no edge call.
pub async fn run(args: MaintenanceArgs, output: Output) -> stow_types::error::Result<()> {
    let token = cloudflare::api_token()?;
    let zone_id = zone_id()?;
    match args.action {
        MaintenanceAction::Status => run_status(&token, &zone_id, output).await,
        MaintenanceAction::Ensure => run_ensure(&token, &zone_id, args.yes, output).await,
        MaintenanceAction::On | MaintenanceAction::Off => {
            run_toggle(&token, &zone_id, args, output).await
        }
    }
}

/// `maintenance status` — one row per scope.
async fn run_status(token: &str, zone_id: &str, output: Output) -> stow_types::error::Result<()> {
    let status = MaintenanceStatus {
        anonymous: scope_enabled(token, zone_id, MaintenanceScope::Anonymous)
            .await
            .map_err(|error| stow_types::stow_error!("{error}"))?,
        lanes: scope_enabled(token, zone_id, MaintenanceScope::Lanes)
            .await
            .map_err(|error| stow_types::stow_error!("{error}"))?,
        all: scope_enabled(token, zone_id, MaintenanceScope::All)
            .await
            .map_err(|error| stow_types::stow_error!("{error}"))?,
    };
    render::emit(output, &status, |status| {
        let mut out = String::new();
        for (scope, enabled) in [
            (MaintenanceScope::Anonymous, status.anonymous),
            (MaintenanceScope::Lanes, status.lanes),
            (MaintenanceScope::All, status.all),
        ] {
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!(
                    "{:<10} {}\n",
                    scope.description(),
                    if enabled { "on" } else { "off" }
                ),
            );
        }
        out.trim_end().to_owned()
    })
}

/// `maintenance ensure` — plan from one dry pass, apply on `--yes`.
async fn run_ensure(
    token: &str,
    zone_id: &str,
    yes: bool,
    output: Output,
) -> stow_types::error::Result<()> {
    let host = edge_host()?;
    let planned = ensure(token, zone_id, &host, false)
        .await
        .map_err(|error| stow_types::stow_error!("{error}"))?;
    render::mutation(
        output,
        yes,
        planned,
        |envelope: &render::Planned<EnsureOutcome, EnsureOutcome>| {
            let mut out = String::new();
            let plan = &envelope.plan;
            if plan.created.is_empty() {
                out.push_str("all three maintenance rules already present — nothing to do\n");
            } else {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!(
                        "{}: {}\n",
                        if plan.appended_to_existing {
                            "append to the entrypoint"
                        } else {
                            "create the entrypoint with"
                        },
                        plan.created.join(", ")
                    ),
                );
            }
            if let Some(result) = &envelope.result {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!("created: {}\n", result.created.join(", ")),
                );
            }
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!("{}", render::plan_footer(envelope.dry_run)),
            );
            out
        },
        async move |_plan: &EnsureOutcome| {
            ensure(token, zone_id, &host, true)
                .await
                .map_err(|error| stow_types::stow_error!("{error}"))
        },
    )
    .await
}

/// `maintenance on|off` — flip one scope's `enabled` flag.
async fn run_toggle(
    token: &str,
    zone_id: &str,
    args: MaintenanceArgs,
    output: Output,
) -> stow_types::error::Result<()> {
    let host = edge_host()?;
    let Some(scope) = args.scope else {
        return Err(stow_types::stow_error!(
            "`maintenance on|off` needs `--scope anonymous|lanes|all`"
        ));
    };
    let enabled = matches!(args.action, MaintenanceAction::On);
    let plan = MaintenancePlan {
        rule: scope.description().to_owned(),
        enabled,
    };
    render::mutation(
        output,
        args.yes,
        plan,
        |envelope: &render::Planned<MaintenancePlan, MaintenanceResult>| {
            let mut out = format!(
                "set `{}` {}\n",
                envelope.plan.rule,
                if envelope.plan.enabled { "on" } else { "off" }
            );
            if let Some(result) = &envelope.result {
                let _ = std::fmt::Write::write_fmt(
                    &mut out,
                    format_args!(
                        "`{}` is now {}\n",
                        result.rule,
                        if result.enabled { "on" } else { "off" }
                    ),
                );
            }
            let _ = std::fmt::Write::write_fmt(
                &mut out,
                format_args!("{}", render::plan_footer(envelope.dry_run)),
            );
            out
        },
        async move |plan: &MaintenancePlan| {
            let applied = set_scope(token, zone_id, scope, plan.enabled, &host)
                .await
                .map_err(|error| stow_types::stow_error!("{error}"))?;
            Ok(MaintenanceResult {
                rule: plan.rule.clone(),
                enabled: applied,
            })
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The entrypoint answer when the phase was never provisioned —
    /// `errors[0].code == 10003` and HTTP 404.
    const ENTRYPOINT_ABSENT: &str = r#"{"success":false,"errors":[{"code":10003,"message":"could not find entrypoint ruleset for phase http_request_firewall_custom"}],"messages":[],"result":null}"#;

    /// An entrypoint carrying all three maintenance rules disabled.
    const ENTRYPOINT_PRESENT: &str = r#"{"success":true,"errors":[],"messages":[],"result":{"id":"rs-1","name":"stow maintenance","kind":"zone","phase":"http_request_firewall_custom","rules":[{"id":"r-anon","description":"stow maintenance: anonymous","expression":"http.host eq \"stow.waterui.dev\" and not starts_with(http.request.uri.path, \"/api/v1/admin\") and not starts_with(http.request.uri.path, \"/api/v1/scheduler\") and not starts_with(http.request.uri.path, \"/api/v1/github\")","action":"block","enabled":false},{"id":"r-lanes","description":"stow maintenance: scheduler lanes","expression":"http.host eq \"stow.waterui.dev\" and (starts_with(http.request.uri.path, \"/api/v1/admissions\") or starts_with(http.request.uri.path, \"/api/v1/enqueue\") or starts_with(http.request.uri.path, \"/api/v1/requests\") or starts_with(http.request.uri.path, \"/requests/\"))","action":"block","enabled":true},{"id":"r-all","description":"stow maintenance: all","expression":"http.host eq \"stow.waterui.dev\"","action":"block","enabled":false}]}}"#;

    #[test]
    fn absent_entrypoint_decodes_as_10003_not_a_ruleset() {
        let envelope: CfResponse =
            serde_json::from_str(ENTRYPOINT_ABSENT).expect("decode absent envelope");
        assert_eq!(envelope.errors[0].code, 10003);
        assert!(envelope.result.is_none());
    }

    #[test]
    fn present_entrypoint_decodes_rules_by_description() {
        let envelope: CfResponse =
            serde_json::from_str(ENTRYPOINT_PRESENT).expect("decode present envelope");
        let ruleset: Ruleset =
            serde_json::from_value(envelope.result.expect("result")).expect("decode ruleset");
        assert_eq!(ruleset.id, "rs-1");
        let anon = find_rule(&ruleset, MaintenanceScope::Anonymous.description())
            .expect("anonymous rule present");
        assert_eq!(anon.id, "r-anon");
        assert!(!anon.enabled);
        assert!(find_rule(&ruleset, MaintenanceScope::All.description()).is_some());
        assert!(find_rule(&ruleset, "stow maintenance: mystery").is_none());
    }

    #[test]
    fn patch_body_carries_full_rule_spec() {
        let body = RuleBody {
            description: MaintenanceScope::Anonymous.description(),
            expression: &MaintenanceScope::Anonymous.expression("stow.waterui.dev"),
            action: "block",
            enabled: true,
        };
        let json = serde_json::to_value(&body).expect("serialize rule body");
        assert_eq!(json["action"], "block");
        assert_eq!(json["enabled"], true);
        assert!(
            json["expression"]
                .as_str()
                .expect("expression string")
                .contains("/api/v1/admin")
        );
        assert_eq!(json["description"], "stow maintenance: anonymous");
    }

    /// The anonymous carve-out keeps the trusted prefixes — the admin
    /// routes the breaker exists to keep, the scheduler lane the
    /// builder callbacks arrive on, and the GitHub webhook completions
    /// drain through.
    #[test]
    fn anonymous_expression_carves_out_trusted_prefixes() {
        let expression = MaintenanceScope::Anonymous.expression("stow.waterui.dev");
        for trusted in ["/api/v1/admin", "/api/v1/scheduler", "/api/v1/github"] {
            assert!(
                expression.contains(&format!(
                    "not starts_with(http.request.uri.path, \"{trusted}\")"
                )),
                "anonymous scope must not block {trusted}"
            );
        }
        assert!(expression.contains("stow.waterui.dev"));
    }

    /// The host in every expression is the `STOW_EDGE_URL` host — the
    /// rules must track whichever edge they were ensured against.
    #[test]
    fn expressions_take_the_host_of_the_edge_url() {
        for scope in ALL_SCOPES {
            let expression = scope.expression("edge.example.com");
            assert!(
                expression.contains("http.host eq \"edge.example.com\""),
                "{} expression must bind the given host: {expression}",
                scope.description()
            );
        }
        assert_eq!(
            host_from_url("https://stow.waterui.dev"),
            Ok("stow.waterui.dev".into())
        );
        assert_eq!(
            host_from_url("https://stow.waterui.dev:443/api"),
            Ok("stow.waterui.dev".into())
        );
        assert!(host_from_url("https:///pathless").is_err());
    }

    /// Every scheduler-lane route constant is covered by the `lanes`
    /// rule's `starts_with` clauses — a lane added to `ALL` without a
    /// matching clause would serve DO-backed traffic the rule promised
    /// to shed.
    #[test]
    fn lanes_expression_covers_every_scheduler_lane() {
        let expression = MaintenanceScope::Lanes.expression("stow.waterui.dev");
        let prefixes = lane_prefixes();
        for path in scheduler_lanes::ALL {
            assert!(
                prefixes.iter().any(|prefix| path.starts_with(prefix)),
                "lanes rule must shed {path}"
            );
        }
        for prefix in &prefixes {
            assert!(
                expression.contains(&format!("starts_with(http.request.uri.path, \"{prefix}\")")),
                "expression must carry the {prefix} clause: {expression}"
            );
        }
        assert!(
            !expression.contains("{task_id}"),
            "route params are prefixes on the wire: {expression}"
        );
    }

    /// `ensure` against an absent entrypoint plans all three rules;
    /// the dedupe by description is what a populated fixture feeds.
    #[test]
    fn wanted_rules_cover_every_scope_disabled() {
        let wanted = wanted_rules("edge.example.com");
        assert_eq!(wanted.len(), ALL_SCOPES.len());
        for (scope, expression) in &wanted {
            assert!(expression.contains("edge.example.com"));
            assert_ne!(scope.description(), "");
        }
    }
}

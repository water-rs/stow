//! R2 publishing and Cloudflare zone edge rules for the site's slim
//! cache-lookup index (stow#1688).
//!
//! `stow.waterui.dev` reads `https://stow-index.waterui.dev/v1/lookup/<target>.json`
//! directly from the public `stow-lookup` R2 bucket behind Cloudflare CDN,
//! bypassing the `stow-edge` Worker entirely. To protect the R2 free Class B
//! allowance against cache-busting and random-path probes, `ensure_rules`
//! maintains two zone rules on `waterui.dev`:
//!
//! - `stow lookup: allowlist` (`http_request_firewall_custom`) — blocks any
//!   request to the lookup host whose path is not one of the
//!   `CI_TARGET_TRIPLES` `/v1/lookup/<target>.json` files.
//! - `stow lookup: ignore query strings` (`http_request_cache_settings`) —
//!   excludes all query strings from the cache key on the lookup host so
//!   `?foo=bar` hits the same CDN entry instead of reaching R2.

use std::path::PathBuf;

use clap::Args;
use serde::{Deserialize, Serialize};
use stow_types::api::CI_TARGET_TRIPLES;
use stow_types::index::{LookupIndex, lookup_object_key};
use stow_types::stow_error;
use zenwave::{Client as _, ResponseExt as _};

use crate::cloudflare::{self, API_BASE};
use crate::maintenance::CF_ZONE_ID_ENV;
use crate::render;

/// Default R2 bucket holding the public lookup JSON files.
pub const DEFAULT_LOOKUP_BUCKET: &str = "stow-lookup";
/// Default custom domain serving [`DEFAULT_LOOKUP_BUCKET`].
pub const DEFAULT_LOOKUP_HOST: &str = "stow-index.waterui.dev";
/// `Cache-Control` stamped onto every uploaded lookup JSON object.
pub const LOOKUP_CACHE_CONTROL: &str = "public, max-age=300";

const CLOUDFLARE_ACCOUNT_ID_ENV: &str = "CLOUDFLARE_ACCOUNT_ID";
const CF_ACCOUNT_ID_ENV: &str = "CF_ACCOUNT_ID";

const WAF_PHASE: &str = "http_request_firewall_custom";
const CACHE_PHASE: &str = "http_request_cache_settings";

/// Stable description of the WAF allowlist rule on the lookup host.
pub const LOOKUP_WAF_RULE_DESCRIPTION: &str = "stow lookup: allowlist";
/// Stable description of the Cache Rule ignoring query strings on the lookup host.
pub const LOOKUP_CACHE_RULE_DESCRIPTION: &str = "stow lookup: ignore query strings";

/// `stow-admin index publish-lookup`: upload exported lookup JSON files to R2.
#[derive(Args)]
pub struct IndexPublishLookupArgs {
    /// Lookup JSON files (`index export --out-dir` wrote them) — repeatable.
    #[arg(long, required = true)]
    pub file: Vec<PathBuf>,
    /// Target R2 bucket name.
    #[arg(long, default_value = DEFAULT_LOOKUP_BUCKET)]
    pub bucket: String,
}

/// `stow-admin index sync-lookup`: pull live verified slices from GHCR for
/// one rustc and upload their deduplicated lookup JSON files to R2.
#[derive(Args)]
pub struct IndexSyncLookupArgs {
    /// Rustc version whose published slices are synced to R2.
    #[arg(long)]
    pub rustc_version: String,
    /// Target R2 bucket name.
    #[arg(long, default_value = DEFAULT_LOOKUP_BUCKET)]
    pub bucket: String,
}

/// `stow-admin index ensure-lookup-rules`: idempotently ensure the Cloudflare
/// WAF path allowlist and Cache Rule (ignore query strings) on the lookup host.
#[derive(Args)]
pub struct IndexEnsureLookupRulesArgs {
    /// Public custom domain fronting the R2 bucket.
    #[arg(long, default_value = DEFAULT_LOOKUP_HOST)]
    pub host: String,
    /// Apply mutations. Without `--yes`, prints the plan and exits 0.
    #[arg(long)]
    pub yes: bool,
}

/// JSON summary emitted per uploaded lookup object.
#[derive(Debug, Serialize)]
pub struct LookupUploadSummary {
    pub target: String,
    pub rustc_version: String,
    pub bucket: String,
    pub key: String,
    pub crates: u64,
    pub rows: u64,
    pub bytes: usize,
}

/// JSON summary emitted by `ensure-lookup-rules`.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct LookupRulesOutcome {
    pub host: String,
    pub applied: bool,
    pub waf: RuleAction,
    pub cache: RuleAction,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Unchanged,
    CreateRuleset,
    AddRule,
    UpdateRule,
}

/// WAF expression blocking any path on `host` outside `CI_TARGET_TRIPLES`'s
/// `/v1/lookup/<target>.json` files.
#[must_use]
pub fn lookup_waf_expression(host: &str) -> String {
    let clauses = CI_TARGET_TRIPLES
        .iter()
        .map(|target| {
            format!(
                "http.request.uri.path eq \"/{}\"",
                lookup_object_key(target)
            )
        })
        .collect::<Vec<_>>()
        .join(" or ");
    format!("http.host eq \"{host}\" and not ({clauses})")
}

/// Cache Rule expression matching all requests to `host`.
#[must_use]
pub fn lookup_cache_expression(host: &str) -> String {
    format!("http.host eq \"{host}\"")
}

/// Resolve the Cloudflare account id from `CLOUDFLARE_ACCOUNT_ID` or
/// `CF_ACCOUNT_ID`.
fn account_id_from_env() -> stow_types::error::Result<String> {
    std::env::var(CLOUDFLARE_ACCOUNT_ID_ENV)
        .or_else(|_| std::env::var(CF_ACCOUNT_ID_ENV))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| stow_error!("missing {CLOUDFLARE_ACCOUNT_ID_ENV} (or {CF_ACCOUNT_ID_ENV})"))
}

/// Upload one serialized [`LookupIndex`] to R2 through Cloudflare's v4 REST API.
pub async fn upload_lookup_index(
    lookup: &LookupIndex,
    bucket: &str,
) -> stow_types::error::Result<LookupUploadSummary> {
    let token = cloudflare::api_token()?;
    let account_id = account_id_from_env()?;
    upload_lookup_index_at(API_BASE, &token, &account_id, bucket, lookup).await
}

/// Upload one [`LookupIndex`] to `api_base` — production passes
/// [`cloudflare::API_BASE`], unit tests a loopback server.
async fn upload_lookup_index_at(
    api_base: &str,
    token: &str,
    account_id: &str,
    bucket: &str,
    lookup: &LookupIndex,
) -> stow_types::error::Result<LookupUploadSummary> {
    let target = lookup.header.target.as_str();
    let key = lookup_object_key(target);
    let body = serde_json::to_vec(lookup)
        .map_err(|error| stow_error!("serialize lookup index for {target}: {error}"))?;
    let url = format!(
        "{}/accounts/{account_id}/r2/buckets/{bucket}/objects/{key}",
        api_base.trim_end_matches('/')
    );
    let mut client = zenwave::client();
    let request = client
        .method(zenwave::Method::PUT, &url)
        .and_then(|req| req.header("Authorization", format!("Bearer {token}")))
        .and_then(|req| req.header("Content-Type", "application/json"))
        .and_then(|req| req.header("Cache-Control", LOOKUP_CACHE_CONTROL))
        .map_err(|error| stow_error!("build R2 PUT {url}: {error}"))?
        .bytes_body(body.clone());
    match request.await {
        Ok(response) => {
            let status = response.status().as_u16();
            if !(200..300).contains(&status) {
                let text = response.into_string().await.unwrap_or_default();
                return Err(stow_error!("R2 PUT {url}: HTTP {status} — {text}"));
            }
        }
        Err(zenwave::Error::Http {
            status, response, ..
        }) => {
            return Err(stow_error!(
                "R2 PUT {url}: HTTP {} — {}",
                status.as_u16(),
                response.body_text.unwrap_or_default()
            ));
        }
        Err(error) => return Err(stow_error!("R2 PUT {url}: {error}")),
    }
    Ok(LookupUploadSummary {
        target: target.to_owned(),
        rustc_version: lookup.header.rustc_version.as_str().to_owned(),
        bucket: bucket.to_owned(),
        key,
        crates: lookup.header.crate_count,
        rows: lookup.header.row_count,
        bytes: body.len(),
    })
}

/// Upload exported lookup JSON files from disk to R2.
pub async fn publish_lookup_files(args: IndexPublishLookupArgs) -> stow_types::error::Result<()> {
    let token = cloudflare::api_token()?;
    let account_id = account_id_from_env()?;
    for path in &args.file {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|error| stow_error!("read lookup {}: {error}", path.display()))?;
        let lookup: LookupIndex = serde_json::from_slice(&bytes)
            .map_err(|error| stow_error!("parse lookup {}: {error}", path.display()))?;
        let summary =
            upload_lookup_index_at(API_BASE, &token, &account_id, &args.bucket, &lookup).await?;
        let line = serde_json::to_string(&summary)
            .map_err(|error| stow_error!("serialize upload summary: {error}"))?;
        render::emit_line(&line);
    }
    Ok(())
}

/// Run `stow-admin index ensure-lookup-rules`.
pub async fn ensure_lookup_rules_cmd(
    args: IndexEnsureLookupRulesArgs,
) -> stow_types::error::Result<()> {
    let token = cloudflare::api_token()?;
    let zone_id =
        std::env::var(CF_ZONE_ID_ENV).map_err(|_| stow_error!("missing {CF_ZONE_ID_ENV}"))?;
    let outcome = ensure_lookup_rules_at(API_BASE, &token, &zone_id, &args.host, args.yes)
        .await
        .map_err(|error| stow_error!("{error}"))?;
    let line = serde_json::to_string(&outcome)
        .map_err(|error| stow_error!("serialize lookup rules outcome: {error}"))?;
    render::emit_line(&line);
    Ok(())
}

// ===== Cloudflare Rulesets API =====

#[derive(Debug, Deserialize)]
struct CfResponse {
    #[serde(default)]
    errors: Vec<CfError>,
    result: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct CfError {
    code: u32,
    message: String,
}

#[derive(Debug, Deserialize)]
struct Ruleset {
    id: String,
    #[serde(default)]
    rules: Vec<ZoneRule>,
}

#[derive(Debug, Deserialize)]
struct ZoneRule {
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    expression: String,
    #[serde(default)]
    action: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    action_parameters: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct RuleBody<'a> {
    description: &'a str,
    expression: &'a str,
    action: &'a str,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_parameters: Option<&'a serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct RulesetBody<'a> {
    name: &'a str,
    kind: &'a str,
    phase: &'a str,
    rules: Vec<RuleBody<'a>>,
}

async fn cf_json_request(
    token: &str,
    method: zenwave::Method,
    url: &str,
    body: Option<&(impl Serialize + Sync)>,
) -> Result<(u16, CfResponse), String> {
    let mut client = zenwave::client();
    let builder = client
        .method(method, url)
        .and_then(|req| req.header("Authorization", format!("Bearer {token}")))
        .and_then(|req| match body {
            Some(body) => req.json_body(body),
            None => Ok(req),
        })
        .map_err(|error| format!("build {url}: {error}"))?;
    let (status, text) = match builder.await {
        Ok(response) => {
            let status = response.status().as_u16();
            let text = response
                .into_string()
                .await
                .map_err(|error| format!("read {url} body: {error}"))?;
            (status, text)
        }
        Err(zenwave::Error::Http {
            status, response, ..
        }) => (
            status.as_u16(),
            response.body_text.unwrap_or_default().into(),
        ),
        Err(error) => return Err(format!("{url}: {error}")),
    };
    let envelope: CfResponse = serde_json::from_str(text.as_ref())
        .map_err(|error| format!("decode {url} ({status}): {error} — {text}"))?;
    let absent = status == 404
        && !envelope.errors.is_empty()
        && envelope.errors.iter().all(|error| error.code == 10003);
    if let Some(error) = envelope.errors.first() {
        if !absent {
            return Err(format!("{url}: API error {} {}", error.code, error.message));
        }
    } else if status == 404 {
        return Err(format!(
            "{url}: HTTP 404 without the absent-entrypoint errors"
        ));
    }
    Ok((status, envelope))
}

async fn ensure_single_rule(
    api_base: &str,
    token: &str,
    zone_id: &str,
    phase: &str,
    ruleset_name: &str,
    wanted: &RuleBody<'_>,
    apply: bool,
) -> Result<RuleAction, String> {
    let base = api_base.trim_end_matches('/');
    let entrypoint_url = format!("{base}/zones/{zone_id}/rulesets/phases/{phase}/entrypoint");
    let (status, envelope) =
        cf_json_request(token, zenwave::Method::GET, &entrypoint_url, None::<&u8>).await?;
    if status == 404 {
        if apply {
            let body = RulesetBody {
                name: ruleset_name,
                kind: "zone",
                phase,
                rules: vec![RuleBody {
                    description: wanted.description,
                    expression: wanted.expression,
                    action: wanted.action,
                    enabled: wanted.enabled,
                    action_parameters: wanted.action_parameters,
                }],
            };
            let url = format!("{base}/zones/{zone_id}/rulesets");
            let (create_status, _) =
                cf_json_request(token, zenwave::Method::POST, &url, Some(&body)).await?;
            if !(200..300).contains(&create_status) {
                return Err(format!("{url}: HTTP {create_status}"));
            }
        }
        return Ok(RuleAction::CreateRuleset);
    }
    if !(200..300).contains(&status) {
        return Err(format!("{entrypoint_url}: HTTP {status}"));
    }
    let result = envelope
        .result
        .ok_or_else(|| format!("{entrypoint_url}: empty result"))?;
    let ruleset: Ruleset =
        serde_json::from_value(result).map_err(|error| format!("decode ruleset: {error}"))?;

    let existing = ruleset
        .rules
        .iter()
        .find(|rule| rule.description == wanted.description);
    match existing {
        None => {
            if apply {
                let url = format!("{base}/zones/{zone_id}/rulesets/{}/rules", ruleset.id);
                let (add_status, _) =
                    cf_json_request(token, zenwave::Method::POST, &url, Some(wanted)).await?;
                if !(200..300).contains(&add_status) {
                    return Err(format!("{url}: HTTP {add_status}"));
                }
            }
            Ok(RuleAction::AddRule)
        }
        Some(rule) => {
            let params_match = match (wanted.action_parameters, &rule.action_parameters) {
                (None, None) => true,
                (Some(expected), Some(actual)) => expected == actual,
                _ => false,
            };
            if rule.expression == wanted.expression
                && rule.action == wanted.action
                && rule.enabled == wanted.enabled
                && params_match
            {
                return Ok(RuleAction::Unchanged);
            }
            if apply {
                let url = format!(
                    "{base}/zones/{zone_id}/rulesets/{}/rules/{}",
                    ruleset.id, rule.id
                );
                let (patch_status, _) =
                    cf_json_request(token, zenwave::Method::PATCH, &url, Some(wanted)).await?;
                if !(200..300).contains(&patch_status) {
                    return Err(format!("{url}: HTTP {patch_status}"));
                }
            }
            Ok(RuleAction::UpdateRule)
        }
    }
}

/// Ensure both edge protection rules for `host` on `zone_id`.
pub async fn ensure_lookup_rules_at(
    api_base: &str,
    token: &str,
    zone_id: &str,
    host: &str,
    apply: bool,
) -> Result<LookupRulesOutcome, String> {
    let waf_expr = lookup_waf_expression(host);
    let waf_rule = RuleBody {
        description: LOOKUP_WAF_RULE_DESCRIPTION,
        expression: &waf_expr,
        action: "block",
        enabled: true,
        action_parameters: None,
    };
    let waf = ensure_single_rule(
        api_base,
        token,
        zone_id,
        WAF_PHASE,
        "stow lookup",
        &waf_rule,
        apply,
    )
    .await?;

    let cache_expr = lookup_cache_expression(host);
    let cache_params = serde_json::json!({
        "cache": true,
        "cache_key": {
            "custom_key": {
                "query_string": {
                    "exclude": {
                        "all": true
                    }
                }
            }
        }
    });
    let cache_rule = RuleBody {
        description: LOOKUP_CACHE_RULE_DESCRIPTION,
        expression: &cache_expr,
        action: "set_cache_settings",
        enabled: true,
        action_parameters: Some(&cache_params),
    };
    let cache = ensure_single_rule(
        api_base,
        token,
        zone_id,
        CACHE_PHASE,
        "stow lookup cache",
        &cache_rule,
        apply,
    )
    .await?;

    Ok(LookupRulesOutcome {
        host: host.to_owned(),
        applied: apply,
        waf,
        cache,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use stow_types::api::CI_TARGET_TRIPLES;
    use stow_types::identity::{TargetTriple, WireRustcVersion};
    use stow_types::index::{LOOKUP_INDEX_FORMAT_VERSION, LookupIndex, LookupIndexHeader};

    use super::{
        LOOKUP_CACHE_CONTROL, LOOKUP_CACHE_RULE_DESCRIPTION, LOOKUP_WAF_RULE_DESCRIPTION,
        RuleAction, ensure_lookup_rules_at, lookup_waf_expression, upload_lookup_index_at,
    };
    use crate::test_server::{Loopback, Step};

    #[test]
    fn waf_expression_allowlists_every_ci_target() {
        let expr = lookup_waf_expression("stow-index.waterui.dev");
        assert!(expr.starts_with(r#"http.host eq "stow-index.waterui.dev" and not ("#));
        for target in CI_TARGET_TRIPLES {
            assert!(
                expr.contains(&format!(
                    r#"http.request.uri.path eq "/v1/lookup/{target}.json""#
                )),
                "missing {target} in {expr}"
            );
        }
    }

    #[tokio::test]
    async fn upload_lookup_index_puts_json_with_cache_control() {
        let server = Loopback::start(vec![Step::Respond {
            status: 200,
            retry_after: None,
            body: r#"{"success":true}"#,
        }])
        .await;
        let mut crates = BTreeMap::new();
        let mut versions = BTreeMap::new();
        let mut feats = BTreeMap::new();
        feats.insert("default".to_owned(), 4096_u64);
        versions.insert("1.0.219".to_owned(), feats);
        crates.insert("serde".to_owned(), versions);
        let lookup = LookupIndex {
            header: LookupIndexHeader {
                format_version: LOOKUP_INDEX_FORMAT_VERSION,
                target: TargetTriple::parse("x86_64-unknown-linux-gnu").expect("target"),
                rustc_version: WireRustcVersion::parse("1.100.0").expect("rustc"),
                generated_at: "2026-11-24T00:00:00Z".to_owned(),
                generation: 10,
                crate_count: 1,
                row_count: 4,
            },
            crates,
        };

        let summary =
            upload_lookup_index_at(&server.url, "cf-secret", "acct-1", "stow-lookup", &lookup)
                .await
                .expect("upload succeeds");
        assert_eq!(summary.key, "v1/lookup/x86_64-unknown-linux-gnu.json");
        assert_eq!(summary.crates, 1);

        let captured = server.join().await;
        assert_eq!(captured.len(), 1);
        let req = &captured[0];
        assert_eq!(req.head.method, "PUT");
        assert_eq!(
            req.head.uri.path(),
            "/accounts/acct-1/r2/buckets/stow-lookup/objects/v1/lookup/x86_64-unknown-linux-gnu.json"
        );
        assert_eq!(
            req.head
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
            Some("Bearer cf-secret")
        );
        assert_eq!(
            req.head
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            req.head
                .headers
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some(LOOKUP_CACHE_CONTROL)
        );
        let reparsed: LookupIndex = serde_json::from_slice(&req.body).expect("body parses");
        assert_eq!(reparsed, lookup);
    }

    #[tokio::test]
    async fn ensure_lookup_rules_appends_waf_and_creates_cache_ruleset() {
        let server = Loopback::start(vec![
            // WAF entrypoint exists with maintenance rules only
            Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"result":{"id":"waf-rs","rules":[{"id":"r1","description":"stow maintenance: all","expression":"http.host eq \"stow.waterui.dev\"","action":"block","enabled":false}]}}"#,
            },
            // POST new WAF rule
            Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"result":{"id":"waf-rs"}}"#,
            },
            // Cache rules entrypoint absent (10003)
            Step::Respond {
                status: 404,
                retry_after: None,
                body: r#"{"errors":[{"code":10003,"message":"could not find entrypoint ruleset"}]}"#,
            },
            // POST new cache ruleset
            Step::Respond {
                status: 200,
                retry_after: None,
                body: r#"{"result":{"id":"cache-rs"}}"#,
            },
        ])
        .await;

        let outcome = ensure_lookup_rules_at(
            &server.url,
            "cf-secret",
            "zone-1",
            "stow-index.waterui.dev",
            true,
        )
        .await
        .expect("ensure succeeds");
        assert_eq!(outcome.waf, RuleAction::AddRule);
        assert_eq!(outcome.cache, RuleAction::CreateRuleset);

        let captured = server.join().await;
        assert_eq!(captured.len(), 4);
        assert_eq!(captured[1].head.method, "POST");
        assert_eq!(
            captured[1].head.uri.path(),
            "/zones/zone-1/rulesets/waf-rs/rules"
        );
        let waf_body: serde_json::Value =
            serde_json::from_slice(&captured[1].body).expect("waf json");
        assert_eq!(waf_body["description"], LOOKUP_WAF_RULE_DESCRIPTION);
        assert_eq!(waf_body["enabled"], true);

        assert_eq!(captured[3].head.method, "POST");
        assert_eq!(captured[3].head.uri.path(), "/zones/zone-1/rulesets");
        let cache_body: serde_json::Value =
            serde_json::from_slice(&captured[3].body).expect("cache json");
        assert_eq!(cache_body["phase"], "http_request_cache_settings");
        assert_eq!(
            cache_body["rules"][0]["description"],
            LOOKUP_CACHE_RULE_DESCRIPTION
        );
        assert_eq!(
            cache_body["rules"][0]["action_parameters"]["cache_key"]["custom_key"]["query_string"]
                ["exclude"]["all"],
            true
        );
    }
}

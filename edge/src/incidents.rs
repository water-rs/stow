//! The GitHub `incident`-issue alert channel and the fan-out that pairs
//! it with the email notify — #279/#438 alerts go to both.
//!
//! Every incident is one open issue in `GITHUB_REPO` labelled
//! `incident`, found by the stable title prefix `[incident] {key}:` —
//! a re-engaged incident comments on its existing issue rather than
//! opening a duplicate, and a cleared incident comments and closes.
//!
//! The edge authenticates as the GitHub App installation token it
//! already mints for dispatch (`github_app::installation_token`, cached
//! in DO storage). The token carries whatever the App installation
//! grants — nothing in this code can ask for `issues: write`, so a
//! missing grant surfaces as a `403` `Failed` outcome naming the
//! permission instead of being worked around.
//!
//! Channels never block each other: [`EdgeAlerter`] sends the email
//! first, then runs the issue call with the email's failure (when any)
//! annotated into the issue body — the spec's "a channel's failure is
//! recorded in the issue".

use serde::{Deserialize, Serialize};
use skyzen_cloudflare::worker::send::{IntoSendFuture as _, SendWrapper};
use wasm_bindgen::JsValue;

use stow_types::api::{AlertOutcome, ChannelOutcome};

use crate::env_binding;
use crate::freeze::{AlertDraft, AlertSink};
use crate::github_app::{self, AppConfig};
use skyzen_services::durable::DurableDb;

/// The REST API root every call hits.
const GITHUB_API: &str = "https://api.github.com";
/// The label every incident issue carries — the open-issue lookup
/// filters on it plus the title prefix.
const INCIDENT_LABEL: &str = "incident";
/// The title prefix every incident issue shares — `[incident] {key}:`.
const INCIDENT_PREFIX: &str = "[incident]";

/// `GITHUB_REPO` — `water-rs/stow` — the repo incident issues live in.
const GITHUB_REPO_BINDING: &str = "GITHUB_REPO";
/// The App credential bindings `installation_token` mints from.
const GITHUB_APP_ID_BINDING: &str = "GITHUB_APP_ID";
const GITHUB_APP_INSTALLATION_ID_BINDING: &str = "GITHUB_APP_INSTALLATION_ID";
const GITHUB_APP_PRIVATE_KEY_BINDING: &str = "GITHUB_APP_PRIVATE_KEY";

/// One open (or just-mutated) issue the API returned.
#[derive(Debug, Clone, Deserialize)]
struct IssueRow {
    /// Issue number, for comment/close calls.
    number: u64,
    /// `html_url` — the link the outcome and alert bodies carry.
    html_url: String,
    /// Title, for the prefix dedup check.
    title: String,
    /// Present iff the row is a pull request — the issues listing
    /// returns PRs too.
    #[serde(default)]
    pull_request: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct CreateIssue<'a> {
    title: &'a str,
    body: &'a str,
    labels: [&'static str; 1],
}

#[derive(Debug, Serialize)]
struct CreateComment<'a> {
    body: &'a str,
}

#[derive(Debug, Serialize)]
struct PatchIssue<'a> {
    state: &'a str,
}

/// The GitHub issues channel: an installation token plus the repo the
/// incidents live in.
pub struct GitHubIssues {
    token: String,
    repo: String,
}

/// Turn a failed HTTP status into the recorded outcome, attaching the
/// `issues: write` hint a permission failure points at.
fn status_failed(status: u16, body: &str) -> ChannelOutcome {
    ChannelOutcome::Failed {
        message: format!("github api returned {status}: {}", truncate(body, 300)),
        hint: (status == 403).then(|| {
            "the GitHub App installation needs Issues: write on the repo — grant it \
             under the app's permissions and re-save the installation"
                .to_owned()
        }),
    }
}

fn truncate(body: &str, max: usize) -> &str {
    body.get(..max).unwrap_or(body)
}

/// The dedup prefix a draft's incident key renders to — every title
/// this channel writes starts with it.
fn title_prefix(key: &str) -> String {
    format!("{INCIDENT_PREFIX} {key}:")
}

impl GitHubIssues {
    /// One JSON API call — `GET`/`POST`/`PATCH` against
    /// `api.github.com/repos/{repo}/…` with the installation token.
    /// Outcomes are data, not errors: every failure shape returns a
    /// `ChannelOutcome` so the caller's state transition always lands.
    async fn request<T: for<'de> Deserialize<'de>>(
        &self,
        method: skyzen_cloudflare::worker::Method,
        path: &str,
        body: Option<String>,
    ) -> Result<T, ChannelOutcome> {
        let url = format!("{GITHUB_API}/repos/{}/{path}", self.repo);
        let authorization = format!("Bearer {}", self.token);
        let request = crate::cf_http::bare_request(
            method,
            &url,
            &[
                ("Authorization", authorization.as_str()),
                ("Accept", "application/vnd.github+json"),
                ("X-GitHub-Api-Version", "2022-11-28"),
                ("User-Agent", "stow-incidents"),
            ],
            body.as_deref().map(str::as_bytes),
        )
        .map_err(|error| ChannelOutcome::Failed {
            message: format!("build github request: {error}"),
            hint: None,
        })?;
        let mut response =
            SendWrapper::new(skyzen_cloudflare::CfFetch.request(&request).await.map_err(
                |error| ChannelOutcome::Failed {
                    message: format!("github api fetch: {error}"),
                    hint: None,
                },
            )?);
        let status = response.status_code();
        if !(200..300).contains(&status) {
            let body = response
                .text()
                .into_send()
                .await
                .unwrap_or_else(|_| "<unreadable body>".to_owned());
            return Err(status_failed(status, &body));
        }
        response
            .json()
            .into_send()
            .await
            .map_err(|error| ChannelOutcome::Failed {
                message: format!("decode github response: {error}"),
                hint: None,
            })
    }

    /// The open incident issue for `key`, if one exists — matched by
    /// `incident` label + the stable `[incident] {key}:` title prefix.
    /// Pull requests leaking into the issues listing are skipped.
    async fn find_open(&self, key: &str) -> Result<Option<IssueRow>, ChannelOutcome> {
        let rows: Vec<IssueRow> = self
            .request(
                skyzen_cloudflare::worker::Method::Get,
                &format!("issues?state=open&labels={INCIDENT_LABEL}&per_page=100"),
                None,
            )
            .await?;
        let prefix = title_prefix(key);
        Ok(rows
            .into_iter()
            .find(|row| row.pull_request.is_none() && row.title.starts_with(&prefix)))
    }

    /// `POST /issues` — create the incident issue.
    async fn create(&self, draft: &AlertDraft) -> Result<IssueRow, ChannelOutcome> {
        let body = serde_json::to_string(&CreateIssue {
            title: &draft.title,
            body: &draft.body,
            labels: [INCIDENT_LABEL],
        })
        .map_err(|error| ChannelOutcome::Failed {
            message: format!("serialize create-issue body: {error}"),
            hint: None,
        })?;
        self.request(
            skyzen_cloudflare::worker::Method::Post,
            "issues",
            Some(body),
        )
        .await
    }

    /// `POST /issues/{n}/comments`.
    async fn comment(&self, number: u64, body: &str) -> Result<(), ChannelOutcome> {
        let body = serde_json::to_string(&CreateComment { body }).map_err(|error| {
            ChannelOutcome::Failed {
                message: format!("serialize comment body: {error}"),
                hint: None,
            }
        })?;
        let _: serde_json::Value = self
            .request(
                skyzen_cloudflare::worker::Method::Post,
                &format!("issues/{number}/comments"),
                Some(body),
            )
            .await?;
        Ok(())
    }

    /// `PATCH /issues/{n}` with `state: closed`.
    async fn close(&self, number: u64) -> Result<(), ChannelOutcome> {
        let body = serde_json::to_string(&PatchIssue { state: "closed" }).map_err(|error| {
            ChannelOutcome::Failed {
                message: format!("serialize close body: {error}"),
                hint: None,
            }
        })?;
        let _: serde_json::Value = self
            .request(
                skyzen_cloudflare::worker::Method::Patch,
                &format!("issues/{number}"),
                Some(body),
            )
            .await?;
        Ok(())
    }

    /// An incident opened: reuse the open issue for its key (a
    /// re-engaged incident comments) or create it.
    pub async fn opened(&self, draft: &AlertDraft) -> ChannelOutcome {
        match self.find_open(draft.key).await {
            Err(outcome) => outcome,
            Ok(Some(issue)) => match self.comment(issue.number, &draft.body).await {
                Ok(()) => ChannelOutcome::Commented {
                    url: issue.html_url,
                },
                Err(outcome) => outcome,
            },
            Ok(None) => match self.create(draft).await {
                Ok(issue) => ChannelOutcome::Opened {
                    url: issue.html_url,
                },
                Err(outcome) => outcome,
            },
        }
    }

    /// A still-open incident update: the hourly digest comment.
    /// If the issue is gone (a human closed it mid-incident) it is
    /// recreated — an open incident is owed an open record.
    pub async fn updated(&self, draft: &AlertDraft) -> ChannelOutcome {
        match self.find_open(draft.key).await {
            Err(outcome) => outcome,
            Ok(Some(issue)) => match self.comment(issue.number, &draft.body).await {
                Ok(()) => ChannelOutcome::Commented {
                    url: issue.html_url,
                },
                Err(outcome) => outcome,
            },
            Ok(None) => match self.create(draft).await {
                Ok(issue) => ChannelOutcome::Opened {
                    url: issue.html_url,
                },
                Err(outcome) => outcome,
            },
        }
    }

    /// The incident cleared: comment the resolve body and close the
    /// issue. No open issue means the record is already gone — the
    /// resolve is a no-op the record still notes.
    pub async fn resolved(&self, draft: &AlertDraft) -> ChannelOutcome {
        match self.find_open(draft.key).await {
            Err(outcome) => outcome,
            Ok(None) => ChannelOutcome::Disabled {
                reason: format!(
                    "no open `incident` issue matching '{}' to resolve",
                    title_prefix(draft.key)
                ),
            },
            Ok(Some(issue)) => {
                if let Err(outcome) = self.comment(issue.number, &draft.body).await {
                    return outcome;
                }
                match self.close(issue.number).await {
                    Ok(()) => ChannelOutcome::Resolved {
                        url: issue.html_url,
                    },
                    Err(outcome) => outcome,
                }
            }
        }
    }
}

/// Build the issues channel inside the scheduler object — the
/// installation token comes from the DO's cached mint. A missing
/// App binding or repo name resolves to `Disabled`; a failed mint to
/// `Failed`.
pub async fn for_object(db: &DurableDb, env: &JsValue) -> Result<GitHubIssues, ChannelOutcome> {
    let Some(repo) = env_binding::optional_string(env, GITHUB_REPO_BINDING) else {
        return Err(ChannelOutcome::Disabled {
            reason: format!("'{GITHUB_REPO_BINDING}' binding is not set"),
        });
    };
    let config = app_config(env)?;
    let token = github_app::installation_token(db, &config)
        .await
        .map_err(|error| ChannelOutcome::Failed {
            message: format!("mint installation token: {error}"),
            hint: None,
        })?
        .token;
    Ok(GitHubIssues { token, repo })
}

/// Build the issues channel from the Worker's side (the scheduled
/// handler, where there is no DO token cache) — mints an uncached
/// installation token per call; alert failures are rare enough that
/// the extra exchange costs nothing.
pub async fn for_worker(env: &JsValue) -> Result<GitHubIssues, ChannelOutcome> {
    let Some(repo) = env_binding::optional_string(env, GITHUB_REPO_BINDING) else {
        return Err(ChannelOutcome::Disabled {
            reason: format!("'{GITHUB_REPO_BINDING}' binding is not set"),
        });
    };
    let config = app_config(env)?;
    let token = github_app::mint_installation_token(&config)
        .await
        .map_err(|error| ChannelOutcome::Failed {
            message: format!("mint installation token: {error}"),
            hint: None,
        })?
        .token;
    Ok(GitHubIssues { token, repo })
}

/// Resolve the App bindings — all three or `Disabled` naming the first
/// absent one.
fn app_config(env: &JsValue) -> Result<AppConfig, ChannelOutcome> {
    let read = |binding: &str| -> Result<String, ChannelOutcome> {
        env_binding::optional_string(env, binding).ok_or_else(|| ChannelOutcome::Disabled {
            reason: format!("'{binding}' binding is not set"),
        })
    };
    Ok(AppConfig {
        app_id: read(GITHUB_APP_ID_BINDING)?,
        installation_id: read(GITHUB_APP_INSTALLATION_ID_BINDING)?,
        private_key_pem: read(GITHUB_APP_PRIVATE_KEY_BINDING)?,
    })
}

/// Append the email channel's failure to the draft's body — the
/// "recorded in the issue" half of the fan-out rule.
fn annotate_email_failure(draft: &AlertDraft, email: &ChannelOutcome) -> AlertDraft {
    let ChannelOutcome::Failed { message, hint } = email else {
        return draft.clone();
    };
    let mut annotated = draft.clone();
    annotated.body = format!(
        "{}\n\n> **Alert note:** the email copy of this alert failed: {message}{}",
        draft.body,
        hint.as_deref()
            .map_or(String::new(), |hint| format!(" — {hint}")),
    );
    annotated
}

/// The two-channel alert sink the object and the scheduled handler use:
/// an [`crate::email::AlertConfig`] for the notify and a
/// [`GitHubIssues`] for the record, each independently fallible.
pub struct EdgeAlerter {
    email: Result<crate::email::AlertConfig, ChannelOutcome>,
    issues: Result<GitHubIssues, ChannelOutcome>,
}

impl EdgeAlerter {
    /// Resolve both channels once against the object context.
    pub async fn for_object(db: &DurableDb, env: &JsValue) -> Self {
        Self {
            email: crate::email::alert_config(env),
            issues: for_object(db, env).await,
        }
    }

    /// Resolve both channels from the Worker's scheduled context —
    /// the issues channel mints uncached here.
    pub async fn for_worker(env: &JsValue) -> Self {
        Self {
            email: crate::email::alert_config(env),
            issues: for_worker(env).await,
        }
    }

    /// Run `side` (the issues call shape differs per verb) after the
    /// email; the email failure is annotated into the issue body.
    async fn fan_out(
        &self,
        draft: &AlertDraft,
        issue_call: impl AsyncFnOnce(&GitHubIssues, &AlertDraft) -> ChannelOutcome,
    ) -> AlertOutcome {
        let email = match &self.email {
            Ok(config) => {
                crate::email::send_alert(config, &draft.subject, &draft.body, &draft.html).await
            }
            Err(outcome) => outcome.clone(),
        };
        let issue_draft = annotate_email_failure(draft, &email);
        let issue = match &self.issues {
            Ok(issues) => issue_call(issues, &issue_draft).await,
            Err(outcome) => outcome.clone(),
        };
        AlertOutcome { email, issue }
    }
}

impl AlertSink for EdgeAlerter {
    fn opened(&self, draft: &AlertDraft) -> impl Future<Output = AlertOutcome> + Send {
        self.fan_out(draft, async |issues, draft| issues.opened(draft).await)
    }
    fn updated(&self, draft: &AlertDraft) -> impl Future<Output = AlertOutcome> + Send {
        self.fan_out(draft, async |issues, draft| issues.updated(draft).await)
    }
    fn resolved(&self, draft: &AlertDraft) -> impl Future<Output = AlertOutcome> + Send {
        self.fan_out(draft, async |issues, draft| issues.resolved(draft).await)
    }
}

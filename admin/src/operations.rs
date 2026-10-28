//! The traced operator path (stow#955): outside GitHub Actions, every
//! mutating `stow-admin` command dispatches `operations.yml` on `main`
//! with the operator's `stow-admin login` token and follows the run to
//! its end. The run's OIDC token is the only credential the edge's
//! operator routes accept, and the run is the record. Inside Actions,
//! or against the mock stack where the bearer is already a minted JWT,
//! commands call the edge directly.

use std::collections::BTreeMap;
use std::time::Duration;

use stow_types::stow_error;
use stow_types::transient::Backoff;

use crate::github;

/// The workflow file that performs every operator mutation.
pub const WORKFLOW: &str = "operations.yml";

/// Where the workflow writes the carried files — the replayed argv names
/// each file under it.
pub const FILES_DIR: &str = "/tmp/stow-ops-files";

/// How long a dispatched run may take before the follow gives up — the
/// workflow's `timeout-minutes` plus queueing slack.
const RUN_DEADLINE: Duration = Duration::from_mins(75);

/// The interval between two reads of the followed run.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// A command to replay inside `operations.yml`: its arguments, and the
/// local files they named, keyed by the bare name the workflow writes
/// each under [`FILES_DIR`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Dispatch {
    argv: Vec<String>,
    files: BTreeMap<String, String>,
}

impl Dispatch {
    /// The `dispatches` request body: `main`, the inputs `operations.yml`
    /// declares, and `return_run_details` so GitHub answers with the
    /// run it created.
    #[must_use]
    pub fn body(&self) -> serde_json::Value {
        let mut inputs = serde_json::json!({
            "argv": serde_json::to_string(&self.argv).expect("argv serializes"),
        });
        if !self.files.is_empty() {
            inputs["files"] =
                serde_json::Value::from(serde_json::to_string(&self.files).expect("files"));
        }
        serde_json::json!({
            "ref": "main",
            "inputs": inputs,
            "return_run_details": true,
        })
    }

    /// Replace the value of `flag` (`--flag value` or `--flag=value`)
    /// with the path the workflow writes that file's contents at.
    ///
    /// # Errors
    /// `stow_error` when the file is unreadable, has no plain file name,
    /// or shares its name with another carried file.
    fn carry(&mut self, flag: &str) -> stow_types::error::Result<()> {
        let inline = format!("{flag}=");
        let Some(index) = self
            .argv
            .iter()
            .position(|arg| arg == flag || arg.starts_with(&inline))
        else {
            return Ok(());
        };
        let path = match self.argv[index].strip_prefix(&inline) {
            Some(path) => path.to_owned(),
            None => self
                .argv
                .get(index + 1)
                .cloned()
                .ok_or_else(|| stow_error!("{flag} needs a value"))?,
        };
        let content = std::fs::read_to_string(&path)
            .map_err(|error| stow_error!("{flag} {path}: {error}"))?;
        let name = std::path::Path::new(&path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| stow_error!("{flag} {path}: no file name"))?
            .to_owned();
        if self.files.insert(name.clone(), content).is_some() {
            return Err(stow_error!(
                "{flag} {path}: another carried file is also named {name}"
            ));
        }
        let carried = format!("{FILES_DIR}/{name}");
        if self.argv[index] == flag {
            self.argv[index + 1] = carried;
        } else {
            self.argv[index] = format!("{inline}{carried}");
        }
        Ok(())
    }
}

/// Whether this invocation reaches the edge with an Actions OIDC
/// identity — inside Actions (`ACTIONS_ID_TOKEN_REQUEST_*`), or on the
/// mock stack, whose scripts export a mock-minted JWT as `GH_TOKEN` /
/// `GITHUB_TOKEN`. A `stow-admin login` token never parses as a JWT, so
/// it always takes the traced path.
fn has_oidc_credential() -> bool {
    crate::actions_oidc_available()
        || ["GH_TOKEN", "GITHUB_TOKEN"]
            .iter()
            .any(|name| std::env::var(name).is_ok_and(|token| looks_like_jwt(&token)))
}

/// Three dot-separated segments, the first a base64url JSON object —
/// enough to tell a JWT from GitHub's prefixed tokens; the edge does
/// the verifying.
fn looks_like_jwt(token: &str) -> bool {
    token.starts_with("eyJ") && token.split('.').count() == 3
}

/// The traced dispatch `command` needs, or `None` to run it here:
/// read-only commands, the mock-only budget probe, the workflow legs
/// (`request resolve`, `index report`, `deploy`) and every invocation
/// that already holds an OIDC credential. `args` is the process argv
/// minus the program name; the global `--json` flag is dropped, since
/// the operator's result is the run's conclusion.
pub fn traced(
    command: &crate::Command,
    args: impl IntoIterator<Item = String>,
) -> Option<stow_types::error::Result<Dispatch>> {
    if has_oidc_credential() {
        return None;
    }
    let mut dispatch = Dispatch {
        argv: args.into_iter().filter(|arg| arg != "--json").collect(),
        files: BTreeMap::new(),
    };
    let carried: &[&str] = match command {
        crate::Command::Scheduler(a) => match &a.command {
            crate::scheduler::SchedulerCommand::Reset { yes } if *yes => &[],
            crate::scheduler::SchedulerCommand::DemandFeed { .. } => &[],
            _ => return None,
        },
        crate::Command::Queue(a) => match &a.command {
            crate::queue::QueueCommand::Retry(a)
            | crate::queue::QueueCommand::Cancel(a)
            | crate::queue::QueueCommand::Promote(a)
            | crate::queue::QueueCommand::Purge(a)
                if a.yes =>
            {
                &[]
            }
            _ => return None,
        },
        crate::Command::DispatchFreeze(a)
            if a.yes && !matches!(a.action, crate::DispatchFreezeAction::Status) =>
        {
            &[]
        }
        crate::Command::Submit(a) if a.yes => &[],
        crate::Command::Maintenance(_) => &[],
        crate::Command::Watchdog(a) if !a.dry_run => &[],
        crate::Command::Preheat(a) => match &a.command {
            crate::preheat::PreheatCommand::Binary(a) if a.yes => &[],
            crate::preheat::PreheatCommand::TopBinaries(a) if a.yes => &[],
            crate::preheat::PreheatCommand::Missed(a) if a.yes => &[],
            crate::preheat::PreheatCommand::Manual(a) if a.yes => {
                if a.dirs.is_some() {
                    return Some(Err(stow_error!(
                        "preheat manual --dirs resolves directories on this machine, which \
                         {WORKFLOW} cannot see — submit the same crates with --crates or \
                         --projects"
                    )));
                }
                &["--crates", "--projects", "--source-trees"]
            }
            crate::preheat::PreheatCommand::Projects(a) => match &a.command {
                crate::projects::ProjectsCommand::Submit(a) if a.yes => &[],
                _ => return None,
            },
            _ => return None,
        },
        _ => return None,
    };
    Some(
        carried
            .iter()
            .try_for_each(|flag| dispatch.carry(flag))
            .map(|()| dispatch),
    )
}

/// The traced path still requires the operator to name the edge, as a
/// direct call does — an invocation with no edge fails before anything
/// leaves the machine. `operations.yml` acts on the production edge
/// whatever `STOW_EDGE_URL` says, so a traced command aimed at a
/// loopback (mock) edge would reach production instead; the mock's
/// mutating routes take a mock-issued JWT in `GH_TOKEN`, which keeps
/// such a command off this path.
fn refuse_loopback_edge(edge_url: Option<&str>) -> stow_types::error::Result<()> {
    let edge_url = edge_url.ok_or_else(|| stow_error!("missing {}", crate::STOW_EDGE_URL_ENV))?;
    let url = url::Url::parse(edge_url)
        .map_err(|error| stow_error!("STOW_EDGE_URL {edge_url}: {error}"))?;
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback() || ip.is_unspecified(),
        None => false,
    };
    if loopback {
        return Err(stow_error!(
            "STOW_EDGE_URL {edge_url} is a local edge, but this command would dispatch \
             {WORKFLOW} against production — on the mock stack, set GH_TOKEN to a token \
             the mock registry minted at /oidc/token"
        ));
    }
    Ok(())
}

/// GitHub's answer to a dispatch with `return_run_details`.
#[derive(Debug, serde::Deserialize)]
struct DispatchedRun {
    workflow_run_id: u64,
    html_url: String,
}

#[derive(Debug, serde::Deserialize)]
struct WorkflowRun {
    status: Option<String>,
    conclusion: Option<String>,
}

/// Dispatch `dispatch` to `operations.yml` on `main` and follow the run
/// to its conclusion. Prints the run URL as soon as GitHub creates the
/// run; the command succeeds only when the run does.
///
/// # Errors
/// `stow_error` when `STOW_EDGE_URL` is unset or names a local edge, the
/// dispatch is refused, the run does not finish inside [`RUN_DEADLINE`],
/// or it concludes other than `success`.
pub async fn dispatch_and_follow(dispatch: &Dispatch) -> stow_types::error::Result<()> {
    refuse_loopback_edge(std::env::var(crate::STOW_EDGE_URL_ENV).ok().as_deref())?;
    let token = crate::operator_token()?;
    let run: DispatchedRun = github::post(
        &token,
        &format!("actions/workflows/{WORKFLOW}/dispatches"),
        &dispatch.body(),
    )
    .await
    .map_err(|error| stow_error!("dispatch {WORKFLOW}: {error}"))?;
    println!("{WORKFLOW} run: {}", run.html_url);

    let run_url = format!(
        "{}/repos/{}/actions/runs/{}",
        github::API_BASE,
        github::REPO,
        run.workflow_run_id
    );
    let deadline = tokio::time::Instant::now() + RUN_DEADLINE;
    loop {
        let current: WorkflowRun =
            github::get_url_json(&run_url, Some(&token), Backoff::default()).await?;
        if current.status.as_deref() == Some("completed") {
            return match current.conclusion.as_deref() {
                Some("success") => Ok(()),
                other => Err(stow_error!("{} concluded {other:?}", run.html_url)),
            };
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(stow_error!(
                "{} did not finish within {} minutes",
                run.html_url,
                RUN_DEADLINE.as_secs() / 60
            ));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{Dispatch, FILES_DIR, refuse_loopback_edge};

    fn argv(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    /// The dispatch names `main`, asks for the run's id, and carries the
    /// argv as a JSON array — the shape `operations.yml` parses without
    /// a shell, so an argument with spaces or shell syntax stays one
    /// literal argument.
    #[test]
    fn the_body_carries_main_and_a_literal_argv() {
        let dispatch = Dispatch {
            argv: argv(&["queue", "retry", "--crate", "a b; $(x)", "--yes"]),
            files: std::collections::BTreeMap::new(),
        };
        let body = dispatch.body();
        assert_eq!(body["ref"], "main");
        assert_eq!(body["return_run_details"], true);
        let replayed: Vec<String> =
            serde_json::from_str(body["inputs"]["argv"].as_str().expect("argv is a string"))
                .expect("argv is a JSON array");
        assert_eq!(replayed, dispatch.argv);
        assert!(body["inputs"].get("files").is_none());
    }

    /// A file argument travels as contents under its bare name, and the
    /// replayed argv points at where the workflow writes it — in both
    /// the `--flag value` and `--flag=value` spellings.
    #[test]
    fn a_file_argument_is_carried_by_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let crates = dir.path().join("crates.txt");
        let projects = dir.path().join("projects.toml");
        std::fs::write(&crates, "serde\n").expect("write");
        std::fs::write(&projects, "[[project]]\n").expect("write");
        let mut dispatch = Dispatch {
            argv: vec![
                "preheat".to_owned(),
                "manual".to_owned(),
                "--crates".to_owned(),
                crates.display().to_string(),
                format!("--projects={}", projects.display()),
                "--yes".to_owned(),
            ],
            files: std::collections::BTreeMap::new(),
        };
        dispatch.carry("--crates").expect("carry crates");
        dispatch.carry("--projects").expect("carry projects");
        dispatch
            .carry("--source-trees")
            .expect("absent flag is a no-op");
        assert_eq!(
            dispatch.argv,
            vec![
                "preheat".to_owned(),
                "manual".to_owned(),
                "--crates".to_owned(),
                format!("{FILES_DIR}/crates.txt"),
                format!("--projects={FILES_DIR}/projects.toml"),
                "--yes".to_owned(),
            ]
        );
        let files: std::collections::BTreeMap<String, String> = serde_json::from_str(
            dispatch.body()["inputs"]["files"]
                .as_str()
                .expect("files is a string"),
        )
        .expect("files is a JSON object");
        assert_eq!(files["crates.txt"], "serde\n");
        assert_eq!(files["projects.toml"], "[[project]]\n");
    }

    #[test]
    fn two_carried_files_may_not_share_a_name() {
        let first = tempfile::tempdir().expect("tempdir");
        let second = tempfile::tempdir().expect("tempdir");
        let a = first.path().join("list.toml");
        let b = second.path().join("list.toml");
        std::fs::write(&a, "a").expect("write");
        std::fs::write(&b, "b").expect("write");
        let mut dispatch = Dispatch {
            argv: argv(&[
                "--projects",
                a.to_str().expect("utf-8"),
                "--source-trees",
                b.to_str().expect("utf-8"),
            ]),
            files: std::collections::BTreeMap::new(),
        };
        dispatch.carry("--projects").expect("first");
        assert!(dispatch.carry("--source-trees").is_err());
    }

    /// A traced command aimed at the mock edge, or at no edge, must not
    /// dispatch the production workflow.
    #[test]
    fn a_loopback_edge_refuses_the_dispatch() {
        for url in [
            "http://127.0.0.1:8787",
            "http://localhost:8787",
            "http://[::1]:8787",
        ] {
            assert!(refuse_loopback_edge(Some(url)).is_err(), "{url}");
        }
        assert!(refuse_loopback_edge(Some("https://stow.waterui.dev")).is_ok());
        assert!(refuse_loopback_edge(None).is_err(), "no edge, no dispatch");
    }
}

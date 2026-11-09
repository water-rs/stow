//! Real human-request lifecycle on native mocked egress. Preparation selects
//! unused published serde versions; measured events never deduplicate requests.

use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;

use serde::de::DeserializeOwned;
use stow_types::api::{
    CI_TARGET_TRIPLES, CrateRequest, CrateRequestPhase, CrateRequestStatus, CrateVersionsResponse,
    EnqueueRequest, EnqueueSource, RequestOutcome, RequestOutcomeReport, RequestRootOutcome,
    SubmissionSource, SubmissionTree,
};
use stow_types::identity::{CrateVersion, FeaturesJson, WireRustcVersion};
use stow_types::node_profile::NodeProfile;
use zenwave::Client;

use super::lanes::{Outcome, sign_body, workflow_delivery_body};
use crate::Edge;

#[derive(Debug)]
struct Case {
    request: CrateRequest,
    request_id: String,
}

/// One owner prepares identities before they are timed or profiled.
#[derive(Debug)]
pub struct HumanLane {
    secret: String,
    token_file: PathBuf,
    rustc: WireRustcVersion,
    prepared: Mutex<VecDeque<Case>>,
}

impl HumanLane {
    pub(super) fn new(secret: String, token_file: PathBuf, rustc: &str) -> Result<Self, String> {
        Ok(Self {
            secret,
            token_file,
            rustc: rustc
                .parse::<WireRustcVersion>()
                .map_err(|error| error.to_string())?,
            prepared: Mutex::new(VecDeque::new()),
        })
    }

    pub(super) async fn ready(&self, edge: &Edge, needed: usize) -> Result<(), String> {
        let existing: BTreeSet<String> = self
            .prepared
            .lock()
            .expect("human cases")
            .iter()
            .map(|case| case.request_id.clone())
            .collect();
        if existing.len() >= needed {
            return Ok(());
        }
        let mut client = zenwave::client();
        let versions: CrateVersionsResponse = client
            .get(format!("{}/api/v1/crates/serde/versions", edge.base()))
            .map_err(|error| error.to_string())?
            .await
            .map_err(|error| error.to_string())?
            .into_body()
            .json()
            .await
            .map_err(|error| error.to_string())?;
        let mut fresh = Vec::new();
        for version in versions.versions {
            let semver =
                semver::Version::parse(&version.to_string()).map_err(|error| error.to_string())?;
            // These real serde releases have no enabled normal dependencies
            // with default features disabled; newer serde uses serde_core.
            if semver.major != 1 || semver.minor != 0 || semver.patch > 219 {
                continue;
            }
            let request_id = stow_types::api::request_id(
                "serde",
                &version.to_string(),
                "[]",
                self.rustc.as_str(),
            );
            if existing.contains(&request_id) {
                continue;
            }
            let response = client
                .get(format!("{}/api/v1/requests/{request_id}", edge.base()))
                .map_err(|error| error.to_string())?
                .await;
            match response {
                Err(zenwave::Error::Http { status, .. }) if status.as_u16() == 404 => {}
                Ok(response) => {
                    response
                        .into_body()
                        .into_bytes()
                        .await
                        .map_err(|error| error.to_string())?;
                    continue;
                }
                Err(error) => return Err(error.to_string()),
            }
            fresh.push(Case {
                request_id,
                request: CrateRequest {
                    crate_name: "serde"
                        .parse()
                        .map_err(|error| format!("serde name: {error}"))?,
                    version: Some(version),
                    features_json: FeaturesJson::default(),
                    turnstile_token: "pass".to_owned(),
                },
            });
            if existing.len() + fresh.len() >= needed {
                break;
            }
        }
        if existing.len() + fresh.len() < needed {
            return Err(format!(
                "human lifecycle needs {needed} unused serde identities; found {}",
                existing.len() + fresh.len()
            ));
        }
        self.prepared.lock().expect("human cases").extend(fresh);
        Ok(())
    }

    pub(super) async fn fire(
        &self,
        edge: &Edge,
        client: &mut zenwave::DefaultClient,
    ) -> Result<Outcome, String> {
        let case = self
            .prepared
            .lock()
            .expect("human cases")
            .pop_front()
            .ok_or("human lifecycle fired without preparation")?;
        let admitted: CrateRequestStatus = post(
            client,
            &format!("{}/api/v1/requests", edge.base()),
            None,
            &case.request,
        )
        .await?;
        if admitted.request_id != case.request_id || admitted.status != CrateRequestPhase::Accepted
        {
            return Err(format!("human admission was not fresh: {admitted:?}"));
        }
        let title = stow_types::records::resolve_run_title(1, &case.request_id);
        for action in ["requested", "in_progress"] {
            self.delivery(client, edge.base(), action, &title).await?;
        }
        let token = tokio::fs::read_to_string(&self.token_file)
            .await
            .map_err(|error| error.to_string())?;
        let report = outcome(
            case.request
                .version
                .as_ref()
                .ok_or("human fixture needs an exact version")?,
            &self.rustc,
        )?;
        let settled: CrateRequestStatus = post(
            client,
            &format!(
                "{}/api/v1/scheduler/requests/{}/outcome",
                edge.base(),
                case.request_id
            ),
            Some(token.trim()),
            &report,
        )
        .await?;
        if settled.status != CrateRequestPhase::Enqueued
            || settled.targets.len() != CI_TARGET_TRIPLES.len()
        {
            return Err(format!(
                "human outcome did not enqueue all targets: {settled:?}"
            ));
        }
        self.delivery(client, edge.base(), "completed", &title)
            .await?;
        Ok(Outcome::Response {
            status: 200,
            overloaded: false,
        })
    }

    async fn delivery(
        &self,
        client: &mut zenwave::DefaultClient,
        base: &str,
        action: &str,
        title: &str,
    ) -> Result<(), String> {
        let body = workflow_delivery_body(
            action,
            stow_types::trusted_builder::RESOLVE_WORKFLOW_FILE,
            12345,
            title,
        );
        let response = client
            .post(format!("{base}/api/v1/github/workflow-run"))
            .map_err(|error| error.to_string())?
            .header("X-GitHub-Event", "workflow_run")
            .map_err(|error| error.to_string())?
            .header(
                "X-Hub-Signature-256",
                sign_body(&self.secret, body.as_bytes()),
            )
            .map_err(|error| error.to_string())?
            .header("Content-Type", "application/json")
            .map_err(|error| error.to_string())?
            .bytes_body(body.into_bytes())
            .await
            .map_err(|error| error.to_string())?;
        response
            .into_body()
            .into_bytes()
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

async fn post<T: DeserializeOwned>(
    client: &mut zenwave::DefaultClient,
    url: &str,
    token: Option<&str>,
    body: &impl serde::Serialize,
) -> Result<T, String> {
    let request = client.post(url).map_err(|error| error.to_string())?;
    let request = match token {
        Some(token) => request
            .header("Authorization", format!("Bearer {token}"))
            .map_err(|error| error.to_string())?,
        None => request,
    };
    request
        .json_body(body)
        .map_err(|error| error.to_string())?
        .await
        .map_err(|error| error.to_string())?
        .into_body()
        .json()
        .await
        .map_err(|error| error.to_string())
}

fn outcome(
    version: &CrateVersion,
    rustc: &WireRustcVersion,
) -> Result<RequestOutcomeReport, String> {
    let requests = CI_TARGET_TRIPLES
        .iter()
        .map(|target| {
            Ok(EnqueueRequest {
                crate_name: "serde"
                    .parse()
                    .map_err(|error| format!("serde name: {error}"))?,
                version: version.clone(),
                features_json: FeaturesJson::default(),
                target: target
                    .parse()
                    .map_err(|error| format!("CI target: {error}"))?,
                rustc_version: rustc.clone(),
                downloads: 0,
                source: EnqueueSource::CrateUpdate,
                dependency_subgraph: stow_types::api::TaskSubgraph::default(),
                host_side: false,
                profile: NodeProfile::Dev,
                explicit_spelling: stow_types::public_cache::ExplicitSpelling::KeysAsNative,
                preserve_lockfile: false,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let tree = SubmissionTree::from_enqueue_requests(SubmissionSource::HumanRequest, &requests)
        .map_err(|error| error.to_string())?;
    let roots = tree
        .roots
        .iter()
        .map(|&root| {
            let node = &tree.nodes[root as usize];
            RequestRootOutcome {
                target: node.target.clone(),
                task_id: Some(node.task_id.clone()),
                cached: false,
            }
        })
        .collect();
    Ok(RequestOutcomeReport {
        attempt: 1,
        outcome: RequestOutcome::Resolved {
            trees: vec![tree],
            roots,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_lifecycle_names_every_target_and_canonical_leaf_identity() {
        let report = outcome(
            &"1.0.219".parse().expect("version"),
            &"1.99.1".parse().expect("rustc"),
        )
        .expect("report");
        let RequestOutcome::Resolved { trees, roots } = report.outcome else {
            panic!("resolved outcome");
        };
        assert_eq!(trees.len(), 1);
        let tree = &trees[0];
        assert_eq!(tree.source, SubmissionSource::HumanRequest);
        assert_eq!(tree.nodes.len(), CI_TARGET_TRIPLES.len());
        assert_eq!(roots.len(), CI_TARGET_TRIPLES.len());
        let leaf = stow_types::identity::DependencyIdentity::leaf().expect("leaf");
        for ((root, node), target) in roots.iter().zip(&tree.nodes).zip(CI_TARGET_TRIPLES) {
            assert_eq!(root.target.as_str(), *target);
            assert_eq!(root.task_id.as_ref(), Some(&node.task_id));
            assert_eq!(node.crate_name.as_str(), "serde");
            assert_eq!(node.features_json, FeaturesJson::default());
            assert_eq!(node.dependency_identity, leaf);
            assert!(!root.cached);
            assert!(node.deps.is_empty());
        }
    }
}

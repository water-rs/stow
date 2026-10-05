//! `--source-trees` — the operator's pinned source-tree declarations
//! (stow#558).
//!
//! A project whose git tree does not carry every Rust input it names
//! (Bun's `vendor/lolhtml` lives in a second repository, populated by
//! `scripts/build/deps/lolhtml.ts`) resolves only with this file: each
//! `[[project]]` declares the exact commit the ranked input resolves
//! at, and each `[[project.source]]` the repository, commit, and
//! project-relative destination of one extra tree.
//!
//! ```toml
//! [[project]]
//! repo = "https://github.com/owner/name"
//! commit = "<full git commit id>"
//!
//! [[project.source]]
//! destination = "vendor/component"
//! repo = "https://github.com/owner/source"
//! commit = "<full git commit id>"
//! ```
//!
//! The file is parsed once per command, before the resolve pool
//! starts; every declaration must name a repository the input list
//! actually contains — a declaration for a project not being resolved
//! is rejected, never quietly ignored.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use stow_resolver::{GitCommit, PreparedSourceTree, RelativeSourcePath, SourcePreparation};
use stow_types::stow_error;

/// The schema of a `--source-trees` file.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceTreesFile {
    /// One entry per project that needs prepared sources.
    project: Vec<DeclaredProject>,
}

/// One declared project: the repository (the projects-list identity)
/// and the commit its checkout must sit at.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredProject {
    /// `https://github.com/<owner>/<name>`, normalized like the input.
    repo: String,
    /// Full git commit id the project's checkout must hold.
    commit: String,
    /// The extra source trees this project needs.
    source: Vec<DeclaredSource>,
}

/// One declared source tree inside a project.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredSource {
    /// Project-relative destination — portable forward-slash, normal
    /// components only.
    destination: String,
    /// The repository to fetch (any git-compatible absolute URL).
    repo: String,
    /// Full git commit id the source's checkout must hold.
    commit: String,
}

/// The parsed file: a lookup from normalized project repo URL to its
/// [`SourcePreparation`].
#[derive(Debug, Default)]
pub struct SourceTrees {
    preparations: BTreeMap<String, SourcePreparation>,
}

impl SourceTrees {
    /// The preparation for one normalized repository URL, if declared.
    #[must_use]
    pub fn get(&self, normalized_repo: &str) -> Option<&SourcePreparation> {
        self.preparations.get(normalized_repo)
    }

    /// The normalized repository URLs this file declares.
    pub fn declared_repos(&self) -> impl Iterator<Item = &str> {
        self.preparations.keys().map(String::as_str)
    }
}

/// Load and validate a `--source-trees` file. Repositories normalize
/// through the same rule `preheat/projects.toml` entries do, and
/// commit ids parse as full git object ids — a malformed row fails the
/// command before any resolve runs.
///
/// # Errors
/// Read/parse failures, unknown fields, duplicate project
/// declarations, an empty source set, a malformed commit/URL/
/// destination, or overlapping destinations.
pub fn load_source_trees(path: &Path) -> stow_types::error::Result<SourceTrees> {
    let raw =
        std::fs::read(path).map_err(|error| stow_error!("read {}: {error}", path.display()))?;
    parse_source_trees(&raw, &path.display().to_string())
}

/// The parse-and-validate half of [`load_source_trees`], split so a
/// test can drive it without a file. `display` names the file in
/// errors.
fn parse_source_trees(raw: &[u8], display: &str) -> stow_types::error::Result<SourceTrees> {
    let file: SourceTreesFile =
        toml::from_slice(raw).map_err(|error| stow_error!("parse {display}: {error}"))?;
    let mut preparations = BTreeMap::new();
    for project in &file.project {
        let repo = crate::projects::normalize_repo_url(&project.repo)
            .map_err(|error| stow_error!("{display}: {error}"))?;
        if preparations.contains_key(&repo) {
            return Err(stow_error!("{display} declares {repo} twice"));
        }
        let commit = GitCommit::parse(&project.commit)
            .map_err(|error| stow_error!("{display} {repo}: {error:#}"))?;
        let mut sources = Vec::with_capacity(project.source.len());
        for source in &project.source {
            let destination = RelativeSourcePath::parse(&source.destination)
                .map_err(|error| stow_error!("{display} {repo}: {error:#}"))?;
            let source_repo = url::Url::parse(&source.repo)
                .map_err(|error| stow_error!("{display} {repo} source repo: {error}"))?;
            let source_commit = GitCommit::parse(&source.commit)
                .map_err(|error| stow_error!("{display} {repo}: {error:#}"))?;
            sources.push(
                PreparedSourceTree::new(destination, source_repo, source_commit)
                    .map_err(|error| stow_error!("{display} {repo}: {error:#}"))?,
            );
        }
        let preparation = SourcePreparation::new(commit, sources)
            .map_err(|error| stow_error!("{display} {repo}: {error:#}"))?;
        preparations.insert(repo, preparation);
    }
    Ok(SourceTrees { preparations })
}

/// Load the optional `--source-trees` argument into a validated
/// lookup for `normalized_input` — `None` means every project
/// resolves its ordinary git tree, and a provided file must declare
/// only repositories the input lists.
///
/// # Errors
/// Any of [`load_source_trees`]'s, or a declaration for a repository
/// the input does not contain.
pub fn load_optional_source_trees(
    path: Option<&PathBuf>,
    normalized_input: &[String],
) -> stow_types::error::Result<Option<SourceTrees>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let trees = load_source_trees(path)?;
    check_declared_inputs(&trees, normalized_input)?;
    Ok(Some(trees))
}

/// Reject declarations for repositories the input list does not
/// contain — every row must refer to a project actually being
/// resolved.
///
/// # Errors
/// A declared repository is absent from `normalized_input`.
pub fn check_declared_inputs(
    trees: &SourceTrees,
    normalized_input: &[String],
) -> stow_types::error::Result<()> {
    for declared in trees.declared_repos() {
        if !normalized_input.iter().any(|repo| repo == declared) {
            return Err(stow_error!(
                "--source-trees declares {declared}, which the projects input does not list"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A sha1-looking id the fixtures reuse — content never fetched.
    const SHA: &str = "0123456789012345678901234567890123456789";

    /// A syntactically malformed document — a small checked-in text
    /// fixture, not something a serializer would emit.
    const MALFORMED: &[u8] = include_bytes!("../tests/fixtures/source-trees-malformed.toml");

    /// A lookalike row carrying one field the schema rejects — typed
    /// so the unknown field still serializes as valid TOML and the
    /// rejection is `deny_unknown_fields`' alone.
    #[derive(serde::Serialize)]
    struct BogusSource {
        #[serde(flatten)]
        source: DeclaredSource,
        bogus: u32,
    }

    /// A project row holding [`BogusSource`]s.
    #[derive(serde::Serialize)]
    struct BogusProject {
        repo: &'static str,
        commit: &'static str,
        source: Vec<BogusSource>,
    }

    /// A file of [`BogusProject`]s.
    #[derive(serde::Serialize)]
    struct BogusFile {
        project: Vec<BogusProject>,
    }

    /// One source row, serialized.
    fn declared_source(destination: &str, repo: &str) -> DeclaredSource {
        DeclaredSource {
            destination: destination.to_owned(),
            repo: repo.to_owned(),
            commit: SHA.to_owned(),
        }
    }

    /// One project row with `commit`, serialized.
    fn declared_project(repo: &str, commit: &str, source: Vec<DeclaredSource>) -> DeclaredProject {
        DeclaredProject {
            repo: repo.to_owned(),
            commit: commit.to_owned(),
            source,
        }
    }

    /// A whole `--source-trees` document built the way an operator's
    /// file is shaped — typed rows serialized, never concatenated
    /// text.
    fn document(projects: Vec<DeclaredProject>) -> Vec<u8> {
        toml::to_string(&SourceTreesFile { project: projects })
            .expect("a typed document serializes")
            .into_bytes()
    }

    /// One project declaring one source.
    fn one_document(repo: &str) -> Vec<u8> {
        document(vec![declared_project(
            repo,
            SHA,
            vec![declared_source(
                "vendor/sub",
                "https://github.com/owner/source",
            )],
        )])
    }

    #[test]
    fn a_declaration_parses_into_a_preparation() {
        let trees = parse_source_trees(&one_document("https://github.com/owner/proj"), "test")
            .expect("a well-formed file parses");
        assert!(
            trees.get("https://github.com/owner/proj").is_some(),
            "the normalized project URL resolves its preparation"
        );
        assert!(
            trees.get("https://github.com/owner/other").is_none(),
            "an undeclared project gets no preparation"
        );
    }

    #[test]
    fn a_duplicate_project_declaration_fails() {
        let raw = document(vec![
            declared_project(
                "https://github.com/owner/proj",
                SHA,
                vec![declared_source(
                    "vendor/sub",
                    "https://github.com/owner/source",
                )],
            ),
            declared_project(
                "https://github.com/owner/proj/",
                SHA,
                vec![declared_source(
                    "other/dir",
                    "https://github.com/owner/source",
                )],
            ),
        ]);
        assert!(
            parse_source_trees(&raw, "test").is_err(),
            "the same normalized repo declared twice fails"
        );
    }

    #[test]
    fn a_malformed_document_fails() {
        assert!(parse_source_trees(MALFORMED, "test").is_err());
    }

    #[test]
    fn an_unknown_field_fails() {
        let raw = toml::to_string(&BogusFile {
            project: vec![BogusProject {
                repo: "https://github.com/owner/proj",
                commit: SHA,
                source: vec![BogusSource {
                    source: declared_source("vendor/sub", "https://github.com/owner/source"),
                    bogus: 1,
                }],
            }],
        })
        .expect("a typed bogus document serializes");
        assert!(
            parse_source_trees(raw.as_bytes(), "test").is_err(),
            "a field the schema does not declare fails"
        );
    }

    #[test]
    fn an_empty_source_set_fails() {
        let raw = document(vec![declared_project(
            "https://github.com/owner/proj",
            SHA,
            vec![],
        )]);
        assert!(
            parse_source_trees(&raw, "test").is_err(),
            "a project with no declared sources needs no row"
        );
    }

    #[test]
    fn a_bad_commit_fails() {
        let raw = document(vec![declared_project(
            "https://github.com/owner/proj",
            "not-a-commit",
            vec![declared_source(
                "vendor/sub",
                "https://github.com/owner/source",
            )],
        )]);
        assert!(
            parse_source_trees(&raw, "test").is_err(),
            "a non-object-id commit fails"
        );
    }

    #[test]
    fn a_declaration_for_an_absent_input_fails() {
        let trees =
            parse_source_trees(&one_document("https://github.com/owner/proj"), "test").unwrap();
        assert!(
            check_declared_inputs(&trees, &["https://github.com/owner/proj".to_owned()]).is_ok()
        );
        assert!(
            check_declared_inputs(&trees, &["https://github.com/owner/other".to_owned()]).is_err(),
            "a declaration for a project the input does not list is rejected"
        );
    }

    #[test]
    fn overlapping_destinations_fail() {
        let raw = document(vec![declared_project(
            "https://github.com/owner/proj",
            SHA,
            vec![
                declared_source("vendor/sub", "https://github.com/owner/a"),
                declared_source("vendor/sub/inner", "https://github.com/owner/b"),
            ],
        )]);
        assert!(
            parse_source_trees(&raw, "test").is_err(),
            "a nested destination would shadow the outer tree"
        );
    }

    /// `preheat projects submit` accepts `--source-trees`.
    #[test]
    fn projects_submit_accepts_the_source_trees_flag() {
        let cli = crate::Cli::try_parse_from([
            "stow-admin",
            "preheat",
            "projects",
            "submit",
            "--rustc-version",
            "1.99.0",
            "--source-trees",
            "trees.toml",
        ])
        .expect("projects submit accepts --source-trees");
        let crate::Command::Preheat(preheat) = &cli.command else {
            panic!("expected preheat");
        };
        let crate::preheat::PreheatCommand::Projects(projects) = &preheat.command else {
            panic!("expected projects");
        };
        let crate::projects::ProjectsCommand::Submit(submit) = &projects.command else {
            panic!("expected submit");
        };
        assert_eq!(
            submit.source_trees.as_deref(),
            Some(std::path::Path::new("trees.toml")),
            "the flag lands on the submit args"
        );
    }
}

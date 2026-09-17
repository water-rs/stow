//! Identity of the one GitHub Actions workflow whose signatures the CLI
//! trusts.
//!
//! The scheduler dispatches builds to exactly this workflow on exactly this
//! ref, and the CLI accepts a Fulcio certificate only when its subject is the
//! URL these pieces compose to. Spelling each piece once keeps the two ends
//! from drifting apart.

/// `concat!` needs literals, hence the macros.
macro_rules! repository {
    () => {
        "water-rs/stow"
    };
}
macro_rules! workflow_file {
    () => {
        "build-crate.yml"
    };
}
macro_rules! branch {
    () => {
        "main"
    };
}

/// GitHub repository (`owner/name`) that hosts the trusted build workflow.
pub const REPOSITORY: &str = repository!();
/// Workflow file under `.github/workflows/` that performs trusted builds.
pub const WORKFLOW_FILE: &str = workflow_file!();
/// Branch the trusted workflow runs from. `workflow_dispatch` takes the bare
/// branch name; the certificate subject carries the full ref.
pub const BRANCH: &str = branch!();
/// Subject Alternative Name Fulcio issues to the trusted workflow.
pub const CERTIFICATE_IDENTITY: &str = concat!(
    "https://github.com/",
    repository!(),
    "/.github/workflows/",
    workflow_file!(),
    "@refs/heads/",
    branch!()
);
/// OIDC issuer of GitHub Actions job tokens.
pub const CERTIFICATE_ISSUER: &str = "https://token.actions.githubusercontent.com";

#[cfg(test)]
mod tests {
    use super::CERTIFICATE_IDENTITY;

    #[test]
    fn certificate_identity_composes_repository_workflow_and_ref() {
        assert_eq!(
            CERTIFICATE_IDENTITY,
            "https://github.com/water-rs/stow/.github/workflows/build-crate.yml@refs/heads/main"
        );
    }
}

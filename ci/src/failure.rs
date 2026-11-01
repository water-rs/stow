//! Compiler evidence for cache-free verification of failed builds.

use std::collections::BTreeSet;
use std::path::Path;

use cargo_metadata::{Message, diagnostic::DiagnosticLevel};
use stow_types::build_failure::SourceDiagnostic;

/// Untrusted handoff: only a fresh replay can turn this into a verified
/// failure. The lockfile bytes let the verifier reproduce the resolution.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FailureCandidate {
    pub observation: stow_types::build_failure::CompilationFailure,
    pub lockfile: String,
}

/// Bind the untrusted handoff to one GitHub run attempt, including reruns.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FailureReport {
    pub build: stow_types::records::BuildRun,
    pub candidate: FailureCandidate,
}

impl FailureReport {
    pub fn for_run(
        self,
        expected: stow_types::records::BuildRun,
    ) -> stow_types::error::Result<FailureCandidate> {
        verify_run(self.build, expected)?;
        Ok(self.candidate)
    }
}

fn verify_run(
    actual: stow_types::records::BuildRun,
    expected: stow_types::records::BuildRun,
) -> stow_types::error::Result<()> {
    if actual != expected {
        return Err(stow_types::stow_error!(
            "failure candidate belongs to a different run attempt"
        ));
    }
    Ok(())
}

#[derive(serde::Serialize)]
pub struct VerifiedFailureReport {
    pub build: stow_types::records::BuildRun,
    pub failure: stow_types::build_failure::VerifiedSourceFailure,
}

/// Collect source diagnostics from Cargo's JSON stream. A process exit
/// alone, a linker summary, or an error outside registry sources does
/// not establish that a published crate's source failed to compile.
pub fn source_diagnostics(
    output: &[u8],
    cargo_home: &Path,
) -> std::io::Result<BTreeSet<SourceDiagnostic>> {
    let source_root = cargo_home.join("registry/src");
    let messages = Message::parse_stream(output).collect::<std::io::Result<Vec<_>>>()?;
    Ok(messages
        .into_iter()
        .filter_map(|message| match message {
            Message::CompilerMessage(message)
                if message.message.level == DiagnosticLevel::Error =>
            {
                Some(message)
            }
            _ => None,
        })
        .flat_map(|message| {
            let diagnostic = message.message;
            diagnostic
                .spans
                .into_iter()
                .filter(|span| span.is_primary)
                .filter_map(|span| {
                    let relative = Path::new(&span.file_name).strip_prefix(&source_root).ok()?;
                    let mut components = relative.components();
                    // Cargo's registry source layout is registry/package/source.
                    components.next()?;
                    components.next()?;
                    let source = components.as_path();
                    if source.as_os_str().is_empty() {
                        return None;
                    }
                    Some(SourceDiagnostic {
                        package: message.package_id.to_string(),
                        source: source.to_string_lossy().replace('\\', "/"),
                        line: span.line_start as u64,
                        code: diagnostic.code.as_ref().map(|code| code.code.clone()),
                        message: diagnostic.message.clone(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect())
}

/// A compiler diagnostic cannot hide a second failing tool. Cargo's
/// compilation summaries are expected; its other errors and the Rust
/// supervisor's `main -> Result` errors prevent a source verdict.
pub fn has_tool_failure(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr).lines().any(|line| {
        line.starts_with("Error:")
            || line.starts_with("thread '")
            || line.strip_prefix("error: ").is_some_and(|error| {
                !error.starts_with("could not compile `")
                    && !error.starts_with("failed to run custom build command for `")
            })
    })
}

/// Cargo prefixes native compiler warnings with the package that emitted
/// them. Only GNU/Clang source-located errors qualify; command-launch,
/// linker, and build-script exit summaries do not.
pub fn native_diagnostics(stderr: &[u8]) -> BTreeSet<SourceDiagnostic> {
    String::from_utf8_lossy(stderr)
        .lines()
        .filter_map(|line| {
            let (package, diagnostic) = line.strip_prefix("warning: ")?.split_once(": ")?;
            let (_, version) = package.rsplit_once('@')?;
            semver::Version::parse(version).ok()?;
            let (location, message) = diagnostic
                .split_once(": fatal error: ")
                .or_else(|| diagnostic.split_once(": error: "))?;
            let (file_line, column) = location.rsplit_once(':')?;
            column.parse::<u64>().ok()?;
            let (source, line) = file_line.rsplit_once(':')?;
            let line = line.parse::<u64>().ok()?;
            let path = Path::new(source);
            if path.is_absolute()
                || path
                    .components()
                    .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                return None;
            }
            Some(SourceDiagnostic {
                package: package.to_owned(),
                source: source.replace('\\', "/"),
                line,
                code: None,
                message: message.to_owned(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::source_diagnostics;

    #[test]
    fn failure_reports_reject_previous_runs_and_attempts() {
        use stow_types::records::BuildRun;
        let expected = BuildRun {
            run_id: 42,
            run_attempt: 2,
        };
        assert!(super::verify_run(expected, expected).is_ok());
        for actual in [
            BuildRun {
                run_id: 41,
                run_attempt: 2,
            },
            BuildRun {
                run_id: 42,
                run_attempt: 1,
            },
        ] {
            assert!(super::verify_run(actual, expected).is_err());
        }
    }

    #[test]
    fn source_diagnostics_cannot_hide_a_failing_tool() {
        for stderr in [
            "error: could not compile `uuid` (lib) due to 1 previous error\nError: cached bundle digest mismatch",
            "error: could not execute process `rustc` (never executed)",
            "error: the compiler unexpectedly panicked. this is a bug.",
            "thread 'main' panicked at capture.rs:10",
        ] {
            assert!(super::has_tool_failure(stderr.as_bytes()));
        }
        assert!(!super::has_tool_failure(
            b"error: could not compile `uuid` (lib) due to 1 previous error"
        ));
    }

    #[test]
    fn native_source_errors_require_package_and_source_location() {
        let evidence = super::native_diagnostics(b"warning: onig_sys@69.9.3: oniguruma/src/regint.h:123:10: fatal error: 'stdlib.h' file not found");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence.first().expect("C diagnostic").line, 123);
        for output in [
            "error: failed to run custom build command for `onig_sys v69.9.3`",
            "warning: cc@1.0.0: ToolNotFound: clang not found",
            "warning: cc@1.0.0: /tmp/tool.c:1:1: error: tool failed",
            "warning: cc@1.0.0: ../tool.c:1:1: error: tool failed",
        ] {
            assert!(super::native_diagnostics(output.as_bytes()).is_empty());
        }
    }

    fn message(file: &str, level: &str, primary: bool) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "reason": "compiler-message",
            "package_id": "registry+https://github.com/rust-lang/crates.io-index#uuid@1.29.0",
            "target": {
                "kind": ["lib"], "crate_types": ["lib"], "name": "uuid",
                "src_path": "/cargo/registry/src/index/uuid-1.29.0/src/lib.rs",
                "edition": "2021", "doc": true, "doctest": true, "test": true
            },
            "message": {
                "message": "specify a source of randomness", "code": null,
                "level": level, "children": [], "rendered": null,
                "spans": [{
                    "file_name": file, "byte_start": 0, "byte_end": 1,
                    "line_start": 104, "line_end": 104,
                    "column_start": 1, "column_end": 2,
                    "is_primary": primary, "text": [], "label": null,
                    "suggested_replacement": null, "suggestion_applicability": null,
                    "expansion": null
                }]
            }
        }))
        .expect("compiler message")
    }

    #[test]
    fn registry_source_errors_are_independent_of_cargo_home() {
        let first = source_diagnostics(
            &message(
                "/cargo/registry/src/index/uuid-1.29.0/src/rng.rs",
                "error",
                true,
            ),
            Path::new("/cargo"),
        )
        .expect("diagnostics");
        let second = source_diagnostics(
            &message(
                "/replay/registry/src/index/uuid-1.29.0/src/rng.rs",
                "error",
                true,
            ),
            Path::new("/replay"),
        )
        .expect("diagnostics");
        assert_eq!(first.len(), 1);
        assert_eq!(first, second);
        assert_eq!(first.first().expect("diagnostic").source, "src/rng.rs");
    }

    #[test]
    fn unattributed_and_non_error_output_is_not_source_evidence() {
        for (file, level, primary) in [
            (
                "/cargo/registry/src/index/uuid-1.29.0/src/rng.rs",
                "warning",
                true,
            ),
            (
                "/cargo/registry/src/index/uuid-1.29.0/src/rng.rs",
                "error",
                false,
            ),
            ("/workspace/src/lib.rs", "error", true),
        ] {
            assert!(
                source_diagnostics(&message(file, level, primary), Path::new("/cargo"))
                    .expect("diagnostics")
                    .is_empty()
            );
        }
        assert!(
            source_diagnostics(b"error: could not compile uuid", Path::new("/cargo"))
                .expect("diagnostics")
                .is_empty()
        );
    }
}

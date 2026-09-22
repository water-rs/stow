//! The `CompileMode`/`UserIntent` enums (vendored verbatim).
//!
//! `cargo::core::compiler::build_config` also carries `BuildConfig` — the
//! build-runner's `-j`/`--target` aggregation — which the resolver never
//! constructs, so it is not ported.

use serde::ser;

/// The specific action to be performed on each `Unit` of work.
#[derive(Clone, Copy, PartialEq, Debug, Eq, Hash, PartialOrd, Ord)]
pub enum CompileMode {
    /// Test with `rustc`.
    Test,
    /// Compile with `rustc`.
    Build,
    /// Type-check with `rustc` by emitting `rmeta` metadata only.
    ///
    /// If `test` is true, then it is also compiled with `--test` to check it like
    /// a test.
    Check { test: bool },
    /// Document with `rustdoc`.
    Doc,
    /// Test with `rustdoc`.
    Doctest,
    /// Scrape for function calls by `rustdoc`.
    Docscrape,
    /// Execute the binary built from the `build.rs` script.
    RunCustomBuild,
}

impl ser::Serialize for CompileMode {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use self::CompileMode::*;
        match *self {
            Test => "test".serialize(s),
            Build => "build".serialize(s),
            Check { .. } => "check".serialize(s),
            Doc { .. } => "doc".serialize(s),
            Doctest => "doctest".serialize(s),
            Docscrape => "docscrape".serialize(s),
            RunCustomBuild => "run-custom-build".serialize(s),
        }
    }
}

impl<'de> serde::Deserialize<'de> for CompileMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "test" => Ok(CompileMode::Test),
            "build" => Ok(CompileMode::Build),
            "check" => Ok(CompileMode::Check { test: false }),
            "doc" => Ok(CompileMode::Doc),
            "doctest" => Ok(CompileMode::Doctest),
            "docscrape" => Ok(CompileMode::Docscrape),
            "run-custom-build" => Ok(CompileMode::RunCustomBuild),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &[
                    "test",
                    "build",
                    "check",
                    "doc",
                    "doctest",
                    "docscrape",
                    "run-custom-build",
                ],
            )),
        }
    }
}

impl CompileMode {
    /// Returns `true` if the unit is being checked.
    pub fn is_check(self) -> bool {
        matches!(self, CompileMode::Check { .. })
    }

    /// Returns `true` if this is generating documentation.
    pub fn is_doc(self) -> bool {
        matches!(self, CompileMode::Doc { .. })
    }

    /// Returns `true` if this a doc test.
    pub fn is_doc_test(self) -> bool {
        self == CompileMode::Doctest
    }

    /// Returns `true` if this is scraping examples for documentation.
    pub fn is_doc_scrape(self) -> bool {
        self == CompileMode::Docscrape
    }

    /// Returns `true` if this is any type of test (test, benchmark, doc test, or
    /// check test).
    pub fn is_any_test(self) -> bool {
        matches!(
            self,
            CompileMode::Test | CompileMode::Check { test: true } | CompileMode::Doctest
        )
    }

    /// Returns `true` if this is something that passes `--test` to rustc.
    pub fn is_rustc_test(self) -> bool {
        matches!(self, CompileMode::Test | CompileMode::Check { test: true })
    }

    /// Returns `true` if this is the *execution* of a `build.rs` script.
    pub fn is_run_custom_build(self) -> bool {
        self == CompileMode::RunCustomBuild
    }

    /// Returns `true` if this mode may generate an executable.
    ///
    /// Note that this also returns `true` for building libraries, so you also
    /// have to check the target.
    pub fn generates_executable(self) -> bool {
        matches!(self, CompileMode::Test | CompileMode::Build)
    }
}

/// Represents the high-level operation requested by the user.
///
/// It determines which "Cargo targets" are selected by default and influences
/// how they will be processed. This is derived from the Cargo command the user
/// invoked (like `cargo build` or `cargo test`).
///
/// Unlike [`CompileMode`], which describes the specific compilation steps for
/// individual units, [`UserIntent`] represents the overall goal of the build
/// process as specified by the user.
///
/// For example, when a user runs `cargo test`, the intent is [`UserIntent::Test`],
/// but this might result in multiple [`CompileMode`]s for different units.
#[derive(Clone, Copy, Debug)]
pub enum UserIntent {
    /// Build benchmark binaries, e.g., `cargo bench`
    Bench,
    /// Build binaries and libraries, e.g., `cargo run`, `cargo install`, `cargo build`.
    Build,
    /// Perform type-check, e.g., `cargo check`.
    Check { test: bool },
    /// Document packages.
    ///
    /// If `deps` is true, then it will also document all dependencies.
    /// if `json` is true, the documentation output is in json format.
    Doc { deps: bool, json: bool },
    /// Build doctest binaries, e.g., `cargo test --doc`
    Doctest,
    /// Build test binaries, e.g., `cargo test`
    Test,
}

impl UserIntent {
    /// Returns `true` if this is generating documentation.
    pub fn is_doc(self) -> bool {
        matches!(self, UserIntent::Doc { .. })
    }

    /// User wants rustdoc output in JSON format.
    pub fn wants_doc_json_output(self) -> bool {
        matches!(self, UserIntent::Doc { json: true, .. })
    }

    /// User wants to document also for dependencies.
    pub fn wants_deps_docs(self) -> bool {
        matches!(self, UserIntent::Doc { deps: true, .. })
    }

    /// Returns `true` if this is any type of test (test, benchmark, doc test, or
    /// check test).
    pub fn is_any_test(self) -> bool {
        matches!(
            self,
            UserIntent::Test
                | UserIntent::Bench
                | UserIntent::Check { test: true }
                | UserIntent::Doctest
        )
    }

    /// Returns `true` if this is something that passes `--test` to rustc.
    pub fn is_rustc_test(self) -> bool {
        matches!(
            self,
            UserIntent::Test | UserIntent::Bench | UserIntent::Check { test: true }
        )
    }
}

//! `cargo_util_terminal::report` boundary — re-exports `annotate_snippets`,
//! which is what `cargo-util-terminal` itself re-exports as `report`.

pub use annotate_snippets::*;
pub use anstyle_hyperlink::Hyperlink;

/// The amount of messages emitted, ported from
/// `cargo-util-terminal/src/shell.rs`.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Verbosity {
    Verbose,
    Normal,
    Quiet,
}

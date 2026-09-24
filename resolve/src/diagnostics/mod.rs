//! Diagnostics helpers needed by `util::toml` (path display + key/span
//! lookup). The lint-pass machinery of `cargo::diagnostics` is not carried.

mod report;

pub use report::{AsIndex, cwd_rel_path, get_key_value, get_key_value_span, workspace_rel_path};

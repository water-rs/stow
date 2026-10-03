//! The workerd budget table — it lives in `stow-types` (`do_budgets`)
//! so every consumer reads the same table: the edge's probe routes and
//! host drift gate, the admin crate's budget renderer, and the stow#452
//! launch gate's fixture.

pub use stow_types::do_budgets::*;

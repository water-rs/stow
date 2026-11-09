//! Fixed-size fragments keep append slack independent of the graph's size.

use std::ops::{Deref, DerefMut};

use orx_split_vec::{Linear, PseudoDefault, SplitVec};

/// Indexed records whose growth never relocates the preceding fragments.
#[derive(Debug)]
pub(super) struct Arena<T>(SplitVec<T, Linear>);

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self(SplitVec::with_growth(Linear::pseudo_default()))
    }
}

impl<T> Deref for Arena<T> {
    type Target = SplitVec<T, Linear>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Arena<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

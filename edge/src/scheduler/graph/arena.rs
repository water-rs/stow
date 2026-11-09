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

impl<'a, T> IntoIterator for &'a Arena<T> {
    type Item = &'a T;
    type IntoIter = <&'a SplitVec<T, Linear> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.0).into_iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Arena<T> {
    type Item = &'a mut T;
    type IntoIter = <&'a mut SplitVec<T, Linear> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&mut self.0).into_iter()
    }
}

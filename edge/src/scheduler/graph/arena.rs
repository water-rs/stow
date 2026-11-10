//! Fixed-size fragments keep append slack independent of the graph's size.

use std::ops::{Deref, DerefMut};

use orx_split_vec::{Linear, PinnedVec, PseudoDefault, SplitVec};

/// Indexed records whose growth never relocates the preceding fragments.
#[derive(Debug)]
pub(super) struct Arena<T>(SplitVec<T, Linear>);

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self(SplitVec::with_growth(Linear::pseudo_default()))
    }
}

impl<T: Clone> Arena<T> {
    /// Retain initialized records and append only the missing tail.
    pub(super) fn resize(&mut self, len: usize, value: T) {
        self.0.truncate(len);
        self.0
            .extend(std::iter::repeat_n(value, len - self.0.len()));
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

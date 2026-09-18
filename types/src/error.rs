//! The error type shared across stow crates, plus the [`Context`] extension
//! trait that annotates foreign `Result`s with stow-style context.

use std::error::Error as StdError;
use std::fmt::Display;

use thiserror::Error as ThisError;

/// Error type used across stow crates.
///
/// Carries either a bare message or a context string wrapping a lower-level
/// cause; both render as a single `Display` line.
#[derive(Debug)]
pub struct Error(ErrorKind);

#[derive(Debug, ThisError)]
enum ErrorKind {
    #[error("{0}")]
    Message(String),
    #[error("{context}: {cause}")]
    Context { context: String, cause: String },
}

/// `Result` alias using stow's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Build an error from a bare message.
    pub fn msg(message: impl Into<String>) -> Self {
        Self(ErrorKind::Message(message.into()))
    }

    /// Attach `context` to this error, keeping the original message as the
    /// cause.
    #[must_use]
    pub fn wrap_err(self, context: impl Display) -> Self {
        Self(ErrorKind::Context {
            context: context.to_string(),
            cause: self.to_string(),
        })
    }

    fn context_with_source(context: impl Display, source: impl Display) -> Self {
        Self(ErrorKind::Context {
            context: context.to_string(),
            cause: source.to_string(),
        })
    }
}

/// Extension trait that annotates foreign `Result`s with stow-style context.
///
/// Implemented for every `Result<T, E: Display>`; the source error's
/// `Display` output becomes the wrapped cause.
pub trait Context<T> {
    /// Convert the error into [`Error`] with `context` prepended.
    ///
    /// # Errors
    /// Returns the source error wrapped in `context` when `self` is `Err`.
    fn wrap_err(self, context: impl Display) -> Result<T>;
    /// Lazily evaluated variant of [`Context::wrap_err`]: `context` runs only
    /// when `self` is `Err`.
    ///
    /// # Errors
    /// Returns the source error wrapped in `context()` when `self` is `Err`.
    fn wrap_err_with<C>(self, context: impl FnOnce() -> C) -> Result<T>
    where
        C: Display;
}

impl<T, E> Context<T> for std::result::Result<T, E>
where
    E: Display,
{
    fn wrap_err(self, context: impl Display) -> Result<T> {
        self.map_err(|source| Error::context_with_source(context, source))
    }

    fn wrap_err_with<C>(self, context: impl FnOnce() -> C) -> Result<T>
    where
        C: Display,
    {
        self.map_err(|source| Error::context_with_source(context(), source))
    }
}

impl<E> From<E> for Error
where
    E: StdError + Send + Sync + 'static,
{
    fn from(value: E) -> Self {
        Self::msg(value.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Build an [`Error`](crate::error::Error) from a `format!`-style message.
#[macro_export]
macro_rules! stow_error {
    ($($arg:tt)*) => {
        $crate::error::Error::msg(format!($($arg)*))
    };
}

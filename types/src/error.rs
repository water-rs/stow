use std::error::Error as StdError;
use std::fmt::Display;

use thiserror::Error as ThisError;

#[derive(Debug)]
pub struct Error(ErrorKind);

#[derive(Debug, ThisError)]
enum ErrorKind {
    #[error("{0}")]
    Message(String),
    #[error("{context}: {cause}")]
    Context { context: String, cause: String },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn msg(message: impl Into<String>) -> Self {
        Self(ErrorKind::Message(message.into()))
    }

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

pub trait Context<T> {
    fn wrap_err(self, context: impl Display) -> Result<T>;
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

#[macro_export]
macro_rules! stow_error {
    ($($arg:tt)*) => {
        $crate::error::Error::msg(format!($($arg)*))
    };
}

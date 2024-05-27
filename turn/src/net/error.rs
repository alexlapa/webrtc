use std::io;

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    #[error("Invalid mask")]
    ErrInvalidMask,

    #[error("{0}")]
    Io(#[source] IoError),

    #[error("{0}")]
    Std(#[source] StdError),
}

impl Error {
    pub fn from_std<T>(error: T) -> Self
    where
        T: std::error::Error + Send + Sync + 'static,
    {
        Error::Std(StdError(Box::new(error)))
    }

    pub fn downcast_ref<T: std::error::Error + 'static>(&self) -> Option<&T> {
        if let Error::Std(s) = self {
            return s.0.downcast_ref();
        }

        None
    }
}

#[derive(Debug, Error)]
#[error("io error: {0}")]
pub struct IoError(#[from] pub io::Error);

// Workaround for wanting PartialEq for io::Error.
impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.0.kind() == other.0.kind()
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(IoError(e))
    }
}

/// An escape hatch to preserve stack traces when we don't know the error.
///
/// This crate exports some traits such as `Conn` and `Listener`. The trait
/// functions produce the local error `util::Error`. However when used in crates
/// higher up the stack, we are forced to handle errors that are local to that
/// crate. For example we use `Listener` the `dtls` crate and it needs to handle
/// `dtls::Error`.
///
/// By using `util::Error::from_std` we can preserve the underlying error (and
/// stack trace!).
#[derive(Debug, Error)]
#[error("{0}")]
pub struct StdError(pub Box<dyn std::error::Error + Send + Sync>);

impl PartialEq for StdError {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

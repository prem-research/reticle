use std::{convert::Infallible, fmt::Display};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[macro_export]
macro_rules! bail {
    ($msg:expr) => {
        return libattest::error::AttestationError::internal($msg);
    };

    (exposed: $msg:expr) => {
        return libattest::error::AttestationError::exposed($msg);
    };
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    #[default]
    Internal,
    Exposed(Vec<String>),
}

// #[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Debug)]
pub struct AttestationError {
    kind: ErrorKind,
    error: anyhow::Error,
}

fn format_exposed(errors: impl IntoIterator<Item = String>) -> String {
    // errors
    //     .into_iter()
    //     .enumerate()
    //     .map(|(n, err)| if n == 0 { err } else { format!(" → {err}") })
    //     .collect()
    errors.into_iter().next().unwrap_or_default()
}

#[cfg(target_family = "wasm")]
impl From<AttestationError> for JsValue {
    fn from(value: AttestationError) -> Self {
        let cause: Vec<String> = value
            .error
            .chain()
            .enumerate()
            .map(|(n, cause)| format!("{cause}"))
            .collect();

        let error_message = match value.kind {
            ErrorKind::Internal => "An internal error occurred",
            ErrorKind::Exposed(exposed) => &format_exposed(exposed),
        };

        let error = js_sys::Error::new(error_message);
        error.set_name("AttestationError");
        error.set_cause(&cause.into());
        error.into()
    }
}

impl Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::Internal => self.error.fmt(f),
            ErrorKind::Exposed(ref exp) => f.write_str(&format_exposed(exp.iter().cloned())),
        }
    }
}

impl AttestationError {
    pub fn internal<T>(message: &'static str) -> Result<T, Self> {
        Err(Self {
            kind: ErrorKind::Internal,
            error: anyhow::Error::msg(message),
        })
    }

    /// Exposes the last error in the chain for the user to
    /// see. If called multiple times, the exposed errors will be chained
    pub fn exposed<T>(message: &'static str) -> Result<T, Self> {
        Self::internal(message).expose_error()
    }

    pub fn expose(mut self) -> Self {
        let last_message = self.error.to_string();
        match self.kind {
            ErrorKind::Internal => self.kind = ErrorKind::Exposed(vec![last_message]),
            ErrorKind::Exposed(ref mut exposed) => exposed.push(last_message),
        }
        self
    }

    pub(crate) fn from_anyhow(error: anyhow::Error) -> Self {
        AttestationError {
            error,
            kind: ErrorKind::Internal,
        }
    }
}

impl From<AttestationError> for anyhow::Error {
    fn from(value: AttestationError) -> Self {
        value.error
    }
}

#[allow(clippy::missing_errors_doc)]
pub trait Context<T, E> {
    fn context<C>(self, context: C) -> Result<T, AttestationError>
    where
        C: Display + Send + Sync + 'static;

    fn with_context<C, F>(self, f: F) -> Result<T, AttestationError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

impl<A> Context<A, AttestationError> for Result<A, AttestationError> {
    fn context<C>(self, context: C) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
    {
        self.map_err(|AttestationError { kind, error }| AttestationError {
            kind,
            error: error.context(context),
        })
    }

    fn with_context<C, F>(self, f: F) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|AttestationError { kind, error }| AttestationError {
            kind,
            error: error.context(f()),
        })
    }
}

impl<A, B: Send + Sync + 'static + std::error::Error> Context<A, B> for Result<A, B> {
    fn context<C>(self, context: C) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
    {
        anyhow::Context::context(self, context).map_err(AttestationError::from_anyhow)
    }

    fn with_context<C, F>(self, f: F) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        anyhow::Context::with_context(self, f).map_err(AttestationError::from_anyhow)
    }
}

impl<A> Context<A, Infallible> for Option<A> {
    fn context<C>(self, context: C) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
    {
        anyhow::Context::context(self, context).map_err(AttestationError::from_anyhow)
    }

    fn with_context<C, F>(self, f: F) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        anyhow::Context::with_context(self, f).map_err(AttestationError::from_anyhow)
    }
}

impl<T: std::error::Error + Send + Sync + 'static> From<T> for AttestationError {
    fn from(value: T) -> Self {
        Self {
            kind: ErrorKind::Internal,
            error: value.into(),
        }
    }
}

pub trait Expose {
    /// Exposes the last error in the chain for the user to
    /// see. If called multiple times, the exposed errors will be chained
    fn expose_error(self) -> Self;
}

impl<T> Expose for Result<T, AttestationError> {
    fn expose_error(self) -> Self {
        self.map_err(AttestationError::expose)
    }
}

#[cfg(target_family = "wasm")]
pub mod root;

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
pub enum Exposure {
    #[default]
    Internal,
    Exposed(Vec<String>),
}

#[derive(Debug)]
pub struct AttestationError {
    exposure: Exposure,
    error: anyhow::Error,

    #[cfg(target_family = "wasm")]
    root: Option<JsValue>,
}

fn format_exposed(errors: impl IntoIterator<Item = String>) -> String {
    errors.into_iter().next().unwrap_or_default()
}

#[cfg(target_family = "wasm")]
impl From<AttestationError> for JsValue {
    fn from(value: AttestationError) -> Self {
        let cause: Vec<String> = value
            .error
            .chain()
            .map(|cause| format!("{cause}"))
            .collect();

        let error_message = match value.exposure {
            Exposure::Internal => "An internal error occurred",
            Exposure::Exposed(exposed) => &format_exposed(exposed),
        };

        let error = js_sys::Error::new(error_message);
        error.set_name("AttestationError");
        error.set_cause(&cause.into());

        // expose root to .kind property
        // if the root error is js representable
        if let Some(root) = value.root {
            js_sys::Reflect::set(&error, &"kind".into(), &root).unwrap();
        }

        error.into()
    }
}

impl Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.exposure {
            Exposure::Internal => self.error.fmt(f),
            Exposure::Exposed(ref exp) => f.write_str(&format_exposed(exp.iter().cloned())),
        }
    }
}

impl AttestationError {
    pub fn new<E>(error: E) -> Self
    where
        E: Send + Display + std::fmt::Debug + Sync + 'static,
    {
        let error = anyhow::format_err!(error);

        Self {
            exposure: Exposure::Internal,
            error,
            #[cfg(target_family = "wasm")]
            root: None,
        }
    }

    #[cfg(target_family = "wasm")]
    pub fn with_root<E>(error: E) -> Self
    where
        E: Send + Display + std::fmt::Debug + Send + Sync + 'static,
        E: Into<JsValue> + Clone,
    {
        let value: JsValue = error.clone().into();
        AttestationError {
            root: Some(value),
            ..AttestationError::new(error)
        }
    }

    #[cfg(not(target_family = "wasm"))]
    pub fn with_root<E>(error: E) -> Self
    where
        E: Send + Display + std::fmt::Debug + Sync + 'static,
    {
        Self::new(error)
    }

    pub fn internal<T>(message: &'static str) -> Result<T, Self> {
        Err(Self {
            exposure: Exposure::Internal,
            error: anyhow::Error::msg(message),
            #[cfg(target_family = "wasm")]
            root: None,
        })
    }

    /// Exposes the last error in the chain for the user to
    /// see. If called multiple times, the exposed errors will be chained
    pub fn exposed<T>(message: &'static str) -> Result<T, Self> {
        Self::internal(message).expose_error()
    }

    pub fn expose(mut self) -> Self {
        let last_message = self.error.to_string();
        match self.exposure {
            Exposure::Internal => self.exposure = Exposure::Exposed(vec![last_message]),
            Exposure::Exposed(ref mut exposed) => exposed.push(last_message),
        }
        self
    }

    pub(crate) fn from_anyhow(error: anyhow::Error) -> Self {
        AttestationError {
            error,
            exposure: Exposure::Internal,
            #[cfg(target_family = "wasm")]
            root: None,
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
        self.map_err(|x| AttestationError {
            error: x.error.context(context),
            ..x
        })
    }

    fn with_context<C, F>(self, f: F) -> Result<A, AttestationError>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|c| AttestationError {
            error: c.error.context(f()),
            ..c
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
            exposure: Exposure::Internal,
            error: value.into(),

            #[cfg(target_family = "wasm")]
            root: None,
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

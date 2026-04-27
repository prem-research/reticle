use std::fmt::Display;

use wasm_bindgen::JsValue;

use crate::error::AttestationError;

pub trait Root<T> {
    fn js_root(self) -> Result<T, AttestationError>;
}

impl<T, E> Root<T> for Result<T, E>
where
    E: Send + Display + std::fmt::Debug + Send + Sync + 'static,
    E: Into<JsValue> + Clone,
{
    fn js_root(self) -> Result<T, AttestationError> {
        self.map_err(AttestationError::with_root)
    }
}

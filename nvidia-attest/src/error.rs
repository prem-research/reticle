use thiserror::Error;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::verifiers::VerificationError;

#[derive(Error, Debug)]
pub enum GpuAttestationError {
    #[error("parsing error: {0}")]
    Parse(&'static str),
    #[error("verification error: {0}")]
    Verification(&'static str),
    #[error("json parsing error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("failed validation: {0}")]
    Validation(#[from] VerificationError),
    #[error("json web token error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("the key used to encode this jwt is not in the keychain")]
    MissingKey,
}

#[cfg(target_family = "wasm")]
impl From<GpuAttestationError> for JsValue {
    fn from(value: GpuAttestationError) -> Self {
        JsError::from(value).into()
    }
}

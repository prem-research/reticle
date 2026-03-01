use std::str::FromStr;

use reqwest::Url;
use thiserror::Error;
use wasm_bindgen::{JsError, JsValue};

#[derive(Error, Debug)]
pub enum PremErr {
    #[error("error parsing the server url")]
    Parse(<Url as FromStr>::Err),
    #[error("error requesting prem's server: ${0}")]
    Request(#[from] reqwest::Error),
    #[error("error from sev attestation: ${0}")]
    Sev(#[from] snp_attest::error::AttestationError),
    #[error("error from nvidia attestation: ${0}")]
    Nvidia(#[from] nvidia_attest::error::GpuAttestationError),
}

impl From<PremErr> for JsValue {
    fn from(value: PremErr) -> Self {
        JsError::from(value).into()
    }
}

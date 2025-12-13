use thiserror::Error;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;
use x509_parser::error::X509Error;

// #[wasm_bindgen]
#[derive(Error, Debug)]
pub enum VerificationReason {
    #[error("received bad product name from kds")]
    BadProductName,
    #[error("spl")]
    Spl,
    #[error("mismatched chip id")]
    ChipId,
}

#[derive(Error, Debug)]
pub enum ParseReason {
    #[error("unable to decode product name from attestation certificate")]
    DecodeProductName,
    #[error("found bad data when parsing the attestation report")]
    BadAttestationData,
    #[error("missing field from attestation report")]
    MissingAttestationField,
    #[error("unable to idenfity cpu")]
    IdentifyCpu,
}

// #[wasm_bindgen]
#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("error parsing the pem certificate: {0}")]
    X509Cert(#[from] der::Error),
    #[error("error parsing the pem certificate: {0}")]
    X509Parse(#[from] X509Error),
    #[error("error parsing the attestation report: {0}")]
    ParseAttestation(#[from] ParseReason),
    #[error("one or more supplied certificates were revoked")]
    RevokedCertificate,
    #[error("error while verifying attestation claims")]
    Verification(#[from] VerificationReason),
    #[error("unable to get certificates from KDS keychain")]
    KdsRequest,
    #[error("a pem signature was invalid")]
    Signature,
    #[error("mismatched nonce between attestation and user provided data")]
    WrongNonce,
}

#[cfg(target_family = "wasm")]
impl From<AttestationError> for JsValue {
    fn from(value: AttestationError) -> Self {
        JsError::from(value).into()
    }
}

// pub trait LogError {
//     fn log_err(self) -> Self;
// }

// impl<T, E: std::fmt::Display> LogError for Result<T, E> {
//     fn log_err(self) -> Self {
//         if let Err(ref err) = self {
//             log::error!("{err}");
//         }
//         self
//     }
// }

#[cfg(feature = "logger")]
mod logger {
    use wasm_log::Config;

    #[wasm_bindgen(start)]
    fn start() {
        wasm_log::init(Config::default());
    }
}

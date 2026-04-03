use std::{backtrace::Backtrace, convert::Infallible, fmt::Display};

use libattest::error::AttestationError;

use crate::{certificates::CertificateError, dcap::parser::ParseError};

pub type TdxError = AttestationError;
// #[derive(Error, Debug)]
// pub enum Error {
//     #[error("certificate error: {0}")]
//     Certificate(#[from] CertificateError),

//     #[error("error parsing the dcap quote: {0}")]
//     Parse(#[from] ParseError),

//     #[error("cryptographic error: {0}")]
//     Crypto(#[from] p256::ecdsa::Error),

//     #[error("this error")]
//     SignatureFormat(#[from] sec1::Error),

//     #[error("error returned from pcs: {0}")]
//     Reqwest(#[from] reqwest::Error),

//     #[error("failed parsing json data: {0}")]
//     Json(#[from] serde_json::Error),

//     #[error("pcs response did not include a certificate chain header")]
//     MissingCertChain,
// }

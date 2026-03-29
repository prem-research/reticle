#![warn(clippy::pedantic)]
#![allow(unused, clippy::missing_panics_doc)]

use p256::ecdsa::VerifyingKey;
use p256::{EncodedPoint, elliptic_curve};
use p256::{PublicKey, ecdsa::Signature};

use crate::certificates::ca;
use crate::certificates::extensions::{SgxExtension, SgxExtensions};
use crate::dcap::TdQuote;
use crate::dcap::parser::Parse;
use crate::error::{Context, TdxError};

use crate::{
    certificates::CertificateChain,
    dcap::types::{EnclaveReport, TdxQuoteBody, TdxQuoteHeader},
};

pub(crate) mod certificates;
pub mod dcap;
pub mod error;
pub mod keychain;
pub mod nonce;
pub mod pcs;
pub mod quote;
pub mod verify;

pub use quote::*;

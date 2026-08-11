pub mod claims;
pub mod pcr;
pub mod verify;

use libattest::validation::Verifiable;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use snp_attest::SevQuote;
use tdx_attest::TdxQuote;
use tpm2_protocol::data::TpmsAttest;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    collateral::ReportVerifier,
    nonce::AzureNonce,
    quote::{claims::AzureClaims, pcr::PcrBankReading},
    report::{AttestationReport, HardwareReport},
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AzureTrust {
    quote_signature: rsa::pkcs1v15::Signature,
    ak_key: rsa::pkcs1v15::VerifyingKey<Sha256>,

    #[serde(with = "crate::serde::serde_cert")]
    ak_cert: x509_cert::Certificate,
}

impl AzureTrust {
    pub fn new(
        quote_signature: rsa::pkcs1v15::Signature,
        ak_key: rsa::pkcs1v15::VerifyingKey<Sha256>,
        ak_cert: x509_cert::Certificate,
    ) -> Self {
        Self {
            quote_signature,
            ak_key,
            ak_cert,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct AzureQuote {
    #[serde(with = "crate::serde::serde_tpm")]
    quote: TpmsAttest,
    /// we store a single bank in the quote as we are requesting a single bank
    /// from the vtpm (sha256)
    pcr_bank: PcrBankReading<Sha256>,
    hardware_report: AttestationReport,
    trust: AzureTrust,
}

// create only implementations
impl AzureQuote {
    pub(crate) fn new(
        quote: TpmsAttest,
        pcr_bank: PcrBankReading<Sha256>,
        hardware_report: AttestationReport,
        trust: AzureTrust,
    ) -> Self {
        Self {
            quote,
            hardware_report,
            pcr_bank,
            trust,
        }
    }

    pub(crate) fn parse_hardware_report(&self) -> libattest::Result<ParsedHardwareReport> {
        let report = match &self.hardware_report.payload {
            HardwareReport::Tdx(items) => ParsedHardwareReport::Tdx(TdxQuote::from_bytes(items)?),
            HardwareReport::Sev(items) => ParsedHardwareReport::Sev(SevQuote::new(items)?),
        };

        Ok(report)
    }
}

impl Verifiable for AzureQuote {
    type Claims<'x>
        = AzureClaims<'x>
    where
        Self: 'x;
}

pub(crate) enum ParsedHardwareReport {
    Tdx(TdxQuote),
    Sev(SevQuote),
}

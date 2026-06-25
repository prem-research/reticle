pub mod verify;

use serde::{Deserialize, Serialize};
use sha2::Sha256;
use snp_attest::SevQuote;
use tdx_attest::TdxQuote;
use tpm2_protocol::data::TpmsAttest;

use crate::report::{AttestationReport, HardwareReport};

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
pub struct AzureQuote {
    #[serde(with = "crate::serde::serde_tpm")]
    quote: TpmsAttest,
    hardware_report: AttestationReport,

    trust: AzureTrust,
}

impl AzureQuote {
    pub fn new(quote: TpmsAttest, hardware_report: AttestationReport, trust: AzureTrust) -> Self {
        Self {
            quote,
            hardware_report,
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

pub(crate) enum ParsedHardwareReport {
    Tdx(TdxQuote),
    Sev(SevQuote),
}

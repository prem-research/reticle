pub mod report;
mod serde_cert;
mod serde_tpm;

use rsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tpm2_protocol::{TpmMarshal, TpmUnmarshal, TpmWriter, data::TpmsAttest};

use crate::report::AttestationReport;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AzureTrust {
    quote_signature: rsa::pkcs1v15::Signature,
    ak_key: rsa::pkcs1v15::VerifyingKey<Sha256>,

    #[serde(with = "serde_cert")]
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
    #[serde(with = "serde_tpm")]
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

    // pub fn parse(data: &AzureQuoteData) -> libattest::Result<Self> {
    //     let (attestation, _) = TpmsAttest::unmarshal(&data.quote)?;

    //     Ok(Self {
    //         quote: attestation,
    //         hardware_report: data.hardware_report.clone(),
    //         trust: data.trust.clone(),
    //     })
    // }

    pub fn verify(&self) -> libattest::Result<()> {
        let mut buffer = Box::new([0u8; 2048]);

        let mut writer = TpmWriter::new(buffer.as_mut_slice());
        self.quote.attested.marshal(&mut writer)?;
        let written = writer.len();

        let marshaled = &buffer[..written];

        self.trust
            .ak_key
            .verify(marshaled, &self.trust.quote_signature)?;

        todo!()
    }
}

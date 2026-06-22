mod serde_cert;

use rsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snp_attest::ParsedAttestation;
use tdx_attest::TdxQuote;
use tpm2_protocol::{TpmMarshal, TpmUnmarshal, TpmWriter, data::TpmsAttest};

#[derive(Deserialize)]
enum HardwareReportType {
    Tdx(Vec<u8>),
    Sev(Vec<u8>),
}

#[derive(Deserialize)]
pub struct AzureQuoteData {
    quote: Vec<u8>,
    hardware_report: HardwareReportType,

    trust: AzureTrust,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AzureTrust {
    quote_signature: rsa::pkcs1v15::Signature,
    ak_key: rsa::pkcs1v15::VerifyingKey<Sha256>,

    #[serde(with = "serde_cert")]
    ak_cert: x509_cert::Certificate,
}

pub enum AzureHardwareReport {
    Tdx(TdxQuote),
    Sev(ParsedAttestation),
}

pub struct AzureQuote {
    quote: TpmsAttest,
    hardware_report: AzureHardwareReport,

    trust: AzureTrust,
}

impl AzureQuote {
    pub fn parse(data: &AzureQuoteData) -> libattest::Result<Self> {
        let (attestation, _) = TpmsAttest::unmarshal(&data.quote)?;

        let hardware_report = match &data.hardware_report {
            HardwareReportType::Tdx(data) => AzureHardwareReport::Tdx(TdxQuote::from_bytes(data)?),
            HardwareReportType::Sev(data) => {
                AzureHardwareReport::Sev(ParsedAttestation::new(data)?)
            }
        };

        Ok(Self {
            quote: attestation,
            hardware_report,
            trust: data.trust.clone(),
        })
    }

    pub async fn verify(&self) -> libattest::Result<()> {
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

use libattest::error::Context;
use p256::ecdsa::{Signature, VerifyingKey};

use crate::{
    certificates::{CertificateChain, ca, extensions::SgxExtensions},
    dcap::{
        self, TdQuote,
        parser::Parse,
        types::{EnclaveReport, TdxQuoteBody, TdxQuoteHeader},
    },
    error::TdxError,
};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug)]
pub struct QeReportCertificationData {
    pub(crate) qe_report: EnclaveReport,
    pub(crate) qe_report_signature: Signature,
    pub(crate) authentication_data: Vec<u8>,
    pub(crate) certification_data: CertificationData,
}

#[derive(Debug)]
pub enum CertificationData {
    PlainText(Vec<u8>),
    EncryptedCpuSvnsRSA2048(Vec<u8>),
    EncryptedCpuSvnsRSA3072(Vec<u8>),
    PckChain(CertificateChain),
    QeReportCertificationData(Box<QeReportCertificationData>),
}

impl CertificationData {
    /// Digs into the recursive data structure until it finds
    /// a certificate chain.
    ///
    /// Returns Some if the leaf of this data structure has a certificate chain, None if
    /// trust is based on other identifiers
    pub fn pck_chain(&self) -> Option<&CertificateChain> {
        match self {
            Self::QeReportCertificationData(data) => data.certification_data.pck_chain(),
            Self::PckChain(chain) => Some(chain),
            _ => None,
        }
    }

    pub fn qe_report(&self) -> Option<&QeReportCertificationData> {
        match self {
            Self::QeReportCertificationData(data) => Some(&data),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct TdxCertification {
    pub(crate) attestation_signature: Signature,
    pub(crate) attestation_key: VerifyingKey,
    pub(crate) data: CertificationData,
}

impl TdxCertification {
    /// Retrieves the SGX extensions from the leaf pck certificate.
    /// # Errors
    /// Returns error if no pck certificate could be found or if there was
    /// an error parsing the SGX X509 certificate extension
    pub fn sgx_extensions(&self) -> Result<SgxExtensions<'_>, TdxError> {
        let fmspc = self.data.pck_chain().context(
            "quote does not contain a pck certificate chain thus fmspc could not be derived",
        )?;

        let leaf = fmspc
            .leaf()
            .context("certificate chain provided in quote does not have any certificates")?;

        let (_, extensions) = leaf
            .cert()
            .get_extension::<SgxExtensions>()?
            .context("fmspc extension not found in pck certificate")?;

        Ok(extensions)
    }
}

#[derive(Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct TdxQuote {
    pub(crate) header: TdxQuoteHeader,
    pub(crate) body: TdxQuoteBody,
    pub(crate) certification: TdxCertification,
}

impl TdxQuote {
    #[must_use]
    pub fn header(&self) -> &TdxQuoteHeader {
        &self.header
    }

    #[must_use]
    pub fn body(&self) -> &TdxQuoteBody {
        &self.body
    }

    #[must_use]
    pub fn certification(&self) -> &TdxCertification {
        &self.certification
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl TdxQuote {
    /// Attempts to parse a quote from DCAP bytes.
    pub fn from_bytes(quote: &[u8]) -> Result<Self, TdxError> {
        let quote = TdQuote::parse(quote)?;
        let quote = quote.try_into()?;

        Ok(quote)
    }
}

/// public keys are encoded in dcap without the header for sec1 (0x04)
/// so we have to add it manually
fn decode_public_key(public_key: &[u8; 64]) -> Result<VerifyingKey, p256::ecdsa::Error> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(public_key);

    VerifyingKey::from_sec1_bytes(&sec1)
}

impl TryFrom<dcap::TdQuote<'_>> for TdxQuote {
    type Error = TdxError;
    fn try_from(value: dcap::TdQuote<'_>) -> Result<Self, Self::Error> {
        let header = value.quote_header.clone();
        let body = value.quote_body.clone();
        let certification = value.certification.try_into()?;

        Ok(Self {
            header,
            body,
            certification,
        })
    }
}

impl TryFrom<dcap::Certification<'_>> for TdxCertification {
    type Error = TdxError;
    fn try_from(value: dcap::Certification<'_>) -> Result<Self, Self::Error> {
        // let attestation_key = VerifyingKey::from_sec1_bytes(value.attestation_key)?;
        let attestation_key = decode_public_key(value.attestation_key)?;
        let attestation_signature = Signature::from_bytes(value.quote_signature.into())?;
        let certification_data = value.quote_data.try_into()?;

        Ok(Self {
            attestation_signature,
            attestation_key,
            data: certification_data,
        })
    }
}

impl TryFrom<dcap::QeCertificationData<'_>> for CertificationData {
    type Error = TdxError;
    fn try_from(value: dcap::QeCertificationData<'_>) -> Result<Self, Self::Error> {
        use dcap::QeCertificationData::*;

        let certification_data = match value {
            PlainText(x) => Self::PlainText(x.to_owned()),
            EncryptedCpuSvnsRSA2048(x) => Self::EncryptedCpuSvnsRSA2048(x.to_owned()),
            EncryptedCpuSvnsRSA3072(x) => Self::EncryptedCpuSvnsRSA3072(x.to_owned()),
            PckChain(chain) => {
                Self::PckChain(CertificateChain::with_anchor(&ca::INTEL_CA).parse_pem_chain(chain)?)
            }
            QeReportCertificationData(report) => {
                Self::QeReportCertificationData(Box::new((*report).try_into()?))
            }
        };

        Ok(certification_data)
    }
}

impl TryFrom<dcap::QeReportCertificationData<'_>> for QeReportCertificationData {
    type Error = TdxError;
    fn try_from(value: dcap::QeReportCertificationData<'_>) -> Result<Self, Self::Error> {
        let qe_report = value.qe_report.clone();
        let certification_data = value.certification_data.try_into()?;
        let qe_report_signature = Signature::from_bytes(value.qe_report_signature.into())?;
        let authentication_data = value.qe_authentication_data.inner().to_vec();

        Ok(Self {
            qe_report,
            qe_report_signature,
            authentication_data,
            certification_data,
        })
    }
}

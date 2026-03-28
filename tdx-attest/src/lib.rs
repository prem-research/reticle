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
    dcap::types::{EnclaveReport, QuoteBody, QuoteHeader},
};

pub mod certificates;
pub mod dcap;
pub mod error;
pub mod keychain;
pub mod nonce;
pub mod pcs;
pub mod verify;

#[derive(Debug)]
pub struct QeReportCertificationData {
    qe_report: EnclaveReport,
    qe_report_signature: Signature,
    authentication_data: Vec<u8>,
    certification_data: CertificationData,
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
pub struct Certification {
    pub(crate) attestation_signature: Signature,
    pub(crate) attestation_key: VerifyingKey,
    pub(crate) data: CertificationData,
}

impl Certification {
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
pub struct Quote {
    pub(crate) header: QuoteHeader,
    pub(crate) body: QuoteBody,
    pub(crate) certification: Certification,
}

impl Quote {
    #[must_use]
    pub fn header(&self) -> &QuoteHeader {
        &self.header
    }

    #[must_use]
    pub fn body(&self) -> &QuoteBody {
        &self.body
    }

    #[must_use]
    pub fn certification(&self) -> &Certification {
        &self.certification
    }

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

impl TryFrom<dcap::TdQuote<'_>> for Quote {
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

impl TryFrom<dcap::Certification<'_>> for Certification {
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

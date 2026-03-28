use std::ops::Deref;

use der::{Decode, DecodePem};
use sev::{
    certs::snp::{Certificate, Chain, Verifiable, ca},
    firmware::guest::AttestationReport,
};
use x509_cert::crl::{CertificateList, RevokedCert};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use super::error::AttestationError;

fn parse_pem_to_cert(pem: &str) -> Result<Certificate, AttestationError> {
    let certificate = x509_cert::Certificate::from_pem(pem)?;
    Ok(certificate.into())
}

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "sev"))]
#[derive(Debug, Clone)]
/// A chain which has been cryptographically verified
pub struct VerifiedChain(Chain);

impl Deref for VerifiedChain {
    type Target = Chain;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl VerifiedChain {
    pub(crate) fn verify(chain: Chain) -> Result<VerifiedChain, AttestationError> {
        chain.verify().map_err(|_| AttestationError::Signature)?;

        Ok(Self(chain))
    }

    pub(crate) fn check_signature(
        &self,
        report: &AttestationReport,
    ) -> Result<(), AttestationError> {
        (&self.0, report)
            .verify()
            .map_err(|_| AttestationError::Signature)
    }

    /// returns true if one of the certificates matches this serial number
    pub fn revoked(&self, revoked: &RevokedCert) -> bool {
        self.vek.cert().tbs_certificate.serial_number == revoked.serial_number
            || self.ca.ark.cert().tbs_certificate.serial_number == revoked.serial_number
            || self.ca.ask.cert().tbs_certificate.serial_number == revoked.serial_number
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl VerifiedChain {
    /// parses a triad of ark, ask and vek certificates in the PEM format,
    /// cryptographically verifies the chain is valid, returns a `VerifiedChain` object
    pub fn parse_verify(
        ark_pem: String,
        ask_pem: String,
        vek_pem: String,
    ) -> Result<VerifiedChain, AttestationError> {
        let ark = parse_pem_to_cert(&ark_pem)?;
        let ask = parse_pem_to_cert(&ask_pem)?;
        let vek = parse_pem_to_cert(&vek_pem)?;

        let ca = ca::Chain { ark, ask };
        let chain = Chain { ca, vek };

        let chain = VerifiedChain::verify(chain)?;

        Ok(chain)
    }

    pub fn to_pem(&self) -> Result<ExportPem, AttestationError> {
        Ok(ExportPem {
            ark: self.ca.ark.to_pem().unwrap(),
            ask: self.ca.ask.to_pem().unwrap(),
            vek: self.vek.to_pem().unwrap(),
        })
    }
}

#[cfg_attr(
    target_family = "wasm",
    wasm_bindgen(js_namespace = "sev", getter_with_clone)
)]
pub struct ExportPem {
    pub ark: Vec<u8>,
    pub ask: Vec<u8>,
    pub vek: Vec<u8>,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "sev"))]
/// A parsed certificate revocation list
pub struct CRL(x509_cert::crl::CertificateList);

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl CRL {
    /// Parses a certificate revocation list from DER format binary data
    pub fn from_der(list: &[u8]) -> Result<CRL, AttestationError> {
        CertificateList::from_der(list).map(CRL).map_err(Into::into)
    }

    /// Passes if the certificates are not in the certificate revocation list
    /// Throws `AttestationError` on fail
    pub fn check_chain(&self, chain: &VerifiedChain) -> Result<(), AttestationError> {
        let CRL(crl) = self;

        let revoked = crl
            .tbs_cert_list
            .revoked_certificates
            .iter()
            .flatten()
            .find(|revoked| chain.revoked(revoked));

        revoked
            .is_none()
            .then_some(())
            .ok_or(AttestationError::RevokedCertificate)
    }
}

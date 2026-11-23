use std::ops::Deref;

use der::{
    Decode, DecodePem, Encode,
    asn1::{AnyRef, ObjectIdentifier},
    referenced::OwnedToRef,
};
use libattest::error::{AttestationError, Context, Expose};
use rsa::{Pss, RsaPublicKey, pkcs1::RsaPssParams};
use sev::{
    certs::snp::{Certificate, Chain, Verifiable, ca},
    firmware::guest::AttestationReport,
};
use sha2::{Digest, Sha384};
use x509_cert::crl::{CertificateList, RevokedCert};

use super::kds::ARK;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

fn parse_pem_to_cert(pem: &str) -> Result<Certificate, AttestationError> {
    let certificate = x509_cert::Certificate::from_pem(pem)?;
    Ok(certificate.into())
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
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
        chain
            .verify()
            .context("could not verify certificate chain signature")
            .expose_error()?;

        Ok(Self(chain))
    }

    pub(crate) fn check_signature(
        &self,
        report: &AttestationReport,
    ) -> Result<(), AttestationError> {
        (&self.0, report)
            .verify()
            .context("could not verify certificate chain signature")
            .expose_error()
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

#[cfg_attr(target_family = "wasm", wasm_bindgen(getter_with_clone))]
pub struct ExportPem {
    pub ark: Vec<u8>,
    pub ask: Vec<u8>,
    pub vek: Vec<u8>,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
/// A certificate revocation list signed by an embedded AMD root.
pub struct CRL {
    list: CertificateList,
    signer: &'static Certificate,
}

impl CRL {
    pub fn verify(list: CertificateList) -> Result<Self, AttestationError> {
        const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
        const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
        const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

        let algorithm = &list.signature_algorithm;
        if algorithm.oid != RSA_PSS || *algorithm != list.tbs_cert_list.signature {
            return AttestationError::internal("invalid AMD CRL signature algorithm");
        }

        let params: RsaPssParams<'_> = algorithm
            .parameters
            .as_ref()
            .context("missing AMD CRL RSA-PSS parameters")?
            .decode_as()?;
        let mask_hash = params
            .mask_gen
            .parameters
            .context("missing AMD CRL MGF1 hash algorithm")?;
        if params.hash.oid != SHA384
            || params.hash.parameters.is_some_and(|p| p != AnyRef::NULL)
            || params.mask_gen.oid != MGF1
            || mask_hash.oid != SHA384
            || mask_hash.parameters.is_some_and(|p| p != AnyRef::NULL)
            || params.salt_len != 48
        {
            return AttestationError::internal("unsupported AMD CRL RSA-PSS parameters");
        }

        let digest = Sha384::digest(list.tbs_cert_list.to_der()?);
        let signature = list
            .signature
            .as_bytes()
            .context("invalid AMD CRL signature")?;
        let signer = ARK
            .values()
            .filter(|ark| ark.cert().tbs_certificate.subject == list.tbs_cert_list.issuer)
            .find(|ark| {
                let spki = &ark.cert().tbs_certificate.subject_public_key_info;
                RsaPublicKey::try_from(spki.owned_to_ref())
                    .is_ok_and(|key| key.verify(Pss::new::<Sha384>(), &digest, signature).is_ok())
            })
            .context("AMD CRL signature did not verify against the embedded ARKs")?;

        Ok(Self { list, signer })
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl CRL {
    /// Parses a DER certificate revocation list and verifies its signature.
    pub fn from_der(list: &[u8]) -> Result<CRL, AttestationError> {
        Self::verify(CertificateList::from_der(list)?)
    }

    /// Passes if the certificates are not in the certificate revocation list
    /// Throws `AttestationError` on fail
    pub fn check_chain(&self, chain: &VerifiedChain) -> Result<(), AttestationError> {
        if self.signer != &chain.ca.ark {
            return AttestationError::exposed(
                "AMD CRL signer does not match the certificate chain's ARK",
            );
        }

        let revoked = self
            .list
            .tbs_cert_list
            .revoked_certificates
            .iter()
            .flatten()
            .find(|revoked| chain.revoked(revoked));

        if revoked.is_some() {
            return AttestationError::exposed("certificate has been revoked");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_amd_crl_signature() {
        // AMD KDS Genoa CRL number 12.
        let der = include_bytes!("certificates/test/genoa_crl.der");
        let crl = CRL::from_der(der).unwrap();
        assert_eq!(crl.signer, &ARK["Genoa"]);

        let mut tampered = *der;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(CRL::verify(CertificateList::from_der(&tampered).unwrap()).is_err());
    }
}

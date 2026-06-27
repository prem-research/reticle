use der::{
    Encode,
    oid::db::{rfc5753::ID_EC_PUBLIC_KEY, rfc5912::ECDSA_WITH_SHA_256},
};
use p256::ecdsa::{Signature, VerifyingKey};
use signature::Verifier;
use x509_cert::certificate::TbsCertificateInner;

use crate::crypto::{
    CertificateError,
    algorithms::{Cert, CertFormat, verify_cert_common},
};

#[derive(Debug)]
pub struct EcdsaCert {
    /// the original certificate where public_key and signature were derived from
    certificate: x509_cert::Certificate,
    /// this is the public key the certificate is trying to attest
    public_key: VerifyingKey,
    /// this is the signature attesting the authenticity and trustworthyness of the public key
    signature: Signature,
}

impl super::sealed::Sealed for EcdsaCert {}

impl CertFormat for EcdsaCert {
    fn from_certificate(cert: x509_cert::Certificate) -> Result<Self, CertificateError> {
        Self::from_cert(cert)
    }

    fn certificate(&self) -> &TbsCertificateInner {
        self.certificate.tbs_certificate()
    }
}

impl signature::Verifier<Signature> for EcdsaCert {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
        self.public_key.verify(msg, signature)
    }
}

impl Cert for EcdsaCert {
    /// verifies that this certificate (`self`) contains a signed public key
    /// that attests for the authenticity of the signature of another certificate (`other`)
    ///
    /// # Errors
    /// Returns error if the two certificates cannot be linked by cryptographical means
    fn verify_cert(&self, other: &Self) -> Result<(), CertificateError> {
        let other_tbs = other.certificate.tbs_certificate().to_der()?;
        self.public_key
            .verify(&other_tbs, &other.signature)
            .map_err(CertificateError::BadSignature)?;

        Ok(())
    }
}

pub type PinnedCertificate = &'static EcdsaCert;

impl EcdsaCert {
    #[must_use]
    pub fn cert(&self) -> &TbsCertificateInner {
        self.certificate.tbs_certificate()
    }

    /// verifies if the certificate is self-signed
    ///
    /// # Errors
    /// Returns error if trust cannot be enstablished
    /// within self
    pub fn verify_self(&self) -> Result<(), CertificateError> {
        self.verify_cert(self)
    }

    /// Steps:
    /// - decode signature and public key
    /// - check for certificate validity
    fn from_cert(certificate: x509_cert::Certificate) -> Result<Self, CertificateError> {
        // Check that the signature and public key are in the
        // format supported by the library (elliptic curve certificates)
        certificate
            .signature_algorithm()
            .assert_algorithm_oid(ECDSA_WITH_SHA_256)
            .map_err(CertificateError::WrongAlgorithm)?;

        certificate
            .tbs_certificate()
            .subject_public_key_info()
            .algorithm
            .assert_algorithm_oid(ID_EC_PUBLIC_KEY)
            .map_err(CertificateError::WrongAlgorithm)?;

        // signature
        let signature = certificate
            .signature()
            .as_bytes()
            .ok_or(CertificateError::WrongFormat)?;

        let signature =
            Signature::from_der(signature).expect("could not re-decode an encoded signature");

        // signed public key
        let public_key = certificate
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .as_bytes()
            .ok_or(CertificateError::WrongFormat)?;

        let public_key = VerifyingKey::from_sec1_bytes(public_key)
            .expect("could not re-decode an encoded public key");

        verify_cert_common(&certificate)?;

        Ok(Self {
            certificate,
            public_key,
            signature,
        })
    }
}

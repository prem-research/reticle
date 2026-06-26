use der::{
    Encode,
    oid::db::rfc5912::{RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION},
};
use rsa::{
    RsaPublicKey,
    pkcs1::DecodeRsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
    signature::Verifier,
};
use sha2::Sha384;
use x509_cert::certificate::TbsCertificateInner;

use crate::certificates::{
    CertificateError,
    format::{Cert, CertFormat, Verify, verify_cert_common},
};

#[derive(Debug)]
pub struct RsaCert {
    certificate: x509_cert::Certificate,
    public_key: VerifyingKey<Sha384>,
    signature: Signature,
}

impl super::sealed::Sealed for RsaCert {}

impl CertFormat for RsaCert {
    type Signature = Signature;

    fn from_certificate(cert: x509_cert::Certificate) -> Result<Self, CertificateError> {
        Self::from_cert(cert)
    }

    fn cetificate(&self) -> &TbsCertificateInner {
        self.certificate.tbs_certificate()
    }
}

impl Verify<Signature> for RsaCert {
    fn verify_signature(&self, msg: &[u8], signature: &Signature) -> Result<(), CertificateError> {
        self.public_key.verify(msg, signature).map_err(Into::into)
    }
}

impl Cert for RsaCert {
    fn verify_cert(&self, other: &Self) -> Result<(), CertificateError> {
        let other_tbs = other.certificate.tbs_certificate().to_der()?;
        self.verify_signature(&other_tbs, &other.signature)
    }
}

impl RsaCert {
    fn from_cert(certificate: x509_cert::Certificate) -> Result<Self, CertificateError> {
        certificate
            .signature_algorithm()
            .assert_algorithm_oid(SHA_384_WITH_RSA_ENCRYPTION)
            .map_err(CertificateError::WrongAlgorithm)?;

        let pk = certificate.tbs_certificate().subject_public_key_info();
        pk.algorithm
            .assert_algorithm_oid(RSA_ENCRYPTION)
            .map_err(CertificateError::WrongAlgorithm)?;

        let signature = certificate
            .signature()
            .as_bytes()
            .ok_or(CertificateError::WrongFormat)
            .and_then(|sig| Signature::try_from(sig).map_err(Into::into))?;

        let public_key = RsaPublicKey::from_pkcs1_der(pk.subject_public_key.raw_bytes())
            .map(VerifyingKey::new)
            .map_err(|_| CertificateError::WrongFormat)?;

        verify_cert_common(&certificate)?;

        Ok(Self {
            certificate,
            public_key,
            signature,
        })
    }
}

impl TryFrom<x509_cert::Certificate> for RsaCert {
    type Error = CertificateError;

    fn try_from(value: x509_cert::Certificate) -> Result<Self, Self::Error> {
        Self::from_cert(value)
    }
}

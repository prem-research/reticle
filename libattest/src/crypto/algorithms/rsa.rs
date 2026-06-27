use std::sync::Arc;

use der::{
    Encode,
    oid::db::rfc5912::{RSA_ENCRYPTION, SHA_256_WITH_RSA_ENCRYPTION, SHA_384_WITH_RSA_ENCRYPTION},
};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs1v15::Signature, signature::Verifier};
use sha2::{Sha256, Sha384};
use x509_cert::certificate::TbsCertificateInner;

use crate::crypto::{
    CertificateError, DigestSignature,
    algorithms::{Cert, CertFormat, verify_cert_common},
    signature::rsa::RsaSignature,
};

#[derive(Clone)]
pub struct RsaCert {
    certificate: x509_cert::Certificate,

    /// verifyingkey algorithm is dictated by the format
    /// of the signature, not by our public key, so we keep generic
    public_key: RsaPublicKey,

    // this should be Signature<Digest / Type>.
    signature: Arc<dyn DigestSignature + Send + Sync>,
}

impl super::sealed::Sealed for RsaCert {}

impl CertFormat for RsaCert {
    fn from_certificate(cert: x509_cert::Certificate) -> Result<Self, CertificateError> {
        Self::from_cert(cert)
    }

    fn certificate(&self) -> &TbsCertificateInner {
        self.certificate.tbs_certificate()
    }
}

impl<D: DigestSignature> Verifier<D> for RsaCert {
    fn verify(&self, msg: &[u8], signature: &D) -> Result<(), signature::Error> {
        signature.verify(msg, &self.public_key.clone())
    }
}

impl Cert for RsaCert {
    fn verify_cert(&self, other: &Self) -> Result<(), CertificateError> {
        let other_tbs = other.certificate.tbs_certificate().to_der()?;

        let public_key = self.public_key.clone();

        other
            .signature
            .verify(&other_tbs, &public_key)
            .map_err(CertificateError::BadSignature)
    }
}

impl RsaCert {
    fn from_cert(certificate: x509_cert::Certificate) -> Result<Self, CertificateError> {
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
            .map_err(|_| CertificateError::WrongFormat)?;

        verify_cert_common(&certificate)?;

        let signature: Arc<dyn DigestSignature + Send + Sync> =
            match certificate.signature_algorithm().oid {
                SHA_384_WITH_RSA_ENCRYPTION => Arc::new(RsaSignature::<Sha384>::new(signature)),
                SHA_256_WITH_RSA_ENCRYPTION => Arc::new(RsaSignature::<Sha256>::new(signature)),
                _ => return Err(CertificateError::Unsupported),
            };

        Ok(Self {
            certificate,
            public_key,
            signature,
        })
    }
}

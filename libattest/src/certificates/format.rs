use x509_cert::certificate::TbsCertificateInner;

use crate::certificates::CertificateError;

pub mod ecdsa;
pub mod rsa;

mod sealed {
    pub trait Sealed {}
}

pub trait CertFormat: Sized + sealed::Sealed {
    type Signature;

    /// Parse this certificate format from the generix `x509_cert::Certificate` type
    fn from_certificate(cert: x509_cert::Certificate) -> Result<Self, CertificateError>;

    /// Get inner signed data of this certificate
    fn cetificate(&self) -> &TbsCertificateInner;
}

pub trait Verify<Signature> {
    /// Uses the public component of this certificate to verify another signature
    /// over arbitrary data.
    fn verify_signature(&self, msg: &[u8], signature: &Signature) -> Result<(), CertificateError>;
}

pub trait Cert: CertFormat + Verify<Self::Signature> {
    /// Verifies that the public component of this certificate signs another certificate's TBS
    fn verify_cert(&self, other: &Self) -> Result<(), CertificateError>;

    /// Verifies that the public component of this certificate signs its own TBS.
    /// This is the case for Certificate Authorities (root of trust)
    fn verify_self(&self) -> Result<(), CertificateError> {
        self.verify_cert(self)
    }
}

fn verify_cert_common(certificate: &x509_cert::Certificate) -> Result<(), CertificateError> {
    // check for certificate validity
    let not_after = certificate
        .tbs_certificate()
        .validity()
        .not_after
        .to_system_time();

    let not_before = certificate
        .tbs_certificate()
        .validity()
        .not_before
        .to_system_time();

    let now = crate::now();

    if not_before > now || not_after < now {
        return Err(CertificateError::Expired);
    }

    Ok(())
}

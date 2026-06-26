pub mod crl;
pub mod error;
pub mod format;

pub use error::CertificateError;

use crate::certificates::format::{Cert, Verify};

pub type PinnedCertificate<C: Cert> = &'static C;

#[derive(Debug)]
/// represents a cryptographically verified
/// certificate chain
pub struct CertificateChain<C: Cert + 'static> {
    /// optional trust anchor of a pinned certificate
    anchor: Option<PinnedCertificate<C>>,
    /// a chain of certificates. Last one is leaf.
    chain: Vec<C>,
}

impl<C: Cert + 'static> CertificateChain<C> {
    #[must_use]
    pub fn with_anchor(anchor: PinnedCertificate<C>) -> Self {
        Self {
            anchor: Some(anchor),
            chain: vec![],
        }
    }

    #[must_use]
    /// Returns the leaf certificate or None if this certificate chain is empty
    /// and does not have any anchor of trust
    pub fn leaf(&self) -> Option<&C> {
        self.chain.last()
    }

    /// Inserts a new leaf into this certificate chain. The certificate is first
    /// verified by the previous certificates
    pub fn push_certificate(&mut self, other: C) -> Result<(), CertificateError> {
        let verifier = self.chain.last().or(self.anchor);

        match verifier {
            Some(verifier) => verifier.verify_cert(&other)?,
            None => other.verify_self()?,
        };

        self.chain.push(other);

        Ok(())
    }

    pub fn parse_pem_chain(mut self, chain: &[u8]) -> Result<Self, CertificateError> {
        let chain = chain.strip_suffix(b"\0").unwrap_or(chain); // chain from tdx could be 0 terminated so we do a little sanitization

        let chain: Vec<C> = x509_cert::Certificate::load_pem_chain(chain)?
            .into_iter()
            .map(C::from_certificate)
            .collect::<Result<_, _>>()?;

        let mut chain = chain.into_iter().rev();

        if let Some(_anchor) = self.anchor {
            // discard the root certificate from the pem chain if we already have our own embedded trust
            let _root = chain.next().ok_or(CertificateError::BadChain)?;

            // todo: maybe verify they match?
        }

        chain.try_for_each(|cert| self.push_certificate(cert))?;

        Ok(self)
    }
}

impl<C: Cert> Verify<C::Signature> for CertificateChain<C> {
    fn verify_signature(&self, msg: &[u8], sig: &C::Signature) -> Result<(), CertificateError> {
        self.leaf()
            .ok_or(CertificateError::NoLeaf)?
            .verify_signature(msg, sig)
    }
}

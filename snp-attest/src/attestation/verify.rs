use libattest::{
    error::{Context, Expose},
    quote::QuoteVerifier,
};

use crate::{
    SevQuote,
    chain::{CRL, VerifiedChain},
    claims::SevClaims,
    nonce::SevNonce,
};

pub struct SevQuoteVerifier {
    collateral: VerifiedChain,
    crl: Option<CRL>,
}

impl SevQuoteVerifier {
    pub fn new(collateral: VerifiedChain) -> Self {
        Self {
            collateral,
            crl: None,
        }
    }

    pub fn with_crl(self, crl: CRL) -> Self {
        Self {
            crl: Some(crl),
            ..self
        }
    }
}

impl QuoteVerifier for SevQuoteVerifier {
    type Nonce = SevNonce;
    type Quote = SevQuote;

    fn verify(&self, quote: &SevQuote, nonce: &SevNonce) -> libattest::Result<SevClaims> {
        if let Some(crl) = &self.crl {
            crl.check_chain(&self.collateral)
                .context("Certificate Revocation List botched the fetched AMD certificates")
                .expose_error()?;
        }

        quote.verify(&self.collateral, nonce)?;
        Ok(SevClaims::from(quote.report()))
    }
}

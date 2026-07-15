use libattest::quote::QuoteVerifier;

use crate::{SevQuote, chain::VerifiedChain, nonce::SevNonce};

pub struct SevQuoteVerifier {
    collateral: VerifiedChain,
}

impl SevQuoteVerifier {
    pub fn new(collateral: VerifiedChain) -> Self {
        Self { collateral }
    }
}

impl QuoteVerifier for SevQuoteVerifier {
    type Nonce = SevNonce;
    type Quote = SevQuote;

    fn verify(&self, quote: &SevQuote, nonce: &SevNonce) -> libattest::Result<()> {
        quote.verify(&self.collateral, nonce)
    }
}

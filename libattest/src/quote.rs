pub trait QuoteVerifier {
    type Nonce;
    type Quote;

    fn verify(&self, quote: &Self::Quote, nonce: &Self::Nonce) -> crate::Result<()>;
}

use crate::validation::Verifiable;

pub trait QuoteVerifier {
    type Nonce;
    type Quote: Verifiable;

    fn verify<'a>(
        &self,
        quote: &'a Self::Quote,
        nonce: &Self::Nonce,
    ) -> crate::Result<<Self::Quote as Verifiable>::Claims<'a>>;
}

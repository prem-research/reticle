use snp_attest::{SevQuote, nonce::SevNonce, verify::SevQuoteVerifier};
use tdx_attest::{TdxQuote, nonce::TdxNonce, verify::TdxQuoteVerifier};

use crate::AzureQuote;

pub struct AzureVerifierBuilder<T, S> {
    fetch_tdx: T,
    fetch_sev: S,
}

impl AzureVerifierBuilder<(), ()> {
    pub fn new() -> AzureVerifierBuilder<(), ()> {
        AzureVerifierBuilder {
            fetch_sev: (),
            fetch_tdx: (),
        }
    }
}

impl<T, S> AzureVerifierBuilder<T, S> {
    pub fn tdx<N>(self, fetch_tdx: N) -> AzureVerifierBuilder<N, S>
    where
        N: AsyncFnOnce(&TdxQuote) -> libattest::Result<TdxQuoteVerifier>,
    {
        AzureVerifierBuilder {
            fetch_tdx,
            fetch_sev: self.fetch_sev,
        }
    }

    pub fn sev<N>(self, fetch_sev: N) -> AzureVerifierBuilder<T, N>
    where
        N: AsyncFnOnce(&SevQuote) -> libattest::Result<SevQuoteVerifier>,
    {
        AzureVerifierBuilder {
            fetch_tdx: self.fetch_tdx,
            fetch_sev,
        }
    }
}

impl<T, S> AzureVerifierBuilder<T, S>
where
    T: AsyncFnOnce(&TdxQuote) -> libattest::Result<TdxQuoteVerifier>,
    S: AsyncFnOnce(&SevQuote) -> libattest::Result<SevQuoteVerifier>,
{
    pub async fn fetch_collateral(
        self,
        quote: &AzureQuote,
    ) -> libattest::Result<AzureQuoteVerifier> {
        // let report = quote.parse_hardware_report()?;

        let verifier = match quote.hardware_report.payload {
            ParserdHardwareReport::Tdx(ref tdx_quote) => {
                let verifier = (self.fetch_tdx)(tdx_quote).await?;
                AzureQuoteVerifier::Tdx(Box::new(verifier))
            }
            ParserdHardwareReport::Sev(ref sev_quote) => {
                let verifier = (self.fetch_sev)(sev_quote).await?;
                AzureQuoteVerifier::Sev(Box::new(verifier))
            }
        };

        Ok(verifier)
    }
}

pub enum AzureQuoteVerifier {
    Tdx(Box<TdxQuoteVerifier>),
    Sev(Box<SevQuoteVerifier>),
}

impl AzureQuoteVerifier {
    pub fn tdx(&self) -> Option<&TdxQuoteVerifier> {
        match self {
            AzureQuoteVerifier::Tdx(tdx_quote_verifier) => Some(tdx_quote_verifier),
            _ => None,
        }
    }

    pub fn sev(&self) -> Option<&SevQuoteVerifier> {
        match self {
            AzureQuoteVerifier::Sev(sev) => Some(sev),
            _ => None,
        }
    }
}

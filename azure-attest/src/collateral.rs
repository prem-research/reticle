use libattest::quote::QuoteVerifier;
use snp_attest::{SevQuote, verify::SevQuoteVerifier};
use tdx_attest::{TdxQuote, verify::TdxQuoteVerifier};

use crate::{
    nonce::AzureNonce,
    quote::{AzureQuote, ParsedHardwareReport, verify},
};

/// Construct the builder providing two async functions
/// that fetch collateral and build a quote verifier
/// based on the type of hardware report contained in the
/// vtpm report data.
pub struct ReportVerifierBuilder<T, S> {
    fetch_tdx: T,
    fetch_sev: S,
}

impl ReportVerifierBuilder<(), ()> {
    pub fn new() -> ReportVerifierBuilder<(), ()> {
        ReportVerifierBuilder {
            fetch_sev: (),
            fetch_tdx: (),
        }
    }
}

impl Default for ReportVerifierBuilder<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, S> ReportVerifierBuilder<T, S> {
    pub fn tdx<N>(self, fetch_tdx: N) -> ReportVerifierBuilder<N, S>
    where
        N: AsyncFnOnce(&TdxQuote) -> libattest::Result<TdxQuoteVerifier>,
    {
        ReportVerifierBuilder {
            fetch_tdx,
            fetch_sev: self.fetch_sev,
        }
    }

    pub fn sev<N>(self, fetch_sev: N) -> ReportVerifierBuilder<T, N>
    where
        N: AsyncFnOnce(&SevQuote) -> libattest::Result<SevQuoteVerifier>,
    {
        ReportVerifierBuilder {
            fetch_tdx: self.fetch_tdx,
            fetch_sev,
        }
    }
}

impl<T, S> ReportVerifierBuilder<T, S>
where
    T: AsyncFnOnce(&TdxQuote) -> libattest::Result<TdxQuoteVerifier>,
    S: AsyncFnOnce(&SevQuote) -> libattest::Result<SevQuoteVerifier>,
{
    /// Chooses the right function to collect evidence depending
    /// on the type of report data (sev or tdx) contained in the azure quote
    pub async fn fetch_collateral(self, quote: &AzureQuote) -> libattest::Result<ReportVerifier> {
        let report = quote.parse_hardware_report()?;

        let verifier = match report {
            ParsedHardwareReport::Tdx(ref tdx_quote) => {
                let verifier = (self.fetch_tdx)(tdx_quote).await?;
                ReportVerifier::Tdx(Box::new(verifier))
            }
            ParsedHardwareReport::Sev(ref sev_quote) => {
                let verifier = (self.fetch_sev)(sev_quote).await?;
                ReportVerifier::Sev(Box::new(verifier))
            }
        };

        Ok(verifier)
    }
}

pub enum ReportVerifier {
    Tdx(Box<TdxQuoteVerifier>),
    Sev(Box<SevQuoteVerifier>),
}

impl ReportVerifier {
    pub fn tdx(&self) -> Option<&TdxQuoteVerifier> {
        match self {
            ReportVerifier::Tdx(tdx_quote_verifier) => Some(tdx_quote_verifier),
            _ => None,
        }
    }

    pub fn sev(&self) -> Option<&SevQuoteVerifier> {
        match self {
            ReportVerifier::Sev(sev) => Some(sev),
            _ => None,
        }
    }
}

impl QuoteVerifier for ReportVerifier {
    type Nonce = AzureNonce;
    type Quote = AzureQuote;

    /// performs cryptographic verification of the whole azure stack
    /// and returns a set of verified claims on which the client can apply policies
    fn verify<'a>(
        &self,
        quote: &'a Self::Quote,
        nonce: &Self::Nonce,
    ) -> libattest::Result<<Self::Quote as libattest::validation::Verifiable>::Claims<'a>> {
        verify::verify_impl(quote, self, nonce)
    }
}

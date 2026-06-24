use libattest::{ByteNonce, error::Context};
use rsa::signature::Verifier;

use crate::{AzureQuote, ParsedHardwareReport, collateral::AzureQuoteVerifier};

pub fn verify_quote_signature(quote: &AzureQuote) -> libattest::Result<()> {
    use tpm2_protocol::{TpmMarshal, TpmWriter};

    let mut buffer = Box::new([0u8; 512]);
    let mut writer = TpmWriter::new(buffer.as_mut_slice());

    quote.quote.marshal(&mut writer)?;

    let written = writer.len();
    let marshaled = &buffer[..written];

    quote
        .trust
        .ak_key
        .verify(marshaled, &quote.trust.quote_signature)?;

    Ok(())
}

pub fn verify_report_digest(
    quote: &AzureQuote,
    verifier: &AzureQuoteVerifier,
) -> libattest::Result<()> {
    use libattest::quote::QuoteVerifier;
    use snp_attest::nonce::SevNonce;
    use tdx_attest::nonce::TdxNonce;

    let report = quote
        .parse_hardware_report()
        .context("unable to parse hardware report")?;

    let mut nonce = quote.hardware_report.hash_runtime_data()?;

    let padding = &[0u8; 64][..(64usize.saturating_sub(nonce.len()))];
    nonce.extend_from_slice(padding); // pad nonce to cover all 64 bytes of nonces

    // convert to fixed size nonce
    let nonce = Box::<[u8; 64]>::try_from(nonce)
        .ok()
        .map(ByteNonce::from)
        .context("nonce didn't fit")?;

    match report {
        ParsedHardwareReport::Tdx(tdx_quote) => {
            let verifier = verifier.tdx().context("didn't receive tdx verifier")?;
            let nonce = TdxNonce::new(nonce);

            verifier.verify(&tdx_quote, &nonce)?;
        }
        ParsedHardwareReport::Sev(sev_quote) => {
            let verifier = verifier.sev().context("didn't receive sev verifier")?;
            let nonce = SevNonce::new(nonce);

            verifier.verify(&sev_quote, &nonce)?;
        }
    };

    Ok(())
}

pub fn verify(azure_quote: AzureQuote, verifier: AzureQuoteVerifier) -> libattest::Result<()> {
    verify_quote_signature(&azure_quote)?;
    verify_report_digest(&azure_quote, &verifier)?;

    Ok(())
}

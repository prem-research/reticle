use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use libattest::{ByteNonce, error::Context};
use rsa::{BoxedUint, signature::Verifier};

use crate::{AzureQuote, ParsedHardwareReport, collateral::ReportVerifier, report::RuntimeClaims};

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

fn decode_base64_component(base64: &str) -> Result<rsa::BoxedUint, base64::DecodeError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let decoded = URL_SAFE_NO_PAD.decode(base64)?;
    Ok(BoxedUint::from_be_slice_vartime(&decoded))
}

pub fn verify_runtime_data(quote: &AzureQuote) -> libattest::Result<RuntimeClaims> {
    let claims = quote
        .hardware_report
        .runtime
        .claims()
        .context("failed parsing Runtime Data claims")?;

    // Gather keys from runtime claims to enstablish trust into the keys used to sign
    // the vTPM quote.

    let set = JwkSet {
        keys: claims.keys.clone(),
    };

    let hclakpub = set
        .find("HCLAkPub")
        .context("Missing HCLAkPub from Runtime Claims")?;

    // Verify that keys match
    let AlgorithmParameters::RSA(ref hclakpub) = hclakpub.algorithm else {
        libattest::bail!("Received wrong key type in Report Data JWT for HCKLAkPub");
    };

    // we decode the components of the rsa key from
    // base64 encoded format of jsonwebkeys
    let modulus = decode_base64_component(&hclakpub.n).context("failed parsing modulus")?;
    let exponent = decode_base64_component(&hclakpub.e).context("failed parsing exponent")?;

    // convert the key into something we can compare
    let report_ak = rsa::RsaPublicKey::new(modulus, exponent)
        .map(rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new)
        .context("failed constructing rsa public key from report data")?;

    // Finally, we check if the vendored ak key and the trusted ak key
    // whose trust we derive from the hardware report match
    if report_ak != quote.trust.ak_key {
        libattest::bail!(exposed: "TPM read key and Hardware Report verified key do not match");
    }

    Ok(claims)
}

pub fn verify_report_digest(
    quote: &AzureQuote,
    verifier: &ReportVerifier,
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

pub fn verify(azure_quote: AzureQuote, report_verifier: ReportVerifier) -> libattest::Result<()> {
    // 1: verify that AK signs Quote through signature
    verify_quote_signature(&azure_quote)?;
    // 2: verify that the hardware report signs report data
    verify_report_digest(&azure_quote, &report_verifier)?;
    // 3: verify that report data contains the correct ak key,
    // sprouting azure trust from SEV/TDX
    verify_runtime_data(&azure_quote)?;

    Ok(())
}

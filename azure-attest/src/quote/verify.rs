use std::ops::Deref;

use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use libattest::{
    ByteNonce,
    crypto::{
        CertificateChain,
        algorithms::{CertFormat, rsa::RsaCert},
        signature::rsa::RsaSignature,
    },
    error::Context,
};
use rsa::{BoxedUint, pkcs1::DecodeRsaPublicKey, pkcs1v15::VerifyingKey, signature::Verifier};
use sha2::Sha256;
use tpm2_protocol::data::{TpmAlgId, TpmuAttest};
use x509_cert::der::oid::db::rfc9688::RSA_ENCRYPTION;

use crate::{
    ca::AZURE_CA,
    collateral::ReportVerifier,
    nonce::AzureNonce,
    quote::{
        AzureQuote, ParsedHardwareReport,
        claims::{AzureClaims, HardwareClaims, TpmAttestEvidence},
    },
    report::RuntimeClaims,
};

pub fn verify_quote_signature(
    quote: &AzureQuote,
    trust_chain: CertificateChain<RsaCert>,
) -> libattest::Result<()> {
    use tpm2_protocol::{TpmMarshal, TpmWriter};

    let mut buffer = Box::new([0u8; 512]);
    let mut writer = TpmWriter::new(buffer.as_mut_slice());

    quote.quote.marshal(&mut writer)?;

    let written = writer.len();
    let marshaled = &buffer[..written];

    let signature = RsaSignature::<Sha256>::new(quote.trust.quote_signature.clone());
    trust_chain.verify(marshaled, &signature)?;

    Ok(())
}

pub fn verify_quote_trust_chain(
    quote: &AzureQuote,
) -> libattest::Result<CertificateChain<RsaCert>> {
    let pk = quote
        .trust
        .ak_cert
        .tbs_certificate()
        .subject_public_key_info();

    pk.algorithm
        .assert_algorithm_oid(RSA_ENCRYPTION)
        .context("invalid AK cert public key encryption algorithm")?;

    let public_key = rsa::RsaPublicKey::from_pkcs1_der(pk.subject_public_key.raw_bytes())?;
    let public_key: VerifyingKey<Sha256> = VerifyingKey::new(public_key);

    if quote.trust.ak_key != public_key {
        libattest::bail!(exposed: "mismatched ak key between certificate and evidence");
    }

    let cert = RsaCert::from_certificate(quote.trust.ak_cert.clone())
        .context("failed validating certificate")?;

    let intermediate = crate::ca::intermediate_db()
        .find_intermediate(&cert)
        .context("failed finding matching intermediate certificate for ak_cert")?;

    let chain = CertificateChain::<RsaCert>::with_anchor(&AZURE_CA)
        .with_certificate(intermediate.clone())?
        .with_certificate(cert)?;

    Ok(chain)
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
) -> libattest::Result<HardwareClaims> {
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

    let claims = match report {
        ParsedHardwareReport::Tdx(tdx_quote) => {
            let verifier = verifier.tdx().context("didn't receive tdx verifier")?;
            let nonce = TdxNonce::new(nonce);

            let claims = verifier.verify(&tdx_quote, &nonce)?;
            HardwareClaims::Tdx(claims.clone().into())
        }
        ParsedHardwareReport::Sev(sev_quote) => {
            let verifier = verifier.sev().context("didn't receive sev verifier")?;
            let nonce = SevNonce::new(nonce);

            let claims = verifier.verify(&sev_quote, &nonce)?;
            HardwareClaims::Sev(claims.into())
        }
    };

    Ok(claims)
}

fn verify_quote_nonce(azure_quote: &AzureQuote, nonce: &AzureNonce) -> libattest::Result<()> {
    let tpm_nonce = azure_quote.quote.extra_data;

    // try to fit the tpm nonce into our azurenonce type.
    // tpm nonces can be arbitrary sized (MAX 64) so we
    // have to check manually
    let tpm_nonce = <&[u8; _]>::try_from(tpm_nonce.deref())
        .map(AzureNonce::from)
        .context("received nonce does not fit into defined AzureNonce type")?;

    if !nonce.eq(&tpm_nonce) {
        libattest::bail!(exposed: "Mismatched vTPM nonce");
    }

    Ok(())
}

fn verify_pcr_digest(azure_quote: &AzureQuote) -> libattest::Result<()> {
    let digest = azure_quote.pcr_bank.pcr_digest();

    let TpmuAttest::Quote(ref info) = azure_quote.quote.attested else {
        libattest::bail!("wrong type of attested data in quote");
    };

    verify_pcr_selection(info)?;

    if info.pcr_digest.deref() != digest.deref() {
        libattest::bail!(exposed: "PCR digest mismatch");
    }

    Ok(())
}

fn verify_pcr_selection(info: &tpm2_protocol::data::TpmsQuoteInfo) -> libattest::Result<()> {
    const EXPECTED_PCR_SELECT: &[u8] = &[0xff, 0xff, 0xff];

    if info.pcr_select.len() != 1 {
        libattest::bail!(exposed: "TPM quote must contain exactly one PCR selection");
    }

    let selection = &info.pcr_select[0];
    if selection.hash != TpmAlgId::Sha256 {
        libattest::bail!(exposed: "TPM quote PCR selection must use SHA-256");
    }

    if selection.pcr_select.deref() != EXPECTED_PCR_SELECT {
        libattest::bail!(exposed: "TPM quote must select PCRs 0 through 23");
    }

    Ok(())
}

pub fn verify_impl<'a>(
    azure_quote: &'a AzureQuote,
    report_verifier: &ReportVerifier,
    nonce: &AzureNonce,
) -> libattest::Result<AzureClaims<'a>> {
    // 1: verify quote certificate chain against pinned trust
    let trust_chain =
        verify_quote_trust_chain(azure_quote).context("while verifying quote certificates")?;
    // 2: verify that AK signs Quote through leaf certificate
    verify_quote_signature(azure_quote, trust_chain).context("while verifying quote signature")?;
    // 3: verify that the hardware report signs report data
    let hardware_claims = verify_report_digest(azure_quote, &report_verifier)
        .context("while verifying report digest")?;
    // 4: verify that report data contains the correct ak key,
    // sprouting azure trust from SEV/TDX
    let runtime_claims =
        verify_runtime_data(azure_quote).context("while verifying runtime data")?;
    // 5: Verify that user supplied nonce and received quote nonce match
    verify_quote_nonce(azure_quote, nonce).context("while verifying quote nonce")?;
    // 6: Verify pcr digest
    verify_pcr_digest(azure_quote).context("failed verifying pcr bank digest")?;

    let tpm_evidence = TpmAttestEvidence::from(&azure_quote.quote);

    let azure_claims = AzureClaims::new(
        &azure_quote.pcr_bank,
        hardware_claims,
        tpm_evidence,
        runtime_claims,
    );

    Ok(azure_claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATTESTATION: &str = include_str!("../../tests/attestation.json");

    #[test]
    fn bundled_quote_selects_sha256_pcrs_0_through_23() {
        let quote: AzureQuote = serde_json::from_str(ATTESTATION).unwrap();
        let TpmuAttest::Quote(ref info) = quote.quote.attested else {
            panic!("bundled attestation is not a TPM quote");
        };

        verify_pcr_selection(info).unwrap();
    }
}

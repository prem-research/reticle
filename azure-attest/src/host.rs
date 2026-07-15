use std::ops::Deref;

use tpm2_protocol::{TpmUnmarshal, data::TpmsAttest};
use tss_esapi::{structures::Signature, traits::Marshall};

use crate::{AzureQuote, nonce::AzureNonce, quote::AzureTrust};

pub mod vtpm;

/// Performs attestation on an AzureTpm object
pub fn azure_attest(
    mut tpm: vtpm::AzureTpmCtx,
    nonce: &AzureNonce,
) -> anyhow::Result<crate::AzureQuote> {
    let cert = tpm.ak_cert()?;
    let key = tpm.ak().unwrap();
    let report = tpm.hardware_report().unwrap();
    let pcr = tpm.read_pcr_bank()?;
    let (attest, signature) = tpm.quote(nonce.deref()).unwrap();

    // convert tpm structure to wire compatible format
    let marshaled = attest.marshall()?;
    let (attest, _) = TpmsAttest::unmarshal(&marshaled)?;

    let signature = match signature {
        Signature::RsaSsa(ref signature) => signature.signature().value(),
        _ => anyhow::bail!("unsupported signature algorithm"),
    };

    let signature = rsa::pkcs1v15::Signature::try_from(signature)?;

    let azure_trust = AzureTrust::new(signature, key, cert);
    let azure_quote = AzureQuote::new(attest, pcr, report, azure_trust);

    Ok(azure_quote)
}

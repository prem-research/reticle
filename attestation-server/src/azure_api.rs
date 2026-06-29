use anyhow::Context;
use azure_attest::{AzureQuote, host::vtpm::AzureTpmCtx, nonce::AzureNonce};

use crate::{nonce::NonceParam, response::ApiJsonResult};

#[rocket::get("/azure?<nonce>")]
pub async fn azure_attestation(
    nonce: NonceParam<libattest::ByteNonce<32>, 32>,
) -> ApiJsonResult<AzureQuote> {
    let NonceParam(nonce) = nonce;
    let tpm = AzureTpmCtx::default_context().context("failed creating tpm context")?;
    let nonce = AzureNonce::new(nonce);

    let quote = azure_attest::host::azure_attest(tpm, &nonce)?;

    Ok(quote.into())
}

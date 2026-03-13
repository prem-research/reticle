use anyhow::Context;
use nvat::{AttestationBuilder, SdkHandle, nonce::NvatNonce};
use rocket::State;

use crate::nonce::NonceParam;
#[cfg(feature = "nvidia")]
use crate::response::ApiError;

#[rocket::get("/nvidia?<nonce>")]
#[cfg(feature = "nvidia")]
pub async fn nvidia_attestation(
    nonce: NonceParam<libattest::ByteNonce<32>, 32>,
    sdk: &State<SdkHandle>,
) -> Result<String, ApiError> {
    let NonceParam(nonce) = nonce;

    // TEMPORARY FIX FOR BAD NVIDIA APIS
    let nonce = hex::encode(&nonce[..]);
    let nonce = NvatNonce::from_hex(sdk, &nonce)
        .context("internal nvat error when converting the nonce")?;

    let result = AttestationBuilder::new(sdk)
        .context("cannot create attestation context")?
        .gpu()
        .verifier_remote()
        .build()
        .attest_device(&nonce)
        .context("cannot complete attestation process")?;

    Ok(result
        .detached_eat
        .as_str()
        .context("attestation contains bad string data")?
        .to_string())
}

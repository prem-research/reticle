use std::{fmt::Display, path::PathBuf};

use anyhow::Context;
use nvat::{AttestationBuilder, SdkHandle, nonce::NvatNonce};
use rocket::State;

use crate::{nonce::NonceParam, response::ApiJsonResult};

#[rocket::get("/nvidia?<nonce>")]
pub async fn nvidia_attestation(
    nonce: NonceParam<Box<[u8; 32]>, 32>,
    sdk: &State<SdkHandle>,
) -> ApiJsonResult<String> {
    let NonceParam(nonce) = nonce;

    // TEMPORARY FIX FOR BAD NVIDIA APIS
    let nonce = hex::encode(&nonce[..]);
    let nonce = NvatNonce::from_hex(&sdk, &nonce)
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
        .to_string()
        .into())
}

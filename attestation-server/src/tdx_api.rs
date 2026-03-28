use anyhow::Context;

use crate::{nonce::NonceParam, response::ApiError};

#[rocket::get("/cpu?<nonce>")]
pub async fn tdx_attestation(
    nonce: NonceParam<libattest::ByteNonce<64>, 64>,
) -> Result<Vec<u8>, ApiError> {
    let quote = configfs_tsm::create_tdx_quote(*nonce.inner().as_ref())
        .context("error while getting tdx report")?;

    Ok(quote)
}

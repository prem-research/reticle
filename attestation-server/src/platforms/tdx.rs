use anyhow::Context;
use configfs_tsm::QuoteGenerationError;
use rocket::State;

use crate::{nonce::NonceParam, response::ApiError};

pub struct TdxProvider;

impl TdxProvider {
    pub fn create_tdx_quote(&self, input: [u8; 64]) -> Result<Vec<u8>, QuoteGenerationError> {
        configfs_tsm::create_tdx_quote(input)
    }
}

#[rocket::get("/tdx?<nonce>")]
pub async fn tdx_attestation(
    nonce: NonceParam<libattest::ByteNonce<64>, 64>,
    tdx: &State<TdxProvider>,
) -> Result<Vec<u8>, ApiError> {
    let quote = tdx
        .create_tdx_quote(*nonce.inner().as_ref())
        .context("error while getting tdx report")?;

    Ok(quote)
}

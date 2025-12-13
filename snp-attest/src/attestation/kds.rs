#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    ParsedAttestation,
    chain::{CRL, VerifiedChain},
    error::AttestationError,
};

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
/// Fetches the certificate chain for the correct CPU from AMD's KDS server
pub async fn fetch_certificates(
    attestation: &ParsedAttestation,
) -> Result<VerifiedChain, AttestationError> {
    log::info!("Fetching the chain from KDS");
    let chain = crate::kds::get_chain(
        &attestation.report.chip_id,
        attestation.report.reported_tcb,
        &attestation.generation.titlecase(),
    )
    .await
    .map_err(|_| AttestationError::KdsRequest)?;

    log::info!("Cryptographically verifying the fetched chain");
    let chain = VerifiedChain::verify(chain)?;
    Ok(chain)
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
/// Fetches the certificate revocation list from AMD's KDS
pub async fn fetch_crl(attestation: &ParsedAttestation) -> Result<CRL, AttestationError> {
    let crl = crate::kds::get_crl(&attestation.generation.titlecase())
        .await
        .map_err(|_| AttestationError::KdsRequest)?;

    CRL::from_der(&crl)
}

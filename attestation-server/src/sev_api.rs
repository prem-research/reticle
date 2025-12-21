use rocket::State;
use sev::firmware::guest::Firmware;
use snp_attest::nonce::SevNonce;
use tokio::sync::Mutex;

use crate::nonce::NonceParam;
use crate::response::ApiError;

pub type SharedFirmware = Mutex<Firmware>;

#[rocket::get("/cpu?<nonce>")]
#[cfg(feature = "sev")]
pub async fn cpu_attestation(
    nonce: NonceParam<SevNonce, 64>,
    firmware: &State<SharedFirmware>,
) -> Result<Vec<u8>, ApiError> {
    let NonceParam(nonce) = nonce;
    use anyhow::Context;

    let mut firmware = firmware.lock().await;
    let report = firmware
        .get_report(None, Some(*nonce), None)
        .context("error sourcing the report")?;

    drop(firmware); // release the lock

    Ok(report)
}

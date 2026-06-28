use serde::{Deserialize, Serialize};
use snp_attest::claims::SevClaims;
use tdx_attest::dcap::types::TdxQuoteBody;

#[derive(Serialize)]
pub enum HardwareClaims {
    Sev(SevClaims),
    Tdx(TdxQuoteBody),
}

#[derive(Serialize)]
pub struct TpmClockInfo {
    clock: u64,
    reset_count: u32,
    restart_count: u32,
    safe: bool,
}

// #[derive(Serialize)]
// pub struct TpmAttestEvidence {
//     qualified_signer: String,
//     #[serde(with = "hex::serde")]
//     extra_data: Vec<u8>,
//     clock_info: TpmClockInfo,
//     firmware_version: u64,

//     quote:
// }

#[derive(Serialize)]
pub struct AzureClaims {
    hardware_claims: HardwareClaims,
}

use serde::Serialize;
use sha2::Sha256;
use snp_attest::claims::SevClaims;
use tdx_attest::dcap::types::TdxQuoteBody;
use tpm2_protocol::data::{TpmsAttest, TpmsClockInfo};

use crate::{quote::pcr::PcrBankReading, report::RuntimeClaims};

#[derive(Serialize, Debug)]
#[serde(tag = "type", content = "report")]
pub enum HardwareClaims {
    Sev(Box<SevClaims>),
    Tdx(Box<TdxQuoteBody>),
}

#[derive(Serialize, Debug)]
pub struct TpmClockInfo {
    clock: u64,
    reset_count: u32,
    restart_count: u32,
    safe: bool,
}

impl From<TpmsClockInfo> for TpmClockInfo {
    fn from(value: TpmsClockInfo) -> Self {
        Self {
            clock: value.clock.value(),
            reset_count: value.reset_count.value(),
            restart_count: value.restart_count.value(),
            safe: value.safe.0,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct TpmAttestEvidence<'a> {
    qualified_signer: &'a [u8],
    #[serde(with = "hex::serde")]
    extra_data: &'a [u8],
    clock_info: TpmClockInfo,
    firmware_version: u64,
}

impl<'a> From<&'a TpmsAttest> for TpmAttestEvidence<'a> {
    fn from(value: &'a TpmsAttest) -> Self {
        Self {
            qualified_signer: &value.qualified_signer,
            extra_data: &value.extra_data,
            clock_info: value.clock_info.into(),
            firmware_version: value.firmware_version.0,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct AzureClaims<'a> {
    pcr_bank: &'a PcrBankReading<Sha256>,
    tpm_evidence: TpmAttestEvidence<'a>,

    hardware_claims: HardwareClaims,
    runtime_claims: RuntimeClaims,
}

impl<'a> AzureClaims<'a> {
    pub(super) fn new(
        pcr_bank: &'a PcrBankReading<Sha256>,
        hardware_claims: HardwareClaims,
        tpm_evidence: TpmAttestEvidence<'a>,
        runtime_claims: RuntimeClaims,
    ) -> Self {
        Self {
            pcr_bank,
            hardware_claims,
            tpm_evidence,
            runtime_claims,
        }
    }
}

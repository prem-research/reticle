use libattest::validation::WithPolicy;
use serde::Serialize;
use sev::firmware::guest::{AttestationReport, GuestPolicy};

use crate::SevQuote;

#[derive(Debug, Serialize)]
pub struct GuestPolicyClaims {
    pub abi_minor: u64,
    pub abi_major: u64,
    pub smt_allowed: bool,
    pub migrate_ma_allowed: bool,
    pub debug_allowed: bool,
    pub single_socket_required: bool,
    pub cxl_allowed: bool,
    pub mem_aes_256_xts: bool,
    pub rapl_dis: bool,
    pub ciphertext_hiding: bool,
    pub page_swap_disabled: bool,
}

impl From<&GuestPolicy> for GuestPolicyClaims {
    fn from(p: &GuestPolicy) -> Self {
        Self {
            abi_minor: p.abi_minor(),
            abi_major: p.abi_major(),
            smt_allowed: p.smt_allowed(),
            migrate_ma_allowed: p.migrate_ma_allowed(),
            debug_allowed: p.debug_allowed(),
            single_socket_required: p.single_socket_required(),
            cxl_allowed: p.cxl_allowed(),
            mem_aes_256_xts: p.mem_aes_256_xts(),
            rapl_dis: p.rapl_dis(),
            ciphertext_hiding: p.ciphertext_hiding(),
            page_swap_disabled: p.page_swap_disabled(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SevClaims {
    pub version: u32,
    pub policy: GuestPolicyClaims,
    pub vmpl: u32,
    #[serde(with = "hex::serde")]
    pub measurement: [u8; 48],
    pub reported_tcb: sev::firmware::host::TcbVersion,
    pub current_tcb: sev::firmware::host::TcbVersion,
}

impl From<&AttestationReport> for SevClaims {
    fn from(report: &AttestationReport) -> Self {
        Self {
            version: report.version,
            policy: GuestPolicyClaims::from(&report.policy),
            vmpl: report.vmpl,
            measurement: report.measurement,
            reported_tcb: report.reported_tcb,
            current_tcb: report.current_tcb,
        }
    }
}

impl libattest::validation::IntoClaims for &SevQuote {
    type Claims = WithPolicy<SevClaims>;
    fn into_claims(self) -> WithPolicy<SevClaims> {
        WithPolicy::new("sev.allow", SevClaims::from(self.report()))
    }
}

use azure_attest::AzureQuote;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use snp_attest::SevQuote;

pub mod manifest;

pub use manifest::Manifest;

#[serde_as]
#[derive(Serialize, Deserialize)]
pub enum CpuReport {
    /// AMD Sev-Snp
    Sev(Box<SevQuote>),
    /// Intel TDX
    Tdx(#[serde_as(as = "Base64")] Vec<u8>),
    /// Hyper-V
    Azr(Box<AzureQuote>),
}

#[derive(Serialize, Deserialize)]
pub enum GpuReport {
    Absent,
    Nvidia(String),
}

#[derive(Serialize, Deserialize)]
pub struct CvmReport {
    // everything else to be defined.
    pub manifest: Manifest,
    pub cpu: CpuReport,
    pub gpu: GpuReport,
}

libattest::define_nonce_type!(pub CvmNonce, 64);

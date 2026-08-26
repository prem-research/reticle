use azure_attest::AzureQuote;
use digest::Update;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use sha2::Digest;
use snp_attest::SevQuote;

pub mod manifest;

pub use manifest::Manifest;

use crate::bind::sealed::Bindable;

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

impl Bindable for CpuReport {}

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

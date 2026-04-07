use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Free-form certificate chain object (additionalProperties: true).
pub type CertChainClaims = HashMap<String, Value>;

/// Free-form mismatched-measurement record (additionalProperties: true).
pub type MismatchedMeasurement = HashMap<String, Value>;

pub type DigestRepr = (String, (String, String));

#[derive(Error, Debug)]
#[error("invalid digest representation")]
pub struct InvalidDigestRepr;

#[derive(Deserialize, Serialize, Debug)]
#[serde(try_from = "DigestRepr")]
pub enum Digest {
    Sha256([u8; 32]),
}

impl Digest {
    pub fn digest(&self) -> &[u8] {
        match self {
            Digest::Sha256(digest) => digest,
        }
    }
}

impl TryFrom<DigestRepr> for Digest {
    type Error = InvalidDigestRepr;

    fn try_from((_, (alg, hash)): DigestRepr) -> Result<Self, Self::Error> {
        match alg.as_ref() {
            "SHA-256" => {
                let decoded = hex::decode(hash).map_err(|_| InvalidDigestRepr)?;
                let digest = decoded.try_into().map_err(|_| InvalidDigestRepr)?;

                Ok(Digest::Sha256(digest))
            }
            _ => Err(InvalidDigestRepr),
        }
    }
}

/// Claims from the overall JWT token.
#[derive(Debug, Serialize, Deserialize)]
pub struct OverallClaims {
    #[serde(rename = "x-nvidia-ver")]
    pub claims_version: Option<String>,
    #[serde(rename = "eat_nonce", deserialize_with = "hex::serde::deserialize")]
    pub eat_nonce: [u8; 32],
    #[serde(rename = "x-nvidia-overall-att-result")]
    pub overall_att_result: Option<bool>,

    pub submods: HashMap<String, Digest>,
}

/// Measurement validation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MeasuresClaim {
    Success,
    Failure,
}

/// Detached claims containing GPU-specific information.
#[derive(Debug, Deserialize)]
pub struct DetachedClaims {
    pub gpu_claims: Vec<GpuClaims>,
    pub overall_detached: Option<OverallClaims>,
}

/// Claims specific to a single GPU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuClaims {
    /// Overall measurement validation result.
    pub measres: MeasuresClaim,

    #[serde(rename = "eat_nonce", deserialize_with = "hex::serde::deserialize")]
    pub eat_nonce: [u8; 32],

    /// Secure boot status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secboot: Option<bool>,

    /// Debug status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dbgstat: Option<String>,

    /// Records of mismatched measurements.
    #[serde(
        rename = "x-nvidia-mismatch-measurement-records",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub mismatch_measurement_records: Option<Vec<MismatchedMeasurement>>,

    /// GPU architecture validation result.
    #[serde(rename = "x-nvidia-gpu-arch-check")]
    pub arch_check: bool,

    /// GPU driver version string.
    #[serde(rename = "x-nvidia-gpu-driver-version")]
    pub driver_version: String,

    /// GPU VBIOS version string.
    #[serde(rename = "x-nvidia-gpu-vbios-version")]
    pub vbios_version: String,

    /// Physical data-interface IDs from this GPU to NVSwitches.
    #[serde(
        rename = "x-nvidia-gpu-switch-pdis",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub switch_pdis: Option<Vec<String>>,

    // ---- Attestation report ------------------------------------------------
    #[serde(rename = "x-nvidia-gpu-attestation-report-cert-chain")]
    pub attestation_report_cert_chain: CertChainClaims,

    #[serde(rename = "x-nvidia-gpu-attestation-report-cert-chain-fwid-match")]
    pub attestation_report_cert_chain_fwid_match: bool,

    #[serde(rename = "x-nvidia-gpu-attestation-report-parsed")]
    pub attestation_report_parsed: bool,

    #[serde(rename = "x-nvidia-gpu-attestation-report-nonce-match")]
    pub attestation_report_nonce_match: bool,

    #[serde(rename = "x-nvidia-gpu-attestation-report-signature-verified")]
    pub attestation_report_signature_verified: bool,

    // ---- Driver RIM --------------------------------------------------------
    #[serde(rename = "x-nvidia-gpu-driver-rim-fetched")]
    pub driver_rim_fetched: bool,

    #[serde(rename = "x-nvidia-gpu-driver-rim-schema-validated")]
    pub driver_rim_schema_validated: bool,

    #[serde(rename = "x-nvidia-gpu-driver-rim-cert-chain")]
    pub driver_rim_cert_chain: CertChainClaims,

    #[serde(rename = "x-nvidia-gpu-driver-rim-signature-verified")]
    pub driver_rim_signature_verified: bool,

    #[serde(rename = "x-nvidia-gpu-driver-rim-version-match")]
    pub driver_rim_version_match: bool,

    #[serde(rename = "x-nvidia-gpu-driver-rim-measurements-available")]
    pub driver_rim_measurements_available: bool,

    // ---- VBIOS RIM ---------------------------------------------------------
    #[serde(rename = "x-nvidia-gpu-vbios-rim-fetched")]
    pub vbios_rim_fetched: bool,

    #[serde(rename = "x-nvidia-gpu-vbios-rim-schema-validated")]
    pub vbios_rim_schema_validated: bool,

    #[serde(rename = "x-nvidia-gpu-vbios-rim-cert-chain")]
    pub vbios_rim_cert_chain: CertChainClaims,

    #[serde(rename = "x-nvidia-gpu-vbios-rim-version-match")]
    pub vbios_rim_version_match: bool,

    #[serde(rename = "x-nvidia-gpu-vbios-rim-signature-verified")]
    pub vbios_rim_signature_verified: bool,

    #[serde(rename = "x-nvidia-gpu-vbios-rim-measurements-available")]
    pub vbios_rim_measurements_available: bool,

    #[serde(rename = "x-nvidia-gpu-vbios-index-no-conflict")]
    pub vbios_index_no_conflict: bool,
}

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Response from the attestation server containing the EAT token and metadata.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub success: bool,
    pub eat_token: String,
    pub nonce: String,
    pub metadata: Metadata,
}

/// Metadata about the attestation response.
#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    pub claims_version: String,
    pub evidence_count: u32,
    pub attestation_result: bool,
    #[serde(default)]
    pub rim_source: Option<String>,
}

/// Parsed EAT (Entity Attestation Token) structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct EATToken {
    pub overall_jwt: String,
    pub detached: serde_json::Value,
}

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

/// Detached claims containing GPU-specific information.
#[derive(Debug, Deserialize)]
pub struct DetachedClaims {
    pub gpu_claims: Vec<GpuClaims>,
    pub overall_detached: Option<OverallClaims>,
}

/// Claims specific to a single GPU.
#[derive(Debug, Serialize, Deserialize)]
pub struct GpuClaims {
    #[serde(rename = "measres")]
    pub measres: Option<String>,
    #[serde(rename = "x-nvidia-gpu-arch-check")]
    pub arch_check: Option<bool>,
    #[serde(rename = "x-nvidia-gpu-driver-version")]
    pub driver_version: Option<String>,
    #[serde(rename = "x-nvidia-gpu-vbios-version")]
    pub vbios_version: Option<String>,
    #[serde(rename = "x-nvidia-gpu-attestation-report-cert-chain-validated")]
    pub attestation_report_cert_validated: Option<bool>,
    #[serde(rename = "x-nvidia-gpu-driver-rim-fetched")]
    pub driver_rim_fetched: Option<bool>,
    #[serde(rename = "x-nvidia-gpu-driver-rim-cert-validated")]
    pub driver_rim_cert_validated: Option<bool>,
    #[serde(rename = "x-nvidia-gpu-driver-rim-signature-verified")]
    pub driver_rim_signature_verified: Option<bool>,
    #[serde(rename = "x-nvidia-gpu-vbios-rim-fetched")]
    pub vbios_rim_fetched: Option<bool>,
    #[serde(rename = "x-nvidia-gpu-vbios-rim-cert-validated")]
    pub vbios_rim_cert_validated: Option<bool>,
    #[serde(rename = "x-nvidia-gpu-vbios-rim-signature-verified")]
    pub vbios_rim_signature_verified: Option<bool>,
    #[serde(rename = "eat_nonce", deserialize_with = "hex::serde::deserialize")]
    pub eat_nonce: [u8; 32],
    #[serde(rename = "hwmodel")]
    pub hw_model: Option<String>,
    #[serde(rename = "ueid")]
    pub uuid: Option<String>,
}

/// Complete validation result with status, errors, and detailed checks.
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub checks: ValidationChecks,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationChecks {
    pub eat_structure: bool,
    pub nonce_match: bool,
    pub overall_att_result: bool,
    pub measurement_result: bool,
    pub certificate_validation: bool,
    pub rim_validation: bool,
    pub arch_check: bool,
    pub timestamps: bool,
    // Detailed results
    pub details: ValidationDetails,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationDetails {
    pub vbios: VBIOSValidation,
    pub drivers: DriverValidation,
    pub certificates: CertificateValidation,
    pub rim_service: RIMServiceValidation,
    pub ocsp: OCSPValidation,
    pub gpu_info: Vec<GPUInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VBIOSValidation {
    pub valid: bool,
    pub rim_fetched: bool,
    pub rim_signature_verified: bool,
    pub cert_validated: bool,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DriverValidation {
    pub valid: bool,
    pub measurement_result: String, // "success" or "fail"
    pub rim_fetched: bool,
    pub rim_signature_verified: bool,
    pub cert_validated: bool,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateValidation {
    pub valid: bool,
    pub attestation_report_cert: bool,
    pub driver_rim_cert: bool,
    pub vbios_rim_cert: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RIMServiceValidation {
    pub valid: bool,
    pub driver_rim_fetched: bool,
    pub driver_rim_signature_verified: bool,
    pub vbios_rim_fetched: bool,
    pub vbios_rim_signature_verified: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OCSPValidation {
    pub valid: bool,
    pub note: String, // OCSP is included in certificate validation
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPUInfo {
    pub gpu_id: String,
    pub driver_version: Option<String>,
    pub vbios_version: Option<String>,
    pub hw_model: Option<String>,
    pub uuid: Option<String>,
}

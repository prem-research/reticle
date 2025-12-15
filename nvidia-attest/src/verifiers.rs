use libattest::VerificationRule;
use thiserror::Error;

use crate::types::{GpuClaims, OverallClaims};

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("attestation failed this check: {0}")]
    FailedCheck(&'static str),

    #[error("missing field from attestation: ${0}")]
    MissingData(&'static str),

    #[error("either missing or invalid nonce: got ${0} expected ${1}")]
    InvalidNonce(String, String),
}

impl VerificationError {
    fn invalid_nonce(got: impl Into<String>, expected: impl Into<String>) -> VerificationError {
        VerificationError::InvalidNonce(got.into(), expected.into())
    }
}

pub struct CheckValidator;

impl VerificationRule<GpuClaims> for CheckValidator {
    type Error = VerificationError;
    fn verify(&self, claims: &GpuClaims) -> Result<(), Self::Error> {
        let checks = [
            // ("arch_check", claims.arch_check), ??
            (
                "attestation_report_cert_validated",
                claims.attestation_report_cert_validated,
            ),
            (
                "driver_rim_cert_validated",
                claims.driver_rim_cert_validated,
            ),
            // ("driver_rim_fetched", claims.driver_rim_fetched), ??
            // (
            //     "driver_rim_signature_verified",
            //     claims.driver_rim_signature_verified,
            // ),
            // ("vbios_rim_cert_validated", claims.vbios_rim_cert_validated),
            // (
            //     "vbios_rim_signature_verified",
            //     claims.vbios_rim_signature_verified,
            // ),
        ];
        checks
            .into_iter()
            .find(|(_, v)| v.unwrap_or_default())
            .map_or(Ok(()), |(name, _)| {
                Err(VerificationError::FailedCheck(name))
            })
    }
}

impl VerificationRule<OverallClaims> for CheckValidator {
    type Error = VerificationError;
    fn verify(&self, claims: &OverallClaims) -> Result<(), Self::Error> {
        claims
            .overall_att_result
            .unwrap_or_default()
            .then_some(())
            .ok_or(VerificationError::FailedCheck("overall_att_result"))
    }
}

pub struct NonceValidator<T: AsRef<str>>(T);

impl<T: AsRef<str>> From<T> for NonceValidator<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

// implementing nonce validator for gpu claims
impl<T: AsRef<str>> VerificationRule<GpuClaims> for NonceValidator<T> {
    type Error = VerificationError;
    fn verify(&self, claims: &GpuClaims) -> Result<(), Self::Error> {
        let nonce = claims
            .eat_nonce
            .as_ref()
            .ok_or(VerificationError::MissingData("eat_nonce"))?;

        let expected_nonce = self.0.as_ref();

        (nonce == expected_nonce)
            .then_some(())
            .ok_or(VerificationError::invalid_nonce(nonce, expected_nonce))
    }
}

// implementing nonce validator for overall claims
impl<T: AsRef<str>> VerificationRule<OverallClaims> for NonceValidator<T> {
    type Error = VerificationError;
    fn verify(&self, claims: &OverallClaims) -> Result<(), Self::Error> {
        let nonce = claims
            .eat_nonce
            .as_ref()
            .ok_or(VerificationError::MissingData("eat_nonce"))?;

        let expected_nonce = self.0.as_ref();

        (nonce == expected_nonce)
            .then_some(())
            .ok_or(VerificationError::invalid_nonce(nonce, expected_nonce))
    }
}

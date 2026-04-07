use libattest::VerificationRule;
use thiserror::Error;

use crate::{
    nonce::NvidiaNonce,
    types::{GpuClaims, OverallClaims},
};

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
    fn invalid_nonce(got: impl AsRef<[u8]>, expected: impl AsRef<[u8]>) -> VerificationError {
        let got = hex::encode(got);
        let expected = hex::encode(expected);
        VerificationError::InvalidNonce(got, expected)
    }
}

// pub struct CheckValidator;

// impl VerificationRule<GpuClaims> for CheckValidator {
//     type Error = VerificationError;
//     fn verify(&self, claims: &GpuClaims) -> Result<(), Self::Error> {
//         let checks = [
//             // ("arch_check", claims.arch_check), ??
//             (
//                 "attestation_report_cert_validated",
//                 claims.attestation_report_cert_validated,
//             ),
//             (
//                 "driver_rim_cert_validated",
//                 claims.driver_rim_cert_validated,
//             ),
//             // ("driver_rim_fetched", claims.driver_rim_fetched), ??
//             // (
//             //     "driver_rim_signature_verified",
//             //     claims.driver_rim_signature_verified,
//             // ),
//             // ("vbios_rim_cert_validated", claims.vbios_rim_cert_validated),
//             // (
//             //     "vbios_rim_signature_verified",
//             //     claims.vbios_rim_signature_verified,
//             // ),
//         ];
//         checks
//             .into_iter()
//             .find(|(_, v)| v.unwrap_or_default())
//             .map_or(Ok(()), |(name, _)| {
//                 Err(VerificationError::FailedCheck(name))
//             })
//     }
// }

// impl VerificationRule<OverallClaims> for CheckValidator {
//     type Error = VerificationError;
//     fn verify(&self, claims: &OverallClaims) -> Result<(), Self::Error> {
//         claims
//             .overall_att_result
//             .unwrap_or_default()
//             .then_some(())
//             .ok_or(VerificationError::FailedCheck("overall_att_result"))
//     }
// }

// pub struct NonceValidator<'a>(&'a NvidiaNonce);

// impl<'a> From<&'a NvidiaNonce> for NonceValidator<'a> {
//     fn from(value: &'a NvidiaNonce) -> Self {
//         NonceValidator(value)
//     }
// }

// // implementing nonce validator for gpu claims
// impl VerificationRule<GpuClaims> for NonceValidator<'_> {
//     type Error = VerificationError;
//     fn verify(&self, claims: &GpuClaims) -> Result<(), Self::Error> {
//         let expected: &[u8; 32] = self.0.as_ref();

//         (&claims.eat_nonce == expected)
//             .then_some(())
//             .ok_or(VerificationError::invalid_nonce(claims.eat_nonce, expected))
//     }
// }

// // implementing nonce validator for overall claims
// impl VerificationRule<OverallClaims> for NonceValidator<'_> {
//     type Error = VerificationError;
//     fn verify(&self, claims: &OverallClaims) -> Result<(), Self::Error> {
//         let expected: &[u8; 32] = self.0.as_ref();

//         (&claims.eat_nonce == expected)
//             .then_some(())
//             .ok_or(VerificationError::invalid_nonce(claims.eat_nonce, expected))
//     }
// }

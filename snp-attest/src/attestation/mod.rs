/// Certificate chain structures and methods
pub mod chain;
/// Error structure
pub mod error;
/// Methods for interacting with AMD's keyserver
pub mod kds;
// pub mod nonce;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{nonce::SevNonce, oid};
use der::Encode;
use sev::{
    CpuFamily, CpuModel, Generation, firmware::guest::AttestationReport, parser::ByteParser,
};
use x509_parser::prelude::*;

use self::{
    chain::VerifiedChain,
    error::{AttestationError, ParseReason, VerificationReason},
};

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "sev"))]
/// Represents a parsed attestation report with some already
/// parsed commonly accessed fields
#[allow(unused)]
pub struct ParsedAttestation {
    cpu_fam_id: CpuFamily,
    cpu_mod_id: CpuModel,
    generation: Generation,

    report: AttestationReport,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl ParsedAttestation {
    /// Parses and constructs a new attestation report from a stream of binary data
    pub fn new(bytes: &[u8]) -> Result<Self, AttestationError> {
        let report =
            AttestationReport::from_bytes(bytes).map_err(|_| ParseReason::BadAttestationData)?;

        let cpu_fam_id = report
            .cpuid_fam_id
            .ok_or(ParseReason::MissingAttestationField)?;
        let cpu_mod_id = report
            .cpuid_mod_id
            .ok_or(ParseReason::MissingAttestationField)?;

        let generation = sev::Generation::identify_cpu(cpu_fam_id, cpu_mod_id)
            .map_err(|_| ParseReason::IdentifyCpu)?;

        Ok(ParsedAttestation {
            cpu_fam_id,
            cpu_mod_id,
            generation,
            report,
        })
    }

    pub fn cpu_fam_id(&self) -> CpuFamily {
        self.cpu_fam_id
    }

    pub fn cpu_mod_id(&self) -> CpuModel {
        self.cpu_mod_id
    }

    /// Verifies the attestation report against a certificate chain
    pub fn verify(&self, chain: &VerifiedChain, nonce: &SevNonce) -> Result<(), AttestationError> {
        // let certificates = chain.parse_certificates()?;

        // TODO: unify everything and use either x509-cert or x509-parser
        let vek = chain.vek.cert();
        let vek = vek.to_der().unwrap();
        let (_, vek) = X509Certificate::from_der(&vek).unwrap();

        /* Check TCB */
        let exts_map = vek.extensions_map()?;

        oid::check_spl(self.report.reported_tcb, &exts_map).map_err(|_| VerificationReason::Spl)?;

        /* Compare HWID */
        if let Some(hwid) = exts_map.get(&oid::HWID) {
            oid::compare_bytes(hwid, self.report.chip_id.as_ref())
                .then_some(())
                .ok_or(VerificationReason::ChipId)?;
        }

        let product_name_ext = exts_map.get(&oid::PRODUCT_NAME).unwrap();
        let (product_name, _) =
            crate::kds_util::decode_product_name(product_name_ext.value.to_vec())
                .map_err(|_| ParseReason::DecodeProductName)?;

        if product_name != self.generation.titlecase() {
            Err(VerificationReason::BadProductName)?;
        }

        /* check for revocation */
        // TODO: check in certificate revocation list

        /* Check full chain */
        log::info!("Verifying self report signature");
        chain.check_signature(&self.report)?;

        let nonce: &[u8; 64] = nonce.as_ref();
        if &self.report.report_data != nonce {
            log::error!("wrong nonce in reported data");
            return Err(AttestationError::WrongNonce);
        }

        log::info!("Verification ok!");
        Ok(())
    }
}

impl ParsedAttestation {
    pub fn generation(&self) -> Generation {
        self.generation
    }

    pub fn report(&self) -> &AttestationReport {
        &self.report
    }
}

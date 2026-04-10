/// Certificate chain structures and methods
pub mod chain;
/// Methods for interacting with AMD's keyserver
pub mod kds;

// pub mod nonce;

use libattest::{
    error::{AttestationError, Context, Expose},
};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{kds::chipid_from_gen, nonce::SevNonce, oid};
use der::Encode;
use sev::{
    CpuFamily, CpuModel, Generation, firmware::guest::AttestationReport, parser::ByteParser,
};
use x509_parser::prelude::*;

use self::chain::VerifiedChain;

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
            AttestationReport::from_bytes(bytes).context("failed parsing attestation report")?;

        let cpu_fam_id = report
            .cpuid_fam_id
            .context("missing cpuid_fam_id from attestation report")?;
        let cpu_mod_id = report
            .cpuid_mod_id
            .context("missing cpuid_mod_id from attestation report")?;

        let generation = sev::Generation::identify_cpu(cpu_fam_id, cpu_mod_id)
            .context("could not identify cpu from attestation report")?;

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

        oid::check_spl(self.report.reported_tcb, &exts_map)
            .context("failed to check spl from attestation report")
            .expose_error()?;

        /* Compare HWID */
        if let Some(hwid) = exts_map.get(&oid::HWID) {
            oid::compare_bytes(
                hwid,
                chipid_from_gen(&self.report.chip_id, self.generation()),
            )
            .then_some(())
            .context("mismatched chip id")?
        }

        let product_name_ext = exts_map.get(&oid::PRODUCT_NAME).unwrap();
        let (product_name, _) = kds::decode_product_name(product_name_ext.value.to_vec())
            .context("could not get product name")?;

        if product_name != self.generation.titlecase() {
            return AttestationError::internal(
                "mismatched product name from one gathered from kds",
            );
        }

        /* check for revocation */
        // TODO: check in certificate revocation list

        /* Check full chain */
        log::info!("Verifying self report signature");
        chain.check_signature(&self.report)?;

        let nonce: &[u8; 64] = nonce.as_ref();
        if &self.report.report_data != nonce {
            return AttestationError::exposed(
                "attestation report nonce does not match with provided nonce",
            );
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

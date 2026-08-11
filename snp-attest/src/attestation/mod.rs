/// Certificate chain structures and methods
pub mod chain;
/// Methods for interacting with AMD's keyserver
pub mod kds;
pub mod verify;

// pub mod nonce;

use libattest::{
    error::{AttestationError, Context, Expose},
    validation::Verifiable,
};

use serde::{Deserialize, Serialize};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{claims::SevClaims, kds::chipid_from_gen, nonce::SevNonce, oid};
use der::Encode;
use sev::{
    CpuFamily, CpuModel, Generation, firmware::guest::AttestationReport, parser::ByteParser,
};
use x509_parser::prelude::*;

use self::chain::VerifiedChain;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
/// Represents a parsed attestation report with some already
/// parsed commonly accessed fields
#[allow(unused)]
#[derive(Serialize, Deserialize)]
pub struct SevQuote {
    cpu_fam_id: CpuFamily,
    cpu_mod_id: CpuModel,
    // generation: Generation,
    report: AttestationReport,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl SevQuote {
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

        Ok(SevQuote {
            cpu_fam_id,
            cpu_mod_id,
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
    fn verify(&self, chain: &VerifiedChain, nonce: &SevNonce) -> Result<(), AttestationError> {
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

        let generation = self.generation()?;

        /* Compare HWID */
        if let Some(hwid) = exts_map.get(&oid::HWID) {
            oid::compare_bytes(hwid, chipid_from_gen(&self.report.chip_id, generation))
                .then_some(())
                .context("mismatched chip id")?
        }

        let product_name_ext = exts_map.get(&oid::PRODUCT_NAME).unwrap();
        let (product_name, _) = kds::decode_product_name(product_name_ext.value.to_vec())
            .context("could not get product name")?;

        if product_name != generation.titlecase() {
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

impl SevQuote {
    pub fn report(&self) -> &AttestationReport {
        &self.report
    }

    pub fn generation(&self) -> libattest::Result<Generation> {
        sev::Generation::identify_cpu(self.cpu_fam_id, self.cpu_mod_id)
            .context("could not identify cpu from attestation report")
    }
}

impl Verifiable for SevQuote {
    type Claims<'a>
        = SevClaims
    where
        Self: 'a;
}

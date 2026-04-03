use std::ops::Deref;

use libattest::error::Context;
use sha2::{Digest, Sha256, digest::Update};
use signature::Verifier;
use zerocopy::IntoBytes;

use crate::{
    TdxCertification, TdxQuote,
    certificates::crl::VerifyCrl,
    dcap::types::{ReportData, TdxQuoteBody},
    error::TdxError,
    nonce::TdxNonce,
    pcs::{
        Collateral,
        qe::QeTcbLevel,
        tcb::{self, Tcb, TcbLevel, TcbStatus},
    },
};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

/// Verifies:
/// 1. QE report signature
/// 2. QE report hashes
///
/// After this function the ISV report key can be used to verify
/// the ISV report signature
fn verify_qe_report(quote: &TdxQuote, collateral: &Collateral) -> Result<(), TdxError> {
    let certification = quote.certification();

    // Certificate revocation check
    let pck_chain = certification
        .data
        .pck_chain()
        .context("failed extracting pck chain from tdx quote")?;

    // check for certificate revocation status
    // in pcs obtained certificate revocation list
    collateral.crl.check_revoked(pck_chain)?;

    // Verify that pck_chain attests the qe signature
    let qe_report = certification
        .data
        .qe_report()
        .context("qe report is not in the first level of nesting in dcap quote")?;

    let qe_report_data = qe_report.qe_report.as_bytes();
    pck_chain.verify(qe_report_data, &qe_report.qe_report_signature)?;

    // now verify hashes
    let attestation_key = certification.attestation_key.to_sec1_bytes();
    let attestation_key = &attestation_key[1..]; // remove 0x04 header
    debug_assert_eq!(attestation_key.len(), 64);

    let sha = Sha256::new()
        .chain(attestation_key)
        .chain(&qe_report.authentication_data)
        // .chain([0x00; 32])
        .finalize();

    let report_data = &qe_report.qe_report.report_data[..32]; // hash is found only in first 32 bytes as per dcap documentation

    if sha.as_bytes() != report_data {
        return TdxError::internal("qe report_data hash mismatch");
    }

    Ok(())
}

/// Verifies:
/// 1. ISV report signature using ISV report key
fn verify_isv_signature(quote: &TdxQuote, collateral: &Collateral) -> Result<(), TdxError> {
    let mut signed_data = vec![];
    signed_data.extend_from_slice(quote.header.as_bytes());
    signed_data.extend_from_slice(quote.body.as_bytes());

    quote
        .certification
        .attestation_key
        .verify(&signed_data, &quote.certification.attestation_signature)?;

    Ok(())
}

/// Verifies all Quoting Enclave policies and returns
/// the TCB level for this quoting enclave if succesfull
fn verify_qe_identity_policy(
    quote: &TdxQuote,
    collateral: &Collateral,
) -> Result<QeTcbLevel, TdxError> {
    let enclave_report = &quote
        .certification
        .data
        .qe_report()
        .context("missing qe report from certification data")?
        .qe_report;
    let qe_identity = &collateral.qe_identity;

    if enclave_report.mrsigner != qe_identity.mrsigner {
        return TdxError::internal("mrsigner mismatch between qe identity and enclave report");
    }

    if enclave_report.isv_prod_id != qe_identity.isvprodid {
        return TdxError::internal("isv_prod_id mismatch between qe identity and enclave report");
    }

    if enclave_report.attributes[0] & 0x02 != 0x00 {
        return TdxError::internal("qe debug mode is active");
    }

    // verify miscselect by applying mask
    verify_mask(
        &enclave_report.miscselect,
        &qe_identity.miscselect,
        &qe_identity.miscselect_mask,
    )
    .then_some(())
    .context("failed verifying miscselect")?;

    // verify attributes by applying mask
    verify_mask(
        &enclave_report.attributes,
        &qe_identity.attributes,
        &qe_identity.attributes_mask,
    )
    .then_some(())
    .context("failed verifying attributes")?;

    // Tmatch quoting enclave tcb level
    let tcb = qe_identity
        .tcb_levels
        .iter()
        .find(|level| level.tcb.isvsvn <= enclave_report.isv_svn)
        .cloned()
        .context("TCB level not supported")?;

    // all checks ok
    Ok(tcb)
}

fn verify_platform_tcb(quote: &TdxQuote, collateral: &Collateral) -> Result<TcbLevel, TdxError> {
    // verify fmspc match
    // 1. Retrieve FMSPC value from SGX PCK Certificate assigned to a given platform.
    let fmspc = quote
        .certification()
        .sgx_extensions()?
        .fmspc()
        .context("failed to get fmspc from sgx extensions")?;

    // 2. Retrieve TDX TCB Info matching the FMSPC value.
    // > collateral.tcb_info

    if fmspc != collateral.tcb_info.fmspc {
        return TdxError::internal("fmspc mismatch");
    }

    let sgx_extensions = quote.certification().sgx_extensions()?;
    let pck_tcb = sgx_extensions
        .tcb()
        .context("failed to get tcb from sgx extension")?;

    for tcb_level in &collateral.tcb_info.tcb_levels {
        // Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to 16)
        // with the corresponding values of SVNs in sgxtcbcomponents array of TCB Level.
        // If all SGX TCB Comp SVNs in the certificate are greater or equal to the corresponding values in TCB Level, go to 3.b,
        // otherwise move to the next item on TCB Levels list.
        let comp_svn_check = tcb_level
            .tcb
            .sgxtcbcomponents
            .iter()
            .zip(pck_tcb.cpu_svn.into_iter())
            .all(|(collateral, quote)| quote >= collateral.svn);

        if !comp_svn_check {
            continue;
        }

        // Compare PCESVN value retrieved from the SGX PCK certificate with the corresponding value in the TCB Level.
        // If it is greater or equal to the value in TCB Level, go to 3.c, otherwise move to the next item on TCB Levels list.
        if pck_tcb.pce_svn < u32::from(tcb_level.tcb.pcesvn) {
            continue;
        }

        // Compare SVNs in TEE TCB SVN array retrieved from TD Report in Quote (from index 0 to 15 if TEE TCB SVN at index 1 is set to 0,
        // or from index 2 to 15 otherwise) with the corresponding values of SVNs in tdxtcbcomponents array of TCB Level.
        // If all TEE TCB SVNs in the TD Report are greater or equal to the corresponding values in TCB Level,
        // read tcbStatus assigned to this TCB level. Otherwise, move to the next item on TCB Levels list.\
        let tdxtcbcomponents = tcb_level
            .tcb
            .tdxtcbcomponents
            .as_ref()
            .context("missing tdx tcb components")?;

        let mut comp_tee_svn_check = tdxtcbcomponents
            .iter()
            .zip(quote.body().tee_tcb_svn.into_iter());

        // https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-info-v4:~:text=from%20index%200%20to%2015%20if%20TEE%20TCB%20SVN%20at%20index%201%20is%20set%20to%200%2C%20or%20from%20index%202%20to%2015%20otherwise
        let tee_tcb_svn_1 = tdxtcbcomponents.get(1).context("missing TEE TCB SVN")?.svn;
        if tee_tcb_svn_1 == 0 {
            comp_tee_svn_check.by_ref().take(2).count(); // skip 2 items from the iterator if tee_tcb_svn = 0
        }

        let comp_tee_svn_check =
            comp_tee_svn_check.all(|(collateral, quote)| u32::from(quote) >= collateral.svn);

        if !comp_tee_svn_check {
            continue;
        }

        // we found our tcb level
        return Ok(tcb_level.clone());
    }

    TdxError::internal("Could not find an appropriate TCB Level for this quote")
}

fn verify_report_data(quote: &TdxQuote, report_data: &TdxNonce) -> Result<(), TdxError> {
    if quote.body.report_data != report_data.as_bytes() {
        return TdxError::internal("quote report data does not match expected report data");
    }

    Ok(())
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct TcbLevels {
    qe_tcb: QeTcbLevel,
    isv_tcb: TcbLevel,
}

// #[cfg_attr(target_family = "wasm", wasm_bindgen)]
fn verify(
    quote: &TdxQuote,
    collateral: &Collateral,
    report_data: &TdxNonce,
) -> Result<TcbLevels, TdxError> {
    let certification = quote.certification();

    verify_qe_report(quote, collateral).context("error while verifying qe report")?;
    verify_isv_signature(quote, collateral).context("error while verifying isv signature")?;
    let qe_tcb = verify_qe_identity_policy(quote, collateral)
        .context("error while verifying qe identity policy")?;
    let isv_tcb = verify_platform_tcb(quote, collateral)
        .context("failed to match a tcb level for this quote")?;

    verify_report_data(quote, report_data).context("error while matching report data")?;

    let tcb_levels = TcbLevels { qe_tcb, isv_tcb };
    Ok(tcb_levels)
}

fn verify_mask<const N: usize>(quote: &[u8; N], expected: &[u8; N], mask: &[u8; N]) -> bool {
    quote
        .iter()
        .zip(expected)
        .zip(mask)
        .map(|((quote, expected), mask)| (quote, expected, mask))
        .all(|(quote, expected, mask)| (quote & mask) == (expected & mask))
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct QuoteVerifier {
    collateral: Collateral,
    quote: TdxQuote,
    minimum_tcb_level: TcbStatus,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl QuoteVerifier {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn new(collateral: Collateral, quote: TdxQuote) -> Self {
        Self {
            collateral,
            quote,
            minimum_tcb_level: TcbStatus::UpToDate,
        }
    }

    pub fn verify(&self, nonce: &TdxNonce) -> Result<(), TdxError> {
        let tcb_levels = verify(&self.quote, &self.collateral, nonce)?;
        let minimum_tcb = &self.minimum_tcb_level;

        if tcb_levels.qe_tcb.tcb_status < self.minimum_tcb_level {
            let tcb_status = tcb_levels.qe_tcb.tcb_status;
            return TdxError::internal("minimum qe_tcb not matched")
                .with_context(|| format!("expected {minimum_tcb} got {tcb_status}"));
        }

        if tcb_levels.isv_tcb.tcb_status < self.minimum_tcb_level {
            let tcb_status = tcb_levels.isv_tcb.tcb_status;
            return TdxError::internal("minimum isv_tcb not matched")
                .with_context(|| format!("expected {minimum_tcb} got {tcb_status}"));
        }

        Ok(())
    }
}

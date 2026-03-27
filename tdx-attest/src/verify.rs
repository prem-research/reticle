use sha2::{Digest, Sha256, digest::Update};
use signature::Verifier;
use zerocopy::IntoBytes;

use crate::{
    Certification, Quote,
    certificates::crl::VerifyCrl,
    dcap::types::{QuoteBody, ReportData},
    error::{Context, TdxError},
    pcs::{
        Collateral,
        qe::QeTcbLevel,
        tcb::{self, Tcb, TcbLevel},
    },
};

/// Verifies:
/// 1. QE report signature
/// 2. QE report hashes
///
/// After this function the ISV report key can be used to verify
/// the ISV report signature
fn verify_qe_report(quote: &Quote, collateral: &Collateral) -> Result<(), TdxError> {
    let certification = quote.certification();

    // Certificate revocation check
    let pck_chain = certification
        .data
        .pck_chain()
        .context("failed extracting pck chain from tdx quote")?;

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
        return TdxError::msg("qe report_data hash mismatch");
    }

    Ok(())
}

/// Verifies:
/// 1. ISV report signature using ISV report key
fn verify_isv_signature(quote: &Quote, collateral: &Collateral) -> Result<(), TdxError> {
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
    quote: &Quote,
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
        return TdxError::msg("mrsigner mismatch between qe identity and enclave report");
    }

    if enclave_report.isv_prod_id != qe_identity.isvprodid {
        return TdxError::msg("isv_prod_id mismatch between qe identity and enclave report");
    }

    if enclave_report.attributes[0] & 0x02 != 0x00 {
        return TdxError::msg("qe debug mode is active");
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

fn verify_platform_tcb(quote: &Quote, collateral: &Collateral) -> Result<TcbLevel, TdxError> {
    // verify fmspc match
    let fmspc = quote
        .certification()
        .sgx_extensions()?
        .fmspc()
        .context("failed to get fmspc from sgx extensions")?;

    if fmspc != collateral.tcb_info.fmspc {
        return TdxError::msg("fmspc mismatch");
    }

    let sgx_extensions = quote.certification().sgx_extensions()?;
    let pck_tcb = sgx_extensions
        .tcb()
        .context("failed to get tcb from sgx extension")?;

    for tcb_level in &collateral.tcb_info.tcb_levels {
        let comp_svn_check = tcb_level
            .tcb
            .sgxtcbcomponents
            .iter()
            .zip(pck_tcb.cpu_svn.into_iter())
            .all(|(collateral, quote)| quote >= collateral.svn);

        if !comp_svn_check {
            continue;
        }

        if pck_tcb.pce_svn < u32::from(tcb_level.tcb.pcesvn) {
            continue;
        }

        let tdxtcbcomponents = tcb_level
            .tcb
            .tdxtcbcomponents
            .as_ref()
            .context("missing tdx tcb components")?;

        let comp_tee_svn_check = tdxtcbcomponents
            .iter()
            .zip(quote.body().tee_tcb_svn.into_iter())
            .all(|(collateral, quote)| u32::from(quote) >= collateral.svn);

        if !comp_tee_svn_check {
            continue;
        }

        // we found our tcb level
        return Ok(tcb_level.clone());
    }

    TdxError::msg("Could not find an appropriate TCB Level for this quote")
}

fn verify_report_data(quote: &Quote, report_data: &ReportData) -> Result<(), TdxError> {
    if &quote.body.report_data != report_data {
        return TdxError::msg("quote report data does not match expected report data");
    }

    Ok(())
}

pub fn verify(
    quote: &Quote,
    collateral: &Collateral,
    report_data: &ReportData,
) -> Result<(), TdxError> {
    let certification = quote.certification();

    verify_qe_report(quote, collateral).context("error while verifying qe report")?;
    verify_isv_signature(quote, collateral).context("error while verifying isv signature")?;
    let qe_tcb = verify_qe_identity_policy(quote, collateral)
        .context("error while verifying qe identity policy")?;
    let isv_tcb = verify_platform_tcb(quote, collateral)
        .context("failed to match a tcb level for this quote")?;

    verify_report_data(quote, report_data).context("error while matching report data")?;

    Ok(())
}

fn verify_mask<const N: usize>(quote: &[u8; N], expected: &[u8; N], mask: &[u8; N]) -> bool {
    quote
        .iter()
        .zip(expected)
        .zip(mask)
        .map(|((quote, expected), mask)| (quote, expected, mask))
        .all(|(quote, expected, mask)| (quote & mask) == (expected & mask))
}

// fn match_tcb_level() {}

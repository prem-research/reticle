use std::ops::Deref;

use libattest::{
    crypto::chain::crl::VerifyCrl, error::Context, quote::QuoteVerifier, validation::Verifiable,
};
use sha2::{Digest, Sha256, digest::Update};
use signature::Verifier;
use zerocopy::IntoBytes;

use crate::{
    TdxCertification, TdxQuote,
    certificates::extensions::TcbExtension,
    dcap::types::{ReportData, TdxQuoteBody},
    error::TdxError,
    nonce::TdxNonce,
    pcs::{
        Collateral,
        qe::QeTcbLevel,
        tcb::{TcbInfo, TcbLevel, TcbStatus, TdxModuleTcbStatus},
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

    match_platform_tcb(
        pck_tcb,
        &quote.body().tee_tcb_svn,
        &collateral.tcb_info.tcb_levels,
    )
    .cloned()
}

fn match_platform_tcb<'a>(
    pck_tcb: &TcbExtension,
    tee_tcb_svn: &[u8; 16],
    levels: &'a [TcbLevel],
) -> Result<&'a TcbLevel, TdxError> {
    // PCS TDX TCB Info v4: module versions above zero are appraised separately.
    // https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-info-v4
    let start = if tee_tcb_svn[1] == 0 { 0 } else { 2 };

    for tcb_level in levels {
        let tdxtcbcomponents = tcb_level
            .tcb
            .tdxtcbcomponents
            .as_ref()
            .context("missing tdx tcb components")?;
        if tcb_level.tcb.sgxtcbcomponents.len() != 16 || tdxtcbcomponents.len() != 16 {
            return TdxError::internal("TCB component arrays must contain exactly 16 entries");
        }
        // Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to 16)
        // with the corresponding values of SVNs in sgxtcbcomponents array of TCB Level.
        // If all SGX TCB Comp SVNs in the certificate are greater or equal to the corresponding values in TCB Level, go to 3.b,
        // otherwise move to the next item on TCB Levels list.
        let comp_svn_check = tcb_level
            .tcb
            .sgxtcbcomponents
            .iter()
            .zip(pck_tcb.cpu_svn.iter())
            .all(|(collateral, quote)| *quote >= collateral.svn);

        if !comp_svn_check {
            continue;
        }

        // Compare PCESVN value retrieved from the SGX PCK certificate with the corresponding value in the TCB Level.
        // If it is greater or equal to the value in TCB Level, go to 3.c, otherwise move to the next item on TCB Levels list.
        if pck_tcb.pce_svn < u32::from(tcb_level.tcb.pcesvn) {
            continue;
        }

        let comp_tee_svn_check = tdxtcbcomponents
            .iter()
            .zip(tee_tcb_svn)
            .skip(start)
            .all(|(collateral, quote)| u32::from(*quote) >= collateral.svn);

        if !comp_tee_svn_check {
            continue;
        }

        // we found our tcb level
        return Ok(tcb_level);
    }

    TdxError::internal("Could not find an appropriate TCB Level for this quote")
}

fn verify_tdx_module(body: &TdxQuoteBody, tcb_info: &TcbInfo) -> Result<TcbStatus, TdxError> {
    let version = body.tee_tcb_svn[1];
    let (mrsigner, attributes, attributes_mask, status) = if version == 0 {
        let module = tcb_info
            .tdx_module
            .as_ref()
            .context("missing base TDX module")?;
        (
            &module.mrsigner,
            &module.attributes,
            &module.attributes_mask,
            TcbStatus::UpToDate,
        )
    } else {
        let id = format!("TDX_{version:02X}");
        let module = tcb_info
            .tdx_module_identities
            .as_ref()
            .and_then(|identities| {
                identities
                    .iter()
                    .find(|module| module.id.eq_ignore_ascii_case(&id))
            })
            .context("TDX module identity not supported")?;
        let level = module
            .tcb_levels
            .iter()
            .find(|level| level.tcb.isvsvn <= u32::from(body.tee_tcb_svn[0]))
            .context("TDX module TCB level not supported")?;
        let status = match level.tcb_status {
            TdxModuleTcbStatus::UpToDate => TcbStatus::UpToDate,
            TdxModuleTcbStatus::OutOfDate => TcbStatus::OutOfDate,
            TdxModuleTcbStatus::Revoked => TcbStatus::Revoked,
        };
        (
            &module.mrsigner,
            &module.attributes,
            &module.attributes_mask,
            status,
        )
    };

    let mut signer = [0; 48];
    let mut attrs = [0; 8];
    let mut mask = [0; 8];
    hex::decode_to_slice(mrsigner, &mut signer).context("invalid TDX module mrsigner")?;
    hex::decode_to_slice(attributes, &mut attrs).context("invalid TDX module attributes")?;
    hex::decode_to_slice(attributes_mask, &mut mask)
        .context("invalid TDX module attributes mask")?;
    if body.mrsignerseam.as_bytes() != signer {
        return TdxError::internal("TDX module mrsigner mismatch");
    }
    // QVL QuoteVerifier.cpp (d12717e3): SEAMATTRIBUTES are reserved and must
    // equal the collateral attributes and zero, regardless of the mask.
    if body.seamsttributes != attrs || attrs != [0; 8] {
        return TdxError::internal("TDX module attributes mismatch or nonzero reserved attributes");
    }

    Ok(status)
}

fn effective_tcb_status(platform: &TcbStatus, module: &TcbStatus, qe: &TcbStatus) -> TcbStatus {
    use TcbStatus::*;

    // Intel QVL EvaluateTcb.cpp (d12717e3), convergeTcbStatuses.
    match (platform, module, qe) {
        (Revoked, _, _) | (_, Revoked, _) | (_, _, Revoked) => Revoked,
        (_, OutOfDate, _) | (_, _, OutOfDate) => match platform {
            UpToDate | SWHardeningNeeded => OutOfDate,
            ConfigurationNeeded | ConfigurationAndSWHardeningNeeded => OutOfDateConfigurationNeeded,
            Revoked | OutOfDate | OutOfDateConfigurationNeeded => platform.clone(),
        },
        _ => platform.clone(),
    }
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
    effective_tcb_status: TcbStatus,
}

impl TcbLevels {
    fn verify_minimum(&self, minimum_tcb: &TcbStatus) -> Result<(), TdxError> {
        if self.qe_tcb.tcb_status < *minimum_tcb {
            let tcb_status = &self.qe_tcb.tcb_status;
            return TdxError::internal("minimum qe_tcb not matched")
                .with_context(|| format!("expected {minimum_tcb} got {tcb_status}"));
        }

        if self.effective_tcb_status < *minimum_tcb {
            let tcb_status = &self.effective_tcb_status;
            return TdxError::internal("minimum effective TCB not matched")
                .with_context(|| format!("expected {minimum_tcb} got {tcb_status}"));
        }

        Ok(())
    }
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
    let module_tcb = verify_tdx_module(quote.body(), &collateral.tcb_info)
        .context("failed to verify TDX module")?;
    let effective_tcb_status =
        effective_tcb_status(&isv_tcb.tcb_status, &module_tcb, &qe_tcb.tcb_status);

    verify_report_data(quote, report_data).context("error while matching report data")?;

    let tcb_levels = TcbLevels {
        qe_tcb,
        isv_tcb,
        effective_tcb_status,
    };
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
pub struct TdxQuoteVerifier {
    collateral: Collateral,
    // quote: TdxQuote,
    minimum_tcb_level: TcbStatus,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl TdxQuoteVerifier {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    #[must_use]
    pub fn new(collateral: Collateral) -> Self {
        Self {
            collateral,
            minimum_tcb_level: TcbStatus::UpToDate,
        }
    }
}

impl QuoteVerifier for TdxQuoteVerifier {
    type Nonce = TdxNonce;
    type Quote = TdxQuote;

    fn verify<'a>(
        &self,
        quote: &'a TdxQuote,
        nonce: &TdxNonce,
    ) -> Result<&'a TdxQuoteBody, TdxError> {
        let tcb_levels = verify(quote, &self.collateral, nonce)?;
        tcb_levels.verify_minimum(&self.minimum_tcb_level)?;

        Ok(&quote.body)
    }
}

pub mod qe;
pub mod signed_response;
pub mod tcb;

use std::str::FromStr;

use p256::ecdsa::Signature;
use reqwest::{Client, IntoUrl, Url};
use serde::Deserialize;
use x509_cert::Certificate;

use crate::{
    TdxQuote,
    certificates::{CertificateChain, IntermediateCa, ca::INTEL_CA, crl::Crl},
    dcap::types::Fmspc,
    error::{Context, TdxError},
    pcs::{qe::EnclaveIdentity, signed_response::ParseSignedResponse, tcb::TcbInfo},
};

const INTEL_PCS: &str = "https://api.trustedservices.intel.com/";

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct Pcs {
    base_url: Url,
    client: Client,
}

impl Default for Pcs {
    fn default() -> Self {
        Self {
            base_url: INTEL_PCS.parse().unwrap(),
            client: Client::default(),
        }
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl Pcs {
    #[wasm_bindgen(constructor)]
    pub fn new(base_url: &str) -> Result<Self, TdxError> {
        let base_url = Url::from_str(base_url)?;
        let client = Client::default();

        Ok(Pcs { base_url, client })
    }

    async fn fetch_crl(&self, intermediate_ca: IntermediateCa) -> Result<Crl, TdxError> {
        let mut url = self.base_url.join("/sgx/certification/v4/pckcrl").unwrap();
        url.query_pairs_mut()
            .append_pair("ca", intermediate_ca.as_str())
            .append_pair("encoding", "pem");

        let response = self.client.get(url).send().await?.error_for_status()?;
        let certificate_chain = response
            .headers()
            .get("SGX-PCK-CRL-Issuer-Chain")
            .context("crl response does not contain a certificate chain")?;

        let chain = CertificateChain::with_anchor(&INTEL_CA)
            .parse_pem_chain(&urlencoding::decode_binary(certificate_chain.as_bytes()))
            .context("failed parsing crl certificate chain")?;

        let crl = response.text().await?;

        // TODO: review this very bad thing. We really should build our own pccs already.
        let crl = hex::decode(crl)?;
        let crl = Crl::from_der(&chain, crl).context("failed parsing and verifying crl")?;

        Ok(crl)
    }

    async fn fetch_qe_identity(&self) -> Result<EnclaveIdentity, TdxError> {
        let mut url = self
            .base_url
            .join("/tdx/certification/v4/qe/identity")
            .unwrap();

        let signed_response = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .parse_signed_response("SGX-Enclave-Identity-Issuer-Chain", "enclaveIdentity")
            .await?;

        let identity: EnclaveIdentity = signed_response
            .verify_signature()
            .context("failed to verify pcs response")?;

        Ok(identity)
    }

    async fn fetch_tcb_info(&self, fmspc: Fmspc) -> Result<TcbInfo, TdxError> {
        let mut url = self.base_url.join("/tdx/certification/v4/tcb").unwrap();

        // url.quer

        let signed_response = self
            .client
            .get(url)
            .query(&[("fmspc", fmspc.to_string())])
            .send()
            .await
            .context("failed sending tcb_info request")?
            .error_for_status()
            .context("error returned from tcb info endpoint")?
            .parse_signed_response("TCB-Info-Issuer-Chain", "tcbInfo")
            .await?;

        let tcb_info: TcbInfo = signed_response
            .verify_signature()
            .context("failed to verify tcb info signature from pcs")?;

        Ok(tcb_info)
    }

    pub async fn fetch_collateral(&self, quote: &TdxQuote) -> Result<Collateral, TdxError> {
        // extract fmspc from quote
        let fmspc = quote
            .certification()
            .sgx_extensions()
            .context("failed getting sgx extensions from quote")?
            .fmspc()
            .context("sgx extensions do not contain fmspc")?;

        let tcb_info = self.fetch_tcb_info(fmspc).await?;
        let crl = self.fetch_crl(IntermediateCa::Processor).await?;
        let qe_identity = self.fetch_qe_identity().await?;

        Ok(Collateral {
            crl,
            qe_identity,
            tcb_info,
        })
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct Collateral {
    pub(crate) crl: Crl,
    pub(crate) qe_identity: EnclaveIdentity,
    pub(crate) tcb_info: TcbInfo,
}

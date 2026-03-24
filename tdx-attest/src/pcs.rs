pub mod qe;
pub mod signed_response;
pub mod tcb;

use p256::ecdsa::Signature;
use reqwest::{Client, IntoUrl, Url};
use serde::Deserialize;
use x509_cert::Certificate;

use crate::{
    Quote,
    certificates::{CertificateChain, IntermediateCa, ca::INTEL_CA, crl::Crl},
    dcap::types::Fmspc,
    error::{Context, TdxError},
    pcs::{qe::EnclaveIdentity, signed_response::ParseSignedResponse, tcb::TcbInfo},
};

const INTEL_PCS: &str = "https://api.trustedservices.intel.com/";

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

impl Pcs {
    pub fn new(base_url: impl IntoUrl) -> Result<Self, reqwest::Error> {
        let base_url = base_url.into_url()?;
        let client = Client::default();

        Ok(Pcs { base_url, client })
    }

    pub async fn fetch_crl(&self, intermediate_ca: IntermediateCa) -> Result<Crl, TdxError> {
        let mut url = self.base_url.join("/sgx/certification/v4/pckcrl").unwrap();
        url.query_pairs_mut()
            .append_pair("ca", intermediate_ca.as_str());

        let response = self.client.get(url).send().await?.error_for_status()?;
        let certificate_chain = response
            .headers()
            .get("SGX-PCK-CRL-Issuer-Chain")
            .context("crl response does not contain a certificate chain")?;

        let chain = CertificateChain::with_anchor(&INTEL_CA)
            .parse_pem_chain(certificate_chain.as_bytes())
            .context("failed parsing crl certificate chain")?;

        let crl = response.text().await?;
        let crl = Crl::from_pem(&chain, crl).context("failed parsing and verifying crl")?;

        Ok(crl)
    }

    pub async fn fetch_qe_identity(&self) -> Result<EnclaveIdentity, TdxError> {
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

    pub async fn fetch_tcb_info(&self, fmspc: Fmspc) -> Result<TcbInfo, TdxError> {
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
}

pub struct Collateral {}

// pub fn fetch_collateral(quote: &Quote) -> Result<Collateral, Error> {
//     todo!()
// }

// #[cfg(test)]
// mod test {
//     use crate::pcs::Pcs;

//     #[tokio::test]
//     async fn fetch_crl() {
//         let pcs = Pcs::default();
//         pcs.fetch_crl(crate::certificates::IntermediateCa::Platform)
//             .await;
//     }
// }

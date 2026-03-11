pub mod qe;
pub mod signed_response;

use p256::ecdsa::Signature;
use reqwest::{Client, IntoUrl, Url};
use serde::Deserialize;

use crate::{
    Quote,
    certificates::{CertificateChain, IntermediateCa},
    error::{Context, TdxError},
    pcs::{qe::EnclaveIdentity, signed_response::ParseSignedResponse},
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

    pub async fn fetch_crl(&self, intermediate_ca: IntermediateCa) {
        let mut url = self.base_url.join("/sgx/certification/v4/pckcrl").unwrap();
        url.query_pairs_mut()
            .append_pair("ca", intermediate_ca.as_str());

        let text = self.client.get(url).send().await.unwrap().text().await;
        panic!("{text:?}");
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

    // pub async fn
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

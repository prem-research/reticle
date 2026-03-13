pub mod error;

use libattest::{CpuModule, GpuModule, Modules};
use nvidia_attest::{EATToken, keychain::KeyChain, nonce::NvidiaNonce};
use snp_attest::{ParsedAttestation, nonce::SevNonce};

pub use nvidia_attest;
use reqwest::Url;
pub use snp_attest;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::error::PremErr;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct ClientBuilder {
    url: String,
    reqwest_client: Option<reqwest::Client>,
}

impl ClientBuilder {
    pub fn with_reqwest_client(self, client: reqwest::Client) -> Self {
        Self {
            reqwest_client: Some(client),
            ..self
        }
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl ClientBuilder {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            reqwest_client: None,
        }
    }

    pub fn build(self) -> Result<Client, PremErr> {
        let reqwest_client = self.reqwest_client.unwrap_or_default();

        Ok(Client {
            url: self.url.parse().map_err(PremErr::Parse)?,
            reqwest_client,
        })
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct Client {
    url: Url,
    reqwest_client: reqwest::Client,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl Client {
    /// Gather available attestable modules from remote attestation endpoint
    pub async fn request_modules(&self) -> Result<libattest::Modules, PremErr> {
        let url = self.url.join("/attestation/modules").unwrap();

        let response: Modules = self.reqwest_client.get(url).send().await?.json().await?;

        // check whether the modules are enough to attest a device (a gpu and a cpu)
        Ok(response)
    }

    /// Requests and parses a SEV-SNP attestation from the attestation server.
    ///
    /// ### Warning
    /// This method exposes core functionality and does not perform cryptographic
    /// or measurement checks on the attestation. If you want to perform end-to-end attestation
    /// please refer to [`Self::attest_sev`]
    pub async fn request_sev(&self, nonce: &SevNonce) -> Result<ParsedAttestation, PremErr> {
        let url = self.url.join("/attestation/cpu").unwrap();

        // build the request with parameter ?nonce=<nonce> encoded in hex
        let response = self
            .reqwest_client
            .get(url)
            .query(&[("nonce", nonce.to_hex())])
            .send()
            .await?;

        // decode the raw byte stream from the http request
        let attestation = response.error_for_status()?.bytes().await?;

        // parse attestation using snp-attest crate
        let attestation = ParsedAttestation::new(&attestation)?;

        Ok(attestation)
    }

    /// Requests and parses an Nvidia EATToken attestation from the attestation server
    ///
    /// ### Warning
    /// This method exposes core functionality and does not perform cryptographic
    /// or measurement checks on the attestation. If you want to perform end-to-end attestation
    /// please refer to [`Self::attest_nvidia`]
    pub async fn request_nvidia(&self, nonce: &NvidiaNonce) -> Result<EATToken, PremErr> {
        let url = self.url.join("/attestation/nvidia").unwrap();

        let response = self
            .reqwest_client
            .get(url)
            .query(&[("nonce", nonce.to_hex())])
            .send()
            .await?;

        let response = response.error_for_status()?.text().await?;
        let response = EATToken::parse(&response)?;

        Ok(response)
    }

    /// Performs end-to-end sev-snp attestation. Generates nonce and validates claims all in one
    pub async fn attest_sev(&self) -> Result<(), PremErr> {
        let nonce = SevNonce::generate();

        let attestation = self.request_sev(&nonce).await?;
        let keychain = snp_attest::kds::fetch_certificates(&attestation).await?;

        attestation.verify(&keychain, &nonce)?;

        // TODO: measurement verification

        Ok(())
    }

    /// Completes end-to-end nvidia attestation. Generates nonce and validates claims all in one
    pub async fn attest_nvidia(&self) -> Result<(), PremErr> {
        let nonce = NvidiaNonce::generate();
        let keychain = KeyChain::fetch_keychain().await?;

        let attestation = self.request_nvidia(&nonce).await?;
        let claims = attestation.verify(&keychain)?;

        claims.validate(&nonce)?;

        Ok(())
    }

    /// Steps:
    /// - Gathers modules to attest from attestation server
    /// - Iterates through each module and performs end-to-end attestation
    /// - Returns the list of attested modules
    pub async fn attest(&self) -> Result<Modules, PremErr> {
        let modules = self.request_modules().await?;

        match modules.cpu() {
            CpuModule::Sev => self.attest_sev().await?,
            _ => unimplemented!(),
        }

        match modules.gpu() {
            Some(GpuModule::Nvidia) => self.attest_nvidia().await?,
            _ => unimplemented!(),
        }

        Ok(modules)
    }
}

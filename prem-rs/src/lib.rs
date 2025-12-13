use std::str::FromStr;

use snp_attest::{ParsedAttestation, nonce::SevNonce};
use thiserror::Error;
use wasm_bindgen::prelude::*;

pub use nvidia_attest;
use reqwest::Url;
pub use snp_attest;

#[derive(Error, Debug)]
pub enum PremErr {
    #[error("error parsing the server url")]
    Parse(<Url as FromStr>::Err),
    #[error("error requesting prem's server: ${0}")]
    Request(#[from] reqwest::Error),
    #[error("error from sev attestation: ${0}")]
    Sev(#[from] snp_attest::error::AttestationError),
}

impl From<PremErr> for JsValue {
    fn from(value: PremErr) -> Self {
        JsError::from(value).into()
    }
}

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
        let reqwest_client = self
            .reqwest_client
            .unwrap_or_else(|| reqwest::Client::default());

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
    pub async fn request_attestation(
        &self,
        nonce: &SevNonce,
    ) -> Result<ParsedAttestation, PremErr> {
        let url = self.url.join("/attestation/cpu").unwrap();

        // build the request with parameter ?nonce=<nonce> encoded in hex
        let response = self
            .reqwest_client
            .get(url)
            .query(&[("nonce", nonce.to_hex())])
            .send()
            .await?;

        // decode the raw byte stream from the http request
        let attestation = response.bytes().await?;

        // parse attestation using snp-attest crate
        let attestation = ParsedAttestation::new(&attestation)?;

        Ok(attestation)
    }
}

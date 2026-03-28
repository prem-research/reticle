pub mod error;

use libattest::{CpuModule, GpuModule, Modules};
use nvidia_attest::{EATToken, keychain::KeyChain, nonce::NvidiaNonce};
use snp_attest::{ParsedAttestation, nonce::SevNonce};

pub use nvidia_attest;
use reqwest::{
    Url, header::{HeaderMap, HeaderValue}
};
pub use snp_attest;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::error::PremErr;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Clone)]
pub struct AttestHeaders {
    cpu: Option<ResponseHeaders>,
    gpu: Option<ResponseHeaders>
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl AttestHeaders {
    pub fn cpu(&self) -> Option<ResponseHeaders> {
        self.cpu.clone()
    }

    pub fn gpu(&self) -> Option<ResponseHeaders> {
        self.gpu.clone()
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Clone)]
pub struct AttestResult {
    modules: Modules,
    headers: AttestHeaders,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl AttestResult {
    pub fn modules(&self) -> Modules {
        self.modules
    }

    pub fn headers(&self) -> AttestHeaders {
        self.headers.clone()
    }
}

#[derive(Clone)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct ResponseHeaders(HeaderMap);

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl ResponseHeaders {
    pub fn get(&self, name: &str) -> Option<String> {
        self.0.get(name)?.to_str().ok().map(String::from)
    }

    pub fn keys(&self) -> Vec<String> {                                                                                                           
        self.0.keys().map(|k| k.to_string()).collect()                                                                                            
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct NvidiaAttestResult {
    eat_token: EATToken,
    headers: ResponseHeaders,
}

/// Generic per-request query parameters.
///
/// The `nonce` key is reserved and will be rejected.
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Clone)]
pub struct QueryParams(Vec<(String, String)>);

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl QueryParams {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        Self(vec![])
    }

    /// Appends a query parameter. Returns `Err` if `key` is `"nonce"` (reserved).
    pub fn with(mut self, key: &str, value: &str) -> Result<Self, PremErr> {
        if key == "nonce" {
            return Err(PremErr::ForbiddenQueryParam);
        }
        self.0.push((key.to_string(), value.to_string()));
        Ok(self)
    }
}

impl Default for QueryParams {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct ClientBuilder {
    url: String,
    headers: HeaderMap,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl ClientBuilder {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            headers: HeaderMap::default(),
        }
    }

    /// Sets `Authorization` header
    pub fn with_authorization(mut self, token: &str) -> Result<Self, PremErr> {
        self.headers
            .insert("Authorization", HeaderValue::from_str(token)?);

        Ok(self)
    }

    pub fn build(self) -> Result<Client, PremErr> {
        let reqwest_client = reqwest::Client::builder()
            .default_headers(self.headers)
            .build()?;

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
    pub async fn request_modules(&self, query: Option<QueryParams>) -> Result<libattest::Modules, PremErr> {
        let url = self.url.join("/attestation/modules").unwrap();

        let response = self
            .reqwest_client
            .get(url)
            .query(&query.unwrap_or_default().0)
            .send()
            .await?
            .json()
            .await?;

        Ok(response)
    }

    /// Requests and parses a SEV-SNP attestation from the attestation server.
    ///
    /// ### Warning
    /// This method exposes core functionality and does not perform cryptographic
    /// or measurement checks on the attestation. If you want to perform end-to-end attestation
    /// please refer to [`Self::attest_sev`]
    pub async fn request_sev(&self, nonce: &SevNonce, query: &QueryParams) -> Result<ParsedAttestation, PremErr> {
        let url = self.url.join("/attestation/cpu").unwrap();

        let response = self
            .reqwest_client
            .get(url)
            .query(&query.0)
            .query(&[("nonce", nonce.to_hex())])
            .send()
            .await?;

        let attestation = response.error_for_status()?.bytes().await?;
        let attestation = ParsedAttestation::new(&attestation)?;

        Ok(attestation)
    }

    /// Requests and parses an Nvidia EATToken attestation from the attestation server
    ///
    /// ### Warning
    /// This method exposes core functionality and does not perform cryptographic
    /// or measurement checks on the attestation. If you want to perform end-to-end attestation
    /// please refer to [`Self::attest_nvidia`]
    pub async fn request_nvidia(&self, nonce: &NvidiaNonce, query: &QueryParams) -> Result<NvidiaAttestResult, PremErr> {
        let url = self.url.join("/attestation/nvidia").unwrap();

        let response = self
            .reqwest_client
            .get(url)
            .query(&query.0)
            .query(&[("nonce", nonce.to_hex())])
            .send()
            .await?;

        let headers = response.headers().clone();
        let response_text = response.error_for_status()?.text().await?;
        let eat_token = EATToken::parse(&response_text)?;

        Ok(NvidiaAttestResult{ eat_token: eat_token, headers: ResponseHeaders(headers) })
    }

    /// Performs end-to-end sev-snp attestation. Generates nonce and validates claims all in one
    pub async fn attest_sev(&self, query: Option<QueryParams>) -> Result<(), PremErr> {
        let nonce = SevNonce::generate();

        let attestation = self.request_sev(&nonce, &query.unwrap_or_default()).await?;
        let keychain = snp_attest::kds::fetch_certificates(&attestation).await?;

        attestation.verify(&keychain, &nonce)?;

        // TODO: measurement verification

        Ok(())
    }

    /// Completes end-to-end nvidia attestation. Generates nonce and validates claims all in one
    pub async fn attest_nvidia(&self, query: Option<QueryParams>) -> Result<ResponseHeaders, PremErr> {
        let nonce = NvidiaNonce::generate();
        let keychain = KeyChain::fetch_keychain().await?;

        let attest_result = self.request_nvidia(&nonce, &query.unwrap_or_default()).await?;
        let claims = attest_result.eat_token.verify(&keychain)?;

        claims.validate(&nonce)?;

        Ok(attest_result.headers)
    }

    /// Steps:
    /// - Gathers modules to attest from attestation server
    /// - Iterates through each module and performs end-to-end attestation
    /// - Returns the list of attested modules
    pub async fn attest(&self, query: Option<QueryParams>) -> Result<AttestResult, PremErr> {
        // get modules
        let modules = self.request_modules(query.clone()).await?;

        match modules.cpu() {
            CpuModule::Sev => self.attest_sev(query.clone()).await?,
            _ => unimplemented!(),
        }

        let gpu_headers = match modules.gpu() {
            Some(GpuModule::Nvidia) => Some(self.attest_nvidia(query.clone()).await?),
            _ => unimplemented!(),
        };

        Ok(AttestResult { modules, headers: AttestHeaders { cpu: None, gpu: gpu_headers } })
    }
}

pub mod rego;

use std::borrow::Cow;

use libattest::{
    CpuModule, GpuModule, Modules,
    error::{AttestationError, Context, Expose},
    validation::{Validator, WithPolicy},
};
use nvidia_attest::{EATToken, keychain::KeyChain, nonce::NvidiaNonce};
use snp_attest::{ParsedAttestation, kds::Kds, nonce::SevNonce};

pub use nvidia_attest;
use reqwest::{
    Url,
    header::{HeaderMap, HeaderValue},
};
pub use snp_attest;

use tdx_attest::{TdxQuote, error::TdxError, nonce::TdxNonce, pcs::Pcs, verify::QuoteVerifier};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::rego::PoliciesClient;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Clone, Debug)]
pub struct AttestHeaders {
    cpu: Option<ResponseHeaders>,
    gpu: Option<ResponseHeaders>,
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
#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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
    pub fn with(mut self, key: &str, value: &str) -> Result<Self, AttestationError> {
        if key == "nonce" {
            return TdxError::exposed("cannot use nonce as a query parameter as it's reserved");
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
    /// base url for PREM attestation server
    url: String,
    /// intel collateral server
    pcs: Pcs,
    // amd collateral server
    kds: Kds,
    // prem OPA policies url
    policies: Cow<'static, str>,

    headers: HeaderMap,
}

const PREM_PCCS: &str = "https://pccs.prem.io/";
const PREM_KCDS: &str = "https://kcds.prem.io";
const PREM_POLICIES: &str = "https://policies.prem.io";

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl ClientBuilder {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            pcs: Pcs::new(PREM_PCCS).unwrap(),
            kds: Kds::new(PREM_KCDS).unwrap(),
            policies: PREM_POLICIES.into(),
            headers: HeaderMap::default(),
        }
    }

    /// Sets `Authorization` header
    pub fn with_authorization(mut self, token: &str) -> Result<Self, AttestationError> {
        self.headers
            .insert("Authorization", HeaderValue::from_str(token)?);

        Ok(self)
    }

    /// Sets custom KDS for AMD collateral server
    pub fn with_kds(mut self, kds: Kds) -> Self {
        self.kds = kds;
        self
    }

    /// Sets custom PCS for Intel collateral server
    pub fn with_pcs(mut self, pcs: Pcs) -> Self {
        self.pcs = pcs;
        self
    }

    /// sets custom url for OPA policies index
    pub fn with_policies_url(mut self, url: &str) -> Self {
        self.policies = url.to_string().into();
        self
    }

    pub async fn build(self) -> Result<Client, AttestationError> {
        let reqwest_client = reqwest::Client::builder()
            .default_headers(self.headers)
            .build()?;

        let validator = PoliciesClient::new(self.policies.as_ref())?
            .fetch_validator()
            .await
            .context("failed fetching OPA policies from url")?;

        Ok(Client {
            url: self
                .url
                .parse::<Url>()
                .context("cannot build client with supplied url because it is invalid")
                .expose_error()?,
            kds: self.kds,
            pcs: self.pcs,
            policy_validator: validator,
            reqwest_client,
        })
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct Client {
    /// base url
    url: Url,
    reqwest_client: reqwest::Client,

    kds: Kds,
    pcs: Pcs,
    policy_validator: Validator,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl Client {
    /// Gather available attestable modules from remote attestation endpoint
    pub async fn request_modules(
        &self,
        query: Option<QueryParams>,
    ) -> Result<libattest::Modules, AttestationError> {
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
    pub async fn request_sev(
        &self,
        nonce: &SevNonce,
        query: &QueryParams,
    ) -> Result<ParsedAttestation, AttestationError> {
        let url = self.url.join("/attestation/sev").unwrap();

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
    pub async fn request_nvidia(
        &self,
        nonce: &NvidiaNonce,
        query: &QueryParams,
    ) -> Result<NvidiaAttestResult, AttestationError> {
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

        Ok(NvidiaAttestResult {
            eat_token,
            headers: ResponseHeaders(headers),
        })
    }

    /// Requests and parses a TDX quote
    ///
    /// ### Warning
    /// This method exposes core functionality and does not perform cryptographic
    /// or measurement checks on the attestation. If you want to perform end-to-end attestation
    /// please refer to [`Self::attest_tdx`]
    pub async fn request_tdx(
        &self,
        nonce: &TdxNonce,
        query: &QueryParams,
    ) -> Result<TdxQuote, AttestationError> {
        let url = self.url.join("/attestation/tdx").unwrap();

        let response = self
            .reqwest_client
            .get(url)
            .query(&query.0)
            .query(&[("nonce", nonce.to_hex())])
            .send()
            .await?;

        let response = response.error_for_status()?.bytes().await?;
        let quote =
            TdxQuote::from_bytes(&response).context("error while parsing tdx attestation")?;

        Ok(quote)
    }

    /// Performs end-to-end sev-snp attestation. Generates nonce and validates claims all in one
    pub async fn attest_sev(&self, query: Option<QueryParams>) -> Result<(), AttestationError> {
        let nonce = SevNonce::generate();
        let attestation = self.request_sev(&nonce, &query.unwrap_or_default()).await?;
        let keychain = self.kds.fetch_certificates(&attestation).await?;

        attestation.verify(&keychain, &nonce)?;

        let report = attestation.report();
        let claims = WithPolicy::new("sev.allow", report);

        self.policy_validator
            .verify_claim(claims)?
            .or_err("sev claims did not match specified OPA policy")
            .expose_error()?;

        Ok(())
    }

    /// Performs end-to-end tdx attestation. Generates nonce and validates claims all in one
    pub async fn attest_tdx(&self, query: Option<QueryParams>) -> Result<(), AttestationError> {
        let nonce = TdxNonce::generate();

        let quote = self.request_tdx(&nonce, &query.unwrap_or_default()).await?;
        let collateral = self
            .pcs
            .fetch_collateral(&quote)
            .await
            .context("failed fetching collateral from pcs server")
            .expose_error()?;

        let claims = quote.body().clone();

        let verifier = QuoteVerifier::new(collateral, quote);
        verifier
            .verify(&nonce)
            .context("TDX quote verification has failed")
            .expose_error()?;

        let claims = WithPolicy::new("tdx.allow", claims);
        self.policy_validator
            .verify_claim(claims)?
            .or_err("tdx claims did not match specified OPA policy")
            .expose_error()?;

        Ok(())
    }

    /// Completes end-to-end nvidia attestation. Generates nonce and validates claims all in one
    pub async fn attest_nvidia(
        &self,
        query: Option<QueryParams>,
    ) -> Result<ResponseHeaders, AttestationError> {
        let nonce = NvidiaNonce::generate();
        let keychain = KeyChain::fetch_keychain().await?;

        let attest_result = self
            .request_nvidia(&nonce, &query.unwrap_or_default())
            .await?;

        let claims = attest_result.eat_token.verify(&keychain, &nonce)?;
        let claims = WithPolicy::new("nvidia.allow", claims);

        self.policy_validator
            .verify_claim(claims)?
            .or_err("nvidia claims did not match specified OPA policy")
            .expose_error()?;

        Ok(attest_result.headers)
    }

    /// Steps:
    /// - Gathers modules to attest from attestation server
    /// - Iterates through each module and performs end-to-end attestation
    /// - Returns the list of attested modules
    pub async fn attest(
        &self,
        query: Option<QueryParams>,
    ) -> Result<AttestResult, AttestationError> {
        // get modules
        let modules = self
            .request_modules(query.clone())
            .await
            .context("failed to request modules from attestation server")
            .expose_error()?;

        match modules.cpu() {
            CpuModule::Sev => self
                .attest_sev(query.clone())
                .await
                .context("failed to attest sev module")
                .expose_error()?,
            CpuModule::Tdx => self
                .attest_tdx(query.clone())
                .await
                .context("failed to attest tdx module")
                .expose_error()?,
        }

        let gpu_headers = match modules.gpu() {
            None => None,
            Some(GpuModule::Nvidia) => Some(
                self.attest_nvidia(query.clone())
                    .await
                    .context("failed to attest nvidia module")
                    .expose_error()?,
            ),
        };

        Ok(AttestResult {
            modules,
            headers: AttestHeaders {
                cpu: None,
                gpu: gpu_headers,
            },
        })
    }
}

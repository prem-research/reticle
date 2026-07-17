// pub mod client;
#[cfg(target_family = "wasm")]
pub mod fetch;
pub mod gateway;
pub mod query;
pub mod rego;

use std::pin::Pin;

use azure_attest::{AzureQuote, collateral::ReportVerifierBuilder, nonce::AzureNonce};
use futures::future::OptionFuture;
use libattest::{
    CpuModule, GpuModule, Modules, bail,
    error::{AttestationError, Context, Expose},
    quote::QuoteVerifier,
    validation::{Validator, WithPolicy},
};
use nvidia_attest::{EATToken, keychain::KeyChain, nonce::NvidiaNonce};
use snp_attest::{SevQuote, kds::Kds, nonce::SevNonce, verify::SevQuoteVerifier};

pub use nvidia_attest;
use reqwest::{
    Url,
    header::{HeaderMap, HeaderValue},
};
pub use snp_attest;

use tdx_attest::{TdxQuote, nonce::TdxNonce, pcs::Pcs, verify::TdxQuoteVerifier};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    query::QueryParams,
    rego::{PolicyProvider, UrlPolicies},
};

#[cfg(feature = "debug")]
#[cfg(target_family = "wasm")]
#[wasm_bindgen(start)]
pub fn __prem_rs_start() {
    console_error_panic_hook::set_once();
}

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

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct ClientBuilder {
    /// base url for PREM attestation server
    url: String,
    /// intel collateral server
    pcs: Pcs,
    // amd collateral server
    kds: Kds,
    // prem OPA policies url
    policies: Box<dyn PolicyProvider + Send>,

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
            policies: Box::new(UrlPolicies::new(PREM_POLICIES).unwrap()),
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

    pub async fn build(self) -> Result<Client, AttestationError> {
        let reqwest_client = reqwest::Client::builder()
            .default_headers(self.headers)
            .build()?;

        let validator = self
            .policies
            .fetch_validator()
            .await
            .context("failed fetching OPA policies from provider")?;

        Ok(Client {
            url: self
                .url
                .parse::<Url>()
                .context("cannot build client with supplied url because it is invalid")
                .expose_error()?,
            kds: self.kds,
            pcs: self.pcs,
            query_params: QueryParams::new(),
            policy_validator: validator,
            reqwest_client,
        })
    }
}

impl ClientBuilder {
    /// sets custom url for OPA policies index
    // pub fn with_policies_url(mut self, url: &str) -> Self {
    //     self.policies = url.to_string().into();
    //     self
    // }
    pub fn with_policy_provider(mut self, policy: impl PolicyProvider + Send + 'static) -> Self {
        self.policies = Box::new(policy);
        self
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct Client {
    /// base url
    url: Url,
    reqwest_client: reqwest::Client,

    query_params: QueryParams,

    kds: Kds,
    pcs: Pcs,
    policy_validator: Validator,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl Client {
    /// Gather available attestable modules from remote attestation endpoint
    pub async fn request_modules(&self) -> Result<libattest::Modules, AttestationError> {
        let url = self.url.join("/attestation/modules").unwrap();
        let response = self.request(url, &()).await?.json().await?;

        Ok(response)
    }

    /// Requests and parses a SEV-SNP attestation from the attestation server.
    ///
    /// ### Warning
    /// This method exposes core functionality and does not perform cryptographic
    /// or measurement checks on the attestation. If you want to perform end-to-end attestation
    /// please refer to [`Self::attest_sev`]
    pub async fn request_sev(&self, nonce: &SevNonce) -> Result<SevQuote, AttestationError> {
        let url = self.url.join("/attestation/sev").unwrap();

        let query = [("nonce", &nonce.to_hex())];
        let response = self.request(url, &query).await?.bytes().await?;
        let attestation = SevQuote::new(&response)?;

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
    ) -> Result<NvidiaAttestResult, AttestationError> {
        let url = self.url.join("/attestation/nvidia").unwrap();

        let query = [("nonce", &nonce.to_hex())];
        let response = self.request(url, &query).await?;

        let headers = response.headers().clone();
        let response_text = response.text().await?;
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
    pub async fn request_tdx(&self, nonce: &TdxNonce) -> Result<TdxQuote, AttestationError> {
        let url = self.url.join("/attestation/tdx").unwrap();
        let query = [("nonce", &nonce.to_hex())];

        let response = self.request(url, &query).await?.bytes().await?;
        let quote =
            TdxQuote::from_bytes(&response).context("error while parsing tdx attestation")?;

        Ok(quote)
    }

    /// Requests and parses an Azure Quote
    ///
    pub async fn request_azure(&self, nonce: &AzureNonce) -> Result<AzureQuote, AttestationError> {
        let url = self.url.join("/attestation/azure").unwrap();
        let query = [("nonce", &nonce.to_hex())];

        let response: AzureQuote = self.request(url, &query).await?.json().await?;

        Ok(response)
    }

    pub async fn attest_azure(&self) -> Result<(), AttestationError> {
        let nonce = AzureNonce::generate();

        let quote = self.request_azure(&nonce).await?;
        let verifier = ReportVerifierBuilder::default()
            .sev(async |quote| {
                self.kds
                    .fetch_certificates(quote)
                    .await
                    .map(SevQuoteVerifier::new)
            })
            .tdx(async |_| unimplemented!())
            .fetch_collateral(&quote)
            .await?;

        let evidence = quote.verify(verifier, &nonce)?;

        let claims = WithPolicy::new("azure.allow", evidence);

        self.policy_validator
            .verify_claim(claims)?
            .or_err("azure claims did not match specified opa policy")
            .expose_error()?;

        Ok(())
    }

    /// Performs end-to-end sev-snp attestation. Generates nonce and validates claims all in one
    pub async fn attest_sev(&self) -> Result<(), AttestationError> {
        let nonce = SevNonce::generate();
        let attestation = self.request_sev(&nonce).await?;
        let keychain = self.kds.fetch_certificates(&attestation).await?;

        let verifier = SevQuoteVerifier::new(keychain);
        verifier.verify(&attestation, &nonce)?;

        let claims = WithPolicy::new("sev.allow", attestation);

        self.policy_validator
            .verify_claim(&claims)?
            .or_err("sev claims did not match specified OPA policy")
            .expose_error()?;

        Ok(())
    }

    /// Performs end-to-end tdx attestation. Generates nonce and validates claims all in one
    pub async fn attest_tdx(&self) -> Result<(), AttestationError> {
        let nonce = TdxNonce::generate();

        let quote = self.request_tdx(&nonce).await?;
        let collateral = self
            .pcs
            .fetch_collateral(&quote)
            .await
            .context("failed fetching collateral from pcs server")
            .expose_error()?;

        let verifier = TdxQuoteVerifier::new(collateral);
        verifier
            .verify(&quote, &nonce)
            .context("TDX quote verification has failed")
            .expose_error()?;

        let claims = WithPolicy::new("tdx.allow", quote);

        self.policy_validator
            .verify_claim(&claims)?
            .or_err("tdx claims did not match specified OPA policy")
            .expose_error()?;

        Ok(())
    }

    /// Completes end-to-end nvidia attestation. Generates nonce and validates claims all in one
    pub async fn attest_nvidia(&self) -> Result<ResponseHeaders, AttestationError> {
        let nonce = NvidiaNonce::generate();
        let keychain = KeyChain::fetch_keychain().await?;

        let attest_result = self.request_nvidia(&nonce).await?;

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
    pub async fn attest(&self) -> Result<AttestResult, AttestationError> {
        // get modules
        let modules = self
            .request_modules()
            .await
            .context("failed to request modules from attestation server")
            .expose_error()?;

        let cpu_attest: Pin<Box<dyn Future<Output = Result<(), AttestationError>>>> =
            match modules.cpu() {
                CpuModule::Sev => Box::pin(self.attest_sev()),
                CpuModule::Tdx => Box::pin(self.attest_tdx()),
                CpuModule::Azure => Box::pin(self.attest_azure()),
                _ => bail!("we do not yet support the advertised cpu platform"),
            };

        let gpu_attest = match modules.gpu() {
            None => None,
            Some(GpuModule::Nvidia) => Some(self.attest_nvidia()),
            _ => bail!("we do not yet support the advertised gpu platform"),
        };
        let gpu_attest = OptionFuture::from(gpu_attest);

        // join futures for concurrent requests and attestation execution
        let (cpu, gpu) = futures::join!(cpu_attest, gpu_attest);

        // error handling
        let gpu_headers = gpu.transpose()?;
        cpu?;

        Ok(AttestResult {
            modules,
            headers: AttestHeaders {
                cpu: None,
                gpu: gpu_headers,
            },
        })
    }
}

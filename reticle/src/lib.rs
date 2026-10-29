// pub mod client;
#[cfg(target_family = "wasm")]
pub mod fetch;
pub mod gateway;
pub mod measurements;
pub mod query;
pub mod rego;
pub mod sigstore;

use attestation_protocol::{
    bind::Bind,
    modules::{CpuModule, GpuModule, Modules, ModulesBuilder},
    report::{CpuReport, CvmNonce, CvmReport, GpuReport, manifest::PodManifest},
};
use azure_attest::collateral::ReportVerifierBuilder;
use libattest::{
    error::{AttestationError, Context, Expose},
    quote::QuoteVerifier,
    validation::{Validator, Verifiable},
};
use nvidia_attest::{EATToken, keychain::KeyChain, verifier::NvidiaVerifier};
use serde::Serialize;
use snp_attest::{kds::Kds, verify::SevQuoteVerifier};

pub use nvidia_attest;
use reqwest::{
    Url,
    header::{HeaderMap, HeaderValue},
};
pub use snp_attest;

use tdx_attest::{TdxQuote, pcs::Pcs, verify::TdxQuoteVerifier};

use wasm_bindgen::JsValue;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    measurements::{MeasurementsProvider, url::UrlMeasurements},
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

pub struct AttestResult {
    manifest: PodManifest,
    modules: Modules,
    headers: ResponseHeaders,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl AttestResult {
    /// Returns the manifest as serde serialized data. This means that it will
    /// go through JSON representation first. You can expect this to preserve the
    /// same format as the JSON report inside the CVM.
    pub fn pod_report(&self) -> JsValue {
        serde_wasm_bindgen::to_value(&self.manifest)
            .expect("Failed serializing the manifest into a JsValue. This should not ever happen.")
    }

    /// Returns the Modules that the remote party attested.
    pub fn modules(&self) -> Modules {
        self.modules
    }

    /// Returns the response headers returned by the attestation request.
    pub fn headers(&self) -> ResponseHeaders {
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
pub struct AttestResponse {
    report: CvmReport,
    headers: ResponseHeaders,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct ClientBuilder {
    /// base url for PREM attestation server
    url: String,
    /// base url for sigstore repository
    sigstore_url: String,
    /// intel collateral server
    pcs: Pcs,
    // amd collateral server
    kds: Kds,

    /// Provider for Rego policies
    policies: Box<dyn PolicyProvider + Send>,

    /// PodVM measurements golden reference values
    /// to be injected into the regorous engine for
    /// validation
    measurements: Box<dyn MeasurementsProvider + Send>,

    headers: HeaderMap,
    gpu_required: bool,
}

const PREM_PCCS: &str = "https://pccs.prem.io/";
const PREM_KCDS: &str = "https://kcds.prem.io";
const PREM_MEASUREMENTS: &str = "https://trustbase.prem.io";

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl ClientBuilder {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            pcs: Pcs::new(PREM_PCCS).unwrap(),
            kds: Kds::new(PREM_KCDS).unwrap(),
            policies: Box::new(UrlPolicies::new(PREM_MEASUREMENTS).unwrap()),
            measurements: Box::new(UrlMeasurements::new(PREM_MEASUREMENTS).unwrap()),
            headers: HeaderMap::default(),
            gpu_required: false,
            sigstore_url: PREM_MEASUREMENTS.to_string(),
        }
    }

    /// Sets `Authorization` header
    pub fn with_authorization(mut self, token: &str) -> Result<Self, AttestationError> {
        self.headers
            .insert("Authorization", HeaderValue::from_str(token)?);

        Ok(self)
    }

    /// Require verified GPU evidence regardless of the signed Init-Data policy.
    pub fn with_gpu_required(mut self, required: bool) -> Self {
        self.gpu_required = required;
        self
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

    /// sets the confidential policy provider to URL source with the specified url
    pub fn with_policies_url(mut self, url: &str) -> libattest::Result<Self> {
        self.policies = Box::new(UrlPolicies::new(url)?);
        Ok(self)
    }

    /// Sets the Trustbase URL where to look for measurements (golden values)
    pub fn with_measurements_url(self, url: &str) -> libattest::Result<Self> {
        // replace measurements provider
        Ok(Self {
            measurements: Box::new(UrlMeasurements::new(url)?),
            ..self
        })
    }

    pub async fn build(self) -> Result<Client, AttestationError> {
        let reqwest_client = reqwest::Client::builder()
            .default_headers(self.headers)
            .build()?;

        let sigstore = sigstore::fetch_sigstore(self.sigstore_url)
            .await
            .context("failed fetching sigstore verifier")?;

        // fetch the rego policies and output a validator
        // for us to inject the rest of the data
        let validator = self
            .policies
            .fetch_validator(&sigstore)
            .await
            .context("failed fetching OPA policies from provider")?;

        // fetch measurements from trustbase. these are our golden values
        let measurements = self
            .measurements
            .fetch_measurements(&sigstore)
            .await
            .context("failed fetching measurements from provider")?;

        let validator = validator
            .add_meaurements(&measurements)?
            .build()
            .context("failed building the rego engine")?;

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
            gpu_required: self.gpu_required,
            measurements,
        })
    }
}

impl ClientBuilder {
    /// sets custom url for OPA policies index
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
    gpu_required: bool,
    measurements: measurements::Measurements,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl Client {
    /// Request unified `CvmReport` attestation from endpoint
    pub async fn request_attestation(
        &self,
        nonce: &CvmNonce,
    ) -> Result<AttestResponse, AttestationError> {
        let url = self.url.join("/attestation/attest").unwrap();
        let query = [("nonce", &nonce.to_hex())];

        let response = self.request(url, &query).await?;

        let response = AttestResponse {
            headers: ResponseHeaders(response.headers().clone()),
            report: response.json().await?,
        };

        Ok(response)
    }

    fn attest_quote<'a, Q: QuoteVerifier>(
        &self,
        verifier: Q,
        manifest: &PodManifest,
        quote: &'a Q::Quote,
        nonce: &Q::Nonce,
        policy: &'static str,
    ) -> Result<<Q::Quote as Verifiable>::Claims<'a>, AttestationError> {
        let claims = verifier
            .verify(quote, nonce)
            .context("Quote verification has failed")
            .expose_error()?;

        #[derive(Serialize)]
        struct Input<M, C> {
            manifest: M,
            claims: C,
        }

        let input = Input {
            manifest,
            claims: &claims,
        };

        self.policy_validator
            .evaluate(policy, &input)?
            .or_err("quote claims did not match OPA policy")
            .expose_error()?;

        Ok(claims)
    }

    /// Steps:
    /// - Gathers modules to attest from attestation server
    /// - Iterates through each module and performs end-to-end attestation
    /// - Returns the list of attested modules
    pub async fn attest(&self) -> Result<AttestResult, AttestationError> {
        let nonce = CvmNonce::generate();
        let response = self.request_attestation(&nonce).await?;
        let mut modules = ModulesBuilder::new();

        let AttestResponse { report, headers } = response;

        // verify depending on the module
        match &report.cpu {
            CpuReport::Sev(attestation) => {
                let keychain = self.kds.fetch_certificates(attestation).await?;
                let verifier = SevQuoteVerifier::new(keychain);

                // we ""bind"" the nonce to the manifest depending on what
                // size of nonce our downstream module (in this case sev) needs.
                let nonce = report.manifest.bind(&*nonce).into();

                let claims =
                    self.attest_quote(verifier, &report.manifest, attestation, &nonce, "sev.allow")?;
                measurements::initdata::verify_sev_host_data(
                    &self.measurements,
                    &report.manifest,
                    &claims.host_data,
                )?;
                modules = modules.with_cpu(CpuModule::Sev);
            }
            CpuReport::Tdx(items) => {
                let tdx = TdxQuote::from_bytes(items).context("failed parsing tdx quote")?;
                let collateral = self
                    .pcs
                    .fetch_collateral(&tdx)
                    .await
                    .context("failed fetching collateral from pcs server")
                    .expose_error()?;

                let verifier = TdxQuoteVerifier::new(collateral);
                let nonce = report.manifest.bind(&*nonce).into();

                let claims =
                    self.attest_quote(verifier, &report.manifest, &tdx, &nonce, "tdx.allow")?;
                measurements::initdata::verify_tdx_mr_config_id(
                    &self.measurements,
                    &report.manifest,
                    &claims.mrconfigid,
                )?;
                modules = modules.with_cpu(CpuModule::Tdx);
            }
            CpuReport::Azr(azure_quote) => {
                let nonce = report.manifest.bind(&*nonce).into();
                let verifier = ReportVerifierBuilder::default()
                    .sev(async |quote| {
                        self.kds
                            .fetch_certificates(quote)
                            .await
                            .map(SevQuoteVerifier::new)
                    })
                    .tdx(async |_| libattest::bail!("TDX attestation is unimplemented for Azure"))
                    .fetch_collateral(azure_quote)
                    .await?;

                self.attest_quote(
                    verifier,
                    &report.manifest,
                    azure_quote,
                    &nonce,
                    "azure.allow",
                )?;
                modules = modules.with_cpu(CpuModule::Azure);
            }
        }

        if matches!(report.gpu, GpuReport::Absent) && self.gpu_required {
            libattest::bail!(exposed: "GPU evidence is required for this workload");
        }

        let expected_gpus =
            measurements::initdata::expected_gpus(&self.measurements, &report.manifest).await?;

        // attest gpu report
        match report.gpu {
            GpuReport::Absent => {
                if expected_gpus > 0 {
                    libattest::bail!(exposed: "GPU evidence is required for this workload");
                }
            }
            GpuReport::Nvidia(nvidia) => {
                let quote = EATToken::parse(&nvidia).context("failed parsing nvidia EAT token")?;
                let keychain = KeyChain::fetch_keychain().await?;
                let verifier = NvidiaVerifier::new(keychain);

                let nonce = report.cpu.bind(&*nonce).into();
                let claims =
                    self.attest_quote(verifier, &report.manifest, &quote, &nonce, "nvidia.allow")?;
                if claims.gpu_claims().len() != expected_gpus {
                    libattest::bail!(exposed: "attested GPU count does not match the workload Init-Data");
                }
                modules = modules.with_gpu(Some(GpuModule::Nvidia));
            }
        };

        let modules = modules
            .build()
            .context("not enough modules were provided to complete attestation")?;

        Ok(AttestResult {
            manifest: report.manifest,
            modules,
            headers,
        })
    }
}

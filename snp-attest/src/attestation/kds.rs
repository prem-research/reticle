use libattest::error::{AttestationError, Context};
use reqwest::{Client, Url};
use sev::{Generation, firmware::host::TcbVersion};
use x509_cert::certificate::{CertificateInner, Rfc5280};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    ParsedAttestation,
    chain::{CRL, VerifiedChain},
};

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "sev"))]
pub struct Kds {
    kds: Url,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl Kds {
    // pub fn new() -> Self {
    //     Self {
    //         kds: Url::parse("https://kdsintf.amd.com/").unwrap(),
    //     }
    // }

    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn new(cache_url: &str) -> Result<Self, AttestationError> {
        let kds = cache_url.parse()?;
        Ok(Self { kds })
    }

    fn get_base_url(&self, product: Generation) -> Url {
        self.kds
            .join("/vcek/v1/")
            .unwrap()
            .join(&product.titlecase())
            .unwrap()
    }

    async fn get_cert_chain(
        &self,
        generation: Generation,
    ) -> libattest::Result<sev::certs::snp::ca::Chain> {
        let client = Client::new();
        let url = format!("{}/cert_chain", self.get_base_url(generation));
        let req = client.get(&url);
        let resp = req.send().await?.bytes().await?;

        log::debug!("Requesting {url}");

        let cert = CertificateInner::<Rfc5280>::load_pem_chain(&resp)?;
        let Ok([ask, ark]): Result<[CertificateInner; 2], _> = cert.try_into() else {
            return AttestationError::internal("missing ask or ark certificate from kds response");
        };

        Ok(sev::certs::snp::ca::Chain {
            ask: ask.into(),
            ark: ark.into(), // TODO: should be embedded? they're being pulled from https so it might not matter that much
        })
    }

    async fn get_vcek_tcb(
        &self,
        chip_id: &[u8; 64],
        tcb: TcbVersion,
        generation: Generation,
    ) -> libattest::Result<sev::certs::snp::Certificate> {
        let client = Client::new();
        let mut query = vec![
            get_query_tuple("blSPL", tcb.bootloader),
            get_query_tuple("teeSPL", tcb.tee),
            get_query_tuple("snpSPL", tcb.snp),
            get_query_tuple("ucodeSPL", tcb.microcode),
        ];

        if let Some(fmc) = tcb.fmc {
            query.push(get_query_tuple("fmcSPL", fmc));
        }

        let req = client
            .get(format!(
                "{}/{}",
                self.get_base_url(generation),
                encode_hw_id(chip_id, generation)
            ))
            .query(&query);

        let resp = req.send().await?.bytes().await?;
        Ok(sev::certs::snp::Certificate::from_der(&resp).expect("invalid vcek from AMD KDS"))
    }

    async fn get_chain(
        &self,
        chip_id: &[u8; 64],
        tcb: TcbVersion,
        generation: Generation,
    ) -> libattest::Result<sev::certs::snp::Chain> {
        let vcek = self.get_vcek_tcb(chip_id, tcb, generation).await?;
        let cert_chain = self.get_cert_chain(generation).await?;

        Ok(sev::certs::snp::Chain {
            ca: cert_chain,
            vek: vcek,
        })
    }

    pub async fn fetch_certificates(
        &self,
        attestation: &ParsedAttestation,
    ) -> Result<VerifiedChain, AttestationError> {
        log::info!("Fetching the chain from KDS");
        let chain = self
            .get_chain(
                &attestation.report.chip_id,
                attestation.report.reported_tcb,
                attestation.generation,
            )
            .await?;

        log::info!("Cryptographically verifying the fetched chain");
        let chain = VerifiedChain::verify(chain)?;
        Ok(chain)
    }

    /// Fetches the certificate revocation list from AMD's KDS
    pub async fn fetch_crl(
        &self,
        attestation: &ParsedAttestation,
    ) -> Result<CRL, AttestationError> {
        let client = Client::new();
        let req = client.get(format!(
            "{}/crl",
            self.get_base_url(attestation.generation())
        ));

        let resp = req.send().await?.bytes().await?;

        CRL::from_der(&resp)
    }
}

impl Default for Kds {
    fn default() -> Self {
        Self::new("https://kdsintf.amd.com").unwrap()
    }
}

pub fn chipid_from_gen(chip_id: &[u8; 64], generation: Generation) -> &[u8] {
    match generation {
        Generation::Milan | Generation::Genoa => &chip_id[..],
        _ => &chip_id[..8], // newer generations have smaller chip ids truncated to 8 bytes
    }
}

fn encode_hw_id(chip_id: &[u8; 64], generation: Generation) -> String {
    hex::encode(chipid_from_gen(chip_id, generation))
}

pub fn decode_product_name(
    product_name: Vec<u8>,
) -> libattest::Result<(
    std::string::String,
    std::option::Option<std::string::String>,
)> {
    let decoded: Vec<std::string::String> = std::string::String::from_utf8(product_name)?
        .chars()
        .filter(|c| c.is_alphanumeric() || c.eq(&'-'))
        .collect::<std::string::String>()
        .split('-')
        .take(2)
        .map(|e: &str| std::string::String::from(e))
        .collect::<Vec<std::string::String>>();

    match &decoded[..] {
        [decoded] => Ok((decoded.clone(), None)),
        [name, stepping] => Ok((name.clone(), Some(stepping.clone()))),
        _ => AttestationError::internal("unhandled number of parameters"),
    }
}

pub fn get_query_tuple(name: &str, byte: u8) -> (std::string::String, std::string::String) {
    (String::from(name), format!("{:02}", byte))
}

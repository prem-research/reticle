use sev::firmware::host::TcbVersion;
use x509_cert::certificate::{CertificateInner, Rfc5280};

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";
const KDS_CERT_CHAIN: &str = "cert_chain";

#[cfg(feature = "kds_async")]
pub use async_kds::*;
#[cfg(feature = "kds_sync")]
pub use sync_kds::*;

fn get_base_url(product_name: String) -> String {
    return format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/\
        {product_name}"
    );
}

fn encode_hw_id(chip_id: &[u8; 64]) -> String {
    return hex::encode(chip_id);
}

pub fn decode_stepping(
    stepping: std::string::String,
) -> std::option::Option<(std::string::String, std::string::String)> {
    match stepping.chars().nth(0) {
        Some(rev) => Some((rev.to_string(), stepping[1..].to_string())),
        None => None,
    }
}

pub fn decode_product_name(
    product_name: Vec<u8>,
) -> anyhow::Result<(
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

    match decoded.len() {
        1 => Ok((decoded.get(0).unwrap().to_string(), None)),
        _ => {
            let [name, stepping]: [std::string::String; 2] = decoded.try_into().unwrap();
            Ok((name, Some(stepping)))
        }
    }
}

pub fn get_query_tuple(name: &str, byte: u8) -> (std::string::String, std::string::String) {
    return (String::from(name), format!("{:02}", byte));
}

#[cfg(feature = "kds_sync")]
mod sync_kds {
    use super::*;
    use sev::firmware::host::TcbVersion;

    pub fn get_vcek_tcb(
        chip_id: &[u8; 64],
        tcb: TcbVersion,
        product_name: &str,
    ) -> anyhow::Result<sev::certs::snp::Certificate> {
        let client = reqwest::blocking::Client::new();
        let req = client
            .get(format!(
                "{}/{}",
                get_base_url(product_name.to_string()),
                encode_hw_id(chip_id)
            ))
            .query(&[
                get_query_tuple("blSPL", tcb.bootloader),
                get_query_tuple("teeSPL", tcb.tee),
                get_query_tuple("snpSPL", tcb.snp),
                get_query_tuple("ucodeSPL", tcb.microcode),
            ]);

        let resp = req.send()?.bytes()?;
        Ok(sev::certs::snp::Certificate::from_der(&resp).expect("invalid vcek from AMD KDS"))
    }

    pub fn get_cert_chain(product_name: &str) -> anyhow::Result<sev::certs::snp::ca::Chain> {
        let client = reqwest::blocking::Client::new();
        let req = client.get(format!(
            "{}/{}",
            get_base_url(product_name.to_string()),
            KDS_CERT_CHAIN,
        ));
        let resp = req.send()?.bytes()?;

        let cert = CertificateInner::<Rfc5280>::load_pem_chain(&resp)?;

        let ask = cert.get(0).context("missing ask")?.to_pem(LineEnding::LF)?;
        let ark = cert.get(1).context("missing ark")?.to_pem(LineEnding::LF)?;

        Ok(sev::certs::snp::ca::Chain::from_pem(
            ark.as_bytes(),
            ask.as_bytes(),
        )?)
    }

    pub fn get_chain(
        chip_id: &[u8; 64],
        tcb: TcbVersion,
        product_name: &str,
    ) -> anyhow::Result<sev::certs::snp::Chain> {
        let vcek = get_vcek_tcb(&chip_id, tcb, product_name)?;
        let cert_chain = get_cert_chain(product_name)?;
        Ok(sev::certs::snp::Chain {
            ca: cert_chain,
            vek: vcek,
        })
    }

    pub fn get_crl(product_name: &str) -> anyhow::Result<Vec<u8>> {
        let client = reqwest::blocking::Client::new();
        let req = client.get(format!(
            "{}/crl",
            super::get_base_url(product_name.to_string())
        ));
        let resp = req.send()?.bytes()?;

        Ok(resp.into())
    }
}

#[cfg(feature = "kds_async")]
mod async_kds {
    use reqwest::Client;

    use super::*;

    pub async fn get_vcek_tcb(
        chip_id: &[u8; 64],
        tcb: TcbVersion,
        product_name: &str,
    ) -> anyhow::Result<sev::certs::snp::Certificate> {
        let client = Client::new();
        let req = client
            .get(format!(
                "{}/{}",
                get_base_url(product_name.to_string()),
                encode_hw_id(chip_id)
            ))
            .query(&[
                get_query_tuple("blSPL", tcb.bootloader),
                get_query_tuple("teeSPL", tcb.tee),
                get_query_tuple("snpSPL", tcb.snp),
                get_query_tuple("ucodeSPL", tcb.microcode),
            ]);

        let resp = req.send().await?.bytes().await?;
        Ok(sev::certs::snp::Certificate::from_der(&resp).expect("invalid vcek from AMD KDS"))
    }

    pub async fn get_cert_chain(product_name: &str) -> anyhow::Result<sev::certs::snp::ca::Chain> {
        let client = Client::new();
        let url = format!(
            "{}/{}",
            get_base_url(product_name.to_string()),
            KDS_CERT_CHAIN,
        );
        let req = client.get(&url);
        let resp = req.send().await?.bytes().await?;

        log::debug!("Requesting {url}");

        let cert = CertificateInner::<Rfc5280>::load_pem_chain(&resp)?;
        let [ask, ark]: [CertificateInner; 2] = cert
            .try_into()
            .map_err(|_| anyhow::format_err!("missing ask or ark from certificate chain"))?;

        Ok(sev::certs::snp::ca::Chain {
            ask: ask.into(),
            ark: ark.into(),
        })
    }

    pub async fn get_chain(
        chip_id: &[u8; 64],
        tcb: TcbVersion,
        product_name: &str,
    ) -> anyhow::Result<sev::certs::snp::Chain> {
        let vcek = get_vcek_tcb(&chip_id, tcb, product_name).await?;
        let cert_chain = get_cert_chain(product_name).await?;
        Ok(sev::certs::snp::Chain {
            ca: cert_chain,
            vek: vcek,
        })
    }

    pub async fn get_crl(product_name: &str) -> Result<Vec<u8>, reqwest::Error> {
        let client = Client::new();
        let req = client.get(format!(
            "{}/crl",
            super::get_base_url(product_name.to_string())
        ));
        let resp = req.send().await?.bytes().await?;

        Ok(resp.into())
    }
}

// #[cfg(feature = "")]
pub mod crl {
    use x509_parser::prelude::*;

    pub fn is_revoked(ask: &X509Certificate, crl: &CertificateRevocationList) -> bool {
        let ask_serial = &ask.serial;

        crl.iter_revoked_certificates()
            .find(|a| a.serial() == ask_serial)
            .is_some()
    }

    pub fn verify(ark: &X509Certificate, crl: &CertificateRevocationList) -> anyhow::Result<bool> {
        let public_key = ark.public_key();

        Ok(crl.verify_signature(public_key).is_ok())
    }
}

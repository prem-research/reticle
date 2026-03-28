use sev::firmware::host::TcbVersion;
use x509_cert::certificate::{CertificateInner, Rfc5280};

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";
const KDS_CERT_CHAIN: &str = "cert_chain";

fn get_base_url(product_name: String) -> String {
    format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/\
        {product_name}"
    )
}

fn encode_hw_id(chip_id: &[u8; 64]) -> String {
    hex::encode(chip_id)
}

// pub fn decode_stepping(
//     stepping: std::string::String,
// ) -> std::option::Option<(std::string::String, std::string::String)> {
//     stepping
//         .chars()
//         .next()
//         .map(|rev| (rev.to_string(), stepping[1..].to_string()))
// }

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
        1 => Ok((decoded.first().unwrap().to_string(), None)),
        _ => {
            let [name, stepping]: [std::string::String; 2] = decoded.try_into().unwrap();
            Ok((name, Some(stepping)))
        }
    }
}

pub fn get_query_tuple(name: &str, byte: u8) -> (std::string::String, std::string::String) {
    (String::from(name), format!("{:02}", byte))
}

use reqwest::Client;

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
        ark: ark.into(), // TODO: should be embedded? they're being pulled from https so it might not matter that much
    })
}

pub async fn get_chain(
    chip_id: &[u8; 64],
    tcb: TcbVersion,
    product_name: &str,
) -> anyhow::Result<sev::certs::snp::Chain> {
    let vcek = get_vcek_tcb(chip_id, tcb, product_name).await?;
    let cert_chain = get_cert_chain(product_name).await?;
    Ok(sev::certs::snp::Chain {
        ca: cert_chain,
        vek: vcek,
    })
}

pub async fn get_crl(product_name: &str) -> Result<Vec<u8>, reqwest::Error> {
    let client = Client::new();
    let req = client.get(format!("{}/crl", get_base_url(product_name.to_string())));
    let resp = req.send().await?.bytes().await?;

    Ok(resp.into())
}

// // #[cfg(feature = "")]
// pub mod crl {
//     use x509_parser::prelude::*;

//     pub fn is_revoked(ask: &X509Certificate, crl: &CertificateRevocationList) -> bool {
//         let ask_serial = &ask.serial;

//         crl.iter_revoked_certificates()
//             .any(|a| a.serial() == ask_serial)
//     }

//     pub fn verify(ark: &X509Certificate, crl: &CertificateRevocationList) -> anyhow::Result<bool> {
//         let public_key = ark.public_key();

//         Ok(crl.verify_signature(public_key).is_ok())
//     }
// }

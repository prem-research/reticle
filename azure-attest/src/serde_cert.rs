use serde::{Deserialize, Deserializer, Serializer};
use x509_cert::der::{DecodePem, EncodePem};

pub fn serialize<S>(certificate: &x509_cert::Certificate, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let serialized = certificate
        .to_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(<S::Error as serde::ser::Error>::custom)?;

    serializer.serialize_str(&serialized)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<x509_cert::Certificate, D::Error>
where
    D: Deserializer<'de>,
{
    let pem = String::deserialize(deserializer)?;

    let certificate =
        x509_cert::Certificate::from_pem(pem).map_err(<D::Error as serde::de::Error>::custom)?;

    Ok(certificate)
}

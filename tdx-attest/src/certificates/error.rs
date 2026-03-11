use thiserror::Error;
use x509_cert::serial_number::SerialNumber;

#[derive(Debug, Error)]
pub enum CertificateError {
    #[error("tried parsing a certificate with an unsupported algorithm: {0}")]
    WrongAlgorithm(spki::Error),

    #[error("a signature or key was serialized in the wrong format in the certificate")]
    WrongFormat,

    #[error("the format for the certificate chain is wrong")]
    BadChain,

    #[error("error while verifying the signature of one or more certificates: {0}")]
    BadSignature(p256::ecdsa::Error),

    #[error("this cryptographic entity is expired")]
    Expired,

    #[error("certificate extension is malformed")]
    Extension,

    #[error("an error occurred while parsing the certificate: {0}")]
    Der(#[from] der::Error),

    #[error("a certificate (serial_number = {serial_number}) has been revoked")]
    Revoked { serial_number: SerialNumber },
}

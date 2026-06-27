use std::sync::LazyLock;

use der::Decode;
use libattest::crypto::algorithms::{CertFormat, ecdsa::EcdsaCert};
use x509_cert::Certificate;

static INTEL_CA_DER: &[u8; 659] = include_bytes!("./IntelCA.der");

pub static INTEL_CA: LazyLock<EcdsaCert> = LazyLock::new(|| {
    EcdsaCert::from_certificate(Certificate::from_der(INTEL_CA_DER).unwrap()).unwrap()
});

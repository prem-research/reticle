use std::sync::LazyLock;

use libattest::certificates::format::{CertFormat, rsa::RsaCert};
use x509_cert::{Certificate, der::DecodePem};

static AZURE_CA_PEM: &[u8] = include_bytes!("./Azure.crt");

pub static AZURE_CA: LazyLock<RsaCert> = LazyLock::new(|| {
    RsaCert::from_certificate(Certificate::from_pem(AZURE_CA_PEM).unwrap()).unwrap()
});

#[cfg(test)]
mod test {
    use libattest::certificates::format::{CertFormat, rsa::RsaCert};

    use crate::ca::AZURE_CA;

    #[test]
    fn read_parse_ca() {
        let ca: &RsaCert = &AZURE_CA;
        ca.cetificate();
    }
}

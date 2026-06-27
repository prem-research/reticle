use std::sync::LazyLock;

use libattest::{
    crypto::algorithms::{CertFormat, rsa::RsaCert},
    error::Context,
};
use x509_cert::{
    der::DecodePem,
    ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier},
};

pub struct IntermediateDb {
    certs: Vec<(SubjectKeyIdentifier, RsaCert)>,
}

impl IntermediateDb {
    fn new() -> Self {
        Self { certs: vec![] }
    }

    fn add_pem(mut self, pem: &str) -> Self {
        let cert = x509_cert::Certificate::from_pem(pem).unwrap();
        let cert = RsaCert::from_certificate(cert).unwrap();

        let (_, ski) = cert
            .certificate()
            .get_extension::<SubjectKeyIdentifier>()
            .unwrap()
            .expect("missing intermediate SKI from intermediate certificate");

        self.certs.push((ski, cert));
        self
    }

    pub fn find_intermediate(&self, leaf: &RsaCert) -> libattest::Result<&RsaCert> {
        let (_, leaf_issuer_id) = leaf
            .certificate()
            .get_extension::<AuthorityKeyIdentifier>()?
            .context("AuthorityKeyIdentifier extension not found in leaf certificate")?;

        let leaf_issuer_id = leaf_issuer_id
            .key_identifier
            .context("missing key identifier from leaf certificate")?;

        let (_, cert) = self
            .certs
            .iter()
            .find(|(ski, _)| ski.0 == leaf_issuer_id)
            .context("couldn't find appropriate intermediate certificate")?;

        Ok(cert)
    }
}

static INTERMEDIATE_DB: LazyLock<IntermediateDb> = LazyLock::new(|| {
    IntermediateDb::new()
        // .add_pem(include_str!("./ICA01.crt"))
        .add_pem(include_str!("./ICA03.crt"))
});

pub fn intermediate_db() -> &'static IntermediateDb {
    &INTERMEDIATE_DB
}

#[cfg(test)]
mod test {
    use crate::ca::intermediate_db;

    #[test]
    fn parse_intermediate_cas() {
        let db = intermediate_db();
    }
}

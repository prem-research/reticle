use std::time::SystemTime;

use der::oid::db::rfc5912::ECDSA_WITH_SHA_256;
use der::{Decode, Encode};
use p256::ecdsa::Signature;
use signature::Verifier;
use x509_cert::der::DecodePem;
use x509_cert::time::Time;
use x509_cert::{certificate::Rfc5280, crl::CertificateList};

use crate::certificates::{CertificateChain, CertificateError, EcdsaCert};

mod sealed {
    pub trait Sealed {}
}

pub struct Crl {
    list: CertificateList,

    signature: Signature,
}

impl sealed::Sealed for Crl {}

impl Crl {
    pub fn from_pem(
        verifier: impl Verifier<Signature>,
        pem: impl AsRef<[u8]>,
    ) -> Result<Self, CertificateError> {
        let list = CertificateList::from_pem(pem)?;
        Self::from_certificate_list(verifier, list)
    }
    pub fn from_der(
        verifier: impl Verifier<Signature>,
        der: impl AsRef<[u8]>,
    ) -> Result<Self, CertificateError> {
        let list = CertificateList::from_der(der.as_ref())?;
        Self::from_certificate_list(verifier, list)
    }

    pub fn from_certificate_list(
        verifier: impl Verifier<Signature>,
        list: CertificateList,
    ) -> Result<Self, CertificateError> {
        // let list: CertificateList<Rfc5280> = CertificateList::from_pem(pem)?;

        // verify validity of crl
        let expired = list
            .tbs_cert_list
            .next_update
            .is_some_and(|a| a.to_system_time() < SystemTime::now());

        if expired {
            return Err(CertificateError::Expired);
        }

        // signature is over der bytes
        let tbs_list = list.tbs_cert_list.to_der()?;

        // verify correct format of signature
        list.signature_algorithm
            .assert_algorithm_oid(ECDSA_WITH_SHA_256)
            .map_err(CertificateError::WrongAlgorithm)?;

        // re-interpret the signature as NistP256
        let signature = list
            .signature
            .as_bytes()
            .ok_or(CertificateError::WrongFormat)?;

        let signature =
            Signature::from_der(signature).expect("could not re-decode an encoded signature");

        // verify the signature of the certificate chain
        verifier
            .verify(&tbs_list, &signature)
            .map_err(CertificateError::BadSignature)?;

        // ok!
        Ok(Self { list, signature })
    }
}

pub trait VerifyCrl<Tbs>: sealed::Sealed {
    fn check_revoked(&self, tbs: &Tbs) -> Result<(), CertificateError>;
}

impl VerifyCrl<CertificateChain> for Crl {
    fn check_revoked(&self, tbs: &CertificateChain) -> Result<(), CertificateError> {
        tbs.chain
            .iter()
            .try_for_each(|cert| self.check_revoked(cert))
    }
}

impl VerifyCrl<EcdsaCert> for Crl {
    fn check_revoked(&self, tbs: &EcdsaCert) -> Result<(), CertificateError> {
        let certificates = self
            .list
            .tbs_cert_list
            .revoked_certificates
            .iter()
            .flatten();

        // if this serial number is found in the list, the certificate has been revoked
        let serial_number = tbs.certificate.tbs_certificate().serial_number().clone();

        let found = certificates
            .map(|cert| &cert.serial_number)
            .find(|&serial| serial == &serial_number);

        match found {
            Some(_) => Err(CertificateError::Revoked { serial_number }),
            None => Ok(()),
        }
    }
}

// #[cfg(test)]
// mod test {
//     use der::DecodePem;
//     use x509_cert::certificate::CertificateInner;

//     use crate::certificates::{
//         EcdsaCert,
//         crl::{Crl, VerifyCrl},
//     };

//     const FAKE_CA: &str = include_str!("./test/ca_cert.pem");
//     const FAKE_CERTIFICATE: &str = include_str!("./test/revoked_cert.pem");
//     const FAKE_CRL: &str = include_str!("./test/ca_crl.pem");

//     #[test]
//     fn test_revoked() {
//         let fake_ca = EcdsaCert::from_cert(CertificateInner::from_pem(FAKE_CA).unwrap()).unwrap();
//         let fake_revoked =
//             EcdsaCert::from_cert(CertificateInner::from_pem(FAKE_CERTIFICATE).unwrap()).unwrap();

//         let crl = Crl::from_pem(fake_ca, FAKE_CRL).unwrap();
//         crl.check_revoked(&fake_revoked).unwrap_err();
//     }
// }

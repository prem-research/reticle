pub mod ca;
pub mod extensions;

use std::fmt::Display;
use std::time::SystemTime;

use der::{
    Encode,
    oid::db::rfc5912::{ECDSA_WITH_SHA_256, ID_EC_PUBLIC_KEY},
};
use p256::{
    PublicKey,
    ecdsa::{DerSignature, Signature, VerifyingKey, signature::Verifier},
};
use spki::{DecodePublicKey, ObjectIdentifier};
use thiserror::Error;
use x509_cert::{
    Certificate, anchor::CertPolicies, certificate::TbsCertificateInner, crl::TbsCertList,
    serial_number::SerialNumber,
};

#[derive(Debug)]
pub enum IntermediateCa {
    Platform,
    Processor,
}

impl IntermediateCa {
    pub fn as_str(&self) -> &'static str {
        match self {
            IntermediateCa::Platform => "platform",
            IntermediateCa::Processor => "processor",
        }
    }
}

// pub type CertificateL

use std::str::FromStr;

use der::Decode;
use hex::ToHex;
use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub type SVNs = [u8; 16];

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
pub struct Fmspc(#[serde(with = "hex::serde")] pub [u8; 6]);

impl From<[u8; 6]> for Fmspc {
    fn from(value: [u8; 6]) -> Self {
        Self(value)
    }
}

impl Fmspc {
    pub fn hex(&self) -> String {
        self.0.encode_hex()
    }
}

impl ToString for Fmspc {
    fn to_string(&self) -> String {
        self.hex()
    }
}

#[repr(C, packed)]
#[derive(FromBytes, KnownLayout, IntoBytes, Immutable, Unaligned, Debug, Clone)]
pub struct TdxQuoteHeader {
    pub version: u16,
    pub attestation_type: u16,
    pub tee_type: u32,

    pub reserved: [u8; 4],

    pub qe_vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

pub type Sha384 = [u8; 48];

pub type ReportData = [u8; 64];

#[repr(C, packed)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned, Debug, IntoBytes, Clone)]
pub struct TdxQuoteBody {
    pub tee_tcb_svn: SVNs,
    pub mrseam: Sha384,
    pub mrsignerseam: Sha384,
    pub seamsttributes: [u8; 8],
    pub tdattributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mrtd: Sha384,
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    pub rtmr: [Sha384; 4],
    pub report_data: ReportData,
}

#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, IntoBytes)]
pub struct EnclaveReport {
    pub cpu_svn: SVNs,
    pub miscselect: [u8; 4],
    pub reserved: [u8; 28],
    pub attributes: [u8; 16],
    pub mrenclave: [u8; 32],
    pub _1_reserved: [u8; 32],
    pub mrsigner: [u8; 32],
    pub _2_reserved: [u8; 96],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub _3_reserved: [u8; 60],
    pub report_data: [u8; 64],
}

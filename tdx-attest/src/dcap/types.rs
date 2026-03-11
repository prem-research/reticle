use der::Decode;
use hex::ToHex;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

#[repr(transparent)]
#[derive(FromBytes, KnownLayout, Clone, Copy, Immutable, Unaligned, Debug)]
pub struct SVN([u8; 16]);

#[derive(Debug, Clone, Copy)]
pub struct Fmspc(pub [u8; 6]);

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
#[derive(FromBytes, KnownLayout, Immutable, Unaligned, Debug, Clone)]
pub struct QuoteHeader {
    pub version: u16,
    pub attestation_type: u16,
    pub tee_type: u32,

    pub reserved: [u8; 4],

    pub qe_vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

pub type Sha384 = [u8; 48];

#[repr(C, packed)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned, Debug, Clone)]
pub struct QuoteBody {
    pub tee_tcb_svn: SVN,
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
    pub report_data: [u8; 64],
}

#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone)]
pub struct EnclaveReport {
    pub cpu_svn: SVN,
    pub miscselect: u32,
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

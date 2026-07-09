use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

#[cfg(feature = "host")]
use sha2::Digest;
use sha2::digest;
#[cfg(feature = "host")]
use tss_esapi::abstraction::pcr::PcrBank;
#[cfg(feature = "host")]
use tss_esapi::structures::PcrSlot;

#[derive(Serialize, Deserialize, Debug)]
pub struct Pcr {
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
}

impl Pcr {
    pub fn new(digest: impl Into<Vec<u8>>) -> Self {
        Self {
            digest: digest.into(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PcrBankReading<D: digest::Digest> {
    pcr_list: BTreeMap<u32, Pcr>,
    _digest: PhantomData<D>,
}

impl<D: digest::Digest> PcrBankReading<D> {
    pub fn pcr_digest(&self) -> digest::Output<D> {
        // Hash( PCR[0] | PCR[1] | ... ) <- concatenated
        let data: Vec<u8> = self
            .pcr_list
            .values()
            .flat_map(|pcr| pcr.digest.deref())
            .copied()
            .collect();

        D::digest(data)
    }
}

#[cfg(feature = "host")]
impl<D: digest::Digest> From<&PcrBank> for PcrBankReading<D> {
    fn from(value: &PcrBank) -> Self {
        let pcr_list = value
            .into_iter()
            .map(|(slot, digest)| (pcr_slot_to_number(*slot), digest.to_vec()))
            .map(|(slot, digest)| (slot, Pcr::new(digest)))
            .collect();

        PcrBankReading {
            pcr_list,
            _digest: PhantomData::default(),
        }
    }
}

#[cfg(feature = "host")]
fn pcr_slot_to_number(slot: PcrSlot) -> u32 {
    let slot: u32 = slot.into();
    slot.ilog2()
}

use chrono::Utc;
use serde::Deserialize;

use crate::pcs::tcb::{TcbLevel, TcbStatus};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub tcb_evaluation_data_number: u32,
    #[serde(with = "hex::serde")]
    pub miscselect: [u8; 4],
    #[serde(with = "hex::serde")]
    pub miscselect_mask: [u8; 4],
    #[serde(with = "hex::serde")]
    pub attributes: [u8; 16],
    #[serde(with = "hex::serde")]
    pub attributes_mask: [u8; 16],
    #[serde(with = "hex::serde")]
    pub mrsigner: [u8; 32],
    pub isvprodid: u16,
    pub tcb_levels: Vec<QeTcbLevel>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
#[must_use]
pub struct QeTcbLevel {
    pub tcb: QeTcb,
    pub tcb_date: chrono::DateTime<Utc>,
    pub tcb_status: TcbStatus,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QeTcb {
    pub isvsvn: u16,
}

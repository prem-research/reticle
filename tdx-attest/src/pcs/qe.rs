use serde::{Deserialize, Serialize};

use crate::pcs::tcb::TcbLevel;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub tcb_evaluation_data_number: u32,
    pub miscselect: String,
    pub miscselect_mask: String,
    pub attributes: String,
    pub attributes_mask: String,
    pub mrsigner: String,
    pub isvprodid: u16,
    pub tcb_levels: Vec<QeTcbLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QeTcbLevel {
    pub tcb: QeTcb,
    pub tcb_date: String,
    pub tcb_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QeTcb {
    pub isvsvn: u16,
}

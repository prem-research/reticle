use serde::{Deserialize, Serialize};

use crate::bind::sealed::Bindable;

#[derive(Copy, Clone, Serialize, Deserialize, Debug)]
pub enum SevGen {
    Naples,
    Rome,
    Milan,
    Genoa,
    Turin,
    Venice,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub enum Tee {
    Tdx,
    Sev(SevGen),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PodReport {
    pub podvm_version: String,
    pub workload_id: String,
    pub tee_type: Tee,
}

impl Bindable for PodReport {}

use serde::{Deserialize, Serialize};

use crate::bind::sealed::Bindable;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InitData {
    pub gpus: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PodManifest {
    pub podvm_version: String,
    pub init_data: InitData,
    pub workload_id: String,
}

impl Bindable for PodManifest {}

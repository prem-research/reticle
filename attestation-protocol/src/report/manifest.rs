use serde::{Deserialize, Serialize};

use crate::{bind::sealed::Bindable, initdata::InitDataDocument};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PodManifest {
    pub podvm_version: String,
    pub init_data_document: InitDataDocument,
    pub workload_id: String,
}

impl Bindable for PodManifest {}

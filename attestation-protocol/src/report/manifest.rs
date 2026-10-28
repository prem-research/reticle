use serde::{Deserialize, Serialize};

use crate::bind::sealed::Bindable;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PodManifest {
    pub podvm_version: String,
    pub workload_id: String,
}

impl Bindable for PodManifest {}

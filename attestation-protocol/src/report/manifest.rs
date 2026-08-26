use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bind::sealed::Bindable;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub status: Status,
    pub generated_at: String,
    pub manifest: String,
    pub claims: BTreeMap<String, Claim>,
}

impl Bindable for Manifest {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Claim {
    #[serde(rename = "dm-verity")]
    DmVerity(DmVerityClaim),
    #[serde(rename = "container_image_hash")]
    ContainerImageHash(ContainerImageHashClaim),
    #[serde(rename = "file_sha256")]
    FileSha256(FileSha256Claim),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmVerityClaim {
    pub status: Status,
    pub device: String,
    pub mapper: String,
    pub root_hash: String,
    pub data_device: String,
    pub hash_device: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerImageHashClaim {
    pub status: Status,
    pub container: String,
    pub configured: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub config_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSha256Claim {
    pub status: Status,
    pub path: String,
    pub sha256: String,
}

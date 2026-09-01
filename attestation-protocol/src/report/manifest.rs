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

#[cfg(test)]
mod tests {
    use super::Manifest;

    #[test]
    fn json_round_trip_preserves_manifest_layout() {
        const JSON: &str = r#"
        {
            "version": 1,
            "status": "ok",
            "generated_at": "2026-09-01T12:00:00Z",
            "manifest": "production",
            "claims": {
                "rootfs": {
                    "type": "dm-verity",
                    "status": "ok",
                    "device": "/dev/dm-0",
                    "mapper": "rootfs",
                    "root_hash": "0123456789abcdef",
                    "data_device": "/dev/vda2",
                    "hash_device": "/dev/vda3"
                },
                "container": {
                    "type": "container_image_hash",
                    "status": "error",
                    "container": "api",
                    "configured": "registry.example.com/api:latest",
                    "ref": "registry.example.com/api@sha256:abcdef",
                    "config_sha256": "abcdef"
                },
                "configuration": {
                    "type": "file_sha256",
                    "status": "ok",
                    "path": "/etc/example/config.toml",
                    "sha256": "fedcba9876543210"
                }
            }
        }
        "#;

        let expected_layout: serde_json::Value = serde_json::from_str(JSON).unwrap();
        let manifest: Manifest = serde_json::from_str(JSON).unwrap();

        let serialized_layout = serde_json::to_value(&manifest).unwrap();
        assert_eq!(serialized_layout, expected_layout);

        let deserialized: Manifest = serde_json::from_value(serialized_layout).unwrap();
        assert_eq!(deserialized, manifest);
    }
}

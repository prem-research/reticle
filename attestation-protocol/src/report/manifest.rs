use std::collections::BTreeMap;

use digest::Update;
use libattest::ByteNonce;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub status: Status,
    pub generated_at: String,
    pub manifest: String,
    pub claims: BTreeMap<String, Claim>,
}

impl Manifest {
    /// Binds the manifest to a nonce, producing a nonce that can be used as input
    /// for other cryptographical components to create a trust chian.
    ///
    /// Panics if N is larger than 64
    pub fn bind<const N: usize>(&self, to: impl AsRef<[u8]>) -> libattest::ByteNonce<N> {
        let manifest = postcard::to_allocvec(self).unwrap();
        let digest = Sha512::new().chain(to).chain_update(manifest).finalize();

        if digest.len() < N {
            panic!("Requested digest binding of size {N} is not computable (Max size 64 bytes)");
        }

        let digest: &[u8; N] = digest.as_slice()[..N].try_into().unwrap();

        ByteNonce::from(digest)
    }
}

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

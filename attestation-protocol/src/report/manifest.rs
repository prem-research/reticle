use serde::{Deserialize, Serialize};

use crate::bind::sealed::Bindable;

// wrapper module to transport the ohttp key into
// base64 format over the wire for http requests / json payloads
mod ohttp_key {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_with::base64::Base64;
    use serde_with::serde_as;

    #[serde_as]
    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    struct WithHex(#[serde_as(as = "Base64")] Vec<u8>);

    pub fn serialize<S>(key: &ohttp::KeyConfig, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WithHex(key.encode().unwrap()).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ohttp::KeyConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        let deserialized = WithHex::deserialize(deserializer)?;
        let key = ohttp::KeyConfig::decode(&deserialized.0)
            .map_err(<D::Error as serde::de::Error>::custom)?;

        Ok(key)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PodManifest {
    pub podvm_version: String,
    pub workload_id: String,
    #[serde(with = "ohttp_key")]
    pub ohttp_key_config: ohttp::KeyConfig,
}

impl Bindable for PodManifest {}

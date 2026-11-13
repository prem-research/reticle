use std::{collections::BTreeMap, str::FromStr};

use serde::Deserialize;

/// Kata Init-Data shared by the attestation server and verifier.
#[derive(Deserialize)]
pub struct InitDataDocument {
    pub algorithm: String,
    pub version: String,
    pub data: BTreeMap<String, String>,
}

impl FromStr for InitDataDocument {
    type Err = toml::de::Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        toml::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::InitDataDocument;

    #[test]
    fn parses_shared_init_data_format() {
        let text = r#"version = "0.1.0"
algorithm = "sha384"

[data]
id = "gpu-workload"
"policy.rego" = '''package agent_policy
policy_data := {"containers": []}
'''
"#;
        let document: InitDataDocument = text.parse().unwrap();
        assert_eq!(document.data["id"], "gpu-workload");
        assert!(document.data["policy.rego"].contains("policy_data := "));
    }
}

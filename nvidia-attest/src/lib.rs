pub mod keychain;
pub mod nonce;
pub mod types;
pub mod verifier;

use std::{collections::HashMap, ops::Deref};

use libattest::{
    bail,
    error::{AttestationError, Context},
    validation::Verifiable,
};
use serde::Serialize;
use serde_json::Value;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::types::{GpuClaims, OverallClaims};

#[derive(Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Serialize)]
pub struct DecodedClaims {
    overall_claims: OverallClaims,
    gpu_claims: HashMap<String, GpuClaims>,
}

impl Verifiable for EATToken {
    type Claims<'a>
        = DecodedClaims
    where
        Self: 'a;

    // fn claims<'a>(&'a self) -> Self::Claims<'a> {
    //     self
    // }
}

impl DecodedClaims {
    pub fn overall_claims(&self) -> &OverallClaims {
        &self.overall_claims
    }

    pub fn gpu_claims(&self) -> &HashMap<String, GpuClaims> {
        &self.gpu_claims
    }
}

#[derive(PartialEq, Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct EATToken {
    overall: String,
    gpu: HashMap<String, String>,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl EATToken {
    pub fn parse(from: &str) -> Result<Self, AttestationError> {
        let [overall, gpu]: [serde_json::Value; 2] = serde_json::from_str(from)?;

        let overall = match overall.as_array().map(|val| val.deref()) {
            Some([_, Value::String(overall)]) => overall.clone(),
            _ => bail!("wrong overall attestation format"),
        };

        let gpu: HashMap<String, String> = gpu
            .as_object()
            .context("gpu claims are wrongly formatted")?
            .iter()
            .map(element_as_string)
            .collect::<Option<_>>()
            .context("gpu claims should be jwt strings")?;

        Ok(Self { overall, gpu })
    }
}

fn element_as_string((key, value): (&String, &Value)) -> Option<(String, String)> {
    match value {
        Value::String(value) => Some((key.to_string(), value.clone())),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::EATToken;

    #[test]
    fn parse() {
        const EAT_EXAMPLE: &str = r#"[["JWT", "test"], {"key": "value"}]"#;
        let parse = super::EATToken::parse(EAT_EXAMPLE).expect("failed parsing");

        let expected = EATToken {
            overall: "test".to_string(),
            gpu: HashMap::from([("key".to_string(), "value".to_string())]),
        };

        assert_eq!(parse, expected)
    }
}

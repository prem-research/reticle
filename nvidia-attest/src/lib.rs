pub mod keychain;
pub mod nonce;
pub mod types;
pub mod verifiers;

use std::{collections::HashMap, ops::Deref};

use jsonwebtoken::{DecodingKey, Validation};
use libattest::{
    AddRule, VerificationBuilder, bail,
    error::{AttestationError, Context, Expose},
    verification_new::AssignedPolicy,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    keychain::KeyChain,
    nonce::NvidiaNonce,
    types::{GpuClaims, OverallClaims},
};

#[derive(Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "nvidia"))]
#[derive(Serialize)]
pub struct DecodedClaims {
    overall_claims: OverallClaims,
    gpu_claims: HashMap<String, GpuClaims>,
}

impl AssignedPolicy for DecodedClaims {
    fn policy(&self) -> std::borrow::Cow<'static, str> {
        "nvidia.allow".into()
    }
}

#[derive(PartialEq, Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "nvidia"))]
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

    pub fn verify(
        self,
        keys: &KeyChain,
        nonce: &NvidiaNonce,
    ) -> Result<DecodedClaims, AttestationError> {
        // decoding the header beforehand is necessary to gain the kid
        let jwt_header = jsonwebtoken::decode_header(&self.overall)?;

        let key = jwt_header
            .kid
            .context("missing field kid from jwt headers")
            .and_then(|kid| keys.find(&kid).context("missing key from jwks"))?;

        let key = DecodingKey::from_jwk(key)?;

        // setup validation requirements (just expiration and algorithm for now)
        let mut validation = Validation::new(jwt_header.alg);
        validation.set_required_spec_claims(&["exp"]); // validate expiration (internal jwt stuff should work right)

        // decode and verify overall claims with the correct key
        let overall_claims =
            jsonwebtoken::decode::<OverallClaims>(&self.overall, &key, &validation)?.claims;

        // hashes from calculated from the JWTs of the detached claims
        let gpu_hashes: HashMap<&str, _> = self
            .gpu
            .iter()
            .map(|(k, v)| (k.as_ref(), Sha256::digest(v)))
            .collect();

        // do hashed jwts match with overall claims?
        for (gpu, digest) in &overall_claims.submods {
            let hash = gpu_hashes.get(gpu.deref()).context(
                "overall jwt claims require a submodule that was not found in the detached claims",
            ).expose_error()?;

            if hash.deref() != digest.digest() {
                return AttestationError::exposed(
                    "digest mismatch between submodule claims and detached submodules",
                );
            }
        }

        let mut gpu_claims = HashMap::new();

        for (gpu, gpu_jwt) in self.gpu {
            let header = jsonwebtoken::decode_header(&gpu_jwt)?;
            let key = header
                .kid
                .context("missing field kid from jwt headers")
                .and_then(|kid| keys.find(&kid).context("jwk server does not have our key"))?;

            let key = DecodingKey::from_jwk(key)?;

            let decoded =
                jsonwebtoken::decode::<GpuClaims>(&gpu_jwt, &key, &Validation::new(header.alg))
                    .context("gpu module signature error")?;

            gpu_claims.insert(gpu, decoded.claims);
        }

        // nonce checking
        if overall_claims.eat_nonce != nonce.as_ref() {
            bail!(exposed: "mismatched nvidia nonce");
        }

        if !gpu_claims
            .iter()
            .all(|(_, claim)| claim.eat_nonce == nonce.as_ref())
        {
            bail!(exposed: "mismatched nvidia nonce in one or more gpu modules");
        }

        Ok(DecodedClaims {
            overall_claims,
            gpu_claims,
        })
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

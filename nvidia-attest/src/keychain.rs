use std::{cell::LazyCell, ops::Deref};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use jsonwebtoken::jwk;
use reqwest::Url;

use crate::error::GpuAttestationError;

const NVIDIA_NRAS: LazyCell<Url> =
    LazyCell::new(|| Url::parse("https://nras.attestation.nvidia.com").unwrap());

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "nvidia"))]
pub struct KeyChain(jwk::JwkSet);

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "nvidia"))]
pub async fn fetch_keychain() -> Result<KeyChain, GpuAttestationError> {
    let well_known = reqwest::get(NVIDIA_NRAS.join(".well-known/jwks.json").unwrap()).await?;
    let jwk_set: jwk::JwkSet = well_known.json().await?;

    Ok(KeyChain(jwk_set))
}

impl Deref for KeyChain {
    type Target = jwk::JwkSet;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

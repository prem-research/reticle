use std::{ops::Deref, sync::LazyLock, time::Duration};

use libattest::error::AttestationError;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use jsonwebtoken::jwk;
use reqwest::Url;

static NVIDIA_NRAS: LazyLock<Url> =
    LazyLock::new(|| Url::parse("https://nras.attestation.nvidia.com").unwrap());

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct KeyChain(jwk::JwkSet);

impl KeyChain {
    pub async fn fetch_keychain() -> Result<KeyChain, AttestationError> {
        Self::fetch_keychain_with_timeout(libattest::HTTP_TIMEOUT).await
    }

    pub async fn fetch_keychain_with_timeout(
        timeout: Duration,
    ) -> Result<KeyChain, AttestationError> {
        let well_known = reqwest::Client::new()
            .get(NVIDIA_NRAS.join(".well-known/jwks.json").unwrap())
            .timeout(timeout)
            .send()
            .await?;
        let jwk_set: jwk::JwkSet = well_known.json().await?;

        Ok(KeyChain(jwk_set))
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
/// Same as [`KeyChain:fetch_keychain`], put in for better wasm compatibility
pub async fn fetch_keychain() -> Result<KeyChain, AttestationError> {
    KeyChain::fetch_keychain().await
}

impl Deref for KeyChain {
    type Target = jwk::JwkSet;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

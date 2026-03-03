use std::ops::Deref;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "nvidia"))]
pub struct NvidiaNonce(libattest::ByteNonce<32>);

impl Deref for NvidiaNonce {
    type Target = libattest::ByteNonce<32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl NvidiaNonce {
    pub fn generate() -> Self {
        Self(libattest::ByteNonce::generate())
    }

    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

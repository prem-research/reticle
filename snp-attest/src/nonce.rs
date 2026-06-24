use std::ops::Deref;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct SevNonce(libattest::ByteNonce<64>);

impl Deref for SevNonce {
    type Target = libattest::ByteNonce<64>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl SevNonce {
    pub fn new(byte_nonce: libattest::ByteNonce<64>) -> Self {
        Self(byte_nonce)
    }

    pub fn generate() -> Self {
        Self(libattest::ByteNonce::generate())
    }

    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

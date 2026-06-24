use std::ops::Deref;

use libattest::ByteNonce;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct TdxNonce(libattest::ByteNonce<64>);

impl Deref for TdxNonce {
    type Target = libattest::ByteNonce<64>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl TdxNonce {
    pub fn new(byte_nonce: libattest::ByteNonce<64>) -> Self {
        Self(byte_nonce)
    }

    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn generate() -> Self {
        Self(libattest::ByteNonce::generate())
    }

    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl From<ByteNonce<64>> for TdxNonce {
    fn from(value: ByteNonce<64>) -> Self {
        Self(value)
    }
}

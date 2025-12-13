use std::ops::Deref;

use crate::nonce::SevNonce;
use wasm_bindgen::prelude::*;

#[cfg(not(feature = "kds_async"))]
compile_error!("the wasm target can only be compiled with the kds_async feature");

#[wasm_bindgen]
pub struct Nonce(crate::nonce::SevNonce);

impl Deref for Nonce {
    type Target = [u8; 64];

    fn deref(&self) -> &Self::Target {
        self.0.get_bytes()
    }
}

#[wasm_bindgen]
impl Nonce {
    #[wasm_bindgen(constructor)]
    /// securely generates a new random nonce
    pub fn generate() -> Nonce {
        Nonce(SevNonce::new())
    }

    /// creates a new nonce object from bytes.
    ///
    /// ### Error:
    /// this function will return error if `from` is not exactly 64 bytes in length
    pub fn from_bytes(from: &[u8]) -> Option<Nonce> {
        let from: [u8; 64] = from.try_into().ok()?;
        Some(Nonce(from.into()))
    }

    /// Generates a copy of the underlying data of this nonce
    /// (a 64 byte array will returned)
    pub fn bytes(&self) -> Vec<u8> {
        self.0.get_bytes().to_vec()
    }
}

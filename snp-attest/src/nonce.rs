use std::ops::Deref;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "sev"))]
pub struct SevNonce(Box<[u8; 64]>);

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl SevNonce {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn new() -> Self {
        let mut bytes = Box::new([0u8; 64]);

        getrandom::getrandom(bytes.as_mut_slice()).unwrap();

        SevNonce(bytes)
    }

    pub fn generate() -> Self {
        Self::new()
    }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(self.0.as_ref())
    }
}

impl Deref for SevNonce {
    type Target = [u8; 64];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SevNonce {
    pub fn get_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Default for SevNonce {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Box<[u8; 64]>> for SevNonce {
    fn from(value: Box<[u8; 64]>) -> Self {
        Self(value)
    }
}

// impl TryFrom<std::string::String> for SevNonce {
//     type Error = anyhow::Error;

//     fn try_from(value: std::string::String) -> anyhow::Result<Self, Self::Error> {
//         let mut b_arr: [u8; 64] = [0u8; 64];

//         hex::decode(&value)
//             .expect("invalid hex")
//             .into_iter()
//             .take(64)
//             .enumerate()
//             .for_each(|(i, val)| b_arr[i] = val);

//         Ok(SevNonce { bytes: b_arr })
//     }
// }

// impl From<[u8; 64]> for SevNonce {
//     fn from(value: [u8; 64]) -> Self {
//         SevNonce { bytes: value }
//     }
// }

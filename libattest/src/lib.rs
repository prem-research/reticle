pub mod modules;
pub mod verification;

pub use modules::*;
pub use verification::*;

//#[cfg(target_family = "wasm")]
//use wasm_bindgen::prelude::*;

// #[cfg_attr(target_family = "wasm", wasm_bindgen(js_namespace = "sev"))]
#[derive(Debug, PartialEq, Eq)]
pub struct ByteNonce<const N: usize>(Box<[u8; N]>);

// #[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl<const N: usize> ByteNonce<N> {
    // #[cfg_attr(target_family = "wasm", wasm_bindgen(constructor))]
    pub fn generate() -> Self {
        let mut bytes = Box::new([0u8; N]);

        getrandom::fill(bytes.as_mut_slice()).unwrap();

        Self(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(self.0.as_ref())
    }
}

impl<const N: usize> From<[u8; N]> for ByteNonce<N> {
    fn from(value: [u8; N]) -> Self {
        Self(Box::new(value))
    }
}

impl<const N: usize> From<Box<[u8; N]>> for ByteNonce<N> {
    fn from(value: Box<[u8; N]>) -> Self {
        Self(value)
    }
}

impl<const N: usize> std::ops::Deref for ByteNonce<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> AsRef<[u8]> for ByteNonce<N> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<const N: usize> AsRef<[u8; N]> for ByteNonce<N> {
    fn as_ref(&self) -> &[u8; N] {
        self.0.as_ref()
    }
}

// impl<const N: usize> From<Box<[u8; N]>> for ByteNonce<N> {
//     fn from(value: Box<[u8; N]>) -> Self {
//         Self(value)
//     }
// }

pub mod error;
pub mod modules;
pub mod quote;
pub mod validation;

pub use modules::*;

pub type Result<T> = std::result::Result<T, error::AttestationError>;

#[macro_export]
macro_rules! define_nonce_type {
    ($(#[$meta:meta])* $vis:vis $name:ident, $size:literal $(,)?) => {
        $(#[$meta])*
        #[cfg_attr(target_family = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
        $vis struct $name($crate::ByteNonce<$size>);

        impl $name {
            pub const SIZE: usize = $size;

            pub fn new(byte_nonce: $crate::ByteNonce<$size>) -> Self {
                Self(byte_nonce)
            }
        }

        impl From<$crate::ByteNonce<$size>> for $name {
            fn from(value: $crate::ByteNonce<$size>) -> Self {
                Self::new(value)
            }
        }

        impl From<&[u8; $size]> for $name {
            fn from(value: &[u8; $size]) -> Self {
                Self::new(value.into())
            }
        }

        impl From<Box<[u8; $size]>> for $name {
            fn from(value: Box<[u8; $size]>) -> Self {
                Self::new(value.into())
            }
        }

        impl std::ops::Deref for $name {
            type Target = $crate::ByteNonce<$size>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        #[cfg(not(target_family = "wasm"))]
        impl $name {
            pub fn generate() -> Self {
                Self($crate::ByteNonce::<$size>::generate())
            }
        }

        #[cfg(target_family = "wasm")]
        #[wasm_bindgen::prelude::wasm_bindgen]
        impl $name {
            pub fn generate() -> Self {
                Self($crate::ByteNonce::<$size>::generate())
            }

            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }
        }
    };
}

#[derive(Debug, PartialEq, Eq)]
pub struct ByteNonce<const N: usize>(Box<[u8; N]>);

impl<const N: usize> ByteNonce<N> {
    pub fn generate() -> Self {
        let mut bytes = Box::new([0u8; N]);

        getrandom::fill(bytes.as_mut_slice()).unwrap();

        Self(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(self.0.as_ref())
    }
}

impl<const N: usize> From<&[u8; N]> for ByteNonce<N> {
    fn from(value: &[u8; N]) -> Self {
        Self(Box::new(*value))
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

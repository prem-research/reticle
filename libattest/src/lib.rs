pub mod error;
pub mod modules;
pub mod verification;
pub mod verification_new;

pub use modules::*;
pub use verification::*;

pub type Result<T> = std::result::Result<T, error::AttestationError>;

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

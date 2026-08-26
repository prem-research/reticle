use digest::Update;
use sha2::Digest;

use crate::bind::sealed::Bindable;

pub(crate) mod sealed {
    pub trait Bindable {}
}

pub trait Bind: Bindable {
    /// Binds this data to a nonce, producing a nonce that can be used as input
    /// for other cryptographical components to create a trust chian.
    fn bind<const N: usize>(&self, to: impl AsRef<[u8]>) -> libattest::ByteNonce<N>;
}

impl<B: Bindable + serde::Serialize> Bind for B {
    fn bind<const N: usize>(&self, to: impl AsRef<[u8]>) -> libattest::ByteNonce<N> {
        let manifest = postcard::to_allocvec(self).unwrap();
        let digest = sha2::Sha512::new()
            .chain(to)
            .chain_update(manifest)
            .finalize();

        if digest.len() < N {
            panic!("Requested digest binding of size {N} is not computable (Max size 64 bytes)");
        }

        let digest: &[u8; N] = digest.as_slice()[..N].try_into().unwrap();

        libattest::ByteNonce::from(digest)
    }
}

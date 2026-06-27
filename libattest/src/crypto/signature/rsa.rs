use std::marker::PhantomData;

use digest::FixedOutputReset;
use rsa::{
    RsaPublicKey,
    pkcs1v15::{Signature, VerifyingKey},
};
use signature::Verifier;

/// PKCS1v15 signature, digest agnostic
pub struct RsaSignature<D: digest::Digest> {
    signature: Signature,
    _digest: PhantomData<D>,
}

impl<D: digest::Digest> RsaSignature<D> {
    pub fn new(signature: Signature) -> Self {
        Self {
            signature,
            _digest: PhantomData,
        }
    }
}

impl<D: digest::Digest + FixedOutputReset + der::oid::AssociatedOid> super::DigestSignature
    for RsaSignature<D>
{
    fn verify(&self, msg: &[u8], pk: &RsaPublicKey) -> signature::Result<()> {
        let verifying = VerifyingKey::<D>::new(pk.clone());
        verifying.verify(msg, &self.signature)
    }
}

use ::rsa::RsaPublicKey;

pub mod rsa;

pub trait DigestSignature {
    /// automatically converts this public key into an appropriate
    fn verify(&self, msg: &[u8], pk: &RsaPublicKey) -> signature::Result<()>;
}

use azure_attest::AzureQuote;
use digest::Update;
use libattest::ByteNonce;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

#[derive(Serialize, Deserialize)]
pub enum CpuReport {
    /// AMD Sev-Snp
    Sev(Vec<u8>),
    /// Intel TDX
    Tdx(Vec<u8>),
    /// Hyper-V
    Azr(Box<AzureQuote>),
}

#[derive(Serialize, Deserialize)]
pub enum GpuReport {
    Absent,
    Nvidia(String),
}

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    // todo
}

impl Manifest {
    /// Binds the manifest to a nonce, producing a nonce that can be used as input
    /// for other cryptographical components to create a trust chian.
    ///
    /// Panics if N is larger than 64
    pub fn bind<const N: usize>(&self, to: impl AsRef<[u8]>) -> libattest::ByteNonce<N> {
        let manifest = postcard::to_allocvec(self).unwrap();
        let digest = Sha512::new().chain(to).chain_update(manifest).finalize();

        if digest.len() > N {
            panic!("Requested digest binding of size {N} is not computable (Max size 64 bytes)");
        }

        let digest: &[u8; N] = digest.as_slice()[..N].try_into().unwrap();

        ByteNonce::from(digest)
    }
}

#[derive(Serialize, Deserialize)]
pub struct CvmReport {
    // everything else to be defined.
    pub manifest: Manifest,
    pub cpu: CpuReport,
    pub gpu: GpuReport,
}

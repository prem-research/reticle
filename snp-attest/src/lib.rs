#[cfg(feature = "attestation")]
pub mod claims;

pub mod nonce;
pub mod oid;

// mod compatibility;
// #[cfg(feature = "kds")]
// pub mod json;

// #[cfg(target_family = "wasm")]
#[cfg(feature = "attestation")]
pub mod attestation;
// #[cfg(target_family = "wasm")]
#[cfg(feature = "attestation")]
pub use attestation::*;

/* temporarily disable hyperv */
// #[cfg(feature = "hyperv")]
// pub mod hyperv;

pub mod certificates;
pub mod error;
pub mod modules;
pub mod nonce;
pub mod quote;
pub mod validation;

pub use modules::*;
pub use nonce::*;

pub type Result<T> = std::result::Result<T, error::AttestationError>;
pub use error::AttestationError;

#[cfg(target_arch = "wasm32")]
pub(crate) fn now() -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH
        + web_time::SystemTime::now()
            .duration_since(web_time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now() -> std::time::SystemTime {
    std::time::SystemTime::now()
}

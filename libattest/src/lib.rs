pub mod crypto;
pub mod error;
pub mod nonce;
pub mod quote;
pub mod time;
pub mod validation;

pub use nonce::*;

pub type Result<T> = std::result::Result<T, error::AttestationError>;
pub use error::AttestationError;

pub use p256;

/// Default HTTP request timeout. Set per request.
pub const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

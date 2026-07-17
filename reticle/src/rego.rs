pub mod file;
pub mod url;

pub use file::FilePolicies;
pub use url::UrlPolicies;

use libattest::{error::AttestationError, validation::Validator};

#[async_trait::async_trait(?Send)]
pub trait PolicyProvider {
    async fn fetch_validator(&self) -> Result<Validator, AttestationError>;
}

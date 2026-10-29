use std::{path::PathBuf, time::Duration};

use libattest::{
    AttestationError,
    validation::{ValidationBuilder, Validator},
};

use crate::{rego::PolicyProvider, sigstore::SigstoreVerifier};

/// fetch rego policies from the filesystem. Useful for local testing.
/// Will just list all .rego files in a directory and load them all
pub struct FilePolicies {
    path: PathBuf,
}

impl FilePolicies {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait::async_trait(?Send)]
impl PolicyProvider for FilePolicies {
    async fn fetch_validator(
        &self,
        _: &SigstoreVerifier,
        _: Duration,
    ) -> Result<ValidationBuilder, AttestationError> {
        if !self.path.is_dir() {
            libattest::bail!("not a directory");
        }

        let mut policies = vec![];

        for dir_entry in std::fs::read_dir(&self.path)? {
            let policy = std::fs::read_to_string(dir_entry?.path())?;
            policies.push(policy);
        }

        Ok(Validator::builder().add_policies(policies))
    }
}

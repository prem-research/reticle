use futures::{TryStreamExt, stream::FuturesUnordered};
use libattest::{
    AttestationError, bail,
    error::Context,
    validation::{ValidationBuilder, Validator},
};
use reqwest::{IntoUrl, Url};
use serde::Deserialize;

use crate::{rego::PolicyProvider, sigstore::SigstoreVerifier};

pub struct UrlPolicies {
    client: reqwest::Client,
    base_url: Url,
}

impl UrlPolicies {
    pub fn new(url: impl IntoUrl) -> Result<Self, AttestationError> {
        let client = reqwest::Client::default();
        let base_url = url.into_url()?;

        Ok(Self { client, base_url })
    }

    async fn fetch_index(
        &self,
        index_file: &str,
        sigstore: &SigstoreVerifier,
    ) -> Result<Index, AttestationError> {
        let url = self.base_url.join(index_file).unwrap();
        let index = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        sigstore.verify_file(index_file, index.as_bytes())?;
        let index = serde_json::from_str(&index)?;

        Ok(index)
    }

    // async fn fetch_single(&self,

    async fn fetch_multiple<S, I>(
        &self,
        paths: I,
        sigstore: &SigstoreVerifier,
    ) -> Result<Vec<String>, AttestationError>
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        let fetch_tasks = FuturesUnordered::new();

        for path in paths {
            let url = self
                .base_url
                .join(path.as_ref())
                .context("failed parsing url from index")?;

            if url.authority() != self.base_url.authority() {
                bail!("changed authority when joining url!");
            }

            let rego_fetch = async move {
                let policy = self
                    .client
                    .get(url)
                    .send()
                    .await?
                    .error_for_status()?
                    .text()
                    .await?;

                sigstore.verify_file(path.as_ref(), &policy)?;
                Ok::<String, libattest::AttestationError>(policy)
            };

            // push all fetch tasks into a joinset
            fetch_tasks.push(rego_fetch);
        }

        // poll that joinset
        fetch_tasks
            .try_collect::<Vec<_>>()
            .await
            .context("failed fetching one or more rego policies")
    }
}

#[async_trait::async_trait(?Send)]
impl PolicyProvider for UrlPolicies {
    async fn fetch_validator(
        &self,
        sigstore: &SigstoreVerifier,
    ) -> Result<ValidationBuilder, AttestationError> {
        let index = self.fetch_index("policies.json", sigstore).await?;
        let policies = self.fetch_multiple(index.policies, sigstore).await?;

        let _data = self.fetch_multiple(index.data, sigstore).await?;
        if !_data.is_empty() {
            libattest::bail!("policies-supplied data is no longer supported");
        }

        let validator = Validator::builder().add_policies(policies);

        Ok(validator)
    }
}

#[derive(Deserialize)]
struct Index {
    policies: Vec<String>,
    data: Vec<String>,
}

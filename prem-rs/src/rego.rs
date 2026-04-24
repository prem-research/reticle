use futures::{TryStreamExt, stream::FuturesUnordered};
use libattest::{
    bail,
    error::{AttestationError, Context},
    validation::Validator,
};
use reqwest::{IntoUrl, Url};
use serde::Deserialize;

pub struct PoliciesClient {
    client: reqwest::Client,
    base_url: Url,
}

impl PoliciesClient {
    pub fn new(url: impl IntoUrl) -> Result<Self, AttestationError> {
        let client = reqwest::Client::default();
        let base_url = url.into_url()?;

        Ok(Self { client, base_url })
    }

    async fn fetch_index(&self, index_file: &str) -> Result<Index, AttestationError> {
        let url = self.base_url.join(index_file).unwrap();
        let index: Index = self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("received wrongly formatted policies index")?;

        Ok(index)
    }

    // async fn fetch_single(&self,

    async fn fetch_multiple<S, I>(&self, paths: I) -> Result<Vec<String>, AttestationError>
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
                bail!("changed authority when joining url!")
            }

            let rego_fetch = async move {
                self.client
                    .get(url)
                    .send()
                    .await?
                    .error_for_status()?
                    .text()
                    .await
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

    pub async fn fetch_validator(&self) -> Result<Validator, AttestationError> {
        let index = self.fetch_index("policies.json").await?;
        let policies = self.fetch_multiple(index.policies).await?;
        let data = self.fetch_multiple(index.data).await?;

        let validator = Validator::builder()
            .add_policies(policies)
            .add_datas_json(data)?
            .build()
            .context("failed building validator from source")?;

        Ok(validator)
    }
}

#[derive(Deserialize)]
struct Index {
    policies: Vec<String>,
    data: Vec<String>,
}

use std::time::Duration;

use libattest::AttestationError;
use reqwest::{IntoUrl, Url};

use crate::{
    measurements::{Measurements, MeasurementsProvider},
    sigstore::SigstoreVerifier,
};

pub struct UrlMeasurements {
    base_url: Url,
}

impl UrlMeasurements {
    pub fn new(url: impl IntoUrl) -> Result<Self, AttestationError> {
        let base_url = url.into_url()?;

        Ok(Self { base_url })
    }
}

#[async_trait::async_trait(?Send)]
impl MeasurementsProvider for UrlMeasurements {
    async fn fetch_measurements(
        &self,
        sigstore: &SigstoreVerifier,
        timeout: Duration,
    ) -> Result<Measurements, AttestationError> {
        let measurements = self.base_url.join("measurements.json")?;
        let measurements = reqwest::Client::new()
            .get(measurements)
            .timeout(timeout)
            .send()
            .await?
            .text()
            .await?;

        sigstore.verify_file("measurements.json", measurements.as_bytes())?;

        let measurements = serde_json::from_str(&measurements)?;
        Ok(measurements)
    }
}

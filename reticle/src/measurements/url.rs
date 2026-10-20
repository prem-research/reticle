use libattest::AttestationError;
use reqwest::{IntoUrl, Url};

use crate::measurements::{Measurements, MeasurementsProvider};

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
    async fn fetch_measurements(&self) -> Result<Measurements, AttestationError> {
        let measurements = self.base_url.join("measurements.json")?;
        let measurements = reqwest::get(measurements).await?.json().await?;

        Ok(measurements)
    }
}

pub mod url;

use std::collections::BTreeMap;

use libattest::AttestationError;
use serde::{Deserialize, Serialize};

use crate::sigstore::SigstoreVerifier;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Measurements {
    pub schema_version: u32,
    pub schema: String,
    pub release: Release,
    pub workloads: BTreeMap<String, Workload>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<RevokedWorkload>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub version: String,
    pub source_repository: String,

    #[serde(with = "hex::serde")]
    pub source_revision: [u8; 20],

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<PreviousRelease>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousRelease {
    pub version: String,

    #[serde(with = "hex::serde")]
    pub measurements_sha256: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedWorkload {
    pub id: String,

    #[serde(with = "hex::serde")]
    pub sha256: [u8; 32],

    pub reason: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub initdata: InitData,
    pub releases: BTreeMap<String, TeeMeasurements>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InitData {
    pub algorithm: HashAlgorithm,

    #[serde(with = "hex::serde")]
    pub digest: Vec<u8>,

    pub path: String,

    #[serde(with = "hex::serde")]
    pub sha256: [u8; 32],

    #[serde(with = "hex::serde")]
    pub host_data: [u8; 32],

    #[serde(with = "hex::serde")]
    pub mr_config_id: [u8; 48],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(transparent)]
pub struct SevMeasurement(#[serde(with = "hex::serde")] pub [u8; 48]);

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TeeMeasurements {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snp: Option<BTreeMap<VcpuType, SevMeasurement>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx: Option<TdxMeasurements>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TdxMeasurements {
    #[serde(with = "hex::serde")]
    pub mr_td: [u8; 48],

    #[serde(with = "hex::serde")]
    pub rtmr_0: [u8; 48],

    #[serde(with = "hex::serde")]
    pub rtmr_1: [u8; 48],

    #[serde(with = "hex::serde")]
    pub rtmr_2: [u8; 48],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum VcpuType {
    #[serde(rename = "EPYC")]
    Epyc,
    #[serde(rename = "EPYC-Genoa")]
    EpycGenoa,
    #[serde(rename = "EPYC-Genoa-v1")]
    EpycGenoaV1,
    #[serde(rename = "EPYC-IBPB")]
    EpycIbpb,
    #[serde(rename = "EPYC-Milan")]
    EpycMilan,
    #[serde(rename = "EPYC-Milan-v1")]
    EpycMilanV1,
    #[serde(rename = "EPYC-Milan-v2")]
    EpycMilanV2,
    #[serde(rename = "EPYC-Rome")]
    EpycRome,
    #[serde(rename = "EPYC-Rome-v1")]
    EpycRomeV1,
    #[serde(rename = "EPYC-Rome-v2")]
    EpycRomeV2,
    #[serde(rename = "EPYC-Rome-v3")]
    EpycRomeV3,
    #[serde(rename = "EPYC-Turin")]
    EpycTurin,
    #[serde(rename = "EPYC-v1")]
    EpycV1,
    #[serde(rename = "EPYC-v2")]
    EpycV2,
    #[serde(rename = "EPYC-v3")]
    EpycV3,
    #[serde(rename = "EPYC-v4")]
    EpycV4,
}

#[async_trait::async_trait(?Send)]
pub trait MeasurementsProvider {
    async fn fetch_measurements(
        &self,
        sigstore: &SigstoreVerifier,
        timeout: std::time::Duration,
    ) -> Result<Measurements, AttestationError>;
}

#[cfg(test)]
mod test {
    use crate::measurements::Measurements;

    #[tokio::test]
    async fn measurements_deserialize() {
        let measurements = reqwest::get("https://trustbase.prem.io/measurements.json")
            .await
            .unwrap()
            .json::<Measurements>()
            .await
            .expect("format to be parsable");

        println!("Measurement test: {measurements:?}")
    }
}

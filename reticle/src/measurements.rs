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
    pub tdx: Option<BTreeMap<String, TdxMeasurements>>,
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
    use libattest::validation::{ValidationResult, Validator};
    use serde_json::json;

    use crate::measurements::Measurements;

    const TDX_RELEASE: &str = "/workloads/deepseek/releases/v0.3.19/tdx";

    fn catalog() -> serde_json::Value {
        let initdata = json!({
            "algorithm": "sha384",
            "digest": "22".repeat(48),
            "path": format!("init-data/{}.toml", "00".repeat(32)),
            "sha256": "00".repeat(32),
            "host_data": "00".repeat(32),
            "mr_config_id": "00".repeat(48),
        });

        json!({
            "schema_version": 1,
            "schema": "schemas/measurements.schema.json",
            "release": {
                "version": "v1.1.3",
                "source_repository": "https://github.com/prem-research/trustbase",
                "source_revision": "00".repeat(20),
            },
            "workloads": {
                "deepseek": {
                    "initdata": initdata.clone(),
                    "releases": {
                        "v0.3.19": {
                            "tdx": {
                                "granite-rapids-a06d1": {
                                    "mr_td": "11".repeat(48),
                                    "rtmr_0": "22".repeat(48),
                                    "rtmr_1": "33".repeat(48),
                                    "rtmr_2": "44".repeat(48),
                                }
                            }
                        }
                    }
                },
                "qwen": {
                    "initdata": initdata,
                    "releases": {
                        "v0.3.18": {
                            "snp": {
                                "EPYC-Milan": "55".repeat(48),
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn processor_keyed_tdx_catalog_deserializes_and_round_trips() {
        let catalog = catalog();
        let measurements: Measurements = serde_json::from_value(catalog.clone())
            .expect("processor-keyed TDX and SNP catalog should parse");

        assert_eq!(
            serde_json::to_value(measurements).expect("catalog should serialize"),
            catalog
        );
    }

    #[test]
    fn processor_keyed_tdx_catalog_feeds_rego() {
        let measurements: Measurements = serde_json::from_value(catalog())
            .expect("processor-keyed TDX and SNP catalog should parse");
        let validator = Validator::builder()
            .add_meaurements(measurements)
            .expect("catalog should convert to Rego data")
            .add_policy(format!(
                r#"
package measurements_test

import rego.v1

default allow := false

allow if {{
    reference := data.measurements.workloads.deepseek.releases["v0.3.19"].tdx
    some processor, expected in reference
    processor == "granite-rapids-a06d1"
    expected == {{
        "mr_td": "{mr_td}",
        "rtmr_0": "{rtmr_0}",
        "rtmr_1": "{rtmr_1}",
        "rtmr_2": "{rtmr_2}",
    }}
    data.measurements.workloads.qwen.releases["v0.3.18"].snp["EPYC-Milan"] == "{snp}"
}}
"#,
                mr_td = "11".repeat(48),
                rtmr_0 = "22".repeat(48),
                rtmr_1 = "33".repeat(48),
                rtmr_2 = "44".repeat(48),
                snp = "55".repeat(48),
            ))
            .build()
            .expect("Rego policy should compile");

        assert!(matches!(
            validator.evaluate("measurements_test.allow", &json!({})),
            Ok(ValidationResult::Success)
        ));
    }

    #[test]
    fn flat_tdx_catalog_is_rejected() {
        let mut catalog = catalog();
        *catalog
            .pointer_mut(TDX_RELEASE)
            .expect("TDX fixture should exist") = json!({
            "mr_td": "11".repeat(48),
            "rtmr_0": "22".repeat(48),
            "rtmr_1": "33".repeat(48),
            "rtmr_2": "44".repeat(48),
        });

        serde_json::from_value::<Measurements>(catalog)
            .expect_err("flat TDX records must not be accepted as a processor map");
    }

    #[test]
    fn tdx_record_rejects_unknown_fields() {
        let mut catalog = catalog();
        catalog["workloads"]["deepseek"]["releases"]["v0.3.19"]["tdx"]["granite-rapids-a06d1"]["unexpected"] =
            json!("00".repeat(48));

        serde_json::from_value::<Measurements>(catalog)
            .expect_err("TDX measurement records must reject unknown fields");
    }
}

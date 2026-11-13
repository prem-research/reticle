//! Exercises the shipped TDX example policy against the processor-keyed
//! Trustbase catalog shape. `Client::attest_quote` serializes the same
//! `{manifest, claims}` input for the same `tdx.allow` query.

use std::collections::BTreeMap;

use attestation_protocol::report::manifest::PodManifest;
use libattest::validation::{ValidationResult, Validator};
use reticle::measurements::Measurements;
use serde_json::json;
use tdx_attest::dcap::types::{Sha384, TdxQuoteBody};

const POLICY: &str = include_str!("../examples/policies/tdx.rego");
const PROCESSOR: &str = "granite-rapids-a06d1";

fn register(byte: u8) -> [u8; 48] {
    [byte; 48]
}

fn sha(byte: u8) -> Sha384 {
    Sha384::from_bytes(register(byte))
}

fn manifest() -> PodManifest {
    PodManifest {
        workload_id: "deepseek".to_owned(),
        podvm_version: "v0.3.19".to_owned(),
        ohttp_key_config: None,
    }
}

struct Catalog {
    mr_config_id: [u8; 48],
    initdata_sha256: [u8; 32],
}

fn processor_keyed_catalog() -> (Measurements, Catalog) {
    let initdata = Catalog {
        mr_config_id: register(0x01),
        initdata_sha256: [0x02; 32],
    };

    let workload_initdata = json!({
        "algorithm": "sha384",
        "digest": "03".repeat(48),
        "path": format!("init-data/{}.toml", "04".repeat(32)),
        "sha256": hex::encode(initdata.initdata_sha256),
        "host_data": "05".repeat(32),
        "mr_config_id": hex::encode(initdata.mr_config_id),
    });

    let measurements = json!({
        "schema_version": 1,
        "schema": "schemas/measurements.schema.json",
        "release": {
            "version": "v1.1.3",
            "source_repository": "https://github.com/prem-research/trustbase",
            "source_revision": "06".repeat(20),
        },
        "workloads": {
            "deepseek": {
                "initdata": workload_initdata,
                "releases": {
                    "v0.3.19": {
                        "tdx": BTreeMap::from([
                            (
                                PROCESSOR,
                                json!({
                                    "mr_td": hex::encode(register(0x10)),
                                    "rtmr_0": hex::encode(register(0x11)),
                                    "rtmr_1": hex::encode(register(0x12)),
                                    "rtmr_2": hex::encode(register(0x13)),
                                }),
                            ),
                            (
                                "sapphire-rapids-8a00f",
                                json!({
                                    "mr_td": hex::encode(register(0x20)),
                                    "rtmr_0": hex::encode(register(0x21)),
                                    "rtmr_1": hex::encode(register(0x22)),
                                    "rtmr_2": hex::encode(register(0x23)),
                                }),
                            ),
                        ]),
                    }
                }
            }
        }
    });

    let measurements =
        serde_json::from_value(measurements).expect("processor-keyed catalog should parse");
    (measurements, initdata)
}

fn matching_claims(catalog: &Catalog) -> TdxQuoteBody {
    TdxQuoteBody {
        tee_tcb_svn: [7, 3, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mrseam: sha(0),
        mrsignerseam: sha(0),
        seamsttributes: [0; 8],
        tdattributes: [0; 8],
        xfam: [0; 8],
        mrtd: sha(0x20),
        mrconfigid: catalog.mr_config_id,
        mrowner: register(0),
        mrownerconfig: register(0),
        rtmr: [sha(0x21), sha(0x22), sha(0x23), sha(0x24)],
        report_data: [0; 64],
    }
}

fn evaluate(measurements: Measurements, claims: &TdxQuoteBody) -> ValidationResult {
    let validator = Validator::builder()
        .add_meaurements(measurements)
        .expect("catalog should convert to Rego data")
        .add_policy(POLICY)
        .build()
        .expect("shipped TDX policy should compile");

    validator
        .evaluate(
            "tdx.allow",
            &json!({
                "manifest": manifest(),
                "claims": claims,
            }),
        )
        .expect("policy should evaluate")
}

#[test]
fn processor_keyed_catalog_matches_listed_processor() {
    let (measurements, catalog) = processor_keyed_catalog();

    match evaluate(measurements, &matching_claims(&catalog)) {
        ValidationResult::Success => {}
        ValidationResult::Failure { coverage } => panic!("{coverage}"),
    }
}

#[test]
fn processor_keyed_catalog_rejects_unlisted_measurements() {
    let (measurements, catalog) = processor_keyed_catalog();
    let mut claims = matching_claims(&catalog);
    claims.rtmr[2] = sha(0x30);

    assert!(matches!(
        evaluate(measurements, &claims),
        ValidationResult::Failure { .. }
    ));
}

#[test]
fn processor_keyed_catalog_rejects_mixed_processor_registers() {
    let (measurements, catalog) = processor_keyed_catalog();
    let mut claims = matching_claims(&catalog);
    claims.rtmr[0] = sha(0x11);

    assert!(matches!(
        evaluate(measurements, &claims),
        ValidationResult::Failure { .. }
    ));
}

#[test]
fn processor_keyed_catalog_rejects_revoked_initdata() {
    let (mut measurements, catalog) = processor_keyed_catalog();
    measurements
        .revoked
        .push(reticle::measurements::RevokedWorkload {
            id: "deepseek".to_owned(),
            sha256: catalog.initdata_sha256,
            reason: "withdrawn".to_owned(),
        });

    assert!(matches!(
        evaluate(measurements, &matching_claims(&catalog)),
        ValidationResult::Failure { .. }
    ));
}

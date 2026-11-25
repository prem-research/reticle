use std::num::NonZeroU32;

use attestation_protocol::{initdata::InitDataDocument, report::manifest::InitData};
use libattest::{AttestationError, error::Context, regorus};

/// VFIO GPUs passed to the pod's containers must match their CDI GPU annotations.
const REGO_EVALUATOR: &str = include_str!("./evaluator.rego");

pub struct InitDataParser {
    engine: regorus::Engine,
}

impl InitDataParser {
    pub fn new() -> Self {
        let mut engine = regorus::Engine::default();

        // settings for the regorus engine
        engine.set_policy_length_config(regorus::PolicyLengthConfig {
            max_col: NonZeroU32::MAX,
            ..Default::default()
        });

        engine
            .add_policy("evaluator.rego".to_string(), REGO_EVALUATOR.to_string())
            .unwrap(); // this has to parse everytime, it's compile time bound

        Self { engine }
    }

    pub fn parse_initdata(&self, manifest: &InitDataDocument) -> libattest::Result<InitData> {
        let init_data = manifest
            .data
            .get("policy.rego") // key for the kata policy
            .context("pod manifest does not container ini-data.toml")?;

        let mut engine = self.engine.clone();
        engine
            .add_policy("policy.rego".to_string(), init_data.clone())
            .map_err(AttestationError::from_anyhow)
            .context("supplied an invalid policy.rego")?;

        let gpus = engine
            .eval_rule("data.reticle.gpus".into())
            .and_then(|gpus| gpus.as_u64())
            .map_err(AttestationError::from_anyhow)
            .context("agent policy has no GPU count consistent with its CDI annotations")?;

        Ok(InitData { gpus })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use attestation_protocol::initdata::InitDataDocument;

    use super::InitDataParser;

    const VFIO: &str = r#"{"type_": "vfio-pci-gk", "container_path": "/dev/vfio/devices/vfio"}"#;

    fn init_data(policy: String) -> InitDataDocument {
        InitDataDocument {
            algorithm: "sha384".into(),
            version: "0.1.0".into(),
            data: BTreeMap::from([
                ("id".into(), "test-workload".into()),
                ("policy.rego".into(), policy),
            ]),
        }
    }

    fn policy(devices: &[&str], annotation: &str) -> String {
        format!(
            r#"package agent_policy
policy_data := {{"containers": [
  {{"OCI": {{"Annotations": {{{annotation}}}}}, "devices": []}},
  {{"OCI": {{"Annotations": {{{annotation}}}}}, "devices": [{}]}}
], "devices": {{"vfio": {{"device_path": "/dev/vfio/devices/vfio", "nvidia": {{}}}}}}}}
"#,
            devices.join(",")
        )
    }

    #[test]
    fn counts_gpus_assigned_by_policy() {
        let parser = InitDataParser::new();
        let one = init_data(policy(&[VFIO], r#""cdi.k8s.io/gpu": "nvidia.com/pgpu=0""#));
        assert_eq!(parser.parse_initdata(&one).unwrap().gpus, 1);

        let two = init_data(policy(
            &[VFIO, VFIO],
            r#""cdi.k8s.io/gpu": "nvidia.com/pgpu=0,nvidia.com/pgpu=1""#,
        ));
        assert_eq!(parser.parse_initdata(&two).unwrap().gpus, 2);
    }

    #[test]
    fn rejects_inconsistent_gpu_assignments() {
        let parser = InitDataParser::new();
        let missing_device = init_data(policy(&[], r#""cdi.k8s.io/gpu": "nvidia.com/pgpu=0""#));
        assert!(parser.parse_initdata(&missing_device).is_err());

        let missing_annotation = init_data(policy(&[VFIO], ""));
        assert!(parser.parse_initdata(&missing_annotation).is_err());
    }

    #[test]
    fn cpu_only_policy_has_no_gpus() {
        let parser = InitDataParser::new();
        let cpu = r#"package agent_policy
policy_data := {"containers": [{"OCI": {"Annotations": {}}}], "devices": {"vfio": {}}}
"#;
        let cpu = init_data(cpu.into());
        assert_eq!(parser.parse_initdata(&cpu).unwrap().gpus, 0);

        let empty_devices = init_data(policy(&[], ""));
        assert_eq!(parser.parse_initdata(&empty_devices).unwrap().gpus, 0);
    }

    #[test]
    fn rejects_missing_policy_data() {
        let document = init_data("package agent_policy".into());
        assert!(InitDataParser::new().parse_initdata(&document).is_err());
    }

    #[test]
    fn rejects_missing_policy_in_init_data() {
        let mut document = init_data(policy(&[], ""));
        document.data.remove("policy.rego");
        assert!(InitDataParser::new().parse_initdata(&document).is_err());
    }
}

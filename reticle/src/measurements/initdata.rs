use attestation_protocol::{initdata::InitDataDocument, report::manifest::PodManifest};
use libattest::{AttestationError, error::Context};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::Measurements;

/// Fetch Init-Data from the catalog's pinned Trustbase revision and verify its digest.
pub(crate) async fn requires_gpu(
    measurements: &Measurements,
    manifest: &PodManifest,
) -> Result<bool, AttestationError> {
    let workload = measurements
        .workloads
        .get(&manifest.workload_id)
        .ok_or_else(|| AttestationError::new("workload is absent from signed measurements"))?;
    let initdata = &workload.initdata;
    let digest = hex::encode(initdata.sha256);
    let expected_path = format!("init-data/{digest}.toml");

    if measurements.release.source_repository != "prem-research/trustbase"
        || initdata.path != expected_path
    {
        libattest::bail!("invalid signed Init-Data source");
    }

    let revision = hex::encode(measurements.release.source_revision);
    let url = format!(
        "https://raw.githubusercontent.com/prem-research/trustbase/{revision}/{expected_path}"
    );
    let bytes = reqwest::get(url)
        .await?
        .error_for_status()?
        .bytes()
        .await
        .context("failed fetching signed Init-Data")?;

    if Sha256::digest(&bytes).as_slice() != initdata.sha256 {
        libattest::bail!("Init-Data digest does not match signed measurements");
    }

    let text = std::str::from_utf8(&bytes)?;
    let document: InitDataDocument = text
        .parse()
        .map_err(AttestationError::from)
        .context("invalid Init-Data TOML")?;
    if document.data.get("id") != Some(&manifest.workload_id) {
        libattest::bail!("Init-Data workload ID does not match the CPU-bound manifest");
    }

    let policy = document
        .data
        .get("policy.rego")
        .ok_or_else(|| AttestationError::new("Init-Data is missing agent policy"))?;
    policy_requires_gpu(policy)
}

fn policy_requires_gpu(policy: &str) -> Result<bool, AttestationError> {
    let marker = "policy_data := ";
    let position = policy
        .match_indices(marker)
        .find(|(index, _)| *index == 0 || policy.as_bytes()[index - 1] == b'\n')
        .map(|(index, _)| index + marker.len())
        .ok_or_else(|| AttestationError::new("agent policy has no policy_data"))?;

    let data: Value = serde_json::Deserializer::from_str(&policy[position..])
        .into_iter()
        .next()
        .transpose()?
        .ok_or_else(|| AttestationError::new("agent policy has empty policy_data"))?;
    let data = data
        .as_object()
        .ok_or_else(|| AttestationError::new("agent policy_data is not an object"))?;

    let nvidia_device = data
        .get("devices")
        .and_then(|devices| devices.get("vfio"))
        .and_then(|vfio| vfio.get("nvidia"))
        .is_some();
    let gpu_annotation = data
        .get("containers")
        .and_then(Value::as_array)
        .ok_or_else(|| AttestationError::new("agent policy_data has no container list"))?
        .iter()
        .any(|container| {
            container
                .get("OCI")
                .and_then(|oci| oci.get("Annotations"))
                .and_then(|annotations| annotations.get("cdi.k8s.io/gpu"))
                .and_then(Value::as_str)
                .is_some_and(|device| !device.trim().is_empty())
        });

    Ok(nvidia_device || gpu_annotation)
}

#[cfg(test)]
mod tests {
    #[test]
    fn gpu_devices_and_annotations_require_evidence() {
        let device = r#"package agent_policy
policy_data := {"containers": [], "devices": {"vfio": {"nvidia": {}}}}
"#;
        assert!(policy_requires_gpu(device).unwrap());

        let annotation = r#"package agent_policy
policy_data := {"containers": [{"OCI": {"Annotations": {"cdi.k8s.io/gpu": "nvidia.com/pgpu=0"}}}]}
"#;
        assert!(policy_requires_gpu(annotation).unwrap());

        let other_gpu = r#"package agent_policy
policy_data := {"containers": [{"OCI": {"Annotations": {"cdi.k8s.io/gpu": "vendor.example/gpu=0"}}}]}
"#;
        assert!(policy_requires_gpu(other_gpu).unwrap());
    }

    #[test]
    fn cpu_only_policy_does_not_require_gpu() {
        let cpu = r#"package agent_policy
policy_data := {"containers": [{"OCI": {"Annotations": {}}}], "devices": {"vfio": {}}}
"#;
        assert!(!policy_requires_gpu(cpu).unwrap());
        assert!(policy_requires_gpu("package agent_policy").is_err());
    }
}

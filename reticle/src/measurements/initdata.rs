use std::collections::BTreeSet;

use attestation_protocol::{initdata::InitDataDocument, report::manifest::PodManifest};
use libattest::{AttestationError, error::Context};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::{HashAlgorithm, InitData, Measurements};

/// Fetch and verify the signed Init-Data, then return the GPU count its policy assigns.
pub(crate) async fn expected_gpus(
    measurements: &Measurements,
    manifest: &PodManifest,
) -> Result<usize, AttestationError> {
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
    verify_host_data(initdata, &bytes)?;

    let text = std::str::from_utf8(&bytes)?;
    let document: InitDataDocument = text
        .parse()
        .map_err(AttestationError::from)
        .context("invalid Init-Data TOML")?;
    if document.algorithm != algorithm_name(initdata.algorithm) {
        libattest::bail!("Init-Data algorithm does not match signed measurements");
    }
    if document.data.get("id") != Some(&manifest.workload_id) {
        libattest::bail!("Init-Data workload ID does not match the CPU-bound manifest");
    }

    let policy = document
        .data
        .get("policy.rego")
        .ok_or_else(|| AttestationError::new("Init-Data is missing agent policy"))?;
    policy_gpu_count(policy)
}

/// Check the Init-Data digest against the signed SNP host_data and TDX mr_config_id.
fn verify_host_data(initdata: &InitData, bytes: &[u8]) -> Result<(), AttestationError> {
    let digest = match initdata.algorithm {
        HashAlgorithm::Sha256 => Sha256::digest(bytes).to_vec(),
        HashAlgorithm::Sha384 => Sha384::digest(bytes).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(bytes).to_vec(),
    };

    if digest != initdata.digest
        || fit::<32>(&digest) != initdata.host_data
        || fit::<48>(&digest) != initdata.mr_config_id
    {
        libattest::bail!("Init-Data digest does not match signed host_data");
    }
    Ok(())
}

fn fit<const N: usize>(digest: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    let len = digest.len().min(N);
    out[..len].copy_from_slice(&digest[..len]);
    out
}

fn algorithm_name(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha384 => "sha384",
        HashAlgorithm::Sha512 => "sha512",
    }
}

/// Count the policy's VFIO devices, which must match its CDI GPU annotations.
fn policy_gpu_count(policy: &str) -> Result<usize, AttestationError> {
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

    let vfio = data.get("devices").and_then(|devices| devices.get("vfio"));
    let nvidia_device = vfio.and_then(|vfio| vfio.get("nvidia")).is_some();
    let device_path = vfio
        .and_then(|vfio| vfio.get("device_path"))
        .and_then(Value::as_str);

    let containers = data
        .get("containers")
        .and_then(Value::as_array)
        .ok_or_else(|| AttestationError::new("agent policy_data has no container list"))?;

    let mut vfio_devices = 0;
    let mut cdi_devices = BTreeSet::new();
    for container in containers {
        vfio_devices += container
            .get("devices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|device| {
                device_path.is_some()
                    && device.get("container_path").and_then(Value::as_str) == device_path
            })
            .count();

        let annotation = container
            .get("OCI")
            .and_then(|oci| oci.get("Annotations"))
            .and_then(|annotations| annotations.get("cdi.k8s.io/gpu"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        cdi_devices.extend(
            annotation
                .split(',')
                .map(str::trim)
                .filter(|device| !device.is_empty()),
        );
    }

    if vfio_devices != cdi_devices.len() {
        libattest::bail!("agent policy VFIO devices do not match its CDI GPU annotations");
    }
    if nvidia_device && vfio_devices == 0 {
        libattest::bail!("agent policy configures NVIDIA devices but assigns no GPU");
    }

    Ok(vfio_devices)
}

#[cfg(test)]
mod tests {
    use super::{fit, policy_gpu_count};

    const VFIO: &str = r#"{"type_": "vfio-pci-gk", "container_path": "/dev/vfio/devices/vfio"}"#;

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
        let one = policy(&[VFIO], r#""cdi.k8s.io/gpu": "nvidia.com/pgpu=0""#);
        assert_eq!(policy_gpu_count(&one).unwrap(), 1);

        let two = policy(
            &[VFIO, VFIO],
            r#""cdi.k8s.io/gpu": "nvidia.com/pgpu=0,nvidia.com/pgpu=1""#,
        );
        assert_eq!(policy_gpu_count(&two).unwrap(), 2);
    }

    #[test]
    fn rejects_inconsistent_gpu_assignments() {
        let missing_device = policy(&[], r#""cdi.k8s.io/gpu": "nvidia.com/pgpu=0""#);
        assert!(policy_gpu_count(&missing_device).is_err());

        let missing_annotation = policy(&[VFIO], "");
        assert!(policy_gpu_count(&missing_annotation).is_err());

        let unassigned_nvidia = policy(&[], "");
        assert!(policy_gpu_count(&unassigned_nvidia).is_err());
    }

    #[test]
    fn cpu_only_policy_has_no_gpus() {
        let cpu = r#"package agent_policy
policy_data := {"containers": [{"OCI": {"Annotations": {}}}], "devices": {"vfio": {}}}
"#;
        assert_eq!(policy_gpu_count(cpu).unwrap(), 0);
        assert!(policy_gpu_count("package agent_policy").is_err());
    }

    #[test]
    fn fits_digest_to_tee_field() {
        let sha384 = [7u8; 48];
        assert_eq!(fit::<32>(&sha384), [7u8; 32]);
        assert_eq!(fit::<48>(&[7u8; 32])[32..], [0u8; 16]);
    }
}

use anyhow::Context;
use libattest::{CpuModule, GpuModule, Modules, ModulesBuilder};
use serde::Deserialize;
use std::{path::Path, time::Duration};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SecurityProfile {
    security_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComputeMetadata {
    // name: String,
    security_profile: SecurityProfile,
}

struct AzureDetector;

impl AzureDetector {
    pub fn fetch_imds() -> anyhow::Result<ComputeMetadata> {
        let res: ComputeMetadata = reqwest::blocking::ClientBuilder::new()
            .timeout(Duration::from_secs(2))
            .build()?
            .get("http://169.254.169.254/metadata/instance/compute")
            .query(&[("api-version", "2025-04-07")])
            .send()?
            .error_for_status()?
            .json()?;

        Ok(res)
    }
}

pub struct ModuleDetector;

impl ModuleDetector {
    const SEV_PATH: &str = "/dev/sev-guest";
    const TDX_PATH: &str = "/dev/tdx-guest";
    const NVIDIA_PATH: &str = "/dev/nvidiactl";

    fn path_exists(&self, path: impl AsRef<Path>) -> bool {
        path.as_ref().exists()
    }

    fn detect_azure(&self) -> Option<()> {
        log::info!("Trying to detect for Azure...");
        let imds = AzureDetector::fetch_imds().ok()?;

        log::debug!("Got security_type {}", imds.security_profile.security_type);
        (imds.security_profile.security_type == "ConfidentialVM").then_some(())
    }

    fn detect_cpu(&self) -> Option<CpuModule> {
        if self.path_exists(Self::SEV_PATH) {
            Some(CpuModule::Sev)
        } else if self.path_exists(Self::TDX_PATH) {
            Some(CpuModule::Tdx)
        } else if self.detect_azure().is_some() {
            Some(CpuModule::Azure)
        } else {
            None
        }
    }

    fn detect_gpu(&self) -> Option<GpuModule> {
        self.path_exists(Self::NVIDIA_PATH)
            .then_some(GpuModule::Nvidia)
    }

    pub fn detect(&self) -> anyhow::Result<Modules> {
        let cpu_module = self
            .detect_cpu()
            .context("host must provide at least one cpu module to perform attestation")?;

        let gpu_module = self.detect_gpu();

        let modules = ModulesBuilder::new()
            .with_cpu(cpu_module)
            .with_gpu(gpu_module)
            .build()
            .unwrap();

        Ok(modules)
    }
}

// pub fn detect_modules() -> Modules {

// }

use anyhow::Context;
use libattest::{CpuModule, GpuModule, Modules, ModulesBuilder};
use std::path::Path;

pub struct ModuleDetector;

impl ModuleDetector {
    const SEV_PATH: &str = "/dev/sev-guest";
    const TDX_PATH: &str = "/dev/tdx-guest";
    const NVIDIA_PATH: &str = "/dev/nvidiactl";

    fn path_exists(&self, path: impl AsRef<Path>) -> bool {
        path.as_ref().exists()
    }

    fn detect_cpu(&self) -> Option<CpuModule> {
        if self.path_exists(Self::SEV_PATH) {
            Some(CpuModule::Sev)
        } else if self.path_exists(Self::TDX_PATH) {
            Some(CpuModule::Tdx)
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

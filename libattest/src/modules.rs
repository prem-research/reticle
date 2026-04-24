use serde::{Deserialize, Serialize};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Clone, Copy)]
#[non_exhaustive]
pub enum CpuModule {
    Sev,
    Tdx,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Clone, Copy)]
#[non_exhaustive]
pub enum GpuModule {
    Nvidia,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct Modules {
    cpu: CpuModule,
    gpu: Option<GpuModule>,
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl Modules {
    pub fn cpu(&self) -> CpuModule {
        self.cpu
    }

    pub fn gpu(&self) -> Option<GpuModule> {
        self.gpu
    }

    pub fn has_gpu(&self) -> bool {
        self.gpu.is_some()
    }
}

pub struct ModulesBuilder {
    cpu: Option<CpuModule>,
    gpu: Option<GpuModule>,
}

impl ModulesBuilder {
    pub fn new() -> Self {
        Self {
            cpu: None,
            gpu: None,
        }
    }

    pub fn with_cpu(self, cpu: CpuModule) -> Self {
        let cpu = Some(cpu);
        Self { cpu, ..self }
    }

    pub fn with_gpu(self, gpu: Option<GpuModule>) -> Self {
        Self { gpu, ..self }
    }

    pub fn build(self) -> Option<Modules> {
        let cpu = self.cpu?;
        Some(Modules { cpu, gpu: self.gpu })
    }
}

impl Default for ModulesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

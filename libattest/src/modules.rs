use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Clone, Copy)]
pub enum Module {
    Sev,
    Tdx,
    Nvidia,
}

impl Module {
    pub fn is_cpu(&self) -> bool {
        match self {
            Module::Nvidia => false,
            Module::Sev | Module::Tdx => true,
        }
    }

    pub fn is_gpu(&self) -> bool {
        match self {
            Module::Nvidia => true,
            Module::Sev | Module::Tdx => false,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Modules {
    modules: Vec<Module>,
}

impl Modules {
    /// Returns whether the available modules specified make up a complete
    /// attestable system (cpu, gpu, ecc..)
    pub fn is_complete(&self) -> bool {
        // reduces the modules to find both at least one cpu module
        // and one gpu module
        let (cpu, gpu) = self
            .modules
            .iter()
            .fold((false, false), |(cpu, gpu), module| {
                (cpu || module.is_cpu(), gpu || module.is_gpu())
            });

        // returns true when there's moth a cpu and gpu available in the system
        cpu && gpu
    }

    pub fn modules(&self) -> &[Module] {
        &self.modules
    }
}

pub struct ModulesBuilder {
    modules: HashSet<Module>,
}

impl ModulesBuilder {
    pub fn new() -> Self {
        Self {
            modules: HashSet::new(),
        }
    }

    pub fn insert(mut self, module: Module) -> Self {
        self.modules.insert(module);
        self
    }

    pub fn insert_if(self, module: Module, predicate: bool) -> Self {
        if predicate { self.insert(module) } else { self }
    }

    pub fn build(self) -> Modules {
        Modules {
            modules: self.modules.into_iter().collect(),
        }
    }
}

impl Default for ModulesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

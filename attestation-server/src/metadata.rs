use std::{collections::BTreeMap, path::Path};

use anyhow::{Context, bail};
use attestation_protocol::{
    modules::{CpuModule, Modules},
    report::manifest::{PodReport, SevGen, Tee},
};
use serde::Deserialize;

const OS_RELEASE: &str = "/run/podvm/os-release";
const INIT_DATA: &str = "/run/podvm/initdata.toml";

/// Describes a Kata podvm init-data toml configuration
#[derive(Deserialize)]
pub struct InitData {
    algorithm: String,
    version: String,
    data: BTreeMap<String, String>,
}

impl InitData {
    pub fn read(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let file = std::fs::read_to_string(path).context("failed reading init-data file")?;
        let decoded = toml::from_str(&file).context("failed parsing init-data")?;

        Ok(decoded)
    }
}

pub fn parse_env(env: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let kv: Vec<(&str, &str)> = env
        .lines()
        .map(|line| line.split_once('='))
        .collect::<Option<_>>()
        .context("invalid kv pair in parsed env file")?;

    let env = kv
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.trim_matches('"').to_string()))
        .collect();

    Ok(env)
}

fn get_sev_gen() -> SevGen {
    let generation = sev::Generation::identify_host_generation().unwrap();

    match generation {
        sev::Generation::Milan => SevGen::Milan,
        sev::Generation::Genoa => SevGen::Genoa,
        sev::Generation::Turin => SevGen::Turin,
        sev::Generation::Venice => SevGen::Venice,
    }
}

pub fn fetch_claims(modules: &Modules) -> anyhow::Result<PodReport> {
    // identify podvm version
    let os_release = Path::new(OS_RELEASE);
    let os_release =
        std::fs::read_to_string(os_release).context("could not read /etc/os-release")?;

    let os_release = parse_env(&os_release).context("failed parsing /etc/os-release")?;
    let podvm_version = os_release
        .get("IMAGE_VERSION")
        .context("/etc/os-release does not contain podvm image version")?
        .to_string();

    let mut init_data = InitData::read(INIT_DATA)?;
    let workload_id = init_data
        .data
        .remove("id")
        .context("missing workload id from init-data")?;

    let tee_type = match modules.cpu() {
        CpuModule::Sev => Tee::Sev(get_sev_gen()),
        CpuModule::Tdx => Tee::Tdx,
        _ => bail!("other attestation types haven't been implemented yet here"),
    };

    Ok(PodReport {
        podvm_version,
        workload_id,
        tee_type,
    })
}

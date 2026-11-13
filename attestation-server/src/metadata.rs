use std::{collections::BTreeMap, path::Path};

use anyhow::Context;
use attestation_protocol::{initdata::InitDataDocument, report::manifest::PodManifest};

const OS_RELEASE: &str = "/run/podvm/os-release";
const INIT_DATA: &str = "/run/podvm/initdata.toml";

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

pub fn fetch_claims() -> anyhow::Result<PodManifest> {
    // identify podvm version
    let os_release = Path::new(OS_RELEASE);
    let os_release =
        std::fs::read_to_string(os_release).context("could not read /etc/os-release")?;

    let os_release = parse_env(&os_release).context("failed parsing /etc/os-release")?;
    let podvm_version = os_release
        .get("IMAGE_VERSION")
        .context("/etc/os-release does not contain podvm image version")?
        .to_string();

    let init_data = std::fs::read_to_string(INIT_DATA).context("failed reading init-data file")?;
    let mut init_data: InitDataDocument = init_data.parse().context("failed parsing init-data")?;
    let workload_id = init_data
        .data
        .remove("id")
        .context("missing workload id from init-data")?;

    Ok(PodManifest {
        podvm_version,
        workload_id,
    })
}

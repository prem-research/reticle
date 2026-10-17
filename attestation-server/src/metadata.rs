use std::{collections::BTreeMap, path::Path};

use anyhow::Context;
use attestation_protocol::report::manifest::{PodReport, SevGen, Tee};

const OS_RELEASE: &str = "/run/host/os-release";
const WORKLOAD_TYPE: &str = "/run/host/initdata/id";

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

fn identify_tee() -> Tee {
    if let Ok(generation) = sev::Generation::identify_host_generation() {
        let generation = match generation {
            sev::Generation::Milan => SevGen::Milan,
            sev::Generation::Genoa => SevGen::Genoa,
            sev::Generation::Turin => SevGen::Turin,
            sev::Generation::Venice => SevGen::Venice,
        };

        Tee::Sev(generation)
    } else {
        Tee::Tdx
    }
}

pub fn fetch_claims() -> anyhow::Result<PodReport> {
    //     // identify podvm version
    //     let os_release = Path::new(OS_RELEASE);
    //     let os_release =
    //         std::fs::read_to_string(os_release).context("could not read /etc/os-release")?;
    //
    //     let os_release = parse_env(&os_release).context("failed parsing /etc/os-release")?;
    //
    //     // then identify what trustbase workload type we are currently running
    //     let workload_id = std::fs::read_to_string(WORKLOAD_TYPE)
    //         .with_context(|| format!("couldn't read {WORKLOAD_TYPE}"))?;
    //
    //     Ok(PodReport {
    //         podvm_version: os_release
    //             .get("IMAGE_VERSION")
    //             .context("/etc/os-release does not contain podvm image version")?
    //             .to_string(),
    //         workload_id,
    //         tee_type: identify_tee(),
    //     })
    Ok(PodReport {
        podvm_version: "test".to_string(),
        workload_id: "test".to_string(),
        tee_type: Tee::Sev(SevGen::Genoa),
    })
}

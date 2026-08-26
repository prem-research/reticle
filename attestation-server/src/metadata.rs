use std::path::Path;

use attestation_protocol::report::Manifest;
use libattest::error::Context;

pub fn fetch_claims() -> anyhow::Result<Manifest> {
    let path = Path::new("/run/cvm/attestation-claim.json");
    let manifest = std::fs::read(path)
        .context("Failed fetching the manifest from /run/cvm/attestation-claim.json")?;

    let manifest = serde_json::from_slice(&manifest)?;
    Ok(manifest)
}

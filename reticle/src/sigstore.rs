use std::{sync::Arc, time::Duration, time::UNIX_EPOCH};

use libattest::error::Context;
use reqwest::IntoUrl;
use serde::Deserialize;
use tinysig::public::PublicVerifier;

const TRUSTBASE_IDENTITY: &str =
    "https://github.com/prem-research/trustbase/.github/workflows/release.yml@refs/tags/v1.1.1";
const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

#[derive(Clone)]
pub struct SigstoreVerifier {
    bundle: String,
    verifier: Arc<PublicVerifier>,
}

impl SigstoreVerifier {
    pub fn from_bundle(bundle: impl Into<String>) -> libattest::Result<Self> {
        const BUNDLED_ROOT: &[u8] = include_bytes!("./trust/sigstore-trusted-root.json");

        Ok(Self {
            bundle: bundle.into(),
            verifier: Arc::new(PublicVerifier::from_json(BUNDLED_ROOT)?),
        })
    }

    pub fn verify_file(&self, file_name: &str, file: impl AsRef<[u8]>) -> libattest::Result<()> {
        let verified = self
            .verifier
            .verify(
                file.as_ref(),
                self.bundle.as_bytes(),
                TRUSTBASE_IDENTITY,
                GITHUB_ISSUER,
                libattest::time::now().duration_since(UNIX_EPOCH)?.as_secs(),
            )
            .with_context(|| format!("sigstore verification failed for {file_name}"))?;

        let Statement { subject } = serde_json::from_slice(
            &verified
                .dsse_payload
                .context("expected a signed statement")?,
        )?;

        let digest = hex::encode(verified.sha256);
        let matches_name = subject
            .iter()
            .any(|subject| subject.name == file_name && subject.digest.sha256 == digest);

        if !matches_name {
            libattest::bail!("artifact name did not match the verified associated digest");
        }

        Ok(())
    }
}

#[derive(Deserialize)]
struct Statement {
    subject: Vec<Subject>,
}

#[derive(Deserialize)]
struct Subject {
    name: String,
    digest: ArtifactDigest,
}

#[derive(Deserialize)]
struct ArtifactDigest {
    sha256: String,
}

pub async fn fetch_sigstore(
    base_url: impl IntoUrl,
    timeout: Duration,
) -> libattest::Result<SigstoreVerifier> {
    let url = base_url.into_url()?.join("./provenance.sigstore.json")?;
    let bundle = reqwest::Client::new()
        .get(url)
        .timeout(timeout)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    SigstoreVerifier::from_bundle(bundle)
}

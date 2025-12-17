use std::{fmt::Display, path::PathBuf};

use anyhow::Context;
use rocket::State;
use serde::Deserialize;
use tokio::process::Command;

use crate::{nonce::NonceParam, response::ApiJsonResult};

pub enum NvVerifier {
    Local,
    Remote,
}

impl Display for NvVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let verifier = match self {
            NvVerifier::Local => "local",
            NvVerifier::Remote => "remote",
        };

        f.write_str(verifier)
    }
}

#[derive(Deserialize)]
pub struct NvAttestation {
    detached_eat: serde_json::Value,
    result_message: String,
}

pub struct AttestCommand {
    command: Command,
}

impl AttestCommand {
    pub fn nonce(mut self, nonce: impl AsRef<[u8]>) -> Self {
        let nonce = hex::encode(nonce);
        self.command.arg(format!("--nonce={nonce}"));
        self
    }

    pub fn verifier(mut self, verifier: NvVerifier) -> Self {
        self.command.arg(format!("--verifier={verifier}"));
        self
    }

    pub async fn run(mut self) -> anyhow::Result<NvAttestation> {
        let output = self.command.output().await?;
        let status = output
            .status
            .code()
            .context("nvattest was killed by a signal")?;

        let attestation: NvAttestation = serde_json::from_slice(&output.stdout)?;

        match status {
            0 => Ok(attestation),
            _ => anyhow::bail!(attestation.result_message),
        }
    }
}

pub struct NvAttest {
    binary_path: PathBuf,
}

impl NvAttest {
    pub fn new(path: impl Into<PathBuf>) -> Option<Self> {
        let path = path.into();

        std::fs::exists(&path)
            .unwrap_or_default()
            .then_some(Self { binary_path: path })
    }

    pub fn attest(&self) -> AttestCommand {
        let command = Command::new(&self.binary_path);
        AttestCommand { command }
    }
}

#[rocket::get("/nvidia?<nonce>")]
pub async fn nvidia_attestation(
    nonce: NonceParam<Box<[u8; 32]>, 32>,
    nvattest: &State<NvAttest>,
) -> ApiJsonResult<serde_json::Value> {
    let NonceParam(nonce) = nonce;

    let attestation = nvattest
        .attest()
        .verifier(NvVerifier::Remote)
        .nonce(nonce.as_ref())
        .run()
        .await?;

    Ok(attestation.detached_eat.into())
}

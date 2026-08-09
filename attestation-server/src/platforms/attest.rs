use anyhow::Context;
use attestation_protocol::report::{CpuReport, CvmReport, GpuReport, Manifest};
use azure_attest::AzureQuote;
use libattest::ByteNonce;
use nvat::{AttestationBuilder, SdkHandle, nonce::NvatNonce};
use rocket::{
    Request, State,
    http::Status,
    request::{FromRequest, Outcome},
};
use sev::firmware::guest::Firmware;

use crate::{
    nonce::NonceParam,
    platforms::{azure::TpmDevice, sev::SharedFirmware, tdx::TdxProvider},
    response::ApiJsonResult,
};

pub enum CpuAttestation<'a> {
    Azure(&'a State<TpmDevice>),
    Tdx(&'a State<TdxProvider>),
    Sev(&'a State<SharedFirmware>),
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for CpuAttestation<'r> {
    type Error = anyhow::Error;

    #[inline(always)]
    async fn from_request(req: &'r Request<'_>) -> rocket::request::Outcome<Self, anyhow::Error> {
        if let Some(azure) = State::get(req.rocket()) {
            return Outcome::Success(CpuAttestation::Azure(azure));
        } else if let Some(tdx) = State::get(req.rocket()) {
            return Outcome::Success(CpuAttestation::Tdx(tdx));
        } else if let Some(sev) = State::get(req.rocket()) {
            return Outcome::Success(CpuAttestation::Sev(sev));
        }

        return Outcome::Error((
            Status::InternalServerError,
            anyhow::anyhow!("No cpu module available"),
        ));
    }
}

pub enum GpuAttestation<'a> {
    Nvidia(&'a State<SdkHandle>),
    Absent,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for GpuAttestation<'r> {
    type Error = anyhow::Error;

    #[inline(always)]
    async fn from_request(req: &'r Request<'_>) -> rocket::request::Outcome<Self, anyhow::Error> {
        if let Some(nvidia) = State::get(req.rocket()) {
            return Outcome::Success(GpuAttestation::Nvidia(nvidia));
        }
        Outcome::Success(GpuAttestation::Absent)
    }
}

fn attest_tpm(tpm: &TpmDevice, nonce: ByteNonce<32>) -> anyhow::Result<AzureQuote> {
    let tpm = tpm.create_context()?;
    azure_attest::host::azure_attest(tpm, &(nonce.into()))
}

fn attest_tdx(tdx: &TdxProvider, nonce: ByteNonce<64>) -> anyhow::Result<Vec<u8>> {
    tdx.create_tdx_quote(*nonce.as_ref())
        .context("could not generate tdx quote")
}

fn attest_sev(sev: &mut Firmware, nonce: ByteNonce<64>) -> anyhow::Result<Vec<u8>> {
    sev.get_report(None, Some(*nonce), None)
        .context("error sourcing the report")
}

fn attest_gpu(sdk: &SdkHandle, nonce: ByteNonce<32>) -> anyhow::Result<String> {
    // TEMPORARY FIX FOR BAD NVIDIA APIS
    let nonce = hex::encode(&nonce[..]);
    let nonce = NvatNonce::from_hex(sdk, &nonce)
        .context("internal nvat error when converting the nonce")?;

    let result = AttestationBuilder::new(sdk)
        .context("cannot create attestation context")?
        .gpu()
        .verifier_remote()
        .build()
        .attest_device(&nonce)
        .context("cannot complete attestation process")?;

    Ok(result
        .detached_eat
        .as_str()
        .context("attestation contains bad string data")?
        .to_string())
}

#[rocket::get("/attest?<nonce>")]
pub async fn attest(
    nonce: NonceParam<libattest::ByteNonce<64>, 64>,
    cpu: CpuAttestation<'_>,
    gpu: GpuAttestation<'_>,
) -> ApiJsonResult<CvmReport> {
    // placeholder
    let NonceParam(nonce) = nonce;
    let manifest = Manifest {};

    let cpu_report = match cpu {
        CpuAttestation::Azure(tpm) => {
            let nonce = manifest.bind(&nonce);
            attest_tpm(tpm, nonce).map(Box::new).map(CpuReport::Azr)?
        }
        CpuAttestation::Tdx(tdx) => {
            let nonce: ByteNonce<64> = manifest.bind(&nonce);
            attest_tdx(tdx, nonce).map(CpuReport::Tdx)?
        }
        CpuAttestation::Sev(state) => {
            let nonce = manifest.bind(&nonce);
            let mut sev = state.lock().await;
            attest_sev(&mut sev, nonce).map(CpuReport::Sev)?
        }
    };

    let gpu_report = match gpu {
        GpuAttestation::Absent => GpuReport::Absent,
        GpuAttestation::Nvidia(sdk) => {
            let nonce = manifest.bind(nonce);
            attest_gpu(sdk, nonce).map(GpuReport::Nvidia)?
        }
    };

    let report = CvmReport {
        cpu: cpu_report,
        gpu: gpu_report,
        manifest,
    };

    Ok(report.into())
}

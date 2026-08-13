use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

use azure_attest::host::vtpm::AzureTpmCtx;
use rocket::{
    Build, Rocket,
    fairing::{Fairing, Kind},
};

#[derive(Clone)]
pub struct TpmDevice {
    tpm_path: Cow<'static, Path>,
}

impl TpmDevice {
    const TPM_PATH: &'static str = "/dev/tpm0";
    const TPMRM_PATH: &'static str = "/dev/tpmrm0";

    #[allow(dead_code)]
    pub fn with_path(device: impl Into<PathBuf>) -> Self {
        Self {
            tpm_path: device.into().into(),
        }
    }

    pub fn auto_detect() -> anyhow::Result<Self> {
        let tpm_path = Path::new(Self::TPM_PATH);
        let tpmrm_path = Path::new(Self::TPMRM_PATH);

        let tpm_path = if tpmrm_path.exists() {
            tpmrm_path.into()
        } else if tpm_path.exists() {
            tpm_path.into()
        } else {
            anyhow::bail!("Could not find a tpm device at /dev/tpm0 or /dev/tpmrm0");
        };

        Ok(Self { tpm_path })
    }
}

impl TpmDevice {
    pub fn create_context(&self) -> anyhow::Result<AzureTpmCtx> {
        let ctx = AzureTpmCtx::with_device(&self.tpm_path)?;
        Ok(ctx)
    }
}

pub struct AzureFairing {
    device: TpmDevice,
}

impl AzureFairing {
    pub fn new(device: TpmDevice) -> Self {
        Self { device }
    }
}

#[rocket::async_trait]
impl Fairing for AzureFairing {
    fn info(&self) -> rocket::fairing::Info {
        rocket::fairing::Info {
            name: "Azure TPM Fairing",
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> Result<Rocket<Build>, Rocket<Build>> {
        let res_context = self.device.create_context();
        if let Err(error) = res_context {
            let device = self.device.tpm_path.as_ref();
            log::error!("Creating a tpm context with [{device:?}] failed with error: {error}");

            return Err(rocket);
        }

        Ok(rocket.manage(self.device.clone()))
    }
}

// #[rocket::get("/azure?<nonce>")]
// pub async fn azure_attestation(
//     nonce: NonceParam<libattest::ByteNonce<32>, 32>,
//     tpm: &State<TpmDevice>,
// ) -> ApiJsonResult<AzureQuote> {
//     let NonceParam(nonce) = nonce;
//     let nonce = AzureNonce::new(nonce);

//     let tpm = tpm.create_context()?;
//     let quote = azure_attest::host::azure_attest(tpm, &nonce)?;

//     Ok(quote.into())
// }

use anyhow::Context;
use libattest::quote::QuoteVerifier;
use nvat::{AttestationBuilder, SdkHandle, nonce::NvatNonce};
use nvidia_attest::EATToken;
use nvidia_attest::keychain::KeyChain;
use nvidia_attest::nonce::NvidiaNonce;
use nvidia_attest::types::GpuClaims;
use nvidia_attest::verifier::NvidiaVerifier;
use nvml_wrapper::Nvml;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Build, Rocket};

pub struct NvidiaFairing {
    handle: SdkHandle,
    nvml: Nvml,
}

impl NvidiaFairing {
    pub fn init() -> anyhow::Result<Self> {
        let handle = SdkHandle::get_handle()?;
        let nvml = Nvml::init()?;

        Ok(NvidiaFairing { handle, nvml })
    }

    async fn attest_and_init(&self) -> anyhow::Result<()> {
        let keychain = KeyChain::fetch_keychain().await?;

        let nonce = NvidiaNonce::generate();
        let nvat_nonce = NvatNonce::from_hex(&self.handle, &nonce.to_hex())?;

        let attestation = AttestationBuilder::new(&self.handle)
            .context("cannot create attestation context")?
            .gpu()
            .verifier_remote()
            .build()
            .attest_device(&nvat_nonce)?;

        // NvidiaNonce::
        // let claims =
        //     EATToken::parse(attestation.detached_eat.as_str()?)?.verify(&keychain, &nonce)?;
        let quote = EATToken::parse(attestation.detached_eat.as_str()?)?;
        let claims = NvidiaVerifier::new(keychain).verify(&quote, &nonce)?;

        // we gather the device uuids from the claims of the attested gpus
        // so we don't accidentally turn on confidential computing for
        // gpus we didn't explicitly verify
        let attested_gpus: Vec<&GpuClaims> = claims.gpu_claims().values().collect();
        let available_gpus: Vec<nvml_wrapper::Device> = (0..self.nvml.device_count()?)
            .map(|idx| self.nvml.device_by_index(idx))
            .collect::<Result<_, _>>()?;

        if attested_gpus.len() != available_gpus.len() {
            let attested_gpus = attested_gpus.len();
            let available_gpus = available_gpus.len();

            anyhow::bail!(
                "there's a mismatch between the number of available gpus {available_gpus} on this machine and the attested number of gpus {attested_gpus}"
            );
        }

        let gpu = available_gpus
            .first()
            .context("No GPUs available in the system for confidential computing workloads")?;

        // nvml wrapper library is broken and calling this method
        // on the device enables it systemwide. It should be
        // self.nvml.set_confidential_compute_state(true);
        gpu.set_confidential_compute_state(true)?;

        Ok(())
    }
}

#[rocket::async_trait]
impl Fairing for NvidiaFairing {
    fn info(&self) -> rocket::fairing::Info {
        Info {
            name: "Nvidia SDK initializer",
            kind: Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: Rocket<Build>) -> Result<Rocket<Build>, Rocket<Build>> {
        let result = self.attest_and_init().await;
        if let Err(error) = result {
            log::error!("Error returned from SDK initialization fairing: {error:?}");
            return Err(rocket);
        }

        // if initialization succeeds then attach the sdk handle
        let rocket = rocket.manage(self.handle.clone());

        Ok(rocket)
    }
}

// #[rocket::get("/nvidia?<nonce>")]
// pub async fn nvidia_attestation(
//     nonce: NonceParam<libattest::ByteNonce<32>, 32>,
//     sdk: &State<SdkHandle>,
// ) -> Result<String, ApiError> {
//     todo!()
// }

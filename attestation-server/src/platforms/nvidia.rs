use std::collections::HashSet;
use std::ops::Deref;

use anyhow::Context;
use libattest::quote::QuoteVerifier;
use nvat::{AttestationBuilder, SdkHandle, nonce::NvatNonce};
use nvidia_attest::EATToken;
use nvidia_attest::keychain::KeyChain;
use nvidia_attest::nonce::NvidiaNonce;
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
        let uuids: HashSet<String> = claims
            .gpu_claims()
            .values()
            .map(|gpu| &gpu.ueid)
            .cloned()
            .collect();

        for uuid in uuids {
            let device = self.nvml.device_by_uuid(uuid.deref()).with_context(|| {
                format!("Device with UUID: {uuid} was attested but not found by nvml")
            })?;

            // once we attest the device we can activate
            // confidential compute state
            device
                .set_confidential_compute_state(true)
                .with_context(|| {
                    format!("cannot activate confidential computing for gpu uuid:{uuid}")
                })?;
        }

        let count = self.nvml.device_count()? as usize;
        if count != claims.gpu_claims().iter().count() {
            log::warn!(
                "there are still devices on this machine for which confidential computing wasn't enabled."
            )
        }

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

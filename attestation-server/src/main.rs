mod response;

#[cfg(feature = "sev")]
use anyhow::Context;
use base64::{Engine, prelude::BASE64_STANDARD};
use rocket::{
    State,
    form::{self, FromFormField},
    routes,
};
use sev::firmware::guest::Firmware;
use tokio::sync::Mutex;

#[cfg(feature = "sev")]
use crate::response::ApiError;

pub type SharedFirmware = Mutex<Firmware>;

struct CpuNonce(Box<[u8; 64]>);

impl CpuNonce {
    fn nonce(&self) -> [u8; 64] {
        *self.0
    }
}

impl<'a> FromFormField<'a> for CpuNonce {
    fn from_value(field: rocket::form::ValueField<'a>) -> rocket::form::Result<'a, Self> {
        use form::Error;

        let decoded = hex::decode(field.value) // either decode using hex
            .or(BASE64_STANDARD.decode(field.value)) // or using base64
            .map_err(|_| {
                Error::validation("nonce could not be decoded neither from hex nor base64")
            })?;

        let nonce = decoded
            .try_into()
            .map_err(|_| Error::validation("nonce is not exactly 32 bytes wide"))?;

        Ok(CpuNonce(nonce))
    }

    // fn from_param(param: &'a str) -> Result<Self, Self::Error> {}
    fn from_data<'life0, 'async_trait>(
        field: rocket::form::DataField<'a, 'life0>,
    ) -> ::core::pin::Pin<
        Box<
            dyn ::core::future::Future<Output = rocket::form::Result<'a, Self>>
                + ::core::marker::Send
                + 'async_trait,
        >,
    >
    where
        'a: 'async_trait,
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        todo!()
    }
}

#[rocket::get("/cpu?<nonce>")]
#[cfg(feature = "sev")]
async fn cpu_attestation(
    nonce: CpuNonce,
    firmware: &State<SharedFirmware>,
) -> Result<Vec<u8>, ApiError> {
    use anyhow::Context;

    let mut firmware = firmware.lock().await;
    let report = firmware
        .get_report(None, Some(nonce.nonce()), None)
        .context("error sourcing the report")?;

    drop(firmware); // release the lock

    Ok(report)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    #[cfg(feature = "sev")]
    let firmware: Mutex<Firmware> = Firmware::open()
        .context("failed to open sev-snp firmware")?
        .into();

    let rocket = rocket::build();

    #[cfg(feature = "sev")]
    let rocket = rocket.manage(firmware);

    #[cfg(feature = "sev")]
    rocket
        .mount("/attestation", routes![cpu_attestation])
        .launch()
        .await?;

    // graceful shutdown
    Ok(())
}

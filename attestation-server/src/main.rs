mod response;

mod nonce;
#[cfg(feature = "nvidia")]
mod nvidia_api;
#[cfg(feature = "sev")]
mod sev_api;

use rocket::routes;
use tokio::sync::Mutex;

use anyhow::Context;

#[cfg(feature = "sev")]
use sev::firmware::guest::Firmware;

#[cfg(feature = "nvidia")]
use crate::nvidia_api::NvAttest;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let rocket = rocket::build();

    #[cfg(feature = "sev")]
    let rocket = {
        let firmware: Mutex<Firmware> = Firmware::open()
            .context("failed to open sev-snp firmware")?
            .into();

        rocket
            .manage(firmware)
            .mount("/attestation", routes![sev_api::cpu_attestation])
    };

    #[cfg(feature = "nvidia")]
    let rocket = {
        let nvattest =
            NvAttest::new("/usr/local/bin/nvattest").context("missing nvattest binary")?;

        rocket
            .manage(nvattest)
            .mount("/attestation", routes![nvidia_api::nvidia_attestation])
    };

    rocket.launch().await?;

    // // graceful shutdown
    Ok(())
}

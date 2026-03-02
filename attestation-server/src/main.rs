mod response;

mod nonce;
#[cfg(feature = "nvidia")]
mod nvidia_api;
#[cfg(feature = "sev")]
mod sev_api;

use libattest::modules::{Module, Modules, ModulesBuilder};
use log::LevelFilter;
use rocket::routes;
use tokio::sync::Mutex;

use anyhow::Context;

use crate::response::ApiJsonResult;

#[rocket::get("/modules")]
fn modules() -> ApiJsonResult<Modules> {
    let modules = ModulesBuilder::new()
        .insert_if(Module::Nvidia, cfg!(feature = "nvidia"))
        .insert_if(Module::Sev, cfg!(feature = "sev"))
        .insert_if(Module::Tdx, cfg!(feature = "tdx"))
        .build();

    response::ok(modules)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    let rocket = rocket::build();
    let mut routes = routes![];

    // advertise server capabilities
    routes.extend(routes![modules]);

    #[cfg(feature = "sev")]
    let rocket = {
        use sev::firmware::guest::Firmware;

        let firmware: Mutex<Firmware> = Firmware::open()
            .context("failed to open sev-snp firmware")?
            .into();

        routes.extend(routes![sev_api::cpu_attestation]);
        rocket.manage(firmware)
    };

    #[cfg(feature = "nvidia")]
    let rocket = {
        use nvat::SdkHandle;

        let sdk = SdkHandle::get_handle()?;

        routes.extend(routes![nvidia_api::nvidia_attestation]);
        rocket.manage(sdk)
    };

    rocket.mount("/attestation", routes).launch().await?;

    #[cfg(feature = "nvidia")]
    nvat::SdkHandle::get_handle()?.shutdown();

    // // graceful shutdown
    Ok(())
}

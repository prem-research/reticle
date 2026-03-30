mod response;

// pub mod modules;
pub mod modules;
mod nonce;
mod nvidia_api;
mod sev_api;
mod tdx_api;

use std::ops::Deref;

use anyhow::Context;
use libattest::{CpuModule, GpuModule, modules::Modules};
use log::LevelFilter;
use rocket::{State, routes};
use sev::firmware::guest::Firmware;
use tokio::sync::Mutex;

use crate::{modules::ModuleDetector, response::ApiJsonResult};

#[rocket::get("/modules")]
fn get_modules(modules: &State<Modules>) -> ApiJsonResult<&Modules> {
    response::ok(modules.deref())
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
    routes.extend(routes![get_modules]);

    let modules = ModuleDetector.detect()?;
    let rocket = rocket.manage(modules);

    let mut rocket = match modules.cpu() {
        CpuModule::Sev => {
            let firmware: Mutex<Firmware> = Firmware::open()
                .context("failed to open sev-snp firmware")?
                .into();

            routes.extend(routes![sev_api::cpu_attestation]);
            rocket.manage(firmware)
        }
        CpuModule::Tdx => {
            routes.extend(routes![tdx_api::tdx_attestation]);
            rocket
        }
    };

    if let Some(GpuModule::Nvidia) = modules.gpu() {
        use nvat::SdkHandle;

        let sdk = SdkHandle::get_handle()?;

        routes.extend(routes![nvidia_api::nvidia_attestation]);
        rocket = rocket.manage(sdk);
    };

    rocket.mount("/attestation", routes).launch().await?;

    // close sdk on shutdown
    match modules.gpu() {
        Some(GpuModule::Nvidia) => nvat::SdkHandle::get_handle()?.shutdown(),
        None => (),
    }

    Ok(())
}

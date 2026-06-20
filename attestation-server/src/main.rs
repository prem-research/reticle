mod response;

// pub mod modules;
pub mod modules;
mod nonce;
mod nvidia_api;
mod sev_api;
mod tdx_api;

use std::ops::Deref;

use anyhow::{Context, bail};
use libattest::{CpuModule, GpuModule, modules::Modules};
use log::LevelFilter;
use rocket::{State, catch, catchers, routes};
use sev::firmware::guest::Firmware;
use tokio::sync::Mutex;

use crate::{modules::ModuleDetector, nvidia_api::SdkFairing, response::ApiJsonResult};

#[catch(404)]
fn not_found() -> &'static str {
    ""
}

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
        _ => bail!("cpu module not yet supported by attestation-server"),
    };

    if let Some(GpuModule::Nvidia) = modules.gpu() {
        // attach the nvidia fairing responsible for first attestation
        // and enable gpus for confidential computing operations
        let sdk = SdkFairing::init()?;
        rocket = rocket.attach(sdk);

        routes.extend(routes![nvidia_api::nvidia_attestation]);
    };

    rocket
        .mount("/attestation", routes)
        .register("/", catchers![not_found])
        .launch()
        .await?;

    // close sdk on shutdown
    match modules.gpu() {
        Some(GpuModule::Nvidia) => nvat::SdkHandle::get_handle()?.shutdown(),
        Some(_) => todo!(),
        None => (),
    }

    Ok(())
}

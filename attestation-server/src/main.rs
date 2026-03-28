mod response;

mod nonce;
#[cfg(feature = "nvidia")]
mod nvidia_api;
#[cfg(feature = "sev")]
mod sev_api;
#[cfg(feature = "tdx")]
mod tdx_api;

use std::ops::Deref;

use libattest::{
    CpuModule, GpuModule,
    modules::{Modules, ModulesBuilder},
};
use log::LevelFilter;
use rocket::{State, routes};

use anyhow::Context;

use crate::response::ApiJsonResult;

#[rocket::get("/modules")]
fn modules(modules: &State<Modules>) -> ApiJsonResult<&Modules> {
    response::ok(modules.deref())
}

#[cfg(all(feature = "sev", feature = "tdx"))]
compile_error!("Cannot have an attestation-server have both sev and tdx enabled");

fn get_modules() -> anyhow::Result<Modules> {
    #[cfg(feature = "sev")]
    let cpu = CpuModule::Sev;
    #[cfg(feature = "tdx")]
    let cpu = CpuModule::Tdx;

    let gpu: Option<GpuModule> = None;
    #[cfg(feature = "nvidia")]
    let gpu = Some(GpuModule::Nvidia);

    ModulesBuilder::new()
        .with_cpu(cpu)
        .with_gpu(gpu)
        .build()
        .context("cannot build the system with this set of modules")
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

    let modules = get_modules()?;
    let rocket = rocket.manage(modules);

    #[cfg(feature = "sev")]
    let rocket = {
        use sev::firmware::guest::Firmware;
        use tokio::sync::Mutex;

        let firmware: Mutex<Firmware> = Firmware::open()
            .context("failed to open sev-snp firmware")?
            .into();

        routes.extend(routes![sev_api::cpu_attestation]);
        rocket.manage(firmware)
    };

    #[cfg(feature = "tdx")]
    let rocket = {
        routes.extend(routes![tdx_api::tdx_attestation]);
        rocket
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

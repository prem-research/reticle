mod response;

// pub mod modules;
mod metadata;
mod modules;
mod nonce;
mod ohttp;
mod platforms;

use std::ops::Deref;

use anyhow::{Context, bail};
use attestation_protocol::modules::{CpuModule, GpuModule, Modules};
use log::LevelFilter;

use rocket::{State, catch, catchers, routes};
use serde::Deserialize;
use sev::firmware::guest::Firmware;
use tokio::sync::Mutex;

use crate::{
    modules::ModuleDetector,
    ohttp::ReverseProxyConfig,
    platforms::{
        attest::attest,
        azure::{AzureFairing, TpmDevice},
        nvidia::NvidiaFairing,
        tdx::TdxProvider,
    },
    response::ApiJsonResult,
};

#[rocket::get("/modules")]
fn get_modules(modules: &State<Modules>) -> ApiJsonResult<&Modules> {
    response::ok(modules.deref())
}

#[catch(404)]
fn not_found() -> &'static str {
    "route not found"
}

#[derive(Deserialize)]
struct Config {
    gateway: ReverseProxyConfig,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::builder()
        .filter_level(LevelFilter::Info)
        .parse_default_env()
        .init();

    let config_path = std::env::var_os("RETICLE_CONFIG").unwrap_or_else(|| "./config.toml".into());
    let config: Config = toml::from_str(
        &std::fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read configuration {config_path:?}"))?,
    )
    .context("failed to parse configuration")?;
    let reverse_proxy = config.gateway.build()?;

    // generate a new ohttp server private key valid for this
    // run of reticle. The key config will be sent to the client
    // during attestation
    let ohttp_server = ohttp::generate_key_server();

    let rocket = rocket::build();
    let modules = ModuleDetector.detect()?;
    let claims = metadata::fetch_claims(ohttp_server.config())?;

    // attach everything to rocket so it's available
    // in our routes
    let rocket = rocket
        .manage(modules)
        .manage(claims)
        .manage(ohttp_server)
        .manage(reverse_proxy);

    let mut rocket = match modules.cpu() {
        CpuModule::Sev => {
            let firmware: Mutex<Firmware> = Firmware::open()
                .context("failed to open sev-snp firmware")?
                .into();

            rocket.manage(firmware)
        }
        CpuModule::Tdx => rocket.manage(TdxProvider),
        CpuModule::Azure => {
            let tpm = TpmDevice::auto_detect().context("could not detect default tpm device")?;
            let tpm = AzureFairing::new(tpm);

            rocket.attach(tpm)
        }
        _ => bail!("cpu module not yet supported by attestation-server"),
    };

    if let Some(GpuModule::Nvidia) = modules.gpu() {
        // attach the nvidia fairing responsible for first attestation
        // and enable gpus for confidential computing operations
        let sdk = NvidiaFairing::init()?;
        rocket = rocket.attach(sdk);
    };

    rocket
        .mount("/attestation", routes![attest, get_modules])
        .mount("/gateway", routes![ohttp::ohttp_tunnel])
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

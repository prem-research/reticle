use sev::firmware::guest::Firmware;
use tokio::sync::Mutex;

pub type SharedFirmware = Mutex<Firmware>;

// #[rocket::get("/sev?<nonce>")]
// pub async fn cpu_attestation(
//     nonce: NonceParam<libattest::ByteNonce<64>, 64>,
//     firmware: &State<SharedFirmware>,
// ) -> Result<Vec<u8>, ApiError> {
//     // let NonceParam(nonce) = nonce;
//     // use anyhow::Context;

//     // Ok(report)
//     //
//     todo!()
// }

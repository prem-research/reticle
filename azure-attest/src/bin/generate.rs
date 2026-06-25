use std::ops::Deref;

use azure_attest::host::vtpm::AzureTpm;

fn main() {
    // ContextGap
    let mut context =
        tss_esapi::Context::new(TctiNameConf::Device(DeviceConfig::default())).unwrap();

    context.set_sessions((Some(AuthSession::Password), None, None));

    let tpm = AzureTpm::new(context);
    let attestation = azure_attest::host::azure_attest(tpm, &[0u8; 32]).unwrap();

    let attestation = serde_json::to_string(&attestation).unwrap();

    println!("{attestation}");
}

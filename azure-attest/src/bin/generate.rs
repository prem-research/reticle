use azure_attest::{host::vtpm::AzureTpmCtx, nonce::AzureNonce};

fn main() {
    let tpm = AzureTpmCtx::default_device().unwrap();
    let nonce = AzureNonce::generate();

    let attestation = azure_attest::host::azure_attest(tpm, &nonce).unwrap();

    let attestation = serde_json::to_string(&attestation).unwrap();

    println!("{attestation}");
}

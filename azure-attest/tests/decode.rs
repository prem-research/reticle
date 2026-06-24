const ATTESTATION: &'static str = include_str!("./attestation.json");

#[test]
fn decode_attestation() {
    let attestation: azure_attest::AzureQuote = serde_json::from_str(ATTESTATION).unwrap();
}

#[test]
fn verify_attestation() {
    let attestation: azure_attest::AzureQuote = serde_json::from_str(ATTESTATION).unwrap();
    attestation.verify().unwrap();
}

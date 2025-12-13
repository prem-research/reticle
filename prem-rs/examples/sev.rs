use prem_rs::ClientBuilder;
use snp_attest::{kds, nonce::SevNonce};

#[tokio::main]
async fn main() {
    let client = ClientBuilder::new("http://localhost:8000/")
        .build()
        .unwrap();

    let nonce = SevNonce::new();
    let attestation = client.request_attestation(&nonce).await.unwrap();
    let keychain = kds::fetch_certificates(&attestation).await.unwrap();

    attestation.verify(&keychain, &nonce).unwrap();

    println!("success");
}

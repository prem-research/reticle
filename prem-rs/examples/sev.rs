use prem_rs::ClientBuilder;
use snp_attest::nonce::SevNonce;

#[tokio::main]
async fn main() {
    let client = ClientBuilder::new("http://localhost:4000/")
        .build()
        .unwrap();

    let res = client.request_attestation(SevNonce::new()).await.unwrap();

    println!("success");
}

use prem_rs::ClientBuilder;
use snp_attest::kds::Kds;

#[tokio::main]
async fn main() {
    let kds = Kds::new("http://localhost:8443").unwrap();
    let client = ClientBuilder::new("http://localhost:8000/")
        .with_kds(kds)
        .build()
        .unwrap();

    // let nonce = SevNonce::new();
    // let attestation = client.request_sev(&nonce).await.unwrap();
    // let keychain = kds::fetch_certificates(&attestation).await.unwrap();

    // attestation.verify(&keychain, &nonce).unwrap();

    // println!("success");

    // let nonce = NvidiaNonce::generate();
    // let attestation = client.request_nvidia(&nonce).await.unwrap();
    // let keychain = nvidia_attest::keychain::fetch_keychain().await.unwrap();

    // let parsed = attestation.verify(&keychain).unwrap();
    // parsed.validate(&nonce).unwrap();

    let result = client.attest(None).await.unwrap();
    // println!("{result}");
}

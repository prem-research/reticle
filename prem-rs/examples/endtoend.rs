use prem_rs::ClientBuilder;
use snp_attest::kds::Kds;

#[tokio::main]
async fn main() {
    let client = ClientBuilder::new("http://localhost:8000/")
        .build()
        .await
        .unwrap();

    let result = client.attest(None).await.unwrap();
    // println!("{result}");
}

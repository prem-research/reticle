use reticle::{ClientBuilder, query::QueryParams};
use snp_attest::kds::Kds;

#[tokio::main]
async fn main() {
    let api_url = std::env::args()
        .nth(1)
        .expect("must supply api url as first argument");

    let kds = Kds::default();
    let client = ClientBuilder::new(&api_url)
        .with_kds(kds)
        .build()
        .await
        .unwrap();

    let result = client.attest2().await.unwrap();
    println!("{result:?}");
}

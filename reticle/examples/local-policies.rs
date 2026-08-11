use reticle::{ClientBuilder, rego::FilePolicies};
use snp_attest::kds::Kds;

#[tokio::main]
async fn main() {
    let api_url = std::env::args()
        .nth(1)
        .expect("must supply api url as first argument");

    let kds = Kds::default();
    let client = ClientBuilder::new(&api_url)
        .with_kds(kds)
        .with_policy_provider(FilePolicies::new("./examples/policies/"))
        .build()
        .await
        .unwrap();

    // let result = client.attest().await.unwrap();
    // println!("{result:?}");
    //
    todo!()
}

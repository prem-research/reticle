use reticle::{ClientBuilder, rego::FilePolicies};
use snp_attest::kds::Kds;

#[tokio::main]
async fn main() -> libattest::Result<()> {
    let api_url = std::env::args()
        .nth(1)
        .expect("must supply api url as first argument");

    let kds = Kds::default();
    let client = ClientBuilder::new(&api_url)
        .with_kds(kds)
        .with_policy_provider(FilePolicies::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/policies/"
        )))
        .build()
        .await?;

    let result = client.attest().await.unwrap();
    println!("{result:?}");

    Ok(())
}

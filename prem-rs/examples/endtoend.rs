use prem_rs::ClientBuilder;

#[tokio::main]
async fn main() {
    let api_url = std::env::args()
        .nth(1)
        .expect("must supply api url as first argument");

    let client = ClientBuilder::new(&api_url).build().await.unwrap();

    let result = client.attest(None).await.unwrap();
    println!("{result:?}");
}

use prem_rs::rego::PoliciesClient;

#[tokio::test]
async fn fetch_validator() {
    let policies = PoliciesClient::new("https://policies.prem.io").unwrap();
    let validator = policies.fetch_validator().await.unwrap();

    // validator.verify_claims(claims);
    println!("{validator:?}");
}

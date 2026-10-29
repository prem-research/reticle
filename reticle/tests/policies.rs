use reticle::{
    rego::{PolicyProvider, UrlPolicies},
    sigstore::fetch_sigstore,
};

const TRUSTBASE: &str = "https://trustbase.prem.io";

#[tokio::test]
async fn fetch_validator() {
    let sigstore = fetch_sigstore(TRUSTBASE, libattest::HTTP_TIMEOUT)
        .await
        .unwrap();
    let policies = UrlPolicies::new(TRUSTBASE).unwrap();
    let validator = policies
        .fetch_validator(&sigstore, libattest::HTTP_TIMEOUT)
        .await
        .unwrap()
        .build()
        .unwrap();

    println!("{validator:?}");
}

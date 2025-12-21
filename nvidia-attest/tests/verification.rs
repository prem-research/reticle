use nvidia_attest::{EATToken, keychain::KeyChain};

// const EAT_EXAMPLE: &'static str = include_str!("./eat_example.json");

#[tokio::test]
async fn get_chain() {
    let _ = KeyChain::fetch_keychain().await.unwrap();
}

#[tokio::test]
async fn test_validation() {
    let mut args = std::env::args().skip(1);
    let report = args
        .next()
        .expect("expected attestation report in first argument ");
    let nonce = args.next().expect("expected nonce in second argument");

    let report = tokio::fs::read_to_string(report).await.unwrap();

    let token = EATToken::parse(&report).unwrap();
    let chain = KeyChain::fetch_keychain().await.unwrap();
    let decoded = token.verify(&chain).unwrap();

    // let nonce = "0000000000000000000000000000000000000000000000000000000000000000"; // this is the nonce requested when asking the server for attestation

    // decoded.validate(nonce).unwrap();

    // panic!("{decoded:?}");
}

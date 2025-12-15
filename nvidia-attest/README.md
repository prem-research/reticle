# Example workflow

```rust
async fn main() {
    let chain = KeyChain::fetch_keychain().await.unwrap();
    let token = EATToken::parse(EAT_EXAMPLE).unwrap();

    let decoded = token.verify(&chain).unwrap();

    let nonce = "..."; // this is the nonce requested when asking the server for attestation
    decoded.validate().unwrap();

    panic!("{decoded:?}");
}
```

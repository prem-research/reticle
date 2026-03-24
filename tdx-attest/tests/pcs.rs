use tdx_attest::{error::Context, pcs::Pcs};

const QUOTE: &[u8] = include_bytes!("./tdx_quote");

#[tokio::test]
async fn qe_identity() -> anyhow::Result<()> {
    // let input = std::fs::read("./examples/tdx_quote").unwrap();
    // let quote = Quote::from_bytes(&input)?;

    let pcs = Pcs::new("https://pccs.phala.network")?;

    pcs.fetch_qe_identity()
        .await
        .context("failed fetching qe identity")?;

    todo!()
}

use tdx_attest::{Quote, dcap::parser::ParseErrorExt, pcs::Pcs, verify};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let input = std::fs::read("./examples/quote.dat").unwrap();
    let quote = Quote::from_bytes(&input)?;

    // let quote = TdQuote::parse(&input[..]).unwrap();
    // let quote_data = quote.certification.quote_data;
    // let QeCertificationData::QeReportCertificationData(data) = quote_data else {
    //     panic!()
    // };

    // let QeCertificationData::PckChain(chain) = data.certification_data else {
    //     panic!()
    // };

    // let chain = CertificateChain::parse_pem_chain(chain).unwrap();
    // // let chain = String::from_utf8_lossy(chain);

    // println!("{quote:?}");

    // let fmspc = quote.certification().sgx_extensions()?.fmspc().unwrap();
    // dbg!(fmspc);

    // let fmspc = quote
    //     .certification()
    //     .sgx_extensions()?
    //     .fmspc()
    //     .context("context")?;

    let pcs = Pcs::new("https://pccs.prem.io/")?;
    // let tcb = pcs.fetch_tcb_info(fmspc).await?;

    let collateral = pcs.fetch_collateral(&quote).await?;

    verify::verify(&quote, &collateral, &[0x00; 64])?;

    println!("Verification success");
    // println!("{identity:?}");

    Ok(())
}

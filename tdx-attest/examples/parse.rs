use tdx_attest::{Quote, dcap::parser::ParseErrorExt, pcs::Pcs};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let input = std::fs::read("./examples/tdx_quote").unwrap();
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

    let fmspc = quote
        .certification()
        .sgx_extensions()?
        .fmspc()
        .context("context")?;

    let pcs = Pcs::new("https://pccs.phala.network")?;
    let tcb = pcs.fetch_tcb_info(fmspc).await?;

    pcs.fetch_crl(tdx_attest::certificates::IntermediateCa::Platform)
        .await?;

    // println!("{identity:?}");

    Ok(())
}

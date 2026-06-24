use azure_attest::collateral::ReportVerifierBuilder;
use libattest::error::Context;
use snp_attest::{kds::Kds, verify::SevQuoteVerifier};

const ATTESTATION: &'static str = include_str!("./attestation.json");

#[test]
fn decode_attestation() {
    let attestation: azure_attest::AzureQuote = serde_json::from_str(ATTESTATION).unwrap();
}

#[tokio::test]
async fn verify_attestation() {
    let quote: azure_attest::AzureQuote = serde_json::from_str(ATTESTATION).unwrap();

    let kds = Kds::default();

    let verifier = ReportVerifierBuilder::new()
        .sev(async |quote| {
            kds.fetch_certificates(quote)
                .await
                .map(SevQuoteVerifier::new)
        })
        .tdx(async |_| todo!())
        .fetch_collateral(&quote)
        .await
        .unwrap();

    azure_attest::verify::verify(quote, verifier).unwrap();
}

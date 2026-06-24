use azure_attest::collateral::AzureVerifierBuilder;
use libattest::error::Context;
use snp_attest::{kds::Kds, verify::SevQuoteVerifier};

const ATTESTATION: &'static str = include_str!("./attestation.json");

#[test]
fn decode_attestation() {
    let attestation: azure_attest::AzureQuote = serde_json::from_str(ATTESTATION).unwrap();
}

#[tokio::test]
async fn verify_attestation() {
    let attestation: azure_attest::AzureQuote = serde_json::from_str(ATTESTATION).unwrap();
    let report = attestation.verify().unwrap();

    let kds = Kds::default();

    let verifier = AzureVerifierBuilder::new()
        .sev(async |quote| {
            kds.fetch_certificates(quote)
                .await
                .map(SevQuoteVerifier::new)
                .context("lol")
        })
        .tdx(async |_| todo!())
        .fetch_collateral(&report)
        .await
        .unwrap();

    report.verify(&verifier).unwrap();

    todo!()
}

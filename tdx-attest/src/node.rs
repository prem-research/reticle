//! Raw TDX node verification, independent of the PodVM session protocol.
//!
//! The caller supplies its trusted policy and reference data. Neither may come
//! from the node being verified. This operation attests a node at check time;
//! it does not bind a historical inference request or application to that node.

use libattest::{ByteNonce, quote::QuoteVerifier, validation::Validator};

use crate::{TdxQuote, nonce::TdxNonce, pcs::Pcs, verify::TdxQuoteVerifier};

/// Verify Intel signatures, collateral, module/platform security status and a
/// fresh caller challenge, then apply the caller's pinned measurement policy.
/// Returns only the verified quote body, encoded as JSON.
pub async fn verify_node(
    raw: &[u8],
    nonce_hex: &str,
    policy: &str,
    reference: &str,
    workload_policy: Option<&str>,
) -> Result<String, String> {
    if raw.is_empty()
        || raw.len() > 65_536
        || policy.is_empty()
        || policy.len() > 65_536
        || reference.len() > 65_536
        || workload_policy.is_some_and(|p| p.is_empty() || p.len() > 65_536)
        || nonce_hex.len() != 128
    {
        return Err("Invalid verification input size".into());
    }
    let nonce: [u8; 64] = hex::decode(nonce_hex)
        .map_err(|_| "Invalid nonce")?
        .try_into()
        .map_err(|_| "Invalid nonce length")?;
    let quote = TdxQuote::from_bytes(raw).map_err(|e| format!("Quote parsing: {e:?}"))?;
    let pcs = Pcs::new("https://pccs.prem.io/")
        .map_err(|e| format!("Collateral configuration: {e:?}"))?;
    let collateral = pcs
        .fetch_collateral(&quote)
        .await
        .map_err(|e| format!("Collateral: {e:?}"))?;
    let verifier = TdxQuoteVerifier::new(collateral);
    let claims = verifier
        .verify(&quote, &TdxNonce::new(ByteNonce::from(&nonce)))
        .map_err(|e| format!("Hardware verification: {e:?}"))?;
    let mut builder = Validator::builder()
        .add_policy(policy)
        .add_data_json(reference)
        .map_err(|e| format!("Reference: {e:?}"))?;
    if let Some(workload) = workload_policy {
        builder = builder.add_policy(workload);
    }
    let validator = builder.build().map_err(|e| format!("Policy: {e:?}"))?;
    validator
        .evaluate("tdx.allow", &claims)
        .and_then(|result| result.or_err("Platform policy denied"))
        .map_err(|e| format!("Policy verification: {e:?}"))?;
    if workload_policy.is_some() {
        validator
            .evaluate("workload.allow", &claims)
            .and_then(|result| result.or_err("Workload policy denied"))
            .map_err(|e| format!("Policy verification: {e:?}"))?;
    }
    serde_json::to_string(claims).map_err(|_| "Cannot serialize verified measurements".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_invalid_input_before_contacting_collateral_service() {
        let nonce = "00".repeat(64);
        assert!(
            verify_node(&[], &nonce, "policy", "{}", None)
                .await
                .unwrap_err()
                .starts_with("Invalid")
        );
        assert!(
            verify_node(&[0; 16], "00", "policy", "{}", None)
                .await
                .unwrap_err()
                .starts_with("Invalid")
        );
        assert!(
            verify_node(&[0; 16], &nonce, "", "{}", None)
                .await
                .unwrap_err()
                .starts_with("Invalid")
        );
        assert!(
            verify_node(&[0; 16], &nonce, "policy", "{}", None)
                .await
                .unwrap_err()
                .starts_with("Quote parsing:")
        );
    }
}

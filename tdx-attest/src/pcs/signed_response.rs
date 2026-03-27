use std::marker::PhantomData;

use crate::{
    ca::INTEL_CA,
    error::{Context, TdxError},
};
use anyhow::bail;
use chrono::Utc;
use p256::ecdsa::Signature;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use signature::Verifier;

use crate::certificates::CertificateChain;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Header {
    issue_date: chrono::DateTime<Utc>,
    next_update: chrono::DateTime<Utc>,
}

/// Every signed response from the PCS has these 3 things.
pub struct SignedResponse<T> {
    chain: CertificateChain,
    signature: Signature,

    header: Header,
    data: serde_json::Value,

    _data_type: PhantomData<T>,
}

impl<T> SignedResponse<T> {
    /// verifies the signature attached to the json data returned by the PCS. Unlocks the
    /// inner data upon verification
    ///
    /// # Errors
    /// Returns error upon either:
    /// - the expected data of the
    pub fn verify_signature(self) -> Result<T, TdxError>
    where
        T: DeserializeOwned,
    {
        let now = chrono::Utc::now();

        if self.header.issue_date > now {
            return TdxError::msg("pcs response signature has a later issue_date than now");
        }

        if self.header.next_update < now {
            return TdxError::msg("pcs response signature has expired content");
        }

        // message is re-compacted json. Intel documentation explicitly states
        // that the signature must be checked upon this format of data.
        let msg = serde_json::to_vec(&self.data)
            .context("failed re-serializing data into compact json")?;

        // verify signature and message using certificate chain
        self.chain
            .verify(&msg, &self.signature)
            .context("signed response has a bad signature")?;

        let data = T::deserialize(&self.data).context("response data is in the wrong format")?;

        Ok(data)
    }
}

/// Helper method for [`reqwest::Response`] to parse a signed response off of pcs
pub(super) trait ParseSignedResponse {
    async fn parse_signed_response<T: DeserializeOwned>(
        self,
        chain_header: &str,
        data_field: &str,
    ) -> Result<SignedResponse<T>, TdxError>;
}

impl ParseSignedResponse for reqwest::Response {
    async fn parse_signed_response<T: DeserializeOwned>(
        self,
        chain_header: &str,
        data_field: &str,
    ) -> Result<SignedResponse<T>, TdxError> {
        let chain = self
            .headers()
            .get(chain_header)
            .context("response does not contain certificate chain header")?
            .as_bytes();
        let chain = urlencoding::decode_binary(chain);

        // anchor our trust in embedded intel_ca, still parsing pem chain from
        // response
        let chain = CertificateChain::with_anchor(&INTEL_CA)
            .parse_pem_chain(&chain)
            .context("failed parsing certificate chain from header")?;

        let PcsResponse { signature, data }: PcsResponse = self.json().await?;
        let signature = Signature::from_slice(&signature).context("failed decoding signature")?;

        // Since data was a flatten map over the remaining fields (except signature)
        // we now have to extract the contents of the actual data field we specified
        let Value::Object(mut map) = data else {
            return TdxError::msg("invalid data object in response does not contain a map");
        };

        let data = map
            .remove(data_field)
            .context("invalid data object does not contain specified data field")?;

        let header = Header::deserialize(&data)
            .context("failed to deserialize signature header from pcs response")?;

        Ok(SignedResponse {
            chain,
            signature,
            header,
            data,
            _data_type: PhantomData,
        })
    }
}

#[derive(Deserialize)]
struct PcsResponse {
    #[serde(flatten)]
    data: serde_json::Value,
    #[serde(deserialize_with = "hex::serde::deserialize")]
    signature: [u8; 64],
}

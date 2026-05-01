use std::{convert::Infallible, fmt::Display};

use libattest::error::AttestationError;
use reqwest::{IntoUrl, Response};
use serde::{Deserialize, Serialize};

use crate::Client;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
struct GatewayError {
    #[cfg_attr(target_family = "wasm", wasm_bindgen(getter_with_clone))]
    #[serde(rename = "error")]
    pub message: String,
}

impl Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

async fn response_to_error(response: Response) -> Result<Infallible, AttestationError> {
    let error: GatewayError = response.json().await?;
    let error = AttestationError::with_root(error);

    Err(error)
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl Client {
    pub(crate) async fn request(
        &self,
        url: impl IntoUrl,
        query: &impl Serialize,
    ) -> Result<Response, AttestationError> {
        let response = self.reqwest_client.get(url).query(query).send().await?;

        if !response.status().is_success() {
            response_to_error(response).await?;
            unreachable!()
        }

        Ok(response)
    }
}

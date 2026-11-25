use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Kata Init-Data shared by the attestation server and verifier.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct InitDataDocument {
    pub algorithm: String,
    pub version: String,
    pub data: BTreeMap<String, String>,
}

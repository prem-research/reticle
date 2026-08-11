use std::{collections::HashMap, ops::Deref};

use jsonwebtoken::{DecodingKey, Validation};
use libattest::{
    AttestationError, bail,
    error::{Context, Expose},
    quote::QuoteVerifier,
};
use sha2::{Digest, Sha256};

use crate::{
    DecodedClaims, EATToken,
    keychain::KeyChain,
    nonce::NvidiaNonce,
    types::{GpuClaims, MeasuresClaim, OverallClaims},
};

pub struct NvidiaVerifier {
    keychain: KeyChain,
}

impl NvidiaVerifier {
    pub fn new(keychain: KeyChain) -> Self {
        Self { keychain }
    }
}

impl QuoteVerifier for NvidiaVerifier {
    type Nonce = NvidiaNonce;
    type Quote = EATToken;

    fn verify(
        &self,
        quote: &EATToken,
        nonce: &NvidiaNonce,
    ) -> Result<DecodedClaims, AttestationError> {
        // decoding the header beforehand is necessary to gain the kid
        let jwt_header = jsonwebtoken::decode_header(&quote.overall)?;

        let key = jwt_header
            .kid
            .context("missing field kid from jwt headers")
            .and_then(|kid| self.keychain.find(&kid).context("missing key from jwks"))?;

        let key = DecodingKey::from_jwk(key)?;

        // setup validation requirements (just expiration and algorithm for now)
        let mut validation = Validation::new(jwt_header.alg);
        validation.set_required_spec_claims(&["exp"]); // validate expiration (internal jwt stuff should work right)

        // decode and verify overall claims with the correct key
        let overall_claims =
            jsonwebtoken::decode::<OverallClaims>(&quote.overall, &key, &validation)?.claims;

        // hashes from calculated from the JWTs of the detached claims
        let gpu_hashes: HashMap<&str, _> = quote
            .gpu
            .iter()
            .map(|(k, v)| (k.as_ref(), Sha256::digest(v)))
            .collect();

        // do hashed jwts match with overall claims?
        for (gpu, digest) in &overall_claims.submods {
            let hash = gpu_hashes.get(gpu.deref()).context(
                "overall jwt claims require a submodule that was not found in the detached claims",
            ).expose_error()?;

            if hash.deref() != digest.digest() {
                return AttestationError::exposed(
                    "digest mismatch between submodule claims and detached submodules",
                );
            }
        }

        let mut gpu_claims = HashMap::new();

        for (gpu, gpu_jwt) in &quote.gpu {
            let header = jsonwebtoken::decode_header(gpu_jwt)?;
            let key = header
                .kid
                .context("missing field kid from jwt headers")
                .and_then(|kid| {
                    self.keychain
                        .find(&kid)
                        .context("jwk server does not have our key")
                })?;

            let key = DecodingKey::from_jwk(key)?;

            let decoded =
                jsonwebtoken::decode::<GpuClaims>(&gpu_jwt, &key, &Validation::new(header.alg))
                    .context("gpu module signature error")?;

            if decoded.claims.measres != MeasuresClaim::Success {
                bail!("gpu claim contained failed measres");
            }

            gpu_claims.insert(gpu.clone(), decoded.claims);
        }

        // nonce checking
        if overall_claims.eat_nonce != nonce.as_ref() {
            bail!(exposed: "mismatched nvidia nonce");
        }

        if !gpu_claims
            .iter()
            .all(|(_, claim)| claim.eat_nonce == nonce.as_ref())
        {
            bail!(exposed: "mismatched nvidia nonce in one or more gpu modules");
        }

        Ok(DecodedClaims {
            overall_claims,
            gpu_claims,
        })
    }
}

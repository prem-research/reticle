pub mod rewrite;

use std::collections::BTreeMap;

use crate::{
    ohttp::rewrite::{BHTTPRequest, OHTTPResponder, ProxyClient},
    response::{ApiJsonResult, ApiResult},
};
use anyhow::Context;
use attestation_protocol::report::manifest::{PodKey, PodManifest};
use bhttp::stream::AsyncReadMessage;
use ohttp::{
    KeyConfig,
    hpke::{Aead, Kdf, Kem},
};
use reqwest::Url;
use rocket::{Data, State, data::ToByteUnit, get, http::uri::Origin, response::Responder};
use serde::Deserialize;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

#[derive(Deserialize)]
struct RouteEntry {
    path: String,
    forward_to: Url,
}

#[derive(Deserialize)]
pub struct ReverseProxyConfig {
    routes: Vec<RouteEntry>,
}

impl ReverseProxyConfig {
    pub fn build(self) -> anyhow::Result<ReverseProxy> {
        let client = ProxyClient::new();
        let routes = self
            .routes
            .into_iter()
            .map(|RouteEntry { path, forward_to }| {
                let origin = Origin::parse(&path).map_err(|error| {
                    anyhow::anyhow!("invalid reverse proxy route {path:?}: {error}")
                })?;
                Ok((
                    origin.path().as_str().to_owned(),
                    RouteSettings {
                        base_url: forward_to,
                    },
                ))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;

        Ok(ReverseProxy { client, routes })
    }
}

#[derive(Deserialize)]
pub struct RouteSettings {
    base_url: Url,
}

pub struct ReverseProxy {
    client: ProxyClient,
    routes: BTreeMap<String, RouteSettings>,
}

impl ReverseProxy {
    pub fn search(&self, path: &Origin<'_>) -> Option<(&str, &RouteSettings)> {
        let (path, route) = self.routes.iter().rev().find(|(route, _)| {
            path.path()
                .as_str()
                .strip_prefix(route.as_str())
                .is_some_and(|suffix| {
                    suffix.is_empty() || route.as_str().ends_with('/') || suffix.starts_with('/')
                })
        })?;

        Some((path.as_str(), route))
    }

    pub fn client(&self) -> &ProxyClient {
        &self.client
    }

    pub fn reroute(&self, url: &Origin<'static>) -> Option<Url> {
        let (prefix, settings) = self.search(url)?;
        let suffix = url.path().as_str().strip_prefix(prefix)?;
        let mut target = settings.base_url.clone();
        if target.cannot_be_a_base() {
            return None;
        }

        if !suffix.is_empty() {
            let path = format!(
                "{}/{}",
                target.path().trim_end_matches('/'),
                suffix.trim_start_matches('/')
            );
            // Set only the path so the request cannot replace the configured host.
            target.set_path(&path);
        }
        target.set_query(url.query().map(|query| query.as_str()));
        target.set_fragment(None);

        Some(target)
    }
}

/// Audit: Cloudflare has verified that the key generation
/// behind the ohttp rust library uses a secure system random generator
/// and has found no obvious security flaw in it
///
/// to be independently audited
pub fn generate_key_server() -> ohttp::Server {
    let symmetric = vec![
        ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm),
        ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305),
    ];

    let config =
        KeyConfig::new(1, Kem::XWing, symmetric).expect("invalid key generation configuration");

    ohttp::Server::new(config).expect("unable to create ohttp server with this configuration")
}

#[rocket::post("/", data = "<request>")]
pub async fn ohttp_tunnel<'r>(
    request: Data<'r>,
    reverse_proxy: &'r State<ReverseProxy>,
    ohttp_server: &'r State<ohttp::Server>,
) -> ApiResult<impl Responder<'r, 'static>> {
    // request.
    let server = ohttp::Server::clone(ohttp_server);
    let request = request.open(20.megabytes());
    let mut request = server.decapsulate_stream(request.compat());
    // request.

    let mut async_request = bhttp::Message::async_read(&mut request);
    let header = async_request
        .header()
        .await
        .context("failed getting headers from OHTTP request")?;

    let forwarded_request = BHTTPRequest::from_bhttp(header, async_request)?;
    let rerouted = State::inner(reverse_proxy)
        .reroute(forwarded_request.path())
        .context("couldn't find the correct route where to reroute the OHTTP request")?;

    // forwarded_request.
    // make the request to the backend server
    let response = reverse_proxy
        .client()
        .reroute(forwarded_request, rerouted)
        .await?;

    // Consume remaining BHTTP padding and verify OHTTP's final chunk.
    // Missing or invalid final authentication causes an error here.
    futures::io::copy(&mut request, &mut futures::io::sink())
        .await
        .context("failed sinking the rest of the request")?;

    let responder = OHTTPResponder::new(response, move |to| {
        request.response(to.compat_write()).unwrap()
    });

    Ok(responder)
}

#[get("/key_config")]
/// INSECURELY (for the client ofc) return the key information without performing attestation.
pub async fn key_config(ohttp_server: &State<PodManifest>) -> ApiJsonResult<Option<PodKey>> {
    Ok(ohttp_server.ohttp_key_config.clone().into())
}

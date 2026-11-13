//! Reqwest transport and reqwest-middleware integration.

use std::{io, pin::Pin};

use bytes::Bytes;
use futures::{Stream, TryStreamExt, io::AsyncRead};
use http::{HeaderValue, Method, header};
use reqwest::Url;

use super::middleware::{OhttpMiddleware, REQUEST_TYPE, RESPONSE_TYPE};
use super::{HttpRequest, HttpResponse};

use http::Extensions;
use reqwest::{Body, ResponseBuilderExt};
pub use reqwest::{Request, Response};
pub use reqwest_middleware::RequestBuilder;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, Middleware, Next};

pub(super) type ByteStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send>>;
pub(super) type Reader = Pin<Box<dyn AsyncRead + Send>>;
pub(super) type Producer = futures::future::BoxFuture<'static, io::Result<()>>;

/// Encapsulates each request in a fresh chunked OHTTP exchange.
///
/// The underlying client must disable redirects, retries, decompression,
/// cookies, and sensitive default headers. Downstream middleware sees the
/// outer request. Use [`super::OHTTPClient`] for a configured transport.
#[derive(Clone, Debug)]
pub struct OhttpReqwest(OhttpMiddleware);

impl OhttpReqwest {
    pub fn new(endpoint: Url, key_config: ohttp::KeyConfig) -> reqwest_middleware::Result<Self> {
        OhttpMiddleware::new(endpoint, key_config)
            .map(Self)
            .map_err(reqwest_middleware::Error::middleware)
    }
}

#[derive(Clone, Debug)]
pub(super) struct Provider {
    client: ClientWithMiddleware,
}

impl Provider {
    pub(super) fn new(middleware: OhttpMiddleware) -> reqwest_middleware::Result<Self> {
        let transport = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .build()?;
        Ok(Self {
            client: ClientBuilder::new(transport)
                .with(OhttpReqwest(middleware))
                .build(),
        })
    }

    pub(super) fn request(&self, method: Method, url: Url) -> RequestBuilder {
        self.client.request(method, url)
    }

    pub(super) async fn execute(&self, request: Request) -> reqwest_middleware::Result<Response> {
        self.client.execute(request).await
    }
}

#[async_trait::async_trait]
impl Middleware for OhttpReqwest {
    async fn handle(
        &self,
        mut request: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let wrap = reqwest_middleware::Error::middleware;
        let url = request.url().clone();
        // Reqwest exposes byte streams on Response, but not on Body itself.
        let body = Response::from(http::Response::new(
            request.body_mut().take().unwrap_or_default(),
        ))
        .bytes_stream()
        .map_err(io::Error::other);
        let logical = HttpRequest {
            method: request.method().clone(),
            url: url.clone(),
            headers: request.headers().clone(),
            body: Box::pin(body),
        };
        let timeout = request.timeout().copied();
        let decoded = self
            .0
            .handle(logical, |endpoint, body| async move {
                let mut outer = Request::new(Method::POST, endpoint);
                *outer.timeout_mut() = timeout;
                outer
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, HeaderValue::from_static(REQUEST_TYPE));
                outer
                    .headers_mut()
                    .insert(header::ACCEPT, HeaderValue::from_static(RESPONSE_TYPE));
                *outer.body_mut() = Some(Body::wrap_stream(body));
                let outer = next
                    .run(outer, extensions)
                    .await
                    .map_err(io::Error::other)?;
                Ok(HttpResponse {
                    status: outer.status(),
                    headers: outer.headers().clone(),
                    body: Box::pin(outer.bytes_stream().map_err(io::Error::other)),
                })
            })
            .await
            .map_err(wrap)?;
        let mut response = http::Response::builder()
            .status(decoded.status)
            .url(url)
            .body(Body::wrap_stream(decoded.body))
            .map_err(reqwest_middleware::Error::middleware)?;
        *response.headers_mut() = decoded.headers;
        Ok(response.into())
    }
}

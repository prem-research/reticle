//! Backpressure-driven chunked OHTTP, using reqwest natively and Fetch on WASM.
//!
//! Successful body EOF includes verification of the final OHTTP chunk. Unread
//! response suffixes are not authenticated. Cancel browser bodies when abandoning
//! them; native bodies release their resources on drop.
//! Informational responses and trailers are validated but not exposed.
//!
//! The WASM client accepts browser Requests and returns browser Responses. Streamed
//! uploads are buffered by default for browser and HTTP/1 compatibility. Opt-in
//! streamed uploads require browser support and HTTP/2 or HTTP/3. Both modes
//! require appropriate relay CORS and preserve streaming responses.

use std::rc::Rc;

use http::{HeaderMap, Method, StatusCode};
use libattest::error::Context;
use reqwest::Url;

mod body;
#[cfg(target_arch = "wasm32")]
mod browser;
mod codec;
mod middleware;
#[cfg(not(target_arch = "wasm32"))]
mod native;

#[cfg(target_arch = "wasm32")]
use browser as transport;
use middleware::OhttpMiddleware;
#[cfg(not(target_arch = "wasm32"))]
use native as transport;
#[cfg(not(target_arch = "wasm32"))]
pub use native::OhttpReqwest;
use transport::{ByteStream, Producer, Reader};
pub use transport::{Request, RequestBuilder, Response};

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::AttestResult;

/// A streaming OHTTP client with a target-specific middleware provider.
///
/// Native requests use reqwest; WASM requests use browser Request/Response
/// objects. Both providers use the same OHTTP middleware and protocol pipeline.
#[derive(Clone, Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen)]
pub struct AttestedHttp {
    provider: transport::Provider,
}

impl AttestedHttp {
    pub fn request(&self, method: Method, url: Url) -> RequestBuilder {
        self.provider.request(method, url)
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
impl AttestedHttp {
    /// Enable streaming uploads instead of the browser-compatible buffered default.
    ///
    /// Requires streaming Fetch support and HTTP/2 or HTTP/3. Failed requests
    /// are not retried, since replaying a POST could duplicate side effects.
    #[cfg(target_arch = "wasm32")]
    pub fn with_streaming_uploads(mut self) -> Self {
        self.provider.streaming_uploads = true;
        self
    }

    #[wasm_bindgen(constructor)]
    pub fn new(attestation: &AttestResult) -> libattest::Result<AttestedHttp> {
        let gateway_url = attestation.attested_url.join("/gateway")?;

        let key = attestation
            .manifest
            .ohttp_key_config
            .clone()
            .context("this attestation does not provide an ohttp key")?;

        let provider = transport::Provider::new(OhttpMiddleware::new(gateway_url, key.key_config))
            .context("could not build http provider")?;

        Ok(AttestedHttp { provider })
    }

    pub async fn make_request(&self, request: Request) -> libattest::Result<Response> {
        let response = self
            .provider
            .execute(request)
            .await
            .context("failed making attested http request")?;

        Ok(response)
    }

    #[cfg(target_family = "wasm")]
    pub fn fetch_client(&self) -> web_sys::js_sys::Function {
        type Fetch = dyn Fn(JsValue, Option<web_sys::RequestInit>) -> web_sys::js_sys::Promise;

        // we wrap the current configuration into
        // reference count because the data might be moved
        // across many different fetches and uncoupled promises
        let client = Rc::new(self.clone());

        // we wrap a fetch implementation that takes
        // generic jsvalue parameters, just like the real fetch
        let fetch_impl =
            move |input: JsValue, init: Option<web_sys::RequestInit>| -> web_sys::js_sys::Promise {
                // we cast it into a request type

                // cheap clone, the inners are Rc
                let client = client.clone();

                wasm_bindgen_futures::future_to_promise(async move {
                    let input = input.unchecked_ref();
                    let init = init.unwrap_or_default();

                    let request = web_sys::Request::new_with_request_and_init(input, &init)?;

                    client
                        .make_request(request)
                        .await
                        .map(Into::into)
                        .map_err(Into::into)
                })
            };

        Closure::<Fetch>::new(fetch_impl)
            .into_js_value()
            .unchecked_into()
    }
}

struct HttpRequest {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: ByteStream,
}

struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: ByteStream,
}

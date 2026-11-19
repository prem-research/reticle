//! Streaming Fetch transport and browser stream lifecycle management.

use std::{io, pin::Pin};

use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt, io::AsyncRead, stream};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use reqwest::Url;

use super::codec::invalid;
use super::middleware::{OhttpMiddleware, REQUEST_TYPE, RESPONSE_TYPE};
use super::{HttpRequest, HttpResponse};

use futures::{
    future::{AbortHandle, Abortable},
    lock::Mutex,
};
use std::rc::Rc;
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use web_sys::js_sys::{self, Array, Promise, Uint8Array};

pub(super) type ByteStream = Pin<Box<dyn Stream<Item = io::Result<Bytes>>>>;
pub(super) type Reader = Pin<Box<dyn AsyncRead>>;
pub(super) type Producer = futures::future::LocalBoxFuture<'static, io::Result<()>>;

// Rust owns framing and crypto; JavaScript only bridges browser IO.
#[wasm_bindgen(module = "/src/ohttp/browser.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name = ohttpReadable)]
    fn readable(source: OhttpByteSource) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = ohttpFetch)]
    fn start_fetch(
        url: &str,
        body: &JsValue,
        request: &web_sys::Request,
        request_type: &str,
        response_type: &str,
        streaming_uploads: bool,
    ) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = ohttpFetchPromise)]
    fn fetch_promise(handle: &JsValue) -> Promise;
    #[wasm_bindgen(js_name = ohttpAbortFetch)]
    fn abort_fetch(handle: &JsValue);
    #[wasm_bindgen(js_name = ohttpCancelStream)]
    fn cancel_stream(stream: &JsValue);
    #[wasm_bindgen(catch, js_name = ohttpGetReader)]
    fn get_reader(stream: &JsValue) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = ohttpRead)]
    fn read(reader: &JsValue) -> Promise;
    #[wasm_bindgen(js_name = ohttpReleaseReader)]
    fn release_reader(reader: &JsValue);
    #[wasm_bindgen(js_name = ohttpRequestBody)]
    fn request_body(request: &web_sys::Request) -> JsValue;
    #[wasm_bindgen(js_name = ohttpResponseBody)]
    fn response_body(response: &web_sys::Response) -> JsValue;
    #[wasm_bindgen(catch, js_name = ohttpResponse)]
    fn make_response(
        body: &JsValue,
        status: u16,
        headers: &Array,
    ) -> Result<web_sys::Response, JsValue>;
}

pub use web_sys::{Request, Response};
pub type RequestBuilder = io::Result<Request>;

#[derive(Clone, Debug)]
pub(super) struct Provider {
    middleware: OhttpMiddleware,
    pub(super) streaming_uploads: bool,
}

impl Provider {
    pub(super) fn new(middleware: OhttpMiddleware) -> reqwest_middleware::Result<Self> {
        Ok(Self {
            middleware,
            streaming_uploads: false,
        })
    }

    pub(super) fn request(&self, method: Method, url: Url) -> RequestBuilder {
        let init = web_sys::RequestInit::new();
        init.set_method(method.as_str());
        Request::new_with_str_and_init(url.as_str(), &init).map_err(js_error)
    }

    pub(super) async fn execute(&self, request: Request) -> reqwest_middleware::Result<Response> {
        let wrap = reqwest_middleware::Error::middleware;
        let logical = prepare_request(&request).map_err(wrap)?;
        let method = logical.method.clone();
        let decoded = self
            .middleware
            .handle(logical, |endpoint, body| {
                send(endpoint, body, &request, self.streaming_uploads)
            })
            .await
            .map_err(wrap)?;
        finish_response(decoded, method).await.map_err(wrap)
    }
}

fn prepare_request(request: &Request) -> io::Result<HttpRequest> {
    Ok(HttpRequest {
        method: Method::from_bytes(request.method().as_bytes()).map_err(invalid)?,
        url: Url::parse(&request.url()).map_err(invalid)?,
        headers: read_headers(&request.headers())?,
        body: body_stream(request_body(request), None)?,
    })
}

async fn send(
    endpoint: Url,
    body: ByteStream,
    request: &Request,
    streaming_uploads: bool,
) -> io::Result<HttpResponse> {
    let body = readable(OhttpByteSource::new(body)).map_err(js_error)?;
    let handle = start_fetch(
        endpoint.as_str(),
        &body,
        request,
        REQUEST_TYPE,
        RESPONSE_TYPE,
        streaming_uploads,
    )
    .map_err(|error| {
        cancel_stream(&body);
        js_error(error)
    })?;
    let guard = FetchGuard(handle);
    let outer: web_sys::Response = JsFuture::from(fetch_promise(&guard.0))
        .await
        .map_err(js_error)?
        .dyn_into()
        .map_err(js_error)?;
    let status = StatusCode::from_u16(outer.status()).map_err(invalid)?;
    let headers = read_headers(&outer.headers())?;
    let body = body_stream(response_body(&outer), Some(guard))?;
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

async fn finish_response(mut decoded: HttpResponse, method: Method) -> io::Result<Response> {
    let headers = Array::new();
    for (name, value) in &decoded.headers {
        let pair = Array::new();
        pair.push(&JsValue::from_str(name.as_str()));
        // Fetch header strings are ByteStrings, not UTF-8 strings.
        let value: String = value
            .as_bytes()
            .iter()
            .map(|&byte| char::from(byte))
            .collect();
        pair.push(&JsValue::from_str(&value));
        headers.push(&pair);
    }
    let body = if method == Method::HEAD || matches!(decoded.status.as_u16(), 204 | 205 | 304) {
        // Browser Response rejects bodies for these statuses. Authenticate
        // the empty body before constructing the corresponding response.
        while let Some(chunk) = decoded.body.try_next().await? {
            if !chunk.is_empty() {
                return Err(invalid("unexpected BHTTP response body"));
            }
        }
        JsValue::NULL
    } else {
        readable(OhttpByteSource::new(decoded.body)).map_err(js_error)?
    };
    make_response(&body, decoded.status.as_u16(), &headers).map_err(|error| {
        if !body.is_null() {
            cancel_stream(&body);
        }
        js_error(error)
    })
}

struct FetchGuard(JsValue);

impl Drop for FetchGuard {
    fn drop(&mut self) {
        abort_fetch(&self.0);
    }
}

struct BrowserReader {
    raw: JsValue,
    _fetch: Option<FetchGuard>,
}

impl Drop for BrowserReader {
    fn drop(&mut self) {
        release_reader(&self.raw);
    }
}

fn body_stream(body: JsValue, fetch: Option<FetchGuard>) -> io::Result<ByteStream> {
    if body.is_null() || body.is_undefined() {
        return Ok(Box::pin(stream::empty()));
    }
    let reader = BrowserReader {
        raw: get_reader(&body).map_err(js_error)?,
        _fetch: fetch,
    };
    Ok(Box::pin(stream::try_unfold(reader, |reader| async move {
        let value = JsFuture::from(read(&reader.raw)).await.map_err(js_error)?;
        if value.is_undefined() {
            return Ok(None);
        }
        let bytes = value
            .dyn_into::<Uint8Array>()
            .map_err(|_| invalid("Fetch body must contain Uint8Array chunks"))?;
        Ok(Some((Bytes::from(bytes.to_vec()), reader)))
    })))
}

fn read_headers(headers: &web_sys::Headers) -> io::Result<HeaderMap> {
    let mut result = HeaderMap::new();
    let entries = js_sys::try_iter(headers)
        .map_err(js_error)?
        .ok_or_else(|| invalid("Fetch headers are not iterable"))?;
    for entry in entries {
        let pair = Array::from(&entry.map_err(js_error)?);
        let name = pair
            .get(0)
            .as_string()
            .ok_or_else(|| invalid("invalid Fetch header name"))?;
        let value = pair
            .get(1)
            .as_string()
            .ok_or_else(|| invalid("invalid Fetch header value"))?;
        let value = value
            .chars()
            .map(|ch| u8::try_from(u32::from(ch)).map_err(invalid))
            .collect::<io::Result<Vec<_>>>()?;
        result.append(
            HeaderName::from_bytes(name.as_bytes()).map_err(invalid)?,
            HeaderValue::from_bytes(&value).map_err(invalid)?,
        );
    }
    Ok(result)
}

// JS owns this source and explicitly frees it on EOF, cancellation, or error.
// Returning a Promise synchronously releases wasm-bindgen's borrow before JS
// can cancel/free the source while a read is pending.
#[wasm_bindgen]
pub struct OhttpByteSource {
    stream: Rc<Mutex<ByteStream>>,
    abort: AbortHandle,
}

impl OhttpByteSource {
    fn new(stream: ByteStream) -> Self {
        let (abort, registration) = AbortHandle::new_pair();
        Self {
            stream: Rc::new(Mutex::new(Box::pin(Abortable::new(stream, registration)))),
            abort,
        }
    }
}

#[wasm_bindgen]
impl OhttpByteSource {
    pub fn next(&self) -> Promise {
        let stream = self.stream.clone();
        future_to_promise(async move {
            match stream.lock().await.next().await {
                Some(Ok(bytes)) => Ok(Uint8Array::from(bytes.as_ref()).into()),
                Some(Err(error)) => Err(JsValue::from_str(&error.to_string())),
                None => Ok(JsValue::UNDEFINED),
            }
        })
    }

    pub fn cancel(&self) {
        self.abort.abort();
    }
}

impl Drop for OhttpByteSource {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

fn js_error(error: JsValue) -> io::Error {
    let message = error.as_string().unwrap_or_else(|| format!("{error:?}"));
    io::Error::other(message)
}

use async_once_cell::OnceCell;
use libattest::{
    bail,
    error::{AttestationError, Context},
};
use reqwest::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, js_sys::Promise};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);

    #[wasm_bindgen(js_namespace = globalThis, js_name = fetch)]
    fn js_fetch(input: &JsValue) -> Promise;

    #[wasm_bindgen(js_namespace = globalThis, js_name = fetch)]
    fn js_fetch_with_init(input: &JsValue, init: &JsValue) -> Promise;
}

static FETCH_CLIENT: OnceCell<crate::Client> = OnceCell::new();

#[wasm_bindgen(js_name = fetch)]
pub async fn fetch(input: JsValue, init: Option<JsValue>) -> Result<JsValue, JsValue> {
    // Extract the URL from the input (it may be a Request object or a string)
    let mut url = extract_url(&input)?;

    // extract root of url
    url.set_path("/");

    let client = FETCH_CLIENT
        .get_or_try_init(async { crate::ClientBuilder::new(url.as_str()).build().await })
        .await?;

    // Build the attestation client and perform full attestation
    client.attest().await?;

    // --- Actual fetch ---
    let promise = match init {
        None => js_fetch(&input),
        Some(init) => js_fetch_with_init(&input, &init),
    };

    JsFuture::from(promise).await
}

/// Extract the URL string from a fetch input, which may be a `Request` object or a plain string.
fn extract_url(input: &JsValue) -> Result<Url, AttestationError> {
    let url = if let Some(url) = input.as_string() {
        url
    } else if let Some(request) = input.dyn_ref::<Request>() {
        request.url()
    } else {
        bail!("could not convert request to url")
    };

    let url = Url::parse(&url).context("failed parsing url from fetch request")?;

    Ok(url)
}

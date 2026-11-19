//! Shared OHTTP middleware and per-request encryption state.

use std::io;

use futures::{
    TryStreamExt,
    channel::{mpsc, oneshot},
    stream,
};
use http::{HeaderMap, Method, StatusCode, header};
use reqwest::Url;

use super::body::{ChannelWriter, driven_stream};
use super::codec::{decode_response, invalid, request_head, upload};
use super::{ByteStream, HttpRequest, HttpResponse, Reader};

pub(super) const REQUEST_TYPE: &str = "message/ohttp-chunked-req";
pub(super) const RESPONSE_TYPE: &str = "message/ohttp-chunked-res";

#[derive(Clone, Debug)]
pub(super) struct OhttpMiddleware {
    endpoint: Url,
    key_config: ohttp::KeyConfig,
}

impl OhttpMiddleware {
    pub(super) fn new(endpoint: Url, key_config: ohttp::KeyConfig) -> Self {
        Self {
            endpoint,
            key_config,
        }
    }

    pub(super) async fn handle<F, Fut>(
        &self,
        request: HttpRequest,
        send: F,
    ) -> io::Result<HttpResponse>
    where
        F: FnOnce(Url, ByteStream) -> Fut,
        Fut: std::future::Future<Output = io::Result<HttpResponse>>,
    {
        let Exchange { body, response } = Exchange::new(
            &request.method,
            &request.url,
            &request.headers,
            request.body,
            self.key_config.clone(),
        )?;

        let outer = send(self.endpoint.clone(), body).await?;
        response
            .decode(outer.status, &outer.headers, outer.body)
            .await
    }
}

struct Exchange {
    body: ByteStream,
    response: ResponseDecoder,
}

struct ResponseDecoder {
    sender: oneshot::Sender<ByteStream>,
    reader: Reader,
}

impl Exchange {
    fn new(
        method: &Method,
        url: &Url,
        headers: &HeaderMap,
        body: ByteStream,
        mut config: ohttp::KeyConfig,
    ) -> io::Result<Self> {
        let head = request_head(method, url, headers)?;
        let client = ohttp::ClientRequest::from_config(&mut config).map_err(io::Error::other)?;
        let (sender, receiver) = mpsc::channel(1);
        let writer = client
            .encapsulate_stream(ChannelWriter(sender))
            .map_err(io::Error::other)?;
        // Derive response keys before moving the encryptor into the upload. The
        // ciphertext source arrives later, without sharing mutable crypto state.
        let (response_tx, response_rx) = oneshot::channel::<ByteStream>();
        let source = stream::once(async move { response_rx.await.map_err(io::Error::other) })
            .try_flatten()
            .into_async_read();
        let reader = writer
            .response(Box::pin(source))
            .map_err(io::Error::other)?;
        let upload = Box::pin(upload(head, Box::pin(body.into_async_read()), writer));
        Ok(Self {
            body: driven_stream(upload, receiver),
            response: ResponseDecoder {
                sender: response_tx,
                reader: Box::pin(reader),
            },
        })
    }
}

impl ResponseDecoder {
    async fn decode(
        self,
        status: StatusCode,
        headers: &HeaderMap,
        body: ByteStream,
    ) -> io::Result<HttpResponse> {
        if status != StatusCode::OK {
            return Err(invalid(format!("OHTTP relay returned {status}")));
        }
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next());
        if !content_type.is_some_and(|value| value.trim().eq_ignore_ascii_case(RESPONSE_TYPE)) {
            return Err(invalid("unexpected OHTTP response content type"));
        }
        self.sender
            .send(body)
            .map_err(|_| invalid("OHTTP response decoder closed"))?;
        decode_response(self.reader).await
    }
}

use std::{marker::PhantomData, panic};

use anyhow::Context;
use bhttp::{ControlData, Mode, stream::AsyncMessage};
use reqwest::{
    Method, Url,
    header::{CONNECTION, HeaderMap, HeaderName, HeaderValue},
    redirect::Policy,
};
use rocket::{
    http::{ContentType, uri::Origin},
    response::Responder,
};
use tokio::io::{AsyncWrite, AsyncWriteExt, SimplexStream, WriteHalf};
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};

static NOPROXY_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

pub struct BHTTPRequest<S> {
    to: Origin<'static>,
    method: Method,
    headers: HeaderMap,
    body: AsyncMessage<S>,
}

impl<S> BHTTPRequest<S> {
    pub fn from_bhttp(header: bhttp::Header, body: AsyncMessage<S>) -> anyhow::Result<Self> {
        let bhttp::ControlData::Request {
            method,
            scheme,
            path,
            ..
        } = header.control()
        else {
            anyhow::bail!("expected a BHTTP request, received a response");
        };

        // general sanity checks of the request, they don't
        // really matter because we're gonna rewrite most of it anyway
        anyhow::ensure!(
            matches!(&scheme[..], b"http" | b"https"),
            "expected HTTP(S) scheme"
        );

        let method = Method::from_bytes(method).context("invalid method")?;

        let path = String::from_utf8(path.clone()).context("request path is not valid utf-8")?;
        let path =
            Origin::parse_owned(path).map_err(|_| anyhow::format_err!("failed parsing origin"))?;
        let path = path.into_normalized();

        let mut headers = HeaderMap::new();

        // we parse and insert the headers from the request into
        // out HeaderMap for forwarding
        for field in header.iter() {
            let name = HeaderName::from_bytes(field.name()).context("invalid BHTTP header name")?;
            let value =
                HeaderValue::from_bytes(field.value()).context("invalid BHTTP header value")?;
            headers.append(name, value);
        }

        // we should remove the headers listed in the Connection header
        let connection_headers = headers.clone();
        let connection_headers = connection_headers
            .get_all(CONNECTION)
            .into_iter()
            .flat_map(|content| content.to_str())
            .flat_map(|content| content.split(','))
            .map(|header| header.trim())
            .filter(|header| !header.is_empty());

        let to_be_removed = connection_headers.chain(NOPROXY_HEADERS.iter().copied());

        // remove all connection headers as they are related
        // to the gateway-bound connection only
        for header in to_be_removed {
            headers.remove(header);
        }

        Ok(Self {
            to: path,
            method,
            headers,
            body,
        })
    }

    pub fn path(&self) -> &Origin<'static> {
        &self.to
    }
}

pub struct ProxyClient {
    client: reqwest::Client,
}

impl ProxyClient {
    pub fn new() -> Self {
        let client = reqwest::ClientBuilder::new()
            .redirect(Policy::limited(0))
            .build()
            .unwrap();

        Self { client }
    }
}

impl ProxyClient {
    pub async fn reroute<S>(
        &self,
        mut request: BHTTPRequest<S>,
        to: Url,
    ) -> anyhow::Result<reqwest::Response>
    where
        S: rocket::futures::AsyncRead + Unpin,
    {
        // due to lifetime requirements we spin a
        // simplex writer coroutine to transport bytes from
        // the ohttp request to the underlying request
        let (rx, mut tx) = tokio::io::simplex(1024);

        let relay = async move {
            let mut req = request.body.body().context("cannot open")?.compat();
            tokio::io::copy(&mut req, &mut tx).await?;

            let trailer = request
                .body
                .trailer()
                .await
                .context("failed getting trailed")?;

            if !trailer.is_empty() {
                anyhow::bail!("OHTTP trailer is unsupported");
            }

            // shutdown means we're done and the response
            // cleanly flushes through
            tx.shutdown().await?;

            Ok::<(), anyhow::Error>(())
        };

        let request_dump = async {
            self.client
                .request(request.method, to)
                .headers(request.headers)
                .body(reqwest::Body::wrap_stream(
                    tokio_util::io::ReaderStream::new(rx),
                ))
                .send()
                .await
                .context("failed building outbound request")
        };

        let (_, response) = tokio::try_join!(relay, request_dump)?;

        // flush out the remaining request bytes

        Ok(response)
    }
}

pub struct OHTTPResponder<W, S>
where
    W: futures::io::AsyncWrite + Send + Sync,
    S: FnOnce(WriteHalf<SimplexStream>) -> W + Send,
{
    ohttp_encrypter: S,
    response: reqwest::Response,

    _rewriter_variance: PhantomData<fn(()) -> W>,
}

impl<W, S> OHTTPResponder<W, S>
where
    W: futures::io::AsyncWrite + Send + Sync,
    S: FnOnce(WriteHalf<SimplexStream>) -> W + Send,
{
    pub fn new(response: reqwest::Response, ohttp_encrypter: S) -> Self {
        Self {
            ohttp_encrypter,
            response,
            _rewriter_variance: PhantomData,
        }
    }
}

impl<'r, 'o, W, S> Responder<'r, 'o> for OHTTPResponder<W, S>
where
    'o: 'r,
    W: futures::io::AsyncWrite + Send + Sync + Unpin + 'static,
    S: FnOnce(WriteHalf<SimplexStream>) -> W + Send,
{
    fn respond_to(self, _request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let (reader, writer) = tokio::io::simplex(64 * 1024);
        let mut encrypter = (self.ohttp_encrypter)(writer).compat_write();

        tokio::spawn(async move {
            let res = async move {
                // we pipe the body into the encrypter
                // which encrypts and pipes the body into the response
                pipe_http_to_bhttp(self.response, &mut encrypter).await?;
                encrypter.shutdown().await?;

                Ok::<(), anyhow::Error>(())
            };

            if let Err(error) = res.await {
                log::error!("Pipe closed unexpectedly: {error:#?}");
            }
        });

        rocket::Response::build()
            .header(ContentType::new("message", "ohttp-chunked-res"))
            .streamed_body(reader)
            .ok()
    }
}

async fn pipe_http_to_bhttp<A: AsyncWrite + Unpin>(
    mut response: reqwest::Response,
    writer: &mut A,
) -> anyhow::Result<()> {
    // fields
    let mut fields = bhttp::FieldSection::default();
    let mut headers = response.headers().clone();

    // remove all connection-dependent headers
    for value in response.headers().get_all(CONNECTION) {
        for name in value
            .to_str()?
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            headers.remove(HeaderName::from_bytes(name.as_bytes())?);
        }
    }

    headers
        .iter()
        .filter(|(name, _)| !NOPROXY_HEADERS.contains(&name.as_str()))
        .for_each(|(name, value)| fields.put(name.as_str(), value.as_bytes()));

    // we produce a handcrafted bhttp header because
    // we need to stream the body back to the client
    let mut header = vec![3]; // 3 is for an indeterminate-length BHTTP response

    // encode status code
    let status = bhttp::StatusCode::try_from(response.status().as_u16())?;
    ControlData::Response(status)
        .write_bhttp(&mut header)
        .unwrap();

    // encode the headers
    fields
        .write_bhttp(Mode::IndeterminateLength, &mut header)
        .unwrap();

    // stream the header to the client before we start streaming the body
    writer.write_all(&header).await?;

    while let Some(chunk) = response.chunk().await? {
        if chunk.is_empty() {
            continue;
        }

        let mut size_header_buffer = [0u8; 8];
        let chunk_size = chunk.len();

        let size = write_bhttp_varint(chunk_size as u64, &mut size_header_buffer);

        writer.write_all(&size_header_buffer[..size]).await?;
        writer.write_all(&chunk).await?;
        writer.flush().await?;
    }

    // trailing 0-chunk means no more chunks
    writer.write_all(&[0, 0]).await?;
    writer.flush().await?;

    Ok(())
}

// BHTTP uses QUIC variable-length integers.
fn write_bhttp_varint(n: u64, out: &mut [u8]) -> usize {
    debug_assert!(out.len() >= 8);

    let (tagged, width) = match n {
        0..=63 => (n, 1),
        64..=16383 => (n | (1u64 << 14), 2),
        16384..=1073741823 => (n | (2u64 << 30), 4),
        1073741824..=4_611_686_018_427_387_903 => (n | (3u64 << 62), 8),
        _ => panic!("how did we get here?"),
    };

    out[..width].copy_from_slice(&tagged.to_be_bytes()[8 - width..]);
    width
}

use anyhow::Context;
use bhttp::stream::AsyncMessage;
use reqwest::{
    Method, Url,
    header::{CONNECTION, HeaderMap, HeaderName, HeaderValue},
};
use rocket::{futures::AsyncReadExt, http::uri::Origin};

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
    pub fn reroute<S>(&self, request: BHTTPRequest<S>, to: Url) -> anyhow::Result<reqwest::Request>
    where
        S: rocket::futures::AsyncRead + Unpin + Send + 'static,
    {
        let body = rocket::response::stream::stream! {
            let mut body = request.body;
            {
                let mut body = body.body().context("failed opening BHTTP body")?;
                let mut buffer = [0u8; 16 * 1024];
                loop {
                    let read = body.read(&mut buffer).await.context("failed reading BHTTP body")?;
                    if read == 0 {
                        break;
                    }
                    yield Ok::<_, anyhow::Error>(buffer[..read].to_vec());
                }
            }
            let trailer = body.trailer().await.context("failed reading BHTTP trailers")?;
            if !trailer.is_empty() {
                yield Err(anyhow::anyhow!("BHTTP request trailers are unsupported"));
            }
        };

        self.client
            .request(request.method, to)
            .headers(request.headers)
            .body(reqwest::Body::wrap_stream(body))
            .build()
            .context("failed building outbound request")
    }
}

/// Builds an outbound request from a BHTTP header and its remaining message.
/// The header must already have been read; body errors surface when sending.
pub fn bhttp_to_reqwest<S>(
    client: &reqwest::Client,
    header: bhttp::Header,
    mut message: bhttp::stream::AsyncMessage<S>,
) -> anyhow::Result<reqwest::Request>
where
    S: rocket::futures::AsyncRead + Unpin + Send + 'static,
{
    use reqwest::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue};
    use rocket::futures::AsyncReadExt;

    let bhttp::ControlData::Request {
        method,
        scheme,
        authority,
        path,
    } = header.control()
    else {
        anyhow::bail!("expected a BHTTP request, received a response");
    };

    let method = reqwest::Method::from_bytes(method).context("invalid BHTTP request method")?;
    anyhow::ensure!(method != reqwest::Method::CONNECT, "CONNECT is unsupported");
    let scheme = std::str::from_utf8(scheme).context("invalid BHTTP scheme")?;
    let authority = std::str::from_utf8(authority).context("invalid BHTTP authority")?;
    let path = std::str::from_utf8(path).context("invalid BHTTP path")?;
    anyhow::ensure!(
        matches!(scheme, "http" | "https"),
        "expected HTTP(S) scheme"
    );
    anyhow::ensure!(
        !authority.is_empty()
            && !authority.chars().any(|c| {
                c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '?' | '#' | '@')
            }),
        "invalid BHTTP authority"
    );
    anyhow::ensure!(
        path.starts_with('/')
            && !path
                .chars()
                .any(|c| { c.is_whitespace() || c.is_control() || matches!(c, '#' | '\\') }),
        "expected an origin-form BHTTP path"
    );
    let url = reqwest::Url::parse(&format!("{scheme}://{authority}{path}"))
        .context("invalid BHTTP request URL")?;

    let mut headers = HeaderMap::new();
    for field in header.iter() {
        let name = HeaderName::from_bytes(field.name()).context("invalid BHTTP header name")?;
        let value = HeaderValue::from_bytes(field.value()).context("invalid BHTTP header value")?;
        headers.append(name, value);
    }
    let mut connection_headers = Vec::new();
    for value in headers.get_all(CONNECTION) {
        for name in value
            .to_str()
            .context("invalid Connection header")?
            .split(',')
        {
            let name = name.trim();
            if !name.is_empty() {
                connection_headers.push(
                    HeaderName::from_bytes(name.as_bytes())
                        .context("invalid Connection header token")?,
                );
            }
        }
    }
    for name in connection_headers {
        headers.remove(name);
    }
    for name in [
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
    ] {
        headers.remove(name);
    }

    let body = rocket::response::stream::stream! {
        {
            let mut body = message.body().context("failed opening BHTTP body")?;
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let read = body.read(&mut buffer).await.context("failed reading BHTTP body")?;
                if read == 0 {
                    break;
                }
                yield Ok::<_, anyhow::Error>(buffer[..read].to_vec());
            }
        }
        let trailer = message.trailer().await.context("failed reading BHTTP trailers")?;
        if !trailer.is_empty() {
            yield Err(anyhow::anyhow!("BHTTP request trailers are unsupported"));
        }
    };

    client
        .request(method, url)
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body))
        .build()
        .context("failed building outbound request")
}

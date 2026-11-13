//! Bounded Binary HTTP framing, parsing, and message validation.

use std::io;

use bytes::Bytes;
use futures::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    stream,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use reqwest::Url;

use super::{HttpResponse, Reader};

pub(super) const CHUNK_SIZE: usize = 16 * 1024;
const MAX_METADATA: usize = 64 * 1024;

pub(super) fn validate_url(url: &Url) -> io::Result<()> {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "OHTTP requires an HTTP(S) URL without credentials or a fragment",
        ));
    }
    Ok(())
}

pub(super) fn request_head(
    method: &Method,
    url: &Url,
    request_headers: &HeaderMap,
) -> io::Result<Vec<u8>> {
    validate_url(url)?;
    if *method == Method::CONNECT || request_headers.contains_key(header::UPGRADE) {
        return Err(invalid(
            "OHTTP does not support CONNECT or protocol upgrades",
        ));
    }
    let authority = url.authority();
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let control = bhttp::ControlData::Request {
        method: method.as_str().as_bytes().to_vec(),
        scheme: url.scheme().as_bytes().to_vec(),
        authority: authority.as_bytes().to_vec(),
        path: path.as_bytes().to_vec(),
    };
    let mut headers = request_headers.clone();
    strip_connection_headers(&mut headers)?;
    // BHTTP authority is authoritative; HTTP transfer framing is not forwarded.
    headers.remove(header::HOST);
    headers.remove(header::CONTENT_LENGTH);
    let mut fields = bhttp::FieldSection::default();
    for (name, value) in &headers {
        fields.put(name.as_str(), value.as_bytes());
    }
    let mut head = vec![2];
    control.write_bhttp(&mut head).map_err(io::Error::other)?;
    fields
        .write_bhttp(bhttp::Mode::IndeterminateLength, &mut head)
        .map_err(io::Error::other)?;
    if head.len() > MAX_METADATA {
        return Err(invalid("BHTTP request headers exceed the metadata limit"));
    }
    Ok(head)
}

fn strip_connection_headers(headers: &mut HeaderMap) -> io::Result<()> {
    let mut named = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        for name in value.to_str().map_err(invalid)?.split(',').map(str::trim) {
            if !name.is_empty() {
                named.push(HeaderName::from_bytes(name.as_bytes()).map_err(invalid)?);
            }
        }
    }
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    Ok(())
}

pub(super) async fn upload<W: AsyncWrite + Unpin>(
    head: Vec<u8>,
    mut reader: Reader,
    mut writer: W,
) -> io::Result<()> {
    writer.write_all(&head).await?;
    let mut buffer = vec![0; CHUNK_SIZE];
    loop {
        let len = reader.read(&mut buffer).await?;
        if len == 0 {
            break;
        }
        let mut prefix = Vec::with_capacity(8);
        write_varint(len as u64, &mut prefix);
        writer.write_all(&prefix).await?;
        writer.write_all(&buffer[..len]).await?;
    }
    writer.write_all(&[0, 0]).await?;
    writer.close().await
}

pub(super) async fn decode_response(mut reader: Reader) -> io::Result<HttpResponse> {
    let known_length = match read_varint(&mut reader).await? {
        1 => true,
        3 => false,
        _ => return Err(invalid("expected a BHTTP response")),
    };
    let mut budget = MAX_METADATA;
    let (status, mut headers) = loop {
        spend(&mut budget, 1)?;
        let code = u16::try_from(read_varint(&mut reader).await?).map_err(invalid)?;
        if !(100..=599).contains(&code) {
            return Err(invalid("invalid BHTTP response status"));
        }
        let status = StatusCode::from_u16(code).map_err(invalid)?;
        let headers = read_fields(&mut reader, known_length, &mut budget, false).await?;
        if status == StatusCode::SWITCHING_PROTOCOLS {
            return Err(invalid("BHTTP protocol upgrade is unsupported"));
        }
        if !status.is_informational() {
            break (status, headers);
        }
    };
    strip_connection_headers(&mut headers)?;
    let body = stream::try_unfold(
        (reader, None, known_length),
        |(mut reader, remaining, known_length)| async move {
            let mut remaining = match remaining {
                Some(remaining) => remaining,
                None => read_varint_optional(&mut reader).await?.unwrap_or(0),
            };
            if remaining == 0 {
                let mut budget = MAX_METADATA;
                read_fields(&mut reader, known_length, &mut budget, true).await?;
                // BHTTP padding is zero-filled; read through OHTTP's final tag.
                let mut padding = [0; CHUNK_SIZE];
                loop {
                    let len = reader.read(&mut padding).await?;
                    if len == 0 {
                        break;
                    }
                    if padding[..len].iter().any(|byte| *byte != 0) {
                        return Err(invalid("invalid BHTTP padding"));
                    }
                }
                return Ok(None);
            }
            let mut chunk = vec![0; remaining.min(CHUNK_SIZE as u64) as usize];
            let len = reader.read(&mut chunk).await?;
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated BHTTP body",
                ));
            }
            chunk.truncate(len);
            remaining -= len as u64;
            let remaining = if remaining == 0 && !known_length {
                None
            } else {
                Some(remaining)
            };
            Ok(Some((
                Bytes::from(chunk),
                (reader, remaining, known_length),
            )))
        },
    );
    Ok(HttpResponse {
        status,
        headers,
        body: Box::pin(body),
    })
}

// The upstream async BHTTP parser allocates before reading field bytes. Keep
// lengths bounded here before allocation, including informational responses.
async fn read_fields<R: AsyncRead + Unpin>(
    reader: &mut R,
    known_length: bool,
    budget: &mut usize,
    allow_eof: bool,
) -> io::Result<HeaderMap> {
    if known_length {
        let length = if allow_eof {
            read_varint_optional(reader).await?.unwrap_or(0)
        } else {
            read_varint(reader).await?
        };
        let len = usize::try_from(length).map_err(invalid)?;
        spend(budget, len)?;
        let mut bytes = vec![0; len];
        reader.read_exact(&mut bytes).await?;
        let mut cursor = futures::io::Cursor::new(bytes);
        let mut headers = HeaderMap::new();
        let mut remaining = len;
        while cursor.position() < len as u64 {
            let (name, value) = read_field(&mut cursor, &mut remaining, false)
                .await?
                .ok_or_else(|| invalid("empty name in a known-length BHTTP field section"))?;
            headers.append(name, value);
        }
        Ok(headers)
    } else {
        let mut headers = HeaderMap::new();
        while let Some((name, value)) = read_field(reader, budget, allow_eof).await? {
            headers.append(name, value);
        }
        Ok(headers)
    }
}

async fn read_field<R: AsyncRead + Unpin>(
    reader: &mut R,
    budget: &mut usize,
    allow_eof: bool,
) -> io::Result<Option<(HeaderName, HeaderValue)>> {
    let name = read_string(reader, budget, allow_eof).await?;
    if name.is_empty() {
        return Ok(None);
    }
    let value = read_string(reader, budget, false).await?;
    let name = HeaderName::from_bytes(&name).map_err(invalid)?;
    let value = HeaderValue::from_bytes(&value).map_err(invalid)?;
    Ok(Some((name, value)))
}

async fn read_string<R: AsyncRead + Unpin>(
    reader: &mut R,
    budget: &mut usize,
    allow_eof: bool,
) -> io::Result<Vec<u8>> {
    let length = if allow_eof {
        read_varint_optional(reader).await?.unwrap_or(0)
    } else {
        read_varint(reader).await?
    };
    let len = usize::try_from(length).map_err(invalid)?;
    spend(budget, len.saturating_add(1))?;
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}

fn spend(budget: &mut usize, amount: usize) -> io::Result<()> {
    *budget = budget
        .checked_sub(amount)
        .ok_or_else(|| invalid("BHTTP metadata limit exceeded"))?;
    Ok(())
}

async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    read_varint_optional(reader)
        .await?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "missing BHTTP integer"))
}

async fn read_varint_optional<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<u64>> {
    let mut first = [0];
    if reader.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let width = 1usize << (first[0] >> 6);
    let mut value = u64::from(first[0] & 0x3f);
    let mut rest = [0; 7];
    reader.read_exact(&mut rest[..width - 1]).await?;
    for byte in &rest[..width - 1] {
        value = (value << 8) | u64::from(*byte);
    }
    Ok(Some(value))
}

fn write_varint(value: u64, output: &mut Vec<u8>) {
    let (tagged, width) = match value {
        0..=63 => (value, 1),
        64..=16383 => (value | (1 << 14), 2),
        16384..=1073741823 => (value | (2 << 30), 4),
        _ => (value | (3 << 62), 8),
    };
    output.extend_from_slice(&tagged.to_be_bytes()[8 - width..]);
}

pub(super) fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

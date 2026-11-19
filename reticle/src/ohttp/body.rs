//! Bounded, consumer-driven adaptation from asynchronous writers to byte streams.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use futures::{Sink, StreamExt, channel::mpsc, future::poll_fn, io::AsyncWrite, stream};

use super::codec::CHUNK_SIZE;
use super::{ByteStream, Producer};

/// A bounded byte pipe: the body consumer, not an executor task, drives writes.
pub(super) struct ChannelWriter(pub(super) mpsc::Sender<Bytes>);

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.0).poll_ready(cx)).map_err(io::Error::other)?;
        let len = bytes.len().min(CHUNK_SIZE);
        Pin::new(&mut self.0)
            .start_send(Bytes::copy_from_slice(&bytes[..len]))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.close_channel();
        Poll::Ready(Ok(()))
    }
}

pub(super) fn driven_stream(producer: Producer, receiver: mpsc::Receiver<Bytes>) -> ByteStream {
    Box::pin(stream::try_unfold(
        (Some(producer), receiver),
        |(mut producer, mut receiver)| async move {
            let chunk = poll_fn(|cx| {
                if let Some(task) = &mut producer
                    && let Poll::Ready(result) = task.as_mut().poll(cx)
                {
                    producer = None;
                    result?;
                }
                receiver.poll_next_unpin(cx).map(Ok::<_, io::Error>)
            })
            .await?;
            Ok(chunk.map(|chunk| (chunk, (producer, receiver))))
        },
    ))
}

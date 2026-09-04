//! Adapter from `tokio::io::AsyncRead` to `futures_core::Stream<Item = Result<Bytes, io::Error>>`.
//!
//! Ported from plain-nas `src/async_read_stream.rs`, which replaced its
//! single use of `tokio_util::io::ReaderStream` to avoid pulling in
//! `tokio-util` (and its dependency fan-out) for one call site.
//!
//! Behaviour matches `tokio_util::io::ReaderStream::with_capacity(r, 64 KiB)`:
//! read up to 64 KiB per `poll_next`, yield each chunk as a fresh
//! `Bytes`, terminate with `None` on EOF.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use tokio::io::AsyncRead;

/// Adapter that turns an `AsyncRead` into a `Stream<Item = Result<Bytes, io::Error>>`.
pub struct AsyncReadStream<R> {
    reader: R,
    buf: [u8; 64 * 1024],
}

impl<R: AsyncRead + Unpin> AsyncReadStream<R> {
    pub fn new(reader: R) -> Self {
        Self { reader, buf: [0u8; 64 * 1024] }
    }
}

impl<R: AsyncRead + Unpin> Stream for AsyncReadStream<R> {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let mut read_buf = tokio::io::ReadBuf::new(&mut this.buf);
        match Pin::new(&mut this.reader).poll_read(cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    Poll::Ready(None) // EOF
                } else {
                    // Copy out of the stack buffer into a fresh `Bytes`.
                    Poll::Ready(Some(Ok(Bytes::copy_from_slice(&this.buf[..n]))))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn streams_then_ends_at_eof() {
        use futures::StreamExt;
        let data = vec![7u8; 200_000]; // > 64 KiB → multiple chunks
        let mut stream = Box::pin(AsyncReadStream::new(Cursor::new(data)));
        let mut total = 0;
        let mut chunks = 0;
        while let Some(res) = stream.as_mut().next().await {
            let bytes = res.unwrap();
            assert!(bytes.len() <= 64 * 1024);
            assert_eq!(bytes[0], 7);
            total += bytes.len();
            chunks += 1;
        }
        assert_eq!(total, 200_000);
        assert!(chunks >= 3);
    }
}

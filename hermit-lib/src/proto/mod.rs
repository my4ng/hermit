pub mod handshake;
pub mod transfer;

use std::pin::Pin;
use async_std::io::{ReadExt, WriteExt};
pub(crate) use handshake::*;
use quinn::{RecvStream, SendStream};
pub(crate) use transfer::*;

use crate::crypto;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolVersion {
    // NOTE: 0x00 RESERVED
    V0_1 = 0x01,
}

pub(crate) const CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V0_1;

pub trait Stream {}

pub trait InsecureStream: Stream + WriteExt + ReadExt + Unpin {}

pub struct NilStream;

impl Stream for NilStream {}

pub use async_std::net::TcpStream;

impl Stream for TcpStream {}
impl InsecureStream for TcpStream {}

pub struct QuicStream {
    pub(crate) send_stream: Pin<Box<SendStream>>,
    pub(crate) recv_stream: Pin<Box<RecvStream>>,
}

impl Stream for QuicStream {}

impl futures_io::AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<futures_io::Result<usize>> {
        self.get_mut().recv_stream.as_mut().poll_read(cx, buf)
    }
}

impl futures_io::AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<futures_io::Result<usize>> {
        self.get_mut().send_stream.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<futures_io::Result<()>> {
        self.get_mut().send_stream.as_mut().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<futures_io::Result<()>> {
        self.get_mut().send_stream.as_mut().poll_close(cx)
    }
}

impl InsecureStream for QuicStream {}

pub struct SecureStream<S: InsecureStream> {
    pub(crate) stream: S,
    pub(crate) session_secrets: crypto::SessionSecrets,
}

impl<S: InsecureStream> Stream for SecureStream<S> {}

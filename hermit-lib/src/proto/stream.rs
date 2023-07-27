use std::pin::Pin;

use async_std::io::{ReadExt, WriteExt};
pub use async_std::net::TcpStream;
use quinn::{RecvStream, SendStream};
use ring::aead;

use super::message::*;
use crate::{crypto, error};

pub trait BaseStream: WriteExt + ReadExt + Unpin + Send {}

impl BaseStream for TcpStream {}

pub struct QuicStream {
    pub(crate) send_stream: Pin<Box<SendStream>>,
    pub(crate) recv_stream: Pin<Box<RecvStream>>,
}

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

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<futures_io::Result<()>> {
        self.get_mut().send_stream.as_mut().poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<futures_io::Result<()>> {
        self.get_mut().send_stream.as_mut().poll_close(cx)
    }
}

impl BaseStream for QuicStream {}

pub struct NilStream;

#[async_trait::async_trait]
pub trait Plain: Send {
    async fn send(&mut self, message: Message) -> Result<(), error::Error>;
    async fn recv(&mut self) -> Result<Message, error::Error>;
}

pub struct PlainStream<S: BaseStream> {
    stream: S,
    header_buffer: Box<[u8; MESSAGE_HEADER_LEN]>,
}

impl<S: BaseStream> PlainStream<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream,
            header_buffer: Box::new([0u8; MESSAGE_HEADER_LEN]),
        }
    }
}

#[async_trait::async_trait]
impl<S: BaseStream> Plain for PlainStream<S> {
    async fn send(&mut self, msg: Message) -> Result<(), error::Error> {
        Ok(self.stream.write_all(msg.as_ref()).await?)
    }

    async fn recv(&mut self) -> Result<Message, error::Error> {
        self.stream.read_exact(self.header_buffer.as_mut()).await?;
        let payload_len = u16::from_be_bytes([self.header_buffer[2], self.header_buffer[3]]);
        let mut message = Message::raw(payload_len);
        self.stream.read_exact(message.payload_mut()).await?;
        message
            .header_mut()
            .copy_from_slice(self.header_buffer.as_ref());
        Ok(message)
    }
}

pub struct SecureStream {
    // Use trait object to abstract over the underlying stream
    stream: Box<dyn Plain>,
    session_secrets: crypto::secrets::SessionSecrets,
}

impl SecureStream {
    pub(crate) fn new(stream: Box<dyn Plain>, session_secrets: crypto::secrets::SessionSecrets) -> Self {
        Self {
            stream,
            session_secrets,
        }
    }
}

pub trait Secure: Plain {
    fn encrypt(&mut self, secure_message: SecureMessage) -> Result<Message, error::CryptoError>;
    fn decrypt(&mut self, message: Message) -> Result<SecureMessage, error::CryptoError>;
}

#[async_trait::async_trait]
impl Plain for SecureStream {
    async fn send(&mut self, msg: Message) -> Result<(), error::Error> {
        self.stream.as_mut().send(msg).await
    }

    async fn recv(&mut self) -> Result<Message, error::Error> {
        self.stream.as_mut().recv().await
    }
}

impl Secure for SecureStream {
    fn encrypt(
        &mut self,
        mut secure_message: SecureMessage,
    ) -> Result<Message, error::CryptoError> {
        let tag = self
            .session_secrets
            .send_key
            .seal_in_place_separate_tag(aead::Aad::empty(), secure_message.payload_mut())?;
        secure_message.tag_mut().copy_from_slice(tag.as_ref());
        Ok(Message::from(secure_message))
    }
    fn decrypt(&mut self, mut message: Message) -> Result<SecureMessage, error::CryptoError> {
        self.session_secrets
            .recv_key
            .open_in_place(aead::Aad::empty(), message.payload_mut())?;
        Ok(SecureMessage::from(message))
    }
}

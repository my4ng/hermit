use std::pin::Pin;

use async_std::io::{ReadExt, WriteExt};
pub use async_std::net::TcpStream;
use quinn::{RecvStream, SendStream};
use ring::aead;

use super::message::*;
use crate::{crypto, error};

pub struct QuicStream {
    pub(crate) send_stream: SendStream,
    pub(crate) recv_stream: RecvStream,
}

impl futures_io::AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<futures_io::Result<usize>> {
        Pin::new(&mut self.get_mut().recv_stream).poll_read(cx, buf)
    }
}

impl futures_io::AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<futures_io::Result<usize>> {
        Pin::new(&mut self.get_mut().send_stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<futures_io::Result<()>> {
        Pin::new(&mut self.get_mut().send_stream).poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<futures_io::Result<()>> {
        Pin::new(&mut self.get_mut().send_stream).poll_close(cx)
    }
}

pub struct NilStream;

pub enum BaseStream {
    Tcp(TcpStream),
    Quic(QuicStream),
}

impl futures_io::AsyncRead for BaseStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<futures_io::Result<usize>> {
        match self.get_mut() {
            BaseStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            BaseStream::Quic(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl futures_io::AsyncWrite for BaseStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<futures_io::Result<usize>> {
        match self.get_mut() {
            BaseStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            BaseStream::Quic(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<futures_io::Result<()>> {
        match self.get_mut() {
            BaseStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            BaseStream::Quic(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<futures_io::Result<()>> {
        match self.get_mut() {
            BaseStream::Tcp(stream) => Pin::new(stream).poll_close(cx),
            BaseStream::Quic(stream) => Pin::new(stream).poll_close(cx),
        }
    }
}

#[async_trait::async_trait]
pub trait Plain {
    async fn send(&mut self, message: Message) -> Result<(), error::Error>;
    async fn recv(&mut self) -> Result<Message, error::Error>;
}

pub struct PlainStream {
    stream: BaseStream,
    header_buffer: [u8; MESSAGE_HEADER_LEN],
}

impl PlainStream {
    pub(crate) fn new(stream: BaseStream) -> Self {
        Self {
            stream,
            header_buffer: [0u8; MESSAGE_HEADER_LEN],
        }
    }
}

#[async_trait::async_trait]
impl Plain for PlainStream {
    async fn send(&mut self, msg: Message) -> Result<(), error::Error> {
        Ok(self.stream.write_all(msg.as_ref()).await?)
    }

    async fn recv(&mut self) -> Result<Message, error::Error> {
        self.stream.read_exact(&mut self.header_buffer).await?;
        let mut message = Message::raw(&self.header_buffer);
        self.stream.read_exact(message.payload_mut()).await?;
        Ok(message)
    }
}

pub struct SecureStream {
    // Use trait object to abstract over the underlying stream
    stream: PlainStream,
    session_secrets: crypto::secrets::SessionSecrets,
}

impl SecureStream {
    pub(crate) fn new(
        stream: PlainStream,
        session_secrets: crypto::secrets::SessionSecrets,
    ) -> Self {
        Self {
            stream,
            session_secrets,
        }
    }
}

pub trait Secure: Plain {
    type PlainType: Plain;

    fn encrypt(&mut self, secure_message: SecureMessage) -> Result<Message, error::CryptoError>;
    fn decrypt(&mut self, message: Message) -> Result<SecureMessage, error::CryptoError>;
    fn downgrade(self) -> Self::PlainType;
}

#[async_trait::async_trait]
impl Plain for SecureStream {
    async fn send(&mut self, msg: Message) -> Result<(), error::Error> {
        self.stream.send(msg).await
    }

    async fn recv(&mut self) -> Result<Message, error::Error> {
        self.stream.recv().await
    }
}

impl Secure for SecureStream {
    type PlainType = PlainStream;

    fn encrypt(
        &mut self,
        mut secure_message: SecureMessage,
    ) -> Result<Message, error::CryptoError> {
        let tag = self
            .session_secrets
            .send_key()
            .seal_in_place_separate_tag(aead::Aad::empty(), secure_message.payload_mut())?;
        Ok(Message::from((secure_message, tag)))
    }
    fn decrypt(&mut self, mut message: Message) -> Result<SecureMessage, error::CryptoError> {
        self.session_secrets
            .recv_key()
            .open_in_place(aead::Aad::empty(), message.payload_mut())?;
        Ok(SecureMessage::from(message))
    }

    fn downgrade(self) -> Self::PlainType {
        self.stream
    }
}

#[cfg(test)]
mod test {
    use ring::agreement;
    use super::*;

    #[ignore]
    #[async_std::test]
    async fn test_encrypt() {
        let stream = PlainStream::new(BaseStream::Tcp(TcpStream::connect("127.0.0.1:8080").await.unwrap()));
        let private_key = crypto::generate_ephemeral_key_pair().unwrap().0;
        let public_key = crypto::generate_ephemeral_key_pair().unwrap().1;
        let public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, <[u8; 32]>::try_from(public_key.as_ref()).unwrap());
        let nonce1 = crypto::generate_nonce().await.unwrap();
        let nonce2 = crypto::generate_nonce().await.unwrap();
        let mut nonces: [u8; 32] = [0u8; 32];
        nonces[..16].copy_from_slice(&nonce1);
        nonces[16..].copy_from_slice(&nonce2);
        let secrets = crypto::generate_session_secrets(private_key, public_key, &nonces, super::super::Side::Client).unwrap();
        let secure = SecureStream::new(stream, secrets);

        todo!()
    }
}

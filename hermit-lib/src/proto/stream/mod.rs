mod plain;
mod secure;
mod buffer;

use std::pin::Pin;

pub use async_std::net::TcpStream;
use quinn::{RecvStream, SendStream};

pub use plain::*;
pub use secure::*;

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

#[cfg(test)]
mod test {
    use crate::{crypto, proto::transfer::SendResourceRequest};

    use super::*;
    use async_std::{net::TcpListener, task, io::ReadExt};
    use chrono::Duration;
    use ring::agreement;

    #[ignore]
    #[async_std::test]
    async fn test_encrypt() {
        let join_handle = task::spawn(async {
            let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Box::new([0u8; 10000]);
            stream.read_exact(buffer.as_mut()).await.unwrap();
            println!("{:02x?}", buffer);
        });

        let stream = PlainStream::new(BaseStream::Tcp(
            TcpStream::connect("127.0.0.1:8080").await.unwrap(),
        ));
        let private_key = crypto::generate_ephemeral_key_pair().unwrap().0;
        let public_key = crypto::generate_ephemeral_key_pair().unwrap().1;
        let public_key = agreement::UnparsedPublicKey::new(
            &agreement::X25519,
            <[u8; 32]>::try_from(public_key.as_ref()).unwrap(),
        );
        let nonce1 = crypto::generate_nonce().await.unwrap();
        let nonce2 = crypto::generate_nonce().await.unwrap();
        let mut nonces: [u8; 32] = [0u8; 32];
        nonces[..16].copy_from_slice(&nonce1);
        nonces[16..].copy_from_slice(&nonce2);
        let secrets = crypto::generate_session_secrets(
            private_key,
            public_key,
            &nonces,
            super::super::Side::Client,
        )
        .await
        .unwrap();
        let mut secure = SecureStream::new(stream, secrets);

        let secure_msg = SendResourceRequest {
            resources: vec![(0, "test".to_string()); 10000],
            expiry_duration: Some(Duration::days(3)),
            receiver_control: None,
        };
        ciborium::into_writer(&secure_msg, &mut secure).unwrap();
        ciborium::into_writer(&secure_msg, &mut secure).unwrap();
        println!("Finished transmitting!");

        join_handle.await;
    }
}

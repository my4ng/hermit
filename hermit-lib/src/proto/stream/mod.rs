use std::pin::Pin;

pub use async_std::net::TcpStream;
use quinn::{RecvStream, SendStream};

pub(crate) use crate::proto::plain::stream::{Plain, PlainStream};
pub(crate) use crate::proto::secure::stream::{Secure, SecureStream};

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
    // TODO: Fix this mess by using a proto::prelude module.
    use crate::{crypto::{self, SIGNED_CONTENT_LEN, NONCE_LEN}, proto::{plain::{stream::{PlainStream, Plain}, handshake::{ClientHelloMessage, ServerHelloMessage}}, Side, secure::{stream::SecureStream, transfer::{SendResourceRequest, ReceiverControl}, message::Secure}}};

    use super::*;
    use async_std::{net::TcpListener, task};
    use chrono::Duration;
    use ring::{agreement::{self, UnparsedPublicKey}, signature};
    use ring::signature::KeyPair;


    #[ignore]
    #[async_std::test]
    async fn test_encrypt() {
        let sig_key_pair = crypto::generate_signature_key_pair().unwrap();
        let sig_pub_key = signature::UnparsedPublicKey::new(&signature::ED25519, sig_key_pair.public_key().as_ref().to_owned());

        let join_handle = task::spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = PlainStream::from(BaseStream::Tcp(stream));

            let (private_key, public_key) = crypto::generate_ephemeral_key_pair().unwrap();
            let nonce = crypto::generate_nonce().await.unwrap();

            let received_msg = ClientHelloMessage::try_from(stream.recv().await.unwrap()).unwrap();
            let mut message = [0u8; SIGNED_CONTENT_LEN];
            message[..NONCE_LEN].copy_from_slice(&received_msg.nonce);
            message[NONCE_LEN..2 * NONCE_LEN].copy_from_slice(&nonce);
            message[2 * NONCE_LEN..].copy_from_slice(public_key.as_ref());

            let msg = ServerHelloMessage {
                nonce,
                public_key_bytes: public_key.as_ref().try_into().unwrap(),
                signature: sig_key_pair.sign(&message).as_ref().try_into().unwrap(),
            };

            stream.send(msg.into()).await.unwrap();

            let secrets = crypto::generate_session_secrets(
                private_key,
                UnparsedPublicKey::new(&agreement::X25519, received_msg.public_key_bytes),
                &message[..2 * NONCE_LEN].try_into().unwrap(),
                Side::Server,
            ).await.unwrap();

            let mut stream = SecureStream::new(stream, secrets);

            let msg = SendResourceRequest::recv(&mut stream).unwrap();
            println!("Received msg: {:?}", msg);
        });

        task::sleep(std::time::Duration::from_millis(100)).await;

        let mut stream = PlainStream::from(BaseStream::Tcp(
            TcpStream::connect("127.0.0.1:8080").await.unwrap(),
        ));

        let (private_key, public_key) = crypto::generate_ephemeral_key_pair().unwrap();
        let nonce = crypto::generate_nonce().await.unwrap();

        let msg = ClientHelloMessage {
            nonce,
            public_key_bytes: <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(public_key.as_ref())
                .unwrap(),
        };

        stream.send(msg.into()).await.unwrap();

        let received_msg = ServerHelloMessage::try_from(stream.recv().await.unwrap()).unwrap();

        let (pub_key, nonces) = crypto::verify_server_hello(received_msg, nonce, &sig_pub_key).unwrap();

        let secrets = crypto::generate_session_secrets(
            private_key,
            pub_key,
            &nonces,
            Side::Client,
        ).await.unwrap();

        let mut secure = SecureStream::new(stream, secrets);

        let secure_msg = SendResourceRequest {
            resources: vec![(0, "test".to_string()); 1000],
            expiry_duration: Some(Duration::days(3)),
            receiver_control: Some(ReceiverControl::Password("password".to_string())),
        };

        secure_msg.send(&mut secure).unwrap();
        println!("Finished transmitting!");

        join_handle.await;
    }
}

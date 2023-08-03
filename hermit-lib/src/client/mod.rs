mod state;

use ring::signature;

use crate::crypto;
use crate::error::Error;
use crate::proto::message::handshake;
use crate::proto::stream::{BaseStream, Plain, PlainStream};
use crate::proto::Side;

use self::state::*;

pub struct ServerSigPubKey(signature::UnparsedPublicKey<Box<[u8]>>);

impl ServerSigPubKey {
    pub fn new<T: Into<Box<[u8]>>>(sig_pub_key: T) -> ServerSigPubKey {
        ServerSigPubKey(signature::UnparsedPublicKey::new(
            &signature::ED25519,
            sig_pub_key.into(),
        ))
    }
}

impl AsRef<signature::UnparsedPublicKey<Box<[u8]>>> for ServerSigPubKey {
    fn as_ref(&self) -> &signature::UnparsedPublicKey<Box<[u8]>> {
        &self.0
    }
}

pub struct Client<T: State> {
    state: T,
}

impl Default for Client<NoConnection> {
    fn default() -> Self {
        Self::new()
    }
}

impl Client<NoConnection> {
    fn new() -> Self {
        Self {
            state: NoConnection,
        }
    }
    fn connect(self, stream: BaseStream) -> Client<InsecureConnection> {
        Client {
            state: InsecureConnection::new(self.state, PlainStream::from(stream)),
        }
    }
}

// TODO: return self when having an error
impl Client<InsecureConnection> {
    async fn client_hello(mut self) -> Result<Client<HandshakingConnection>, Error> {
        let client_nonce = crypto::generate_nonce().await?;
        let (client_private_key, public_key) = crypto::generate_ephemeral_key_pair()?;

        let client_hello_msg = handshake::ClientHelloMessage {
            nonce: client_nonce,
            // SAFETY: public key has the correct length
            public_key_bytes: <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(public_key.as_ref())
                .unwrap(),
        };

        self.state
            .plain_stream()
            .send(client_hello_msg.into())
            .await?;

        Ok(Client {
            state: HandshakingConnection::new(self.state, client_nonce, client_private_key),
        })
    }
}

// TODO: return Client<InsecureConnection> when having an error
impl Client<HandshakingConnection> {
    async fn server_hello(
        mut self,
        server_sig_pub_key: ServerSigPubKey,
        server_hello_msg: handshake::ServerHelloMessage,
    ) -> Result<Client<UpgradedConnection>, Error> {
        // SAFETY: private key has not been taken out before
        let (client_nonce, client_private_key) = self.state.nonce_private_key().unwrap();

        // Verify
        let (server_public_key, nonces) = crypto::verify_server_hello(
            server_hello_msg,
            client_nonce,
            server_sig_pub_key.as_ref(),
        )?;

        // Generate session secrets
        let session_secrets = crypto::generate_session_secrets(
            client_private_key,
            server_public_key,
            &nonces,
            Side::Client,
        )
        .await?;

        // Upgrade stream to secure
        Ok(Client {
            state: UpgradedConnection::new(self.state, session_secrets),
        })
    }
}

impl<T: SecureState<UnderlyingStream = PlainStream>> Client<T> {
    async fn downgrade(mut self) -> Result<Client<InsecureConnection>, Error> {
        self.state
            .plain_stream()
            .send(handshake::DowngradeMessage.into())
            .await?;
        Ok(Client {
            state: InsecureConnection::downgrade(self.state),
        })
    }

    pub async fn send_resource(&mut self) -> Result<(), Error> {
        todo!()
    }
}

// NOTE: for both PlainStream and SecureStream
impl<T: PlainState> Client<T> {
    async fn disconnect(mut self) -> Result<Client<NoConnection>, Error> {
        self.state
            .plain_stream()
            .send(handshake::DisconnectMessage {}.into())
            .await?;
        Ok(Client {
            state: NoConnection,
        })
    }
}

#[cfg(test)]
mod test {
    use async_std::{net::TcpListener, task};

    use super::*;

    // NOTE: run after command `netcat -l 8080` is executed to listen on TCP port 8080
    #[ignore]
    #[async_std::test]
    async fn test_client_new() {
        task::spawn(async {
            TcpListener::bind("127.0.0.1:8080")
                .await
                .unwrap()
                .accept()
                .await
                .unwrap()
        });
        let tcp_stream = async_std::net::TcpStream::connect("127.0.0.1:8080")
            .await
            .unwrap();
        let client = Client::new().connect(BaseStream::Tcp(tcp_stream));
    }
}

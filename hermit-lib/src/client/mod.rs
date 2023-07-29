use crate::crypto;
use crate::error::Error;
use crate::proto::stream::BaseStream;
use crate::proto::{
    message,
    stream::{NilStream, Plain, PlainStream, Secure, SecureStream},
    Side,
};

use ring::signature;

pub struct ServerConfig {
    sig_pub_key: signature::UnparsedPublicKey<Vec<u8>>,
}

impl ServerConfig {
    pub fn new<T: AsRef<[u8]>>(sig_pub_key: T) -> ServerConfig {
        ServerConfig {
            sig_pub_key: signature::UnparsedPublicKey::new(
                &signature::ED25519,
                sig_pub_key.as_ref().to_owned(),
            ),
        }
    }
}

pub struct Client<T> {
    server_config: ServerConfig,
    stream: T,
}

impl Client<NilStream> {
    pub fn new(server_config: ServerConfig) -> Self {
        Self {
            server_config,
            stream: NilStream,
        }
    }
    pub fn connect(self, stream: BaseStream) -> Client<PlainStream> {
        Client {
            server_config: self.server_config,
            stream: PlainStream::new(stream),
        }
    }
}

impl Client<PlainStream> {
    pub async fn handshake(mut self) -> Result<Client<SecureStream>, Error> {
        let client_nonce = crypto::generate_nonce().await?;
        let (client_private_key, public_key) = crypto::generate_ephemeral_key_pair()?;

        let client_hello_msg = message::ClientHelloMessage {
            nonce: client_nonce,
            // SAFETY: public key has the correct length
            public_key_bytes: <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(public_key.as_ref())
                .unwrap(),
        };

        self.stream.send(client_hello_msg.into()).await?;
        let message = self.stream.recv().await?;

        // NOTE: parse -> verify -> generate session secrets (e.g. symmetric keys)

        // Parse
        let server_hello_message = message::ServerHelloMessage::try_from(message)?;

        // Verify
        let (server_public_key, nonces) = crypto::verify_server_hello(
            server_hello_message,
            client_nonce,
            &self.server_config.sig_pub_key,
        )?;

        // Generate session secrets
        let session_secrets = crypto::generate_session_secrets(
            client_private_key,
            server_public_key,
            &nonces,
            Side::Client,
        )?;

        // Upgrade stream to secure
        Ok(Client {
            stream: SecureStream::new(self.stream, session_secrets),
            server_config: self.server_config,
        })
    }
}

impl<T: Secure> Client<T> {
    pub async fn downgrade(mut self) -> Result<Client<T::PlainType>, Error> {
        self.stream.send(message::DowngradeMessage {}.into()).await?;
        Ok(Client {
            server_config: self.server_config,
            stream: self.stream.downgrade(),
        })
    }

    pub async fn send_resource(&mut self) -> Result<(), Error> {
        todo!()
    }
}

// NOTE: for both PlainStream and SecureStream
impl<T: Plain> Client<T> {
    pub async fn disconnect(mut self) -> Result<Client<NilStream>, Error> {
        self.stream
            .send(message::DisconnectMessage {}.into())
            .await?;
        Ok(Client {
            server_config: self.server_config,
            stream: NilStream,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // NOTE: run after command `netcat -l 8080` is executed to listen on TCP port 8080
    #[ignore]
    #[async_std::test]
    async fn test_client_new() {
        let tcp_stream = async_std::net::TcpStream::connect("127.0.0.1:8080")
            .await
            .unwrap();
        let client = Client::new(ServerConfig::new([0u8; 32]))
            .connect(BaseStream::Tcp(tcp_stream));
    }
}

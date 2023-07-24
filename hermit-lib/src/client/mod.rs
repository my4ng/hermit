use std::net::SocketAddr;

use crate::proto;
use crate::crypto;
use crate::error::Error;
use async_std::io::ReadExt;
use async_std::io::WriteExt;
use async_std::net::TcpStream;

use ring::{agreement, signature};


struct ServerConfig {
    socket_addr: SocketAddr,
    sig_pub_key: signature::UnparsedPublicKey<Vec<u8>>,
}

impl ServerConfig {
    pub fn new<S: Into<SocketAddr>>(socket_addr: S, sig_pub_key: Vec<u8>) -> ServerConfig {
        ServerConfig {
            socket_addr: socket_addr.into(),
            sig_pub_key: signature::UnparsedPublicKey::new(&signature::ED25519, sig_pub_key),
        }
    }
}

// NOTE: temporary data structure during handshake
struct ClientSecrets {
    client_nonce: [u8; crypto::NONCE_LEN],
    client_private_key: agreement::EphemeralPrivateKey,
}

pub struct Client {
    connection: Option<proto::ConnectionState>,
    server_config: ServerConfig,
}

impl Client {
    fn new(server_config: ServerConfig) -> Result<Self, Error> {
        Ok(Self {
            server_config,
            connection: None,
        })
    }

    async fn client_hello(&mut self) -> Result<([u8; proto::CLIENT_HELLO_MSG_LEN], ClientSecrets), Error> {
        let client_nonce = crypto::generate_nonce().await?;
        let (private_key, public_key) = crypto::generate_ephemeral_key_pair()?;

        let client_hello_msg = proto::ClientHelloMessage {
            header: proto::ClientHelloMessageHeader {
                version: proto::CURRENT_PROTOCOL_VERSION,
            },
            nonce: client_nonce,
            // SAFETY: public key has the correct length
            public_key_bytes: <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(public_key.as_ref()).unwrap(),
        };
        let client_secrets = ClientSecrets {
            client_nonce,
            client_private_key: private_key,
        };
        Ok((client_hello_msg.into(), client_secrets))
    }

    async fn establish_connection(&mut self) -> Result<(), Error> {
        let stream = TcpStream::connect(self.server_config.socket_addr).await?;
        self.connection = Some(proto::ConnectionState {
            stream,
            session_secrets: None,
        });
        Ok(())
    }

    async fn handshake(&mut self) -> Result<(), Error> {
        match self.connection {
            None => Err(Error::ConnectionNotEstablished),
            Some(proto::ConnectionState {
                stream: _,
                session_secrets: None,
            }) => {
                let (
                    message,
                    ClientSecrets {
                        client_nonce,
                        client_private_key,
                    },
                ) = self.client_hello().await?;

                // SAFETY: connection is Some
                let connection = self.connection.as_mut().unwrap();
                connection.stream.write_all(&message).await?;

                let mut buffer = [0u8; proto::SERVER_HELLO_MSG_LEN];
                connection.stream.read_exact(&mut buffer).await?;

                // NOTE: parse -> verify -> generate PRK -> generate master key

                // Parse
                // SAFETY: read_exact guarantees that the buffer is filled
                let server_hello_message = proto::ServerHelloMessage::try_from(buffer).unwrap();

                // Verify
                let (server_public_key, nonces) = crypto::verify_server_hello(
                    server_hello_message,
                    client_nonce,
                    &self.server_config.sig_pub_key,
                )?;

                // Generate PRK
                let pseudorandom_key = crypto::generate_pseudorandom_key(
                    client_private_key,
                    server_public_key,
                    &nonces,
                )?;

                // Generate master key
                let master_key = crypto::generate_master_key(&pseudorandom_key);

                connection.session_secrets = Some(proto::SessionSecrets {
                    pseudorandom_key,
                    master_key,
                    session_id: nonces, // NOTE: nonces === client_nonce || server_nonce
                });

                Ok(())
            }
            _ => Err(Error::HandshakeAlreadyInitiated),
        }
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        self.establish_connection().await?;
        self.handshake().await?;
        Ok(())
    }
}


#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    #[async_std::test]
    async fn test_client_hello() {
        let test_server_config = ServerConfig::new(SocketAddr::from_str("127.0.0.1:8080").unwrap(), b"test".to_vec());
        let mut test_client = Client::new(test_server_config).unwrap();
        assert_eq!(test_client.client_hello().await.unwrap().0.len(), 64);
    }
}
use std::net::SocketAddr;

use crate::crypto;
use crate::error::Error;
use crate::proto;
use async_std::io::ReadExt;
use async_std::io::WriteExt;

use ring::signature;

pub struct ServerConfig {
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

pub struct Client<S: proto::Stream> {
    server_config: ServerConfig,
    stream: S,
}

impl Client<proto::NilStream> {
    pub fn new(server_config: ServerConfig) -> Result<Self, Error> {
        Ok(Self {
            server_config,
            stream: proto::NilStream,
        })
    }

    pub async fn establish_connection<S: proto::InsecureStream>(self, stream: S) -> Result<Client<S>, Error> {
        Ok(Client {
            stream,
            server_config: self.server_config,
        })
    }
}

impl<S: proto::InsecureStream> Client<S> {
    pub async fn handshake(mut self) -> Result<Client<proto::SecureStream<S>>, Error> {
        let client_nonce = crypto::generate_nonce().await?;
        let (client_private_key, public_key) = crypto::generate_ephemeral_key_pair()?;
        let client_hello_msg = proto::ClientHelloMessage {
            header: proto::ClientHelloMessageHeader {
                version: proto::CURRENT_PROTOCOL_VERSION,
            },
            nonce: client_nonce,
            // SAFETY: public key has the correct length
            public_key_bytes: <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(public_key.as_ref())
                .unwrap(),
        };

        self.stream
            .write_all(&<[u8; proto::CLIENT_HELLO_MSG_LEN]>::from(client_hello_msg))
            .await?;

        let mut buffer = [0u8; proto::SERVER_HELLO_MSG_LEN];
        self.stream.read_exact(&mut buffer).await?;

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
        let pseudorandom_key =
            crypto::generate_pseudorandom_key(client_private_key, server_public_key, &nonces)?;

        // Generate master key
        let master_key = crypto::generate_master_key(&pseudorandom_key);

        let session_secrets = crypto::SessionSecrets::new(
            pseudorandom_key,
            master_key,
            nonces, // NOTE: nonces === client_nonce || server_nonce
        );

        // Upgrade stream to secure
        Ok(Client {
            stream: proto::SecureStream {
                stream: self.stream,
                session_secrets,
            },
            server_config: self.server_config,
        })
    }
}

impl<S: proto::InsecureStream> Client<proto::SecureStream<S>> {
    pub async fn send_resource(&mut self, request: proto::SendResourceRequest) -> Result<(), Error> {
        todo!()
    }
}

impl<S: proto::InsecureStream> Client<S> {
    pub fn disconnect(self) -> Client<proto::NilStream> {
        Client {
            server_config: self.server_config,
            stream: proto::NilStream,
        }
    }
}

mod config;
mod server;
mod state;

use crate::error::Error;
use crate::proto::message::{handshake, len_limit};
use crate::proto::stream::{BaseStream, Plain, PlainStream};
use crate::proto::Side;
use crate::{crypto, error};

use self::config::Config;
use self::server::ServerSigPubKey;
use self::state::*;

#[derive(Debug, Clone, Copy, Default)]
pub struct Client<T: State> {
    state: T,
    conf: Config,
}

impl Client<NoConnection> {
    fn new() -> Self {
        Self {
            state: NoConnection,
            conf: Config::default(),
        }
    }

    fn connect(self, stream: BaseStream) -> Client<InsecureConnection> {
        Client {
            state: InsecureConnection::new(PlainStream::from(stream)),
            conf: self.conf,
        }
    }
}

impl Client<InsecureConnection> {
    async fn client_hello(mut self) -> Result<Client<HandshakingConnection>, (Self, Error)> {
        let client_hello_result = async {
            // Generate client nonce
            let client_nonce = crypto::generate_nonce().await?;

            // Generate ephemeral key pair
            let (client_private_key, public_key) = crypto::generate_ephemeral_key_pair()?;

            let client_hello_msg = handshake::ClientHelloMessage {
                nonce: client_nonce,
                // SAFETY: public key has the correct length
                public_key_bytes: <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(
                    public_key.as_ref(),
                )
                .unwrap(),
            };

            self.state
                .plain_stream()
                .send(client_hello_msg.into())
                .await?;
            Ok::<HandshakeContext, Error>(HandshakeContext {
                nonce: client_nonce,
                private_key: client_private_key,
            })
        }
        .await;

        match client_hello_result {
            Ok(handshake_context) => Ok(Client {
                conf: self.conf,
                state: HandshakingConnection::new(self.state, handshake_context),
            }),
            Err(error) => Err((self, error)),
        }
    }
}

impl Client<HandshakingConnection> {
    async fn server_hello(
        mut self,
        server_hello_msg: handshake::ServerHelloMessage,
        server_sig_pub_key: ServerSigPubKey,
    ) -> Result<Client<UpgradedConnection>, (Client<InsecureConnection>, Error)> {
        let server_hello_result = async {
            // SAFETY: private key has not been taken out before
            let HandshakeContext {
                nonce: client_nonce,
                private_key: client_private_key,
            } = self.state.context().unwrap();

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
                nonces,
                Side::Client,
            )
            .await?;
            Ok::<crypto::secrets::SessionSecrets, Error>(session_secrets)
        }
        .await;

        match server_hello_result {
            Ok(session_secrets) => Ok(Client {
                state: UpgradedConnection::new(self.state, session_secrets),
                conf: self.conf,
            }),
            Err(error) => Err((
                Client {
                    state: self.state.failed(),
                    conf: self.conf,
                },
                error,
            )),
        }
    }
}

impl Client<UpgradedConnection> {
    async fn send_resource_request(mut self) -> Result<Client<SendResourceRequested>, Error> {
        todo!()
    }

    async fn receive_resource_request(mut self) -> Result<Client<ReceiveResourceRequested>, Error> {
        todo!()
    }
}

impl<S: State, T: SecureState<DowngradeState = S>> Client<T> {
    async fn downgrade(mut self) -> Result<Client<S>, Error> {
        self.state
            .plain_stream()
            .send(handshake::DowngradeMessage.into())
            .await?;
        Ok(Client {
            state: self.state.downgrade(),
            conf: self.conf,
        })
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
            conf: Config::default(),
        })
    }

    async fn request_len_limit(mut self, len_limit: usize) -> Result<Client<T>, Error> {
        self.state
            .plain_stream()
            .send(
                len_limit::AdjustMessageLengthRequest::try_new(len_limit)
                    .ok_or(error::InvalidMessageError::NewLengthLimit(len_limit))?
                    .into(),
            )
            .await?;
        Ok(Client {
            state: self.state,
            conf: self.conf.request_len_limit(len_limit),
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

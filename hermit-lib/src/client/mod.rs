mod len_limit;
mod server;
mod state;

use std::{ops::RangeInclusive, sync::Arc};

use crate::proto::{
    channel::{PlainChannel, SecureChannel},
    message::{
        handshake::{ClientHelloMessage, DisconnectMessage, DowngradeMessage, ServerHelloMessage},
        len_limit::{AdjustLenLimitRequest, AdjustLenLimitResponse},
    },
    Side,
};
use crate::{client::state::HandshakeContext, crypto, error};

use self::{len_limit::LenLimit, server::ServerSigPubKey, state::State};

// NOTE: `Client` should be wrapped in a `RwLock` to allow concurrent access, where
// functions that do not mutate the state/len_limit may take a read lock, giving precedence
// to functions that do mutate via a write lock.
pub struct Client {
    channel: Arc<PlainChannel>,
    state: State,
    len_limit: LenLimit,
}

impl Client {
    pub fn new(channel: PlainChannel) -> Self {
        Self {
            channel: Arc::new(channel),
            state: State::default(),
            len_limit: LenLimit::default(),
        }
    }

    pub fn adjust_acceptable_len_limit_range(&mut self, len_limit_range: RangeInclusive<usize>) {
        self.len_limit.adjust_acceptable_range(len_limit_range);
    }
}

impl Client {
    pub async fn send_client_hello(
        &mut self,
        server_sig_pub_key: ServerSigPubKey,
    ) -> Result<(), error::Error> {
        match self.state {
            State::Insecure => {
                async {
                    // Generate client nonce
                    let client_nonce = crypto::generate_nonce().await?;

                    // Generate ephemeral key pair
                    let (client_private_key, public_key) = crypto::generate_ephemeral_key_pair()?;

                    let client_hello_msg = ClientHelloMessage {
                        nonce: client_nonce,
                        // SAFETY: public key has the correct length
                        public_key_bytes: <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(
                            public_key.as_ref(),
                        )
                        .unwrap(),
                    };

                    self.channel.send_msg(client_hello_msg).await?;

                    self.state = State::Handshaking {
                        handshake_context: HandshakeContext {
                            nonce: client_nonce,
                            private_key: client_private_key,
                        },
                        server_sig_pub_key,
                    };
                    Ok(())
                }
                .await
            }
            _ => panic!("Client hello called in invalid state"),
        }
    }

    pub async fn recv_server_hello(
        &mut self,
        server_hello_msg: ServerHelloMessage,
    ) -> Result<(), error::Error> {
        match std::mem::take(&mut self.state) {
            State::Handshaking {
                handshake_context,
                server_sig_pub_key,
            } => {
                async {
                    let HandshakeContext {
                        nonce: client_nonce,
                        private_key: client_private_key,
                    } = handshake_context;

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

                    // Generate secure channel
                    // If any previous error occurs, the state will be set to `Insecure` by `take`.
                    self.state =
                        State::Secure(SecureChannel::new(self.channel.clone(), session_secrets));
                    Ok::<(), error::Error>(())
                }
                .await
            }
            _ => panic!("Server hello received in invalid state"),
        }
    }

    pub async fn send_downgrade(&mut self) -> Result<(), error::Error> {
        match &mut self.state {
            State::Secure(_) => self.channel.send_msg(DowngradeMessage).await,
            _ => panic!("Downgrade called in invalid state"),
        }
    }

    pub async fn recv_downgrade(&mut self, _: DowngradeMessage) -> Result<(), error::Error> {
        match &mut self.state {
            State::Secure(_) => {
                self.state = State::Insecure;
                Ok(())
            }
            _ => panic!("Downgrade received in invalid state"),
        }
    }

    pub async fn send_disconnect(self) -> Result<(), error::Error> {
        self.channel.send_msg(DisconnectMessage).await
    }

    pub async fn recv_disconnect(self, _: DisconnectMessage) {}

    pub async fn send_len_limit_request(&mut self, len_limit: usize) -> Result<(), error::Error> {
        // Per specificiation, return an error if there is an ongoing request.
        if let Some(len_limit) = self.len_limit.requested {
            return Err(error::LenLimitAdjustmentError::OngoingRequest(len_limit).into());
        }

        self.channel
            .send_msg(AdjustLenLimitRequest::try_from(len_limit)?)
            .await?;

        self.len_limit.requested = Some(len_limit);
        Ok(())
    }

    pub async fn recv_len_limit_request(
        &mut self,
        request: AdjustLenLimitRequest,
    ) -> Result<(), error::Error> {
        let len_limit = usize::from(request);
        // Per specificiation, reject if there is an ongoing request.
        let has_accepted = self.len_limit.requested.is_none()
            && self.len_limit.acceptable_range.contains(&len_limit);

        self.channel
            .send_msg(AdjustLenLimitResponse::from(has_accepted))
            .await?;

        if has_accepted {
            self.channel.set_len_limit(len_limit).await;
        }

        Ok(())
    }

    pub async fn recv_len_limit_response(
        &mut self,
        response: AdjustLenLimitResponse,
    ) -> Result<(), error::Error> {
        if let Some(len_limit) = self.len_limit.requested.take() {
            if bool::from(response) {
                self.channel.set_len_limit(len_limit).await;
            }
            Ok(())
        } else {
            Err(error::LenLimitAdjustmentError::NoOngoingRequest.into())
        }
    }
}

//     async fn request_len_limit_responded(
//         &mut self,
//         response: len_limit::AdjustLenLimitResponse,
//     ) -> Result<(), Error> {
//         let len_limit = self
//             .conf
//             .requested_len_limit
//             .take()
//             .ok_or(error::LenLimitAdjustmentError::NoOngoingRequest)?;

//         if response.has_accepted() {
//             self.state.plain_stream().set_len_limit(len_limit);
//         }

//         Ok(())
//     }

// #[cfg(test)]
// mod test {
//     use async_std::{net::TcpListener, task};

//     use super::*;

//     // NOTE: run after command `netcat -l 8080` is executed to listen on TCP port 8080
//     #[ignore]
//     #[async_std::test]
//     async fn test_client_new() {
//         task::spawn(async {
//             TcpListener::bind("127.0.0.1:8080")
//                 .await
//                 .unwrap()
//                 .accept()
//                 .await
//                 .unwrap()
//         });
//         let tcp_stream = async_std::net::TcpStream::connect("127.0.0.1:8080")
//             .await
//             .unwrap();
//         let client = Client::new().connect(BaseStream(tcp_stream));
//     }
// }

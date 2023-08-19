mod len_limit;
mod server;
mod state;

use std::{
    ops::{Deref, RangeInclusive},
    sync::Arc,
};

use crate::proto::{
    channel::{PlainChannel, SecureChannel},
    message::{
        self,
        handshake::{ClientHelloMessage, DisconnectMessage, DowngradeMessage, ServerHelloMessage},
        len_limit::{AdjustLenLimitRequest, AdjustLenLimitResponse},
    },
    Side,
};
use crate::{client::state::HandshakeContext, crypto, error};

use self::{len_limit::LenLimit, server::ServerSigPubKey, state::State};

pub struct Client {
    channel: Arc<PlainChannel>,
    state: State,
    len_limit: LenLimit,
}

impl Client {
    fn new(channel: Arc<PlainChannel>) -> Self {
        Self {
            channel,
            state: State::default(),
            len_limit: LenLimit::default(),
        }
    }

    // NOTE: The final set range is the intersection of the requested range and the acceptable range.
    fn adjust_acceptable_len_limit_range(
        &mut self,
        len_limit_range: RangeInclusive<usize>,
    ) -> RangeInclusive<usize> {
        let &lower_bound = len_limit_range.start().max(&message::MIN_LEN_LIMIT);
        let &upper_bound = len_limit_range.end().min(&message::MAX_LEN_LIMIT);
        let len_limit_range = lower_bound..=upper_bound;
        self.len_limit.acceptable_range = len_limit_range.clone();
        len_limit_range
    }
}

impl Client {
    async fn client_hello(
        &mut self,
        server_sig_pub_key: ServerSigPubKey,
    ) -> Option<Result<(), error::Error>> {
        match self.state {
            State::Insecure => {
                let handshake_context_result = async {
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
                .await;

                Some(handshake_context_result)
            }
            _ => None,
        }
    }

    async fn server_hello(
        &mut self,
        server_hello_msg: ServerHelloMessage,
    ) -> Option<Result<(), error::Error>> {
        let state = std::mem::take(&mut self.state);
        match state {
            State::Handshaking {
                handshake_context,
                server_sig_pub_key,
            } => {
                let server_hello_result = async {
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
                .await;

                Some(server_hello_result)
            }
            _ => {
                self.state = state;
                None
            }
        }
    }

    async fn downgrade(&mut self) -> Option<Result<(), error::Error>> {
        match &mut self.state {
            State::Secure(_) => Some(self.channel.send_msg(DowngradeMessage).await),
            _ => None,
        }
    }

    async fn close(self) -> Result<(), error::Error> {
        self.channel.send_msg(DisconnectMessage).await
    }

    async fn request_len_limit(&mut self, len_limit: usize) -> Result<(), error::Error> {
        async fn helper(
            channel: &PlainChannel,
            len_limit: usize,
            requested: &mut Option<usize>,
        ) -> Result<(), error::Error> {
            // Per specificiation, return an error if there is an ongoing request.
            if let Some(len_limit) = requested {
                return Err(error::LenLimitAdjustmentError::OngoingRequest(*len_limit).into());
            }

            channel
                .send_msg(AdjustLenLimitRequest::try_from(len_limit)?)
                .await?;

            *requested = Some(len_limit);
            Ok(())
        }
        helper(
            self.channel.deref(),
            len_limit,
            &mut self.len_limit.requested,
        )
        .await
    }

    async fn respond_len_limit(
        &mut self,
        request: AdjustLenLimitRequest,
    ) -> Result<(), error::Error> {
        async fn helper(
            channel: &PlainChannel,
            len_limit: &LenLimit,
            request: usize,
        ) -> Result<Option<usize>, error::Error> {
            // Per specificiation, reject if there is an ongoing request.
            let has_accepted =
                len_limit.requested.is_none() && len_limit.acceptable_range.contains(&request);

            channel
                .send_msg(AdjustLenLimitResponse::new(has_accepted))
                .await?;

            Ok(if has_accepted { Some(request) } else { None })
        }

        let helper_result = helper(self.channel.deref(), &self.len_limit, request.into()).await;
        if let Ok(Some(len_limit)) = helper_result {
            self.channel.set_len_limit(len_limit).await;
        }

        helper_result.map(|_| ())
    }

    async fn request_len_limit_responded(
        &mut self,
        response: AdjustLenLimitResponse,
    ) -> Result<(), error::Error> {
        if let Some(len_limit) = self.len_limit.requested.take() {
            if response.has_accepted() {
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

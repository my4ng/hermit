use crate::crypto::NONCE_LEN;
use crate::proto::channel::SecureChannel;

use super::server::ServerSigPubKey;

pub(super) enum State {
    Insecure,
    Handshaking {
        handshake_context: HandshakeContext,
        server_sig_pub_key: ServerSigPubKey,
    },
    Secure(SecureChannel),
}

impl Default for State {
    fn default() -> Self {
        Self::Insecure
    }
}

pub(super) struct HandshakeContext {
    pub(super) nonce: [u8; NONCE_LEN],
    pub(super) private_key: ring::agreement::EphemeralPrivateKey,
}

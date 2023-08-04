use crate::crypto::secrets::SessionSecrets;
use crate::crypto::NONCE_LEN;
use crate::proto::stream::{Plain, PlainStream, Secure, SecureStream};
use crate::{nil, plain, secure};


pub trait State {}
pub trait PlainState: State {
    type PlainStream: Plain;
    fn plain_stream(&mut self) -> &mut Self::PlainStream;
}
pub trait SecureState: PlainState {
    type DowngradeState: PlainState;
    type SecureStream: Secure;
    fn secure_stream(&mut self) -> &mut Self::SecureStream;
    fn downgrade(self) -> Self::DowngradeState;
}

pub(super) struct NoConnection;
nil!(NoConnection);

pub(super) struct InsecureConnection(PlainStream);
plain!(InsecureConnection);
impl InsecureConnection {
    pub(super) fn new(stream: PlainStream) -> Self {
        Self(stream)
    }
}

pub(super) struct HandshakeContext {
    pub(super) nonce: [u8; NONCE_LEN],
    pub(super) private_key: ring::agreement::EphemeralPrivateKey,
}

pub(super) struct HandshakingConnection(
    PlainStream,
    Option<HandshakeContext>,
);
plain!(HandshakingConnection);
impl HandshakingConnection {
    pub(super) fn new(
        state: InsecureConnection,
        handshake_parameters: HandshakeContext,
    ) -> Self {
        Self(state.0, Some(handshake_parameters))
    }
    pub(super) fn context(
        &mut self,
    ) -> Option<HandshakeContext> {
        self.1.take()
    }

    pub(super) fn failed(self) -> InsecureConnection {
        InsecureConnection::new(self.0)
    }
}

pub(super) struct UpgradedConnection(SecureStream);
secure!(UpgradedConnection);
impl UpgradedConnection {
    pub(super) fn new(state: HandshakingConnection, session_secrets: SessionSecrets) -> Self {
        Self(SecureStream::new(state.0, session_secrets))
    }
}

pub(super) struct SendResourceRequested(SecureStream);
secure!(SendResourceRequested);

pub(super) struct ReceiveResourceRequested(SecureStream);
secure!(ReceiveResourceRequested);

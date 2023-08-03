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
    type UnderlyingStream: Plain;
    type SecureStream: Secure<PlainType = Self::UnderlyingStream>;
    fn secure_stream(&mut self) -> &mut Self::SecureStream;
    fn downgrade(self) -> Self::UnderlyingStream;
}

pub(super) struct NoConnection;
nil!(NoConnection);

pub(super) struct InsecureConnection(PlainStream);
plain!(InsecureConnection);
impl InsecureConnection {
    pub(super) fn new(_: NoConnection, stream: PlainStream) -> Self {
        Self(stream)
    }
    pub(super) fn downgrade(state: impl SecureState<UnderlyingStream = PlainStream>) -> Self {
        Self(state.downgrade())
    }
}

pub(super) struct HandshakingConnection(
    PlainStream,
    Option<([u8; NONCE_LEN], ring::agreement::EphemeralPrivateKey)>,
);
plain!(HandshakingConnection);
impl HandshakingConnection {
    pub(super) fn new(
        state: InsecureConnection,
        nonce: [u8; NONCE_LEN],
        private_key: ring::agreement::EphemeralPrivateKey,
    ) -> Self {
        Self(state.0, Some((nonce, private_key)))
    }
    pub(super) fn nonce_private_key(&mut self) -> Option<([u8; NONCE_LEN], ring::agreement::EphemeralPrivateKey)> {
        self.1.take()
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

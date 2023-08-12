use std::sync::Arc;

use crate::crypto::secrets::SessionSecrets;
use crate::crypto::NONCE_LEN;
use crate::proto::stream::{PlainStream, SecureStream};
use crate::{nil, plain, secure};


pub trait State {}
pub trait PlainState: State {
    fn plain_stream(&mut self) -> Arc<PlainStream>;
}
pub trait SecureState: PlainState {
    type DowngradeState: PlainState;
    fn secure_stream(&mut self) -> Arc<SecureStream>;
    fn downgrade(self) -> Self::DowngradeState;
}

pub(super) struct NoConnection;
nil!(NoConnection);

pub(super) struct InsecureConnection(Arc<PlainStream>);
plain!(InsecureConnection);
impl InsecureConnection {
    pub(super) fn new(stream: Arc<PlainStream>) -> Self {
        Self(stream)
    }
}

pub(super) struct HandshakeContext {
    pub(super) nonce: [u8; NONCE_LEN],
    pub(super) private_key: ring::agreement::EphemeralPrivateKey,
}

pub(super) struct HandshakingConnection(
    Arc<PlainStream>,
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

pub(super) struct UpgradedConnection(Arc<SecureStream>);
secure!(UpgradedConnection);
impl UpgradedConnection {
    pub(super) fn new(state: HandshakingConnection, session_secrets: SessionSecrets) -> Self {
        Self(Arc::new(SecureStream::upgrade(state.0, session_secrets)))
    }
}

pub(super) struct SendResourceRequested(Arc<SecureStream>);
secure!(SendResourceRequested);

pub(super) struct ReceiveResourceRequested(Arc<SecureStream>);
secure!(ReceiveResourceRequested);

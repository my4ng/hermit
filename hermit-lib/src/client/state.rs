use crate::crypto::secrets::SessionSecrets;
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

pub struct NoConnection;
nil!(NoConnection);

pub struct InsecureConnection(PlainStream);
plain!(InsecureConnection);
impl InsecureConnection {
    pub(super) fn new(_: NoConnection, stream: PlainStream) -> Self {
        Self(stream)
    }
    pub(super) fn downgrade(state: impl SecureState<UnderlyingStream = PlainStream>) -> Self {
        Self(state.downgrade())
    }
}

pub struct HandshakingConnection(PlainStream, ring::agreement::EphemeralPrivateKey);
plain!(HandshakingConnection);
impl HandshakingConnection {
    pub(super) fn new(state: InsecureConnection, private_key: ring::agreement::EphemeralPrivateKey) -> Self {
        Self(state.0, private_key)
    }
}

pub struct UpgradedConnection(SecureStream);
secure!(UpgradedConnection);
impl UpgradedConnection {
    pub(super) fn new(stream: PlainStream, session_secrets: SessionSecrets) -> Self {
        Self(SecureStream::new(stream, session_secrets))
    }
}

pub struct SendResourceRequested(SecureStream);
secure!(SendResourceRequested);

pub struct ReceiveResourceRequested(SecureStream);
secure!(ReceiveResourceRequested);

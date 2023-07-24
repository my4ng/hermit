use thiserror;
use ring;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Cryptography error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("IO/Network error: {0}")]
    IONetwork(#[from] async_std::io::Error),
    #[error("Unable to initiate handshake; TCP connection not established")]
    ConnectionNotEstablished,
    #[error("Unable to initiate handshake; handshake already initiated")]
    HandshakeAlreadyInitiated,
    #[error("Message parsing error; binary: {0:?}")]
    Parsing(Vec<u8>),
}

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("An error with absolutely no details")]
    Unspecified,
    #[error("An error parsing or validating a key: {0}")]
    KeyRejected(&'static str),
    #[error("Bad server hello signature")]
    BadServerHelloSignature,
    #[error("Bad server public key")]
    BadServerPublicKey,
}

impl From<ring::error::Unspecified> for CryptoError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Unspecified
    }
}

impl From<ring::error::KeyRejected> for CryptoError {
    fn from(err: ring::error::KeyRejected) -> Self {
        Self::KeyRejected(err.description_())
    }
}
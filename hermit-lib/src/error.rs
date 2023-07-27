use ring;
use thiserror;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error performing cryptographic operations: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Error in IO/Network: {0}")]
    IONetwork(#[from] async_std::io::Error),
    #[error("Error parsing message: {0}")]
    MessageParsing(#[from] InvalidMessageError),
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

#[derive(thiserror::Error, Debug)]
pub enum InvalidMessageError {
    #[error("Invalid message length: {0}")]
    MessageLength(usize),
    #[error("Invalid message type: {0}")]
    MessageType(u8),
    #[error("Invalid protocol version: {0}")]
    ProtocolVersion(u8),
    #[error("Invalid payload length; expected {expected}, got {actual}")]
    PayloadLength { expected: usize, actual: usize },
    #[error("Invalid field ({field}) content: {binary:?}")]
    FieldContent {
        binary: Vec<u8>,
        field: &'static str,
    },
}

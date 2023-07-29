use ring;
use thiserror;

use crate::proto::{self, message};

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
    MessageType(#[from] num_enum::TryFromPrimitiveError<message::MessageType>),
    #[error("Invalid secure message type: {0}")]
    SecureMessageType(#[from] num_enum::TryFromPrimitiveError<message::SecureMessageType>),
    #[error("Invalid protocol version: {0}")]
    ProtocolVersion(#[from] num_enum::TryFromPrimitiveError<proto::ProtocolVersion>),
    #[error("Invalid payload length; expected {expected}, got {actual}")]
    PayloadLength { expected: usize, actual: usize },
    #[error("Secure payload too large; size: {0}")]
    SecurePayloadTooLarge(usize),
    #[error("CBOR deserialization error: {0}")]
    CborDeserialization(#[from] ciborium::de::Error<std::io::Error>),
    #[error("CBOR serialization error: {0}")]
    CborSerialization(#[from] ciborium::ser::Error<std::io::Error>),
}

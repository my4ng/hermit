use ring;
use thiserror;

use crate::proto::ProtocolVersion;
use crate::proto::message::{PlainMessageType, SecureMessageType};

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
    #[error("Invalid message type: {0}")]
    MessageType(#[from] num_enum::TryFromPrimitiveError<PlainMessageType>),
    #[error("Invalid secure message type: {0}")]
    SecureMessageType(#[from] num_enum::TryFromPrimitiveError<SecureMessageType>),
    #[error("Invalid protocol version: {0}")]
    ProtocolVersion(#[from] num_enum::TryFromPrimitiveError<ProtocolVersion>),
    #[error("Payload length out of valid range; length {length}")]
    PayloadLengthOutOfRange { length: usize },
    #[error("Payload length above limit; length {length}, limit {limit}")]
    PayloadLengthAboveLimit { length: usize, limit: usize },
    #[error("Invalid payload length; expected {expected}, got {actual}")]
    PayloadLengthMismatch { expected: usize, actual: usize },
    #[error("CBOR deserialization error: {0}")]
    CborDeserialization(String),
    #[error("CBOR serialization error: {0}")]
    CborSerialization(String),
}

// Fix for rust-analyzer
#![allow(non_upper_case_globals)]

use ciborium_io::Write;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{de, ser, Deserialize, Serialize};

use super::stream::SecureStream;
use crate::{error, proto::ProtocolVersion};

pub(crate) use ring::aead::MAX_TAG_LEN as TAG_LEN;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, Deserialize, Serialize,
)]
#[repr(u8)]
#[non_exhaustive]
pub enum SecureMessageType {
    SendResourceRequest = 0x01,
    SendResourceResponse = 0x02,
    ReceiveResourceRequest = 0x03,
    ReceiveResourceResponse = 0x04,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(in crate::proto) struct Header {
    pub(in crate::proto) message_type: SecureMessageType,
    pub(in crate::proto) version: ProtocolVersion,
    pub(in crate::proto) length: usize,
}

// TODO: Separate transport layer protocol (Plain) from application layer protocol (Secure).
// The former uses plain bytes and a fixed-length header, while the latter uses CBOR and a
// variable-length header.

pub(in crate::proto) trait Secure:
    Sized + ser::Serialize + de::DeserializeOwned
{
    fn send(&self, mut secure_stream: &mut SecureStream) -> Result<(), error::Error> {
        ciborium::into_writer(self, &mut secure_stream).map_err(|err| match err {
            ciborium::ser::Error::Io(error) => error,
            ciborium::ser::Error::Value(string) => {
                error::InvalidMessageError::CborSerialization(string).into()
            }
        })?;
        (&mut secure_stream).flush()
    }
    fn recv(mut secure_stream: &mut SecureStream) -> Result<Self, error::Error> {
        ciborium::from_reader(&mut secure_stream).map_err(|err| match err {
            ciborium::de::Error::Io(error) => error,
            others => error::InvalidMessageError::CborDeserialization(others.to_string()).into(),
        })
    }
}

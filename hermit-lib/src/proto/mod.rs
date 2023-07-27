mod handshake;
pub(crate) mod message;
pub(crate) mod stream;
mod transfer;

use crate::error;

pub(crate) static CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V0_1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolVersion {
    // NOTE: 0x00 RESERVED
    V0_1 = 0x01,
}

impl From<ProtocolVersion> for u8 {
    fn from(version: ProtocolVersion) -> Self {
        match version {
            ProtocolVersion::V0_1 => 0x01,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<u8> for ProtocolVersion {
    type Error = error::InvalidMessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::V0_1),
            _ => Err(error::InvalidMessageError::ProtocolVersion(value)),
        }
    }
}

pub(crate) enum Side {
    Client,
    Server,
}

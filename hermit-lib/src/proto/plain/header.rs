#![allow(non_upper_case_globals)]
use num_enum::{IntoPrimitive, TryFromPrimitive};

use crate::{error, proto::ProtocolVersion};

pub(crate) const MSG_HEADER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum PlainMessageType {
    Secure = 0x00,
    ClientHello = 0x01,
    ServerHello = 0x02,
    Disconnect = 0x03,
    Downgrade = 0x04,

    AdjustLenLimitRequest = 0x10,
    AdjustLenLimitResponse = 0x11,
}

// LAYOUT:
// |0         |1         |2         |3         |
// |----------|----------|----------|----------|
// |type      |version   |length               |
// |----------|----------|---------------------|
// |payload                                    |
// |                                           |
// :                                           :
// |-------------------------------------------|

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub(crate) struct MessageHeader {
    plain_msg_type: PlainMessageType,
    version: ProtocolVersion,
    length: usize,
}

impl MessageHeader {
    pub(super) fn new(
        plain_msg_type: PlainMessageType,
        version: ProtocolVersion,
        length: usize,
    ) -> Self {
        Self {
            plain_msg_type,
            version,
            length,
        }
    }

    pub(super) fn plain_msg_type(&self) -> PlainMessageType {
        self.plain_msg_type
    }

    pub(super) fn version(&self) -> ProtocolVersion {
        self.version
    }

    pub(super) fn length(&self) -> usize {
        self.length
    }
}

impl TryFrom<&[u8; MSG_HEADER_LEN]> for MessageHeader {
    type Error = error::InvalidMessageError;

    fn try_from(value: &[u8; MSG_HEADER_LEN]) -> Result<Self, Self::Error> {
        Ok(Self {
            plain_msg_type: PlainMessageType::try_from(value[0])?,
            version: ProtocolVersion::try_from(value[1])?,
            length: u16::from_be_bytes([value[2], value[3]]) as usize,
        })
    }
}

impl From<MessageHeader> for [u8; MSG_HEADER_LEN] {
    fn from(value: MessageHeader) -> Self {
        let mut buf = [0u8; MSG_HEADER_LEN];
        buf[0] = value.plain_msg_type.into();
        buf[1] = value.version.into();
        buf[2..4].copy_from_slice(&u16::to_be_bytes(value.length as u16));
        buf
    }
}

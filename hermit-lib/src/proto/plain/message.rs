#![allow(non_upper_case_globals)]
use crate::{
    error,
    proto::{ProtocolVersion, CURRENT_PROTOCOL_VERSION},
};

use crate::proto::message::MSG_HEADER_LEN;
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum PlainMessageType {
    Secure = 0x00,
    ClientHello = 0x01,
    ServerHello = 0x02,
    Disconnect = 0x03,
    Downgrade = 0x04,

    AdjustMessageLengthRequest = 0x10,
    AdjustMessageLengthResponse = 0x11,
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
pub(crate) struct MessageHeader {
    plain_msg_type: PlainMessageType,
    version: ProtocolVersion,
    length: usize,
}

impl MessageHeader {
    pub(crate) fn plain_msg_type(&self) -> PlainMessageType {
        self.plain_msg_type
    }

    pub(crate) fn version(&self) -> ProtocolVersion {
        self.version
    }

    pub(crate) fn length(&self) -> usize {
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

pub struct Message {
    header: MessageHeader,
    payload: Box<[u8]>,
}

impl Message {
    pub(crate) fn new(msg_type: PlainMessageType, payload: Box<[u8]>) -> Self {
        Self {
            header: MessageHeader {
                plain_msg_type: msg_type,
                version: CURRENT_PROTOCOL_VERSION,
                length: payload.len(),
            },
            payload,
        }
    }

    // TODO: Use uninit such that the payload is not initialized
    // CAUTION: Only use this function to receive messages by filling the payload
    pub(in crate::proto) fn raw(
        header: &[u8; MSG_HEADER_LEN],
    ) -> Result<Self, error::InvalidMessageError> {
        let header = MessageHeader::try_from(header)?;
        Ok(Self {
            payload: Box::from(vec![0u8; header.length]),
            header,
        })
    }

    pub(in crate::proto) fn header(&self) -> MessageHeader {
        self.header
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        self.payload.as_ref()
    }
}

impl AsMut<[u8]> for Message {
    fn as_mut(&mut self) -> &mut [u8] {
        self.payload.as_mut()
    }
}

impl From<Message> for Box<[u8]> {
    fn from(value: Message) -> Self {
        value.payload
    }
}

use ring::aead;
use super::handshake;
pub(crate) use aead::MAX_TAG_LEN as TAG_LEN;


pub(crate) use handshake::ClientHelloMessage as ClientHelloMessage;
pub(crate) use handshake::ServerHelloMessage as ServerHelloMessage;

use super::{ProtocolVersion, CURRENT_PROTOCOL_VERSION};
use crate::error;

pub(crate) const MESSAGE_HEADER_LEN: usize = 4;
pub(crate) const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;
pub(crate) const MAX_SECURE_PAYLOAD_LEN: usize = MAX_PAYLOAD_LEN - TAG_LEN;

pub(super) trait Plain: TryFrom<Message> + Into<Message> {}
pub(super) trait Secure: TryFrom<SecureMessage> + Into<SecureMessage> {}

#[repr(u8)]
pub(super) enum SecureMessageType {
    SendResourceRequest = 0x01,
    SendResourceResponse = 0x02,
    ReceiveResourceRequest = 0x03,
    ReceiveResourceResponse = 0x04,
}

impl TryFrom<u8> for SecureMessageType {
    type Error = error::InvalidMessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::SendResourceRequest),
            0x02 => Ok(Self::SendResourceResponse),
            0x03 => Ok(Self::ReceiveResourceRequest),
            0x04 => Ok(Self::ReceiveResourceResponse),
            _ => Err(error::InvalidMessageError::MessageType(value)),
        }
    }
}

impl From<SecureMessageType> for u8 {
    fn from(msg_type: SecureMessageType) -> Self {
        match msg_type {
            SecureMessageType::SendResourceRequest => 0x01,
            SecureMessageType::SendResourceResponse => 0x02,
            SecureMessageType::ReceiveResourceRequest => 0x03,
            SecureMessageType::ReceiveResourceResponse => 0x04,
            _ => unreachable!(),
        }
    }
}

// LAYOUT:
// |0         |1         |2         |3         |
// |----------|----------|----------|----------|
// |type      |                                |
// |----------|--------------------------------|
// |payload                                    |
// |                                           |
// :                                           :
// |-------------------------------------------|

// TODO: Add generic parameter to distinguish between client and server messages, such that
// server can only send server messages and receive client messages, and vice versa
pub struct SecureMessage(Vec<u8>);

impl SecureMessage {
    pub(super) fn new(
        length: usize,
        msg_type: SecureMessageType,
    ) -> Result<Self, error::InvalidMessageError> {
        if length > MAX_SECURE_PAYLOAD_LEN {
            return Err(error::InvalidMessageError::PayloadLength {
                expected: MAX_SECURE_PAYLOAD_LEN,
                actual: length,
            });
        }

        let mut msg = Self(vec![0; 2 * MESSAGE_HEADER_LEN + length + TAG_LEN]);
        msg.0[MESSAGE_HEADER_LEN] = msg_type.into();
        Ok(msg)
    }

    // SAFETY: message is well-formed if it is created by `SecureMessage::new`

    pub(super) fn payload(&self) -> &[u8] {
        &self.0[2 * MESSAGE_HEADER_LEN..self.0.len() - TAG_LEN]
    }

    pub(super) fn payload_mut(&mut self) -> &mut [u8] {
        let length = self.0.len();
        &mut self.0[2 * MESSAGE_HEADER_LEN..length - TAG_LEN]
    }

    pub(super) fn secure_msg_type(&self) -> Result<SecureMessageType, error::InvalidMessageError> {
        SecureMessageType::try_from(self.0[MESSAGE_HEADER_LEN])
    }

    pub(super) fn tag(&self) -> &[u8] {
        &self.0[self.0.len() - TAG_LEN..]
    }

    pub(super) fn tag_mut(&mut self) -> &mut [u8] {
        let length = self.0.len();
        &mut self.0[length - TAG_LEN..]
    }
}

impl From<Message> for SecureMessage {
    fn from(msg: Message) -> Self {
        Self(msg.0)
    }
}

impl From<SecureMessage> for Message {
    fn from(msg: SecureMessage) -> Self {
        let mut bytes = msg.0;
        bytes[0] = MessageType::Secure.into();
        bytes[1] = CURRENT_PROTOCOL_VERSION.into();
        // SAFETY: length <= u16::MAX
        let length = (bytes.len() - MESSAGE_HEADER_LEN) as u16;
        [bytes[2], bytes[3]] = length.to_be_bytes();
        Self(bytes)
    }
}

#[repr(u8)]
pub(super) enum MessageType {
    Secure = 0x00,
    ClientHello = 0x01,
    ServerHello = 0x02,
    Disconnect = 0x03,
    Downgrade = 0x04,
}

impl From<MessageType> for u8 {
    fn from(msg_type: MessageType) -> Self {
        match msg_type {
            MessageType::Secure => 0x00,
            MessageType::ClientHello => 0x01,
            MessageType::ServerHello => 0x02,
            MessageType::Disconnect => 0x03,
            MessageType::Downgrade => 0x04,
            _ => unreachable!(),
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = error::InvalidMessageError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Secure),
            0x01 => Ok(Self::ClientHello),
            0x02 => Ok(Self::ServerHello),
            0x03 => Ok(Self::Disconnect),
            0x04 => Ok(Self::Downgrade),
            _ => Err(error::InvalidMessageError::MessageType(value)),
        }
    }
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

pub struct Message(Vec<u8>);

impl Message {
    pub(super) fn new(length: usize, msg_type: MessageType) -> Result<Self, error::InvalidMessageError> {
        if length > MAX_PAYLOAD_LEN {
            return Err(error::InvalidMessageError::PayloadLength {
                expected: MAX_PAYLOAD_LEN,
                actual: length,
            });
        }

        let mut msg = Self(vec![0; MESSAGE_HEADER_LEN + length]);
        msg.0[0] = msg_type.into();
        msg.0[1] = CURRENT_PROTOCOL_VERSION.into();
        [msg.0[2], msg.0[3]] = (length as u16).to_be_bytes();
        Ok(msg)
    }

    pub(super) fn raw(length: u16) -> Self {
        Self(vec![0; MESSAGE_HEADER_LEN + length as usize])
    }

    // SAFETY: message is well-formed if it is created by `Message::new`

    pub(super) fn header_mut(&mut self) -> &mut [u8] {
        &mut self.0[..MESSAGE_HEADER_LEN]
    }

    pub(super) fn payload(&self) -> &[u8] {
        &self.0[MESSAGE_HEADER_LEN..]
    }

    pub(super) fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.0[MESSAGE_HEADER_LEN..]
    }

    pub(super) fn msg_type(&self) -> Result<MessageType, error::InvalidMessageError> {
        MessageType::try_from(self.0[0])
    }

    pub(super) fn version(&self) -> Result<ProtocolVersion, error::InvalidMessageError> {
        ProtocolVersion::try_from(self.0[1])
    }

    pub(super) fn length(&self) -> usize {
        u16::from_be_bytes([self.0[2], self.0[3]]) as usize
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

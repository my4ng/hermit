mod types;

use std::io::Cursor;
use ring::aead;
pub(crate) use aead::MAX_TAG_LEN as TAG_LEN;

pub(crate) use types::*;
pub(crate) use super::handshake::*;
pub(crate) use super::transfer::*;

use super::{ProtocolVersion, CURRENT_PROTOCOL_VERSION};
use crate::error;

pub(crate) const MESSAGE_HEADER_LEN: usize = 4;
pub(crate) const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;
pub(crate) const MAX_SECURE_PAYLOAD_LEN: usize = MAX_PAYLOAD_LEN - MESSAGE_HEADER_LEN - TAG_LEN;

// NOTE: All plain message lengths must be fixed and less than `MAX_PAYLOAD_LEN`. 
pub(super) trait Plain: TryFrom<Message> + Into<Message> {}

// CAUTION: Secure messages are not allowed to be longer than `MAX_SECURE_PAYLOAD_LEN`.
// Otherwise, `TryInto` will return `InvalidMessageError::PayloadTooLong`.
pub(super) trait Secure: TryFrom<SecureMessage> + TryInto<SecureMessage> {}

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
    pub(super) fn new(msg_type: SecureMessageType) -> Self {
        let mut msg = Self(vec![0; 2 * MESSAGE_HEADER_LEN]);
        msg.0[MESSAGE_HEADER_LEN] = msg_type.into();
        msg
    }

    // SAFETY: message is well-formed if it is created by `SecureMessage::new`

    pub(super) fn writer(&mut self) -> Cursor<&mut Vec<u8>> {
        let mut cursor = Cursor::new(&mut self.0);
        cursor.set_position(2 * MESSAGE_HEADER_LEN as u64);
        cursor
    }

    pub(super) fn payload(&self) -> &[u8] {
        &self.0[2 * MESSAGE_HEADER_LEN..]
    }

    pub(super) fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.0[2 * MESSAGE_HEADER_LEN..]
    }

    pub(super) fn above_max_len(&self) -> Result<(), error::InvalidMessageError> {
        let len = self.payload().len();
        if len > MAX_SECURE_PAYLOAD_LEN {
            Err(error::InvalidMessageError::SecurePayloadTooLarge(len))
        } else {
            Ok(())
        }
    }
}

impl From<(SecureMessage, aead::Tag)> for Message {
    fn from((secure_message, tag): (SecureMessage, aead::Tag)) -> Self {
        let mut bytes = secure_message.0;
        bytes.extend_from_slice(tag.as_ref());
        
        bytes[0] = MessageType::Secure.into();
        bytes[1] = CURRENT_PROTOCOL_VERSION.into();
        // SAFETY: length <= u16::MAX
        let length = (bytes.len() - MESSAGE_HEADER_LEN) as u16;
        [bytes[2], bytes[3]] = length.to_be_bytes();
        
        Message(bytes)
    }
}

impl From<Message> for SecureMessage {
    fn from(mut value: Message) -> Self {
        value.0.truncate(value.0.len() - TAG_LEN);
        Self(value.0)
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
        let mut msg = Self(vec![0; MESSAGE_HEADER_LEN + length]);
        msg.0[0] = msg_type.into();
        msg.0[1] = CURRENT_PROTOCOL_VERSION.into();
        [msg.0[2], msg.0[3]] = (length as u16).to_be_bytes();
        Ok(msg)
    }

    // TODO: Use uninit such that the payload is not initialized
    // CAUTION: Only use this function to receive messages by filling the payload
    pub(super) fn raw(header: &[u8; MESSAGE_HEADER_LEN]) -> Self {
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut msg = Self(vec![0; MESSAGE_HEADER_LEN + length]);
        msg.0[..MESSAGE_HEADER_LEN].copy_from_slice(header);
        msg
    }

    // SAFETY: message is well-formed if it is created by `Message::new`

    pub(super) fn payload(&self) -> &[u8] {
        &self.0[MESSAGE_HEADER_LEN..]
    }

    pub(super) fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.0[MESSAGE_HEADER_LEN..]
    }

    pub(super) fn msg_type(&self) -> Result<MessageType, error::InvalidMessageError> {
        MessageType::try_from(self.0[0]).map_err(error::InvalidMessageError::from)
    }

    pub(super) fn version(&self) -> Result<ProtocolVersion, error::InvalidMessageError> {
        ProtocolVersion::try_from(self.0[1]).map_err(error::InvalidMessageError::from)
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
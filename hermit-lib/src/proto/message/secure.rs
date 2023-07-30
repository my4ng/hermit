use std::io::Cursor;

use ring::aead;

use crate::{error, proto::CURRENT_PROTOCOL_VERSION};
use super::{PlainMessage, PlainMessageType, SecureMessageType, MESSAGE_HEADER_LEN, TAG_LEN};

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
pub struct SecureMessage(pub(super) Vec<u8>);

impl SecureMessage {
    pub(in crate::proto) fn new(msg_type: SecureMessageType) -> Self {
        let mut msg = Self(vec![0; 2 * MESSAGE_HEADER_LEN]);
        msg.0[MESSAGE_HEADER_LEN] = msg_type.into();
        msg
    }

    pub(in crate::proto) fn writer(&mut self) -> Cursor<&mut Vec<u8>> {
        let mut cursor = Cursor::new(&mut self.0);
        cursor.set_position(2 * MESSAGE_HEADER_LEN as u64);
        cursor
    }

    pub(in crate::proto) fn payload(&self) -> &[u8] {
        &self.0[2 * MESSAGE_HEADER_LEN..]
    }

    pub(in crate::proto) fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.0[2 * MESSAGE_HEADER_LEN..]
    }

    pub(crate) fn secure_msg_type(&self) -> Result<SecureMessageType, error::InvalidMessageError> {
        self.0[MESSAGE_HEADER_LEN]
            .try_into()
            .map_err(error::InvalidMessageError::from)
    }
}

impl From<(SecureMessage, aead::Tag)> for PlainMessage {
    fn from((secure_message, tag): (SecureMessage, aead::Tag)) -> Self {
        let mut bytes = secure_message.0;
        bytes.extend_from_slice(tag.as_ref());

        bytes[0] = PlainMessageType::Secure.into();
        bytes[1] = CURRENT_PROTOCOL_VERSION.into();
        // SAFETY: length <= u16::MAX
        let length = (bytes.len() - MESSAGE_HEADER_LEN) as u16;
        [bytes[2], bytes[3]] = length.to_be_bytes();

        PlainMessage(bytes)
    }
}

impl From<PlainMessage> for SecureMessage {
    fn from(mut value: PlainMessage) -> Self {
        value.0.truncate(value.0.len() - TAG_LEN);
        Self(value.0)
    }
}

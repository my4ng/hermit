use crate::{
    error,
    proto::{ProtocolVersion, CURRENT_PROTOCOL_VERSION},
};

use super::{PlainMessageType, MSG_HEADER_LEN};

// LAYOUT:
// |0         |1         |2         |3         |
// |----------|----------|----------|----------|
// |type      |version   |length               |
// |----------|----------|---------------------|
// |payload                                    |
// |                                           |
// :                                           :
// |-------------------------------------------|

pub struct PlainMessage(pub(super) Vec<u8>);

impl PlainMessage {
    pub(in crate::proto) fn new(length: u16, plain_msg_type: PlainMessageType) -> Self {
        let mut msg = Self(vec![0; MSG_HEADER_LEN + length as usize]);
        msg.0[0] = plain_msg_type.into();
        msg.0[1] = CURRENT_PROTOCOL_VERSION.into();
        [msg.0[2], msg.0[3]] = length.to_be_bytes();
        msg
    }

    // TODO: Use uninit such that the payload is not initialized
    // CAUTION: Only use this function to receive messages by filling the payload
    pub(in crate::proto) fn raw(header: &[u8; MSG_HEADER_LEN]) -> Self {
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        let mut msg = Self(vec![0; MSG_HEADER_LEN + length]);
        msg.0[..MSG_HEADER_LEN].copy_from_slice(header);
        msg
    }

    // SAFETY: message is well-formed if it is created by `Message::new` or `Message::raw`

    pub(in crate::proto) fn payload(&self) -> &[u8] {
        &self.0[MSG_HEADER_LEN..]
    }

    pub(in crate::proto) fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.0[MSG_HEADER_LEN..]
    }

    pub(crate) fn plain_msg_type(&self) -> Result<PlainMessageType, error::InvalidMessageError> {
        PlainMessageType::try_from(self.0[0]).map_err(error::InvalidMessageError::from)
    }

    pub(crate) fn version(&self) -> Result<ProtocolVersion, error::InvalidMessageError> {
        ProtocolVersion::try_from(self.0[1]).map_err(error::InvalidMessageError::from)
    }

    pub(crate) fn length(&self) -> usize {
        u16::from_be_bytes([self.0[2], self.0[3]]) as usize
    }
}

impl AsRef<[u8]> for PlainMessage {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

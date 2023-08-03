use super::header::{MessageHeader, PlainMessageType, MSG_HEADER_LEN};
use crate::{error, proto::CURRENT_PROTOCOL_VERSION};

pub struct Message {
    header: MessageHeader,
    payload: Box<[u8]>,
}

impl Message {
    pub(crate) fn new(plain_msg_type: PlainMessageType, payload: Box<[u8]>) -> Self {
        Self {
            header: MessageHeader::new(plain_msg_type, CURRENT_PROTOCOL_VERSION, payload.len()),
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
            payload: Box::from(vec![0u8; header.length()]),
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

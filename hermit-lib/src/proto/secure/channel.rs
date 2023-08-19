use std::sync::Arc;

use super::buffer::{ReadBuffer, WriteBuffer};
use crate::crypto::secrets;
use crate::proto::channel::PlainChannel;

pub struct SecureChannel {
    channel: Arc<PlainChannel>,
    session_secrets: secrets::SessionSecrets,
    read_buffer: ReadBuffer,
    write_buffer: WriteBuffer,
}

impl SecureChannel {
    pub(crate) fn new(
        channel: Arc<PlainChannel>,
        session_secrets: secrets::SessionSecrets,
    ) -> Self {
        Self {
            channel,
            session_secrets,
            read_buffer: ReadBuffer::new(),
            write_buffer: WriteBuffer::new(),
        }
    }
}

// NOTE: TAG_LEN of space has been reserved at the end of the payload when
// sealing and opening.

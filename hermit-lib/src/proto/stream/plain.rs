use async_std::io::prelude::*;

use super::BaseStream;
use crate::error;
use crate::proto::message::{Message, MIN_LEN_LIMIT, MSG_HEADER_LEN, MAX_LEN_LIMIT};

#[async_trait::async_trait]
pub trait Plain {
    async fn send(&mut self, message: Message) -> Result<(), error::Error>;
    async fn recv(&mut self) -> Result<Message, error::Error>;
}

pub struct PlainStream {
    stream: BaseStream,
    len_limit: usize,
    header_buffer: [u8; MSG_HEADER_LEN],
}

impl PlainStream {
    pub(crate) fn new(stream: BaseStream) -> Self {
        Self {
            stream,
            len_limit: MIN_LEN_LIMIT,
            header_buffer: [0u8; MSG_HEADER_LEN],
        }
    }

    pub(crate) fn len_limit(&self) -> usize {
        self.len_limit
    }

    // NOTE: 
    // 1. Any decision-making should be made in the application layer, and set here.
    // 2. A decrease in limit must be accepted.
    // 3. The new limit should only be set after sending/receiving the accept confirmation.
    // 4. MIN_LEN_LIMIT <= len_limit <= MAX_LEN_LIMIT
    pub(crate) fn set_len_limit(&mut self, len_limit: usize) {
        self.len_limit = len_limit.clamp(MIN_LEN_LIMIT, MAX_LEN_LIMIT);
    }

    // SANITY CHECK
    #[cfg(debug_assertions)]  
    fn send_check(&self, msg: &Message) -> Result<(), error::InvalidMessageError> {
        let len = msg.as_ref().len();
        if len > self.len_limit {
            return Err(error::InvalidMessageError::PayloadLengthAboveLimit { length: len, limit: self.len_limit });
        } else if msg.header().length() != len {
            return Err(error::InvalidMessageError::PayloadLengthMismatch { expected: msg.header().length(), actual: len });
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Plain for PlainStream {
    async fn send(&mut self, msg: Message) -> Result<(), error::Error> {
        self.stream
            .write_all(&<[u8; MSG_HEADER_LEN]>::from(msg.header()))
            .await?;
        self.stream.write_all(msg.as_ref()).await?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Message, error::Error> {
        self.stream.read_exact(&mut self.header_buffer).await?;
        let mut message = Message::raw(&self.header_buffer)?;
        self.stream.read_exact(message.as_mut()).await?;
        Ok(message)
    }
}

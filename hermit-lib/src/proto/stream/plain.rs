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

    pub(crate) fn set_len_limit(&mut self, len_limit: usize) {
        self.len_limit = len_limit.clamp(MIN_LEN_LIMIT, MAX_LEN_LIMIT);
    }

    // SANITY CHECK
    #[cfg(debug_assertions)]  
    fn send_check(&self, msg: &Message) -> Result<(), error::InvalidMessageError> {
        let len = msg.as_ref().len();
        if !(MIN_LEN_LIMIT..=MAX_LEN_LIMIT).contains(&len) {
            return Err(error::InvalidMessageError::PayloadLengthOutOfRange { length: len });
        } else if len > self.len_limit {
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

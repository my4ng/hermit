use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::task::Poll;

use async_std::sync::{Mutex, MutexGuard, RwLock};
use futures::{AsyncReadExt, AsyncWriteExt, Future, Sink, Stream};

use super::header::MSG_HEADER_LEN;
use super::message::Message;
use crate::error;
use crate::proto::message::{MAX_LEN_LIMIT, MIN_LEN_LIMIT};
use crate::proto::stream::BaseStream;

struct InnerSink {
    base_stream: Arc<BaseStream>,
    len_limit: Arc<RwLock<usize>>,

    queue: VecDeque<Message>,
    // NOTE: Multiplier must be non-zero. If it is one, then effectively the queue
    //       must be empty before sending a new message.
    limit_multiplier: NonZeroUsize,
    // INVARIANT: `total_byte_len` <= `limit_multiplier` * `len_limit`
    total_byte_len: usize,
}

impl InnerSink {
    fn new(
        base_stream: Arc<BaseStream>,
        len_limit: Arc<RwLock<usize>>,
        limit_multiplier: NonZeroUsize,
    ) -> Self {
        Self {
            base_stream,
            len_limit,
            queue: VecDeque::new(),
            limit_multiplier,
            total_byte_len: 0,
        }
    }

    // PRECONDITION: `self.send_state.queue` is not empty.
    async fn send(&mut self) -> Result<(), error::Error> {
        let message = self.queue.pop_front().unwrap();
        let mut stream = self.base_stream.as_ref();

        stream
            .write_all(&<[u8; MSG_HEADER_LEN]>::from(message.header()))
            .await?;

        stream.write_all(message.as_ref()).await?;
        stream.flush().await?;

        self.total_byte_len -= message.byte_len();
        Ok(())
    }

    async fn ready(&mut self) -> Result<(), error::Error> {
        // NOTE: A conservative approach is used here such that it is guaranteed that the
        //       `self.send_state.total_byte_len` will never exceed `self.send_state.byte_limit`
        //       even at the maximum length limit.
        let len_limit = *self.len_limit.read().await;

        while self.total_byte_len + len_limit > len_limit * self.limit_multiplier.get() {
            self.send().await?;
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), error::Error> {
        while !self.queue.is_empty() {
            self.send().await?;
        }
        Ok(())
    }
}

impl Sink<Message> for InnerSink {
    type Error = error::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        pin!(self.ready()).as_mut().poll(cx)
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.total_byte_len += item.byte_len();
        self.queue.push_back(item);
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        pin!(self.flush()).as_mut().poll(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        // TODO: Send a disconnect message as well??
        self.poll_flush(cx)
    }
}

struct InnerStream {
    base_stream: Arc<BaseStream>,
    len_limit: Arc<RwLock<usize>>,
}

impl InnerStream {
    fn new(base_stream: Arc<BaseStream>, len_limit: Arc<RwLock<usize>>) -> Self {
        Self {
            base_stream,
            len_limit,
        }
    }

    async fn recv(&self) -> Result<Message, error::Error> {
        let mut stream = self.base_stream.as_ref();

        let mut header = [0u8; MSG_HEADER_LEN];
        stream.read_exact(&mut header).await?;

        let mut message = Message::raw(&header)?;
        stream.read_exact(message.as_mut()).await?;

        Ok(message)
    }
}

impl Stream for InnerStream {
    type Item = Result<Message, error::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match pin!(self.recv()).as_mut().poll(cx) {
            Poll::Ready(Ok(msg)) => Poll::Ready(Some(Ok(msg))),
            Poll::Ready(Err(err @ error::Error::MessageParsing(_))) => Poll::Ready(Some(Err(err))),
            // TODO: Handle other non-fatal errors by return `Some(Err(_))` instead of `None`,
            //       so that the caller can decide whether to continue or not, e.g. timeout, cf. connection aborted.
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct PlainStream {
    base_stream: Arc<BaseStream>,
    len_limit: Arc<RwLock<usize>>,
    inner_stream: Mutex<InnerStream>,
    inner_sink: Mutex<InnerSink>,
}

impl PlainStream {
    pub(crate) fn new(base_stream: BaseStream, limit_multiplier: NonZeroUsize) -> Self {
        let base_stream = Arc::new(base_stream);
        let len_limit = Arc::new(RwLock::new(MIN_LEN_LIMIT));

        Self {
            base_stream: base_stream.clone(),
            len_limit: len_limit.clone(),
            inner_stream: Mutex::new(InnerStream::new(base_stream.clone(), len_limit.clone())),
            inner_sink: Mutex::new(InnerSink::new(
                base_stream.clone(),
                len_limit.clone(),
                limit_multiplier,
            )),
        }
    }

    pub(crate) async fn set_len_limit(&self, len_limit: usize) -> usize {
        let len_limit = len_limit.clamp(MIN_LEN_LIMIT, MAX_LEN_LIMIT);
        *self.len_limit.write().await = len_limit;
        len_limit
    }

    pub(crate) async fn stream(
        &self,
    ) -> MutexGuard<'_, impl Stream<Item = Result<Message, error::Error>>> {
        self.inner_stream.lock().await
    }

    pub(crate) async fn sink(&self) -> MutexGuard<'_, impl Sink<Message, Error=error::Error>> {
        self.inner_sink.lock().await
    }
}

impl PlainStream {
    // SANITY CHECK
    #[cfg(debug_assertions)]
    async fn send_check(&self, msg: &Message) -> Result<(), error::InvalidMessageError> {
        let len = msg.as_ref().len();
        let len_limit = *self.len_limit.read().await;

        if !(MIN_LEN_LIMIT..=MAX_LEN_LIMIT).contains(&len) {
            return Err(error::InvalidMessageError::PayloadLengthOutOfRange { length: len });
        } else if len > len_limit {
            return Err(error::InvalidMessageError::PayloadLengthAboveLimit {
                length: len,
                limit: len_limit,
            });
        } else if msg.header().length() != len {
            return Err(error::InvalidMessageError::PayloadLengthMismatch {
                expected: msg.header().length(),
                actual: len,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use futures::{join, SinkExt};

    use crate::{proto::plain::header::PlainMessageType, test};

    use super::*;

    #[async_std::test]
    async fn test_sink() {
        let (s1, s2) = test::get_test_tcp_streams(8080).await;
        let mut stream1 = PlainStream::new(BaseStream(s1), NonZeroUsize::new(2).unwrap());
        let stream2 = PlainStream::new(BaseStream(s2), NonZeroUsize::new(2).unwrap());

        todo!()
    }
}

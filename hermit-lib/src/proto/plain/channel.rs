use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::pin::pin;
use std::task::Poll;

use async_std::sync::{Mutex, MutexGuard, RwLock};
use async_std::task;
use futures::{AsyncReadExt, AsyncWriteExt, Future, Sink, SinkExt, Stream, StreamExt};

use super::header::MSG_HEADER_LEN;
use super::message::Message;
use crate::error;
use crate::proto::message::{MAX_LEN_LIMIT, MIN_LEN_LIMIT};
use crate::proto::channel::BaseChannel;

struct InnerSink {
    queue: VecDeque<Message>,
    // NOTE: Multiplier must be non-zero. If it is one, then effectively the queue
    //       must be empty before sending a new message.
    limit_multiplier: NonZeroUsize,
    // INVARIANT: `total_byte_len` <= `limit_multiplier` * `len_limit`
    total_byte_len: usize,
}

impl InnerSink {
    fn new(limit_multiplier: NonZeroUsize) -> Self {
        Self {
            queue: VecDeque::new(),
            limit_multiplier,
            total_byte_len: 0,
        }
    }
}

struct InnerStream;

pub struct PlainChannel {
    base_stream: BaseChannel,
    len_limit: RwLock<usize>,
    inner_stream: Mutex<InnerStream>,
    inner_sink: Mutex<InnerSink>,
}

impl PlainChannel {
    pub(crate) fn new(base_stream: BaseChannel, limit_multiplier: NonZeroUsize) -> Self {
        Self {
            base_stream,
            len_limit: RwLock::new(MIN_LEN_LIMIT),
            inner_stream: Mutex::new(InnerStream),
            inner_sink: Mutex::new(InnerSink::new(limit_multiplier)),
        }
    }

    pub(crate) async fn set_len_limit(&self, len_limit: usize) -> usize {
        let len_limit = len_limit.clamp(MIN_LEN_LIMIT, MAX_LEN_LIMIT);
        *self.len_limit.write().await = len_limit;
        len_limit
    }

    // PRECONDITION: `self.send_state.queue` is not empty.
    async fn send(
        mut stream: &BaseChannel,
        sink: &mut MutexGuard<'_, InnerSink>,
    ) -> Result<(), error::Error> {
        let message = sink.queue.pop_front().unwrap();

        stream
            .write_all(&<[u8; MSG_HEADER_LEN]>::from(message.header()))
            .await?;

        stream.write_all(message.as_ref()).await?;
        stream.flush().await?;

        sink.total_byte_len -= message.byte_len();
        Ok(())
    }

    async fn inner_ready(&self) -> Result<(), error::Error> {
        let mut inner_sink = self.inner_sink.lock().await;
        // NOTE: A conservative approach is used here such that it is guaranteed that the
        //       `self.send_state.total_byte_len` will never exceed `self.send_state.byte_limit`
        //       even at the maximum length limit.
        let len_limit = *self.len_limit.read().await;

        while inner_sink.total_byte_len + len_limit > len_limit * inner_sink.limit_multiplier.get()
        {
            Self::send(&self.base_stream, &mut inner_sink).await?;
        }
        Ok(())
    }

    async fn inner_flush(&self) -> Result<(), error::Error> {
        let mut inner_sink = self.inner_sink.lock().await;
        while !inner_sink.queue.is_empty() {
            Self::send(&self.base_stream, &mut inner_sink).await?;
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Message, error::Error> {
        self.inner_stream.lock().await;
        let mut stream = &self.base_stream;

        let mut header = [0u8; MSG_HEADER_LEN];
        stream.read_exact(&mut header).await?;

        let mut message = Message::raw(&header)?;
        stream.read_exact(message.as_mut()).await?;

        Ok(message)
    }

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

impl Sink<Message> for &PlainChannel {
    type Error = error::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        pin!(self.inner_ready()).as_mut().poll(cx)
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        task::block_on(async {
            let mut inner_sink = self.inner_sink.lock().await;
            inner_sink.total_byte_len += item.byte_len();
            inner_sink.queue.push_back(item);
        });
        Ok(())
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        pin!(self.inner_flush()).as_mut().poll(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        // TODO: Send a disconnect message as well??
        self.poll_flush(cx)
    }
}

impl Stream for &PlainChannel {
    type Item = Result<Message, error::Error>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
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

impl PlainChannel {
    pub(crate) async fn send_msg(mut self: &Self, message: impl Into<Message>) -> Result<(), error::Error> {
        <&Self as SinkExt<Message>>::send(&mut self, message.into()).await
    }

    pub(crate) async fn send_msg_iter(
        mut self: &Self,
        messages: impl IntoIterator<Item = impl Into<Message>>,
    ) -> Result<(), error::Error> {
        for message in messages.into_iter() {
            <&Self as SinkExt<Message>>::feed(&mut self, message.into()).await?;
        }
        <&Self as SinkExt<Message>>::flush(&mut self).await?;
        Ok(())
    }

    pub(crate) async fn recv_msg(mut self: &Self) -> Result<Message, error::Error> {
        <&Self as StreamExt>::next(&mut self).await.unwrap()
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use async_std::task;
    use futures::{join, SinkExt, StreamExt};

    use crate::{proto::plain::header::PlainMessageType, test};

    use super::*;

    #[async_std::test]
    async fn test_sink() {
        let (s1, s2) = test::get_test_tcp_streams(8080).await;
        let stream1 = PlainChannel::new(BaseChannel(s1), NonZeroUsize::new(2).unwrap());
        let stream2 = PlainChannel::new(BaseChannel(s2), NonZeroUsize::new(2).unwrap());

        let task1 = async {
            for _ in 0..10 {
                let msg =
                    Message::new(PlainMessageType::AdjustLenLimitResponse, Box::from(vec![0]));
                (&stream1).send(msg).await.unwrap();
                task::sleep(Duration::from_millis(100)).await;
            }
        };

        let task2 = async {
            for _ in 0..10 {
                let msg =
                    Message::new(PlainMessageType::AdjustLenLimitResponse, Box::from(vec![1]));
                (&stream1).send(msg).await.unwrap();
                task::sleep(Duration::from_millis(100)).await;
            }
        };

        join!(task1, task2);

        for _ in 0..20 {
            let msg = (&stream2).next().await.unwrap().unwrap();
            dbg!(msg.as_ref());
        }
    }
}

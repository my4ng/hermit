use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::pin::{pin, Pin};
use std::task::Poll;

use async_std::sync::{Mutex, MutexGuard, RwLock};
use async_std::task;
use futures::{AsyncReadExt, AsyncWriteExt, Future};

use super::header::MSG_HEADER_LEN;
use super::message::Message;
use crate::error;
use crate::proto::message::{MAX_LEN_LIMIT, MIN_LEN_LIMIT};
use crate::proto::stream::BaseStream;

struct SendQueue {
    queue: VecDeque<Message>,
    // NOTE: Multiplier must be non-zero. If it is one, then effectively the queue
    //       must be empty before sending a new message.
    limit_multiplier: NonZeroUsize,
    // INVARIANT: `total_byte_len` <= `limit_multiplier` * `len_limit`
    total_byte_len: usize,
}

impl SendQueue {
    fn new(limit_multiplier: NonZeroUsize) -> Self {
        Self {
            queue: VecDeque::new(),
            limit_multiplier,
            total_byte_len: 0,
        }
    }
}

pub trait Plain:
    futures::stream::Stream<Item = Result<Message, error::Error>> + futures::sink::Sink<Message>
{
    fn set_len_limit(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        len_limit: usize,
    ) -> Poll<()>;
}

pub struct PlainStream {
    stream: BaseStream,
    len_limit: RwLock<usize>,
    send_lock: Mutex<SendQueue>,
    recv_lock: Mutex<()>,
}

impl PlainStream {
    pub(crate) fn new(base_stream: BaseStream, limit_multiplier: NonZeroUsize) -> Self {
        Self {
            stream: base_stream,
            len_limit: RwLock::new(MIN_LEN_LIMIT),
            send_lock: Mutex::new(SendQueue::new(limit_multiplier)),
            recv_lock: Mutex::new(()),
        }
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

    // PRECONDITION: `self.send_state.queue` is not empty.
    async fn send(
        send_guard: &mut MutexGuard<'_, SendQueue>,
        mut stream: &BaseStream,
    ) -> Result<(), error::Error> {
        let message = send_guard.queue.pop_front().unwrap();

        stream
            .write_all(&<[u8; MSG_HEADER_LEN]>::from(message.header()))
            .await?;

        stream.write_all(message.as_ref()).await?;
        stream.flush().await?;

        send_guard.total_byte_len -= message.byte_len();
        Ok(())
    }

    async fn recv(&self) -> Result<Message, error::Error> {
        self.recv_lock.lock().await;
        let mut stream = &self.stream;

        let mut header = [0u8; MSG_HEADER_LEN];
        stream.read_exact(&mut header).await?;

        let mut message = Message::raw(&header)?;
        stream.read_exact(message.as_mut()).await?;

        Ok(message)
    }
}

impl Plain for PlainStream {
    fn set_len_limit(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        len_limit: usize,
    ) -> Poll<()> {
        match Pin::new(&mut self.as_ref().len_limit.write()).poll(cx) {
            Poll::Ready(mut guard) => {
                *guard = len_limit.clamp(MIN_LEN_LIMIT, MAX_LEN_LIMIT);
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl futures::stream::Stream for PlainStream {
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

impl futures::sink::Sink<Message> for PlainStream {
    type Error = error::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        pin!(self.ready()).as_mut().poll(cx)
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        task::block_on(async {
            let mut guard = self.send_lock.lock().await;
            guard.total_byte_len += item.byte_len();
            guard.queue.push_back(item);
            Ok(())
        })
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

impl PlainStream {
    async fn ready(&self) -> Result<(), error::Error> {
        // NOTE: A conservative approach is used here such that it is guaranteed that the
        //       `self.send_state.total_byte_len` will never exceed `self.send_state.byte_limit`
        //       even at the maximum length limit.
        let mut guard = self.send_lock.lock().await;
        let len_limit = *self.len_limit.read().await;

        while guard.total_byte_len + len_limit > len_limit * guard.limit_multiplier.get() {
            Self::send(&mut guard, &self.stream).await?;
        }
        Ok(())
    }

    async fn flush(&self) -> Result<(), error::Error> {
        let mut guard = self.send_lock.lock().await;
        while !guard.queue.is_empty() {
            Self::send(&mut guard, &self.stream).await?;
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

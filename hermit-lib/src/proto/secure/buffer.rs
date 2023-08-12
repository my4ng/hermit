use std::pin::Pin;

use futures::Future;

use super::message::TAG_LEN;

pub(super) struct ReadBuffer {
    buffer: Option<Box<[u8]>>,
    index: usize,
}

impl ReadBuffer {
    pub(super) fn new() -> Self {
        Self {
            buffer: None,
            index: 0,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.buffer.is_none()
    }

    // CAUTION: only call this function when the internal buffer is empty.
    pub(super) async fn fill(&mut self, source: Box<[u8]>)
    {
        self.buffer = Some(source);
        self.index = 0;
    }

    // ASSERT: the internal buffer is not empty.
    pub(super) fn read(&mut self, dst: &mut [u8]) -> usize {
        let dst_len = dst.len();
        let buffer = self.buffer.as_ref().unwrap();

        // NOTE: Prevent deserializing the tag.
        let buffer_len = buffer.len() - TAG_LEN;

        if dst_len < buffer_len - self.index {
            dst.copy_from_slice(&buffer[self.index..self.index + dst_len]);
            self.index += dst_len;
            dst_len
        } else {
            let copy_len = buffer_len - self.index;
            dst[..copy_len].copy_from_slice(&buffer[self.index..buffer_len]);

            self.buffer = None;
            self.index = 0;
            copy_len
        }
    }
}

pub(super) struct WriteBuffer {
    buffer: Option<Box<[u8]>>,
    index: usize,
}

impl WriteBuffer {
    pub(super) fn new() -> Self {
        Self {
            buffer: None,
            index: 0,
        }
    }

    pub(super) async fn write<F, G, E>(
        &mut self,
        source: &[u8],
        sink: F,
        len_limit: G,
    ) -> Result<(), E>
    where
        F: Fn(Box<[u8]>) -> Pin<Box<dyn Future<Output = Result<(), E>>>>,
        G: Fn() -> usize,
    {
        let src_len = source.len();
        let mut remaining = src_len;

        while remaining > 0 {
            if self.buffer.is_none() {
                self.buffer = Some(vec![0; len_limit()].into_boxed_slice());
            }
            // SAFETY: self.buffer is Some
            let buffer = self.buffer.as_mut().unwrap();
            // NOTE: Prevent serializing the tag.
            let buffer_len = buffer.len() - TAG_LEN;
            let src_index = src_len - remaining;

            if remaining < buffer_len - self.index {
                buffer[self.index..self.index + remaining].copy_from_slice(&source[src_index..]);
                self.index += remaining;
                remaining = 0;
            } else {
                let copy_len = buffer_len - self.index;
                buffer[self.index..buffer_len]
                    .copy_from_slice(&source[src_index..src_index + copy_len]);

                // SAFETY: self.buffer is Some
                sink(self.buffer.take().unwrap()).await?;
                self.buffer = None;
                self.index = 0;
                remaining -= copy_len;
            }
        }
        Ok(())
    }

    pub(super) async fn flush<F, E>(&mut self, mut sink: F) -> Result<(), E>
    where
        F: Fn(Box<[u8]>) -> Pin<Box<dyn Future<Output = Result<(), E>>>>,
    {
        if let Some(buffer) = self.buffer.take() {
            let mut buffer = buffer.into_vec();
            buffer.truncate(self.index + TAG_LEN);
            let truncated_buffer = buffer.into_boxed_slice();
            self.index = 0;
            sink(truncated_buffer).await?;
        }
        Ok(())
    }
}

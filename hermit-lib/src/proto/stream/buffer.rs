use crate::proto::message::TAG_LEN;

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

    pub(super) fn read<F, E>(&mut self, sink: &mut [u8], mut source: F) -> Result<(), E>
    where
        F: FnMut() -> Result<Box<[u8]>, E>,
    {
        let sink_len = sink.len();
        let mut remaining = sink_len;

        while remaining > 0 {
            if self.buffer.is_none() {
                self.buffer = Some(source()?);
            }
            // SAFETY: self.buffer is Some
            let buffer = self.buffer.as_ref().unwrap();
            // NOTE: Prevent deserializing the tag.
            let buffer_len = buffer.len() - TAG_LEN;
            let sink_index = sink_len - remaining;

            if remaining < buffer.len() - self.index {
                sink[sink_index..].copy_from_slice(&buffer[self.index..self.index + remaining]);

                self.index += remaining;
                remaining = 0;
            } else {
                let copy_len = buffer_len - self.index;
                sink[sink_index..sink_index + copy_len]
                    .copy_from_slice(&buffer[self.index..buffer_len]);

                self.buffer = None;
                self.index = 0;
                remaining -= copy_len;
            }
        }
        Ok(())
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

    pub(super) fn write<F, G, E>(
        &mut self,
        source: &[u8],
        mut sink: F,
        len_limit: G,
    ) -> Result<(), E>
    where
        F: FnMut(Box<[u8]>) -> Result<(), E>,
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
                sink(self.buffer.take().unwrap())?;
                self.buffer = None;
                self.index = 0;
                remaining -= copy_len;
            }
        }
        Ok(())
    }

    pub(super) fn flush<F, E>(&mut self, mut sink: F) -> Result<(), E>
    where
        F: FnMut(Box<[u8]>) -> Result<(), E>,
    {
        if let Some(buffer) = self.buffer.take() {
            let mut buffer = buffer.into_vec();
            buffer.truncate(self.index + TAG_LEN);
            let truncated_buffer = buffer.into_boxed_slice();
            self.index = 0;
            sink(truncated_buffer)?;
        }
        Ok(())
    }
}

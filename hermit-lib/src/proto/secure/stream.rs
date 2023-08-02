use std::cell::RefCell;

use async_std::task;

use super::buffer::{ReadBuffer, WriteBuffer};
use crate::proto::stream::{Plain, PlainStream};
use crate::proto::message::Message;
use crate::{crypto::secrets, error};

pub trait Secure: Plain {
    type PlainType: Plain;
    // NOTE: TAG_LEN of space has been reserved at the end of the payload when
    // sealing and opening.
    fn upgrade(stream: Self::PlainType, secrets: secrets::SessionSecrets) -> Self;
    fn downgrade(self) -> Self::PlainType;
}

pub struct SecureStream {
    stream: PlainStream,
    session_secrets: secrets::SessionSecrets,
    read_buffer: ReadBuffer,
    write_buffer: WriteBuffer,
}

impl SecureStream {
    pub(crate) fn new(stream: PlainStream, session_secrets: secrets::SessionSecrets) -> Self {
        Self {
            stream,
            session_secrets,
            read_buffer: ReadBuffer::new(),
            write_buffer: WriteBuffer::new(),
        }
    }
}

#[async_trait::async_trait]
impl Plain for SecureStream {
    async fn send(&mut self, msg: Message) -> Result<(), error::Error> {
        self.stream.send(msg).await
    }

    async fn recv(&mut self) -> Result<Message, error::Error> {
        self.stream.recv().await
    }
}

impl Secure for SecureStream {
    type PlainType = PlainStream;

    fn downgrade(self) -> Self::PlainType {
        self.stream
    }

    fn upgrade(stream: Self::PlainType, secrets: secrets::SessionSecrets) -> Self {
        Self::new(stream, secrets)
    }
}

impl ciborium_io::Read for &mut &mut SecureStream {
    type Error = error::Error;

    fn read_exact(&mut self, data: &mut [u8]) -> Result<(), Self::Error> {

        self.read_buffer.read(data, || {
            let msg = task::block_on(self.stream.recv())?;
            let payload = self.session_secrets.open(msg)?;
            Ok::<_, Self::Error>(payload)
        })
    }
}

impl ciborium_io::Write for &mut &mut SecureStream {
    type Error = error::Error;

    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let stream = RefCell::new(&mut self.stream);

        self.write_buffer.write(data, |payload| {
            let msg = self.session_secrets.seal(payload)?;
            task::block_on(stream.borrow_mut().send(msg))?;
            Ok::<_, Self::Error>(())
        }, || {
            stream.borrow().len_limit()
        })
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.write_buffer.flush(|payload| {
            let msg = self.session_secrets.seal(payload)?;
            task::block_on(self.stream.send(msg))?;
            Ok::<_, Self::Error>(())
        })
    }
}

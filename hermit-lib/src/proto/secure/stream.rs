use std::pin::Pin;

use serde::Serialize;

use super::buffer::{ReadBuffer, WriteBuffer};
use super::{header, message};
use crate::proto::message::Message;
use crate::proto::stream::{Plain, PlainStream};
use crate::{crypto::secrets, error};

pub trait Secure: Plain {
    type SessionSecrets;
    type PlainType: Plain;

    fn upgrade(stream: Self::PlainType, secrets: Self::SessionSecrets) -> Self;
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

    fn write(&mut self, secure_msg: impl Serialize) -> Result<(), error::Error> {
        ciborium::into_writer(&secure_msg, self).map_err(|err| match err {
            ciborium::ser::Error::Io(error) => error,
            ciborium::ser::Error::Value(string) => {
                error::InvalidMessageError::CborSerialization(string).into()
            }
        })?;
        Ok(())
    }
}

impl futures::stream::Stream for SecureStream {
    type Item = Result<Message, error::Error>;

    fn poll_next(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.stream).poll_next(cx)
    }
}

impl futures::sink::Sink<Message> for SecureStream {
    type Error = error::Error;

    fn poll_ready(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.stream).poll_ready(cx)
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        Pin::new(&mut self.stream).start_send(item)
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.stream).poll_close(cx)
    }
}

impl Plain for SecureStream {
    fn set_len_limit(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        len_limit: usize,
    ) -> std::task::Poll<()> {
        todo!()
    }
}

impl Secure for SecureStream {
    type SessionSecrets = secrets::SessionSecrets;
    type PlainType = PlainStream;

    // fn send_secure(&mut self, secure_msg: impl message::Secure) -> Result<(), error::Error> {
    //     // NOTE: The buffer is not flushed between the following two writes by `ciborium`.
    //     self.write(secure_msg.header())?;
    //     self.write(secure_msg)?;
    //     let mut self_ref = self;
    //     ciborium_io::Write::flush(&mut self_ref)?;
    //     Ok(())
    // }

    // fn recv_secure_header(&mut self) -> Result<header::SecureMessageHeader, error::Error> {
    //     ciborium::from_reader(self).map_err(|err| match err {
    //         ciborium::de::Error::Io(error) => error,
    //         others => error::InvalidMessageError::CborDeserialization(others.to_string()).into(),
    //     })
    // }

    // fn recv_secure<S: message::Secure>(&mut self) -> Result<S, error::Error> {
    //     ciborium::from_reader(self).map_err(|err| match err {
    //         ciborium::de::Error::Io(error) => error,
    //         others => error::InvalidMessageError::CborDeserialization(others.to_string()).into(),
    //     })
    // }

    fn downgrade(self) -> Self::PlainType {
        self.stream
    }

    fn upgrade(stream: Self::PlainType, secrets: secrets::SessionSecrets) -> Self {
        Self::new(stream, secrets)
    }
}

// NOTE: TAG_LEN of space has been reserved at the end of the payload when
// sealing and opening.

mod cbor {
    use async_std::task;

    use super::*;

    impl ciborium_io::Read for &mut SecureStream {
        type Error = error::Error;

        fn read_exact(&mut self, data: &mut [u8]) -> Result<(), Self::Error> {
            // self.read_buffer.read(data, || {
            //     let msg = task::block_on(self.stream.recv())?;
            //     let payload = self.session_secrets.open(msg)?;
            //     Ok::<_, Self::Error>(payload)
            // })
            todo!()
        }
    }

    impl ciborium_io::Write for &mut SecureStream {
        type Error = error::Error;

        fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            // let stream = RefCell::new(&mut self.stream);

            // self.write_buffer.write(
            //     data,
            //     |payload| {
            //         let msg = self.session_secrets.seal(payload)?;
            //         task::block_on(stream.borrow_mut().send(msg))?;
            //         Ok::<_, Self::Error>(())
            //     },
            //     || stream.borrow().len_limit(),
            // )
            todo!()
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            // self.write_buffer.flush(|payload| {
            //     let msg = self.session_secrets.seal(payload)?;
            //     task::block_on(self.stream.send(msg))?;
            //     Ok::<_, Self::Error>(())
            // })
            todo!()
        }
    }
}

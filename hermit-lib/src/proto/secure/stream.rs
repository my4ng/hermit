use std::sync::Arc;

use serde::Serialize;

use super::buffer::{ReadBuffer, WriteBuffer};
use crate::proto::stream::PlainStream;
use crate::{crypto::secrets, error};

pub struct SecureStream {
    stream: Arc<PlainStream>,
    session_secrets: secrets::SessionSecrets,
    read_buffer: ReadBuffer,
    write_buffer: WriteBuffer,
}

impl SecureStream {
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

impl SecureStream {
    pub(crate) fn downgrade(self: Arc<Self>) -> Arc<PlainStream> {
        self.stream.clone()
    }

    pub(crate) fn upgrade(stream: Arc<PlainStream>, session_secrets: secrets::SessionSecrets) -> Self {
        Self {
            stream,
            session_secrets,
            read_buffer: ReadBuffer::new(),
            write_buffer: WriteBuffer::new(),
        }
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

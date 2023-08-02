use ciborium_io::Write;
use serde::{ser, de};

use crate::{error, proto::stream::SecureStream};

pub(in crate::proto) trait Secure: Sized + ser::Serialize + de::DeserializeOwned {
    fn send(&self, mut secure_stream: &mut SecureStream) -> Result<(), error::Error> {
        ciborium::into_writer(self, &mut secure_stream).map_err(|err| match err {
            ciborium::ser::Error::Io(error) => error,
            ciborium::ser::Error::Value(string) => {
                error::InvalidMessageError::CborSerialization(string).into()
            }
        })?;
        (&mut secure_stream).flush()
    }
    fn recv(mut secure_stream: &mut SecureStream) -> Result<Self, error::Error> {
        ciborium::from_reader(&mut secure_stream).map_err(|err| match err {
            ciborium::de::Error::Io(error) => error,
            others => error::InvalidMessageError::CborDeserialization(others.to_string()).into(),
        })
    }
}

use serde::{ser, de};

use crate::{error, proto::stream::SecureStream};

pub(in crate::proto) trait Secure: Sized + ser::Serialize + de::DeserializeOwned {
    fn send(&self, secure_stream: &mut SecureStream) -> Result<(), error::Error> {
        ciborium::into_writer(self, secure_stream).map_err(|err| match err {
            ciborium::ser::Error::Io(error) => error,
            ciborium::ser::Error::Value(string) => {
                error::InvalidMessageError::CborSerialization(string).into()
            }
        })
    }
    fn recv(secure_stream: &mut SecureStream) -> Result<Self, error::Error> {
        ciborium::from_reader(secure_stream).map_err(|err| match err {
            ciborium::de::Error::Io(error) => error,
            others => error::InvalidMessageError::CborDeserialization(others.to_string()).into(),
        })
    }
}

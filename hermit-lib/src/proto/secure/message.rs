use super::header;

pub(crate) use ring::aead::MAX_TAG_LEN as TAG_LEN;
use serde::{Serialize, de::DeserializeOwned};

// TODO: Separate transport layer protocol (Plain) from application layer protocol (Secure).
// The former uses plain bytes and a fixed-length header, while the latter uses CBOR and a
// variable-length header.

pub trait Secure: Sized + Serialize + DeserializeOwned {
    fn header(&self) -> header::SecureMessageHeader;
}

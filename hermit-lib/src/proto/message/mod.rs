mod plain;
mod secure;
mod types;

pub(crate) use aead::MAX_TAG_LEN as TAG_LEN;
use ring::aead;

pub use self::plain::PlainMessage;
pub use self::secure::SecureMessage;

pub(crate) use super::handshake::*;
pub(crate) use super::transfer::*;
pub(crate) use super::util::*;
pub(crate) use types::*;

pub(crate) const MESSAGE_HEADER_LEN: usize = 4;

// NOTE: All plain messages must have a fixed length <= `MIN_MSG_LEN`.
pub(crate) const MIN_MSG_LEN: usize = (1 << 10) - 1;
pub(crate) const MAX_MSG_LEN: usize = (1 << 15) - 1;

pub(super) trait Plain: TryFrom<PlainMessage> + Into<PlainMessage> {}

pub(super) trait Secure: TryFrom<SecureMessage> + Into<SecureMessage> {}

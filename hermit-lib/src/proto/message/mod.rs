mod plain;
mod secure;
mod types;

pub(crate) use aead::MAX_TAG_LEN as TAG_LEN;
use ring::aead;

pub use self::plain::PlainMessage;
pub use self::secure::SecureMessage;

pub(crate) use super::handshake::*;
pub(crate) use super::transfer::*;
pub(crate) use types::*;

pub(crate) const MESSAGE_HEADER_LEN: usize = 4;
pub(crate) const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;
pub(crate) const MAX_SECURE_PAYLOAD_LEN: usize = MAX_PAYLOAD_LEN - MESSAGE_HEADER_LEN - TAG_LEN;

// NOTE: All plain message lengths must be fixed and less than `MAX_PAYLOAD_LEN`.
pub(super) trait Plain: TryFrom<PlainMessage> + Into<PlainMessage> {}

// CAUTION: Secure messages are not allowed to be longer than `MAX_SECURE_PAYLOAD_LEN`.
// Otherwise, `TryInto` will return `InvalidMessageError::PayloadTooLong`.
pub(super) trait Secure: TryFrom<SecureMessage> + TryInto<SecureMessage> {}

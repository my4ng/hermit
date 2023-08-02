pub(crate) const MIN_LEN_LIMIT: usize = (1 << 10) - 1;
pub(crate) const MAX_LEN_LIMIT: usize = (1 << 15) - 1;

pub(crate) use ring::aead::MAX_TAG_LEN as TAG_LEN;
pub(crate) const MSG_HEADER_LEN: usize = 4;

pub(crate) use crate::proto::plain::message::{PlainMessageType, Message};
pub(crate) use crate::proto::secure::message::SecureMessageType;

pub(crate) use crate::proto::plain::handshake as handshake;
pub(crate) use crate::proto::plain::len_limit as len_limit;
pub(crate) use crate::proto::secure::transfer as transfer;
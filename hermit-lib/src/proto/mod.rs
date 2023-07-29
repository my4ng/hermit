mod handshake;
pub(crate) mod message;
pub(crate) mod stream;
mod transfer;

use num_enum::{TryFromPrimitive, IntoPrimitive};

use crate::error;

pub static CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V0_1;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
pub enum ProtocolVersion {
    // NOTE: 0x00 RESERVED
    V0_1 = 0x01,
}

pub(crate) enum Side {
    Client,
    Server,
}

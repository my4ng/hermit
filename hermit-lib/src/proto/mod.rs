pub(crate) mod message;
mod plain;
mod secure;
pub(crate) mod channel;

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

pub static CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V0_1;

#[repr(u8)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, Deserialize, Serialize,
)]
pub enum ProtocolVersion {
    // NOTE: 0x00 RESERVED
    V0_1 = 0x01,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Client,
    Server,
}

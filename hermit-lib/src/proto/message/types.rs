// Fix for rust-analyzer
#![allow(non_upper_case_globals)]

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, Deserialize, Serialize,
)]
#[repr(u8)]
#[non_exhaustive]
pub enum SecureMessageType {
    SendResourceRequest = 0x01,
    SendResourceResponse = 0x02,
    ReceiveResourceRequest = 0x03,
    ReceiveResourceResponse = 0x04,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
#[non_exhaustive]
pub enum PlainMessageType {
    Secure = 0x00,
    ClientHello = 0x01,
    ServerHello = 0x02,
    Disconnect = 0x03,
    Downgrade = 0x04,

    AdjustMessageLengthRequest = 0x10,
    AdjustMessageLengthResponse = 0x11,
}

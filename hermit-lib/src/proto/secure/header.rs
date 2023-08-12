// Fix for rust-analyzer
#![allow(non_upper_case_globals)]

use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive, Deserialize, Serialize)]
#[repr(u8)]
#[non_exhaustive]
pub enum SecureMessageType {
    SendResourceRequest = 0x01,
    SendResourceResponse = 0x02,
    ReceiveResourceRequest = 0x03,
    ReceiveResourceResponse = 0x04,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[non_exhaustive]
pub struct SecureMessageHeader {
    pub(crate) secure_msg_type: SecureMessageType,
    pub(crate) timestamp: chrono::DateTime<chrono::Utc>,
}
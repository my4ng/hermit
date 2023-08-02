use serde::{Deserialize, Serialize};

use super::message::{PlainMessageType, MIN_LEN_LIMIT, MAX_LEN_LIMIT};
use crate::plain;

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct AdjustMessageLengthRequest {
    // NOTE: `MIN_MSG_LEN` <= `length` <= `MAX_MSG_LEN`.
    length: [u8; 2],
}

impl AdjustMessageLengthRequest {
    pub(crate) fn try_new(length: usize) -> Option<Self> {
        if !(MIN_LEN_LIMIT..=MAX_LEN_LIMIT).contains(&length) {
            return None;
        }
        Some(Self {
            length: (length as u16).to_be_bytes(),
        })
    }

    pub(crate) fn length(&self) -> usize {
        u16::from_be_bytes(self.length) as usize
    }
}

plain!(AdjustMessageLengthRequest, PlainMessageType::AdjustMessageLengthRequest, 2 =>
    length, 2
);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct AdjustMessageLengthResponse {
    has_accepted: [u8; 1],
}

impl AdjustMessageLengthResponse {
    pub const ACCEPTED: AdjustMessageLengthResponse = AdjustMessageLengthResponse {
        has_accepted: [0x01],
    };

    pub const REJECTED: AdjustMessageLengthResponse = AdjustMessageLengthResponse {
        has_accepted: [0x00],
    };
}

plain!(AdjustMessageLengthResponse, PlainMessageType::AdjustMessageLengthResponse, 1 =>
    has_accepted, 1
);

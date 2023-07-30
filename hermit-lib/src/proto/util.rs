use serde::{Deserialize, Serialize};

use super::message::{PlainMessageType, MAX_MSG_LEN, MIN_MSG_LEN};
use crate::plain;

// NOTE: If `length` <= current length, then the request must be accepted.
// Otherwise, the other party may accept or reject the request. All messages
// must conform to the new length if and only if AFTER the request has been accepted.
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct AdjustMessageLengthRequest {
    // NOTE: `MIN_MSG_LEN` <= `length` <= `MAX_MSG_LEN`.
    length: [u8; 2],
}

impl AdjustMessageLengthRequest {
    pub(crate) fn try_new(length: usize) -> Option<Self> {
        if !(MIN_MSG_LEN..=MAX_MSG_LEN).contains(&length) {
            return None;
        }
        Some(Self {
            length: (length as u16).to_be_bytes(),
        })
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

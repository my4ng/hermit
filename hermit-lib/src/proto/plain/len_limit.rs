use serde::{Deserialize, Serialize};

use super::header::PlainMessageType;
use crate::plain_msg;
use crate::proto::message::{MAX_LEN_LIMIT, MIN_LEN_LIMIT};

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct AdjustLenLimitRequest {
    len_limit: [u8; 2],
}

impl AdjustLenLimitRequest {
    pub(crate) fn try_new(len_limit: usize) -> Option<Self> {
        if !(MIN_LEN_LIMIT..=MAX_LEN_LIMIT).contains(&len_limit) {
            return None;
        }
        Some(Self {
            len_limit: (len_limit as u16).to_be_bytes(),
        })
    }

    pub(crate) fn len_limit(self) -> usize {
        u16::from_be_bytes(self.len_limit) as usize
    }
}

plain_msg!(AdjustLenLimitRequest, PlainMessageType::AdjustLenLimitRequest, 2 =>
    len_limit, 2
);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct AdjustLenLimitResponse {
    has_accepted: [u8; 1],
}

impl AdjustLenLimitResponse {
    pub fn new(has_accepted: bool) -> Self {
        Self {
            has_accepted: if has_accepted { [1] } else { [0] },
        }
    }

    pub fn has_accepted(self) -> bool {
        self.has_accepted[0] == 1
    }
}

plain_msg!(AdjustLenLimitResponse, PlainMessageType::AdjustLenLimitResponse, 1 =>
    has_accepted, 1
);

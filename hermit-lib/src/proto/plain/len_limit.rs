use serde::{Deserialize, Serialize};

use super::header::PlainMessageType;
use crate::proto::message::{MAX_LEN_LIMIT, MIN_LEN_LIMIT};
use crate::{error, plain_msg};

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct AdjustLenLimitRequest {
    len_limit: [u8; 2],
}

impl TryFrom<usize> for AdjustLenLimitRequest {
    type Error = error::LenLimitAdjustmentError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if !(MIN_LEN_LIMIT..=MAX_LEN_LIMIT).contains(&value) {
            Err(error::LenLimitAdjustmentError::InvalidLimit(value))
        } else {
            Ok(Self {
                len_limit: (value as u16).to_be_bytes(),
            })
        }
    }
}

impl From<AdjustLenLimitRequest> for usize {
    fn from(request: AdjustLenLimitRequest) -> Self {
        u16::from_be_bytes(request.len_limit) as usize
    }
}

plain_msg!(AdjustLenLimitRequest, PlainMessageType::AdjustLenLimitRequest, 2 =>
    len_limit, 2
);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct AdjustLenLimitResponse {
    has_accepted: [u8; 1],
}

impl From<bool> for AdjustLenLimitResponse {
    fn from(value: bool) -> Self {
        Self {
            has_accepted: [value as u8],
        }
    }
}

impl From<AdjustLenLimitResponse> for bool {
    fn from(response: AdjustLenLimitResponse) -> Self {
        response.has_accepted[0] != 0
    }
}

plain_msg!(AdjustLenLimitResponse, PlainMessageType::AdjustLenLimitResponse, 1 =>
    has_accepted, 1
);

use std::ops::RangeInclusive;

use crate::proto::message::{MIN_LEN_LIMIT, MAX_LEN_LIMIT};

pub(super) struct LenLimit {
    // NOTE: Only applicable for accepting/rejecting requests.
    pub(super) acceptable_range: RangeInclusive<usize>,
    pub(super) requested: Option<usize>,
}

impl Default for LenLimit {
    fn default() -> Self {
        Self {
            acceptable_range: MIN_LEN_LIMIT..=MAX_LEN_LIMIT,
            requested: None,
        }
    }
}
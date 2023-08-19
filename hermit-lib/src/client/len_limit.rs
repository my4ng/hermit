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

impl LenLimit {
    // NOTE: The final set range is the intersection of the requested range and the acceptable range.
    pub(super) fn adjust_acceptable_range(
        &mut self,
        len_limit_range: RangeInclusive<usize>,
    ) -> RangeInclusive<usize> {
        let &lower_bound = len_limit_range.start().max(&MIN_LEN_LIMIT);
        let &upper_bound = len_limit_range.end().min(&MAX_LEN_LIMIT);
        let len_limit_range = lower_bound..=upper_bound;
        self.acceptable_range = len_limit_range.clone();
        len_limit_range
    }
}
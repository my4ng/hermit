#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Config {
    requested_len_limit: Option<usize>,
}

impl Config {
    pub(super) fn request_len_limit(mut self, len_limit: usize) -> Self {
        self.requested_len_limit = Some(len_limit);
        self
    }
}
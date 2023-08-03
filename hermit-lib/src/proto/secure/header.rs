use serde::{Deserialize, Serialize};

use super::message::SecureMessageType;

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[non_exhaustive]
pub(crate) struct SecureMessageHeader {
    pub(super) secure_msg_type: SecureMessageType,
    pub(super) length: usize,
}

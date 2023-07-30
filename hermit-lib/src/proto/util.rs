use serde::{Deserialize, Serialize};

use super::message::SecureMessageType;
use crate::secure;

// NOTE: Currently, only the Client is allowed to send this message.
// The Server has to unconditionally accept it, and adjust the message
// length according thereafter. If the Server is unable to comply, it
// may choose to disconnect or downgrade the connection.
#[serde_with::serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct AdjustMessageLength {
    // NOTE: `MIN_MSG_LEN` <= `length` <= `MAX_MSG_LEN`.
    pub length: u16,
}

secure!(AdjustMessageLength, SecureMessageType::AdjustMessageLength);

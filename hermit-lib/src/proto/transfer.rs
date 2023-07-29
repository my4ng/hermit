use ring::signature;
use serde::{Deserialize, Serialize};
use serde_with;

use crate::error::InvalidMessageError;

use super::message::*;

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) enum ReceiverControl {
    Password(String),
    PublicKey([u8; signature::ED25519_PUBLIC_KEY_LEN]),
}

#[serde_with::serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct SendResourceRequest {
    // The size and name of the resource to be sent.
    pub resources: Vec<(u64, String)>,
    // Suggest an expiry duration to the server which may accept or reject it.
    #[serde_as(as = "Option<serde_with::DurationSeconds<i64>>")]
    pub expiry_duration: Option<chrono::Duration>,
    // The control method to be used by the receiver to authenticate (if any).
    pub receiver_control: Option<ReceiverControl>,
}

// TODO: Implement From and TryFrom using macros.

impl TryFrom<SendResourceRequest> for SecureMessage {
    type Error = InvalidMessageError;

    fn try_from(value: SendResourceRequest) -> Result<Self, Self::Error> {
        let mut message = Self::new(SecureMessageType::SendResourceRequest);
        ciborium::into_writer(&value, message.writer())?;
        message.above_max_len()?;
        Ok(message)
    }
}

impl TryFrom<SecureMessage> for SendResourceRequest {
    type Error = InvalidMessageError;

    fn try_from(value: SecureMessage) -> Result<Self, Self::Error> {
        ciborium::from_reader(value.payload()).map_err(InvalidMessageError::from)
    }
}

impl Secure for SendResourceRequest {}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) enum SendResourceResponse {
    Ok {
        // The resource ID is used to identify the resource in the server.
        // It may be converted to a more memorable passphrase by the client using `niceware`.
        id: Vec<u8>,
        // The actual expiry time of the resource.
        expiry: chrono::DateTime<chrono::Utc>,
    },
    InvalidReceiverControl,
    InvalidExpiry,
    ResourceTooLarge,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct ReceiveResourceRequest {
    pub id: Vec<u8>,
    pub control: Option<ReceiverControl>,
}

#[serde_with::serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct ReceiveResourceResponse {
    // The sizes and names of the files or directories (or a combination of both) to be received.
    pub size: Vec<u64>,
    pub name: Vec<String>,
    pub expiry: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_send_resource_request_serialization() {
        let request = SendResourceRequest {
            resources: vec![(100_000_000, "ABCDEFGHIJKLMNOPQRSTUVWXYZ.txt".to_owned()); 1000],
            expiry_duration: Some(chrono::Duration::days(1)),
            receiver_control: Some(ReceiverControl::Password("test".to_owned())),
        };
        let request_copy = SendResourceRequest {
            resources: vec![(100_000_000, "ABCDEFGHIJKLMNOPQRSTUVWXYZ.txt".to_owned()); 1000],
            expiry_duration: Some(chrono::Duration::days(1)),
            receiver_control: Some(ReceiverControl::Password("test".to_owned())),
        };
        let msg = SecureMessage::try_from(request).unwrap();
        let deserialized = SendResourceRequest::try_from(msg).unwrap();
        assert_eq!(request_copy, deserialized);
    }
}

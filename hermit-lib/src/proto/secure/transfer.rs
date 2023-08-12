use ring::signature;
use serde::{Deserialize, Serialize};
use serde_with;

use crate::secure_msg;

use super::header::SecureMessageType;

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

secure_msg!(SendResourceRequest, SecureMessageType::SendResourceRequest);

// NOTE: the resource ID length is dynamic, depending on the number of active resources
// on the server, and also the duration till the expiry time.
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct ResourceId(Vec<u8>);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) enum SendResourceResponse {
    Ok {
        // The resource ID is used to identify the resource in the server.
        id: ResourceId,
        // The actual expiry time of the resource.
        expiry: chrono::DateTime<chrono::Utc>,
    },
    InvalidReceiverControl,
    InvalidExpiry,
    ResourceTooLarge,
}

secure_msg!(SendResourceResponse, SecureMessageType::SendResourceResponse);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct ReceiveResourceRequest {
    pub id: ResourceId,
    pub control: Option<ReceiverControl>,
}

secure_msg!(ReceiveResourceRequest, SecureMessageType::ReceiveResourceRequest);

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) enum ReceiveResourceResponse {
    Ok {
        // The sizes and names of the files or directories (or a combination of both) to be received.
        size: Vec<u64>,
        name: Vec<String>,
        expiry: chrono::DateTime<chrono::Utc>,
    },
    // The reason for the failure is not specified deliberately.
    // Some possible reasons include:
    // 1. The resource ID is invalid.
    // 2. The resource has expired.
    // 3. The resource has been deleted.
    // 4. The resource has been received by another receiver.
    // 5. The receiver control is invalid.
    // 6. The receiver control is not provided.
    Failed,
}

secure_msg!(ReceiveResourceResponse, SecureMessageType::ReceiveResourceResponse);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_send_resource_request_serialization() {
        let request = SendResourceRequest {
            resources: vec![(100_000_000, "ABCDEFGHIJKLMNOPQRSTUVWXYZ.txt".to_owned()); 10],
            expiry_duration: Some(chrono::Duration::days(1)),
            receiver_control: Some(ReceiverControl::Password("test".to_owned())),
        };
        let request_copy = SendResourceRequest {
            resources: vec![(100_000_000, "ABCDEFGHIJKLMNOPQRSTUVWXYZ.txt".to_owned()); 10],
            expiry_duration: Some(chrono::Duration::days(1)),
            receiver_control: Some(ReceiverControl::Password("test".to_owned())),
        };
        let mut msg = Vec::new();
        ciborium::into_writer(&request, &mut msg).unwrap();
        dbg!(msg.as_slice());
        dbg!(msg.len());
        let deserialized = ciborium::from_reader::<SendResourceRequest, _>(msg.as_slice()).unwrap();
        assert_eq!(request_copy, deserialized);
    }
}

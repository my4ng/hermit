use ring::signature;
use serde::{Deserialize, Serialize};
use serde_with;

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

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub(crate) struct ReceiveResourceRequest {
    pub id: ResourceId,
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
        let mut msg = Vec::new();
        ciborium::into_writer(&request, &mut msg).unwrap();
        let deserialized = ciborium::from_reader::<SendResourceRequest, _>(msg.as_slice()).unwrap();
        assert_eq!(request_copy, deserialized);
    }
}

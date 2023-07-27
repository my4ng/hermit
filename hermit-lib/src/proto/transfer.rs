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
pub struct SendResourceRequest {
    // The sizes and names of the files or directories (or a combination of both) to be sent.
    pub(crate) size: Vec<u64>,
    pub(crate) name: Vec<String>,
    // Suggest an expiry duration to the server which may accept or reject it.
    #[serde_as(as = "Option<serde_with::DurationSeconds<i64>>")]
    pub(crate) expiry_duration: Option<chrono::Duration>,
    // The control method to be used by the receiver to authenticate (if any).
    pub(crate) receiver_control: Option<ReceiverControl>,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum SendResourceResponse {
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
pub struct ReceiveResourceRequest {
    pub(crate) id: Vec<u8>,
    pub(crate) control: Option<ReceiverControl>,
}

#[serde_with::serde_as]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
pub struct ReceiveResourceResponse {
    // The sizes and names of the files or directories (or a combination of both) to be received.
    pub(crate) size: Vec<u64>,
    pub(crate) name: Vec<String>,
    pub(crate) expiry: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_send_resource_request_serialization() {
        let request = SendResourceRequest {
            size: vec![100, 200_000_000, 300],
            name: vec!["test.txt".to_owned(), "folder".to_owned()],
            expiry_duration: Some(chrono::Duration::days(1)),
            receiver_control: Some(ReceiverControl::Password("test".to_owned())),
        };
        let mut buffer = Vec::new();
        ciborium::into_writer(&request, &mut buffer).unwrap();
        let deserialized = ciborium::from_reader(&buffer[..]).unwrap();
        assert_eq!(request, deserialized);
    }

    #[test]
    fn test_receive_resource_request_serialization() {
        let request = ReceiveResourceRequest {
            id: vec![0x24, 0xF5, 0x3A],
            control: Some(ReceiverControl::Password("test".to_owned())),
        };

        let mut buffer = Vec::new();
        ciborium::into_writer(&request, &mut buffer).unwrap();
        let deserialized = ciborium::from_reader(&buffer[..]).unwrap();
        assert_eq!(request, deserialized);
    }
}

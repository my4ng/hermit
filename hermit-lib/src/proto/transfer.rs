use ring::signature::UnparsedPublicKey;

pub(crate) enum ReceiverControl {
    Password(String),
    PublicKey(UnparsedPublicKey<Vec<u8>>),
}

pub struct SendResourceRequest {
    // The sizes and names of the files or directories (or a combination of both) to be sent.
    pub(crate) size: Vec<u64>,
    pub(crate) name: Vec<String>,
    // Suggest an expiry duration to the server which may accept or reject it.
    pub(crate) expiry_duration: Option<chrono::Duration>,
    // The control method to be used by the receiver to authenticate (if any).
    pub(crate) receiver_control: Option<ReceiverControl>,
}

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

pub struct ReceiveResourceRequest {
    pub(crate) id: Vec<u8>,
    pub(crate) control: Option<ReceiverControl>,
}
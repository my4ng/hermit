use ring::signature::UnparsedPublicKey;

pub(crate) enum ReceiverControl {
    Password(String),
    PublicKey(UnparsedPublicKey<Vec<u8>>),
}

pub struct SendResourceRequest {
    pub(crate) size: u64,
    pub(crate) name: String,
    pub(crate) expiry: Option<chrono::DateTime<chrono::Utc>>,
    pub(crate) receiver_control: Option<ReceiverControl>,
}

pub struct ReceiveResourceRequest {
    pub(crate) id: Vec<u8>,
    pub(crate) control: Option<ReceiverControl>,
}
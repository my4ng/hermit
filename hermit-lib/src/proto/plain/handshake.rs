use super::header::PlainMessageType;
use crate::{crypto, plain_msg};

pub(crate) const CLIENT_HELLO_MSG_LEN: usize = crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN;
pub(crate) const SERVER_HELLO_MSG_LEN: usize =
    crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN + crypto::ED25519_SIGNATURE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientHelloMessage {
    pub(crate) nonce: [u8; crypto::NONCE_LEN],
    pub(crate) public_key_bytes: [u8; crypto::X25519_PUBLIC_KEY_LEN],
}

plain_msg!(ClientHelloMessage, PlainMessageType::ClientHello, CLIENT_HELLO_MSG_LEN => 
    nonce, crypto::NONCE_LEN; 
    public_key_bytes, crypto::X25519_PUBLIC_KEY_LEN
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerHelloMessage {
    pub(crate) nonce: [u8; crypto::NONCE_LEN],
    pub(crate) public_key_bytes: [u8; crypto::X25519_PUBLIC_KEY_LEN],
    pub(crate) signature: [u8; crypto::ED25519_SIGNATURE_LEN],
}

plain_msg!(ServerHelloMessage, PlainMessageType::ServerHello, SERVER_HELLO_MSG_LEN => 
    nonce, crypto::NONCE_LEN; 
    public_key_bytes, crypto::X25519_PUBLIC_KEY_LEN;
    signature, crypto::ED25519_SIGNATURE_LEN
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DisconnectMessage;

plain_msg!(DisconnectMessage, PlainMessageType::Disconnect);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DowngradeMessage;

plain_msg!(DowngradeMessage, PlainMessageType::Downgrade);

#[cfg(test)]
mod test {
    use super::*;
    use super::super::message::Message;

    #[async_std::test]
    async fn test_client_hello_message() {
        let test = ClientHelloMessage {
            nonce: crypto::generate_nonce().await.unwrap(),
            public_key_bytes: crypto::generate_ephemeral_key_pair()
                .unwrap()
                .1
                .as_ref()
                .try_into()
                .unwrap(),
        };
        let test_message = Message::from(test);
        let test_from_message = ClientHelloMessage::try_from(test_message).unwrap();
        assert_eq!(test, test_from_message);
    }

    #[async_std::test]
    async fn test_server_hello_message() {
        let sig_key_pair = crypto::generate_signature_key_pair().unwrap();

        let client_nonce = crypto::generate_nonce().await.unwrap();
        let nonce = crypto::generate_nonce().await.unwrap();
        let public_key_bytes: [u8; 32] = crypto::generate_ephemeral_key_pair()
            .unwrap()
            .1
            .as_ref()
            .try_into()
            .unwrap();
        let sig_content_bytes = [
            client_nonce.as_slice(),
            nonce.as_slice(),
            public_key_bytes.as_slice(),
        ]
        .concat();

        let test = ServerHelloMessage {
            nonce,
            public_key_bytes,
            signature: sig_key_pair
                .sign(&sig_content_bytes)
                .as_ref()
                .try_into()
                .unwrap(),
        };

        let test_message = Message::from(test);
        let test_from_message = ServerHelloMessage::try_from(test_message).unwrap();
        assert_eq!(test, test_from_message);
    }

    #[test]
    fn test_disconnect_message() {
        let msg = DisconnectMessage {};
        let msg_from = Message::from(msg);
        let msg_back = DisconnectMessage::try_from(msg_from).unwrap();
        assert_eq!(msg, msg_back);
    }
}

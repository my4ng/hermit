use super::message::{Message, MessageType, Plain};
use crate::{crypto, error::InvalidMessageError};

pub(crate) const CLIENT_HELLO_MSG_LEN: usize = crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN;
pub(crate) const SERVER_HELLO_MSG_LEN: usize =
    crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN + crypto::ED25519_SIGNATURE_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientHelloMessage {
    pub nonce: [u8; crypto::NONCE_LEN],
    pub public_key_bytes: [u8; crypto::X25519_PUBLIC_KEY_LEN],
}

impl From<ClientHelloMessage> for Message {
    fn from(value: ClientHelloMessage) -> Self {
        // SAFETY: length < MAX_PAYLOAD_LEN
        let mut msg = Self::new(CLIENT_HELLO_MSG_LEN, MessageType::ClientHello).unwrap();
        msg.payload_mut()[..crypto::NONCE_LEN].copy_from_slice(&value.nonce);
        msg.payload_mut()[crypto::NONCE_LEN..].copy_from_slice(&value.public_key_bytes);
        msg
    }
}

impl TryFrom<Message> for ClientHelloMessage {
    type Error = InvalidMessageError;

    fn try_from(value: Message) -> Result<Self, Self::Error> {
        let bytes = value.payload();

        if bytes.len() != CLIENT_HELLO_MSG_LEN {
            return Err(InvalidMessageError::PayloadLength {
                expected: CLIENT_HELLO_MSG_LEN,
                actual: bytes.len(),
            });
        }

        // SAFETY: message has the correct length

        let nonce = <[u8; crypto::NONCE_LEN]>::try_from(&bytes[..crypto::NONCE_LEN]).unwrap();
        
        let public_key_bytes =
            <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(&bytes[crypto::NONCE_LEN..]).unwrap();

        Ok(Self {
            nonce,
            public_key_bytes,
        })
    }
}

impl Plain for ClientHelloMessage {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerHelloMessage {
    pub nonce: [u8; crypto::NONCE_LEN],
    pub public_key_bytes: [u8; crypto::X25519_PUBLIC_KEY_LEN],
    pub signature: [u8; crypto::ED25519_SIGNATURE_LEN],
}

impl From<ServerHelloMessage> for Message {
    fn from(value: ServerHelloMessage) -> Self {
        // SAFETY: length < MAX_PAYLOAD_LEN
        let mut msg = Self::new(SERVER_HELLO_MSG_LEN, MessageType::ServerHello).unwrap();
        msg.payload_mut()[..crypto::NONCE_LEN].copy_from_slice(&value.nonce);
        msg.payload_mut()[crypto::NONCE_LEN..crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN]
            .copy_from_slice(&value.public_key_bytes);
        msg.payload_mut()[crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN..]
            .copy_from_slice(&value.signature);
        msg
    }
}

impl TryFrom<Message> for ServerHelloMessage {
    type Error = InvalidMessageError;

    fn try_from(value: Message) -> Result<Self, Self::Error> {
        let bytes = value.payload();

        if bytes.len() != SERVER_HELLO_MSG_LEN {
            return Err(InvalidMessageError::PayloadLength {
                expected: SERVER_HELLO_MSG_LEN,
                actual: bytes.len(),
            });
        }

        // SAFETY: message has the correct length

        let nonce = <[u8; crypto::NONCE_LEN]>::try_from(&bytes[..crypto::NONCE_LEN]).unwrap();

        let public_key_bytes = <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(
            &bytes[crypto::NONCE_LEN..crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN],
        )
        .unwrap();

        let signature = <[u8; crypto::ED25519_SIGNATURE_LEN]>::try_from(
            &bytes[crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN..],
        )
        .unwrap();

        Ok(Self {
            nonce,
            public_key_bytes,
            signature,
        })
    }
}

impl Plain for ServerHelloMessage {}

// #[cfg(test)]
// mod test {
//     use super::*;

//     #[async_std::test]
//     async fn test_client_hello_message() {
//         let test = ClientHelloMessage {
//             nonce: crypto::generate_nonce().await.unwrap(),
//             public_key_bytes: crypto::generate_ephemeral_key_pair()
//                 .unwrap()
//                 .1
//                 .as_ref()
//                 .try_into()
//                 .unwrap(),
//         };
//         let test_bytes = <[u8; CLIENT_HELLO_MSG_LEN]>::from(test);
//         let test_from_bytes = ClientHelloMessage::try_from(test_bytes).unwrap();
//         assert_eq!(test, test_from_bytes);
//     }

//     #[async_std::test]
//     async fn test_server_hello_message() {
//         let sig_key_pair = crypto::generate_signature_key_pair().unwrap();

//         let client_nonce = crypto::generate_nonce().await.unwrap();
//         let nonce = crypto::generate_nonce().await.unwrap();
//         let public_key_bytes: [u8; 32] = crypto::generate_ephemeral_key_pair()
//             .unwrap()
//             .1
//             .as_ref()
//             .try_into()
//             .unwrap();
//         let sig_content_bytes = [
//             client_nonce.as_slice(),
//             nonce.as_slice(),
//             public_key_bytes.as_slice(),
//         ]
//         .concat();

//         let test = ServerHelloMessage {
//             nonce,
//             public_key_bytes,
//             signature: sig_key_pair
//                 .sign(&sig_content_bytes)
//                 .as_ref()
//                 .try_into()
//                 .unwrap(),
//         };

//         let test_bytes = <[u8; SERVER_HELLO_MSG_LEN]>::from(test);
//         let test_from_bytes = ServerHelloMessage::try_from(test_bytes).unwrap();
//         assert_eq!(test, test_from_bytes);
//     }
// }

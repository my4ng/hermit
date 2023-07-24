use crate::{crypto, error};
use super::ProtocolVersion;

pub(crate) const CLIENT_HELLO_MSG_HEADER_LEN: usize = 16;
pub(crate) const CLIENT_HELLO_MSG_LEN: usize =
    CLIENT_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN;

pub(crate) const SERVER_HELLO_MSG_HEADER_LEN: usize = 16;
pub(crate) const SERVER_HELLO_MSG_LEN: usize = SERVER_HELLO_MSG_HEADER_LEN
    + crypto::NONCE_LEN
    + crypto::X25519_PUBLIC_KEY_LEN
    + crypto::ED25519_SIGNATURE_LEN;

// TODO: Use CBOR for both message headers.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientHelloMessageHeader {
    pub version: ProtocolVersion,
}

impl From<ClientHelloMessageHeader> for [u8; CLIENT_HELLO_MSG_HEADER_LEN] {
    fn from(header: ClientHelloMessageHeader) -> Self {
        let mut header_bytes = [0u8; CLIENT_HELLO_MSG_HEADER_LEN];
        header_bytes[0] = header.version as u8;
        header_bytes
    }
}

impl TryFrom<[u8; CLIENT_HELLO_MSG_HEADER_LEN]> for ClientHelloMessageHeader {
    type Error = error::Error;

    fn try_from(header_bytes: [u8; CLIENT_HELLO_MSG_HEADER_LEN]) -> Result<Self, Self::Error> {
        let version = match header_bytes[0] {
            0x01 => ProtocolVersion::V0_1,
            _ => return Err(Self::Error::Parsing(header_bytes.to_vec())),
        };
        Ok(ClientHelloMessageHeader { version })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientHelloMessage {
    pub header: ClientHelloMessageHeader,
    pub nonce: [u8; crypto::NONCE_LEN],
    pub public_key_bytes: [u8; crypto::X25519_PUBLIC_KEY_LEN],
}

impl From<ClientHelloMessage> for [u8; CLIENT_HELLO_MSG_LEN] {
    fn from(msg: ClientHelloMessage) -> Self {
        let mut msg_bytes = [0u8; CLIENT_HELLO_MSG_LEN];

        msg_bytes[..CLIENT_HELLO_MSG_HEADER_LEN]
            .copy_from_slice(&<[u8; CLIENT_HELLO_MSG_HEADER_LEN]>::from(msg.header));

        msg_bytes[CLIENT_HELLO_MSG_HEADER_LEN..CLIENT_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN]
            .copy_from_slice(&msg.nonce);

        msg_bytes[CLIENT_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN..]
            .copy_from_slice(&msg.public_key_bytes);

        msg_bytes
    }
}

impl TryFrom<[u8; CLIENT_HELLO_MSG_LEN]> for ClientHelloMessage {
    type Error = error::Error;

    fn try_from(msg_bytes: [u8; CLIENT_HELLO_MSG_LEN]) -> Result<Self, Self::Error> {
        // SAFETY: message has the correct length
        let header = <[u8; CLIENT_HELLO_MSG_HEADER_LEN]>::try_from(
            &msg_bytes[..CLIENT_HELLO_MSG_HEADER_LEN],
        )
        .unwrap()
        .try_into()?;

        // SAFETY: message has the correct length
        let nonce = <[u8; crypto::NONCE_LEN]>::try_from(
            &msg_bytes
                [CLIENT_HELLO_MSG_HEADER_LEN..CLIENT_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN],
        )
        .unwrap();

        // SAFETY: message has the correct length
        let public_key_bytes = <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(
            &msg_bytes[CLIENT_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN..],
        )
        .unwrap();

        Ok(ClientHelloMessage {
            header,
            nonce,
            public_key_bytes,
        })
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerHelloMessageStatus {
    // NOTE: 0x00 RESERVED
    Ok = 0x01,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerHelloMessageHeader {
    pub status: ServerHelloMessageStatus,
}

impl From<ServerHelloMessageHeader> for [u8; SERVER_HELLO_MSG_HEADER_LEN] {
    fn from(header: ServerHelloMessageHeader) -> Self {
        let mut header_bytes = [0u8; SERVER_HELLO_MSG_HEADER_LEN];
        header_bytes[0] = header.status as u8;
        header_bytes
    }
}

impl TryFrom<[u8; SERVER_HELLO_MSG_HEADER_LEN]> for ServerHelloMessageHeader {
    type Error = error::Error;

    fn try_from(header_bytes: [u8; SERVER_HELLO_MSG_HEADER_LEN]) -> Result<Self, Self::Error> {
        let status = match header_bytes[0] {
            0x01 => ServerHelloMessageStatus::Ok,
            _ => return Err(Self::Error::Parsing(header_bytes.to_vec())),
        };
        Ok(ServerHelloMessageHeader { status })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerHelloMessage {
    pub header: ServerHelloMessageHeader,
    pub nonce: [u8; crypto::NONCE_LEN],
    pub public_key_bytes: [u8; crypto::X25519_PUBLIC_KEY_LEN],
    pub signature: [u8; crypto::ED25519_SIGNATURE_LEN],
}

impl From<ServerHelloMessage> for [u8; SERVER_HELLO_MSG_LEN] {
    fn from(msg: ServerHelloMessage) -> Self {
        let mut msg_bytes = [0u8; SERVER_HELLO_MSG_LEN];

        msg_bytes[..SERVER_HELLO_MSG_HEADER_LEN]
            .copy_from_slice(&<[u8; SERVER_HELLO_MSG_HEADER_LEN]>::from(msg.header));

        msg_bytes[SERVER_HELLO_MSG_HEADER_LEN..SERVER_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN]
            .copy_from_slice(&msg.nonce);

        msg_bytes[SERVER_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN
            ..SERVER_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN]
            .copy_from_slice(&msg.public_key_bytes);

        msg_bytes
            [SERVER_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN..]
            .copy_from_slice(&msg.signature);

        msg_bytes
    }
}

impl TryFrom<[u8; SERVER_HELLO_MSG_LEN]> for ServerHelloMessage {
    type Error = error::Error;

    fn try_from(msg_bytes: [u8; SERVER_HELLO_MSG_LEN]) -> Result<Self, Self::Error> {
        // SAFETY: message has the correct length
        let header = <[u8; SERVER_HELLO_MSG_HEADER_LEN]>::try_from(
            &msg_bytes[..SERVER_HELLO_MSG_HEADER_LEN],
        )
        .unwrap()
        .try_into()?;

        // SAFETY: message has the correct length
        let nonce = <[u8; crypto::NONCE_LEN]>::try_from(
            &msg_bytes
                [SERVER_HELLO_MSG_HEADER_LEN..SERVER_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN],
        )
        .unwrap();

        // SAFETY: message has the correct length
        let public_key_bytes = <[u8; crypto::X25519_PUBLIC_KEY_LEN]>::try_from(
            &msg_bytes[SERVER_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN
                ..SERVER_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN],
        )
        .unwrap();

        // SAFETY: message has the correct length
        let signature = <[u8; crypto::ED25519_SIGNATURE_LEN]>::try_from(
            &msg_bytes
                [SERVER_HELLO_MSG_HEADER_LEN + crypto::NONCE_LEN + crypto::X25519_PUBLIC_KEY_LEN..],
        )
        .unwrap();

        Ok(ServerHelloMessage {
            header,
            nonce,
            public_key_bytes,
            signature,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[async_std::test]
    async fn test_client_hello_message() {
        let test = ClientHelloMessage {
            header: ClientHelloMessageHeader {
                version: super::super::CURRENT_PROTOCOL_VERSION,
            },
            nonce: crypto::generate_nonce().await.unwrap(),
            public_key_bytes: crypto::generate_ephemeral_key_pair()
                .unwrap()
                .1
                .as_ref()
                .try_into()
                .unwrap(),
        };
        let test_bytes = <[u8; CLIENT_HELLO_MSG_LEN]>::from(test);
        let test_from_bytes = ClientHelloMessage::try_from(test_bytes).unwrap();
        assert_eq!(test, test_from_bytes);
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
            header: ServerHelloMessageHeader {
                status: ServerHelloMessageStatus::Ok,
            },
            nonce,
            public_key_bytes,
            signature: sig_key_pair
                .sign(&sig_content_bytes)
                .as_ref()
                .try_into()
                .unwrap(),
        };

        let test_bytes = <[u8; SERVER_HELLO_MSG_LEN]>::from(test);
        let test_from_bytes = ServerHelloMessage::try_from(test_bytes).unwrap();
        assert_eq!(test, test_from_bytes);
    }
}

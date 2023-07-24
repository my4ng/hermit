pub mod handshake;
pub mod transfer;

pub(crate) use handshake::*;
pub(crate) use transfer::*;

use crate::crypto;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolVersion {
    // NOTE: 0x00 RESERVED
    V0_1 = 0x01,
}

pub(crate) const CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V0_1;

pub trait Stream: {}

pub trait DisconnectableStream: Stream {}

pub struct NilStream;
impl Stream for NilStream {}

pub use async_std::net::TcpStream;
impl Stream for TcpStream {}
impl DisconnectableStream for TcpStream {}

pub struct SecureStream {
    pub(crate) stream: TcpStream,
    pub(crate) session_secrets: crypto::SessionSecrets,
}
impl Stream for SecureStream {}
impl DisconnectableStream for SecureStream {}
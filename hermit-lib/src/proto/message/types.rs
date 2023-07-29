use num_enum::{TryFromPrimitive, IntoPrimitive};

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum SecureMessageType {
    SendResourceRequest = 0x01,
    SendResourceResponse = 0x02,
    ReceiveResourceRequest = 0x03,
    ReceiveResourceResponse = 0x04,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum MessageType {
    Secure = 0x00,
    ClientHello = 0x01,
    ServerHello = 0x02,
    Disconnect = 0x03,
    Downgrade = 0x04,
}
#[macro_export]
macro_rules! secure {
    ($message:ty, $message_type:expr) => {
        impl TryFrom<$message> for SecureMessage {
            type Error = InvalidMessageError;
        
            fn try_from(value: $message) -> Result<Self, Self::Error> {
                let mut message = Self::new($message_type);
                ciborium::into_writer(&value, message.writer())?;
                message.above_max_len()?;
                Ok(message)
            }
        }
        
        impl TryFrom<SecureMessage> for $message {
            type Error = InvalidMessageError;
        
            fn try_from(value: SecureMessage) -> Result<Self, Self::Error> {
                ciborium::from_reader(value.payload()).map_err(InvalidMessageError::from)
            }
        }
        
        impl Secure for $message {}
    };
}
#[macro_export]
macro_rules! secure {
    ($message:ty, $message_type:expr) => {
        impl From<$message> for $crate::proto::message::SecureMessage {
            fn from(value: $message) -> Self {
                let mut message = Self::new($message_type);
                ciborium::into_writer(&value, message.writer()).unwrap();
                message
            }
        }

        impl TryFrom<$crate::proto::message::SecureMessage> for $message {
            type Error = $crate::error::InvalidMessageError;

            fn try_from(value: $crate::proto::message::SecureMessage) -> Result<Self, Self::Error> {
                ciborium::from_reader(value.payload()).map_err($crate::error::InvalidMessageError::from)
            }
        }

        impl $crate::proto::message::Secure for $message {}
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! plain_to_msg_helper {
    ($msg:ident, $len:ident, $value:ident;) => {};
    ($msg:ident, $len:ident, $value:ident; $field:tt, $field_len:expr $(; $fields:tt, $field_lens:expr)* ) => {
        $len += $field_len;
        $msg.payload_mut()[$len - $field_len..$len].copy_from_slice(&$value.$field);
        $crate::plain_to_msg_helper!($msg, $len, $value; $($fields, $field_lens);* );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! plain_from_msg_helper {
    ($bytes:ident, $len:ident;) => {};
    ($bytes:ident, $len:ident; $field:tt, $field_len:expr $(; $fields:tt, $field_lens:expr)* ) => {
        $len += $field_len;
        let $field = <[u8; $field_len]>::try_from(&$bytes[$len + $field_len..$len]).unwrap();
        $crate::plain_from_msg_helper!($bytes, $len; $($fields, $field_lens);* );
    };
}


#[macro_export]
macro_rules! plain {
    ($message:ty, $message_type:expr) => {
        impl From<$message> for $crate::proto::message::PlainMessage {
            fn from(_: $message) -> Self {
                let msg = Self::new(0u16, $message_type);
                msg
            }
        }

        impl TryFrom<$crate::proto::message::PlainMessage> for $message {
            type Error = $crate::error::InvalidMessageError;

            fn try_from(value: $crate::proto::message::PlainMessage) -> Result<Self, Self::Error> {
                let bytes = value.payload();
                if bytes.len() != 0 {
                    return Err($crate::error::InvalidMessageError::PayloadLength {
                        expected: 0,
                        actual: bytes.len(),
                    });
                }
                Ok(Self {})
            }
        }

        impl $crate::proto::message::Plain for $message {}
    };

    ($message:ty, $message_type:expr, $len:expr => $($fields:tt, $field_lens:expr);+ ) => {
        impl From<$message> for $crate::proto::message::PlainMessage {
            fn from(value: $message) -> Self {
                let mut msg = Self::new($len as u16, $message_type);
                let mut len = 0;
        
                $crate::plain_to_msg_helper!(msg, len, value; $($fields, $field_lens);+ );
        
                msg
            }
        }

        impl TryFrom<$crate::proto::message::PlainMessage> for $message {
            type Error = $crate::error::InvalidMessageError;

            fn try_from(value: $crate::proto::message::PlainMessage) -> Result<Self, Self::Error> {
                let bytes = value.payload();
                let mut len = 0;

                if bytes.len() != $len {
                    return Err($crate::error::InvalidMessageError::PayloadLength {
                        expected: $len,
                        actual: bytes.len(),
                    });
                }

                $crate::plain_from_msg_helper!(bytes, len; $($fields, $field_lens);+ );

                Ok(Self {
                   $($fields),*
                })
            }
        }

        impl $crate::proto::message::Plain for $message {}
    };
}

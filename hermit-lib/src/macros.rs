#[doc(hidden)]
#[macro_export]
macro_rules! plain_to_msg_helper {
    ($msg:ident, $len:ident, $value:ident;) => {};
    ($msg:ident, $len:ident, $value:ident; $field:tt, $field_len:expr $(; $fields:tt, $field_lens:expr)* ) => {
        $len += $field_len;
        $msg.as_mut()[$len - $field_len..$len].copy_from_slice(&$value.$field);
        $crate::plain_to_msg_helper!($msg, $len, $value; $($fields, $field_lens);* );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! plain_from_msg_helper {
    ($bytes:ident, $len:ident;) => {};
    ($bytes:ident, $len:ident; $field:tt, $field_len:expr $(; $fields:tt, $field_lens:expr)* ) => {
        $len += $field_len;
        let $field = <[u8; $field_len]>::try_from(&$bytes[$len - $field_len..$len]).unwrap();
        $crate::plain_from_msg_helper!($bytes, $len; $($fields, $field_lens);* );
    };
}


#[macro_export]
macro_rules! plain {
    ($message:ty, $message_type:expr) => {
        impl From<$message> for $crate::proto::plain::message::Message {
            fn from(_: $message) -> Self {
                let msg = Self::new($message_type, Box::new([]));
                msg
            }
        }

        impl TryFrom<$crate::proto::plain::message::Message> for $message {
            type Error = $crate::error::InvalidMessageError;

            fn try_from(value: $crate::proto::plain::message::Message) -> Result<Self, Self::Error> {
                let bytes = value.as_ref();
                if bytes.len() != 0 {
                    return Err($crate::error::InvalidMessageError::PayloadLengthMismatch {
                        expected: 0,
                        actual: bytes.len(),
                    });
                }
                Ok(Self {})
            }
        }
    };

    ($message:ty, $message_type:expr, $len:expr => $($fields:tt, $field_lens:expr);+ ) => {
        impl From<$message> for $crate::proto::plain::message::Message {
            fn from(value: $message) -> Self {
                let mut msg = Self::new($message_type, Box::new([0; $len]));
                let mut len = 0;
        
                $crate::plain_to_msg_helper!(msg, len, value; $($fields, $field_lens);+ );
        
                msg
            }
        }

        impl TryFrom<$crate::proto::plain::message::Message> for $message {
            type Error = $crate::error::InvalidMessageError;

            fn try_from(value: $crate::proto::plain::message::Message) -> Result<Self, Self::Error> {
                let bytes = value.as_ref();
                let mut len = 0;

                if bytes.len() != $len {
                    return Err($crate::error::InvalidMessageError::PayloadLengthMismatch {
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
    };
}

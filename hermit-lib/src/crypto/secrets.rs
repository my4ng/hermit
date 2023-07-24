use ring::{hkdf, aead};

// TODO: use `secrecy` and `zeroize` to secure the secrets
pub(crate) struct SessionSecrets {
    // NOTE: kept for potential key generations
    pseudorandom_key: Box<hkdf::Prk>,
    master_key: Box<aead::UnboundKey>,
    // NOTE: nonces (=== client_nonce || server_nonce) is used as the session ID
    session_id: [u8; 2 * super::NONCE_LEN],
}

impl SessionSecrets {
    pub(crate) fn new(
        pseudorandom_key: Box<hkdf::Prk>,
        master_key: Box<aead::UnboundKey>,
        session_id: [u8; 2 * super::NONCE_LEN],
    ) -> Self {
        Self {
            pseudorandom_key,
            master_key,
            session_id,
        }
    }

    // NOTE: ensure no field may be modified

    pub(crate) fn pseudorandom_key(&self) -> &hkdf::Prk {
        &self.pseudorandom_key
    }

    pub(crate) fn master_key(&self) -> &aead::UnboundKey {
        &self.master_key
    }

    pub(crate) fn session_id(&self) -> &[u8; 2 * super::NONCE_LEN] {
        &self.session_id
    }
}

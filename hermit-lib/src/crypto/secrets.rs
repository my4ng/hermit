use ring::aead::{self, BoundKey};
use ring::hkdf;

pub(crate) struct NonceSequence {
    base: [u8; aead::NONCE_LEN],
    counter: u64,
}

impl NonceSequence {
    pub(crate) fn new(base: &[u8; aead::NONCE_LEN]) -> Self {
        Self {
            base: base.to_owned(),
            counter: 0,
        }
    }

    fn xor(base: &[u8; aead::NONCE_LEN], counter: u64) -> [u8; aead::NONCE_LEN] {
        let mut nonce = base.to_owned();
        for (i, byte) in counter.to_be_bytes().iter().enumerate() {
            nonce[i + (aead::NONCE_LEN - u64::BITS as usize / 8)] ^= byte;
        }
        nonce
    }
}

impl aead::NonceSequence for NonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, ring::error::Unspecified> {
        let nonce = Self::xor(&self.base, self.counter);
        self.counter += 1;
        Ok(aead::Nonce::assume_unique_for_key(nonce))
    }
}

// TODO: use `secrecy` and `zeroize` to secure the secrets
pub struct SessionSecrets {
    // NOTE: kept for potential key generations
    pseudorandom_key: Box<hkdf::Prk>,
    send_key: Box<aead::SealingKey<NonceSequence>>,
    recv_key: Box<aead::OpeningKey<NonceSequence>>,
}

impl SessionSecrets {
    pub(super) fn new(
        pseudorandom_key: Box<hkdf::Prk>,
        send_key: Box<aead::UnboundKey>,
        recv_key: Box<aead::UnboundKey>,
        nonce_base: [u8; aead::NONCE_LEN],
    ) -> Self {
        Self {
            pseudorandom_key,
            send_key: Box::new(aead::SealingKey::<NonceSequence>::new(
                *send_key,
                NonceSequence::new(&nonce_base),
            )),
            recv_key: Box::new(aead::OpeningKey::<NonceSequence>::new(
                *recv_key,
                NonceSequence::new(&nonce_base),
            )),
        }
    }
    
    pub(crate) fn pseudorandom_key(&self) -> &hkdf::Prk {
        &self.pseudorandom_key
    }

    pub(crate) fn send_key(&mut self) -> &mut aead::SealingKey<NonceSequence> {
        &mut self.send_key
    }

    pub(crate) fn recv_key(&mut self) -> &mut aead::OpeningKey<NonceSequence> {
        &mut self.recv_key
    }
}

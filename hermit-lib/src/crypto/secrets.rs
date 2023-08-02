use ring::aead::{self, BoundKey};
use ring::hkdf;

use crate::error;
use crate::proto::message::{Message, PlainMessageType, TAG_LEN};

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
    sealing_key: Box<aead::SealingKey<NonceSequence>>,
    opening_key: Box<aead::OpeningKey<NonceSequence>>,
}

impl SessionSecrets {
    pub(super) fn new(
        pseudorandom_key: Box<hkdf::Prk>,
        sealing_key: Box<aead::UnboundKey>,
        opening_key: Box<aead::UnboundKey>,
        nonce_base: [u8; aead::NONCE_LEN],
    ) -> Self {
        Self {
            pseudorandom_key,
            sealing_key: Box::new(aead::SealingKey::<NonceSequence>::new(
                *sealing_key,
                NonceSequence::new(&nonce_base),
            )),
            opening_key: Box::new(aead::OpeningKey::<NonceSequence>::new(
                *opening_key,
                NonceSequence::new(&nonce_base),
            )),
        }
    }

    pub(crate) fn pseudorandom_key(&self) -> &hkdf::Prk {
        &self.pseudorandom_key
    }

    pub(crate) fn seal(&mut self, mut payload: Box<[u8]>) -> Result<Message, error::CryptoError> {
        let len = payload.len();
        let tag = self
            .sealing_key
            .seal_in_place_separate_tag(aead::Aad::empty(), payload[..len - TAG_LEN].as_mut())?;
        payload[len - TAG_LEN..].copy_from_slice(tag.as_ref());
        Ok(Message::new(PlainMessageType::Secure, payload))
    }
    pub(crate) fn open(&mut self, mut message: Message) -> Result<Box<[u8]>, error::CryptoError> {
        self.opening_key
            .open_in_place(aead::Aad::empty(), message.as_mut())?;
        Ok(message.into())
    }
}

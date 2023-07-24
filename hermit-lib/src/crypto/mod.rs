use std::sync::OnceLock;

use crate::{error, proto};
use async_std::task;
use ring::{aead, agreement, hkdf, rand, signature};

pub(crate) const NONCE_LEN: usize = 16;
pub(crate) const ED25519_SIGNATURE_LEN: usize = 64;
pub(crate) const X25519_PUBLIC_KEY_LEN: usize = 32;
pub(crate) const SIGNED_CONTENT_LEN: usize = 2 * NONCE_LEN + X25519_PUBLIC_KEY_LEN;
pub(crate) const AEAD_KEY_LEN: usize = 16;

static SYSTEM_RANDOM: OnceLock<rand::SystemRandom> = OnceLock::new();

pub(crate) async fn generate_nonce() -> Result<[u8; NONCE_LEN], error::CryptoError> {
    // NOTE: Use spawn_blocking to avoid blocking the async runtime
    // SEE: https://docs.rs/ring/latest/ring/rand/struct.SystemRandom.html
    task::spawn_blocking(|| {
        let rng = SYSTEM_RANDOM.get_or_init(rand::SystemRandom::new);
        let mut nonce = [0u8; NONCE_LEN];
        rand::SecureRandom::fill(rng, &mut nonce)?;
        Ok(nonce)
    })
    .await
}

pub(crate) fn generate_ephemeral_key_pair(
) -> Result<(agreement::EphemeralPrivateKey, agreement::PublicKey), error::CryptoError> {
    let rng = SYSTEM_RANDOM.get_or_init(rand::SystemRandom::new);
    let private_key = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng)?;
    let public_key = private_key.compute_public_key()?;
    Ok((private_key, public_key))
}

pub(crate) fn generate_signature_key_pair() -> Result<signature::Ed25519KeyPair, error::CryptoError>{
    let rng = SYSTEM_RANDOM.get_or_init(rand::SystemRandom::new);
    let sig_document = signature::Ed25519KeyPair::generate_pkcs8(rng)?;
    Ok(signature::Ed25519KeyPair::from_pkcs8(sig_document.as_ref())?)
}

pub(crate) fn verify_server_hello(
    proto::ServerHelloMessage {
        header: _,
        nonce: server_nonce,
        public_key_bytes: server_public_key_bytes,
        signature,
    }: proto::ServerHelloMessage,
    client_nonce: [u8; NONCE_LEN],
    server_sig_pub_key: &signature::UnparsedPublicKey<Vec<u8>>,
) -> Result<(agreement::UnparsedPublicKey<[u8; 32]>, [u8; 2 * NONCE_LEN]), error::CryptoError> {
    // LAYOUT: client_nonce || server_nonce || server_public_key
    let mut message = [0u8; SIGNED_CONTENT_LEN];
    message[..NONCE_LEN].copy_from_slice(&client_nonce);
    message[NONCE_LEN..2 * NONCE_LEN].copy_from_slice(&server_nonce);
    message[2 * NONCE_LEN..].copy_from_slice(&server_public_key_bytes);

    server_sig_pub_key
        .verify(&message, &signature)
        .map_err(|_| error::CryptoError::BadServerHelloSignature)?;

    Ok((
        agreement::UnparsedPublicKey::new(&agreement::X25519, server_public_key_bytes),
        <[u8; 2 * NONCE_LEN]>::try_from(&message[..2 * NONCE_LEN]).unwrap(),
    ))
}

pub(crate) fn generate_pseudorandom_key(
    client_private_key: agreement::EphemeralPrivateKey,
    server_public_key: agreement::UnparsedPublicKey<[u8; X25519_PUBLIC_KEY_LEN]>,
    // NOTE: nonces === client_nonce || server_nonce
    nonces: &[u8; 2 * NONCE_LEN],
) -> Result<hkdf::Prk, error::CryptoError> {
    agreement::agree_ephemeral(
        client_private_key,
        &server_public_key,
        error::CryptoError::BadServerPublicKey,
        |key_material| {
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, nonces);
            Ok(salt.extract(key_material))
        },
    )
}

pub(crate) fn generate_master_key(prk: &hkdf::Prk) -> Box<aead::UnboundKey> {
    let mut bytes = [0u8; AEAD_KEY_LEN];
    // SAFETY: len is not too large
    let okm = prk.expand(&[b"master key"], &aead::AES_128_GCM).unwrap();
    // SAFETY: bytes is the correct length
    okm.fill(&mut bytes).unwrap();
    // SAFETY: bytes is the correct length
    Box::new(aead::UnboundKey::new(&aead::AES_128_GCM, &bytes).unwrap())
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_generate_nonce() {
        task::block_on(async {
            assert_ne!(generate_nonce().await.unwrap(), [0u8; NONCE_LEN]);
        });
    }

    #[test]
    fn test_aead_key_len() {
        assert_eq!(AEAD_KEY_LEN, aead::AES_128_GCM.key_len());
    }
}

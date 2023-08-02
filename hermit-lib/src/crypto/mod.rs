pub mod secrets;

use std::sync::OnceLock;

use async_std::task;
use ring::{aead, agreement, digest, hkdf, rand, signature};

use crate::{
    error,
    proto::{self, message},
};

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

pub(crate) fn generate_signature_key_pair() -> Result<signature::Ed25519KeyPair, error::CryptoError>
{
    let rng = SYSTEM_RANDOM.get_or_init(rand::SystemRandom::new);
    let sig_document = signature::Ed25519KeyPair::generate_pkcs8(rng)?;
    Ok(signature::Ed25519KeyPair::from_pkcs8(
        sig_document.as_ref(),
    )?)
}

pub(crate) fn verify_server_hello(
    message::ServerHelloMessage {
        nonce: server_nonce,
        public_key_bytes: server_public_key_bytes,
        signature,
    }: message::ServerHelloMessage,
    client_nonce: [u8; NONCE_LEN],
    server_sig_pub_key: &signature::UnparsedPublicKey<impl AsRef<[u8]>>,
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

fn generate_pseudorandom_key(
    own_private_key: agreement::EphemeralPrivateKey,
    other_public_key: agreement::UnparsedPublicKey<[u8; X25519_PUBLIC_KEY_LEN]>,
    nonces: &[u8; 2 * NONCE_LEN],
) -> Result<Box<hkdf::Prk>, error::CryptoError> {
    agreement::agree_ephemeral(
        own_private_key,
        &other_public_key,
        error::CryptoError::BadServerPublicKey,
        |key_material| {
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, nonces);
            Ok(salt.extract(key_material))
        },
    )
    .map(Box::new)
}

fn generate_master_key(prk: &hkdf::Prk, sender: &'static [u8]) -> Box<aead::UnboundKey> {
    let mut master_key = [0u8; AEAD_KEY_LEN];
    let info = [sender, b"master key"];
    // SAFETY: len is not too large
    let okm = prk.expand(&info, &aead::AES_128_GCM).unwrap();
    // SAFETY: bytes is the correct length
    okm.fill(&mut master_key).unwrap();
    // SAFETY: bytes is the correct length
    Box::new(aead::UnboundKey::new(&aead::AES_128_GCM, &master_key).unwrap())
}

// NOTE: here `aead::NONCE_LEN` is 12
fn generate_nonce_base(nonces: &[u8; 2 * NONCE_LEN]) -> [u8; aead::NONCE_LEN] {
    // SAFETY: output has the correct length
    digest::digest(&digest::SHA256, nonces).as_ref()[..aead::NONCE_LEN]
        .try_into()
        .unwrap()
}

pub(crate) async fn generate_session_secrets(
    own_private_key: agreement::EphemeralPrivateKey,
    other_public_key: agreement::UnparsedPublicKey<[u8; X25519_PUBLIC_KEY_LEN]>,
    // NOTE: nonces === client_nonce || server_nonce
    nonces: &[u8; 2 * NONCE_LEN],
    // NOTE: whether
    own_side: proto::Side,
) -> Result<secrets::SessionSecrets, error::CryptoError> {
    let (send_side_bytes, recv_side_bytes) = match own_side {
        proto::Side::Client => (b"client", b"server"),
        proto::Side::Server => (b"server", b"client"),
    };

    let nonces_copy = *nonces;

    task::spawn_blocking(move || {
        let prk = generate_pseudorandom_key(own_private_key, other_public_key, &nonces_copy)?;
        let send_key = generate_master_key(&prk, send_side_bytes);
        let recv_key = generate_master_key(&prk, recv_side_bytes);
        let nonce_base = generate_nonce_base(&nonces_copy);

        Ok(secrets::SessionSecrets::new(
            prk, send_key, recv_key, nonce_base,
        ))
    })
    .await
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

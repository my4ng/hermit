use ring::signature;

pub struct ServerSigPubKey(signature::UnparsedPublicKey<Box<[u8]>>);

impl ServerSigPubKey {
    pub fn new<T: Into<Box<[u8]>>>(sig_pub_key: T) -> ServerSigPubKey {
        ServerSigPubKey(signature::UnparsedPublicKey::new(
            &signature::ED25519,
            sig_pub_key.into(),
        ))
    }
}

impl AsRef<signature::UnparsedPublicKey<Box<[u8]>>> for ServerSigPubKey {
    fn as_ref(&self) -> &signature::UnparsedPublicKey<Box<[u8]>> {
        &self.0
    }
}

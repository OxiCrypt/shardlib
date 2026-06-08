#[warn(clippy::pedantic)]
#[allow(clippy::missing_errors_doc)]
mod shamir;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce, aead::AeadMut};
use rand::random;
pub use shamir::ShamirError;
pub use shamir::Shares;
pub use shamir::shamir_split;
use std::num::NonZero;
pub use zeroize::Zeroizing;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use shamir::reconstruct_secret_mod;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ShardEncrypted {
    bytes: Vec<u8>,
    shares: Shares,
    nonce: [u8; 24],
}
impl ShardEncrypted {
    pub fn data_as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    pub fn shares(&self) -> &Shares {
        &self.shares
    }
    pub fn nonce_as_slice(&self) -> &[u8] {
        self.nonce.as_slice()
    }
}
/// Errors. ObviousContradiction is impossible, and EncryptionError is opaque
pub enum Error {
    Shamir(ShamirError),
    ObviousContradiction,
    EncryptionError,
    DecryptionError,
}
impl From<ShamirError> for Error {
    fn from(value: ShamirError) -> Self {
        Self::Shamir(value)
    }
}
pub fn encrypt_bytes(
    bytes: &[u8],
    threshold: NonZero<u8>,
    num_shares_out: NonZero<u8>,
) -> Result<ShardEncrypted, Error> {
    let mut result: ShardEncrypted;
    let keyfile: Zeroizing<[u8; 32]> = Zeroizing::new(random());
    result = ShardEncrypted {
        shares: shamir_split(threshold, num_shares_out, &keyfile)?,
        bytes: Vec::new(),
        nonce: [0u8; 24],
    };
    let mut cipher = XChaCha20Poly1305::new(Key::from_slice(keyfile.as_slice()));
    let nonce: [u8; 24] = random();
    result.bytes = cipher
        .encrypt(XNonce::from_slice(&nonce), bytes)
        .map_err(|_| Error::EncryptionError)?;
    result.nonce = nonce;
    Ok(result)
}
pub fn decrypt_bytes(
    bytes: &[u8],
    threshold: NonZero<u8>,
    shares: &Shares,
    nonce: &[u8; 24],
) -> Result<Vec<u8>, Error> {
    let key: Zeroizing<[u8; 32]> = reconstruct_secret_mod(shares, threshold)?;
    let mut cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_slice()));
    cipher
        .decrypt(XNonce::from_slice(nonce), bytes)
        .map_err(|_| Error::DecryptionError)
}

//! Encryption for secrets stored at rest (upstream credentials).
//!
//! `XChaCha20Poly1305` with a 256-bit key loaded from the `SCONCE_SECRET_KEY`
//! environment variable (base64 of 32 bytes). The 192-bit nonce is random per
//! message — safe without nonce-reuse bookkeeping — and is stored as a prefix:
//! the on-disk blob is `nonce(24) || ciphertext+tag`.

use base64::Engine as _;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

const NONCE_LEN: usize = 24;
const ENV_KEY: &str = "SCONCE_SECRET_KEY";

/// A loaded encryption key.
#[derive(Clone)]
pub struct SecretKey(XChaCha20Poly1305);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// Errors loading a key or encrypting/decrypting.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("{ENV_KEY} is not set (required to store/use upstream credentials)")]
    NoKey,
    #[error("{ENV_KEY} must be base64 of exactly 32 bytes")]
    BadKey,
    #[error("ciphertext is malformed or was not encrypted with this key")]
    Decrypt,
}

impl SecretKey {
    /// Load the key from `SCONCE_SECRET_KEY` (base64 of 32 bytes).
    pub fn from_env() -> Result<Self, SecretError> {
        let raw = std::env::var(ENV_KEY).map_err(|_| SecretError::NoKey)?;
        Self::from_base64(raw.trim())
    }

    /// Load the key from a base64 string of 32 bytes.
    pub fn from_base64(b64: &str) -> Result<Self, SecretError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|_| SecretError::BadKey)?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| SecretError::BadKey)?;
        Ok(Self(XChaCha20Poly1305::new(&key.into())))
    }

    /// Encrypt `plaintext`, returning `nonce(24) || ciphertext`.
    ///
    /// # Panics
    /// Never in practice — AEAD encryption only fails for input sizes far larger
    /// than any credential we store.
    #[must_use]
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce_bytes = random_nonce();
        let nonce = XNonce::from_slice(&nonce_bytes);
        // Encryption only fails on absurd input sizes we never produce.
        let ciphertext = self
            .0
            .encrypt(nonce, plaintext)
            .expect("XChaCha20Poly1305 encryption");
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// Decrypt a `nonce(24) || ciphertext` blob produced by [`Self::encrypt`].
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, SecretError> {
        if data.len() < NONCE_LEN {
            return Err(SecretError::Decrypt);
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let nonce = XNonce::from_slice(nonce_bytes);
        self.0
            .decrypt(nonce, ciphertext)
            .map_err(|_| SecretError::Decrypt)
    }
}

/// 24 random bytes from the OS CSPRNG (via v4 UUIDs, which are getrandom-backed).
fn random_nonce() -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    n[16..].copy_from_slice(&uuid::Uuid::new_v4().as_bytes()[..NONCE_LEN - 16]);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SecretKey {
        SecretKey::from_base64(&base64::engine::general_purpose::STANDARD.encode([7u8; 32])).unwrap()
    }

    #[test]
    fn round_trips() {
        let key = test_key();
        let ct = key.encrypt(b"oauth2:glpat-secret");
        assert_ne!(&ct[24..], b"oauth2:glpat-secret", "ciphertext is not plaintext");
        assert_eq!(key.decrypt(&ct).unwrap(), b"oauth2:glpat-secret");
    }

    #[test]
    fn nonce_is_random_so_ciphertexts_differ() {
        let key = test_key();
        assert_ne!(key.encrypt(b"same"), key.encrypt(b"same"));
    }

    #[test]
    fn wrong_key_fails() {
        let a = test_key();
        let b = SecretKey::from_base64(&base64::engine::general_purpose::STANDARD.encode([9u8; 32]))
            .unwrap();
        let ct = a.encrypt(b"secret");
        assert!(matches!(b.decrypt(&ct), Err(SecretError::Decrypt)));
    }

    #[test]
    fn bad_key_rejected() {
        assert!(matches!(
            SecretKey::from_base64("not-base64!!"),
            Err(SecretError::BadKey)
        ));
        assert!(matches!(
            SecretKey::from_base64(&base64::engine::general_purpose::STANDARD.encode([0u8; 16])),
            Err(SecretError::BadKey)
        ));
    }
}

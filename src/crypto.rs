use crate::error::MacaroonError;
use crate::Result;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng},
    XChaCha20Poly1305, XNonce,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::borrow::Borrow;
use std::ops::{Deref, DerefMut};

/// Key size in bytes (256-bit symmetric key).
pub const KEY_BYTES: usize = 32;
/// Nonce size for XChaCha20-Poly1305 (192-bit nonce).
const NONCE_BYTES: usize = 24;
/// Authentication tag size for Poly1305 (128-bit tag).
const MAC_BYTES: usize = 16;

type HmacSha256 = Hmac<Sha256>;

const KEY_GENERATOR: MacaroonKey = MacaroonKey(*b"macaroons-key-generator\0\0\0\0\0\0\0\0\0");

// -----------------------------------------------------------------------------
// MacaroonKey
// -----------------------------------------------------------------------------

/// A 256-bit cryptographic key used throughout the macaroon system.
///
/// This type wraps a fixed-size byte array and is used for:
/// - Root keys that authenticate macaroon creation
/// - Derived keys produced by HMAC chaining during caveat addition
/// - Encryption keys for third-party caveat verifier IDs
///
/// In a DecMed access-control context, the root key is the secret that
/// authorises a particular macaroon token for a patient record or data category.
///
/// # Security
///
/// The `Debug` trait implementation **redacts** all key material to prevent
/// accidental exposure in logs or error messages.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacaroonKey([u8; KEY_BYTES]);

impl std::fmt::Debug for MacaroonKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MacaroonKey(***REDACTED***)")
    }
}

impl AsRef<[u8; KEY_BYTES]> for MacaroonKey {
    fn as_ref(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl AsRef<[u8]> for MacaroonKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Borrow<[u8]> for MacaroonKey {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for MacaroonKey {
    type Target = [u8; KEY_BYTES];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MacaroonKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<[u8; KEY_BYTES]> for MacaroonKey {
    fn from(bytes: [u8; KEY_BYTES]) -> Self {
        MacaroonKey(bytes)
    }
}

impl From<&[u8; KEY_BYTES]> for MacaroonKey {
    fn from(bytes: &[u8; KEY_BYTES]) -> Self {
        MacaroonKey(*bytes)
    }
}

impl TryFrom<&[u8]> for MacaroonKey {
    type Error = MacaroonError;

    fn try_from(slice: &[u8]) -> Result<Self> {
        let bytes: [u8; KEY_BYTES] = slice
            .try_into()
            .map_err(|_| MacaroonError::CryptoError("key must be exactly 32 bytes"))?;
        Ok(MacaroonKey(bytes))
    }
}

impl MacaroonKey {
    /// Creates a new random key using the operating-system CSPRNG.
    ///
    /// Use this when you need a fresh, unpredictable root key — for example,
    /// when issuing a brand-new macaroon for a patient record.
    ///
    /// # Panics
    ///
    /// This function will panic if the OS random number generator is
    /// unavailable, which is exceedingly rare on supported platforms.
    pub fn generate_random() -> Self {
        let mut bytes = [0u8; KEY_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        MacaroonKey(bytes)
    }

    /// Creates a deterministic key by computing `HMAC-SHA256(generator, seed)`.
    ///
    /// The same `seed` always produces the same key, which is useful for
    /// deriving keys from passwords, shared secrets, or other reproducible
    /// inputs.
    ///
    /// # Arguments
    ///
    /// * `seed` — Arbitrary byte slice used as the HMAC message.
    ///
    /// # Example
    ///
    /// ```rust
    /// use macaroon::MacaroonKey;
    /// let key1 = MacaroonKey::generate(b"my-seed");
    /// let key2 = MacaroonKey::generate(b"my-seed");
    /// assert_eq!(key1, key2);
    /// ```
    pub fn generate(seed: &[u8]) -> Self {
        generate_derived_key(seed)
    }

    /// Derives a deterministic key from an IOTA address string.
    ///
    /// This is a convenience wrapper around [`MacaroonKey::generate`] that
    /// uses the UTF-8 bytes of the IOTA address as the seed. Because the
    /// derivation is deterministic, both the token issuer and verifier can
    /// independently compute the same key from the same on-chain address.
    ///
    /// # Arguments
    ///
    /// * `address` — An IOTA address string (e.g. `"iota1qp…"`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use macaroon::MacaroonKey;
    /// let key = MacaroonKey::from_iota_address("iota1qpexample123");
    /// // Same address always yields the same key
    /// assert_eq!(key, MacaroonKey::from_iota_address("iota1qpexample123"));
    /// ```
    pub fn from_iota_address(address: &str) -> Self {
        MacaroonKey::generate(address.as_bytes())
    }
}

// -----------------------------------------------------------------------------
// Derived key
// -----------------------------------------------------------------------------

fn generate_derived_key(key: &[u8]) -> MacaroonKey {
    hmac(&KEY_GENERATOR, key)
}

// -----------------------------------------------------------------------------
// HMAC functions
// -----------------------------------------------------------------------------

/// Computes `HMAC-SHA256(key, text)` and returns the result as a [`MacaroonKey`].
///
/// This is the core chaining primitive in the macaroon protocol: each caveat
/// extends the signature by computing `HMAC(previous_sig, caveat_data)`.
///
/// # Arguments
///
/// * `key`  — The HMAC key (any type that dereferences to `[u8]`).
/// * `text` — The message to authenticate.
pub fn hmac<T, U>(key: &T, text: &U) -> MacaroonKey
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key.as_ref()).expect("HMAC accepts any key size");
    mac.update(text.as_ref());
    let result = mac.finalize().into_bytes();

    let mut bytes = [0u8; KEY_BYTES];
    bytes.copy_from_slice(&result);
    MacaroonKey(bytes)
}

/// Computes `HMAC-SHA256(key, HMAC(key,text1) || HMAC(key,text2))`.
///
/// This "double-HMAC" is used when signing third-party caveats, where both
/// the verifier-ID and the caveat-ID must contribute to the new signature.
///
/// # Arguments
///
/// * `key`   — The HMAC key.
/// * `text1` — First message (typically the verifier ID).
/// * `text2` — Second message (typically the caveat ID).
pub fn hmac2<T, U>(key: &T, text1: &U, text2: &U) -> MacaroonKey
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    let MacaroonKey(tmp1) = hmac(key, text1);
    let MacaroonKey(tmp2) = hmac(key, text2);
    let combined = [tmp1, tmp2].concat();
    hmac(key, &combined)
}

// -----------------------------------------------------------------------------
// Encryption / Decryption (XChaCha20-Poly1305)
// -----------------------------------------------------------------------------

/// Encrypts a key using XChaCha20-Poly1305.
///
/// The output format is `nonce (24 bytes) || ciphertext+tag (N + 16 bytes)`.
/// This is used internally to encrypt the third-party caveat key so that it
/// can be embedded in the macaroon as the "verifier ID".
///
/// # Arguments
///
/// * `key`       — The 256-bit encryption key (typically the current macaroon signature).
/// * `plaintext` — The 256-bit key to encrypt (typically the third-party caveat key).
///
/// # Errors
///
/// Returns `MacaroonError::CryptoError` if encryption fails.
pub fn encrypt_key<T>(key: &T, plaintext: &T) -> Result<Vec<u8>>
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
{
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).expect("key length is always 32 bytes");

    let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);

    let encrypted = cipher
        .encrypt(&nonce, plaintext.as_ref() as &[u8])
        .map_err(|_| MacaroonError::CryptoError("encryption failed"))?;

    let mut result = Vec::with_capacity(NONCE_BYTES + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend(encrypted);
    Ok(result)
}

/// Decrypts data produced by [`encrypt_key`].
///
/// Expects the format `nonce (24 bytes) || ciphertext+tag`. Returns the
/// decrypted key on success.
///
/// # Arguments
///
/// * `key`  — The 256-bit decryption key (must match the key used for encryption).
/// * `data` — The nonce-prefixed ciphertext.
///
/// # Errors
///
/// Returns `MacaroonError::CryptoError` if:
/// - The data is too short to contain a nonce and tag.
/// - Decryption fails (wrong key, tampered ciphertext).
/// - The decrypted plaintext is not exactly 32 bytes.
pub fn decrypt_key<T, U>(key: &T, data: &U) -> Result<MacaroonKey>
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    let raw_data: &[u8] = data.as_ref();

    // Minimal length: nonce (24) + tag (16) + at least 1 byte of plaintext
    if raw_data.len() <= NONCE_BYTES + MAC_BYTES {
        error!(
            "crypto::decrypt: encrypted data too short ({} bytes)",
            raw_data.len()
        );
        return Err(MacaroonError::CryptoError("encrypted data too short"));
    }

    let (nonce_bytes, ciphertext) = raw_data.split_at(NONCE_BYTES);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).expect("key length is always 32 bytes");

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => MacaroonKey::try_from(plaintext.as_slice()).map_err(|_| {
            MacaroonError::CryptoError("decrypted data has wrong length (expected 32 bytes)")
        }),
        Err(_) => {
            error!("crypto::decrypt: decryption failed (wrong key or tampered ciphertext)");
            Err(MacaroonError::CryptoError("failed to decrypt ciphertext"))
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = MacaroonKey::generate_random();
        let plaintext = MacaroonKey::generate_random();

        let encrypted = encrypt_key(&key, &plaintext).unwrap();
        let decrypted = decrypt_key(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = MacaroonKey::generate_random();
        let wrong_key = MacaroonKey::generate_random();
        let plaintext = MacaroonKey::generate_random();

        let encrypted = encrypt_key(&key, &plaintext).unwrap();
        let result = decrypt_key(&wrong_key, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short_fails() {
        let key = MacaroonKey::generate_random();
        let short_data = vec![0u8; 10];

        let result = decrypt_key(&key, &short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_truncated_ciphertext_fails() {
        let key = MacaroonKey::generate_random();
        let plaintext = MacaroonKey::generate_random();

        let encrypted = encrypt_key(&key, &plaintext).unwrap();
        // Truncate: keep nonce but chop most of the ciphertext
        let truncated = &encrypted[..NONCE_BYTES + MAC_BYTES + 1];
        assert!(decrypt_key(&key, truncated).is_err());
    }

    #[test]
    fn test_decrypt_empty_data_fails() {
        let key = MacaroonKey::generate_random();
        let empty: Vec<u8> = vec![];
        assert!(decrypt_key(&key, &empty).is_err());
    }

    #[test]
    fn test_hmac_deterministic() {
        let key = MacaroonKey::generate_random();
        let text = b"test caveat";

        let result1 = hmac(&key, text);
        let result2 = hmac(&key, text);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_generate_seed_deterministic() {
        let seed = b"same seed always same key";
        let key1 = MacaroonKey::generate(seed);
        let key2 = MacaroonKey::generate(seed);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_macaroon_key_debug_redacted() {
        let key = MacaroonKey::generate_random();
        let debug_str = format!("{:?}", key);

        // Ensure raw bytes do not appear in debug output
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("MacaroonKey(["));
    }

    #[test]
    fn test_key_from_iota_address() {
        let addr = "iota1qpexample123";
        let key1 = MacaroonKey::from_iota_address(addr);
        let key2 = MacaroonKey::from_iota_address(addr);
        assert_eq!(key1, key2);

        // Different address produces a different key
        let key3 = MacaroonKey::from_iota_address("iota1qpdifferent456");
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_key_from_array() {
        let bytes = [42u8; KEY_BYTES];
        let key = MacaroonKey::from(bytes);
        assert_eq!(*key, bytes);
    }

    #[test]
    fn test_key_try_from_slice() {
        let bytes = vec![7u8; KEY_BYTES];
        let key = MacaroonKey::try_from(bytes.as_slice()).unwrap();
        assert_eq!(*key, [7u8; KEY_BYTES]);

        // Wrong length should fail
        let short = vec![0u8; 16];
        assert!(MacaroonKey::try_from(short.as_slice()).is_err());
    }
}

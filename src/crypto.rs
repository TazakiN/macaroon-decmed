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

// Ukuran key: 32 bytes (sama dengan sodiumoxide KEYBYTES)
pub const KEY_BYTES: usize = 32;
// Ukuran nonce XChaCha20: 24 bytes (sama dengan sodiumoxide NONCEBYTES)
const NONCE_BYTES: usize = 24;
// Ukuran MAC tag Poly1305: 16 bytes (sama dengan sodiumoxide MACBYTES)
const MAC_BYTES: usize = 16;

type HmacSha256 = Hmac<Sha256>;

const KEY_GENERATOR: MacaroonKey =
    MacaroonKey(*b"macaroons-key-generator\0\0\0\0\0\0\0\0\0");

// -----------------------------------------------------------------------------
// MacaroonKey
// -----------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacaroonKey([u8; KEY_BYTES]);

// Debug sengaja disembunyikan agar key tidak bocor ke log
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
    /// Membuat key acak menggunakan OS RNG.
    /// PERINGATAN: Debug trait tidak akan menampilkan isi key (sudah diredact).
    pub fn generate_random() -> Self {
        let mut bytes = [0u8; KEY_BYTES];
        rand::thread_rng().fill_bytes(&mut bytes);
        MacaroonKey(bytes)
    }

    /// Membuat key deterministik dari seed menggunakan HMAC-SHA256.
    /// Seed yang sama selalu menghasilkan key yang sama.
    pub fn generate(seed: &[u8]) -> Self {
        generate_derived_key(seed)
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

/// Hitung HMAC-SHA256(key, text), hasilnya dijadikan MacaroonKey baru.
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

/// Hitung HMAC-SHA256(key, text1 || text2) dengan cara:
/// tmp1 = HMAC(key, text1)
/// tmp2 = HMAC(key, text2)
/// result = HMAC(key, tmp1 || tmp2)
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

/// Enkripsi plaintext menggunakan XChaCha20-Poly1305.
/// Output format: [nonce (24 bytes)] + [ciphertext + tag (N + 16 bytes)]
pub fn encrypt_key<T>(key: &T, plaintext: &T) -> Vec<u8>
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
{
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .expect("key length sudah pasti 32 bytes");

    let nonce = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);

    let encrypted = cipher
        .encrypt(&nonce, plaintext.as_ref() as &[u8])
        .expect("enkripsi tidak boleh gagal dengan input valid");

    let mut result = Vec::with_capacity(NONCE_BYTES + encrypted.len());
    result.extend_from_slice(&nonce);
    result.extend(encrypted);
    result
}

/// Dekripsi data yang dibuat oleh `encrypt_key`.
/// Mengharapkan format: [nonce (24 bytes)] + [ciphertext + tag]
pub fn decrypt_key<T, U>(key: &T, data: &U) -> Result<MacaroonKey>
where
    T: AsRef<[u8; KEY_BYTES]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    let raw_data: &[u8] = data.as_ref();

    // Minimal length: nonce (24) + tag (16) + setidaknya 1 byte plaintext
    if raw_data.len() <= NONCE_BYTES + MAC_BYTES {
        error!(
            "crypto::decrypt: Encrypted data {:?} too short",
            raw_data
        );
        return Err(MacaroonError::CryptoError("encrypted data too short"));
    }

    let (nonce_bytes, ciphertext) = raw_data.split_at(NONCE_BYTES);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .expect("key length sudah pasti 32 bytes");

    match cipher.decrypt(nonce, ciphertext) {
        Ok(plaintext) => {
            MacaroonKey::try_from(plaintext.as_slice())
                .map_err(|_| MacaroonError::CryptoError(
                    "decrypted data has wrong length (expected 32 bytes)"
                ))
        }
        Err(_) => {
            error!(
                "crypto::decrypt: Decryption failed for data {:?}",
                raw_data
            );
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

        let encrypted = encrypt_key(&key, &plaintext);
        let decrypted = decrypt_key(&key, &encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key = MacaroonKey::generate_random();
        let wrong_key = MacaroonKey::generate_random();
        let plaintext = MacaroonKey::generate_random();

        let encrypted = encrypt_key(&key, &plaintext);
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

        // Pastikan bytes asli tidak muncul di debug output
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("MacaroonKey(["));
    }
}
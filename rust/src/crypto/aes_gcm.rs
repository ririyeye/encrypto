//! AES-256-GCM encryption support.

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};

use crate::error::{Error, Result};
use crate::{AES_KEY_SIZE, IV_SIZE, TAG_SIZE};

/// AES-256-GCM cipher wrapper.
pub struct AesGcmCipher {
    cipher: Aes256Gcm,
}

impl AesGcmCipher {
    /// Create a new AES-GCM cipher with the given key.
    pub fn new(key: &[u8; AES_KEY_SIZE]) -> Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::AesGcm)?;
        Ok(Self { cipher })
    }

    /// Encrypt data in place, returning the authentication tag.
    pub fn encrypt_in_place(&self, iv: &[u8; IV_SIZE], data: &mut Vec<u8>) -> Result<[u8; TAG_SIZE]> {
        let nonce = Nonce::from_slice(iv);
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, &[], data)
            .map_err(|_| Error::AesGcm)?;
        let mut tag_bytes = [0u8; TAG_SIZE];
        tag_bytes.copy_from_slice(&tag);
        Ok(tag_bytes)
    }

    /// Decrypt data in place, verifying the authentication tag.
    pub fn decrypt_in_place(
        &self,
        iv: &[u8],
        data: &mut Vec<u8>,
        tag: &[u8],
    ) -> Result<()> {
        let nonce = Nonce::from_slice(iv);
        let tag = Tag::from_slice(tag);
        self.cipher
            .decrypt_in_place_detached(nonce, &[], data, tag)
            .map_err(|_| Error::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let mut rng = rand::rngs::OsRng;

        let mut key = [0u8; AES_KEY_SIZE];
        let mut iv = [0u8; IV_SIZE];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);

        let cipher = AesGcmCipher::new(&key).unwrap();
        let original = b"Hello, AES-GCM!".to_vec();
        let mut data = original.clone();

        let tag = cipher.encrypt_in_place(&iv, &mut data).unwrap();
        assert_ne!(data, original);

        cipher
            .decrypt_in_place(&iv, &mut data, &tag)
            .unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_aes_gcm_tamper_detection() {
        let mut rng = rand::rngs::OsRng;

        let mut key = [0u8; AES_KEY_SIZE];
        let mut iv = [0u8; IV_SIZE];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);

        let cipher = AesGcmCipher::new(&key).unwrap();
        let mut data = b"Hello, AES-GCM!".to_vec();

        let tag = cipher.encrypt_in_place(&iv, &mut data).unwrap();

        // Tamper with ciphertext
        data[0] ^= 0xFF;

        let result = cipher.decrypt_in_place(&iv, &mut data, &tag);
        assert!(result.is_err());
    }
}

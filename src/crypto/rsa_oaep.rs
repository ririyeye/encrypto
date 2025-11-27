//! RSA-OAEP encryption support.

use rand::{CryptoRng, RngCore};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use crate::error::{Error, Result};

/// Encrypt data with RSA-OAEP using SHA-256.
pub fn encrypt<R: RngCore + CryptoRng>(
    public_key: &RsaPublicKey,
    data: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let padding = Oaep::new::<Sha256>();
    public_key
        .encrypt(rng, padding, data)
        .map_err(Error::Rsa)
}

/// Decrypt data with RSA-OAEP using SHA-256.
pub fn decrypt<R: RngCore + CryptoRng>(
    private_key: &RsaPrivateKey,
    ciphertext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let padding = Oaep::new::<Sha256>();
    private_key
        .decrypt_blinded(rng, padding, ciphertext)
        .map_err(Error::Rsa)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_data;
    use rand::rngs::OsRng;

    #[test]
    fn test_rsa_roundtrip() {
        let public_key = key_data::public_key().unwrap();
        let private_key = key_data::private_key().unwrap();
        let mut rng = OsRng;

        let plaintext = b"Hello, RSA-OAEP!";
        let ciphertext = encrypt(&public_key, plaintext, &mut rng).unwrap();
        let decrypted = decrypt(&private_key, &ciphertext, &mut rng).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}

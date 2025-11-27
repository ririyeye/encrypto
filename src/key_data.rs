//! Key data module - provides embedded RSA keys.
//!
//! Keys are generated at build time and embedded as DER-encoded bytes.

use rsa::{pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey, RsaPrivateKey, RsaPublicKey};

use crate::error::Result;

/// Embedded RSA private key (DER format)
const PRIVATE_KEY_DER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rsa_private_key.der"));

/// Embedded RSA public key (DER format)
const PUBLIC_KEY_DER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rsa_public_key.der"));

/// Get the embedded RSA public key.
pub fn public_key() -> Result<RsaPublicKey> {
    Ok(RsaPublicKey::from_public_key_der(PUBLIC_KEY_DER)?)
}

/// Get the embedded RSA private key.
pub fn private_key() -> Result<RsaPrivateKey> {
    Ok(RsaPrivateKey::from_pkcs8_der(PRIVATE_KEY_DER)?)
}

/// Get the RSA key length in bytes (for 4096-bit keys, this is 512).
pub fn key_len() -> usize {
    // 4096 bits / 8 = 512 bytes
    512
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn test_load_public_key() {
        let key = public_key().expect("Failed to load public key");
        assert_eq!(key.size(), 512); // 4096 bits
    }

    #[test]
    fn test_load_private_key() {
        let key = private_key().expect("Failed to load private key");
        assert_eq!(key.size(), 512); // 4096 bits
    }
}

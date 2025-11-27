//! Container format definitions.
//!
//! The hybrid container format (v2) has the following structure:
//!
//! ```text
//! +---------------------------+
//! | RSA-OAEP encrypted header | (rsa_len bytes)
//! +---------------------------+
//! | RSA-OAEP encrypted key    | (rsa_len bytes)
//! +---------------------------+
//! | AES-GCM IV                | (iv_len bytes, typically 12)
//! +---------------------------+
//! | AES-GCM ciphertext        | (ct_len bytes)
//! +---------------------------+
//! | AES-GCM tag               | (tag_len bytes, typically 16)
//! +---------------------------+
//! ```
//!
//! The decrypted header (18 bytes for v2) contains:
//! - Bytes 0-3: Magic "ENHY"
//! - Byte 4: Version (2)
//! - Byte 5: Compression algorithm ID
//! - Bytes 6-7: RSA ciphertext length (big-endian u16)
//! - Byte 8: IV length
//! - Byte 9: Tag length
//! - Bytes 10-17: Ciphertext length (big-endian u64)

use crate::compression::CompressionAlgorithm;
use crate::error::{Error, Result};
use crate::{FORMAT_VERSION, IV_SIZE, MAGIC, TAG_SIZE};

/// Container header structure.
#[derive(Debug, Clone)]
pub struct ContainerHeader {
    /// Format version
    pub version: u8,
    /// Compression algorithm
    pub compression: CompressionAlgorithm,
    /// RSA ciphertext length
    pub rsa_len: u16,
    /// IV length
    pub iv_len: u8,
    /// Tag length
    pub tag_len: u8,
    /// Ciphertext length
    pub ciphertext_len: u64,
}

impl ContainerHeader {
    /// Size of v2 header in bytes.
    pub const V2_SIZE: usize = 18;

    /// Size of v1 header in bytes.
    pub const V1_SIZE: usize = 17;

    /// Create a new v2 header.
    pub fn new(compression: CompressionAlgorithm, rsa_len: u16, ciphertext_len: u64) -> Self {
        Self {
            version: FORMAT_VERSION,
            compression,
            rsa_len,
            iv_len: IV_SIZE as u8,
            tag_len: TAG_SIZE as u8,
            ciphertext_len,
        }
    }

    /// Serialize header to bytes (v2 format).
    pub fn to_bytes(&self) -> [u8; Self::V2_SIZE] {
        let mut buf = [0u8; Self::V2_SIZE];

        // Magic
        buf[0..4].copy_from_slice(MAGIC);

        // Version
        buf[4] = self.version;

        // Compression algorithm ID
        buf[5] = self.compression.id();

        // RSA length (big-endian u16)
        buf[6..8].copy_from_slice(&self.rsa_len.to_be_bytes());

        // IV length
        buf[8] = self.iv_len;

        // Tag length
        buf[9] = self.tag_len;

        // Ciphertext length (big-endian u64)
        buf[10..18].copy_from_slice(&self.ciphertext_len.to_be_bytes());

        buf
    }

    /// Parse header from decrypted bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != Self::V2_SIZE && data.len() != Self::V1_SIZE {
            return Err(Error::InvalidHeaderLength {
                expected: Self::V2_SIZE,
                got: data.len(),
            });
        }

        // Verify magic
        if &data[0..4] != MAGIC {
            return Err(Error::InvalidMagic);
        }

        let version = data[4];

        match version {
            1 => {
                // v1 format: no compression field, defaults to gzip
                if data.len() < Self::V1_SIZE {
                    return Err(Error::InvalidHeaderLength {
                        expected: Self::V1_SIZE,
                        got: data.len(),
                    });
                }

                let rsa_len = u16::from_be_bytes([data[5], data[6]]);
                let iv_len = data[7];
                let tag_len = data[8];
                let ciphertext_len = u64::from_be_bytes([
                    data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
                ]);

                Ok(Self {
                    version,
                    compression: CompressionAlgorithm::Gzip, // v1 defaults to gzip
                    rsa_len,
                    iv_len,
                    tag_len,
                    ciphertext_len,
                })
            }
            2 => {
                // v2 format: includes compression field
                if data.len() < Self::V2_SIZE {
                    return Err(Error::InvalidHeaderLength {
                        expected: Self::V2_SIZE,
                        got: data.len(),
                    });
                }

                let compression = CompressionAlgorithm::from_id(data[5])?;
                let rsa_len = u16::from_be_bytes([data[6], data[7]]);
                let iv_len = data[8];
                let tag_len = data[9];
                let ciphertext_len = u64::from_be_bytes([
                    data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17],
                ]);

                Ok(Self {
                    version,
                    compression,
                    rsa_len,
                    iv_len,
                    tag_len,
                    ciphertext_len,
                })
            }
            _ => Err(Error::UnsupportedVersion(version)),
        }
    }

    /// Validate header parameters against expected values.
    pub fn validate(&self, expected_rsa_len: usize) -> Result<()> {
        if self.rsa_len as usize != expected_rsa_len {
            return Err(Error::RsaLengthMismatch {
                expected: expected_rsa_len,
                got: self.rsa_len as usize,
            });
        }

        if self.iv_len == 0 || self.iv_len > 32 {
            return Err(Error::InvalidIvLength(self.iv_len));
        }

        if self.tag_len == 0 || self.tag_len > 32 {
            return Err(Error::InvalidTagLength(self.tag_len));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_roundtrip() {
        let header = ContainerHeader::new(CompressionAlgorithm::Zstd, 512, 1024);
        let bytes = header.to_bytes();
        let parsed = ContainerHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.compression, CompressionAlgorithm::Zstd);
        assert_eq!(parsed.rsa_len, 512);
        assert_eq!(parsed.iv_len, IV_SIZE as u8);
        assert_eq!(parsed.tag_len, TAG_SIZE as u8);
        assert_eq!(parsed.ciphertext_len, 1024);
    }

    #[test]
    fn test_invalid_magic() {
        let mut bytes = [0u8; ContainerHeader::V2_SIZE];
        bytes[0..4].copy_from_slice(b"XXXX");

        let result = ContainerHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(Error::InvalidMagic)));
    }

    #[test]
    fn test_unsupported_version() {
        let mut bytes = [0u8; ContainerHeader::V2_SIZE];
        bytes[0..4].copy_from_slice(MAGIC);
        bytes[4] = 99;

        let result = ContainerHeader::from_bytes(&bytes);
        assert!(matches!(result, Err(Error::UnsupportedVersion(99))));
    }
}

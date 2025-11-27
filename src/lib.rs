//! Encrypto - Hybrid RSA-OAEP + AES-GCM encryption library
//!
//! This crate provides hybrid encryption combining RSA-OAEP for key exchange
//! and AES-256-GCM for bulk data encryption, with support for multiple
//! compression algorithms.

pub mod compression;
pub mod crypto;
pub mod error;
pub mod format;
pub mod key_data;

pub use compression::CompressionAlgorithm;
pub use crypto::{decrypt_hybrid, encrypt_hybrid};
pub use error::{Error, Result};
pub use format::ContainerHeader;

/// Stream chunk size for encryption/decryption (64 KiB)
pub const STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// AES-256 key size (32 bytes)
pub const AES_KEY_SIZE: usize = 32;

/// AES-GCM IV size (12 bytes)
pub const IV_SIZE: usize = 12;

/// AES-GCM tag size (16 bytes)
pub const TAG_SIZE: usize = 16;

/// Container magic bytes: "ENHY"
pub const MAGIC: &[u8; 4] = b"ENHY";

/// Current container format version
pub const FORMAT_VERSION: u8 = 2;

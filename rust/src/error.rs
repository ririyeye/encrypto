//! Error types for the encrypto library.

use thiserror::Error;

/// Result type alias for encrypto operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for encryption/decryption operations.
#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("RSA PKCS8 error: {0}")]
    RsaPkcs8(#[from] rsa::pkcs8::Error),

    #[error("RSA SPKI error: {0}")]
    RsaSpki(#[from] rsa::pkcs8::spki::Error),

    #[error("AES-GCM error")]
    AesGcm,

    #[error("Invalid magic bytes")]
    InvalidMagic,

    #[error("Unsupported format version: {0}")]
    UnsupportedVersion(u8),

    #[error("Unknown compression algorithm ID: {0}")]
    UnknownCompression(u8),

    #[error("Invalid compression algorithm: {0}")]
    InvalidCompressionName(String),

    #[error("Authentication failed (tag mismatch)")]
    AuthenticationFailed,

    #[error("Invalid header length: expected {expected}, got {got}")]
    InvalidHeaderLength { expected: usize, got: usize },

    #[error("RSA ciphertext length mismatch: expected {expected}, got {got}")]
    RsaLengthMismatch { expected: usize, got: usize },

    #[error("Invalid IV length: {0}")]
    InvalidIvLength(u8),

    #[error("Invalid tag length: {0}")]
    InvalidTagLength(u8),

    #[error("Unexpected session key length: expected {expected}, got {got}")]
    UnexpectedKeyLength { expected: usize, got: usize },

    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Decompression error: {0}")]
    Decompression(String),

    #[error("Archive error: {0}")]
    Archive(String),

    #[error("Unsafe archive path: {0}")]
    UnsafeArchivePath(String),

    #[error("Deterministic RNG exhausted")]
    RngExhausted,

    #[error("Environment variable error: {0}")]
    EnvVar(String),

    #[error("Path already exists: {0}")]
    PathExists(String),

    #[error("Unsupported file type: {0}")]
    UnsupportedFileType(String),
}

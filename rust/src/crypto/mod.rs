//! Cryptographic operations for hybrid encryption.

pub mod aes_gcm;
pub mod rsa_oaep;
pub mod rng;

use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use ::aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use rand::RngCore;
use rsa::traits::PublicKeyParts;
use rsa::Oaep;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::compression::CompressionAlgorithm;
use crate::error::{Error, Result};
use crate::format::ContainerHeader;
use crate::key_data;
use crate::{AES_KEY_SIZE, IV_SIZE};

/// Encrypt data using hybrid RSA-OAEP + AES-GCM scheme.
pub fn encrypt_hybrid<R: Read, W: Write + Seek>(
    input: &mut R,
    output: &mut W,
    compression: CompressionAlgorithm,
) -> Result<()> {
    let public_key = key_data::public_key()?;
    let rsa_len = public_key.size();

    // Get RNG (deterministic for testing, or system RNG)
    let mut rng = rng::get_rng()?;

    // Generate session key and IV
    let mut session_key = Zeroizing::new([0u8; AES_KEY_SIZE]);
    let mut iv = [0u8; IV_SIZE];
    rng.fill_bytes(session_key.as_mut());
    rng.fill_bytes(&mut iv);

    // Encrypt session key with RSA-OAEP
    let padding = Oaep::new::<Sha256>();
    let encrypted_key = public_key
        .encrypt(&mut rng, padding, session_key.as_ref())
        .map_err(Error::Rsa)?;

    // Reserve space for encrypted header (will be written at the end)
    let header_pos = output.stream_position()?;
    let placeholder = vec![0u8; rsa_len];
    output.write_all(&placeholder)?;

    // Write encrypted session key
    output.write_all(&encrypted_key)?;

    // Write IV
    output.write_all(&iv)?;

    // Create AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(session_key.as_ref())
        .map_err(|_| Error::AesGcm)?;
    let nonce = Nonce::from_slice(&iv);

    // Collect and compress input data
    let mut plaintext = Vec::new();
    input.read_to_end(&mut plaintext)?;

    let compressed = compression.compress(&plaintext)?;
    drop(plaintext);

    // Encrypt with AES-GCM
    let mut ciphertext = compressed;
    let tag = cipher
        .encrypt_in_place_detached(nonce, &[], &mut ciphertext)
        .map_err(|_| Error::AesGcm)?;

    // Write ciphertext
    output.write_all(&ciphertext)?;

    // Write tag
    output.write_all(&tag)?;

    // Create and encrypt header
    let header = ContainerHeader::new(compression, rsa_len as u16, ciphertext.len() as u64);
    let header_bytes = header.to_bytes();

    let padding = Oaep::new::<Sha256>();
    let encrypted_header = public_key
        .encrypt(&mut rng, padding, &header_bytes)
        .map_err(Error::Rsa)?;

    // Write encrypted header at the beginning
    output.seek(SeekFrom::Start(header_pos))?;
    output.write_all(&encrypted_header)?;

    // Seek to end
    output.seek(SeekFrom::End(0))?;

    Ok(())
}

/// Decrypt data using hybrid RSA-OAEP + AES-GCM scheme.
pub fn decrypt_hybrid<R: Read, W: Write>(input: &mut R, output: &mut W) -> Result<()> {
    let private_key = key_data::private_key()?;
    let rsa_len = private_key.size();

    // Get RNG for RSA-OAEP blinding
    let mut rng = rng::get_rng()?;

    // Read encrypted header
    let mut encrypted_header = vec![0u8; rsa_len];
    input.read_exact(&mut encrypted_header)?;

    // Decrypt header
    let padding = Oaep::new::<Sha256>();
    let header_bytes = private_key
        .decrypt_blinded(&mut rng, padding, &encrypted_header)
        .map_err(Error::Rsa)?;

    // Parse header
    let header = ContainerHeader::from_bytes(&header_bytes)?;
    header.validate(rsa_len)?;

    // Read encrypted session key
    let mut encrypted_key = vec![0u8; rsa_len];
    input.read_exact(&mut encrypted_key)?;

    // Read IV
    let mut iv = vec![0u8; header.iv_len as usize];
    input.read_exact(&mut iv)?;

    // Decrypt session key
    let padding = Oaep::new::<Sha256>();
    let session_key_bytes = private_key
        .decrypt_blinded(&mut rng, padding, &encrypted_key)
        .map_err(Error::Rsa)?;

    if session_key_bytes.len() != AES_KEY_SIZE {
        return Err(Error::UnexpectedKeyLength {
            expected: AES_KEY_SIZE,
            got: session_key_bytes.len(),
        });
    }

    let session_key = Zeroizing::new(session_key_bytes);

    // Read ciphertext
    let mut ciphertext = vec![0u8; header.ciphertext_len as usize];
    input.read_exact(&mut ciphertext)?;

    // Read tag
    let mut tag = vec![0u8; header.tag_len as usize];
    input.read_exact(&mut tag)?;

    // Decrypt with AES-GCM
    let cipher = Aes256Gcm::new_from_slice(session_key.as_ref())
        .map_err(|_| Error::AesGcm)?;
    let nonce = Nonce::from_slice(&iv);
    let tag = Tag::from_slice(&tag);

    cipher
        .decrypt_in_place_detached(nonce, &[], &mut ciphertext, tag)
        .map_err(|_| Error::AuthenticationFailed)?;

    // Decompress
    let plaintext = header.compression.decompress(&ciphertext)?;

    // Write output
    output.write_all(&plaintext)?;

    Ok(())
}

/// Encrypt a file or directory to an output file.
pub fn encrypt_path(
    input_path: &Path,
    output_path: &Path,
    compression: CompressionAlgorithm,
) -> Result<()> {

    // Create tar archive of input
    let mut tar_data = Vec::new();
    {
        let mut tar_builder = tar::Builder::new(&mut tar_data);

        let metadata = std::fs::metadata(input_path)?;
        let file_name = input_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "data".to_string());

        if metadata.is_file() {
            tar_builder.append_path_with_name(input_path, &file_name)?;
        } else if metadata.is_dir() {
            tar_builder.append_dir_all(&file_name, input_path)?;
        } else {
            return Err(Error::UnsupportedFileType(
                input_path.display().to_string(),
            ));
        }

        tar_builder.finish()?;
    }

    // Encrypt
    let mut input = Cursor::new(tar_data);
    let output_file = File::create(output_path)?;
    let mut output = BufWriter::new(output_file);

    encrypt_hybrid(&mut input, &mut output, compression)?;

    output.flush()?;
    Ok(())
}

/// Decrypt a file to an output directory.
pub fn decrypt_to_dir(input_path: &Path, output_dir: &Path) -> Result<()> {
    let input_file = File::open(input_path)?;
    let mut input = BufReader::new(input_file);

    // Decrypt to memory
    let mut tar_data = Vec::new();
    decrypt_hybrid(&mut input, &mut tar_data)?;

    // Create output directory
    std::fs::create_dir_all(output_dir)?;

    // First pass: determine the archive structure
    let mut first_archive = tar::Archive::new(Cursor::new(&tar_data));
    let mut archive_root: Option<String> = None;
    let mut root_is_dir = false;
    let mut entry_count = 0;

    for entry in first_archive.entries()? {
        let entry = entry?;
        let path = entry.path()?;
        entry_count += 1;

        // Get the first component
        let first_component: String = path
            .components()
            .next()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .unwrap_or_default();

        if archive_root.is_none() {
            archive_root = Some(first_component.clone());
            root_is_dir = entry.header().entry_type().is_dir();
        } else if let Some(ref root) = archive_root {
            // Check if this entry is under the same root
            if !first_component.starts_with(root.as_str()) && first_component != *root {
                // Multiple top-level entries, don't strip
                archive_root = None;
                break;
            }
        }
    }

    // Only strip root if it's a directory and all entries are under it
    let strip_root = if let Some(root) = archive_root {
        if root_is_dir && entry_count > 1 {
            Some(root)
        } else {
            None
        }
    } else {
        None
    };

    // Extract tar archive (second pass)
    let mut archive = tar::Archive::new(Cursor::new(&tar_data));

    // Extract entries
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        // Validate path safety
        let path_str = path.to_string_lossy();
        if !is_safe_relative_path(&path_str) {
            return Err(Error::UnsafeArchivePath(path_str.to_string()));
        }

        // Determine the output path
        let relative_path = if let Some(ref root) = strip_root {
            let path_str = path.to_string_lossy();
            if path_str == *root || path_str == format!("{}/", root) {
                // This is the root directory entry, skip it
                continue;
            }
            // Strip the root component
            let stripped = path_str
                .strip_prefix(root)
                .and_then(|s| s.strip_prefix('/'))
                .unwrap_or(&path_str);
            std::path::PathBuf::from(stripped)
        } else {
            path.to_path_buf()
        };

        if relative_path.as_os_str().is_empty() {
            continue;
        }

        let full_path = output_dir.join(&relative_path);

        // Create parent directories if needed
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Unpack entry
        entry.unpack(&full_path)?;
    }

    Ok(())
}

/// Check if a path is safe (no absolute paths, no parent directory references).
fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }

    // No absolute paths
    if path.starts_with('/') || path.starts_with('\\') {
        return false;
    }

    // Check each component
    for component in path.split('/') {
        if component.is_empty() {
            continue;
        }
        // No backslashes in components
        if component.contains('\\') {
            return false;
        }
        // No . or .. components
        if component == "." || component == ".." {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_path() {
        assert!(is_safe_relative_path("foo/bar/baz"));
        assert!(is_safe_relative_path("file.txt"));
        assert!(!is_safe_relative_path("/absolute/path"));
        assert!(!is_safe_relative_path("../parent"));
        assert!(!is_safe_relative_path("foo/../bar"));
        assert!(!is_safe_relative_path("./current"));
    }
}

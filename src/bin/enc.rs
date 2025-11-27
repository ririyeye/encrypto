//! Encrypto encryption CLI tool.
//!
//! Usage: enc <input_path> [output_path]
//!
//! Encrypts a file or directory using hybrid RSA-OAEP + AES-GCM encryption.

use std::env;
use std::path::PathBuf;
use std::process;

use encrypto::{crypto, CompressionAlgorithm};

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run() -> encrypto::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: {} <input_path> [output_path]", args[0]);
        process::exit(1);
    }

    let input_path = PathBuf::from(&args[1]);

    // Validate input path
    if !input_path.exists() {
        eprintln!("Input path does not exist: {}", input_path.display());
        process::exit(1);
    }

    // Determine output path
    let output_path = if args.len() == 3 {
        PathBuf::from(&args[2])
    } else {
        derive_output_path(&input_path)
    };

    // Get compression algorithm from environment
    let compression = CompressionAlgorithm::from_env()?;
    eprintln!(
        "Encrypting '{}' -> '{}' (compression: {})",
        input_path.display(),
        output_path.display(),
        compression.name()
    );

    // Perform encryption
    crypto::encrypt_path(&input_path, &output_path, compression)?;

    eprintln!("Encryption complete.");
    Ok(())
}

/// Derive default output path from input path.
fn derive_output_path(input_path: &PathBuf) -> PathBuf {
    let base_name = input_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "output".to_string());

    PathBuf::from(format!("{}.bin", base_name))
}

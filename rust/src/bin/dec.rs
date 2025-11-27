//! Encrypto decryption CLI tool.
//!
//! Usage: dec <input_path> [output_dir]
//!
//! Decrypts a file encrypted with the enc tool.

use std::env;
use std::path::PathBuf;
use std::process;

use encrypto::crypto;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

fn run() -> encrypto::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 || args.len() > 3 {
        eprintln!("Usage: {} <input_path> [output_dir]", args[0]);
        process::exit(1);
    }

    let input_path = PathBuf::from(&args[1]);

    // Validate input path
    if !input_path.exists() {
        eprintln!("Input file does not exist: {}", input_path.display());
        process::exit(1);
    }

    if !input_path.is_file() {
        eprintln!("Input must be a file: {}", input_path.display());
        process::exit(1);
    }

    // Determine output directory
    let output_dir = if args.len() == 3 {
        PathBuf::from(&args[2])
    } else {
        derive_output_dir(&input_path)
    };

    // Ensure unique output directory
    let output_dir = ensure_unique_path(output_dir);

    eprintln!(
        "Decrypting '{}' -> '{}'",
        input_path.display(),
        output_dir.display()
    );

    // Perform decryption
    crypto::decrypt_to_dir(&input_path, &output_dir)?;

    eprintln!("Decryption complete.");
    Ok(())
}

/// Derive default output directory from input path.
fn derive_output_dir(input_path: &PathBuf) -> PathBuf {
    let mut base_name = input_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "output".to_string());

    // Strip .bin extension if present
    if base_name.ends_with(".bin") {
        base_name = base_name[..base_name.len() - 4].to_string();
    }

    PathBuf::from(base_name)
}

/// Ensure the output path is unique by adding a suffix if needed.
fn ensure_unique_path(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }

    let base_str = path.to_string_lossy().to_string();

    // Try random suffixes first
    for _ in 0..64 {
        let suffix = rand::random::<u32>();
        let candidate = PathBuf::from(format!("{}_{}", base_str, suffix));
        if !candidate.exists() {
            return candidate;
        }
    }

    // Fall back to sequential suffixes
    for i in 1..100000 {
        let candidate = PathBuf::from(format!("{}_{}", base_str, i));
        if !candidate.exists() {
            return candidate;
        }
    }

    // Give up and return original
    path
}

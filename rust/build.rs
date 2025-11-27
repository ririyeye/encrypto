//! Build script to generate RSA keys and embed them into the binary.
//!
//! This mirrors the behavior of `scripts/generate_keys.py` in the C version.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let key_dir = Path::new(&out_dir);

    let private_key_path = key_dir.join("rsa_private_key.der");
    let public_key_path = key_dir.join("rsa_public_key.der");

    // Check if keys already exist (for incremental builds)
    if private_key_path.exists() && public_key_path.exists() {
        println!("cargo:rerun-if-changed=build.rs");
        return;
    }

    // Generate 4096-bit RSA key pair
    use rand::rngs::OsRng;
    use rsa::{pkcs8::EncodePrivateKey, pkcs8::EncodePublicKey, RsaPrivateKey};

    println!("cargo:warning=Generating new RSA key pair (4096 bits)...");

    let mut rng = OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, 4096).expect("Failed to generate RSA private key");
    let public_key = private_key.to_public_key();

    // Export as DER format
    let private_der = private_key
        .to_pkcs8_der()
        .expect("Failed to encode private key to DER");
    let public_der = public_key
        .to_public_key_der()
        .expect("Failed to encode public key to DER");

    // Write to OUT_DIR
    fs::write(&private_key_path, private_der.as_bytes())
        .expect("Failed to write private key DER");
    fs::write(&public_key_path, public_der.as_ref())
        .expect("Failed to write public key DER");

    println!("cargo:rerun-if-changed=build.rs");
}

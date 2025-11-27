//! Random number generator support.
//!
//! Supports both system RNG and deterministic RNG for testing.

use std::cell::RefCell;
use std::env;
use std::fs::File;
use std::io::Read;

use rand::{CryptoRng, RngCore};

use crate::error::{Error, Result};

/// Environment variable for deterministic random source file.
const RANDOM_PATH_ENV: &str = "ENCRYPTO_TEST_RANDOM_PATH";

/// Get a random number generator.
///
/// If `ENCRYPTO_TEST_RANDOM_PATH` is set, returns a deterministic RNG
/// that reads from the specified file. Otherwise, returns the system RNG.
pub fn get_rng() -> Result<Box<dyn CryptoRngCore>> {
    if let Ok(path) = env::var(RANDOM_PATH_ENV) {
        if !path.is_empty() {
            let stream = DeterministicRng::from_file(&path)?;
            return Ok(Box::new(stream));
        }
    }
    Ok(Box::new(rand::rngs::OsRng))
}

/// Trait combining CryptoRng and RngCore for boxed trait objects.
pub trait CryptoRngCore: CryptoRng + RngCore {}

impl<T: CryptoRng + RngCore> CryptoRngCore for T {}

/// Deterministic RNG that reads from a pre-loaded byte buffer.
///
/// Used for testing to ensure reproducible encryption outputs.
pub struct DeterministicRng {
    data: Vec<u8>,
    offset: RefCell<usize>,
}

impl DeterministicRng {
    /// Create a new deterministic RNG from a file.
    pub fn from_file(path: &str) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(Self {
            data,
            offset: RefCell::new(0),
        })
    }

    /// Create a new deterministic RNG from bytes.
    #[allow(dead_code)]
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self {
            data,
            offset: RefCell::new(0),
        }
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = self.offset.borrow_mut();
        let remaining = self.data.len().saturating_sub(*offset);
        let to_copy = dest.len().min(remaining);

        if to_copy < dest.len() {
            // Fill with zeros if exhausted, or panic in debug
            #[cfg(debug_assertions)]
            panic!("Deterministic RNG exhausted");
            #[cfg(not(debug_assertions))]
            dest[to_copy..].fill(0);
        }

        dest[..to_copy].copy_from_slice(&self.data[*offset..*offset + to_copy]);
        *offset += to_copy;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        let offset = *self.offset.borrow();
        if offset + dest.len() > self.data.len() {
            return Err(rand::Error::new(Error::RngExhausted));
        }
        self.fill_bytes(dest);
        Ok(())
    }
}

// Mark as cryptographically secure (for testing purposes only!)
impl CryptoRng for DeterministicRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_rng() {
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let mut rng = DeterministicRng::from_bytes(data.clone());

        let mut buf = [0u8; 4];
        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [1, 2, 3, 4]);

        rng.fill_bytes(&mut buf);
        assert_eq!(buf, [5, 6, 7, 8]);
    }
}

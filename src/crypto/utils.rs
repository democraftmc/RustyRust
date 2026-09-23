//! Utility functions for cryptographic operations.

use rand::{RngExt, rng};

/// Generates a random Initialization Vector (IV) for AES-256-CBC encryption.
///
/// An IV is required to ensure that the same plaintext encrypted with the same key
/// results in different ciphertexts, preventing pattern recognition.
///
/// # Returns
///
/// * `[u8; 16]` - A 16-byte array containing the random IV.
pub fn generate_iv() -> [u8; 16] {
    // Create an empty 16-byte array.
    let mut iv = [0u8; 16];
    // Fill the array with random bytes.
    rng().fill(&mut iv[..]);
    // Return the generated IV.
    iv
}

//! Functions for decrypting data received from the RustyConnector broker.

use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::Decryptor;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};

/// Defines the AES-256 CBC Decryptor type using the `cbc` and `aes` crates.
type Aes256CbcDec = Decryptor<Aes256>;

/// Decrypts a Base64 encoded payload that was encrypted with AES-256-CBC.
///
/// This function decodes the Base64 string, extracts the prepended IV
/// (the first 16 bytes), and decrypts the remaining ciphertext using
/// PKCS7 unpadding.
///
/// # Arguments
///
/// * `b64_data` - A string slice containing the Base64 formatted encrypted payload.
/// * `key` - A reference to a 32-byte array representing the symmetric encryption key.
///
/// # Returns
///
/// * `Result<Vec<u8>, anyhow::Error>` - A boolean Result containing the decrypted raw bytes,
///   or an error if decoding, length verification, or block decryption fails.
pub fn decrypt_payload(b64_data: &str, key: &[u8; 32]) -> Result<Vec<u8>, anyhow::Error> {
    // Attempt to decode the Base64 payload into raw binary data.
    let raw = STANDARD.decode(b64_data)?;

    // The payload must be at least 16 bytes long because the IV itself is 16 bytes.
    if raw.len() < 16 {
        return Err(anyhow::anyhow!("Payload too short to contain IV"));
    }

    // Split the raw bytes: the first 16 bytes are the IV, the rest is the encrypted ciphertext.
    let (iv, ct) = raw.split_at(16);

    // Create a mutable copy of the ciphertext because the decrypt_padded function modifies it in-place.
    let mut buf = ct.to_vec();

    // Safely cast the byte slice to a 16-element byte array safely because we know its length is exactly 16.
    let iv_arr: &[u8; 16] = iv.try_into().unwrap();

    // Initialize the decryptor using the provided key and extracted IV.
    let pt = Aes256CbcDec::new(key.into(), iv_arr.into())
        // Decrypt the ciphertext in-place and remove the PKCS7 padding.
        .decrypt_padded::<Pkcs7>(&mut buf)
        // Map the decyption error to an anyhow::Error with a custom message.
        .map_err(|e| anyhow::anyhow!("Decrypt error: {:?}", e))?;

    // Return the resulting plaintext as a fresh Vector of bytes.
    Ok(pt.to_vec())
}

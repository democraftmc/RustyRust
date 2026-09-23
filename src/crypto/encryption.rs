//! Functions for encrypting data sent to the RustyConnector broker.

use crate::crypto::utils::generate_iv;
use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cbc::Encryptor;
use cbc::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};

/// Defines the AES-256 CBC Encryptor type using the `cbc` and `aes` crates.
type Aes256CbcEnc = Encryptor<Aes256>;

/// Encrypts a given raw byte slice payload using AES-256-CBC.
///
/// This function generates a new IV for each encryption, encrypts the data
/// with PKCS7 padding, concatenates the IV and ciphertext, and finally
/// encodes the entire result as a Base64 string.
///
/// # Arguments
///
/// * `data` - A slice of bytes representing the plaintext payload to encrypt.
/// * `key` - A reference to a 32-byte array representing the symmetric encryption key.
///
/// # Returns
///
/// * `String` - A Base64 encoded string containing the IV prepended to the ciphertext.
pub fn encrypt_payload(data: &[u8], key: &[u8; 32]) -> String {
    // Generate a secure, random IV (Initialization Vector) for this encryption process.
    let iv = generate_iv();

    let pt_len = data.len();

    // Create a mutable buffer large enough to hold the plaintext + up to 16 bytes for padding.
    let mut buf = vec![0u8; pt_len + 16];

    // Copy our plaintext data into the front of the buffer.
    buf[..pt_len].copy_from_slice(data);

    // Initialize the encryptor with the provided 32-byte key and the generated 16-byte IV.
    let ct = Aes256CbcEnc::new(key.into(), &iv.into())
        // Encrypt the data in-place inside `buf`, applying PKCS7 padding to match block sizes.
        .encrypt_padded::<Pkcs7>(&mut buf, pt_len)
        // We can safely unwrap here because the buffer size was explicitly calculated to be large enough.
        .unwrap();

    // Create the final output vector starting with the IV and immediately followed by the ciphertext.
    let mut out = Vec::with_capacity(16 + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(ct);

    // Encode the resulting byte sequence as a standard Base64 string so it can be transmitted.
    STANDARD.encode(&out)
}

//! This module contains utilities for generating unique identifiers.
//! Used extensively for creating session IDs, server IDs, and message IDs.

use nanoid::nanoid;

/// The alphabet used for nanoid generation in RustyConnector.
/// Contains all alphanumeric characters (both upper and lower case).
const ALPHABET: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B',
    'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z',
];

/// Generates a random 16-character string used for unique identification.
///
/// # Returns
///
/// * `String` - A randomly generated nanoid string of length 16.
///
/// # Example
///
/// ```rust
/// let my_id = generate_rc_nanoid();
/// println!("Generated ID: {}", my_id);
/// ```
pub fn generate_rc_nanoid() -> String {
    // We use the nanoid crate to generate a string of length 16
    // using the specified alphanumeric alphabet.
    nanoid!(16, ALPHABET)
}

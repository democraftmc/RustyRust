//! Core backend node definitions and initial handshake logic for the proxy connection.

use crate::crypto::decryption::decrypt_payload;
use crate::crypto::encryption::encrypt_payload;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};

/// Contains the HTTP endpoint path for performing preflight verification against the broker.
pub const PREFLIGHT_PATH: &str = "/bDaBMkmYdZ6r4iFExwW6UzJyNMDseWoS3HDa6FcyM7xNeCmtK98S3Mhp4o7g7oW6VB9CA6GuyH2pNhpQk3QvSmBUeCoUDZ6FXUsFCuVQC59CB2y22SBnGkMf9NMB9UWk";

/// Represents an abstract backend connection broker instance.
pub struct BackendNode {
    /// The decoded, 32-byte standardized AES-256-CBC private key.
    pub key: [u8; 32],
    /// The unformatted address path of the primary broker.
    pub proxy_url: String,
    /// The local explicit name of this specific instance to present.
    pub server_name: String,
}

impl BackendNode {
    /// Bootstraps our understanding of a Backend node connection.
    ///
    /// # Arguments
    ///
    /// * `base64_key` - A base64 string matching the configured proxy secret.
    /// * `proxy_url` - The central proxy URI (e.g. `127.0.0.1:8080`).
    /// * `server_name` - The unique explicit name to use throughout network processing.
    ///
    /// # Returns
    ///
    /// * `anyhow::Result<Self>` - Returns the initialized `BackendNode` or an error if key decoding fails.
    pub fn new(base64_key: &str, proxy_url: &str, server_name: &str) -> anyhow::Result<Self> {
        let key_bytes = STANDARD.decode(base64_key)?;

        // Assure length constraints are inherently matching AES specs.
        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Key must be exactly 32 bytes"));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);

        Ok(Self {
            key,
            proxy_url: proxy_url.to_string(),
            server_name: server_name.to_string(),
        })
    }

    /// Performs the primary REST/TCP handshake with the Master Proxy.
    /// Uses an ephemeral encrypted Timestamp request payload to authenticate
    /// the host, demanding a secure, dynamic WebSocket routing URL inside the response.
    ///
    /// # Returns
    ///
    /// * `anyhow::Result<(String, String)>` - A tuple containing `(WebSocket endpoint path, Compound Auth Token)`.
    pub fn perform_handshake(&self) -> anyhow::Result<(String, String)> {
        // Form a verification epoch token containing exactly "NOW" (since unix).
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .to_string();

        let auth_token = encrypt_payload(epoch.as_bytes(), &self.key);

        // Standard HTTP 1.1 preflight connection sequence.
        let request = format!(
            "GET {} HTTP/1.1\r\n\
            Host: {}\r\n\
            Authorization: Bearer {}\r\n\
            Connection: close\r\n\
            \r\n",
            PREFLIGHT_PATH, self.proxy_url, auth_token
        );

        let mut stream = TcpStream::connect(&self.proxy_url)?;
        stream.write_all(request.as_bytes())?;

        let mut response_str = String::new();
        stream.read_to_string(&mut response_str)?;

        // Discard header content safely to query the actual JSON response body.
        let body_str = response_str.split("\r\n\r\n").nth(1).unwrap_or("");
        if body_str.trim().is_empty() {
            return Err(anyhow::anyhow!("Empty response for handshake"));
        }

        // Parse JSON
        let body: Value = serde_json::from_str(body_str)?;

        let enc_endpoint = body["endpoint"].as_str().unwrap_or_default();
        let enc_token = body["token"].as_str().unwrap_or_default();
        let signature = body["signature"].as_str().unwrap_or_default();

        // Reveal the dynamic socket endpoint path from the encrypted chunk.
        let endpoint_raw = String::from_utf8(decrypt_payload(enc_endpoint, &self.key)?)?;
        let endpoint = endpoint_raw.trim_matches(char::from(0)).trim().to_string();

        // Dissect, analyze, and recreate the compound node JWT mapping from the server's signed fragments.
        let token_raw = String::from_utf8(decrypt_payload(enc_token, &self.key)?)?;
        let token = token_raw.trim_matches(char::from(0)).trim().to_string();

        let signature = signature.trim_matches(char::from(0)).trim();

        // Tie the user into the server representation natively.
        let compound = format!("{}${}${}", token, signature, self.server_name);

        let compound_enc = encrypt_payload(compound.as_bytes(), &self.key)
            .replace('\n', "")
            .replace('\r', "");

        Ok((endpoint, compound_enc))
    }
}

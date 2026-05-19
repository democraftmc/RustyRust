//! Main logic client interacting with RustyConnector Proxy WebSockets and Verification Endpoint.
use crate::rustyconnector::crypto::{decrypt_payload, encrypt_payload};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
/// The MagicLink static URI used for querying parameters.
pub const PREFLIGHT_PATH: &str = "/bDaBMkmYdZ6r4iFExwW6UzJyNMDseWoS3HDa6FcyM7xNeCmtK98S3Mhp4o7g7oW6VB9CA6GuyH2pNhpQk3QvSmBUeCoUDZ6FXUsFCuVQC59CB2y22SBnGkMf9NMB9UWk";
/// Main structural wrapper handling the lifecycle and keys of a Node instance.
pub struct BackendNode {
    pub key: [u8; 32],
    pub proxy_url: String, // like "127.0.0.1:8080"
    pub server_name: String,
}
impl BackendNode {
    /// Initializes a Node object properly decoding the provided Base64 Private Key.
    ///
    /// # Arguments
    /// * `base64_key` - 32-byte plain string.
    /// * `proxy_url` - The proxy Host and port. E.g "127.0.0.1:8080"
    /// * `server_name` - Descriptive identity.
    pub fn new(base64_key: &str, proxy_url: &str, server_name: &str) -> anyhow::Result<Self> {
        let key_bytes = STANDARD.decode(base64_key)?;
        if key_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Key must be 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(Self {
            key,
            proxy_url: proxy_url.to_string(),
            server_name: server_name.to_string(),
        })
    }
    /// Performs the mandatory HTTP preflight validation fetching dynamic ws info and tokens.
    ///
    /// The timestamp epoch is exchanged cleanly with the configured Key matrix.
    /// Because WebAssembly (WASIp2) `reqwest` links incorrectly, this natively uses `TcpStream`.
    pub fn perform_handshake(&self) -> anyhow::Result<(String, String)> {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .to_string();
        let auth_token = encrypt_payload(epoch.as_bytes(), &self.key);
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            PREFLIGHT_PATH, self.proxy_url, auth_token
        );
        let mut stream = TcpStream::connect(&self.proxy_url)?;
        stream.write_all(request.as_bytes())?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        let response_str = String::from_utf8_lossy(&response);
        let body_str = response_str.split("\r\n\r\n").nth(1).unwrap_or("");
        if body_str.trim().is_empty() {
            return Err(anyhow::anyhow!("Empty response for handshake"));
        }
        let body: Value = serde_json::from_str(body_str)?;
        let enc_endpoint = body["endpoint"].as_str().unwrap_or_default();
        let enc_token = body["token"].as_str().unwrap_or_default();
        let signature = body["signature"].as_str().unwrap_or_default();
        let endpoint = String::from_utf8(decrypt_payload(enc_endpoint, &self.key)?)?;
        let token = String::from_utf8(decrypt_payload(enc_token, &self.key)?)?;
        let compound = format!("{}${}${}", token, signature, self.server_name);
        let compound_enc = encrypt_payload(compound.as_bytes(), &self.key);
        Ok((endpoint, compound_enc))
    }
}

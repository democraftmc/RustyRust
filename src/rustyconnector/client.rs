use crate::rustyconnector::crypto::{decrypt_payload, encrypt_payload};
use crate::rustyconnector::packets::RCPacket;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
use tungstenite::client::IntoClientRequest;
use tungstenite::connect;
use tungstenite::http::header::{HeaderName, HeaderValue, AUTHORIZATION};
use tungstenite::Message;

pub const PREFLIGHT_PATH: &str = "/bDaBMkmYdZ6r4iFExwW6UzJyNMDseWoS3HDa6FcyM7xNeCmtK98S3Mhp4o7g7oW6VB9CA6GuyH2pNhpQk3QvSmBUeCoUDZ6FXUsFCuVQC59CB2y22SBnGkMf9NMB9UWk";

pub struct BackendNode {
    pub key: [u8; 32],
    pub proxy_url: String,
    pub server_name: String,
}

impl BackendNode {
    pub fn new(base64_key: &str, proxy_url: &str, server_name: &str) -> anyhow::Result<Self> {
        let key_bytes = STANDARD.decode(base64_key)?;
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

    pub fn perform_handshake(&self) -> anyhow::Result<(String, String)> {
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .to_string();

        let auth_token = encrypt_payload(epoch.as_bytes(), &self.key);

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

        let body_str = response_str.split("\r\n\r\n").nth(1).unwrap_or("");
        if body_str.trim().is_empty() {
            return Err(anyhow::anyhow!("Empty response for handshake"));
        }

        let body: Value = serde_json::from_str(body_str)?;

        let enc_endpoint = body["endpoint"].as_str().unwrap_or_default();
        let enc_token = body["token"].as_str().unwrap_or_default();
        let signature = body["signature"].as_str().unwrap_or_default();

        let endpoint_raw = String::from_utf8(decrypt_payload(enc_endpoint, &self.key)?)?;
        let endpoint = endpoint_raw.trim_matches(char::from(0)).trim().to_string();

        let token_raw = String::from_utf8(decrypt_payload(enc_token, &self.key)?)?;
        let token = token_raw.trim_matches(char::from(0)).trim().to_string();

        let signature = signature.trim_matches(char::from(0)).trim();

        let compound = format!("{}${}${}", token, signature, self.server_name);

        let compound_enc = encrypt_payload(compound.as_bytes(), &self.key)
            .replace("\n", "")
            .replace("\r", "");

        Ok((endpoint, compound_enc))
    }

    pub fn connect_websocket(&self, endpoint: &str, compound_token: &str) -> anyhow::Result<()> {
        let ws_url = format!("ws://{}/{}", self.proxy_url, endpoint);
        tracing::info!("Connecting to WebSocket at: {}", ws_url);

        let mut request = ws_url.into_client_request()?;
        let headers = request.headers_mut();

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", compound_token))?,
        );

        let identification_json = serde_json::json!({
            "u": self.server_name,
            "n": 2
        }).to_string();

        headers.insert(
            HeaderName::from_static("x-server-identification"),
            HeaderValue::from_str(&identification_json)?,
        );

        let (mut socket, response) = connect(request)?;
        tracing::info!("WebSocket connected! HTTP Status: {}", response.status());

        // --- HEARTBEAT Websocket. Currently not working
        let ping_packet = crate::rustyconnector::packets::RCPacket::ping(
            &self.server_name,              // Exact match to the HTTP Header "u" field
            "lobby",            // Target Family
            "vaatigames.fr:25552",  // Address
            0                   // Player Count
        );

        let ping_json = serde_json::to_string(&ping_packet)?;
        tracing::info!("Sending Ping JSON: {}", ping_json);

        let encrypted_ping = encrypt_payload(ping_json.as_bytes(), &self.key);
        socket.send(tungstenite::Message::Text(encrypted_ping.into()))?;
        tracing::info!("Sent encrypted Ping packet.");

        // Listen for messages
        loop {
            match socket.read() {
                Ok(msg) => {
                    tracing::info!("Raw WS msg received: {:?}", msg);

                    if msg.is_close() {
                        tracing::info!("WebSocket connection closed by server");
                        break;
                    }

                    if let tungstenite::Message::Text(text) = msg {
                        tracing::info!("Attempting to decrypt payload...");
                        match decrypt_payload(&text, &self.key) {
                            Ok(decrypted_bytes) => {
                                let json_str = String::from_utf8_lossy(&decrypted_bytes);
                                let clean_json = json_str.trim_matches(char::from(0));
                                tracing::info!("SUCCESS DECRYPTED: {}", clean_json);
                            },
                            Err(e) => {
                                tracing::error!("Decryption failed! Proxy might have sent plaintext. Raw Text: {}", text);
                                tracing::error!("Decryption Error: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading from WebSocket: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}
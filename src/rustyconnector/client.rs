use crate::rustyconnector::crypto::{decrypt_payload, encrypt_payload};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pumpkin_plugin_api::scheduler::SchedulerExt;
use pumpkin_plugin_api::Context;
use serde_json::Value;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{SystemTime, UNIX_EPOCH};
use tungstenite::client::IntoClientRequest;
use tungstenite::connect;
use tungstenite::http::header::{HeaderName, HeaderValue, AUTHORIZATION};

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

    pub fn connect_websocket(
        &self,
        endpoint: &str,
        compound_token: &str,
        context: &Context,
        backend_ip: &str,
        target_family: &str,
        state: std::sync::Arc<std::sync::Mutex<crate::PluginState>>, // Passed in from on_load
    ) -> anyhow::Result<()> {
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

        match socket.get_mut() {
            tungstenite::stream::MaybeTlsStream::Plain(s) => s.set_nonblocking(true)?,
            _ => tracing::warn!("WSS TLS streams might require inner stream configuration to be non-blocking!"),
        }

        // --- NEW: Wrap the socket to share it with the plugin struct ---
        let shared_socket = std::sync::Arc::new(std::sync::Mutex::new(socket));
        let closure_socket = shared_socket.clone();

        let server_name = self.server_name.clone();
        let backend_ip = backend_ip.to_string();
        let target_family = target_family.to_string();
        let key = self.key.clone();
        let session_id = crate::rustyconnector::packets::generate_rc_nanoid();

        let mut ticks_since_last_ping = 200;
        let mut ping_interval_ticks = 200;

        let mut is_closed = false;
        let task_id = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let closure_task_id = task_id.clone();

        let scheduled_id = context.schedule_repeating_task(1, 1, move |_server| {
            if is_closed { return; }

            // Obtain the lock dynamically each tick to allow on_unload to access it
            let mut socket = match closure_socket.try_lock() {
                Ok(s) => s,
                Err(_) => return, // Wait until the next tick if locked
            };

            // --- HEARTBEAT MANAGER ---
            ticks_since_last_ping += 1;

            if ticks_since_last_ping >= ping_interval_ticks {
                ticks_since_last_ping = 0;

                let ping_packet = crate::rustyconnector::packets::RCPacket::ping(
                    &server_name,
                    &session_id,
                    &target_family,
                    &backend_ip,
                    0
                );

                if let Ok(ping_json) = serde_json::to_string(&ping_packet) {
                    let encrypted_ping = encrypt_payload(ping_json.as_bytes(), &key);

                    if let Err(e) = socket.send(tungstenite::Message::Text(encrypted_ping.into())) {
                        tracing::error!("Fatal send error, closing MagicLink: {}", e);
                        is_closed = true;
                        pumpkin_plugin_api::scheduler::cancel_task(closure_task_id.load(std::sync::atomic::Ordering::Relaxed));
                        return;
                    } else {
                        tracing::info!("Sent encrypted Ping heartbeat.");
                    }
                }
            }

            // --- INCOMING MESSAGE POLLER ---
            loop {
                match socket.read() {
                    Ok(msg) => {
                        if msg.is_close() {
                            tracing::info!("WebSocket connection closed cleanly by proxy.");
                            is_closed = true;
                            pumpkin_plugin_api::scheduler::cancel_task(closure_task_id.load(std::sync::atomic::Ordering::Relaxed));
                            break;
                        }

                        if let tungstenite::Message::Text(text) = msg {
                            match decrypt_payload(&text, &key) {
                                Ok(decrypted_bytes) => {
                                    let json_str = String::from_utf8_lossy(&decrypted_bytes);
                                    let clean_json = json_str.trim_matches(char::from(0));

                                    if let Ok(parsed_json) = serde_json::from_str::<serde_json::Value>(clean_json) {
                                        if parsed_json["i"].as_str() == Some("RC-R") {
                                            let success = parsed_json["p"]["s"].as_bool().unwrap_or(false);
                                            let message = parsed_json["p"]["r"].as_str().unwrap_or("No message");

                                            if success {
                                                tracing::info!("Proxy ACCEPTED registration: {}", message);
                                                if let Some(interval_secs) = parsed_json["p"]["i"].as_u64() {
                                                    ping_interval_ticks = interval_secs * 20;
                                                }
                                            } else {
                                                tracing::error!("Proxy REJECTED registration: {}", message);
                                                tracing::warn!("Backing off ping interval to 60 seconds to prevent proxy spam.");
                                                ping_interval_ticks = 1200;
                                            }
                                        }
                                    }
                                },
                                Err(e) => {
                                    tracing::error!("Decryption Error: {}", e);
                                }
                            }
                        }
                    }
                    Err(tungstenite::error::Error::Io(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(e) => {
                        tracing::error!("WebSocket read error. Killing task to prevent spam: {}", e);
                        is_closed = true;
                        pumpkin_plugin_api::scheduler::cancel_task(closure_task_id.load(std::sync::atomic::Ordering::Relaxed));
                        break;
                    }
                }
            }
        });

        task_id.store(scheduled_id, std::sync::atomic::Ordering::Relaxed);

        // Store everything in the Plugin State
        if let Ok(mut st) = state.lock() {
            st.task_id = Some(scheduled_id);
            st.socket = Some(shared_socket);
            st.aes_key = Some(self.key.clone());
            st.server_name = Some(self.server_name.clone());
        }

        Ok(())
    }
}
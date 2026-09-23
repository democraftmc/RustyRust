//! Abstract background tasks dedicated to persistent WebSocket upkeep.

use crate::crypto::decryption::decrypt_payload;
use crate::crypto::encryption::encrypt_payload;
use crate::packets::models::RCPacket;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Manages the actual synchronous block logic of checking the active magical socket linkage.
/// Will query and verify connection states, attempt sending out Heartbeat events,
/// and poll all current readable messages pending to parse.
///
/// # Arguments
///
/// * `socket_lock` - Global safe-arc wrapping the live Tungstenite connection.
/// * `closure_ticks` - Thread-safe loop interval timer tracker.
/// * `closure_interval` - Thread-safe configuration holding ping intervals.
/// * `closure_is_closed` - Thread-safe context Boolean if we internally failed.
/// * `closure_task_id` - Represents Pumpkin's ID reference to this looping tick structure.
/// * `server_name` - Current Server/Environment label reference.
/// * `session_id` - Current ephemeral session mapping label reference.
/// * `target_family` - Configured load-balancing role mapping reference.
/// * `backend_ip` - Network forwarding reference IP resolving context.
/// * `key` - Core AES decoding mapping parameter reference.
pub fn process_websocket_tick(
    socket_lock: &crate::plugin::state::SharedSocket,
    closure_ticks: &Arc<AtomicU64>,
    closure_interval: &Arc<AtomicU64>,
    closure_is_closed: &Arc<AtomicBool>,
    closure_task_id: &Arc<AtomicU32>,
    server_name: &str,
    session_id: &str,
    target_family: &str,
    backend_ip: &str,
    key: &[u8; 32],
) {
    if closure_is_closed.load(Ordering::Relaxed) {
        return;
    }

    // Try to take the websocket cleanly to avoid stopping the server thread.
    let mut socket = match socket_lock.try_lock() {
        Ok(s) => s,
        Err(_) => return, // Blocked by on_unload or other mechanics? Reschedule to next tick.
    };

    // --- HEARTBEAT MANAGER ---
    // Increment the counter internally and use its updated representation.
    let current_ticks = closure_ticks.fetch_add(1, Ordering::Relaxed) + 1;

    // Send Heartbeat (Ping) logic
    if current_ticks >= closure_interval.load(Ordering::Relaxed) {
        closure_ticks.store(0, Ordering::Relaxed);

        let ping_packet = RCPacket::ping(server_name, session_id, target_family, backend_ip, 0);

        if let Ok(ping_json) = serde_json::to_string(&ping_packet) {
            let encrypted_ping = encrypt_payload(ping_json.as_bytes(), key);

            if let Err(e) = socket.send(tungstenite::Message::Text(encrypted_ping.into())) {
                crate::log_error!("Fatal send error, closing MagicLink: {}", e);
                closure_is_closed.store(true, Ordering::Relaxed);
                pumpkin_plugin_api::scheduler::cancel_task(closure_task_id.load(Ordering::Relaxed));
                return;
            } else {
                crate::log_info!("Sent encrypted Ping heartbeat.");
            }
        }
    }

    // --- INCOMING MESSAGE POLLER ---
    // Safely reads continuously until WouldBlock intercepts.
    loop {
        match socket.read() {
            Ok(msg) => {
                if msg.is_close() {
                    crate::log_info!("WebSocket connection closed cleanly by proxy.");
                    closure_is_closed.store(true, Ordering::Relaxed);
                    pumpkin_plugin_api::scheduler::cancel_task(
                        closure_task_id.load(Ordering::Relaxed),
                    );
                    break;
                }

                if let tungstenite::Message::Text(text) = msg {
                    match decrypt_payload(&text, key) {
                        Ok(decrypted_bytes) => {
                            let json_str = String::from_utf8_lossy(&decrypted_bytes);
                            let clean_json = json_str.trim_matches(char::from(0));

                            if let Ok(parsed_json) =
                                serde_json::from_str::<serde_json::Value>(clean_json)
                            {
                                // Checking for Registration Request Response (RC-R)
                                if parsed_json["i"].as_str() == Some("RC-R") {
                                    let success = parsed_json["p"]["s"].as_bool().unwrap_or(false);
                                    let message =
                                        parsed_json["p"]["r"].as_str().unwrap_or("No message");

                                    if success {
                                        crate::log_info!("Proxy ACCEPTED registration: {}", message);
                                        if let Some(interval_secs) = parsed_json["p"]["i"].as_u64()
                                        {
                                            // Convert seconds down to proxy heartbeat interval ticks (20 TPS assumed).
                                            closure_interval
                                                .store(interval_secs * 20, Ordering::Relaxed);
                                        }
                                    } else {
                                        crate::log_error!("Proxy REJECTED registration: {}", message);
                                        crate::log_warn!(
                                            "Backing off ping interval to 60 seconds to prevent proxy spam."
                                        );
                                        closure_interval.store(1200, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            crate::log_error!("Decryption Error: {}", e);
                        }
                    }
                }
            }
            // Explicit ignore for logical blocking
            Err(tungstenite::error::Error::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                break;
            }
            Err(e) => {
                crate::log_error!("WebSocket read error. Killing task to prevent spam: {}", e);
                closure_is_closed.store(true, Ordering::Relaxed);
                pumpkin_plugin_api::scheduler::cancel_task(closure_task_id.load(Ordering::Relaxed));
                break;
            }
        }
    }
}

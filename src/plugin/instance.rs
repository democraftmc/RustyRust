//! The core Pumpkin Server API Plugin lifecycle integration bridging module.

use crate::config::loader::load_or_create_config;
use crate::config::models::Config;
use crate::network::node::BackendNode;
use crate::plugin::state::PluginState;
use pumpkin_plugin_api::scheduler::SchedulerExt;
use pumpkin_plugin_api::{Context, Plugin, PluginMetadata};
use std::sync::Arc;

/// The primary structured logic anchor acting within the Pumpkin runtime.
pub struct RustyRustPlugin {
    /// Safe transactional link wrapping dynamic logic state attributes reliably.
    state: std::sync::Arc<std::sync::Mutex<PluginState>>,
}

impl Plugin for RustyRustPlugin {
    /// Constructs a clean context instantiation of the Plugin environment natively.
    fn new() -> Self {
        RustyRustPlugin {
            state: std::sync::Arc::new(std::sync::Mutex::new(PluginState::default())),
        }
    }

    /// Provides central Server environments explicit metadata about RustyRust execution details.
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "RustyRust".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            authors: vec!["Funasitien".into()],
            description: "RustyConnector backend plugin, written in rust.".into(),
            dependencies: vec![],
            permissions: vec![
                "network.outbound".into(),
                "network.tcp".into(),
                "network.tcp.connect".into(),
                "network.dns".into(),
                "fs.read.data".into(),
                "fs.write.data".into(),
                "sys.env.RUSTYRUST_PROXY_URL".into(),
                "sys.env.RUSTYRUST_BACKEND_IP".into(),
                "sys.env.RUSTYRUST_PRIVATE_KEY".into(),
                "sys.env.RUSTYRUST_SERVER_ID".into(),
            ],
        }
    }

    /// Primary execution boot lifecycle triggered dynamically when resolving dependencies sequentially.
    fn on_load(&self, context: Context) -> pumpkin_plugin_api::Result<()> {
        crate::log_info!("RCR is starting, connecting to the proxy...");

        // Load configuration and mapping sequences.
        let mut config = load_or_create_config(&context);

        // Apply environmental variable fallbacks seamlessly.
        if std::env::var("RUSTYRUST_PRIVATE_KEY").is_ok() {
            config.private_key =
                std::env::var("RUSTYRUST_PRIVATE_KEY").unwrap_or(config.private_key);
            crate::log_info!(
                "Overriding internal encryption configuration with environment variable RUSTYRUST_PRIVATE_KEY (redacted)"
            );
        }

        if std::env::var("RUSTYRUST_PROXY_URL").is_ok() {
            config.proxy_url =
                std::env::var("RUSTYRUST_PROXY_URL").unwrap_or(config.proxy_url.clone());
            crate::log_info!(
                "Overriding proxy connection target with environment variable RUSTYRUST_PROXY_URL: {}",
                config.proxy_url
            );
        }

        if std::env::var("RUSTYRUST_BACKEND_IP").is_ok() {
            config.backend_ip =
                std::env::var("RUSTYRUST_BACKEND_IP").unwrap_or(config.backend_ip.clone());
            crate::log_info!(
                "Overriding external IP routing dynamically with environment variable RUSTYRUST_BACKEND_IP: {}",
                config.backend_ip
            );
        }

        if let Ok(env_id) = std::env::var("RUSTYRUST_SERVER_ID") {
            config.server_id = env_id;
            crate::log_info!(
                "Overriding server ID dynamically with environment variable RUSTYRUST_SERVER_ID: {}",
                config.server_id
            );
        }

        crate::log_info!(
            "Registering RustyConnector node {} @ {}...",
            config.server_name,
            config.proxy_url
        );

        let context_arc = std::sync::Arc::new(context);
        let state_clone = self.state.clone();

        // Push actual linkage onto the next processor sequence block safely.
        perform_backend_handshake(&config, &context_arc, state_clone);

        Ok(())
    }

    /// Structured cleanup routine logic terminating threads gracefully.
    fn on_unload(&self, _context: Context) -> pumpkin_plugin_api::Result<()> {
        crate::log_info!("RustyRust plugin unloading. Sending disconnect packet...");

        if let Ok(mut st) = self.state.lock() {
            // Cancel background process logic forcefully.
            if let Some(id) = st.task_id {
                pumpkin_plugin_api::scheduler::cancel_task(id);
                st.task_id = None;
            }

            // Cleanly instruct Proxy that the connection should dissolve legitimately natively.
            if let (Some(socket_arc), Some(key), Some(server_name)) =
                (&st.socket, &st.aes_key, &st.server_name)
            {
                if let Ok(mut socket) = socket_arc.lock() {
                    let disconnect_packet =
                        crate::packets::models::RCPacket::disconnect(server_name);

                    if let Ok(json) = serde_json::to_string(&disconnect_packet) {
                        let encrypted =
                            crate::crypto::encryption::encrypt_payload(json.as_bytes(), key);
                        let _ = socket.send(tungstenite::Message::Text(encrypted.into()));
                    }
                    
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    let _ = socket.close(None);
                    crate::log_info!(
                        "Disconnect packet sent explicitly and local TCP connection cleanly exited."
                    );
                }
            }
        }

        crate::log_info!("RustyRust plugin unloaded heavily. Goodbye!");
        Ok(())
    }
}

/// Abstract recursion handler allowing infinite cyclic loop retry handling transparently.
/// Attempts to attach to the proxy and schedule nested logical tasks accurately.
///
/// # Arguments
///
/// * `config` - Explicit configuration memory reference dictating behavior structures natively.
/// * `context` - Live Server Reference bridging delayed task execution dynamically securely.
/// * `state` - Secure wrapped property block updating actively dynamically efficiently.
pub fn perform_backend_handshake(
    config: &Config,
    context: &Arc<Context>,
    state: Arc<std::sync::Mutex<PluginState>>,
) {
    if config.private_key.is_empty() {
        crate::log_warn!(
            "AES private key is empty! Please configure 'aes.private' in 'config.yml' before continuing."
        );
        crate::log_warn!(
            "Delaying handshake attempt for 60 seconds to allow live configuration..."
        );
        let config_clone = config.clone();
        let context_clone = context.clone();
        let state_clone = state.clone();
        context.schedule_delayed_task(1200, move |_| {
            // Re-load config to catch valid user injection changes dynamically!
            let updated_config = crate::config::loader::load_or_create_config(&context_clone);
            // Replace the key natively in the cloned environment
            let mut final_config = config_clone.clone();
            final_config.private_key = updated_config.private_key;
            perform_backend_handshake(&final_config, &context_clone, state_clone.clone())
        });
        return;
    }

    let node = match BackendNode::new(&config.private_key, &config.proxy_url, &config.server_id) {
        Ok(n) => n,
        Err(error) => {
            crate::log_error!(
                "Failed to generate RustyConnector Backend logic. Key configuration mismatch: {}",
                error
            );

            let config_clone = config.clone();
            let context_clone = context.clone();
            let state_clone = state.clone();
            crate::log_warn!("Retrying connection setup sequence dynamically (60 seconds)...");

            context.schedule_delayed_task(1200, move |_| {
                perform_backend_handshake(&config_clone, &context_clone, state_clone.clone())
            });

            return;
        }
    };

    match node.perform_handshake() {
        Ok((endpoint, compound_token)) => {
            crate::log_info!(
                "Successfully executed Proxy cryptographic sequence successfully. Dynamic endpoint attached: {}",
                endpoint
            );

            if let Err(e) = node.connect_websocket(
                &endpoint,
                &compound_token,
                context,
                config,
                state,
            ) {
                crate::log_error!(
                    "WebSocket dynamic transition connection strictly failed fundamentally: {}",
                    e
                );
            }
        }
        Err(error) => {
            crate::log_error!(
                "RustyConnector HTTP TLS handshake fundamentally mapped rejection aggressively: {}",
                error
            );

            let config_clone = config.clone();
            let context_clone = context.clone();
            let state_clone = state.clone();
            crate::log_warn!(
                "Rapid recursion linkage sequence queued natively efficiently dynamically structurally (10 seconds)..."
            );

            context.schedule_delayed_task(200, move |_| {
                perform_backend_handshake(&config_clone, &context_clone, state_clone.clone())
            });
        }
    }
}

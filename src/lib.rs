pub mod rustyconnector;

use crate::rustyconnector::client::BackendNode;
use pumpkin_plugin_api::{Context, Plugin, PluginMetadata};
use serde::Deserialize;
use std::fs;
use pumpkin_plugin_api::scheduler::SchedulerExt;
use tracing::*;

type SharedSocket = std::sync::Arc<std::sync::Mutex<tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>>>;

#[derive(Default)]
pub struct PluginState {
    pub task_id: Option<u32>,
    pub socket: Option<SharedSocket>,
    pub aes_key: Option<[u8; 32]>,
    pub server_name: Option<String>,
}

struct RustyRustPlugin {
    state: std::sync::Arc<std::sync::Mutex<PluginState>>,
}

#[derive(Debug, Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    proxy_url: Option<String>,
    #[serde(default)]
    backend_ip: Option<String>,
    #[serde(default)]
    target_family: Option<String>,
    #[serde(default)]
    aes: Option<AesSection>,
    #[serde(default, rename = "aes.private")]
    aes_private: Option<String>,
    #[serde(default, rename = "private_key")]
    legacy_private_key: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AesSection {
    #[serde(default)]
    private: Option<String>,
}

#[derive(Debug, Clone)]
struct Config {
    server_name: String,
    proxy_url: String,
    private_key: String,
    backend_ip: String,
    target_family: String,
    server_id: String,
}

const DEFAULT_SERVER_NAME: &str = "rust-node";
const DEFAULT_PROXY_URL: &str = "127.0.0.1:8080";
const DEFAULT_PRIVATE_KEY: &str = "";
const DEFAULT_TARGET_FAMILY: &str = "lobby";
const CONFIG_FILE_NAME: &str = "config.yml";

const DEFAULT_CONFIG_CONTENT: &str =
    "server_name: 'rust-node'\nproxy_url: '127.0.0.1:8080'\nbackend_ip: '127.0.0.1:25566'\ntarget_family: 'lobby'\naes:\n  private: ''\n";

impl Plugin for RustyRustPlugin {
    fn new() -> Self {
        RustyRustPlugin {
            state: std::sync::Arc::new(std::sync::Mutex::new(PluginState::default())),
        }
    }

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
            ],
        }
    }

    fn on_load(&mut self, context: Context) -> pumpkin_plugin_api::Result<()> {
        info!("RCR is starting, connecting to the proxy...");

        let mut config = load_or_create_config(&context);

        if std::env::var("RUSTYRUST_PRIVATE_KEY").is_ok() {
            config.private_key = std::env::var("RUSTYRUST_PRIVATE_KEY").unwrap_or(config.private_key);
            info!("Overriding backend IP with environment variable RUSTYRUST_PRIVATE_KEY (redacted)");
        }

        if std::env::var("RUSTYRUST_PROXY_URL").is_ok() {
            config.proxy_url = std::env::var("RUSTYRUST_PROXY_URL").unwrap_or(config.proxy_url);
            info!("Overriding backend IP with environment variable RUSTYRUST_PROXY_URL: {}", config.proxy_url);
        }

        if std::env::var("RUSTYRUST_BACKEND_IP").is_ok() {
            config.backend_ip = std::env::var("RUSTYRUST_BACKEND_IP").unwrap_or(config.backend_ip);
            info!("Overriding backend IP with environment variable RUSTYRUST_BACKEND_IP: {}", config.backend_ip);
        }

        info!(
            "Registering RustyConnector node {} @ {}...",
            config.server_name, config.proxy_url
        );

        let context_arc = std::sync::Arc::new(context);
        let state_clone = self.state.clone();
        perform_backend_handshake(&config, &context_arc, state_clone);

        Ok(())
    }

    fn on_unload(&mut self, _context: Context) -> pumpkin_plugin_api::Result<()> {
        info!("RustyRust plugin unloading. Sending disconnect packet...");

        if let Ok(mut st) = self.state.lock() {
            // Cancel the repeating task
            if let Some(id) = st.task_id {
                pumpkin_plugin_api::scheduler::cancel_task(id);
                st.task_id = None;
            }

            // Send the RC-D packet
            if let (Some(socket_arc), Some(key), Some(server_name)) = (&st.socket, &st.aes_key, &st.server_name) {
                if let Ok(mut socket) = socket_arc.lock() {
                    let disconnect_packet = crate::rustyconnector::packets::RCPacket::disconnect(server_name);

                    if let Ok(json) = serde_json::to_string(&disconnect_packet) {
                        let encrypted = crate::rustyconnector::crypto::encrypt_payload(json.as_bytes(), key);
                        let _ = socket.send(tungstenite::Message::Text(encrypted.into()));
                    }

                    let _ = socket.close(None);
                    info!("Disconnect packet sent and socket closed.");
                }
            }
        }

        info!("RustyRust plugin unloaded. Goodbye!");
        Ok(())
    }
}

fn load_or_create_config(context: &Context) -> Config {
    let data_folder = std::path::PathBuf::from(context.get_data_folder());
    let _ = fs::create_dir_all(&data_folder);

    let id_file = data_folder.join("server.id");
    let server_id = if id_file.exists() {
        fs::read_to_string(&id_file).unwrap_or_else(|_| crate::rustyconnector::packets::generate_rc_nanoid())
    } else {
        let new_id = crate::rustyconnector::packets::generate_rc_nanoid();
        let _ = fs::write(&id_file, &new_id);
        new_id
    };

    let config_path = data_folder.join(CONFIG_FILE_NAME);
    if !config_path.exists() {
        if let Err(error) = fs::write(&config_path, DEFAULT_CONFIG_CONTENT) {
            error!(
                "Failed to generate default config file {}: {}. Falling back to defaults.",
                config_path.display(),
                error
            );
            let mut config = default_config();
            config.server_id = server_id;
            return config;
        }

        info!("Generated default RustyRust config at {}", config_path.display());
        let mut config = default_config();
        config.server_id = server_id;
        return config;
    }

    let raw_config = match fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(error) => {
            error!(
                "Failed to read config file {}: {}. Falling back to defaults.",
                config_path.display(),
                error
            );
            let mut config = default_config();
            config.server_id = server_id;
            return config;
        }
    };

    match serde_yaml::from_str::<ConfigFile>(&raw_config) {
        Ok(parsed) => {
            let mut config = parsed.into_config();
            config.server_id = server_id;
            config
        },
        Err(_error) => {
            let mut config = default_config();
            config.server_id = server_id;
            config
        }
    }
}

fn default_config() -> Config {
    Config {
        server_name: DEFAULT_SERVER_NAME.to_string(),
        proxy_url: DEFAULT_PROXY_URL.to_string(),
        private_key: DEFAULT_PRIVATE_KEY.to_string(),
        backend_ip: "127.0.0.1:25566".to_string(),
        target_family: DEFAULT_TARGET_FAMILY.to_string(),
        server_id: crate::rustyconnector::packets::generate_rc_nanoid(),
    }
}

impl ConfigFile {
    fn into_config(self) -> Config {
        let private_key = self
            .aes
            .and_then(|aes| aes.private)
            .or(self.aes_private)
            .or(self.legacy_private_key)
            .unwrap_or_else(|| DEFAULT_PRIVATE_KEY.to_string());

        Config {
            server_name: self.server_name.unwrap_or_else(|| DEFAULT_SERVER_NAME.to_string()),
            proxy_url: self.proxy_url.unwrap_or_else(|| DEFAULT_PROXY_URL.to_string()),
            backend_ip: self.backend_ip.unwrap_or_else(|| "127.0.0.1:25566".to_string()),
            target_family: self.target_family.unwrap_or_else(|| DEFAULT_TARGET_FAMILY.to_string()),
            server_id: "".to_string(),
            private_key,
        }
    }
}

fn perform_backend_handshake(config: &Config, context: &std::sync::Arc<Context>, state: std::sync::Arc<std::sync::Mutex<PluginState>>) {
    let node = match BackendNode::new(
        &config.private_key,
        &config.proxy_url,
        &config.server_id,
    ) {
        Ok(node) => node,
        Err(error) => {
            tracing::error!("Failed to create RustyConnector backend node: {}", error);

            let config_clone = config.clone();
            let context_clone = context.clone();
            let state_clone = state.clone();
            tracing::warn!("Retrying handshake in 60 seconds...");

            context.schedule_delayed_task(1200, move |_| {
                perform_backend_handshake(&config_clone, &context_clone, state_clone.clone())
            });

            return;
        }
    };

    match node.perform_handshake() {
        Ok((endpoint, compound_token)) => {
            tracing::info!("Successfully performed handshake. Dynamic endpoint: {}", endpoint);

            if let Err(e) = node.connect_websocket(
                &endpoint,
                &compound_token,
                context,
                &config.backend_ip,
                &config.target_family,
                state,
            ) {
                tracing::error!("WebSocket connection failed: {}", e);
            }
        }
        Err(error) => {
            tracing::error!("RustyConnector handshake failed: {}", error);

            let config_clone = config.clone();
            let context_clone = context.clone();
            let state_clone = state.clone();
            tracing::warn!("Retrying handshake in 10 seconds...");

            context.schedule_delayed_task(200, move |_| {
                perform_backend_handshake(&config_clone, &context_clone, state_clone.clone())
            });
        }
    }
}

pumpkin_plugin_api::register_plugin!(RustyRustPlugin);
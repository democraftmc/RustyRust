pub mod rustyconnector;

use crate::rustyconnector::client::BackendNode;
use base64::Engine as _;
use pumpkin_plugin_api::{Context, Plugin, PluginMetadata};
use serde::Deserialize;
use std::fs;
use tracing::*;

struct RustyRustPlugin;

#[derive(Debug, Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    proxy_url: Option<String>,
    #[serde(default)]
    backend_ip: Option<String>,
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

#[derive(Debug)]
struct Config {
    server_name: String,
    proxy_url: String,
    private_key: String,
    backend_ip: String,
    server_id: String,
}

const DEFAULT_SERVER_NAME: &str = "rust-node";
const DEFAULT_PROXY_URL: &str = "127.0.0.1:8080";
const DEFAULT_PRIVATE_KEY: &str = "";
const CONFIG_FILE_NAME: &str = "config.yml";

const DEFAULT_CONFIG_CONTENT: &str =
    "server_name: 'rust-node'\nproxy_url: '127.0.0.1:8080'\nbackend_ip: '127.0.0.1:25566'\naes:\n  private: ''\n";

impl Plugin for RustyRustPlugin {
    fn new() -> Self {
        RustyRustPlugin
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
            ],
        }
    }

    fn on_load(&mut self, context: Context) -> pumpkin_plugin_api::Result<()> {
        info!("RCR is starting, connecting to the proxy...");

        let config = load_or_create_config(&context);

        info!(
            "Registering RustyConnector node {} @ {}...",
            config.server_name, config.proxy_url
        );

        // Pass the context down
        perform_backend_handshake(&config, &context);

        Ok(())
    }

    fn on_unload(&mut self, _context: Context) -> pumpkin_plugin_api::Result<()> {
        info!("RustyRust plugin unloaded. Goodbye!");
        Ok(())
    }
}

fn load_or_create_config(context: &Context) -> Config {
    let data_folder = std::path::PathBuf::from(context.get_data_folder());
    let _ = fs::create_dir_all(&data_folder); // Ensure folder exists first

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
            return default_config();
        }

        info!("Generated default RustyRust config at {}", config_path.display());
        return default_config();
    }

    let raw_config = match fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(error) => {
            error!(
                "Failed to read config file {}: {}. Falling back to defaults.",
                config_path.display(),
                error
            );
            return default_config();
        }
    };

    match serde_yaml::from_str::<ConfigFile>(&raw_config) {
        Ok(parsed) => {
            let mut config = parsed.into_config();
            config.server_id = server_id; // Inject the persistent ID here
            config
        },
        Err(error) => {
            let mut config = default_config();
            config.server_id = server_id; // Inject the persistent ID here
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
            server_id: "".to_string(),
            private_key,
        }
    }
}

fn perform_backend_handshake(config: &Config, context: &pumpkin_plugin_api::Context) {
    let node = match BackendNode::new(
        &config.private_key,
        &config.proxy_url,
        &config.server_id,
    ) {
        Ok(node) => node,
        Err(error) => {
            tracing::error!("Failed to create RustyConnector backend node: {}", error);
            return;
        }
    };

    match node.perform_handshake() {
        Ok((endpoint, compound_token)) => {
            tracing::info!("Successfully performed handshake. Dynamic endpoint: {}", endpoint);

            // Pass the context into the websocket connection
            if let Err(e) = node.connect_websocket(&endpoint, &compound_token, context, &config.backend_ip) {
                tracing::error!("WebSocket connection failed: {}", e);
            }
        }
        Err(error) => {
            tracing::error!("RustyConnector handshake failed: {}", error);
        }
    }
}

pumpkin_plugin_api::register_plugin!(RustyRustPlugin);
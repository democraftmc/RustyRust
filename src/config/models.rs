//! Structural definitions of the plugin's runtime and deserialized configuration.

use crate::config::defaults::{
    DEFAULT_PRIVATE_KEY, DEFAULT_PROXY_URL, DEFAULT_SERVER_NAME, DEFAULT_TARGET_FAMILY,
};
use serde::Deserialize;

/// Represents the raw deserialized config values exactly as written in `config.yml`.
/// Contains options for all valid fields, allowing graceful defaults.
#[derive(Debug, Deserialize, Default)]
pub struct ConfigFile {
    /// The identifiable name of this specific server instance.
    #[serde(default)]
    pub server_name: Option<String>,

    /// The location/IP of the central RustyConnector Proxy logic.
    #[serde(default)]
    pub proxy_url: Option<String>,

    /// The location/IP where connecting clients should be redirected to.
    #[serde(default)]
    pub backend_ip: Option<String>,

    /// The family type tag used for load balancing grouping.
    #[serde(default)]
    pub target_family: Option<String>,

    /// The nested AES configuration section.
    #[serde(default)]
    pub aes: Option<AesSection>,

    /// An alternative direct key for older specification layouts.
    #[serde(default, rename = "aes.private")]
    pub aes_private: Option<String>,

    /// Legacy mapping for the primary authentication key.
    #[serde(default, rename = "private_key")]
    pub legacy_private_key: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// The inner structure of the AES configuration segment.
#[derive(Debug, Deserialize, Default)]
pub struct AesSection {
    /// The private AES-256-CBC 32-character key matching the central proxy.
    #[serde(default)]
    pub private: Option<String>,
}

/// Represents the normalized, fully-resolved configuration object used internally.
/// Contains no optional fields. Missing values fallback to default behavior.
#[derive(Debug, Clone)]
pub struct Config {
    pub server_name: String,
    pub proxy_url: String,
    pub private_key: String,
    pub backend_ip: String,
    pub target_family: String,
    pub server_id: String,
    pub metadata: serde_json::Value,
}

impl ConfigFile {
    /// Consumes the deserialized `ConfigFile` and maps it into a robust, complete `Config`.
    ///
    /// Ensures that optional configuration blocks are merged downward into sensible defaults
    /// if the user missed fields while editing `config.yml`.
    pub fn into_config(self) -> Config {
        // Resolve private key utilizing multiple fallback points.
        let private_key = self
            .aes
            .and_then(|aes| aes.private)
            .or(self.aes_private)
            .or(self.legacy_private_key)
            .unwrap_or_else(|| DEFAULT_PRIVATE_KEY.to_string());

        Config {
            server_name: self
                .server_name
                .unwrap_or_else(|| DEFAULT_SERVER_NAME.to_string()),
            proxy_url: self
                .proxy_url
                .unwrap_or_else(|| DEFAULT_PROXY_URL.to_string()),
            backend_ip: self
                .backend_ip
                .unwrap_or_else(|| "127.0.0.1:25566".to_string()),
            target_family: self
                .target_family
                .unwrap_or_else(|| DEFAULT_TARGET_FAMILY.to_string()),
            server_id: "".to_string(), // Injected later by the loader
            metadata: self.metadata.unwrap_or_else(|| serde_json::json!({ "hardCap": 40 })),
            private_key,
        }
    }
}

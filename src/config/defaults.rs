//! Default configuration values and templates for RustyRust.

use crate::config::models::Config;
use crate::utils::id_gen::generate_rc_nanoid;

/// The fallback server name.
pub const DEFAULT_SERVER_NAME: &str = "rust-node";
/// The generic loopback string for the RustyConnector proxy target.
pub const DEFAULT_PROXY_URL: &str = "127.0.0.1:8080";
/// Security failure block, preventing connection if no key was generated or supplied.
pub const DEFAULT_PRIVATE_KEY: &str = "";
/// What family this instance belongs to by default.
pub const DEFAULT_TARGET_FAMILY: &str = "lobby";
/// The specific configuration file name to write/read.
pub const CONFIG_FILE_NAME: &str = "config.yml";

/// The structural YAML string output whenever the plugin creates a fresh file layout.
pub const DEFAULT_CONFIG_CONTENT: &str = "server_name: 'rust-node'\nproxy_url: '127.0.0.1:8080'\nbackend_ip: '127.0.0.1:25566'\ntarget_family: 'lobby'\naes:\n  private: ''\n";

/// Spawns an entirely untouched, pristine `Config` object using module defaults.
///
/// Generally used as a fallback if file parsing critically fails.
pub fn default_config() -> Config {
    Config {
        server_name: DEFAULT_SERVER_NAME.to_string(),
        proxy_url: DEFAULT_PROXY_URL.to_string(),
        private_key: DEFAULT_PRIVATE_KEY.to_string(),
        backend_ip: "127.0.0.1:25566".to_string(),
        target_family: DEFAULT_TARGET_FAMILY.to_string(),
        server_id: generate_rc_nanoid(),
    }
}

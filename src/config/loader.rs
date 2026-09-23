//! File IO utilities for processing, verifying, reading, and loading configuration properties.

use crate::config::defaults::{CONFIG_FILE_NAME, DEFAULT_CONFIG_CONTENT, default_config};
use crate::config::models::{Config, ConfigFile};
use crate::utils::id_gen::generate_rc_nanoid;
use pumpkin_plugin_api::Context;
use std::fs;


/// Manages the full initialization pipeline for the plugin configuration.
/// Ensures that necessary default folders, config files, and unique ID
/// tracker keys exist, updating or creating them as needed.
///
/// # Arguments
///
/// * `context` - A reference to the active `Context` representing the Pumpkin API instance.
///
/// # Returns
///
/// * `Config` - A guaranteed valid plugin configuration data object.
pub fn load_or_create_config(_context: &Context) -> Config {
    // 1) Initialize the persistent plugin folder from WASI Context.
    // In Pumpkin, the host mounts the plugin's folder directly, it is already created.
    let data_folder = std::path::PathBuf::from(_context.get_data_folder());

    // 2) Load or create the node's unique `server.id` file.
    let id_file = data_folder.join("server.id");
    let server_id = if id_file.exists() {
        fs::read_to_string(&id_file).unwrap_or_else(|_| generate_rc_nanoid())
    } else {
        let new_id = generate_rc_nanoid();
        let _ = fs::write(&id_file, &new_id);
        new_id
    };

    // 3) Evaluate the global YAML Configuration.
    let config_path = data_folder.join(CONFIG_FILE_NAME);

    // If the config does not exist, write the default fallback and return.
    if !config_path.exists() {
        if let Err(error) = fs::write(&config_path, DEFAULT_CONFIG_CONTENT) {
            crate::log_error!(
                "Failed to generate default config file {}: {}. Falling back to defaults.",
                config_path.display(),
                error
            );
            let mut config = default_config();
            config.server_id = server_id;
            return config;
        }

        crate::log_info!(
            "Generated default RustyRust config at {} (Host path: plugins/rustyrust/config.yml)",
            config_path.display()
        );

        let mut config = default_config();
        config.server_id = server_id;
        return config;
    }

    // 4) Perform the string read sequence of an existing file.
    let raw_config = match fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(error) => {
            crate::log_error!(
                "Failed to read config file {}: {}. Falling back to defaults.",
                config_path.display(),
                error
            );
            let mut config = default_config();
            config.server_id = server_id;
            return config;
        }
    };

    // 5) Safely parse the YAML structure dynamically.
    match serde_yaml::from_str::<ConfigFile>(&raw_config) {
        Ok(parsed) => {
            let mut config = parsed.into_config();
            // Bind the file-loaded server_id to complete the configuration logic.
            config.server_id = server_id;
            config
        }
        Err(_error) => {
            // Panic/Bad-formatting fallback.
            let mut config = default_config();
            config.server_id = server_id;
            config
        }
    }
}

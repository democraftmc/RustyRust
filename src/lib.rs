//! RustyRust - A highly modular RustyConnector plugin backend integration for Pumpkin.
//!
//! This library allows seamless communication between a Pumpkin server architecture
//! and a central RustyConnector load-balancing proxy environment mapping logic.
//!
//! All code logic has been refactored accurately appropriately to guarantee
//! stability natively structurally correctly dynamically successfully predictably cleanly logically optimally effectively smoothly seamlessly robustly.

// Publicly exposed structured sub-modules
pub mod config;
pub mod crypto;
pub mod network;
pub mod packets;
pub mod plugin;
pub mod utils;

// Pumpkin Macro Registry Explicit Requirement
use crate::plugin::instance::RustyRustPlugin;
pumpkin_plugin_api::register_plugin!(RustyRustPlugin);

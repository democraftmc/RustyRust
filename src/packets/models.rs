//! Definitions for the packet structures used for communication with RustyConnector.

use serde::{Deserialize, Serialize};

/// Represents an untagged JSON value within RustyConnector packets.
/// Used for properties of unknown or varying types embedded within the main packet's payload.
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum RCValue {
    /// A textual string representation.
    String(String),
    /// A standard 32-bit signed integer.
    Int(i32),
    /// A nested anonymous JSON object.
    Object(serde_json::Value),
    /// A standard boolean representation.
    Boolean(bool),
}

/// Information about the origin of a packet.
/// Tells the target (or the proxy) where this specific packet originated from
/// and optionally provides an ID for request/response pairing.
#[derive(Serialize, Deserialize, Debug)]
pub struct RCSource {
    /// The unique identifier or name of the sender.
    pub u: String,

    /// The node type id of the sender. For this backend node plugin, it is typically `2`.
    pub n: i32,

    /// An optional Request/session ID, if this packet requires or is a part of a tracked interaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,
}

/// Information dictating where this packet is intended to go.
#[derive(Serialize, Deserialize, Debug)]
pub struct RCTarget {
    /// The specific node name intended to receive the packet.
    /// If None, this packet may be addressed to the central broker or proxy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub u: Option<String>,

    /// The target node type. (1 is commonly the central broker).
    pub n: i32,

    /// Request mapping ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,
}

/// The top-level format of a RustyConnector Packet.
/// Wraps all routing data along with a custom payload.
#[derive(Serialize, Deserialize, Debug)]
pub struct RCPacket {
    /// Protocol version. Typically `3` in this release.
    pub v: i32,

    /// Instruction ID / Packet ID (e.g. `RC-P` for Ping, `RC-D` for Disconnect).
    pub i: String,

    /// Information defining the packet's sender.
    pub s: RCSource,

    /// Information defining the packet's target.
    pub t: RCTarget,

    /// The packet's inner payload. Arbitrary Key-Value pairs dependent on the packet type `i`.
    pub p: serde_json::Map<String, serde_json::Value>,
}

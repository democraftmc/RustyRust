//! Packet structure specifications for MagicLink Version 3 Protocol.
use nanoid::nanoid;
use serde::{Deserialize, Serialize};
/// Dynamic value parsing enum inside parameters.
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum RCValue {
    String(String),
    Int(i32),
    Object(serde_json::Value),
    Boolean(bool),
}
/// Identification block for the origin machine.
#[derive(Serialize, Deserialize, Debug)]
pub struct RCSource {
    pub u: String,
    pub n: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,
}
/// Identification block for the target machine.
#[derive(Serialize, Deserialize, Debug)]
pub struct RCTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub u: Option<String>,
    pub n: i32,
}
/// Top-level Packet representation sent/received over WebSocket.
#[derive(Serialize, Deserialize, Debug)]
pub struct RCPacket {
    pub v: i32,
    pub i: String,
    pub s: RCSource,
    pub t: RCTarget,
    pub p: serde_json::Map<String, serde_json::Value>,
}
impl RCPacket {
    /// Creates a new MagicLink Protocol V3 packet.
    ///
    /// # Arguments
    /// * `id` - The semantic identity of the packet (e.g. `RC-P`).
    /// * `source_id` - Our Server's identification string.
    /// * `target_id` - Optional Target specific routing identifier.
    /// * `reply` - Determines whether a short NanoID should be baked securely to await a reply.
    pub fn new(id: &str, source_id: &str, target_id: Option<String>, reply: bool) -> Self {
        RCPacket {
            v: 3,
            i: id.to_string(),
            s: RCSource {
                u: source_id.to_string(),
                n: 2,
                r: if reply { Some(nanoid!()) } else { None },
            },
            t: RCTarget { u: target_id, n: 1 },
            p: serde_json::Map::new(),
        }
    }
}

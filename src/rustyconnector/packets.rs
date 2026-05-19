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
                n: 2, // Origin::SERVER
                r: if reply { Some(nanoid!()) } else { None },
            },
            t: RCTarget {
                u: target_id,
                n: 1 // Origin::ANY_PROXY
            },
            p: serde_json::Map::new(),
        }
    }

    /// Constructs a Ping packet to maintain the heartbeat and register the server.
    pub fn ping(source_id: &str, target_family: &str, address: &str, player_count: i32) -> Self {
        let mut packet = RCPacket {
            v: 3,
            i: "RC-P".to_string(),
            s: RCSource {
                u: source_id.to_string(),
                n: 2, // Origin::SERVER
                r: None,
            },
            t: RCTarget {
                u: None,
                n: 1 // Origin::ANY_PROXY
            },
            p: serde_json::Map::new(),
        };
        
        // Dummy metadata. Is metadata required?
        let meta = serde_json::json!({
            "softCap": 30,
            "hardCap": 40
        });
        
        packet.p.insert("tf".to_string(), serde_json::json!(target_family));
        packet.p.insert("a".to_string(), serde_json::json!(address));
        packet.p.insert("m".to_string(), meta);
        packet.p.insert("pc".to_string(), serde_json::json!(player_count));

        packet
    }
}
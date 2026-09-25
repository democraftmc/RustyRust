//! Helper methods for constructing standard RustyConnector packets.

use crate::packets::models::{RCPacket, RCSource, RCTarget};
use crate::utils::id_gen::generate_rc_nanoid;

impl RCPacket {
    /// Creates a generic new RC Packet.
    ///
    /// # Arguments
    ///
    /// * `id` - The instructions string ID for the packet (e.g. "CUSTOM-ID").
    /// * `source_id` - Our node's name/unique ID.
    /// * `target_id` - An optional string specifying the destination node.
    /// * `_reply` - Boolean flag representing if this is a reply (currently unused in implementation).
    ///
    /// # Returns
    ///
    /// * `Self` - A populated, empty-payload `RCPacket`.
    pub fn new(id: &str, source_id: &str, target_id: Option<String>, _reply: bool) -> Self {
        RCPacket {
            v: 3,
            i: id.to_string(),
            s: RCSource {
                u: source_id.to_string(),
                n: 2,
                r: Some(generate_rc_nanoid()),
            },
            t: RCTarget { u: target_id, n: 1, r: None },
            p: serde_json::Map::new(),
        }
    }

    /// Constructs an `RC-P` (Ping / Heartbeat) packet.
    /// This packet informs the proxy that this instance is still alive and provides
    /// metadata regarding its current capacity and target configuration.
    ///
    /// # Arguments
    ///
    /// * `source_id` - The name of the server/node sending the ping.
    /// * `session_id` - A unique session string used for connection tracking.
    /// * `target_family` - The grouping label defining what "family" this node serves to.
    /// * `address` - The backend IP that users should be dynamically routed to.
    /// * `player_count` - The current concurrent connection/player count.
    ///
    /// # Returns
    ///
    /// * `Self` - A fully constructed Ping packet.
    pub fn ping(
        source_id: &str,
        session_id: &str,
        target_family: &str,
        address: &str,
        player_count: i32,
        metadata: serde_json::Value,
    ) -> Self {
        let mut packet = RCPacket {
            v: 3,
            i: "RC-P".to_string(),
            s: RCSource {
                u: source_id.to_string(),
                n: 2,
                r: Some(session_id.to_string()),
            },
            t: RCTarget { u: None, n: 1, r: None },
            p: serde_json::Map::new(),
        };

        // Inject the payload arguments required by the proxy
        packet
            .p
            .insert("tf".to_string(), serde_json::json!(target_family));
        packet.p.insert("a".to_string(), serde_json::json!(address));
        packet.p.insert("m".to_string(), metadata);
        packet
            .p
            .insert("pc".to_string(), serde_json::json!(player_count));

        packet
    }

    /// Constructs an `RC-D` (Disconnect) packet.
    /// Used during a graceful shutdown sequence to tell the broker proxy
    /// that this node is purposefully disconnecting.
    ///
    /// # Arguments
    ///
    /// * `source_id` - The node's specific name to alert the proxy which node is disconnecting.
    ///
    /// # Returns
    ///
    /// * `Self` - A populated Disconnect packet.
    pub fn disconnect(source_id: &str) -> Self {
        RCPacket {
            v: 3,
            i: "RC-D".to_string(),
            s: RCSource {
                u: source_id.to_string(),
                n: 2,
                r: None,
            },
            t: RCTarget { u: None, n: 1, r: None },
            p: serde_json::Map::new(),
        }
    }

    /// Constructs an `RC-R` (Response) packet.
    /// Sent back to proxy following a proxy request (e.g. `RC-P`).
    pub fn response(source_id: &str, request_id: Option<String>, success: bool, message: &str) -> Self {
        let mut p = serde_json::Map::new();
        p.insert("s".to_string(), serde_json::json!(success));
        p.insert("r".to_string(), serde_json::json!(message));
        
        RCPacket {
            v: 3,
            i: "RC-R".to_string(),
            s: RCSource {
                u: source_id.to_string(),
                n: 2,
                r: None, 
            },
            t: RCTarget { u: None, n: 1, r: request_id },
            p,
        }
    }

}

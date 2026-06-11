use nanoid::nanoid;
use serde::{Deserialize, Serialize};

const ALPHABET: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];

pub fn generate_rc_nanoid() -> String {
    nanoid!(16, ALPHABET)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum RCValue {
    String(String),
    Int(i32),
    Object(serde_json::Value),
    Boolean(bool),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RCSource {
    pub u: String,
    pub n: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RCTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub u: Option<String>,
    pub n: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RCPacket {
    pub v: i32,
    pub i: String,
    pub s: RCSource,
    pub t: RCTarget,
    pub p: serde_json::Map<String, serde_json::Value>,
}

impl RCPacket {
    pub fn new(id: &str, source_id: &str, target_id: Option<String>, _reply: bool) -> Self {
        RCPacket {
            v: 3,
            i: id.to_string(),
            s: RCSource {
                u: source_id.to_string(),
                n: 2,
                r: Some(generate_rc_nanoid()),
            },
            t: RCTarget {
                u: target_id,
                n: 1
            },
            p: serde_json::Map::new(),
        }
    }

    pub fn ping(source_id: &str, session_id: &str, target_family: &str, address: &str, player_count: i32) -> Self {
        let mut packet = RCPacket {
            v: 3,
            i: "RC-P".to_string(),
            s: RCSource {
                u: source_id.to_string(),
                n: 2,
                r: Some(session_id.to_string()),
            },
            t: RCTarget {
                u: None,
                n: 1
            },
            p: serde_json::Map::new(),
        };

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
    
    pub fn disconnect(source_id: &str) -> Self {
        RCPacket {
            v: 3,
            i: "RC-D".to_string(),
            s: RCSource {
                u: source_id.to_string(),
                n: 2,
                r: None,
            },
            t: RCTarget {
                u: None,
                n: 1,
            },
            p: serde_json::Map::new(),
        }
    }
}
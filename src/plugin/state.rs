//! Internal logical management properties governing module lifecycles.

/// Thread-safe standard definition wrapper for an Active HTTP Web Socket stream
/// utilized globally within the plugin logic.
pub type SharedSocket = std::sync::Arc<
    std::sync::Mutex<
        tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    >,
>;

/// Stateful context variables injected, bound, maintained, and safely modified
/// throughout the entirety of a rusty server's active runtime duration.
#[derive(Default)]
pub struct PluginState {
    /// Scheduled background task references matching Pumpkin context allocations.
    pub task_id: Option<u32>,

    /// Global networking state encapsulating the active proxy tunnel.
    pub socket: Option<SharedSocket>,

    /// The normalized key byte sequence maintained post-parsing for instant processing mapping.
    pub aes_key: Option<[u8; 32]>,

    /// Stored active reference mapping to gracefully broadcast final disconnect sequences accurately.
    pub server_name: Option<String>,
}

//! Contains complex logic used for dynamically attaching to a proxy WebSocket environment.

use crate::network::node::BackendNode;
use crate::network::tasks::process_websocket_tick;
use crate::plugin::state::PluginState;
use crate::utils::id_gen::generate_rc_nanoid;
use pumpkin_plugin_api::Context;
use pumpkin_plugin_api::scheduler::SchedulerExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use tungstenite::client::IntoClientRequest;
use tungstenite::connect;
use tungstenite::http::header::{AUTHORIZATION, HeaderName, HeaderValue};

impl BackendNode {
    /// Upgrades the initial verification handshake sequence into an active persistent WebSocket.
    /// Manages the setup, HTTP 1.1 upgrade configurations, session identifiers, TLS validation,
    /// socket wrapping mechanisms, background poller scheduling, and state linking.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The decoded verification URL string response returned by preflight.
    /// * `compound_token` - A newly encapsulated hashed Token ensuring specific socket connection rights.
    /// * `context` - The Server Plugin API `Context` allowing node interaction and polling generation.
    /// * `backend_ip` - Config property reflecting to proxy traffic correctly.
    /// * `target_family` - Config property categorizing mapping traffic environments dynamically.
    /// * `state` - Secure state map wrapper mutating the application with active properties later.
    ///
    /// # Returns
    ///
    /// * `anyhow::Result<()>` - Void success or mapped breakdown exception if bridging failed structurally.
    pub fn connect_websocket(
        &self,
        endpoint: &str,
        compound_token: &str,
        context: &Context,
        backend_ip: &str,
        target_family: &str,
        state: std::sync::Arc<std::sync::Mutex<PluginState>>,
    ) -> anyhow::Result<()> {
        let ws_url = format!("ws://{}/{}", self.proxy_url, endpoint);
        crate::log_info!("Connecting to WebSocket at: {}", ws_url);

        // Apply headers
        let mut request = ws_url.into_client_request()?;
        let headers = request.headers_mut();

        // Pass the dynamically signed compound Token dynamically.
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", compound_token))?,
        );

        // Construct server context authentication json
        let identification_json = serde_json::json!({
            "u": self.server_name,
            "n": 2
        })
        .to_string();

        headers.insert(
            HeaderName::from_static("x-server-identification"),
            HeaderValue::from_str(&identification_json)?,
        );

        // Blocking negotiation step logic natively.
        let (mut socket, response) = connect(request)?;
        crate::log_info!("WebSocket connected! HTTP Status: {}", response.status());

        // Validate socket environments correctly
        match socket.get_mut() {
            tungstenite::stream::MaybeTlsStream::Plain(s) => s.set_nonblocking(true)?,
            _ => crate::log_warn!(
                "WSS TLS streams might require inner stream configuration to be non-blocking!"
            ),
        }

        // Shared states creation mapping over arc boundaries specifically.
        let shared_socket = std::sync::Arc::new(std::sync::Mutex::new(socket));
        let closure_socket = shared_socket.clone();

        let server_name = self.server_name.clone();
        let backend_ip = backend_ip.to_string();
        let target_family = target_family.to_string();
        let key = self.key;
        let session_id = generate_rc_nanoid();

        let ticks_since_last_ping = Arc::new(AtomicU64::new(200));
        let ping_interval_ticks = Arc::new(AtomicU64::new(200));
        let is_closed = Arc::new(AtomicBool::new(false));
        let task_id = Arc::new(AtomicU32::new(0));

        let closure_ticks = ticks_since_last_ping.clone();
        let closure_interval = ping_interval_ticks.clone();
        let closure_is_closed = is_closed.clone();
        let closure_task_id = task_id.clone();

        // Use scheduler logic
        let scheduled_id = context.schedule_repeating_task(1, 1, move |_server| {
            process_websocket_tick(
                &closure_socket,
                &closure_ticks,
                &closure_interval,
                &closure_is_closed,
                &closure_task_id,
                &server_name,
                &session_id,
                &target_family,
                &backend_ip,
                &key,
            );
        });

        task_id.store(scheduled_id, Ordering::Relaxed);

        // Complete mutations
        if let Ok(mut st) = state.lock() {
            st.task_id = Some(scheduled_id);
            st.socket = Some(shared_socket);
            st.aes_key = Some(self.key);
            st.server_name = Some(self.server_name.clone());
        }

        Ok(())
    }
}

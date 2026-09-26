//! The desktop app's embedded local API stack, extracted from
//! plain-desktop's `src-tauri/local/*`: async-graphql schema + executor,
//! hand-rolled HTTP/WS/TLS server, chat wiring, peer status, nearby
//! discovery, DLNA receiver, downloads and link previews. The Tauri
//! crate consumes this and stays a thin shell (commands + capture).
//!
//! Host integration goes through [`ShellHooks`] — everything the stack
//! needs from its host (persisted preferences, UI notifications, app
//! metadata) instead of a windowing-framework handle.

pub mod chat;
pub mod context;
pub mod db;
pub mod discover;
pub mod dlna;
pub mod download;
pub mod enums;
pub mod executor;
pub mod link_preview;
pub mod peer_graphql;
pub mod schema;
pub mod server;
pub mod tls;

pub use context::ShellHooks;

use crate::{base64_encode, ed25519_generate, short_uuid};

/// Persistent device identity loaded from the host's preferences store.
#[derive(Clone, Debug)]
pub struct AppIdentity {
    pub client_id: String,
    pub device_name: String,
    /// Base64-encoded Ed25519 keypair bytes (64 bytes: private || public).
    pub ed25519_keypair: String,
}

/// Default device name shown on first run (before the user renames):
/// "Plain-<short uuid>".
pub fn default_device_name() -> String {
    format!("Plain-{}", short_uuid::short_uuid())
}

/// Build a fresh device identity (first run). The host persists the three
/// fields under the keys `client_id` / `device_name` /
/// `signature_key_pair`.
pub fn generate_identity() -> AppIdentity {
    let (kp, _) = ed25519_generate();
    AppIdentity {
        client_id: short_uuid::short_uuid(),
        device_name: default_device_name(),
        ed25519_keypair: base64_encode(&kp),
    }
}

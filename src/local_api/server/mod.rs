//! Hand-rolled HTTP/1.1 + WebSocket + TLS server pieces for the local
//! API stack (no axum): request routing, file serving, proxying,
//! uploads, and the WS handlers. The listener loop and port rebinding
//! live in the host (`plain-desktop`'s `local/server/mod.rs`) because
//! they are glued to the host's lifecycle.

pub mod file_server;
pub mod http_handler;
pub mod plain_conn;
pub mod proxy_file;
pub mod response;
pub mod tls_conn;
pub mod upload;
pub mod uri;
pub mod ws_handler;

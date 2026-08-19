//! Lightweight mDNS responder — single receive socket, standards-aware reply.
//!
//! RECEIVE: One socket bound to 0.0.0.0:5353 joins 224.0.0.251 on every valid
//! LAN interface.
//!
//! SEND: Replies are sent via the same socket so the source port is always
//! 5353. RFC 6762 §6.7 requires this — resolvers silently discard mDNS
//! responses whose source port ≠ 5353. QU/legacy-unicast queries are answered
//! directly; ordinary multicast queries are answered to 224.0.0.251:5353.

use super::packet_codec::{self, MdnsResponse};
use super::service_info::MdnsServiceInfo;
use super::service_response_builder;
use if_addrs::{IfAddr, Interface};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const RECEIVE_TIMEOUT_MS: u64 = 1_000;
const RECV_BUF_SIZE: usize = 1500;

pub type PacketListener = Arc<dyn Fn(&[u8], &str) + Send + Sync>;

struct Inner {
    hostname: RwLock<String>,
    service_info: RwLock<Option<MdnsServiceInfo>>,
    socket: RwLock<Option<Arc<std::net::UdpSocket>>>,
    running: AtomicBool,
    listeners: RwLock<Vec<PacketListener>>,
}

static INNER: Inner = Inner {
    hostname: RwLock::new(String::new()),
    service_info: RwLock::new(None),
    socket: RwLock::new(None),
    running: AtomicBool::new(false),
    listeners: RwLock::new(Vec::new()),
};

/// Whether any external (non-local) packet reached the shared multicast
/// socket since the last `take_external_multicast_seen` call.
static SAW_EXTERNAL_MULTICAST: AtomicBool = AtomicBool::new(false);

/// Dedicated QU query socket (ephemeral port), lazily created.
static QU_SOCKET: RwLock<Option<Arc<std::net::UdpSocket>>> = RwLock::new(None);

/// Takes (reads and resets) the external-multicast-seen flag. The browser
/// polls this every scan cycle: no external multicast means the receive path
/// is dead (e.g. a router dropping cross-band multicast) and QU queries must
/// take over.
pub fn take_external_multicast_seen() -> bool {
    SAW_EXTERNAL_MULTICAST.swap(false, Ordering::Relaxed)
}

pub fn is_running() -> bool {
    INNER.running.load(Ordering::SeqCst) && INNER.socket.read().unwrap().is_some()
}

/// Starts the mDNS responder. `service` advertises the PlainApp service
/// (PTR/SRV/TXT/A answers); when None the responder only answers A-record
/// queries for `mdns_hostname`.
pub fn start(mdns_hostname: &str, service: Option<MdnsServiceInfo>) -> bool {
    let normalized = normalize_hostname(mdns_hostname);
    if normalized.is_empty() {
        log::error!("mDNS start skipped: empty hostname");
        return false;
    }
    *INNER.hostname.write().unwrap() = normalized;
    *INNER.service_info.write().unwrap() = service;
    restart_socket()
}

/// Ensures the responder socket is up so discovery works even while the HTTP
/// service is off. When already running this keeps the current configuration.
pub fn ensure_started(mdns_hostname: &str) -> bool {
    if is_running() {
        return true;
    }
    let service = INNER.service_info.read().unwrap().clone();
    start(mdns_hostname, service)
}

/// Recreates the socket after a network change, preserving hostname/service
/// config. mDNS multicast group membership is per-interface; when the device
/// switches networks the new interface was never joined, so the old socket
/// stops receiving multicast until it is recreated.
pub fn restart_socket() -> bool {
    tear_down_socket();
    let hostname = INNER.hostname.read().unwrap().clone();
    if hostname.is_empty() {
        return false;
    }

    let candidates = candidate_interfaces();
    if candidates.is_empty() {
        log::error!("mDNS: no candidate interfaces found");
        return false;
    }

    let socket = match create_mdns_socket() {
        Ok(s) => s,
        Err(e) => {
            log::error!("mDNS socket create failed: {e}");
            return false;
        }
    };

    if let Err(e) = socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into()) {
        let _ = std::net::UdpSocket::from(socket);
        log::error!("mDNS bind/join failed: {e}");
        return false;
    }
    let socket: std::net::UdpSocket = socket.into();
    let socket = Arc::new(socket);
    let mut joined = false;
    for iface in &candidates {
        match socket.join_multicast_v4(&MDNS_GROUP, &iface.ip) {
            Ok(()) => {
                joined = true;
                log::debug!("mDNS joined {}", iface.name);
            }
            Err(e) => log::error!("mDNS joinGroup {}: {e}", iface.name),
        }
    }
    if !joined {
        match socket.join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::UNSPECIFIED) {
            Ok(()) => log::debug!("mDNS joined (default)"),
            Err(e) => log::error!("mDNS joinGroup default: {e}"),
        }
    }

    *INNER.socket.write().unwrap() = Some(socket.clone());
    INNER.running.store(true, Ordering::SeqCst);
    let worker = Worker { socket };
    std::thread::Builder::new()
        .name("plain-mdns-responder".to_string())
        .spawn(move || worker.run_loop())
        .expect("spawn mdns responder");
    log::info!(
        "mDNS socket + receive worker started for {hostname} on {} interface(s)",
        candidates.len()
    );
    true
}

fn tear_down_socket() {
    INNER.running.store(false, Ordering::SeqCst);
    let s = INNER.socket.write().unwrap().take();
    if let Some(s) = s {
        let _ = s.leave_multicast_v4(&MDNS_GROUP, &Ipv4Addr::UNSPECIFIED);
        // Drop closes the socket; the worker's recv times out and exits.
    }
}

/// Registers a listener for every inbound mDNS packet; survives socket restarts.
pub fn add_packet_listener(listener: PacketListener) {
    let mut listeners = INNER.listeners.write().unwrap();
    if !listeners.iter().any(|l| Arc::ptr_eq(l, &listener)) {
        listeners.push(listener);
    }
}

/// Sends an mDNS query through the shared socket so responses come back on
/// port 5353 (RFC 6762 §6.7 requires the source port to be 5353).
pub fn send_query(bytes: &[u8]) {
    let Some(socket) = INNER.socket.read().unwrap().clone() else {
        log::error!("mDNS sendQuery skipped: no socket (responder not started)");
        return;
    };
    send_to_group(&socket, bytes);
}

/// Sends a QU (unicast-response requested, RFC 6762 §5.4) query through a
/// dedicated ephemeral-port socket. Broken routers drop cross-band multicast
/// while unicast still flows; the unicast responses then come back to this
/// exact socket — a 5353-bound socket could lose them to another
/// SO_REUSEPORT peer on the same machine.
pub fn send_qu_query(bytes: &[u8]) {
    let Some(socket) = ensure_qu_socket() else {
        return;
    };
    send_to_group(&socket, bytes);
}

fn send_to_group(socket: &std::net::UdpSocket, bytes: &[u8]) {
    let target = SocketAddrV4::new(MDNS_GROUP, MDNS_PORT);
    let candidates = candidate_interfaces();
    if candidates.is_empty() {
        if let Err(e) = socket.send_to(bytes, target) {
            log::error!("mDNS sendQuery: {e}");
        }
        return;
    }
    // Send once per interface: the multicast egress interface is a socket-wide
    // setting, so a single send can only leave one NIC. Picking just the first
    // candidate silently drops the query when that interface is not where the
    // peers live (e.g. Ethernet/VM bridge enumerated before Wi-Fi).
    for iface in candidates {
        let _ = socket2::SockRef::from(socket).set_multicast_if_v4(&iface.ip);
        if let Err(e) = socket.send_to(bytes, target) {
            log::error!("mDNS sendQuery {}: {e}", iface.name);
        }
    }
}

fn ensure_qu_socket() -> Option<Arc<std::net::UdpSocket>> {
    if let Some(socket) = QU_SOCKET.read().unwrap().clone() {
        return Some(socket);
    }
    let mut guard = QU_SOCKET.write().unwrap();
    if let Some(socket) = guard.clone() {
        return Some(socket);
    }
    let socket = match create_qu_socket() {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log::error!("mDNS QU socket create failed: {e}");
            return None;
        }
    };
    *guard = Some(socket.clone());
    let reader = socket.clone();
    std::thread::Builder::new()
        .name("plain-mdns-qu-reader".to_string())
        .spawn(move || qu_receive_loop(&reader))
        .expect("spawn mdns qu reader");
    Some(socket)
}

fn qu_receive_loop(socket: &std::net::UdpSocket) {
    let mut buf = [0u8; RECV_BUF_SIZE];
    loop {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let std::net::IpAddr::V4(v4) = src.ip() {
                    notify_packet_listeners(&buf[..n], &v4.to_string());
                }
            }
            Err(err) => {
                log::debug!("mDNS QU receive error, stopping: {err}");
                break;
            }
        }
    }
}

fn create_qu_socket() -> io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_multicast_loop_v4(false)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    Ok(socket.into())
}

fn notify_packet_listeners(bytes: &[u8], sender_ip: &str) {
    let listeners = INNER.listeners.read().unwrap().clone();
    for l in listeners {
        l(bytes, sender_ip);
    }
}

struct Worker {
    socket: Arc<std::net::UdpSocket>,
}

impl Worker {
    fn run_loop(&self) {
        let _ = self
            .socket
            .set_read_timeout(Some(Duration::from_millis(RECEIVE_TIMEOUT_MS)));
        let mut buf = [0u8; RECV_BUF_SIZE];
        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((n, src)) => {
                    let sender_ip = match src.ip() {
                        std::net::IpAddr::V4(v4) => v4.to_string(),
                        std::net::IpAddr::V6(_) => continue,
                    };
                    let packet = buf[..n].to_vec();
                    let local = is_local_ip(&sender_ip);
                    // Any external packet proves the multicast receive path
                    // works; the browser polls this for QU fallback.
                    if !local {
                        SAW_EXTERNAL_MULTICAST.store(true, Ordering::Relaxed);
                    }
                    notify_packet_listeners(&packet, &sender_ip);
                    // Our own multicast packets loop back to this socket;
                    // answering them doubles traffic on every discovery cycle.
                    if local {
                        continue;
                    }
                    let fresh = candidate_interfaces();
                    if fresh.is_empty() {
                        continue;
                    }
                    let Some((response_iface, local_ip)) = find_response_iface(&sender_ip, &fresh)
                    else {
                        continue;
                    };
                    let Some(response) = build_response(&packet, &[local_ip.clone()]) else {
                        continue;
                    };
                    let use_unicast =
                        response.unicast_response_requested() || src.port() != MDNS_PORT;
                    let dest = if use_unicast {
                        src
                    } else {
                        std::net::SocketAddr::V4(SocketAddrV4::new(MDNS_GROUP, MDNS_PORT))
                    };
                    let send_result = (|| -> io::Result<()> {
                        if !use_unicast {
                            socket2::SockRef::from(&*self.socket)
                                .set_multicast_if_v4(&response_iface.ip)?;
                        }
                        self.socket.send_to(&response.bytes, dest)?;
                        Ok(())
                    })();
                    if let Err(e) = send_result {
                        log::error!("mDNS send to {sender_ip}: {e}");
                    }
                }
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.kind() == io::ErrorKind::TimedOut => {}
                Err(err) => {
                    // A non-timeout error means this worker's socket is dead
                    // (restart_socket tore it down). Exit unconditionally:
                    // running may already be true again for the NEW worker.
                    log::debug!("mDNS receive error, stopping worker: {err}");
                    break;
                }
            }
            if !INNER.running.load(Ordering::SeqCst) {
                break;
            }
        }
    }
}

/// Answers a query with the PlainApp service records when one is published,
/// otherwise falls back to the A-record hostname responder.
fn build_response(query: &[u8], ips: &[String]) -> Option<MdnsResponse> {
    let service = INNER.service_info.read().unwrap().clone();
    if let Some(mut service) = service {
        service.ips = ips.to_vec();
        let service_response = service_response_builder::build_response_if_match(query, &service)?;
        let matched_questions = packet_codec::read_questions(query)?;
        return Some(MdnsResponse {
            bytes: service_response.bytes,
            matched_questions,
        });
    }
    let hostname = INNER.hostname.read().unwrap().clone();
    packet_codec::build_response_if_match(query, &hostname, ips)
}

pub fn normalize_hostname(value: &str) -> String {
    let trimmed = value.trim().trim_matches('.').to_lowercase();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.ends_with(".local") {
        trimmed
    } else {
        format!("{trimmed}.local")
    }
}

fn create_mdns_socket() -> io::Result<socket2::Socket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_multicast_loop_v4(true)?;
    Ok(socket)
}

/// LAN interfaces with their IPv4 address, used for group join + subnet match.
pub struct MdnsIface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

pub fn candidate_interfaces() -> Vec<MdnsIface> {
    let interfaces: Vec<Interface> = if_addrs::get_if_addrs().unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    interfaces
        .into_iter()
        .filter_map(|iface| match iface.addr {
            IfAddr::V4(v4) => {
                let ip = v4.ip;
                if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
                    return None;
                }
                if !seen.insert(ip) {
                    return None;
                }
                Some(MdnsIface {
                    name: iface.name,
                    ip,
                    netmask: v4.netmask,
                })
            }
            _ => None,
        })
        .collect()
}

fn find_response_iface(sender_ip: &str, candidates: &[MdnsIface]) -> Option<(MdnsIface, String)> {
    let sender: Ipv4Addr = sender_ip.parse().ok()?;
    for iface in candidates {
        let a = u32::from(iface.ip) & u32::from(iface.netmask);
        let b = u32::from(sender) & u32::from(iface.netmask);
        if a == b {
            return Some((MdnsIface {
                name: iface.name.clone(),
                ip: iface.ip,
                netmask: iface.netmask,
            }, iface.ip.to_string()));
        }
    }
    None
}

pub fn local_ipv4_strs() -> Vec<String> {
    candidate_interfaces()
        .into_iter()
        .map(|iface| iface.ip.to_string())
        .collect()
}

/// Whether `ip` is one of this host's own IPv4 addresses. Used to ignore
/// multicast loop-back of our own queries/announcements (RFC 6762 §5.2).
pub fn is_local_ip(ip: &str) -> bool {
    candidate_interfaces()
        .into_iter()
        .any(|iface| iface.ip.to_string() == ip)
}

/// Picks the first candidate IP that shares a subnet with a local interface,
/// falling back to the first entry.
pub fn get_best_ip(ips: &[String]) -> String {
    match ips.first() {
        None => String::new(),
        Some(first) if ips.len() == 1 => first.clone(),
        Some(first) => {
            let locals = candidate_interfaces();
            for ip in ips {
                if find_response_iface(ip, &locals).is_some() {
                    return ip.clone();
                }
            }
            first.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_hostname_appends_local() {
        assert_eq!(normalize_hostname("Ab"), "ab.local");
        assert_eq!(normalize_hostname("ab.local"), "ab.local");
        assert_eq!(normalize_hostname(" AB.LOCAL. "), "ab.local");
        assert_eq!(normalize_hostname(""), "");
    }

    #[test]
    fn candidate_interfaces_exclude_loopback() {
        for iface in candidate_interfaces() {
            assert!(!iface.ip.is_loopback());
        }
    }

    #[test]
    fn find_response_iface_matches_subnet() {
        let candidates = vec![MdnsIface {
            name: "en0".to_string(),
            ip: "192.168.1.5".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
        }];
        let (iface, ip) =
            find_response_iface("192.168.1.100", &candidates).expect("same subnet");
        assert_eq!(iface.name, "en0");
        assert_eq!(ip, "192.168.1.5");
        assert!(find_response_iface("10.0.0.1", &candidates).is_none());
    }

    #[test]
    fn is_local_ip_recognizes_candidate_addresses() {
        let locals = local_ipv4_strs();
        for ip in &locals {
            assert!(is_local_ip(ip), "{ip} should be local");
        }
        // A fabricated external address is never local.
        assert!(!is_local_ip("192.0.2.1"));
        assert!(!is_local_ip(""));
    }
}

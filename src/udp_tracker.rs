use std::collections::HashMap;
use std::fmt;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::tracker::TrackerResponse;

const PROTOCOL_ID: u64 = 0x41727101980;
const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;
const RESPONSE_CONNECT_LEN: usize = 16;
const RESPONSE_HEADER_LEN: usize = 20;

/// BEP 15 specifies 15 * 2^n seconds. We use up to 3 retries (15s, 30s, 60s).
const BEP15_BASE_TIMEOUT_SECS: u64 = 15;
const BEP15_MAX_RETRIES: u32 = 3;

/// Connection IDs are valid for up to 2 minutes per BEP 15.
/// We use a conservative 60-second cache lifetime.
const CONNECTION_ID_MAX_AGE: Duration = Duration::from_secs(60);

/// Cache of connection IDs per tracker address: addr -> (connection_id, obtained_at).
static CONNECTION_CACHE: OnceLock<Mutex<HashMap<SocketAddr, (u64, Instant)>>> = OnceLock::new();

fn connection_cache() -> &'static Mutex<HashMap<SocketAddr, (u64, Instant)>> {
    CONNECTION_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Look up a cached connection ID for `addr`. Returns `Some(connection_id)` if
/// the cached entry is less than `CONNECTION_ID_MAX_AGE` old.
fn get_cached_connection_id(addr: &SocketAddr) -> Option<u64> {
    let cache = connection_cache().lock().ok()?;
    if let Some(&(id, obtained_at)) = cache.get(addr) {
        if obtained_at.elapsed() < CONNECTION_ID_MAX_AGE {
            return Some(id);
        }
    }
    None
}

/// Store a connection ID in the cache.
fn cache_connection_id(addr: SocketAddr, id: u64) {
    if let Ok(mut cache) = connection_cache().lock() {
        cache.insert(addr, (id, Instant::now()));
    }
}

/// Remove a cached connection ID (e.g. after a failed announce with stale ID).
fn clear_cached_connection_id(addr: &SocketAddr) {
    if let Ok(mut cache) = connection_cache().lock() {
        cache.remove(addr);
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    InvalidUrl,
    InvalidResponse,
    InvalidAction,
    InvalidTransaction,
    InvalidPeers,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "io error: {err}"),
            Error::InvalidUrl => write!(f, "invalid udp tracker url"),
            Error::InvalidResponse => write!(f, "invalid udp tracker response"),
            Error::InvalidAction => write!(f, "unexpected udp tracker action"),
            Error::InvalidTransaction => write!(f, "transaction id mismatch"),
            Error::InvalidPeers => write!(f, "invalid peers list"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

/// Perform a UDP connect handshake and return the connection ID.
fn udp_connect(socket: &UdpSocket) -> Result<u64, Error> {
    let transaction_id = next_transaction_id();
    let mut connect_req = [0u8; 16];
    connect_req[..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
    connect_req[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
    connect_req[12..16].copy_from_slice(&transaction_id.to_be_bytes());
    socket.send(&connect_req)?;

    let mut connect_resp = [0u8; 16];
    let n = socket.recv(&mut connect_resp)?;
    if n < RESPONSE_CONNECT_LEN {
        return Err(Error::InvalidResponse);
    }
    let action = u32::from_be_bytes([
        connect_resp[0],
        connect_resp[1],
        connect_resp[2],
        connect_resp[3],
    ]);
    if action != ACTION_CONNECT {
        return Err(Error::InvalidAction);
    }
    let resp_tx = u32::from_be_bytes([
        connect_resp[4],
        connect_resp[5],
        connect_resp[6],
        connect_resp[7],
    ]);
    if resp_tx != transaction_id {
        return Err(Error::InvalidTransaction);
    }
    let connection_id = u64::from_be_bytes([
        connect_resp[8],
        connect_resp[9],
        connect_resp[10],
        connect_resp[11],
        connect_resp[12],
        connect_resp[13],
        connect_resp[14],
        connect_resp[15],
    ]);
    Ok(connection_id)
}

/// Obtain a connection ID, using the cache when possible. On cache miss,
/// performs a fresh UDP connect and caches the result.
fn obtain_connection_id(socket: &UdpSocket, addr: &SocketAddr) -> Result<(u64, bool), Error> {
    if let Some(id) = get_cached_connection_id(addr) {
        return Ok((id, true));
    }
    let id = udp_connect(socket)?;
    cache_connection_id(*addr, id);
    Ok((id, false))
}

/// Send an announce request and parse the response.
fn send_announce(
    socket: &UdpSocket,
    connection_id: u64,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<&str>,
    numwant: u32,
) -> Result<TrackerResponse, Error> {
    let announce_tx = next_transaction_id();
    let mut announce_req = Vec::with_capacity(98);
    announce_req.extend_from_slice(&connection_id.to_be_bytes());
    announce_req.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
    announce_req.extend_from_slice(&announce_tx.to_be_bytes());
    announce_req.extend_from_slice(&info_hash);
    announce_req.extend_from_slice(&peer_id);
    announce_req.extend_from_slice(&downloaded.to_be_bytes());
    announce_req.extend_from_slice(&left.to_be_bytes());
    announce_req.extend_from_slice(&uploaded.to_be_bytes());
    announce_req.extend_from_slice(&event_code(event).to_be_bytes());
    announce_req.extend_from_slice(&0u32.to_be_bytes()); // IP address
    announce_req.extend_from_slice(&next_transaction_id().to_be_bytes()); // key
    announce_req.extend_from_slice(&numwant.to_be_bytes());
    announce_req.extend_from_slice(&port.to_be_bytes());

    socket.send(&announce_req)?;
    let mut response = [0u8; 1500];
    let n = socket.recv(&mut response)?;
    if n < RESPONSE_HEADER_LEN {
        return Err(Error::InvalidResponse);
    }
    let action = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
    if action != ACTION_ANNOUNCE {
        return Err(Error::InvalidAction);
    }
    let resp_tx = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    if resp_tx != announce_tx {
        return Err(Error::InvalidTransaction);
    }
    let interval = u32::from_be_bytes([response[8], response[9], response[10], response[11]]);
    let _leechers =
        u32::from_be_bytes([response[12], response[13], response[14], response[15]]);
    let _seeders = u32::from_be_bytes([response[16], response[17], response[18], response[19]]);

    if !(n - RESPONSE_HEADER_LEN).is_multiple_of(6) {
        return Err(Error::InvalidPeers);
    }
    let mut peers = Vec::with_capacity((n - RESPONSE_HEADER_LEN) / 6);
    let mut pos = RESPONSE_HEADER_LEN;
    while pos + 6 <= n {
        let ip = std::net::Ipv4Addr::new(
            response[pos],
            response[pos + 1],
            response[pos + 2],
            response[pos + 3],
        );
        let port = u16::from_be_bytes([response[pos + 4], response[pos + 5]]);
        peers.push(SocketAddr::from((ip, port)));
        pos += 6;
    }

    Ok(TrackerResponse {
        interval: interval as u64,
        peers,
    })
}

/// Returns true if `err` is a timeout / WouldBlock I/O error.
fn is_timeout(err: &Error) -> bool {
    matches!(
        err,
        Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut
                      || e.kind() == std::io::ErrorKind::WouldBlock
    )
}

#[allow(clippy::too_many_arguments)]
pub fn announce(
    url: &str,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<&str>,
    numwant: u32,
) -> Result<TrackerResponse, Error> {
    let addr = parse_udp_url(url)?;
    let bind_addr: &str = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(addr)?;

    let mut last_err: Option<Error> = None;

    for attempt in 0..BEP15_MAX_RETRIES {
        let timeout = Duration::from_secs(BEP15_BASE_TIMEOUT_SECS * (1 << attempt));
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;

        // Obtain connection ID (cached or fresh).
        let (connection_id, was_cached) = match obtain_connection_id(&socket, &addr) {
            Ok(pair) => pair,
            Err(e) if is_timeout(&e) => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        };

        // Attempt the announce.
        match send_announce(
            &socket,
            connection_id,
            info_hash,
            peer_id,
            port,
            uploaded,
            downloaded,
            left,
            event,
            numwant,
        ) {
            Ok(resp) => return Ok(resp),
            Err(e) if is_timeout(&e) => {
                // If we used a cached ID, it might be stale -- clear and retry.
                if was_cached {
                    clear_cached_connection_id(&addr);
                }
                last_err = Some(e);
                continue;
            }
            Err(e) => {
                // Non-timeout error with cached ID: clear cache and retry once
                // with a fresh connect.
                if was_cached {
                    clear_cached_connection_id(&addr);
                    // Try fresh connect + announce in the next iteration.
                    last_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }

    Err(last_err.unwrap_or(Error::InvalidResponse))
}

const ACTION_SCRAPE: u32 = 2;

#[derive(Debug, Clone)]
pub struct ScrapeResult {
    pub seeders: u32,
    pub leechers: u32,
    #[allow(dead_code)]
    pub completed: u32,
}

/// Send a scrape request and parse the response.
fn send_scrape(
    socket: &UdpSocket,
    connection_id: u64,
    info_hash: [u8; 20],
) -> Result<ScrapeResult, Error> {
    let scrape_tx = next_transaction_id();
    let mut scrape_req = Vec::with_capacity(36);
    scrape_req.extend_from_slice(&connection_id.to_be_bytes());
    scrape_req.extend_from_slice(&ACTION_SCRAPE.to_be_bytes());
    scrape_req.extend_from_slice(&scrape_tx.to_be_bytes());
    scrape_req.extend_from_slice(&info_hash);
    socket.send(&scrape_req)?;

    let mut response = [0u8; 128];
    let n = socket.recv(&mut response)?;
    if n < 20 {
        return Err(Error::InvalidResponse);
    }
    let action = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
    if action != ACTION_SCRAPE {
        return Err(Error::InvalidAction);
    }
    let resp_tx = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    if resp_tx != scrape_tx {
        return Err(Error::InvalidTransaction);
    }
    let seeders = u32::from_be_bytes([response[8], response[9], response[10], response[11]]);
    let completed = u32::from_be_bytes([response[12], response[13], response[14], response[15]]);
    let leechers = u32::from_be_bytes([response[16], response[17], response[18], response[19]]);

    Ok(ScrapeResult {
        seeders,
        leechers,
        completed,
    })
}

pub fn scrape(url: &str, info_hash: [u8; 20]) -> Result<ScrapeResult, Error> {
    let addr = parse_udp_url(url)?;
    let bind_addr: &str = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(addr)?;

    let mut last_err: Option<Error> = None;

    for attempt in 0..BEP15_MAX_RETRIES {
        let timeout = Duration::from_secs(BEP15_BASE_TIMEOUT_SECS * (1 << attempt));
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;

        let (connection_id, was_cached) = match obtain_connection_id(&socket, &addr) {
            Ok(pair) => pair,
            Err(e) if is_timeout(&e) => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        };

        match send_scrape(&socket, connection_id, info_hash) {
            Ok(resp) => return Ok(resp),
            Err(e) if is_timeout(&e) => {
                if was_cached {
                    clear_cached_connection_id(&addr);
                }
                last_err = Some(e);
                continue;
            }
            Err(e) => {
                if was_cached {
                    clear_cached_connection_id(&addr);
                    last_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }

    Err(last_err.unwrap_or(Error::InvalidResponse))
}

fn parse_udp_url(url: &str) -> Result<SocketAddr, Error> {
    let rest = url.strip_prefix("udp://").ok_or(Error::InvalidUrl)?;
    let host_port = rest.split_once('/').map(|(host, _)| host).unwrap_or(rest);
    if host_port.is_empty() {
        return Err(Error::InvalidUrl);
    }
    let addr = host_port
        .to_socket_addrs()
        .map_err(Error::Io)?
        .next()
        .ok_or(Error::InvalidUrl)?;
    Ok(addr)
}

fn event_code(event: Option<&str>) -> u32 {
    match event {
        Some("completed") => 1,
        Some("started") => 2,
        Some("stopped") => 3,
        _ => 0,
    }
}

fn next_transaction_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    static SEED: AtomicU32 = AtomicU32::new(0x1234_5678);
    INIT.get_or_init(|| {
        SEED.store(crate::system_entropy_u64() as u32, Ordering::Relaxed);
    });
    let mut x = SEED.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    SEED.store(x, Ordering::Relaxed);
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_udp_url_accepts_tracker_path() {
        let addr = parse_udp_url("udp://127.0.0.1:6969/announce").unwrap();
        assert_eq!(addr.port(), 6969);
    }

    #[test]
    fn parse_udp_url_rejects_invalid_urls() {
        assert!(matches!(
            parse_udp_url("http://127.0.0.1:6969"),
            Err(Error::InvalidUrl)
        ));
        assert!(matches!(parse_udp_url("udp://"), Err(Error::InvalidUrl)));
    }

    #[test]
    fn event_code_maps_known_events() {
        assert_eq!(event_code(None), 0);
        assert_eq!(event_code(Some("completed")), 1);
        assert_eq!(event_code(Some("started")), 2);
        assert_eq!(event_code(Some("stopped")), 3);
        assert_eq!(event_code(Some("other")), 0);
    }

    #[test]
    fn connection_cache_roundtrip() {
        let addr: SocketAddr = "127.0.0.1:6969".parse().unwrap();
        clear_cached_connection_id(&addr);
        assert!(get_cached_connection_id(&addr).is_none());
        cache_connection_id(addr, 42);
        assert_eq!(get_cached_connection_id(&addr), Some(42));
        clear_cached_connection_id(&addr);
        assert!(get_cached_connection_id(&addr).is_none());
    }

    #[test]
    fn bep15_timeout_schedule() {
        for attempt in 0..BEP15_MAX_RETRIES {
            let timeout_secs = BEP15_BASE_TIMEOUT_SECS * (1 << attempt);
            let expected = [15, 30, 60][attempt as usize];
            assert_eq!(timeout_secs, expected);
        }
    }
}

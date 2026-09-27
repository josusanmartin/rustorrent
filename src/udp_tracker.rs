use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::tracker::{sanitize_failure_reason, TrackerResponse};

const PROTOCOL_ID: u64 = 0x41727101980;
const ACTION_CONNECT: u32 = 0;
const ACTION_ANNOUNCE: u32 = 1;
const RESPONSE_CONNECT_LEN: usize = 16;
const RESPONSE_HEADER_LEN: usize = 20;
const ACTION_ERROR: u32 = 3;
const MAX_CONNECTION_CACHE_ENTRIES: usize = 1024;
#[cfg(test)]
const UDP_TRACKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// BEP 15 specifies 15 * 2^n seconds. We use up to 3 retries (15s, 30s, 60s).
const BEP15_BASE_TIMEOUT_SECS: u64 = 15;
const BEP15_MAX_RETRIES: u32 = 3;

/// Connection IDs are valid for up to 2 minutes per BEP 15.
/// We use a conservative 60-second cache lifetime.
const CONNECTION_ID_MAX_AGE: Duration = Duration::from_secs(60);

/// Cache of connection IDs per tracker address: addr -> (connection_id, obtained_at).
static CONNECTION_CACHE: OnceLock<Mutex<HashMap<SocketAddr, (u64, Instant)>>> = OnceLock::new();
type AnnounceKeyCache = HashMap<(String, [u8; 20]), (u32, Instant)>;
static ANNOUNCE_KEY_CACHE: OnceLock<Mutex<AnnounceKeyCache>> = OnceLock::new();

fn connection_cache() -> &'static Mutex<HashMap<SocketAddr, (u64, Instant)>> {
    CONNECTION_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn announce_key_cache() -> &'static Mutex<AnnounceKeyCache> {
    ANNOUNCE_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn announce_key_for_url(url: &str, info_hash: [u8; 20]) -> u32 {
    let authority = url
        .strip_prefix("udp://")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or(url)
        .to_ascii_lowercase();
    let now = Instant::now();
    if let Ok(mut cache) = announce_key_cache().lock() {
        let cache_key = (authority, info_hash);
        if let Some((key, last_used)) = cache.get_mut(&cache_key) {
            *last_used = now;
            return *key;
        }
        if cache.len() >= MAX_CONNECTION_CACHE_ENTRIES {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (_, last_used))| *last_used)
                .map(|(cache_key, _)| cache_key.clone())
            {
                cache.remove(&oldest);
            }
        }
        let mut key = next_transaction_id();
        for _ in 0..=MAX_CONNECTION_CACHE_ENTRIES {
            if cache.values().all(|(existing, _)| *existing != key) {
                break;
            }
            key = next_transaction_id();
        }
        cache.insert(cache_key, (key, now));
        key
    } else {
        next_transaction_id()
    }
}

/// Look up a cached connection ID for `addr`. Returns `Some(connection_id)` if
/// the cached entry is less than `CONNECTION_ID_MAX_AGE` old.
fn get_cached_connection_id(addr: &SocketAddr) -> Option<u64> {
    let mut cache = connection_cache().lock().ok()?;
    if let Some(&(id, obtained_at)) = cache.get(addr) {
        if obtained_at.elapsed() < CONNECTION_ID_MAX_AGE {
            return Some(id);
        }
    }
    cache.remove(addr);
    None
}

/// Store a connection ID in the cache.
fn cache_connection_id(addr: SocketAddr, id: u64) {
    if let Ok(mut cache) = connection_cache().lock() {
        cache.retain(|_, (_, obtained_at)| obtained_at.elapsed() < CONNECTION_ID_MAX_AGE);
        if cache.len() >= MAX_CONNECTION_CACHE_ENTRIES && !cache.contains_key(&addr) {
            if let Some(oldest) = cache
                .iter()
                .max_by_key(|(_, (_, obtained_at))| obtained_at.elapsed())
                .map(|(addr, _)| *addr)
            {
                cache.remove(&oldest);
            }
        }
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
    Timeout,
    FailureReason(String),
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
            Error::Timeout => write!(f, "udp tracker request deadline exceeded"),
            Error::FailureReason(reason) => write!(f, "tracker failure: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

#[derive(Clone, Copy)]
struct RequestBudget {
    deadline: Instant,
}

impl RequestBudget {
    fn new(deadline: Instant) -> Self {
        Self { deadline }
    }

    fn remaining(self) -> Result<Duration, Error> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(Error::Timeout)
    }

    fn configure_socket(self, socket: &UdpSocket, attempt_timeout: Duration) -> Result<(), Error> {
        let timeout = self.remaining()?.min(attempt_timeout);
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        Ok(())
    }

    fn for_attempt(self, attempt_timeout: Duration) -> Result<Self, Error> {
        let remaining = self.remaining()?;
        Ok(Self {
            deadline: Instant::now() + remaining.min(attempt_timeout),
        })
    }
}

/// Perform a UDP connect handshake and return the connection ID.
fn udp_connect(
    socket: &UdpSocket,
    budget: RequestBudget,
    attempt_timeout: Duration,
    transaction_id: u32,
) -> Result<u64, Error> {
    let attempt = budget.for_attempt(attempt_timeout)?;
    let mut connect_req = [0u8; 16];
    connect_req[..8].copy_from_slice(&PROTOCOL_ID.to_be_bytes());
    connect_req[8..12].copy_from_slice(&ACTION_CONNECT.to_be_bytes());
    connect_req[12..16].copy_from_slice(&transaction_id.to_be_bytes());
    attempt.configure_socket(socket, attempt_timeout)?;
    socket.send(&connect_req)?;

    let mut connect_resp = [0u8; 1500];
    loop {
        attempt.configure_socket(socket, attempt_timeout)?;
        let n = socket.recv(&mut connect_resp)?;
        if n < 8 {
            continue;
        }
        let resp_tx = u32::from_be_bytes([
            connect_resp[4],
            connect_resp[5],
            connect_resp[6],
            connect_resp[7],
        ]);
        if resp_tx != transaction_id {
            continue;
        }
        let action = u32::from_be_bytes([
            connect_resp[0],
            connect_resp[1],
            connect_resp[2],
            connect_resp[3],
        ]);
        if action == ACTION_ERROR {
            return Err(parse_error_response(&connect_resp[..n], transaction_id));
        }
        if action != ACTION_CONNECT {
            return Err(Error::InvalidAction);
        }
        if n < RESPONSE_CONNECT_LEN {
            return Err(Error::InvalidResponse);
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
        return Ok(connection_id);
    }
}

/// Obtain a connection ID, using the cache when possible. On cache miss,
/// performs a fresh UDP connect and caches the result.
fn obtain_connection_id(
    socket: &UdpSocket,
    addr: &SocketAddr,
    budget: RequestBudget,
    attempt_timeout: Duration,
    connect_transaction_id: u32,
) -> Result<(u64, bool), Error> {
    if let Some(id) = get_cached_connection_id(addr) {
        return Ok((id, true));
    }
    let id = udp_connect(socket, budget, attempt_timeout, connect_transaction_id)?;
    cache_connection_id(*addr, id);
    Ok((id, false))
}

/// Send an announce request and parse the response.
#[allow(clippy::too_many_arguments)]
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
    budget: RequestBudget,
    attempt_timeout: Duration,
    announce_tx: u32,
    announce_key: u32,
) -> Result<TrackerResponse, Error> {
    let attempt = budget.for_attempt(attempt_timeout)?;
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
    announce_req.extend_from_slice(&announce_key.to_be_bytes());
    announce_req.extend_from_slice(&numwant.to_be_bytes());
    announce_req.extend_from_slice(&port.to_be_bytes());

    attempt.configure_socket(socket, attempt_timeout)?;
    socket.send(&announce_req)?;
    let mut response = [0u8; 1500];
    let ipv6 = socket.peer_addr()?.is_ipv6();
    loop {
        attempt.configure_socket(socket, attempt_timeout)?;
        let n = socket.recv(&mut response)?;
        if n < 8 {
            continue;
        }
        let response_tx = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
        if response_tx != announce_tx {
            continue;
        }
        return parse_announce_response(&response[..n], announce_tx, ipv6);
    }
}

fn parse_announce_response(
    response: &[u8],
    announce_tx: u32,
    ipv6: bool,
) -> Result<TrackerResponse, Error> {
    let n = response.len();
    if n < 8 {
        return Err(Error::InvalidResponse);
    }
    let action = u32::from_be_bytes([response[0], response[1], response[2], response[3]]);
    if action == ACTION_ERROR {
        return Err(parse_error_response(&response[..n], announce_tx));
    }
    if n < RESPONSE_HEADER_LEN {
        return Err(Error::InvalidResponse);
    }
    if action != ACTION_ANNOUNCE {
        return Err(Error::InvalidAction);
    }
    let resp_tx = u32::from_be_bytes([response[4], response[5], response[6], response[7]]);
    if resp_tx != announce_tx {
        return Err(Error::InvalidTransaction);
    }
    let interval = u32::from_be_bytes([response[8], response[9], response[10], response[11]]);
    let _leechers = u32::from_be_bytes([response[12], response[13], response[14], response[15]]);
    let _seeders = u32::from_be_bytes([response[16], response[17], response[18], response[19]]);

    let stride = if ipv6 { 18 } else { 6 };
    if !(n - RESPONSE_HEADER_LEN).is_multiple_of(stride) {
        return Err(Error::InvalidPeers);
    }
    let mut peers = Vec::with_capacity((n - RESPONSE_HEADER_LEN) / stride);
    let mut pos = RESPONSE_HEADER_LEN;
    while pos + stride <= n {
        let (ip, port) = if ipv6 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&response[pos..pos + 16]);
            (
                std::net::IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([response[pos + 16], response[pos + 17]]),
            )
        } else {
            (
                std::net::IpAddr::V4(Ipv4Addr::new(
                    response[pos],
                    response[pos + 1],
                    response[pos + 2],
                    response[pos + 3],
                )),
                u16::from_be_bytes([response[pos + 4], response[pos + 5]]),
            )
        };
        pos += stride;
        if port != 0 {
            peers.push(SocketAddr::new(ip, port));
        }
    }

    Ok(TrackerResponse {
        interval: interval as u64,
        peers,
        external_ip: None,
    })
}

/// Returns true if `err` is a timeout / WouldBlock I/O error.
fn is_timeout(err: &Error) -> bool {
    matches!(err, Error::Timeout)
        || matches!(
            err,
            Error::Io(e) if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock
        )
}

#[cfg(test)]
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
    announce_until(
        url,
        info_hash,
        peer_id,
        port,
        uploaded,
        downloaded,
        left,
        event,
        numwant,
        Instant::now() + UDP_TRACKER_REQUEST_TIMEOUT,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn announce_until(
    url: &str,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<&str>,
    numwant: u32,
    deadline: Instant,
) -> Result<TrackerResponse, Error> {
    let global_budget = RequestBudget::new(deadline);
    let addrs = parse_udp_urls_with_budget(url, global_budget)?;
    let announce_key = announce_key_for_url(url, info_hash);
    announce_to_addrs(
        &addrs,
        info_hash,
        peer_id,
        port,
        uploaded,
        downloaded,
        left,
        event,
        numwant,
        global_budget,
        announce_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn announce_to_addrs(
    addrs: &[SocketAddr],
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<&str>,
    numwant: u32,
    global_budget: RequestBudget,
    announce_key: u32,
) -> Result<TrackerResponse, Error> {
    let mut last_err = None;
    for (index, addr) in addrs.iter().copied().enumerate() {
        let candidate_budget = split_candidate_budget(global_budget, addrs.len() - index)?;
        match announce_to_addr(
            addr,
            info_hash,
            peer_id,
            port,
            uploaded,
            downloaded,
            left,
            event,
            numwant,
            candidate_budget,
            announce_key,
        ) {
            Ok(response) => return Ok(response),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or(Error::InvalidUrl))
}

fn split_candidate_budget(
    global_budget: RequestBudget,
    remaining_candidates: usize,
) -> Result<RequestBudget, Error> {
    let remaining = global_budget.remaining()?;
    let share = if remaining_candidates > 1 {
        remaining / (remaining_candidates as u32)
    } else {
        remaining
    };
    if share.is_zero() {
        return Err(Error::Timeout);
    }
    Ok(RequestBudget::new(Instant::now() + share))
}

#[allow(clippy::too_many_arguments)]
fn announce_to_addr(
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<&str>,
    numwant: u32,
    budget: RequestBudget,
    announce_key: u32,
) -> Result<TrackerResponse, Error> {
    budget.remaining()?;
    let bind_addr: &str = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(addr)?;

    let mut last_err: Option<Error> = None;
    let connect_transaction_id = next_transaction_id();
    let announce_transaction_id = next_transaction_id();

    for attempt in 0..BEP15_MAX_RETRIES {
        budget.remaining()?;
        let attempt_timeout = Duration::from_secs(BEP15_BASE_TIMEOUT_SECS * (1 << attempt));

        // Obtain connection ID (cached or fresh).
        let (connection_id, was_cached) = match obtain_connection_id(
            &socket,
            &addr,
            budget,
            attempt_timeout,
            connect_transaction_id,
        ) {
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
            budget,
            attempt_timeout,
            announce_transaction_id,
            announce_key,
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

    budget.remaining()?;
    Err(last_err.unwrap_or(Error::InvalidResponse))
}

#[cfg(test)]
fn parse_udp_url(url: &str) -> Result<SocketAddr, Error> {
    parse_udp_urls_with_budget(
        url,
        RequestBudget::new(Instant::now() + Duration::from_secs(2)),
    )
    .and_then(|addrs| addrs.into_iter().next().ok_or(Error::InvalidUrl))
}

fn parse_udp_urls_with_budget(url: &str, budget: RequestBudget) -> Result<Vec<SocketAddr>, Error> {
    budget.remaining()?;
    let rest = url.strip_prefix("udp://").ok_or(Error::InvalidUrl)?;
    let host_port = rest.split_once('/').map(|(host, _)| host).unwrap_or(rest);
    if host_port.is_empty()
        || host_port.len() > 1024
        || host_port
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || host_port.contains(['@', '\\', '?', '#'])
    {
        return Err(Error::InvalidUrl);
    }
    if let Ok(addr) = host_port.parse::<SocketAddr>() {
        let addr = normalize_udp_tracker_addr(addr);
        return if addr.port() == 0 || addr.ip().is_unspecified() {
            Err(Error::InvalidUrl)
        } else {
            Ok(vec![addr])
        };
    }

    let (host, port) = host_port.rsplit_once(':').ok_or(Error::InvalidUrl)?;
    let port = port.parse::<u16>().map_err(|_| Error::InvalidUrl)?;
    let mut candidates = Vec::new();
    let resolved = crate::http::resolve_host(host, port, budget.deadline)
        .map_err(|err| Error::Io(std::io::Error::other(err)))?;
    for addr in resolved {
        let addr = normalize_udp_tracker_addr(addr);
        if addr.port() != 0 && !addr.ip().is_unspecified() && !candidates.contains(&addr) {
            candidates.push(addr);
        }
    }
    budget.remaining()?;
    if candidates.is_empty() {
        return Err(Error::InvalidUrl);
    }
    Ok(candidates)
}

fn normalize_udp_tracker_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(addr_v6) => addr_v6
            .ip()
            .to_ipv4_mapped()
            .map(|ipv4| SocketAddr::from((ipv4, addr_v6.port())))
            .unwrap_or(SocketAddr::V6(addr_v6)),
        addr_v4 => addr_v4,
    }
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
    SEED.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |mut x| {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        Some(x)
    })
    .map(|mut x| {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x
    })
    .unwrap_or_else(|x| x)
}

fn parse_error_response(data: &[u8], expected_tx: u32) -> Error {
    if data.len() < 8 {
        return Error::InvalidResponse;
    }
    let tx = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if tx != expected_tx {
        return Error::InvalidTransaction;
    }
    Error::FailureReason(sanitize_failure_reason(&data[8..]))
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
    fn announce_response_uses_ipv6_peer_stride_for_ipv6_transport() {
        let transaction = 0x1234_5678u32;
        let address: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut response = Vec::new();
        response.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
        response.extend_from_slice(&transaction.to_be_bytes());
        response.extend_from_slice(&900u32.to_be_bytes());
        response.extend_from_slice(&1u32.to_be_bytes());
        response.extend_from_slice(&2u32.to_be_bytes());
        response.extend_from_slice(&address.octets());
        response.extend_from_slice(&6881u16.to_be_bytes());

        let parsed = parse_announce_response(&response, transaction, true).unwrap();
        assert_eq!(parsed.interval, 900);
        assert_eq!(parsed.peers, vec![SocketAddr::from((address, 6881))]);
    }

    #[test]
    fn announce_response_skips_port_zero_peers() {
        let transaction = 7u32;
        let mut response = Vec::new();
        for word in [ACTION_ANNOUNCE, transaction, 60, 0, 2] {
            response.extend_from_slice(&word.to_be_bytes());
        }
        response.extend_from_slice(&[10, 0, 0, 1, 0, 0, 10, 0, 0, 2, 0x1A, 0xE1]);
        let parsed = parse_announce_response(&response, transaction, false).unwrap();
        assert_eq!(parsed.peers, vec!["10.0.0.2:6881".parse().unwrap()]);
    }

    #[test]
    fn connect_response_allows_trailing_extension_bytes() {
        let tracker = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(tracker.local_addr().unwrap()).unwrap();
        let server = std::thread::spawn(move || {
            let mut request = [0u8; 64];
            let (length, source) = tracker.recv_from(&mut request).unwrap();
            assert_eq!(length, 16);
            let transaction = &request[12..16];
            let mut response = Vec::new();
            response.extend_from_slice(&ACTION_CONNECT.to_be_bytes());
            response.extend_from_slice(transaction);
            response.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
            response.extend_from_slice(b"extension");
            let mut stale = response.clone();
            stale[4..8].copy_from_slice(&0x8765_4321u32.to_be_bytes());
            tracker.send_to(&stale, source).unwrap();
            tracker.send_to(&response, source).unwrap();
        });

        let budget = RequestBudget::new(Instant::now() + Duration::from_secs(1));
        assert_eq!(
            udp_connect(&client, budget, Duration::from_secs(1), 0x1234_5678).unwrap(),
            0x1122_3344_5566_7788
        );
        server.join().unwrap();
    }

    #[test]
    fn announce_ignores_stale_and_duplicate_action_datagrams() {
        let tracker = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.connect(tracker.local_addr().unwrap()).unwrap();
        let announce_tx = 0x1234_5678u32;
        let server = std::thread::spawn(move || {
            let mut request = [0u8; 128];
            let (length, source) = tracker.recv_from(&mut request).unwrap();
            assert_eq!(length, 98);

            let mut stale = Vec::new();
            stale.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
            stale.extend_from_slice(&0x8765_4321u32.to_be_bytes());
            stale.extend_from_slice(&30u32.to_be_bytes());
            stale.extend_from_slice(&0u32.to_be_bytes());
            stale.extend_from_slice(&0u32.to_be_bytes());
            tracker.send_to(&stale, source).unwrap();

            let mut duplicate_connect = Vec::new();
            duplicate_connect.extend_from_slice(&ACTION_CONNECT.to_be_bytes());
            duplicate_connect.extend_from_slice(&0x1111_1111u32.to_be_bytes());
            duplicate_connect.extend_from_slice(&99u64.to_be_bytes());
            tracker.send_to(&duplicate_connect, source).unwrap();

            let mut valid = Vec::new();
            valid.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
            valid.extend_from_slice(&announce_tx.to_be_bytes());
            valid.extend_from_slice(&30u32.to_be_bytes());
            valid.extend_from_slice(&0u32.to_be_bytes());
            valid.extend_from_slice(&0u32.to_be_bytes());
            tracker.send_to(&valid, source).unwrap();
        });

        let result = send_announce(
            &client,
            99,
            [1u8; 20],
            [2u8; 20],
            6881,
            0,
            0,
            1,
            Some("started"),
            10,
            RequestBudget::new(Instant::now() + Duration::from_secs(1)),
            Duration::from_secs(1),
            announce_tx,
            0xfeed_beef,
        )
        .unwrap();
        assert_eq!(result.interval, 30);
        assert!(result.peers.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn announce_falls_back_across_addresses_and_keeps_its_key() {
        let failing = UdpSocket::bind("127.0.0.1:0").unwrap();
        let succeeding = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addrs = vec![
            failing.local_addr().unwrap(),
            succeeding.local_addr().unwrap(),
        ];
        for addr in &addrs {
            clear_cached_connection_id(addr);
        }
        let (key_tx, key_rx) = std::sync::mpsc::channel();

        let first_key_tx = key_tx.clone();
        let first = std::thread::spawn(move || {
            serve_connect_response(&failing, 0x1111_2222_3333_4444);
            let mut request = [0u8; 128];
            let (length, source) = failing.recv_from(&mut request).unwrap();
            assert_eq!(length, 98);
            first_key_tx
                .send(u32::from_be_bytes(request[88..92].try_into().unwrap()))
                .unwrap();
            let mut response = Vec::new();
            response.extend_from_slice(&ACTION_ERROR.to_be_bytes());
            response.extend_from_slice(&request[12..16]);
            response.extend_from_slice(b"denied");
            failing.send_to(&response, source).unwrap();
        });
        let second = std::thread::spawn(move || {
            serve_connect_response(&succeeding, 0x5555_6666_7777_8888);
            let mut request = [0u8; 128];
            let (length, source) = succeeding.recv_from(&mut request).unwrap();
            assert_eq!(length, 98);
            key_tx
                .send(u32::from_be_bytes(request[88..92].try_into().unwrap()))
                .unwrap();
            let mut response = Vec::new();
            response.extend_from_slice(&ACTION_ANNOUNCE.to_be_bytes());
            response.extend_from_slice(&request[12..16]);
            response.extend_from_slice(&45u32.to_be_bytes());
            response.extend_from_slice(&0u32.to_be_bytes());
            response.extend_from_slice(&0u32.to_be_bytes());
            succeeding.send_to(&response, source).unwrap();
        });

        let announce_key = 0xaabb_ccdd;
        let result = announce_to_addrs(
            &addrs,
            [1u8; 20],
            [2u8; 20],
            6881,
            0,
            0,
            1,
            Some("started"),
            10,
            RequestBudget::new(Instant::now() + Duration::from_secs(2)),
            announce_key,
        )
        .unwrap();
        assert_eq!(result.interval, 45);
        assert_eq!(key_rx.recv().unwrap(), announce_key);
        assert_eq!(key_rx.recv().unwrap(), announce_key);
        first.join().unwrap();
        second.join().unwrap();
    }

    fn serve_connect_response(socket: &UdpSocket, connection_id: u64) {
        let mut request = [0u8; 64];
        let (length, source) = socket.recv_from(&mut request).unwrap();
        assert_eq!(length, 16);
        let mut response = Vec::new();
        response.extend_from_slice(&ACTION_CONNECT.to_be_bytes());
        response.extend_from_slice(&request[12..16]);
        response.extend_from_slice(&connection_id.to_be_bytes());
        socket.send_to(&response, source).unwrap();
    }

    #[test]
    fn tracker_error_reason_is_sanitized_and_bounded() {
        let transaction = 0x1234_5678u32;
        let mut response = Vec::new();
        response.extend_from_slice(&ACTION_ERROR.to_be_bytes());
        response.extend_from_slice(&transaction.to_be_bytes());
        response.extend_from_slice(b"denied\x1b]0;owned\x07\r\n");
        response.extend(std::iter::repeat_n(b'x', 1000));
        let Error::FailureReason(reason) = parse_error_response(&response, transaction) else {
            panic!("expected a tracker failure reason");
        };
        assert!(!reason.chars().any(char::is_control));
        assert!(reason.chars().count() <= 256);
    }

    #[test]
    fn mapped_ipv4_tracker_address_uses_ipv4_transport() {
        let addrs = parse_udp_urls_with_budget(
            "udp://[::ffff:127.0.0.1]:6969/announce",
            RequestBudget::new(Instant::now() + Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(addrs, vec!["127.0.0.1:6969".parse().unwrap()]);
        assert!(addrs[0].is_ipv4());
    }

    #[test]
    fn announce_key_is_stable_per_tracker_authority() {
        let first = announce_key_for_url("udp://tracker-a.invalid:6969/announce", [1u8; 20]);
        let again = announce_key_for_url("udp://TRACKER-A.invalid:6969/scrape", [1u8; 20]);
        let other = announce_key_for_url("udp://tracker-b.invalid:6969/announce", [1u8; 20]);
        let other_swarm = announce_key_for_url("udp://tracker-a.invalid:6969/announce", [2u8; 20]);
        assert_eq!(first, again);
        assert_ne!(first, other);
        assert_ne!(first, other_swarm);
    }

    #[test]
    fn announce_obeys_absolute_deadline_for_a_silent_tracker() {
        let tracker = UdpSocket::bind("127.0.0.1:0").unwrap();
        let url = format!("udp://{}/announce", tracker.local_addr().unwrap());
        let started = Instant::now();
        let result = announce_until(
            &url,
            [1u8; 20],
            [2u8; 20],
            6881,
            0,
            0,
            1,
            Some("started"),
            10,
            started + Duration::from_millis(50),
        );
        assert!(result.as_ref().is_err_and(is_timeout));
        assert!(started.elapsed() < Duration::from_secs(1));
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

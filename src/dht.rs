use std::collections::{HashMap, HashSet};
#[cfg(any(test, not(any(unix, windows))))]
use std::fs;
#[cfg(not(any(unix, windows)))]
use std::fs::{File, OpenOptions};
#[cfg(not(any(unix, windows)))]
use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
#[cfg(not(any(unix, windows)))]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::bencode::{self, Value};
use crate::sha1;

const DHT_POLL_INTERVAL: Duration = Duration::from_millis(200);
/// How often each torrent runs an iterative get_peers lookup (and announce).
const QUERY_INTERVAL: Duration = Duration::from_secs(120);
/// Concurrent get_peers lookups across all torrents.
const MAX_PEER_LOOKUPS: usize = 8;
const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(60);
const SAVE_INTERVAL: Duration = Duration::from_secs(300);
const K: usize = 8;
const NUM_BUCKETS: usize = 160;
const MAX_PEERS_PER_TORRENT: usize = 256;
const MAX_PEER_STORE_TORRENTS: usize = 1024;
const MAX_PEER_ENDPOINTS_PER_IP: usize = 2;
const MAX_PEER_ENDPOINTS_PER_PREFIX: usize = 16;
const MAX_STORED_SWARMS_PER_IP: usize = 32;
const PEER_STORE_TTL: Duration = Duration::from_secs(30 * 60);
const PEER_STORE_PRUNE_INTERVAL: Duration = Duration::from_secs(60);
const MAX_PENDING_AGE: Duration = Duration::from_secs(30);
const MAX_PENDING_QUERIES: usize = 1024;
const MAX_NODE_CANDIDATES_PER_RESPONSE: usize = 16;
const MAX_NODES_PER_IP: usize = 2;
const MAX_NODES_PER_PREFIX: usize = 4;
const MAX_NODE_FAILURES: u8 = 2;
const QUESTIONABLE_NODE_AGE: Duration = Duration::from_secs(15 * 60);
const BUCKET_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);
const BUCKET_REFRESH_SPACING: Duration = Duration::from_secs(5);
const BUCKET_REFRESH_RETRY_INTERVAL: Duration = Duration::from_secs(60);
const MAX_REPLACEMENT_PROBE_ATTEMPTS: u8 = 2;
const MAX_DEFERRED_REPLACEMENTS: usize = 128;
const DEFERRED_REPLACEMENT_TTL: Duration = Duration::from_secs(5 * 60);
const REFRESH_LOOKUP_ALPHA: usize = 3;
const MAX_REFRESH_LOOKUP_QUERIES: usize = 32;
const MAX_REFRESH_LOOKUP_CANDIDATES: usize = 64;
const REFRESH_LOOKUP_DEADLINE: Duration = Duration::from_secs(2 * 60);
const MAX_CACHED_NODE_CANDIDATES: usize = 64;
const MAX_TRANSACTION_ID_LEN: usize = 16;
const MAX_BOOTSTRAP_ADDRESSES_PER_HOST: usize = 8;
const MAX_BOOTSTRAP_ADDRESSES: usize = BOOTSTRAP_NODES.len() * MAX_BOOTSTRAP_ADDRESSES_PER_HOST;
const BOOTSTRAP_RESOLUTION_DEADLINE: Duration = Duration::from_secs(10);
const BOOTSTRAP_RESOLUTION_REFRESH: Duration = Duration::from_secs(5 * 60);
const BOOTSTRAP_ADDRESS_TTL: Duration = Duration::from_secs(30 * 60);
const QUERY_RATE_WINDOW: Duration = Duration::from_secs(1);
const QUERY_RATE_ENTRY_TTL: Duration = Duration::from_secs(10);
const MAX_QUERY_RATE_ENTRIES: usize = 4096;
const MAX_QUERIES_PER_WINDOW_GLOBAL: u32 = 512;
const MAX_QUERIES_PER_WINDOW_PREFIX: u32 = 64;
const MAX_QUERIES_PER_WINDOW_IP: u32 = 16;
const TOKEN_ROTATION_INTERVAL: Duration = Duration::from_secs(5 * 60);
const MAX_NODES_FILE_BYTES: usize = 1024 * 1024;
const NODES_FILE_NAME: &str = "dht_nodes.dat";
const STATE_DIR_NAME: &str = ".rustorrent";
#[cfg(not(any(unix, windows)))]
static NEXT_CACHE_TEMP: AtomicU64 = AtomicU64::new(0);
static BOOTSTRAP_RESOLVER_IN_FLIGHT: [AtomicBool; BOOTSTRAP_NODES.len()] =
    [const { AtomicBool::new(false) }; BOOTSTRAP_NODES.len()];

static BOOTSTRAP_NODES: [&str; 3] = [
    "router.bittorrent.com:6881",
    "router.utorrent.com:6881",
    "dht.transmissionbt.com:6881",
];

#[derive(Clone)]
pub struct Dht {
    cmd_tx: mpsc::Sender<Command>,
}

enum Command {
    AddTorrent {
        info_hash: [u8; 20],
        port: u16,
        peers_tx: mpsc::Sender<Vec<SocketAddr>>,
    },
    RemoveTorrent {
        info_hash: [u8; 20],
    },
}

pub fn start(bind_port: u16, download_dir: &Path) -> Dht {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let cache = match NodeCache::new(download_dir) {
        Ok(cache) => Some(cache),
        Err(err) => {
            crate::log_stderr(format_args!("dht cache disabled: {err}"));
            None
        }
    };
    thread::spawn(move || {
        dht_thread(bind_port, cmd_rx, cache, Vec::new());
    });
    Dht { cmd_tx }
}

#[cfg(test)]
pub fn start_with_test_candidate(
    bind_port: u16,
    download_dir: &Path,
    id: [u8; 20],
    addr: SocketAddr,
) -> Dht {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let cache = NodeCache::new(download_dir).ok();
    let candidate = Node {
        id,
        addr: normalize_dht_addr(addr),
        last_seen: Instant::now(),
    };
    thread::spawn(move || {
        dht_thread(bind_port, cmd_rx, cache, vec![candidate]);
    });
    Dht { cmd_tx }
}

pub fn disabled() -> Dht {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    drop(cmd_rx);
    Dht { cmd_tx }
}

impl Dht {
    pub fn add_torrent(
        &self,
        info_hash: [u8; 20],
        port: u16,
        peers_tx: mpsc::Sender<Vec<SocketAddr>>,
    ) {
        let _ = self.cmd_tx.send(Command::AddTorrent {
            info_hash,
            port,
            peers_tx,
        });
    }

    pub fn remove_torrent(&self, info_hash: [u8; 20]) {
        let _ = self.cmd_tx.send(Command::RemoveTorrent { info_hash });
    }
}

#[derive(Clone, Copy)]
struct Node {
    id: [u8; 20],
    addr: SocketAddr,
    last_seen: Instant,
}

struct RoutingTable {
    own_id: [u8; 20],
    buckets: Vec<Vec<Node>>,
    bucket_refreshed_at: Vec<Instant>,
    bucket_refresh_attempted_at: Vec<Instant>,
    failures: HashMap<SocketAddr, u8>,
}

impl RoutingTable {
    fn new(own_id: [u8; 20]) -> Self {
        let now = Instant::now();
        let mut buckets = Vec::with_capacity(NUM_BUCKETS);
        for _ in 0..NUM_BUCKETS {
            buckets.push(Vec::new());
        }
        Self {
            own_id,
            buckets,
            bucket_refreshed_at: vec![now; NUM_BUCKETS],
            bucket_refresh_attempted_at: vec![now; NUM_BUCKETS],
            failures: HashMap::new(),
        }
    }

    fn bucket_index(&self, id: &[u8; 20]) -> usize {
        let dist = xor_distance(&self.own_id, id);
        let leading = leading_zeros(&dist);
        if leading >= NUM_BUCKETS {
            NUM_BUCKETS - 1
        } else {
            NUM_BUCKETS - 1 - leading
        }
    }

    fn insert(&mut self, mut node: Node) {
        node.addr = normalize_dht_addr(node.addr);
        if node.id == self.own_id || node.addr.port() == 0 || node.addr.ip().is_unspecified() {
            return;
        }
        let idx = self.bucket_index(&node.id);
        let bucket = &mut self.buckets[idx];
        if let Some(pos) = bucket.iter().position(|n| n.id == node.id) {
            if bucket[pos].addr != node.addr {
                return;
            }
            bucket[pos].last_seen = node.last_seen;
            self.bucket_refreshed_at[idx] = node.last_seen;
            self.failures.remove(&node.addr);
            return;
        }
        // Most candidates land in a full bucket; check that before scanning
        // the whole table for duplicates and address concentration.
        if self.buckets[idx].len() >= K {
            return;
        }
        let ip = normalize_dht_ip(node.addr.ip());
        let (mut same_ip, mut same_prefix) = (0, 0);
        for existing in self.buckets.iter().flatten() {
            if existing.addr == node.addr {
                return;
            }
            same_ip += usize::from(normalize_dht_ip(existing.addr.ip()) == ip);
            same_prefix += usize::from(same_network_prefix(existing.addr, node.addr));
        }
        if same_ip >= MAX_NODES_PER_IP || same_prefix >= MAX_NODES_PER_PREFIX {
            return;
        }
        self.failures.remove(&node.addr);
        self.buckets[idx].push(node);
        self.bucket_refreshed_at[idx] = node.last_seen;
    }

    fn insert_verified(&mut self, node: Node) -> bool {
        if !node_id_matches_address(&node.id, node.addr) {
            return false;
        }
        let before = self.node_count();
        self.insert(node);
        self.node_count() > before
    }

    fn closest_filtered<F>(&self, target: &[u8; 20], count: usize, mut keep: F) -> Vec<Node>
    where
        F: FnMut(&Node) -> bool,
    {
        if count == 0 {
            return Vec::new();
        }
        // DHT queries are unauthenticated. Keep only the requested fixed-size
        // nearest set instead of allocating and sorting the entire table for
        // every datagram.
        let mut best: Vec<([u8; 20], Node)> = Vec::with_capacity(count);
        for node in self.buckets.iter().flatten().filter(|node| keep(node)) {
            let distance = xor_distance(&node.id, target);
            let insert_at = best.partition_point(|(existing, _)| *existing <= distance);
            if insert_at < count {
                best.insert(insert_at, (distance, *node));
                if best.len() > count {
                    best.pop();
                }
            }
        }
        best.into_iter().map(|(_, node)| node).collect()
    }

    fn closest(&self, target: &[u8; 20], count: usize) -> Vec<Node> {
        self.closest_filtered(target, count, |_| true)
    }

    fn node_count(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    fn all_nodes(&self) -> Vec<&Node> {
        self.buckets.iter().flat_map(|b| b.iter()).collect()
    }

    fn contains_endpoint(&self, addr: SocketAddr) -> bool {
        self.buckets.iter().flatten().any(|node| node.addr == addr)
    }

    fn refresh_verified(&mut self, id: &[u8; 20], addr: SocketAddr) -> bool {
        let addr = normalize_dht_addr(addr);
        for (idx, bucket) in self.buckets.iter_mut().enumerate() {
            if let Some(node) = bucket
                .iter_mut()
                .find(|node| node.id == *id && node.addr == addr)
            {
                let now = Instant::now();
                node.last_seen = now;
                self.bucket_refreshed_at[idx] = now;
                self.failures.remove(&addr);
                return true;
            }
        }
        false
    }

    fn questionable_incumbents(&self, candidate: Node) -> Vec<Node> {
        let idx = self.bucket_index(&candidate.id);
        let bucket = &self.buckets[idx];
        if bucket.len() < K {
            return Vec::new();
        }
        let mut questionable: Vec<_> = bucket
            .iter()
            .filter(|node| node.last_seen.elapsed() >= QUESTIONABLE_NODE_AGE)
            .copied()
            .collect();
        crate::util::sort_by_key(&mut questionable, |node| node.last_seen);
        questionable
    }

    fn incumbent_unchanged_since(&self, id: [u8; 20], addr: SocketAddr, sent_at: Instant) -> bool {
        let addr = normalize_dht_addr(addr);
        self.buckets
            .iter()
            .flatten()
            .any(|node| node.id == id && node.addr == addr && node.last_seen <= sent_at)
    }

    fn replace_questionable(
        &mut self,
        incumbent_id: [u8; 20],
        incumbent_addr: SocketAddr,
        probe_sent_at: Instant,
        mut candidate: Node,
    ) -> bool {
        candidate.addr = normalize_dht_addr(candidate.addr);
        let incumbent_addr = normalize_dht_addr(incumbent_addr);
        if candidate.id == self.own_id
            || candidate.addr.port() == 0
            || candidate.addr.ip().is_unspecified()
            || !node_id_matches_address(&candidate.id, candidate.addr)
        {
            return false;
        }
        let idx = self.bucket_index(&candidate.id);
        let Some(incumbent_pos) = self.buckets[idx].iter().position(|node| {
            node.id == incumbent_id
                && node.addr == incumbent_addr
                && node.last_seen <= probe_sent_at
        }) else {
            return false;
        };
        if self.buckets.iter().flatten().any(|node| {
            node.addr != incumbent_addr && (node.id == candidate.id || node.addr == candidate.addr)
        }) {
            return false;
        }
        let same_ip = self
            .buckets
            .iter()
            .flatten()
            .filter(|node| {
                node.addr != incumbent_addr
                    && normalize_dht_ip(node.addr.ip()) == normalize_dht_ip(candidate.addr.ip())
            })
            .count();
        let same_prefix = self
            .buckets
            .iter()
            .flatten()
            .filter(|node| {
                node.addr != incumbent_addr && same_network_prefix(node.addr, candidate.addr)
            })
            .count();
        if same_ip >= MAX_NODES_PER_IP || same_prefix >= MAX_NODES_PER_PREFIX {
            return false;
        }
        self.failures.remove(&incumbent_addr);
        self.failures.remove(&candidate.addr);
        self.buckets[idx][incumbent_pos] = candidate;
        self.bucket_refreshed_at[idx] = candidate.last_seen;
        true
    }

    fn bucket_needing_refresh(&self, now: Instant) -> Option<usize> {
        self.bucket_refreshed_at
            .iter()
            .enumerate()
            .filter(|(idx, refreshed)| {
                !self.buckets[*idx].is_empty()
                    && now.duration_since(**refreshed) >= BUCKET_REFRESH_INTERVAL
                    && now.duration_since(self.bucket_refresh_attempted_at[*idx])
                        >= BUCKET_REFRESH_RETRY_INTERVAL
            })
            .min_by_key(|(idx, _)| self.bucket_refresh_attempted_at[*idx])
            .map(|(idx, _)| idx)
    }

    fn mark_bucket_refreshed(&mut self, idx: usize, now: Instant) {
        if let Some(refreshed) = self.bucket_refreshed_at.get_mut(idx) {
            *refreshed = now;
        }
    }

    fn mark_bucket_refresh_attempted(&mut self, idx: usize, now: Instant) {
        if let Some(attempted) = self.bucket_refresh_attempted_at.get_mut(idx) {
            *attempted = now;
        }
    }

    fn record_query_failure(&mut self, addr: SocketAddr, sent_at: Instant) {
        let addr = normalize_dht_addr(addr);
        let eligible = self
            .buckets
            .iter()
            .flatten()
            .any(|node| node.addr == addr && node.last_seen <= sent_at);
        if !eligible {
            return;
        }
        let failures = self.failures.entry(addr).or_default();
        *failures = failures.saturating_add(1);
        if *failures >= MAX_NODE_FAILURES {
            for bucket in &mut self.buckets {
                bucket.retain(|node| node.addr != addr);
            }
            self.failures.remove(&addr);
        }
    }

    fn scoped_closest(
        &self,
        target: &[u8; 20],
        count: usize,
        requester: SocketAddr,
        ipv6: bool,
    ) -> Vec<Node> {
        self.closest_filtered(target, count, |node| {
            node.addr.is_ipv6() == ipv6 && dht_address_scope_allowed(requester, node.addr)
        })
    }

    fn encode_closest_nodes(&self, target: &[u8; 20], requester: SocketAddr) -> Vec<u8> {
        let closest = self.scoped_closest(target, 8, requester, false);
        let mut out = Vec::new();
        for node in closest {
            if let std::net::IpAddr::V4(ip) = node.addr.ip() {
                out.extend_from_slice(&node.id);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&node.addr.port().to_be_bytes());
            }
        }
        out
    }

    fn encode_closest_nodes6(&self, target: &[u8; 20], requester: SocketAddr) -> Vec<u8> {
        let closest = self.scoped_closest(target, 8, requester, true);
        let mut out = Vec::new();
        for node in closest {
            match node.addr.ip() {
                std::net::IpAddr::V6(ip) => {
                    out.extend_from_slice(&node.id);
                    out.extend_from_slice(&ip.octets());
                    out.extend_from_slice(&node.addr.port().to_be_bytes());
                }
                std::net::IpAddr::V4(_) => continue,
            }
        }
        out
    }
}

fn xor_distance(a: &[u8; 20], b: &[u8; 20]) -> [u8; 20] {
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn leading_zeros(bytes: &[u8; 20]) -> usize {
    let mut count = 0;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as usize;
            break;
        }
    }
    count
}

fn normalize_dht_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(ipv6) => ipv6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(std::net::IpAddr::V6(ipv6)),
        ipv4 => ipv4,
    }
}

fn normalize_dht_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(normalize_dht_ip(addr.ip()), addr.port())
}

fn same_network_prefix(left: SocketAddr, right: SocketAddr) -> bool {
    match (normalize_dht_ip(left.ip()), normalize_dht_ip(right.ip())) {
        (std::net::IpAddr::V4(left), std::net::IpAddr::V4(right)) => {
            left.octets()[..3] == right.octets()[..3]
        }
        (std::net::IpAddr::V6(left), std::net::IpAddr::V6(right)) => {
            left.octets()[..8] == right.octets()[..8]
        }
        _ => false,
    }
}

fn is_local_dht_address(ip: std::net::IpAddr) -> bool {
    match normalize_dht_ip(ip) {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unicast_link_local() || (ip.octets()[0] & 0xfe) == 0xfc
        }
    }
}

fn is_global_dht_address(ip: std::net::IpAddr) -> bool {
    crate::http::is_public_http_ip(normalize_dht_ip(ip))
}

fn dht_address_scope_allowed(responder: SocketAddr, candidate: SocketAddr) -> bool {
    let candidate_ip = candidate.ip();
    (is_local_dht_address(responder.ip())
        && (is_local_dht_address(candidate_ip) || is_global_dht_address(candidate_ip)))
        || (is_global_dht_address(responder.ip()) && is_global_dht_address(candidate_ip))
}

fn prune_peer_store(peer_store: &mut PeerStore) {
    peer_store.prune_expired();
}

fn admit_announced_peer(peer_store: &mut PeerStore, info_hash: [u8; 20], addr: SocketAddr) -> bool {
    peer_store.admit(info_hash, addr)
}

fn node_id_matches_address(id: &[u8; 20], addr: SocketAddr) -> bool {
    if is_local_dht_address(addr.ip()) {
        return true;
    }
    if !is_global_dht_address(addr.ip()) {
        return false;
    }
    let random = id[19] & 0x07;
    let crc = match normalize_dht_ip(addr.ip()) {
        std::net::IpAddr::V4(ip) => {
            let mut bytes = ip.octets();
            let mask = [0x03, 0x0f, 0x3f, 0xff];
            for (byte, mask) in bytes.iter_mut().zip(mask) {
                *byte &= mask;
            }
            bytes[0] |= random << 5;
            crc32c(&bytes)
        }
        std::net::IpAddr::V6(ip) => {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&ip.octets()[..8]);
            let mask = [0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff];
            for (byte, mask) in bytes.iter_mut().zip(mask) {
                *byte &= mask;
            }
            bytes[0] |= random << 5;
            crc32c(&bytes)
        }
    };
    id[0] == (crc >> 24) as u8
        && id[1] == (crc >> 16) as u8
        && (id[2] & 0xf8) == ((crc >> 8) as u8 & 0xf8)
}

fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let low_bit = crc & 1;
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0u32.wrapping_sub(low_bit));
        }
    }
    !crc
}

const NODES_FILE_MAGIC: &[u8; 5] = b"DHTN\x01";

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    first: u64,
    second: u64,
}

#[derive(Clone)]
struct NodeCache {
    #[cfg(not(any(unix, windows)))]
    download_dir: PathBuf,
    #[cfg(any(test, not(any(unix, windows))))]
    state_dir: PathBuf,
    path: PathBuf,
    #[cfg(not(any(unix, windows)))]
    state_identity: Option<FileIdentity>,
}

impl NodeCache {
    #[cfg(any(unix, windows))]
    fn new(download_dir: &Path) -> Result<Self, String> {
        let download_dir = if download_dir.is_absolute() {
            download_dir.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|error| format!("resolve download directory: {error}"))?
                .join(download_dir)
        };
        crate::state_dir::ensure(&download_dir)
            .map_err(|error| format!("state directory is not a real directory: {error}"))?;
        let state_dir = download_dir.join(STATE_DIR_NAME);
        Ok(Self {
            path: state_dir.join(NODES_FILE_NAME),
            #[cfg(test)]
            state_dir,
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn new(download_dir: &Path) -> Result<Self, String> {
        let download_dir = fs::canonicalize(download_dir).map_err(|err| {
            format!(
                "canonicalize download directory {}: {err}",
                download_dir.display()
            )
        })?;
        let download_metadata = fs::symlink_metadata(&download_dir).map_err(|err| {
            format!(
                "inspect download directory {}: {err}",
                download_dir.display()
            )
        })?;
        if !download_metadata.is_dir() || download_metadata.file_type().is_symlink() {
            return Err("download directory is not a real directory".to_string());
        }

        let state_dir = download_dir.join(STATE_DIR_NAME);
        match fs::symlink_metadata(&state_dir) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(format!(
                        "state directory {} is not a real directory",
                        state_dir.display()
                    ));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                create_private_state_dir(&state_dir)?;
            }
            Err(err) => {
                return Err(format!(
                    "inspect state directory {}: {err}",
                    state_dir.display()
                ));
            }
        }

        validate_state_dir(&download_dir, &state_dir, None)?;
        let state_metadata = fs::symlink_metadata(&state_dir)
            .map_err(|err| format!("inspect state directory: {err}"))?;
        let state_identity = state_directory_identity(&state_dir, &state_metadata)?;
        Ok(Self {
            path: state_dir.join(NODES_FILE_NAME),
            download_dir,
            state_dir,
            state_identity,
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn validate_parent(&self) -> Result<(), String> {
        validate_state_dir(&self.download_dir, &self.state_dir, self.state_identity)
    }

    #[cfg(any(unix, windows))]
    fn read(&self) -> Result<Option<Vec<u8>>, String> {
        match crate::state_dir::read_limited(&self.path, MAX_NODES_FILE_BYTES) {
            Ok(data) => Ok(Some(data)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("read DHT cache: {error}")),
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn read(&self) -> Result<Option<Vec<u8>>, String> {
        self.validate_parent()?;
        let path_metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(format!("inspect DHT cache: {err}")),
        };
        validate_cache_file(&path_metadata, "DHT cache")?;
        if path_metadata.len() > MAX_NODES_FILE_BYTES as u64 {
            return Err("DHT cache is too large".to_string());
        }

        let mut options = OpenOptions::new();
        options.read(true);
        let file = options
            .open(&self.path)
            .map_err(|err| format!("open DHT cache: {err}"))?;
        let opened_metadata = file
            .metadata()
            .map_err(|err| format!("inspect open DHT cache: {err}"))?;
        validate_cache_file(&opened_metadata, "open DHT cache")?;
        validate_open_cache_file(&file, "open DHT cache")?;
        if !same_file(&path_metadata, &opened_metadata) {
            return Err("DHT cache path changed while opening".to_string());
        }
        if opened_metadata.len() > MAX_NODES_FILE_BYTES as u64 {
            return Err("DHT cache is too large".to_string());
        }

        let mut data = Vec::new();
        file.take((MAX_NODES_FILE_BYTES + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|err| format!("read DHT cache: {err}"))?;
        if data.len() > MAX_NODES_FILE_BYTES {
            return Err("DHT cache is too large".to_string());
        }
        Ok(Some(data))
    }

    #[cfg(any(unix, windows))]
    fn write(&self, data: &[u8]) -> Result<(), String> {
        if data.len() > MAX_NODES_FILE_BYTES {
            return Err("DHT cache is too large".to_string());
        }
        crate::state_dir::write_atomic(&self.path, data, false, 0o600, MAX_NODES_FILE_BYTES)
            .map_err(|error| format!("write DHT cache: {error}"))
    }

    #[cfg(not(any(unix, windows)))]
    fn write(&self, data: &[u8]) -> Result<(), String> {
        if data.len() > MAX_NODES_FILE_BYTES {
            return Err("DHT cache is too large".to_string());
        }
        self.validate_parent()?;
        validate_cache_target(&self.path)?;

        let temp = self.create_temp_file()?;
        let temp_path = temp.0;
        let mut file = temp.1;
        let result = (|| -> Result<(), String> {
            file.write_all(data)
                .map_err(|err| format!("write DHT cache temp: {err}"))?;
            file.sync_all()
                .map_err(|err| format!("sync DHT cache temp: {err}"))?;
            let metadata = file
                .metadata()
                .map_err(|err| format!("inspect DHT cache temp: {err}"))?;
            validate_cache_file(&metadata, "DHT cache temp")?;
            validate_open_cache_file(&file, "DHT cache temp")?;
            drop(file);

            self.validate_parent()?;
            validate_cache_target(&self.path)?;
            fs::rename(&temp_path, &self.path)
                .map_err(|err| format!("publish DHT cache: {err}"))?;
            sync_directory(&self.state_dir)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    #[cfg(not(any(unix, windows)))]
    fn create_temp_file(&self) -> Result<(PathBuf, File), String> {
        for _ in 0..64 {
            let suffix = NEXT_CACHE_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = self.state_dir.join(format!(
                ".{NODES_FILE_NAME}.tmp-{}-{suffix}",
                std::process::id()
            ));
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            match options.open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(format!("create DHT cache temp: {err}")),
            }
        }
        Err("create DHT cache temp: no unique name available".to_string())
    }
}

#[cfg(not(any(unix, windows)))]
fn create_private_state_dir(path: &Path) -> Result<(), String> {
    let builder = fs::DirBuilder::new();
    builder
        .create(path)
        .map_err(|err| format!("create state directory {}: {err}", path.display()))
}

#[cfg(not(any(unix, windows)))]
fn validate_state_dir(
    download_dir: &Path,
    state_dir: &Path,
    expected_identity: Option<FileIdentity>,
) -> Result<(), String> {
    if state_dir.parent() != Some(download_dir)
        || state_dir.file_name() != Some(std::ffi::OsStr::new(STATE_DIR_NAME))
    {
        return Err("DHT state directory escaped the download directory".to_string());
    }
    let metadata = fs::symlink_metadata(state_dir)
        .map_err(|err| format!("inspect state directory {}: {err}", state_dir.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "state directory {} is not a real directory",
            state_dir.display()
        ));
    }
    let canonical = fs::canonicalize(state_dir)
        .map_err(|err| format!("canonicalize state directory: {err}"))?;
    if canonical != state_dir {
        return Err("state directory is an unsafe filesystem alias".to_string());
    }
    let current_identity = state_directory_identity(state_dir, &metadata)?;
    if expected_identity.is_some() && current_identity != expected_identity {
        return Err("state directory changed after DHT startup".to_string());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_cache_target(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_cache_file(&metadata, "existing DHT cache")?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("inspect existing DHT cache: {err}")),
    }
}

#[cfg(not(any(unix, windows)))]
fn validate_cache_file(metadata: &fs::Metadata, label: &str) -> Result<(), String> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{label} is not a regular file"));
    }
    if hard_link_count(metadata).is_some_and(|count| count != 1) {
        return Err(format!("{label} must not be hard-linked"));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn hard_link_count(_metadata: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(not(any(unix, windows)))]
fn same_file(_first: &fs::Metadata, _second: &fs::Metadata) -> bool {
    // These targets retain regular-file checks but do not expose a portable
    // file identity API. They are never used for state writes unless the
    // directory identity backend below explicitly supports the platform.
    true
}

#[cfg(not(any(unix, windows)))]
fn state_directory_identity(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<Option<FileIdentity>, String> {
    // If this platform cannot provide a stable identity, fail closed instead
    // of writing through a parent directory that could be replaced.
    Err("secure DHT cache directory identity is unsupported on this platform".to_string())
}

#[cfg(not(any(unix, windows)))]
fn validate_open_cache_file(_file: &File, _label: &str) -> Result<(), String> {
    Ok(())
}
#[cfg(not(any(unix, windows)))]
fn sync_directory(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn save_nodes(rt: &RoutingTable, cache: &NodeCache) -> Result<(), String> {
    let nodes = rt.all_nodes();
    let mut data = Vec::with_capacity(NODES_FILE_MAGIC.len() + nodes.len() * 39);
    data.extend_from_slice(NODES_FILE_MAGIC);
    for node in nodes {
        match node.addr.ip() {
            std::net::IpAddr::V4(ip) => {
                data.push(4u8); // type marker
                data.extend_from_slice(&node.id);
                data.extend_from_slice(&ip.octets());
                data.extend_from_slice(&node.addr.port().to_be_bytes());
            }
            std::net::IpAddr::V6(ip) => {
                data.push(6u8); // type marker
                data.extend_from_slice(&node.id);
                data.extend_from_slice(&ip.octets());
                data.extend_from_slice(&node.addr.port().to_be_bytes());
            }
        }
    }
    cache.write(&data)
}

fn load_node_candidates(cache: &NodeCache) -> Result<Vec<Node>, String> {
    let Some(data) = cache.read()? else {
        return Ok(Vec::new());
    };
    let decoded = if data.starts_with(NODES_FILE_MAGIC) {
        decode_nodes_type_prefixed(&data[NODES_FILE_MAGIC.len()..]).unwrap_or_default()
    } else if let Some(nodes) = decode_nodes_type_prefixed(&data) {
        nodes
    } else {
        decode_legacy_nodes(&data)
    };
    let mut selected: Vec<Node> = Vec::new();
    let mut endpoints = HashSet::new();
    let mut ids = HashSet::new();
    for node in decoded {
        if selected.len() >= MAX_CACHED_NODE_CANDIDATES {
            break;
        }
        if node.addr.port() == 0
            || !is_global_dht_address(node.addr.ip())
            || !node_id_matches_address(&node.id, node.addr)
            || endpoints.contains(&node.addr)
            || ids.contains(&node.id)
            || selected
                .iter()
                .filter(|selected| {
                    normalize_dht_ip(selected.addr.ip()) == normalize_dht_ip(node.addr.ip())
                })
                .count()
                >= MAX_NODES_PER_IP
            || selected
                .iter()
                .filter(|selected| same_network_prefix(selected.addr, node.addr))
                .count()
                >= MAX_NODES_PER_PREFIX
        {
            continue;
        }
        endpoints.insert(node.addr);
        ids.insert(node.id);
        selected.push(node);
    }
    Ok(selected)
}

fn decode_nodes_type_prefixed(data: &[u8]) -> Option<Vec<Node>> {
    let mut nodes = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let marker = data[i];
        i += 1;
        if marker == 4 {
            if i + 26 > data.len() {
                return None;
            }
            let mut id = [0u8; 20];
            id.copy_from_slice(&data[i..i + 20]);
            let ip =
                std::net::Ipv4Addr::new(data[i + 20], data[i + 21], data[i + 22], data[i + 23]);
            let port = u16::from_be_bytes([data[i + 24], data[i + 25]]);
            nodes.push(Node {
                id,
                addr: normalize_dht_addr(SocketAddr::new(ip.into(), port)),
                last_seen: Instant::now(),
            });
            i += 26;
        } else if marker == 6 {
            if i + 38 > data.len() {
                return None;
            }
            let mut id = [0u8; 20];
            id.copy_from_slice(&data[i..i + 20]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[i + 20..i + 36]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([data[i + 36], data[i + 37]]);
            nodes.push(Node {
                id,
                addr: normalize_dht_addr(SocketAddr::new(ip.into(), port)),
                last_seen: Instant::now(),
            });
            i += 38;
        } else {
            return None;
        }
    }
    Some(nodes)
}

fn decode_legacy_nodes(data: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    let mut i = 0usize;
    while i + 26 <= data.len() {
        let mut id = [0u8; 20];
        id.copy_from_slice(&data[i..i + 20]);
        let ip = std::net::Ipv4Addr::new(data[i + 20], data[i + 21], data[i + 22], data[i + 23]);
        let port = u16::from_be_bytes([data[i + 24], data[i + 25]]);
        nodes.push(Node {
            id,
            addr: SocketAddr::new(ip.into(), port),
            last_seen: Instant::now(),
        });
        i += 26;
    }
    nodes
}

struct TorrentEntry {
    peers_tx: mpsc::Sender<Vec<SocketAddr>>,
    port: u16,
    last_query: Instant,
    last_bootstrap: Instant,
}

#[derive(Clone)]
struct StoredPeer {
    addr: SocketAddr,
    last_seen: Instant,
}

struct PeerStore {
    swarms: HashMap<[u8; 20], Vec<StoredPeer>>,
    swarms_by_ip: HashMap<std::net::IpAddr, HashSet<[u8; 20]>>,
    swarm_last_seen: HashMap<[u8; 20], Instant>,
}

impl PeerStore {
    fn new() -> Self {
        Self {
            swarms: HashMap::new(),
            swarms_by_ip: HashMap::new(),
            swarm_last_seen: HashMap::new(),
        }
    }

    fn get(&self, info_hash: &[u8; 20]) -> Option<&[StoredPeer]> {
        self.swarms.get(info_hash).map(Vec::as_slice)
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.swarms.is_empty()
    }

    fn remove(&mut self, info_hash: &[u8; 20]) -> Option<Vec<StoredPeer>> {
        let peers = self.swarms.remove(info_hash)?;
        self.swarm_last_seen.remove(info_hash);
        let ips: HashSet<std::net::IpAddr> = peers
            .iter()
            .map(|peer| normalize_dht_ip(peer.addr.ip()))
            .collect();
        for ip in ips {
            let remove_ip = if let Some(swarms) = self.swarms_by_ip.get_mut(&ip) {
                swarms.remove(info_hash);
                swarms.is_empty()
            } else {
                false
            };
            if remove_ip {
                self.swarms_by_ip.remove(&ip);
            }
        }
        Some(peers)
    }

    fn insert_swarm(&mut self, info_hash: [u8; 20], peers: Vec<StoredPeer>) {
        if peers.is_empty() {
            return;
        }
        let latest = peers
            .iter()
            .map(|peer| peer.last_seen)
            .max()
            .unwrap_or_else(Instant::now);
        let ips: HashSet<std::net::IpAddr> = peers
            .iter()
            .map(|peer| normalize_dht_ip(peer.addr.ip()))
            .collect();
        self.swarms.insert(info_hash, peers);
        self.swarm_last_seen.insert(info_hash, latest);
        for ip in ips {
            self.swarms_by_ip.entry(ip).or_default().insert(info_hash);
        }
    }

    fn prune_swarm(&mut self, info_hash: &[u8; 20]) {
        // Rebuilding a swarm's index is only needed when something expired.
        if !self.swarms.get(info_hash).is_some_and(|peers| {
            peers
                .iter()
                .any(|peer| peer.last_seen.elapsed() > PEER_STORE_TTL)
        }) {
            return;
        }
        let Some(mut peers) = self.remove(info_hash) else {
            return;
        };
        peers.retain(|peer| peer.last_seen.elapsed() <= PEER_STORE_TTL);
        self.insert_swarm(*info_hash, peers);
    }

    fn prune_expired(&mut self) {
        let hashes: Vec<[u8; 20]> = self.swarms.keys().copied().collect();
        for hash in hashes {
            self.prune_swarm(&hash);
        }
    }

    fn evict_oldest_swarm(&mut self) {
        let oldest = self
            .swarm_last_seen
            .iter()
            .min_by_key(|(_, last_seen)| **last_seen)
            .map(|(hash, _)| *hash)
            .or_else(|| self.swarms.keys().next().copied());
        if let Some(oldest) = oldest {
            let _ = self.remove(&oldest);
        }
    }

    fn remove_ip_membership_if_unused(&mut self, info_hash: [u8; 20], ip: std::net::IpAddr) {
        let ip = normalize_dht_ip(ip);
        if self.swarms.get(&info_hash).is_some_and(|peers| {
            peers
                .iter()
                .any(|peer| normalize_dht_ip(peer.addr.ip()) == ip)
        }) {
            return;
        }
        let remove_ip = if let Some(swarms) = self.swarms_by_ip.get_mut(&ip) {
            swarms.remove(&info_hash);
            swarms.is_empty()
        } else {
            false
        };
        if remove_ip {
            self.swarms_by_ip.remove(&ip);
        }
    }

    fn admit(&mut self, info_hash: [u8; 20], addr: SocketAddr) -> bool {
        let addr = normalize_dht_addr(addr);
        self.prune_swarm(&info_hash);
        let now = Instant::now();
        if let Some(peers) = self.swarms.get_mut(&info_hash) {
            if let Some(existing) = peers.iter_mut().find(|peer| peer.addr == addr) {
                existing.last_seen = now;
                self.swarm_last_seen.insert(info_hash, now);
                return false;
            }
        }

        let source_ip = normalize_dht_ip(addr.ip());
        let source_swarms = self.swarms_by_ip.get(&source_ip);
        let source_already_in_swarm =
            source_swarms.is_some_and(|swarms| swarms.contains(&info_hash));
        if source_swarms.map_or(0, HashSet::len) >= MAX_STORED_SWARMS_PER_IP
            && !source_already_in_swarm
        {
            return false;
        }

        if !self.swarms.contains_key(&info_hash) && self.swarms.len() >= MAX_PEER_STORE_TORRENTS {
            self.evict_oldest_swarm();
        }
        if !self.swarms.contains_key(&info_hash) && self.swarms.len() >= MAX_PEER_STORE_TORRENTS {
            return false;
        }

        let peers = self.swarms.entry(info_hash).or_default();
        if peers
            .iter()
            .filter(|peer| normalize_dht_ip(peer.addr.ip()) == source_ip)
            .count()
            >= MAX_PEER_ENDPOINTS_PER_IP
            || peers
                .iter()
                .filter(|peer| same_network_prefix(peer.addr, addr))
                .count()
                >= MAX_PEER_ENDPOINTS_PER_PREFIX
        {
            return false;
        }
        let mut removed_ip = None;
        if peers.len() >= MAX_PEERS_PER_TORRENT {
            if let Some(oldest) = peers
                .iter()
                .enumerate()
                .min_by_key(|(_, peer)| peer.last_seen)
                .map(|(index, _)| index)
            {
                removed_ip = Some(peers.swap_remove(oldest).addr.ip());
            }
        }
        peers.push(StoredPeer {
            addr,
            last_seen: now,
        });
        self.swarm_last_seen.insert(info_hash, now);
        self.swarms_by_ip
            .entry(source_ip)
            .or_default()
            .insert(info_hash);
        if let Some(removed_ip) = removed_ip {
            self.remove_ip_membership_if_unused(info_hash, removed_ip);
        }
        true
    }
}

#[derive(Clone, Copy)]
struct PendingQuery {
    kind: PendingKind,
    addr: SocketAddr,
    expected_id: Option<[u8; 20]>,
    sent_at: Instant,
}

#[derive(Clone, Copy)]
enum PendingKind {
    FindNode,
    VerifyNode,
    ReplaceNode {
        candidate: Node,
        attempt: u8,
        probe_started_at: Instant,
    },
    RefreshBucket(u64),
}

/// An iterative lookup towards `target`: a bucket refresh (find_node) or,
/// when `peers` is set, a BEP 5 get_peers search for a torrent.
struct RefreshLookup {
    bucket_idx: usize,
    target: [u8; 20],
    candidates: Vec<Node>,
    queried: HashSet<SocketAddr>,
    outstanding: usize,
    authenticated_responses: usize,
    deadline: Instant,
    peers: Option<PeerLookup>,
}

struct PeerLookup {
    /// Our listening port to announce.
    port: u16,
    /// Responders that handed out write tokens, for the final announce.
    tokens: Vec<(Node, Vec<u8>)>,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum QueryPrefix {
    V4([u8; 3]),
    V6([u8; 8]),
}

fn query_prefix(addr: SocketAddr) -> QueryPrefix {
    match normalize_dht_ip(addr.ip()) {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            QueryPrefix::V4([octets[0], octets[1], octets[2]])
        }
        std::net::IpAddr::V6(ip) => {
            let octets = ip.octets();
            let mut prefix = [0u8; 8];
            prefix.copy_from_slice(&octets[..8]);
            QueryPrefix::V6(prefix)
        }
    }
}

#[derive(Clone, Copy)]
struct RateWindow {
    started_at: Instant,
    count: u32,
}

impl RateWindow {
    fn new(now: Instant) -> Self {
        Self {
            started_at: now,
            count: 0,
        }
    }

    fn count_at(&self, now: Instant) -> u32 {
        if now.duration_since(self.started_at) >= QUERY_RATE_WINDOW {
            0
        } else {
            self.count
        }
    }

    fn increment(&mut self, now: Instant) {
        if now.duration_since(self.started_at) >= QUERY_RATE_WINDOW {
            self.started_at = now;
            self.count = 0;
        }
        self.count = self.count.saturating_add(1);
    }
}

struct QueryRateLimiter {
    global: RateWindow,
    by_ip: HashMap<std::net::IpAddr, RateWindow>,
    by_prefix: HashMap<QueryPrefix, RateWindow>,
    last_prune: Instant,
}

impl QueryRateLimiter {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            global: RateWindow::new(now),
            by_ip: HashMap::new(),
            by_prefix: HashMap::new(),
            last_prune: now,
        }
    }

    fn allow(&mut self, addr: SocketAddr) -> bool {
        self.allow_at(addr, Instant::now())
    }

    fn allow_at(&mut self, addr: SocketAddr, now: Instant) -> bool {
        if now.duration_since(self.last_prune) >= QUERY_RATE_ENTRY_TTL {
            self.by_ip
                .retain(|_, window| now.duration_since(window.started_at) < QUERY_RATE_ENTRY_TTL);
            self.by_prefix
                .retain(|_, window| now.duration_since(window.started_at) < QUERY_RATE_ENTRY_TTL);
            self.last_prune = now;
        }

        let ip = normalize_dht_ip(addr.ip());
        let prefix = query_prefix(addr);
        if (!self.by_ip.contains_key(&ip) && self.by_ip.len() >= MAX_QUERY_RATE_ENTRIES)
            || (!self.by_prefix.contains_key(&prefix)
                && self.by_prefix.len() >= MAX_QUERY_RATE_ENTRIES)
            || self.global.count_at(now) >= MAX_QUERIES_PER_WINDOW_GLOBAL
            || self
                .by_ip
                .get(&ip)
                .is_some_and(|window| window.count_at(now) >= MAX_QUERIES_PER_WINDOW_IP)
            || self
                .by_prefix
                .get(&prefix)
                .is_some_and(|window| window.count_at(now) >= MAX_QUERIES_PER_WINDOW_PREFIX)
        {
            return false;
        }

        self.global.increment(now);
        self.by_ip
            .entry(ip)
            .or_insert_with(|| RateWindow::new(now))
            .increment(now);
        self.by_prefix
            .entry(prefix)
            .or_insert_with(|| RateWindow::new(now))
            .increment(now);
        true
    }
}

struct BootstrapResolution {
    deadline: Instant,
    addrs: Vec<SocketAddr>,
}

struct BootstrapAddress {
    addr: SocketAddr,
    resolved_at: Instant,
}

struct BootstrapResolverGuard {
    host_index: usize,
}

impl Drop for BootstrapResolverGuard {
    fn drop(&mut self) {
        BOOTSTRAP_RESOLVER_IN_FLIGHT[self.host_index].store(false, Ordering::Release);
    }
}

fn acquire_bootstrap_resolver_slot(slot: &AtomicBool) -> bool {
    slot.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

fn launch_bootstrap_resolvers(tx: &mpsc::SyncSender<BootstrapResolution>) {
    for (host_index, host) in BOOTSTRAP_NODES.into_iter().enumerate() {
        if !acquire_bootstrap_resolver_slot(&BOOTSTRAP_RESOLVER_IN_FLIGHT[host_index]) {
            continue;
        }
        let tx = tx.clone();
        let deadline = Instant::now() + BOOTSTRAP_RESOLUTION_DEADLINE;
        let spawn = thread::Builder::new()
            .name("dht-bootstrap-resolver".to_string())
            .spawn(move || {
                let _guard = BootstrapResolverGuard { host_index };
                let mut addrs = Vec::new();
                if let Ok(resolved) = host.to_socket_addrs() {
                    for addr in resolved.take(MAX_BOOTSTRAP_ADDRESSES_PER_HOST) {
                        if !addrs.contains(&addr) {
                            addrs.push(addr);
                        }
                    }
                }
                let _ = tx.try_send(BootstrapResolution { deadline, addrs });
            });
        if let Err(err) = spawn {
            BOOTSTRAP_RESOLVER_IN_FLIGHT[host_index].store(false, Ordering::Release);
            crate::log_stderr(format_args!("dht resolver thread failed: {err}"));
        }
    }
}

fn collect_bootstrap_resolutions(
    rx: &mpsc::Receiver<BootstrapResolution>,
    addrs: &mut Vec<BootstrapAddress>,
) {
    collect_bootstrap_resolutions_at(rx, addrs, Instant::now());
}

fn collect_bootstrap_resolutions_at(
    rx: &mpsc::Receiver<BootstrapResolution>,
    addrs: &mut Vec<BootstrapAddress>,
    now: Instant,
) {
    addrs.retain(|entry| now.duration_since(entry.resolved_at) <= BOOTSTRAP_ADDRESS_TTL);
    for resolution in rx.try_iter() {
        if now > resolution.deadline {
            continue;
        }
        for addr in resolution.addrs {
            if addr.port() == 0 || !is_global_dht_address(addr.ip()) {
                continue;
            }
            if let Some(existing) = addrs.iter_mut().find(|entry| entry.addr == addr) {
                existing.resolved_at = now;
            } else if addrs.len() < MAX_BOOTSTRAP_ADDRESSES {
                addrs.push(BootstrapAddress {
                    addr,
                    resolved_at: now,
                });
            }
        }
    }
}

fn dht_thread(
    bind_port: u16,
    cmd_rx: mpsc::Receiver<Command>,
    cache: Option<NodeCache>,
    test_candidates: Vec<Node>,
) {
    let socket = match UdpSocket::bind(("0.0.0.0", bind_port)) {
        Ok(socket) => socket,
        Err(_) => match UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, bind_port)) {
            Ok(socket) => socket,
            Err(err) => {
                crate::log_stderr(format_args!(
                    "dht bind {bind_port} failed: {err}, using ephemeral port"
                ));
                match UdpSocket::bind("0.0.0.0:0") {
                    Ok(socket) => socket,
                    Err(err) => {
                        crate::log_stderr(format_args!("dht bind failed: {err}"));
                        return;
                    }
                }
            }
        },
    };
    let _ = socket.set_read_timeout(Some(DHT_POLL_INTERVAL));
    // Remote public nodes are admitted only after BEP 42 validation. Our own
    // ID remains random because this process does not yet have a trustworthy
    // consensus view of its externally mapped address; guessing from one
    // remote response would let that responder choose our identity.
    let (Some(node_id), Some(mut token_secrets)) = (secure_random_id(), TokenSecrets::new()) else {
        crate::log_stderr(format_args!(
            "dht disabled: operating-system random source unavailable"
        ));
        return;
    };

    let mut rt = RoutingTable::new(node_id);
    let cached_candidates = cache
        .as_ref()
        .map(load_node_candidates)
        .transpose()
        .unwrap_or_else(|err| {
            crate::log_stderr(format_args!("dht cache load failed: {err}"));
            None
        })
        .unwrap_or_default();

    let mut torrents: HashMap<[u8; 20], TorrentEntry> = HashMap::new();
    let mut peer_store = PeerStore::new();
    let mut pending: HashMap<Vec<u8>, PendingQuery> = HashMap::new();
    let mut deferred_replacements = Vec::new();
    let mut refresh_lookups: HashMap<u64, RefreshLookup> = HashMap::new();
    let mut next_refresh_lookup_id = 0u64;
    let mut query_rate_limiter = QueryRateLimiter::new();
    let (bootstrap_tx, bootstrap_rx) = mpsc::sync_channel(BOOTSTRAP_NODES.len() * 2);
    let mut bootstrap_addrs = Vec::new();
    launch_bootstrap_resolvers(&bootstrap_tx);
    let mut last_bootstrap_resolver_launch = Instant::now();
    if !cached_candidates.is_empty() {
        crate::log_stderr(format_args!(
            "dht: verifying {} cached node candidates",
            cached_candidates.len()
        ));
        schedule_node_verifications(
            cached_candidates,
            false,
            MAX_CACHED_NODE_CANDIDATES,
            &rt,
            &mut pending,
            &socket,
            &node_id,
        );
    }
    if !test_candidates.is_empty() {
        schedule_node_verifications(
            test_candidates,
            true,
            MAX_CACHED_NODE_CANDIDATES,
            &rt,
            &mut pending,
            &socket,
            &node_id,
        );
    }

    let mut last_tick = Instant::now();
    let mut last_save = Instant::now();
    let mut last_peer_store_prune = Instant::now();
    let mut last_bucket_refresh_attempt = Instant::now();

    loop {
        loop {
            match cmd_rx.try_recv() {
                Ok(cmd) => match cmd {
                    Command::AddTorrent {
                        info_hash,
                        port,
                        peers_tx,
                    } => {
                        let now = Instant::now();
                        torrents.insert(
                            info_hash,
                            TorrentEntry {
                                peers_tx,
                                port,
                                last_query: now.checked_sub(QUERY_INTERVAL).unwrap_or(now),
                                last_bootstrap: now.checked_sub(BOOTSTRAP_INTERVAL).unwrap_or(now),
                            },
                        );
                    }
                    Command::RemoveTorrent { info_hash } => {
                        torrents.remove(&info_hash);
                        peer_store.remove(&info_hash);
                    }
                },
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    if let Some(cache) = cache.as_ref() {
                        if let Err(err) = save_nodes(&rt, cache) {
                            crate::log_stderr(format_args!("dht cache save failed: {err}"));
                        }
                    }
                    return;
                }
            };
        }

        if last_tick.elapsed() >= Duration::from_millis(200) {
            last_tick = Instant::now();
            token_secrets.rotate_if_due();
            collect_bootstrap_resolutions(&bootstrap_rx, &mut bootstrap_addrs);
            if last_bootstrap_resolver_launch.elapsed() >= BOOTSTRAP_RESOLUTION_REFRESH {
                launch_bootstrap_resolvers(&bootstrap_tx);
                last_bootstrap_resolver_launch = Instant::now();
            }
            if torrents
                .values()
                .any(|entry| entry.last_bootstrap.elapsed() >= BOOTSTRAP_INTERVAL)
            {
                let bootstrap_attempted =
                    bootstrap_nodes(&socket, &node_id, &bootstrap_addrs, &mut rt, &mut pending);
                if bootstrap_attempted {
                    let now = Instant::now();
                    for entry in torrents.values_mut() {
                        entry.last_bootstrap = now;
                    }
                }
            }
            for (info_hash, entry) in torrents.iter_mut() {
                if entry.last_query.elapsed() >= QUERY_INTERVAL
                    && start_peer_lookup(
                        *info_hash,
                        crate::announce_port(entry.port),
                        &mut rt,
                        &mut pending,
                        &socket,
                        &node_id,
                        &mut refresh_lookups,
                        &mut next_refresh_lookup_id,
                    )
                {
                    entry.last_query = Instant::now();
                }
            }
            expire_pending_queries(
                &mut rt,
                &mut pending,
                &socket,
                &node_id,
                &mut deferred_replacements,
                &mut refresh_lookups,
            );
            maintain_deferred_replacements(
                &mut deferred_replacements,
                &mut rt,
                &mut pending,
                &socket,
                &node_id,
            );
            maintain_refresh_lookups(
                &mut rt,
                &mut pending,
                &socket,
                &node_id,
                &mut refresh_lookups,
            );
            if last_bucket_refresh_attempt.elapsed() >= BUCKET_REFRESH_SPACING {
                schedule_bucket_refresh(
                    &mut rt,
                    &mut pending,
                    &socket,
                    &node_id,
                    &mut refresh_lookups,
                    &mut next_refresh_lookup_id,
                );
                last_bucket_refresh_attempt = Instant::now();
            }
            if last_peer_store_prune.elapsed() >= PEER_STORE_PRUNE_INTERVAL {
                prune_peer_store(&mut peer_store);
                last_peer_store_prune = Instant::now();
            }
        }

        if last_save.elapsed() >= SAVE_INTERVAL {
            if let Some(cache) = cache.as_ref() {
                if let Err(err) = save_nodes(&rt, cache) {
                    crate::log_stderr(format_args!("dht cache save failed: {err}"));
                }
            }
            last_save = Instant::now();
        }

        let mut buf = [0u8; 1500];
        if let Ok((n, addr)) = socket.recv_from(&mut buf) {
            let addr = normalize_dht_addr(addr);
            if let Ok(Value::Dict(dict)) = bencode::parse(&buf[..n]) {
                if let Some(Value::Bytes(y)) = dict_get(&dict, b"y") {
                    match y.as_slice() {
                        b"r" => handle_response(
                            &dict,
                            &addr,
                            &mut rt,
                            &mut pending,
                            &socket,
                            &node_id,
                            &mut peer_store,
                            &torrents,
                            &mut deferred_replacements,
                            &mut refresh_lookups,
                        ),
                        b"q" if query_rate_limiter.allow(addr) => handle_query(
                            &dict,
                            &addr,
                            &socket,
                            &node_id,
                            &token_secrets,
                            &mut rt,
                            &mut peer_store,
                            &torrents,
                        ),
                        _ => {}
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_response(
    dict: &[(Vec<u8>, Value)],
    addr: &SocketAddr,
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    _peer_store: &mut PeerStore,
    torrents: &HashMap<[u8; 20], TorrentEntry>,
    deferred_replacements: &mut Vec<Node>,
    refresh_lookups: &mut HashMap<u64, RefreshLookup>,
) {
    let normalized_addr = normalize_dht_addr(*addr);
    let addr = &normalized_addr;
    let tx = match dict_get(dict, b"t") {
        Some(Value::Bytes(tx)) if !tx.is_empty() && tx.len() <= MAX_TRANSACTION_ID_LEN => {
            tx.clone()
        }
        _ => return,
    };
    let Some(expected) = pending.get(&tx) else {
        return;
    };
    if expected.addr != *addr {
        return;
    }
    let Some(Value::Dict(r)) = dict_get(dict, b"r") else {
        return;
    };
    let responder_id = match dict_get(r, b"id") {
        Some(Value::Bytes(id)) if id.len() == 20 => {
            let mut responder_id = [0u8; 20];
            responder_id.copy_from_slice(id);
            responder_id
        }
        _ => return,
    };
    let pending_query = match pending.remove(&tx) {
        Some(query) => query,
        None => return,
    };
    if pending_query
        .expected_id
        .is_some_and(|expected_id| expected_id != responder_id)
    {
        fail_pending_query(
            rt,
            pending_query,
            pending,
            socket,
            node_id,
            deferred_replacements,
            refresh_lookups,
            None,
        );
        return;
    }
    let trusted_responder = node_id_matches_address(&responder_id, *addr);
    if !trusted_responder {
        fail_pending_query(
            rt,
            pending_query,
            pending,
            socket,
            node_id,
            deferred_replacements,
            refresh_lookups,
            None,
        );
        return;
    }
    let verified_node = Node {
        id: responder_id,
        addr: *addr,
        last_seen: Instant::now(),
    };
    let inserted = rt.insert_verified(verified_node);
    if matches!(
        pending_query.kind,
        PendingKind::VerifyNode | PendingKind::RefreshBucket(_)
    ) && !inserted
        && !rt.contains_endpoint(*addr)
    {
        queue_deferred_replacement(deferred_replacements, verified_node);
    }

    if let PendingKind::ReplaceNode { candidate, .. } = pending_query.kind {
        queue_deferred_replacement(deferred_replacements, candidate);
        return;
    }

    if let PendingKind::RefreshBucket(lookup_id) = pending_query.kind {
        complete_refresh_query(
            lookup_id,
            r,
            verified_node,
            torrents,
            rt,
            pending,
            socket,
            node_id,
            refresh_lookups,
        );
        return;
    }

    if !matches!(
        pending_query.kind,
        PendingKind::VerifyNode | PendingKind::ReplaceNode { .. } | PendingKind::RefreshBucket(_)
    ) {
        let mut candidates = Vec::new();
        if let Some(Value::Bytes(nodes_bytes)) = dict_get(r, b"nodes") {
            candidates.extend(
                decode_nodes(nodes_bytes)
                    .into_iter()
                    .take(MAX_NODE_CANDIDATES_PER_RESPONSE),
            );
        }
        if candidates.len() < MAX_NODE_CANDIDATES_PER_RESPONSE {
            if let Some(Value::Bytes(nodes6_bytes)) = dict_get(r, b"nodes6") {
                candidates.extend(
                    decode_nodes6(nodes6_bytes)
                        .into_iter()
                        .take(MAX_NODE_CANDIDATES_PER_RESPONSE - candidates.len()),
                );
            }
        }
        schedule_node_verifications(
            candidates,
            is_local_dht_address(pending_query.addr.ip()),
            MAX_NODE_CANDIDATES_PER_RESPONSE,
            rt,
            pending,
            socket,
            node_id,
        );
    }
}

/// Forwards peers from a get_peers response to the torrent, keeping only
/// addresses the responder may legitimately point us at.
fn deliver_peer_values(
    response: &[(Vec<u8>, Value)],
    responder: SocketAddr,
    info_hash: [u8; 20],
    torrents: &HashMap<[u8; 20], TorrentEntry>,
) {
    let Some(Value::List(values)) = dict_get(response, b"values") else {
        return;
    };
    let mut peers: Vec<SocketAddr> = values
        .iter()
        .filter_map(|value| match value {
            Value::Bytes(bytes) => decode_peer_value(bytes),
            _ => None,
        })
        .filter(|peer| dht_address_scope_allowed(responder, *peer))
        .collect();
    crate::util::sort(&mut peers);
    peers.dedup();
    peers.truncate(MAX_PEERS_PER_TORRENT);
    if let (false, Some(entry)) = (peers.is_empty(), torrents.get(&info_hash)) {
        let _ = entry.peers_tx.send(peers);
    }
}

fn schedule_node_verifications(
    candidates: Vec<Node>,
    allow_local_candidates: bool,
    max_candidates: usize,
    rt: &RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
) {
    for mut candidate in candidates.into_iter().take(max_candidates) {
        candidate.addr = normalize_dht_addr(candidate.addr);
        if pending.len() >= MAX_PENDING_QUERIES {
            break;
        }
        if candidate.id == *node_id
            || candidate.addr.port() == 0
            || candidate.addr.ip().is_unspecified()
            || !(is_global_dht_address(candidate.addr.ip())
                || (allow_local_candidates && is_local_dht_address(candidate.addr.ip())))
            || !node_id_matches_address(&candidate.id, candidate.addr)
            || rt.contains_endpoint(candidate.addr)
            || pending.values().any(|query| query.addr == candidate.addr)
            || !candidate_probe_fits_diversity(rt, pending, candidate.addr)
        {
            continue;
        }
        let Some(tx) = next_unique_tx(pending) else {
            break;
        };
        let query = build_ping_query(node_id, &tx);
        if socket.send_to(&query, candidate.addr).is_ok() {
            pending.insert(
                tx,
                PendingQuery {
                    kind: PendingKind::VerifyNode,
                    addr: candidate.addr,
                    expected_id: Some(candidate.id),
                    sent_at: Instant::now(),
                },
            );
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReplacementSchedule {
    Scheduled,
    Healthy,
    Busy,
}

fn try_schedule_bucket_replacement(
    candidate: Node,
    rt: &RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
) -> ReplacementSchedule {
    if pending.len() >= MAX_PENDING_QUERIES {
        return ReplacementSchedule::Busy;
    }
    let questionable = rt.questionable_incumbents(candidate);
    if questionable.is_empty() {
        return ReplacementSchedule::Healthy;
    }
    let incumbent = questionable[0];
    if pending.values().any(|query| query.addr == incumbent.addr) {
        return ReplacementSchedule::Busy;
    }
    let Some(tx) = next_unique_tx(pending) else {
        return ReplacementSchedule::Busy;
    };
    let query = build_ping_query(node_id, &tx);
    if socket.send_to(&query, incumbent.addr).is_ok() {
        let probe_started_at = Instant::now();
        pending.insert(
            tx,
            PendingQuery {
                kind: PendingKind::ReplaceNode {
                    candidate,
                    attempt: 1,
                    probe_started_at,
                },
                addr: incumbent.addr,
                expected_id: Some(incumbent.id),
                sent_at: probe_started_at,
            },
        );
        return ReplacementSchedule::Scheduled;
    }
    ReplacementSchedule::Busy
}

fn queue_deferred_replacement(queue: &mut Vec<Node>, mut candidate: Node) {
    candidate.addr = normalize_dht_addr(candidate.addr);
    if queue
        .iter()
        .any(|queued| queued.id == candidate.id || queued.addr == candidate.addr)
    {
        return;
    }
    queue.retain(|queued| queued.last_seen.elapsed() <= DEFERRED_REPLACEMENT_TTL);
    if queue.len() >= MAX_DEFERRED_REPLACEMENTS {
        if let Some(oldest) = queue
            .iter()
            .enumerate()
            .min_by_key(|(_, node)| node.last_seen)
            .map(|(idx, _)| idx)
        {
            queue.swap_remove(oldest);
        }
    }
    queue.push(candidate);
}

fn maintain_deferred_replacements(
    queue: &mut Vec<Node>,
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
) {
    queue.retain(|candidate| candidate.last_seen.elapsed() <= DEFERRED_REPLACEMENT_TTL);
    if queue.is_empty() {
        return;
    }
    let candidate = queue.remove(0);
    if rt.contains_endpoint(candidate.addr) {
        return;
    }
    let bucket_idx = rt.bucket_index(&candidate.id);
    if rt.buckets[bucket_idx].len() < K {
        let _ = rt.insert_verified(candidate);
        return;
    }
    if try_schedule_bucket_replacement(candidate, rt, pending, socket, node_id)
        == ReplacementSchedule::Busy
    {
        queue_deferred_replacement(queue, candidate);
    }
}

fn candidate_probe_fits_diversity(
    rt: &RoutingTable,
    pending: &HashMap<Vec<u8>, PendingQuery>,
    addr: SocketAddr,
) -> bool {
    let verified = rt.buckets.iter().flatten().map(|node| node.addr);
    let verifying = pending.values().filter_map(|query| match query.kind {
        PendingKind::VerifyNode => Some(query.addr),
        PendingKind::ReplaceNode { candidate, .. } => Some(candidate.addr),
        PendingKind::RefreshBucket(_) => Some(query.addr),
        _ => None,
    });
    let candidates: Vec<SocketAddr> = verified.chain(verifying).collect();
    candidates
        .iter()
        .filter(|candidate| normalize_dht_ip(candidate.ip()) == normalize_dht_ip(addr.ip()))
        .count()
        < MAX_NODES_PER_IP
        && candidates
            .iter()
            .filter(|candidate| same_network_prefix(**candidate, addr))
            .count()
            < MAX_NODES_PER_PREFIX
}

#[allow(clippy::too_many_arguments)]
fn expire_pending_queries(
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    deferred_replacements: &mut Vec<Node>,
    refresh_lookups: &mut HashMap<u64, RefreshLookup>,
) {
    expire_pending_queries_at(
        rt,
        pending,
        Instant::now(),
        socket,
        node_id,
        deferred_replacements,
        refresh_lookups,
    );
}

#[allow(clippy::too_many_arguments)]
fn expire_pending_queries_at(
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    now: Instant,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    deferred_replacements: &mut Vec<Node>,
    refresh_lookups: &mut HashMap<u64, RefreshLookup>,
) {
    let expired_queries: Vec<(Vec<u8>, PendingQuery)> = pending
        .iter()
        .filter(|(_, query)| now.duration_since(query.sent_at) > MAX_PENDING_AGE)
        .map(|(tx, query)| (tx.clone(), *query))
        .collect();
    pending.retain(|_, query| now.duration_since(query.sent_at) <= MAX_PENDING_AGE);
    for (tx, query) in expired_queries {
        fail_pending_query(
            rt,
            query,
            pending,
            socket,
            node_id,
            deferred_replacements,
            refresh_lookups,
            Some(tx),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn fail_pending_query(
    rt: &mut RoutingTable,
    query: PendingQuery,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    deferred_replacements: &mut Vec<Node>,
    refresh_lookups: &mut HashMap<u64, RefreshLookup>,
    retry_tx: Option<Vec<u8>>,
) {
    match query.kind {
        PendingKind::ReplaceNode {
            candidate,
            attempt,
            probe_started_at,
        } => {
            let expected_id = query.expected_id.unwrap_or_default();
            if attempt < MAX_REPLACEMENT_PROBE_ATTEMPTS
                && rt.incumbent_unchanged_since(expected_id, query.addr, probe_started_at)
                && pending.len() < MAX_PENDING_QUERIES
            {
                let tx = retry_tx
                    .filter(|tx| !pending.contains_key(tx))
                    .or_else(|| next_unique_tx(pending));
                if let Some(tx) = tx {
                    let ping = build_ping_query(node_id, &tx);
                    if socket.send_to(&ping, query.addr).is_ok() {
                        pending.insert(
                            tx,
                            PendingQuery {
                                kind: PendingKind::ReplaceNode {
                                    candidate,
                                    attempt: attempt + 1,
                                    probe_started_at,
                                },
                                addr: query.addr,
                                expected_id: query.expected_id,
                                sent_at: Instant::now(),
                            },
                        );
                        return;
                    }
                }
            } else if attempt >= MAX_REPLACEMENT_PROBE_ATTEMPTS
                && rt.replace_questionable(expected_id, query.addr, probe_started_at, candidate)
            {
                return;
            }
            queue_deferred_replacement(deferred_replacements, candidate);
        }
        PendingKind::RefreshBucket(lookup_id) => {
            if let Some(lookup) = refresh_lookups.get_mut(&lookup_id) {
                lookup.outstanding = lookup.outstanding.saturating_sub(1);
            }
            rt.record_query_failure(query.addr, query.sent_at);
            advance_refresh_lookup(lookup_id, rt, pending, socket, node_id, refresh_lookups);
            return;
        }
        _ => {}
    }
    rt.record_query_failure(query.addr, query.sent_at);
}

#[allow(clippy::too_many_arguments)]
fn handle_query(
    dict: &[(Vec<u8>, Value)],
    addr: &SocketAddr,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    token_secrets: &TokenSecrets,
    rt: &mut RoutingTable,
    peer_store: &mut PeerStore,
    torrents: &HashMap<[u8; 20], TorrentEntry>,
) {
    let normalized_addr = normalize_dht_addr(*addr);
    let addr = &normalized_addr;
    let tx = match dict_get(dict, b"t") {
        Some(Value::Bytes(tx)) if !tx.is_empty() && tx.len() <= MAX_TRANSACTION_ID_LEN => {
            tx.clone()
        }
        _ => return,
    };
    let Some(Value::Bytes(query)) = dict_get(dict, b"q") else {
        return;
    };
    let Some(Value::Dict(args)) = dict_get(dict, b"a") else {
        return;
    };
    let sender_id = match dict_get(args, b"id") {
        Some(Value::Bytes(id)) if id.len() == 20 => {
            let mut sender_id = [0u8; 20];
            sender_id.copy_from_slice(id);
            sender_id
        }
        _ => return,
    };
    // Unknown query senders are not admitted, but a query from a node that
    // previously answered one of our probes is positive liveness evidence.
    let _ = rt.refresh_verified(&sender_id, *addr);

    match query.as_slice() {
        b"ping" => {
            let resp = build_response(node_id, &tx, vec![], *addr);
            let _ = socket.send_to(&resp, addr);
        }
        b"find_node" => {
            let target = match dict_get(args, b"target") {
                Some(Value::Bytes(t)) if t.len() == 20 => {
                    let mut arr = [0u8; 20];
                    arr.copy_from_slice(t);
                    arr
                }
                _ => return,
            };
            let r = closest_node_fields(rt, &target, *addr, args);
            let resp = build_response(node_id, &tx, r, *addr);
            let _ = socket.send_to(&resp, addr);
        }
        b"get_peers" => {
            let Some(Value::Bytes(info_hash)) = dict_get(args, b"info_hash") else {
                return;
            };
            if info_hash.len() != 20 {
                return;
            }
            let mut info_hash_arr = [0u8; 20];
            info_hash_arr.copy_from_slice(info_hash);
            let mut values = b"l".to_vec();
            for peer in peer_store
                .get(&info_hash_arr)
                .unwrap_or_default()
                .iter()
                .filter(|peer| peer.last_seen.elapsed() <= PEER_STORE_TTL)
                .filter(|peer| peer.addr.is_ipv4() == addr.is_ipv4())
                .filter(|peer| dht_address_scope_allowed(*addr, peer.addr))
                .take(50)
            {
                put_bstr(&mut values, &encode_peer(peer.addr));
            }
            values.push(b'e');
            // Fields in bencode key order: nodes, nodes6, token, values.
            let mut r = if values.len() == 2 {
                closest_node_fields(rt, &info_hash_arr, *addr, args)
            } else {
                Vec::new()
            };
            r.push(("token", bstr(&token_secrets.make(addr))));
            if values.len() > 2 {
                r.push(("values", values));
            }
            let resp = build_response(node_id, &tx, r, *addr);
            let _ = socket.send_to(&resp, addr);
        }
        b"announce_peer" => {
            let Some(Value::Bytes(info_hash)) = dict_get(args, b"info_hash") else {
                return;
            };
            let Some(Value::Bytes(token)) = dict_get(args, b"token") else {
                return;
            };
            if !token_secrets.verify(addr, token) {
                return;
            }
            let announced_port = match dict_get(args, b"port") {
                Some(Value::Int(port)) if *port > 0 && *port <= u16::MAX as i64 => *port as u16,
                _ => return,
            };
            let port = match dict_get(args, b"implied_port") {
                Some(Value::Int(value)) if *value != 0 => addr.port(),
                _ => announced_port,
            };
            let mut info_hash_arr = [0u8; 20];
            if info_hash.len() != 20 {
                return;
            }
            info_hash_arr.copy_from_slice(info_hash);
            let peer_addr = SocketAddr::new(addr.ip(), port);
            if admit_announced_peer(peer_store, info_hash_arr, peer_addr) {
                if let Some(entry) = torrents.get(&info_hash_arr) {
                    let _ = entry.peers_tx.send(vec![peer_addr]);
                }
            }
            let resp = build_response(node_id, &tx, vec![], *addr);
            let _ = socket.send_to(&resp, addr);
        }
        _ => {}
    }
}

fn requested_node_families(args: &[(Vec<u8>, Value)], requester: SocketAddr) -> (bool, bool) {
    if let Some(Value::List(want)) = dict_get(args, b"want") {
        let wants_v4 = want
            .iter()
            .any(|value| matches!(value, Value::Bytes(bytes) if bytes == b"n4"));
        let wants_v6 = want
            .iter()
            .any(|value| matches!(value, Value::Bytes(bytes) if bytes == b"n6"));
        if wants_v4 || wants_v6 {
            return (wants_v4, wants_v6);
        }
    }
    let requester = normalize_dht_addr(requester);
    (requester.is_ipv4(), requester.is_ipv6())
}

/// Response fields as (key, bencoded value) pairs.
type ResponseFields = Vec<(&'static str, Vec<u8>)>;

fn closest_node_fields(
    rt: &RoutingTable,
    target: &[u8; 20],
    requester: SocketAddr,
    args: &[(Vec<u8>, Value)],
) -> ResponseFields {
    let (wants_v4, wants_v6) = requested_node_families(args, requester);
    let mut fields = Vec::with_capacity(3);
    if wants_v4 {
        fields.push(("nodes", bstr(&rt.encode_closest_nodes(target, requester))));
    }
    if wants_v6 {
        fields.push(("nodes6", bstr(&rt.encode_closest_nodes6(target, requester))));
    }
    fields
}

fn put_bstr(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(bytes);
}

fn bstr(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 4);
    put_bstr(&mut out, bytes);
    out
}

/// Encodes a KRPC response directly as bencode. `fields` follow our "id" in
/// sorted key order; the BEP 42 "ip" field reports the requester's address.
fn build_response(
    node_id: &[u8; 20],
    tx: &[u8],
    fields: ResponseFields,
    observed_addr: SocketAddr,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(b"d2:ip");
    put_bstr(&mut out, &encode_peer(normalize_dht_addr(observed_addr)));
    out.extend_from_slice(b"1:rd2:id20:");
    out.extend_from_slice(node_id);
    for (key, value) in fields {
        put_bstr(&mut out, key.as_bytes());
        out.extend_from_slice(&value);
    }
    out.extend_from_slice(b"e1:t");
    put_bstr(&mut out, tx);
    out.extend_from_slice(b"1:y1:re");
    out
}

/// Encodes a KRPC query directly as bencode. `args` (after our "id") must
/// be given in sorted key order, as bencode dictionaries require.
fn build_query(
    node_id: &[u8; 20],
    method: &str,
    tx: &[u8],
    args: &[(&str, QueryArg<'_>)],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(b"d1:ad2:id20:");
    out.extend_from_slice(node_id);
    for (key, value) in args {
        put_bstr(&mut out, key.as_bytes());
        match value {
            QueryArg::Bytes(bytes) => put_bstr(&mut out, bytes),
            QueryArg::Int(value) => {
                out.push(b'i');
                out.extend_from_slice(value.to_string().as_bytes());
                out.push(b'e');
            }
        }
    }
    out.extend_from_slice(b"e1:q");
    put_bstr(&mut out, method.as_bytes());
    out.extend_from_slice(b"1:t");
    put_bstr(&mut out, tx);
    out.extend_from_slice(b"1:y1:qe");
    out
}

enum QueryArg<'a> {
    Bytes(&'a [u8]),
    Int(u16),
}

fn build_ping_query(node_id: &[u8; 20], tx: &[u8]) -> Vec<u8> {
    build_query(node_id, "ping", tx, &[])
}

fn build_get_peers_query(node_id: &[u8; 20], info_hash: [u8; 20], tx: &[u8]) -> Vec<u8> {
    build_query(
        node_id,
        "get_peers",
        tx,
        &[("info_hash", QueryArg::Bytes(&info_hash))],
    )
}

fn build_announce_peer_query(
    node_id: &[u8; 20],
    info_hash: [u8; 20],
    port: u16,
    token: &[u8],
    tx: &[u8],
) -> Vec<u8> {
    build_query(
        node_id,
        "announce_peer",
        tx,
        &[
            ("info_hash", QueryArg::Bytes(&info_hash)),
            ("port", QueryArg::Int(port)),
            ("token", QueryArg::Bytes(token)),
        ],
    )
}

fn build_find_node_query(node_id: &[u8; 20], target: &[u8; 20], tx: &[u8]) -> Vec<u8> {
    build_query(
        node_id,
        "find_node",
        tx,
        &[("target", QueryArg::Bytes(target))],
    )
}

fn bootstrap_nodes(
    socket: &UdpSocket,
    node_id: &[u8; 20],
    bootstrap_addrs: &[BootstrapAddress],
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
) -> bool {
    if rt.node_count() > K * 2 {
        return true;
    }
    if bootstrap_addrs.is_empty() {
        return false;
    }
    for entry in bootstrap_addrs {
        let addr = entry.addr;
        if pending.len() >= MAX_PENDING_QUERIES {
            break;
        }
        if rt.contains_endpoint(addr) || pending.values().any(|query| query.addr == addr) {
            continue;
        }
        let Some(tx) = next_unique_tx(pending) else {
            break;
        };
        let query = build_find_node_query(node_id, node_id, &tx);
        if socket.send_to(&query, addr).is_ok() {
            pending.insert(
                tx,
                PendingQuery {
                    kind: PendingKind::FindNode,
                    addr,
                    expected_id: None,
                    sent_at: Instant::now(),
                },
            );
        }
    }
    true
}

fn schedule_bucket_refresh(
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    refresh_lookups: &mut HashMap<u64, RefreshLookup>,
    next_lookup_id: &mut u64,
) {
    if pending.len() >= MAX_PENDING_QUERIES
        || refresh_lookups
            .values()
            .any(|lookup| lookup.peers.is_none())
    {
        return;
    }
    let now = Instant::now();
    let Some(bucket_idx) = rt.bucket_needing_refresh(now) else {
        return;
    };
    let Some(target) = random_target_for_bucket(node_id, bucket_idx) else {
        return;
    };
    rt.mark_bucket_refresh_attempted(bucket_idx, now);
    let lookup_id = *next_lookup_id;
    *next_lookup_id = next_lookup_id.wrapping_add(1);
    refresh_lookups.insert(
        lookup_id,
        RefreshLookup {
            bucket_idx,
            target,
            candidates: rt.closest(&target, K),
            queried: HashSet::new(),
            outstanding: 0,
            authenticated_responses: 0,
            deadline: now + REFRESH_LOOKUP_DEADLINE,
            peers: None,
        },
    );
    advance_refresh_lookup(lookup_id, rt, pending, socket, node_id, refresh_lookups);
}

/// Starts a get_peers lookup for `info_hash` unless one is already running.
#[allow(clippy::too_many_arguments)]
fn start_peer_lookup(
    info_hash: [u8; 20],
    port: u16,
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    refresh_lookups: &mut HashMap<u64, RefreshLookup>,
    next_lookup_id: &mut u64,
) -> bool {
    let active = refresh_lookups
        .values()
        .filter(|lookup| lookup.peers.is_some())
        .count();
    let candidates = rt.closest(&info_hash, K);
    if active >= MAX_PEER_LOOKUPS
        || candidates.is_empty()
        || refresh_lookups
            .values()
            .any(|lookup| lookup.peers.is_some() && lookup.target == info_hash)
    {
        return false;
    }
    let lookup_id = *next_lookup_id;
    *next_lookup_id = next_lookup_id.wrapping_add(1);
    refresh_lookups.insert(
        lookup_id,
        RefreshLookup {
            bucket_idx: usize::MAX,
            target: info_hash,
            candidates,
            queried: HashSet::new(),
            outstanding: 0,
            authenticated_responses: 0,
            deadline: Instant::now() + REFRESH_LOOKUP_DEADLINE,
            peers: Some(PeerLookup {
                port,
                tokens: Vec::new(),
            }),
        },
    );
    advance_refresh_lookup(lookup_id, rt, pending, socket, node_id, refresh_lookups);
    true
}

/// Completes a lookup: a refresh marks its bucket fresh; a peer search
/// announces to the closest responders that issued write tokens.
fn finish_lookup(
    lookup: RefreshLookup,
    rt: &mut RoutingTable,
    socket: &UdpSocket,
    node_id: &[u8; 20],
) {
    let Some(peers) = lookup.peers else {
        if lookup.authenticated_responses > 0 {
            rt.mark_bucket_refreshed(lookup.bucket_idx, Instant::now());
        }
        return;
    };
    // Candidates are kept sorted by distance, so this announces to the
    // closest responders that issued tokens.
    let closest = lookup.candidates.iter().filter_map(|candidate| {
        peers
            .tokens
            .iter()
            .find(|(node, _)| node.addr == candidate.addr)
    });
    for (node, token) in closest.take(K) {
        let query =
            build_announce_peer_query(node_id, lookup.target, peers.port, token, &next_tx_id());
        let _ = socket.send_to(&query, node.addr);
    }
}

fn maintain_refresh_lookups(
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    refresh_lookups: &mut HashMap<u64, RefreshLookup>,
) {
    let now = Instant::now();
    let lookup_ids: Vec<u64> = refresh_lookups.keys().copied().collect();
    for lookup_id in lookup_ids {
        if refresh_lookups
            .get(&lookup_id)
            .is_some_and(|lookup| now >= lookup.deadline)
        {
            let Some(lookup) = refresh_lookups.remove(&lookup_id) else {
                continue;
            };
            pending.retain(
                |_, query| !matches!(query.kind, PendingKind::RefreshBucket(id) if id == lookup_id),
            );
            finish_lookup(lookup, rt, socket, node_id);
            continue;
        }
        advance_refresh_lookup(lookup_id, rt, pending, socket, node_id, refresh_lookups);
    }
}

fn advance_refresh_lookup(
    lookup_id: u64,
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    refresh_lookups: &mut HashMap<u64, RefreshLookup>,
) {
    // Candidates are kept sorted by distance to the target: lookups start
    // from `RoutingTable::closest` and responses re-sort after merging.
    let Some(lookup) = refresh_lookups.get_mut(&lookup_id) else {
        return;
    };

    while lookup.outstanding < REFRESH_LOOKUP_ALPHA
        && lookup.queried.len() < MAX_REFRESH_LOOKUP_QUERIES
        && pending.len() < MAX_PENDING_QUERIES
    {
        let mut selected = None;
        let mut blocked = false;
        for candidate in &lookup.candidates {
            if lookup.queried.contains(&candidate.addr) {
                continue;
            }
            if pending.values().any(|query| query.addr == candidate.addr) {
                blocked = true;
                continue;
            }
            if !rt.contains_endpoint(candidate.addr)
                && !candidate_probe_fits_diversity(rt, pending, candidate.addr)
            {
                lookup.queried.insert(candidate.addr);
                continue;
            }
            selected = Some(*candidate);
            break;
        }
        let Some(candidate) = selected else {
            if blocked {
                return;
            }
            break;
        };
        lookup.queried.insert(candidate.addr);
        let Some(tx) = next_unique_tx(pending) else {
            break;
        };
        let query = if lookup.peers.is_some() {
            build_get_peers_query(node_id, lookup.target, &tx)
        } else {
            build_find_node_query(node_id, &lookup.target, &tx)
        };
        if socket.send_to(&query, candidate.addr).is_ok() {
            pending.insert(
                tx,
                PendingQuery {
                    kind: PendingKind::RefreshBucket(lookup_id),
                    addr: candidate.addr,
                    expected_id: Some(candidate.id),
                    sent_at: Instant::now(),
                },
            );
            lookup.outstanding += 1;
        }
    }

    let exhausted = lookup.queried.len() >= MAX_REFRESH_LOOKUP_QUERIES
        || lookup
            .candidates
            .iter()
            .all(|candidate| lookup.queried.contains(&candidate.addr));
    if lookup.outstanding == 0 && exhausted {
        if let Some(lookup) = refresh_lookups.remove(&lookup_id) {
            finish_lookup(lookup, rt, socket, node_id);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn complete_refresh_query(
    lookup_id: u64,
    response: &[(Vec<u8>, Value)],
    responder: Node,
    torrents: &HashMap<[u8; 20], TorrentEntry>,
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    refresh_lookups: &mut HashMap<u64, RefreshLookup>,
) {
    let Some(lookup) = refresh_lookups.get_mut(&lookup_id) else {
        return;
    };
    lookup.outstanding = lookup.outstanding.saturating_sub(1);
    lookup.authenticated_responses = lookup.authenticated_responses.saturating_add(1);
    if let Some(peers) = lookup.peers.as_mut() {
        deliver_peer_values(response, responder.addr, lookup.target, torrents);
        if let Some(Value::Bytes(token)) = dict_get(response, b"token") {
            if token.len() <= 64 && peers.tokens.len() < MAX_REFRESH_LOOKUP_QUERIES {
                peers.tokens.push((responder, token.clone()));
            }
        }
    }

    let allow_local = is_local_dht_address(responder.addr.ip());
    let mut returned = Vec::new();
    if let Some(Value::Bytes(nodes)) = dict_get(response, b"nodes") {
        returned.extend(
            decode_nodes(nodes)
                .into_iter()
                .take(MAX_NODE_CANDIDATES_PER_RESPONSE),
        );
    }
    if returned.len() < MAX_NODE_CANDIDATES_PER_RESPONSE {
        if let Some(Value::Bytes(nodes6)) = dict_get(response, b"nodes6") {
            returned.extend(
                decode_nodes6(nodes6)
                    .into_iter()
                    .take(MAX_NODE_CANDIDATES_PER_RESPONSE - returned.len()),
            );
        }
    }
    for mut candidate in returned {
        candidate.addr = normalize_dht_addr(candidate.addr);
        if candidate.id == *node_id
            || candidate.addr.port() == 0
            || candidate.addr.ip().is_unspecified()
            || !(is_global_dht_address(candidate.addr.ip())
                || (allow_local && is_local_dht_address(candidate.addr.ip())))
            || !node_id_matches_address(&candidate.id, candidate.addr)
            || lookup
                .candidates
                .iter()
                .any(|known| known.id == candidate.id || known.addr == candidate.addr)
        {
            continue;
        }
        let same_ip = lookup
            .candidates
            .iter()
            .filter(|known| {
                normalize_dht_ip(known.addr.ip()) == normalize_dht_ip(candidate.addr.ip())
            })
            .count();
        let same_prefix = lookup
            .candidates
            .iter()
            .filter(|known| same_network_prefix(known.addr, candidate.addr))
            .count();
        if same_ip >= MAX_NODES_PER_IP || same_prefix >= MAX_NODES_PER_PREFIX {
            continue;
        }
        lookup.candidates.push(candidate);
    }
    crate::util::sort_by_key(&mut lookup.candidates, |candidate| {
        xor_distance(&candidate.id, &lookup.target)
    });
    lookup.candidates.truncate(MAX_REFRESH_LOOKUP_CANDIDATES);
    advance_refresh_lookup(lookup_id, rt, pending, socket, node_id, refresh_lookups);
}

fn random_target_for_bucket(own_id: &[u8; 20], bucket_idx: usize) -> Option<[u8; 20]> {
    if bucket_idx >= NUM_BUCKETS {
        return None;
    }
    let mut target = secure_random_id()?;
    let differing_bit = NUM_BUCKETS - 1 - bucket_idx;
    for bit in 0..differing_bit {
        let byte = bit / 8;
        let mask = 0x80 >> (bit % 8);
        target[byte] = (target[byte] & !mask) | (own_id[byte] & mask);
    }
    let byte = differing_bit / 8;
    let mask = 0x80 >> (differing_bit % 8);
    target[byte] = (target[byte] & !mask) | ((!own_id[byte]) & mask);
    Some(target)
}

fn decode_nodes(bytes: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    let mut i = 0;
    while i + 26 <= bytes.len() {
        let mut id = [0u8; 20];
        id.copy_from_slice(&bytes[i..i + 20]);
        let ip =
            std::net::Ipv4Addr::new(bytes[i + 20], bytes[i + 21], bytes[i + 22], bytes[i + 23]);
        let port = u16::from_be_bytes([bytes[i + 24], bytes[i + 25]]);
        nodes.push(Node {
            id,
            addr: SocketAddr::new(ip.into(), port),
            last_seen: Instant::now(),
        });
        i += 26;
    }
    nodes
}

#[cfg(test)]
fn decode_peers(bytes: &[u8]) -> Vec<SocketAddr> {
    let mut peers = Vec::new();
    let mut i = 0;
    while i + 6 <= bytes.len() {
        let ip = std::net::Ipv4Addr::new(bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]);
        let port = u16::from_be_bytes([bytes[i + 4], bytes[i + 5]]);
        peers.push(SocketAddr::new(ip.into(), port));
        i += 6;
    }
    peers
}

fn decode_peer_value(bytes: &[u8]) -> Option<SocketAddr> {
    match bytes.len() {
        6 => {
            let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let port = u16::from_be_bytes([bytes[4], bytes[5]]);
            (port != 0).then(|| SocketAddr::new(ip.into(), port))
        }
        18 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[..16]);
            let port = u16::from_be_bytes([bytes[16], bytes[17]]);
            (port != 0).then(|| {
                normalize_dht_addr(SocketAddr::new(
                    std::net::Ipv6Addr::from(octets).into(),
                    port,
                ))
            })
        }
        _ => None,
    }
}

fn encode_peer(peer: SocketAddr) -> Vec<u8> {
    let peer = normalize_dht_addr(peer);
    let mut out = Vec::with_capacity(if peer.is_ipv4() { 6 } else { 18 });
    match peer.ip() {
        std::net::IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
    }
    out.extend_from_slice(&peer.port().to_be_bytes());
    out
}

#[cfg(test)]
fn encode_peers(peers: &[SocketAddr]) -> Vec<u8> {
    let mut out = Vec::new();
    for peer in peers.iter().take(50) {
        if let std::net::IpAddr::V4(ip) = peer.ip() {
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&peer.port().to_be_bytes());
        }
    }
    out
}

fn decode_nodes6(bytes: &[u8]) -> Vec<Node> {
    let mut nodes = Vec::new();
    let mut i = 0;
    // 38 bytes: 20-byte node ID + 16-byte IPv6 + 2-byte port
    while i + 38 <= bytes.len() {
        let mut id = [0u8; 20];
        id.copy_from_slice(&bytes[i..i + 20]);
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&bytes[i + 20..i + 36]);
        let ip = std::net::Ipv6Addr::from(octets);
        let port = u16::from_be_bytes([bytes[i + 36], bytes[i + 37]]);
        nodes.push(Node {
            id,
            addr: normalize_dht_addr(SocketAddr::new(ip.into(), port)),
            last_seen: Instant::now(),
        });
        i += 38;
    }
    nodes
}

fn make_token(secret: &[u8; 20], addr: &SocketAddr) -> [u8; 4] {
    let addr = normalize_dht_addr(*addr);
    let mut data = Vec::with_capacity(32);
    data.extend_from_slice(secret);
    match addr.ip() {
        std::net::IpAddr::V4(ip) => data.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(ip) => data.extend_from_slice(&ip.octets()),
    }
    let hash = sha1::sha1(&data);
    [hash[0], hash[1], hash[2], hash[3]]
}

fn verify_token(secret: &[u8; 20], addr: &SocketAddr, token: &[u8]) -> bool {
    if token.len() != 4 {
        return false;
    }
    make_token(secret, addr) == [token[0], token[1], token[2], token[3]]
}

struct TokenSecrets {
    current: [u8; 20],
    previous: Option<[u8; 20]>,
    rotated_at: Instant,
}

impl TokenSecrets {
    fn new() -> Option<Self> {
        Some(Self {
            current: secure_random_id()?,
            previous: None,
            rotated_at: Instant::now(),
        })
    }

    fn rotate_if_due(&mut self) {
        if self.rotated_at.elapsed() < TOKEN_ROTATION_INTERVAL {
            return;
        }
        // Keep the still-secret current key if the operating-system random
        // source temporarily fails; retry on the next rotation interval.
        if let Some(next) = secure_random_id() {
            self.previous = Some(self.current);
            self.current = next;
        }
        self.rotated_at = Instant::now();
    }

    fn make(&self, addr: &SocketAddr) -> [u8; 4] {
        make_token(&self.current, addr)
    }

    fn verify(&self, addr: &SocketAddr, token: &[u8]) -> bool {
        verify_token(&self.current, addr, token)
            || self
                .previous
                .as_ref()
                .is_some_and(|previous| verify_token(previous, addr, token))
    }
}

fn secure_random_id() -> Option<[u8; 20]> {
    let mut out = [0u8; 20];
    getrandom::fill(&mut out).ok()?;
    Some(out)
}

fn next_tx_id() -> Vec<u8> {
    let mut tx = [0u8; 4];
    if getrandom::fill(&mut tx).is_err() {
        tx = (crate::system_entropy_u64() as u32).to_be_bytes();
    }
    tx.to_vec()
}

fn next_unique_tx(pending: &HashMap<Vec<u8>, PendingQuery>) -> Option<Vec<u8>> {
    for _ in 0..=MAX_PENDING_QUERIES {
        let tx = next_tx_id();
        if !pending.contains_key(&tx) {
            return Some(tx);
        }
    }
    // With at most 1,024 live transactions, checking one more than that many
    // consecutive 32-bit values guarantees a free ID even if the random
    // provider repeatedly failed or was adversarially unlucky.
    let start = crate::system_entropy_u64() as u32;
    for offset in 0..=(MAX_PENDING_QUERIES as u32) {
        let tx = start.wrapping_add(offset).to_be_bytes().to_vec();
        if !pending.contains_key(&tx) {
            return Some(tx);
        }
    }
    None
}

fn dict_get<'a>(dict: &'a [(Vec<u8>, Value)], key: &[u8]) -> Option<&'a Value> {
    dict.iter()
        .find_map(|(k, v)| if k.as_slice() == key { Some(v) } else { None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::too_many_arguments)]
    fn handle_response_test(
        dict: &[(Vec<u8>, Value)],
        addr: &SocketAddr,
        rt: &mut RoutingTable,
        pending: &mut HashMap<Vec<u8>, PendingQuery>,
        socket: &UdpSocket,
        node_id: &[u8; 20],
        peer_store: &mut PeerStore,
        torrents: &HashMap<[u8; 20], TorrentEntry>,
    ) {
        handle_response(
            dict,
            addr,
            rt,
            pending,
            socket,
            node_id,
            peer_store,
            torrents,
            &mut Vec::new(),
            &mut HashMap::new(),
        );
    }

    fn expire_pending_queries_at_test(
        rt: &mut RoutingTable,
        pending: &mut HashMap<Vec<u8>, PendingQuery>,
        now: Instant,
    ) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        expire_pending_queries_at(
            rt,
            pending,
            now,
            &socket,
            &[9u8; 20],
            &mut Vec::new(),
            &mut HashMap::new(),
        );
    }

    fn temp_download_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rustorrent-dht-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn node(id_byte: u8, ip: [u8; 4], port: u16) -> Node {
        let mut id = [0u8; 20];
        id[0] = id_byte;
        Node {
            id,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port),
            last_seen: Instant::now(),
        }
    }

    #[test]
    fn node_cache_roundtrip_is_scoped_and_atomic() {
        let root = temp_download_dir("roundtrip");
        let cache = NodeCache::new(&root).unwrap();
        assert_eq!(cache.path, root.join(STATE_DIR_NAME).join(NODES_FILE_NAME));

        let mut original = RoutingTable::new([0u8; 20]);
        let public_addr: SocketAddr = "124.31.75.21:6881".parse().unwrap();
        original.insert(Node {
            id: node_id_from_hex("5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"),
            addr: public_addr,
            last_seen: Instant::now(),
        });
        original.insert(node(7, [10, 0, 0, 7], 6881));
        save_nodes(&original, &cache).unwrap();
        assert!(fs::read(&cache.path).unwrap().starts_with(NODES_FILE_MAGIC));
        assert!(fs::read_dir(&cache.state_dir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")));

        let candidates = load_node_candidates(&cache).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].addr, public_addr);

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};

            assert_eq!(
                fs::metadata(&cache.state_dir).unwrap().permissions().mode() & 0o777,
                0o700
            );
            let metadata = fs::metadata(&cache.path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }

        // The Windows state backend deliberately pins directory handles for
        // the process lifetime; temporary cleanup is therefore best effort.
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn node_cache_rejects_hard_link_target() {
        let root = temp_download_dir("hard-link");
        let cache = NodeCache::new(&root).unwrap();
        let original = root.join("do-not-overwrite");
        fs::write(&original, b"sentinel").unwrap();
        fs::hard_link(&original, &cache.path).unwrap();

        let table = RoutingTable::new([0u8; 20]);
        let err = save_nodes(&table, &cache).unwrap_err();
        assert!(err.contains("hard-linked") || err.contains("multiply-linked"));
        assert_eq!(fs::read(&original).unwrap(), b"sentinel");

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn node_cache_rejects_symlink_target() {
        use std::os::unix::fs::symlink;

        let root = temp_download_dir("symlink-target");
        let cache = NodeCache::new(&root).unwrap();
        let target = root.join("do-not-overwrite");
        fs::write(&target, b"sentinel").unwrap();
        symlink(&target, &cache.path).unwrap();

        let table = RoutingTable::new([0u8; 20]);
        let err = save_nodes(&table, &cache).unwrap_err();
        assert!(err.contains("not a regular file"));
        assert_eq!(fs::read(&target).unwrap(), b"sentinel");

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn node_cache_rejects_symlinked_or_replaced_state_directory() {
        use std::os::unix::fs::symlink;

        let root = temp_download_dir("symlink-parent");
        let outside = temp_download_dir("symlink-parent-outside");
        symlink(&outside, root.join(STATE_DIR_NAME)).unwrap();
        let err = NodeCache::new(&root).err().unwrap();
        assert!(err.contains("not a real directory") || err.contains("unsafe filesystem alias"));
        assert!(!outside.join(NODES_FILE_NAME).exists());
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&outside).unwrap();

        let root = temp_download_dir("replaced-parent");
        let cache = NodeCache::new(&root).unwrap();
        fs::rename(&cache.state_dir, root.join(".rustorrent-old")).unwrap();
        fs::create_dir(&cache.state_dir).unwrap();
        let err = cache.write(NODES_FILE_MAGIC).unwrap_err();
        assert!(err.contains("changed after"));
        assert!(!cache.path.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn distance_helpers_work_for_extremes() {
        let a = [0u8; 20];
        let mut b = [0u8; 20];
        b[0] = 0x10;
        let dist = xor_distance(&a, &b);
        assert_eq!(dist[0], 0x10);
        assert_eq!(leading_zeros(&dist), 3);
        assert_eq!(leading_zeros(&[0u8; 20]), 160);
    }

    fn node_id_from_hex(hex: &str) -> [u8; 20] {
        assert_eq!(hex.len(), 40);
        let mut id = [0u8; 20];
        for (index, byte) in id.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        id
    }

    #[test]
    fn bep42_official_ipv4_vectors_are_accepted() {
        let vectors = [
            (
                "124.31.75.21:6881",
                "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401",
            ),
            (
                "21.75.31.124:6881",
                "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256",
            ),
            (
                "65.23.51.170:6881",
                "a5d43220bc8f112a3d426c84764f8c2a1150e616",
            ),
            (
                "84.124.73.14:6881",
                "1b0321dd1bb1fe518101ceef99462b947a01ff41",
            ),
            (
                "43.213.53.83:6881",
                "e56f6cbf5b7c4be0237986d5243b87aa6d51305a",
            ),
        ];
        for (addr, id) in vectors {
            assert!(node_id_matches_address(
                &node_id_from_hex(id),
                addr.parse().unwrap()
            ));
        }

        let addr: SocketAddr = "124.31.75.21:6881".parse().unwrap();
        let mut tampered = node_id_from_hex("5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401");
        tampered[0] ^= 0x80;
        assert!(!node_id_matches_address(&tampered, addr));
        assert!(node_id_matches_address(
            &[0xabu8; 20],
            "127.0.0.1:6881".parse().unwrap()
        ));
        assert!(node_id_matches_address(
            &node_id_from_hex("5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401"),
            "[::ffff:124.31.75.21]:6881".parse().unwrap()
        ));
        assert!(same_network_prefix(
            "124.31.75.1:1".parse().unwrap(),
            "[::ffff:124.31.75.2]:2".parse().unwrap()
        ));
    }

    #[test]
    fn dht_scope_rejects_ipv6_translation_and_special_use_ranges() {
        assert!(is_global_dht_address(
            "2001:4860:4860::8888".parse().unwrap()
        ));
        assert!(is_global_dht_address("::ffff:8.8.8.8".parse().unwrap()));
        assert!(is_local_dht_address("::ffff:192.168.1.1".parse().unwrap()));
        for special in [
            "64:ff9b::c0a8:1",
            "64:ff9b:1::c0a8:1",
            "::192.168.1.1",
            "2001:db8::1",
            "2002:c0a8:101::1",
            "3fff::1",
        ] {
            assert!(
                !is_global_dht_address(special.parse().unwrap()),
                "{special}"
            );
        }
    }

    #[test]
    fn peer_codec_roundtrip_skips_ipv6_and_trailing_bytes() {
        let peers = vec![
            "127.0.0.1:6881".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            "[2001:db8::1]:51413".parse().unwrap(),
        ];
        let encoded = encode_peers(&peers);
        assert_eq!(encoded.len(), 12);
        let mut encoded_with_trailing = encoded.clone();
        encoded_with_trailing.push(0xFF);
        let decoded = decode_peers(&encoded_with_trailing);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], "127.0.0.1:6881".parse().unwrap());
        assert_eq!(decoded[1], "10.0.0.2:80".parse().unwrap());
    }

    #[test]
    fn decode_nodes_ignores_partial_tail() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[1u8; 20]);
        bytes.extend_from_slice(&[192, 0, 2, 10]);
        bytes.extend_from_slice(&6881u16.to_be_bytes());
        bytes.extend_from_slice(&[9, 9, 9]); // partial tail

        let nodes = decode_nodes(&bytes);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].addr, "192.0.2.10:6881".parse().unwrap());
        assert_eq!(nodes[0].id, [1u8; 20]);
    }

    #[test]
    fn token_verification_depends_on_address() {
        let secret = [7u8; 20];
        let addr_a: SocketAddr = "203.0.113.2:51413".parse().unwrap();
        let addr_b: SocketAddr = "203.0.113.3:51413".parse().unwrap();
        let token = make_token(&secret, &addr_a);
        assert!(verify_token(&secret, &addr_a, &token));
        assert!(!verify_token(&secret, &addr_b, &token));
        assert!(!verify_token(
            &secret,
            &addr_a,
            &[token[0], token[1], token[2]]
        ));
        assert!(!verify_token(
            &secret,
            &addr_a,
            &[token[0], token[1], token[2], token[3], 0]
        ));
    }

    #[test]
    fn routing_table_returns_closest_nodes_and_encoded_limit() {
        let mut rt = RoutingTable::new([0u8; 20]);
        for i in 1..=10u8 {
            rt.insert(node(i, [10, i, 0, 1], 6000 + i as u16));
        }

        let target = [0u8; 20];
        let closest = rt.closest(&target, 3);
        assert_eq!(closest.len(), 3);
        assert!(closest[0].id[0] <= closest[1].id[0]);

        let encoded = rt.encode_closest_nodes(&target, "127.0.0.1:6881".parse().unwrap());
        assert_eq!(encoded.len(), 26 * 8);
    }

    #[test]
    fn routing_table_limits_endpoint_and_network_concentration() {
        let mut rt = RoutingTable::new([0u8; 20]);
        for i in 1..=8u8 {
            rt.insert(node(i, [10, 42, 7, i], 6000 + i as u16));
        }
        assert_eq!(rt.node_count(), MAX_NODES_PER_PREFIX);

        let duplicate_endpoint = node(99, [10, 42, 7, 1], 6001);
        rt.insert(duplicate_endpoint);
        assert_eq!(rt.node_count(), MAX_NODES_PER_PREFIX);

        rt.insert(node(100, [10, 43, 7, 1], 7001));
        assert_eq!(rt.node_count(), MAX_NODES_PER_PREFIX + 1);
    }

    #[test]
    fn ipv4_compact_nodes_do_not_include_partial_ipv6_records() {
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(node(1, [8, 8, 8, 1], 6881));
        let mut ipv6_id = [0u8; 20];
        ipv6_id[0] = 2;
        rt.insert(Node {
            id: ipv6_id,
            addr: "[2001:db8::1]:6881".parse().unwrap(),
            last_seen: Instant::now(),
        });
        let encoded = rt.encode_closest_nodes(&[0u8; 20], "127.0.0.1:6881".parse().unwrap());
        assert_eq!(encoded.len(), 26);
        assert_eq!(decode_nodes(&encoded).len(), 1);
    }

    #[test]
    fn matched_response_admits_sender_but_only_probes_returned_nodes() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let candidate_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        candidate_socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let candidate_addr = candidate_socket.local_addr().unwrap();
        let addr: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(Node {
            id: [7u8; 20],
            addr,
            last_seen: Instant::now(),
        });
        let mut pending = HashMap::new();
        let mut peer_store = PeerStore::new();
        let torrents = HashMap::new();
        let node_id = [9u8; 20];

        let mut compact_node = Vec::new();
        compact_node.extend_from_slice(&[3u8; 20]);
        compact_node.extend_from_slice(&[127, 0, 0, 1]);
        compact_node.extend_from_slice(&candidate_addr.port().to_be_bytes());
        let dict = vec![
            (b"t".to_vec(), Value::Bytes(b"aa".to_vec())),
            (
                b"r".to_vec(),
                Value::Dict(vec![
                    (b"id".to_vec(), Value::Bytes([2u8; 20].to_vec())),
                    (b"nodes".to_vec(), Value::Bytes(compact_node)),
                ]),
            ),
        ];
        pending.insert(
            b"aa".to_vec(),
            PendingQuery {
                kind: PendingKind::FindNode,
                addr,
                expected_id: None,
                sent_at: Instant::now(),
            },
        );

        handle_response_test(
            &dict,
            &addr,
            &mut rt,
            &mut pending,
            &socket,
            &node_id,
            &mut peer_store,
            &torrents,
        );

        assert_eq!(rt.node_count(), 1);
        assert_eq!(pending.len(), 1);
        let verification = pending.values().next().unwrap();
        assert!(matches!(verification.kind, PendingKind::VerifyNode));
        assert_eq!(verification.addr, candidate_addr);
        assert_eq!(verification.expected_id, Some([3u8; 20]));

        let mut probe = [0u8; 256];
        let (probe_len, _) = candidate_socket.recv_from(&mut probe).unwrap();
        let Value::Dict(probe) = bencode::parse(&probe[..probe_len]).unwrap() else {
            panic!("verification query was not a bencoded dictionary");
        };
        assert_eq!(
            dict_get(&probe, b"q"),
            Some(&Value::Bytes(b"ping".to_vec()))
        );
    }

    fn peer_lookup(target: [u8; 20], candidates: Vec<Node>) -> RefreshLookup {
        RefreshLookup {
            bucket_idx: usize::MAX,
            target,
            candidates,
            queried: HashSet::new(),
            outstanding: 0,
            authenticated_responses: 0,
            deadline: Instant::now() + REFRESH_LOOKUP_DEADLINE,
            peers: Some(PeerLookup {
                port: 6881,
                tokens: Vec::new(),
            }),
        }
    }

    fn torrent_entry(port: u16) -> (TorrentEntry, mpsc::Receiver<Vec<SocketAddr>>) {
        let (peers_tx, peers_rx) = mpsc::channel();
        (
            TorrentEntry {
                peers_tx,
                port,
                last_query: Instant::now(),
                last_bootstrap: Instant::now(),
            },
            peers_rx,
        )
    }

    #[test]
    fn public_responder_cannot_trigger_local_node_or_peer_probes() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let responder: SocketAddr = "124.31.75.21:6881".parse().unwrap();
        let responder_id = node_id_from_hex("5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401");
        let info_hash = [1u8; 20];
        let mut rt = RoutingTable::new([9u8; 20]);
        let mut pending = HashMap::new();
        pending.insert(
            b"scope".to_vec(),
            PendingQuery {
                kind: PendingKind::RefreshBucket(1),
                addr: responder,
                expected_id: Some(responder_id),
                sent_at: Instant::now(),
            },
        );
        let responder_node = Node {
            id: responder_id,
            addr: responder,
            last_seen: Instant::now(),
        };
        let mut lookups = HashMap::from([(1, peer_lookup(info_hash, vec![responder_node]))]);
        lookups.get_mut(&1).unwrap().queried.insert(responder);
        lookups.get_mut(&1).unwrap().outstanding = 1;

        let mut local_node = Vec::new();
        local_node.extend_from_slice(&[3u8; 20]);
        local_node.extend_from_slice(&[127, 0, 0, 1]);
        local_node.extend_from_slice(&6881u16.to_be_bytes());
        let local_peer = vec![127, 0, 0, 1, 0x1a, 0xe1];
        let response = vec![
            (b"t".to_vec(), Value::Bytes(b"scope".to_vec())),
            (
                b"r".to_vec(),
                Value::Dict(vec![
                    (b"id".to_vec(), Value::Bytes(responder_id.to_vec())),
                    (b"nodes".to_vec(), Value::Bytes(local_node)),
                    (
                        b"values".to_vec(),
                        Value::List(vec![Value::Bytes(local_peer)]),
                    ),
                ]),
            ),
        ];
        let (entry, peers_rx) = torrent_entry(6881);
        let torrents = HashMap::from([(info_hash, entry)]);
        let mut peer_store = PeerStore::new();

        handle_response(
            &response,
            &responder,
            &mut rt,
            &mut pending,
            &socket,
            &[9u8; 20],
            &mut peer_store,
            &torrents,
            &mut Vec::new(),
            &mut lookups,
        );

        assert_eq!(rt.node_count(), 1);
        assert!(pending.is_empty(), "the local node must not be probed");
        assert!(peer_store.is_empty());
        assert!(matches!(
            peers_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn get_peers_lookup_collects_values_and_announces_with_tokens() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let responder_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        responder_socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let responder = Node {
            id: [0x42u8; 20],
            addr: responder_socket.local_addr().unwrap(),
            last_seen: Instant::now(),
        };
        let info_hash = [0x43u8; 20];
        let node_id = [9u8; 20];
        let mut rt = RoutingTable::new(node_id);
        rt.insert(responder);
        let mut pending = HashMap::new();
        let mut lookups = HashMap::new();
        let mut next_id = 0;
        assert!(start_peer_lookup(
            info_hash,
            7000,
            &mut rt,
            &mut pending,
            &socket,
            &node_id,
            &mut lookups,
            &mut next_id,
        ));
        // A second lookup for the same torrent is not started concurrently.
        assert!(!start_peer_lookup(
            info_hash,
            7000,
            &mut rt,
            &mut pending,
            &socket,
            &node_id,
            &mut lookups,
            &mut next_id,
        ));

        let mut packet = [0u8; 1500];
        let (len, _) = responder_socket.recv_from(&mut packet).unwrap();
        let Value::Dict(query) = bencode::parse(&packet[..len]).unwrap() else {
            panic!("lookup query was not a dictionary");
        };
        assert_eq!(
            dict_get(&query, b"q"),
            Some(&Value::Bytes(b"get_peers".to_vec()))
        );
        let (tx, sent) = pending
            .iter()
            .next()
            .map(|(tx, query)| (tx.clone(), *query))
            .unwrap();

        let peer: SocketAddr = "127.0.0.1:51413".parse().unwrap();
        let response = vec![
            (b"t".to_vec(), Value::Bytes(tx)),
            (
                b"r".to_vec(),
                Value::Dict(vec![
                    (b"id".to_vec(), Value::Bytes(responder.id.to_vec())),
                    (b"token".to_vec(), Value::Bytes(b"tok".to_vec())),
                    (
                        b"values".to_vec(),
                        Value::List(vec![Value::Bytes(encode_peer(peer))]),
                    ),
                ]),
            ),
        ];
        let (entry, peers_rx) = torrent_entry(7000);
        let torrents = HashMap::from([(info_hash, entry)]);
        handle_response(
            &response,
            &sent.addr,
            &mut rt,
            &mut pending,
            &socket,
            &node_id,
            &mut PeerStore::new(),
            &torrents,
            &mut Vec::new(),
            &mut lookups,
        );
        assert_eq!(peers_rx.try_recv().unwrap(), vec![peer]);
        assert!(lookups.is_empty(), "an exhausted lookup finishes");

        let (len, _) = responder_socket.recv_from(&mut packet).unwrap();
        let Value::Dict(announce) = bencode::parse(&packet[..len]).unwrap() else {
            panic!("announce was not a dictionary");
        };
        assert_eq!(
            dict_get(&announce, b"q"),
            Some(&Value::Bytes(b"announce_peer".to_vec()))
        );
        let Some(Value::Dict(args)) = dict_get(&announce, b"a") else {
            panic!("announce had no arguments");
        };
        assert_eq!(
            dict_get(args, b"token"),
            Some(&Value::Bytes(b"tok".to_vec()))
        );
        assert_eq!(dict_get(args, b"port"), Some(&Value::Int(7000)));
        assert_eq!(
            dict_get(args, b"info_hash"),
            Some(&Value::Bytes(info_hash.to_vec()))
        );
    }

    #[test]
    fn response_with_unexpected_node_id_is_not_admitted() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        let mut rt = RoutingTable::new([0u8; 20]);
        let mut pending = HashMap::new();
        pending.insert(
            b"mismatch".to_vec(),
            PendingQuery {
                kind: PendingKind::VerifyNode,
                addr,
                expected_id: Some([7u8; 20]),
                sent_at: Instant::now(),
            },
        );
        let response = vec![
            (b"t".to_vec(), Value::Bytes(b"mismatch".to_vec())),
            (
                b"r".to_vec(),
                Value::Dict(vec![(b"id".to_vec(), Value::Bytes([8u8; 20].to_vec()))]),
            ),
        ];
        let mut peer_store = PeerStore::new();
        handle_response_test(
            &response,
            &addr,
            &mut rt,
            &mut pending,
            &socket,
            &[9u8; 20],
            &mut peer_store,
            &HashMap::new(),
        );
        assert_eq!(rt.node_count(), 0);
        assert!(pending.is_empty());
    }

    #[test]
    fn unsolicited_queries_do_not_populate_the_routing_table() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        let query = vec![
            (b"t".to_vec(), Value::Bytes(b"ping".to_vec())),
            (b"q".to_vec(), Value::Bytes(b"ping".to_vec())),
            (
                b"a".to_vec(),
                Value::Dict(vec![(b"id".to_vec(), Value::Bytes([4u8; 20].to_vec()))]),
            ),
        ];
        let mut rt = RoutingTable::new([0u8; 20]);
        let token_secrets = TokenSecrets {
            current: [8u8; 20],
            previous: None,
            rotated_at: Instant::now(),
        };
        handle_query(
            &query,
            &addr,
            &socket,
            &[9u8; 20],
            &token_secrets,
            &mut rt,
            &mut PeerStore::new(),
            &HashMap::new(),
        );
        assert_eq!(rt.node_count(), 0);
    }

    #[test]
    fn queries_without_a_valid_sender_id_receive_no_response() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let addr = receiver.local_addr().unwrap();
        let query = vec![
            (b"t".to_vec(), Value::Bytes(b"ping".to_vec())),
            (b"q".to_vec(), Value::Bytes(b"ping".to_vec())),
            (b"a".to_vec(), Value::Dict(Vec::new())),
        ];
        let mut rt = RoutingTable::new([0u8; 20]);
        let token_secrets = TokenSecrets {
            current: [8u8; 20],
            previous: None,
            rotated_at: Instant::now(),
        };
        handle_query(
            &query,
            &addr,
            &socket,
            &[9u8; 20],
            &token_secrets,
            &mut rt,
            &mut PeerStore::new(),
            &HashMap::new(),
        );

        let mut response = [0u8; 32];
        assert!(receiver.recv_from(&mut response).is_err());
        assert_eq!(rt.node_count(), 0);
    }

    #[test]
    fn query_rate_limiter_caps_sources_prefixes_and_global_load() {
        let mut per_source = QueryRateLimiter::new();
        let now = Instant::now();
        for port in 1..=MAX_QUERIES_PER_WINDOW_IP {
            assert!(per_source.allow_at(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), port as u16),
                now
            ));
        }
        assert!(!per_source.allow_at("10.1.2.3:9999".parse().unwrap(), now));
        assert!(per_source.allow_at("10.1.2.3:9999".parse().unwrap(), now + QUERY_RATE_WINDOW));

        let mut per_prefix = QueryRateLimiter::new();
        for host in 1..=4u8 {
            for port in 1..=MAX_QUERIES_PER_WINDOW_IP {
                assert!(per_prefix.allow_at(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 8, host)), port as u16,),
                    now,
                ));
            }
        }
        assert_eq!(MAX_QUERIES_PER_WINDOW_PREFIX, 4 * MAX_QUERIES_PER_WINDOW_IP);
        assert!(!per_prefix.allow_at("10.9.8.5:1".parse().unwrap(), now));

        let mut global = QueryRateLimiter::new();
        for index in 0..MAX_QUERIES_PER_WINDOW_GLOBAL {
            let second = (index / 256) as u8;
            let third = (index % 256) as u8;
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(11, second, third, 1)), 6881);
            assert!(global.allow_at(addr, now));
        }
        assert!(!global.allow_at("12.0.0.1:6881".parse().unwrap(), now));
    }

    #[test]
    fn token_rotation_accepts_only_current_and_previous_secrets() {
        let addr: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        let oldest = [1u8; 20];
        let previous = [2u8; 20];
        let current = [3u8; 20];
        let secrets = TokenSecrets {
            current,
            previous: Some(previous),
            rotated_at: Instant::now(),
        };
        assert!(secrets.verify(&addr, &make_token(&current, &addr)));
        assert!(secrets.verify(&addr, &make_token(&previous, &addr)));
        assert!(!secrets.verify(&addr, &make_token(&oldest, &addr)));
    }

    #[test]
    fn stale_timeout_does_not_remove_a_freshly_refreshed_node() {
        let addr: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        let node_id = [7u8; 20];
        let sent_at = Instant::now();
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(Node {
            id: node_id,
            addr,
            last_seen: sent_at + Duration::from_millis(1),
        });
        let mut pending = HashMap::from([(
            b"old".to_vec(),
            PendingQuery {
                kind: PendingKind::VerifyNode,
                addr,
                expected_id: Some(node_id),
                sent_at,
            },
        )]);

        expire_pending_queries_at_test(
            &mut rt,
            &mut pending,
            sent_at + MAX_PENDING_AGE + Duration::from_secs(1),
        );

        assert!(pending.is_empty());
        assert!(rt.contains_endpoint(addr));
    }

    #[test]
    fn verified_node_requires_two_consecutive_query_failures_for_eviction() {
        let addr: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        let base = Instant::now();
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(Node {
            id: [7u8; 20],
            addr,
            last_seen: base,
        });

        rt.record_query_failure(addr, base + Duration::from_millis(1));
        assert!(rt.contains_endpoint(addr));
        assert_eq!(rt.failures.get(&addr), Some(&1));

        rt.record_query_failure(addr, base + Duration::from_millis(2));
        assert!(!rt.contains_endpoint(addr));
        assert!(!rt.failures.contains_key(&addr));
    }

    #[test]
    fn full_bucket_probes_questionable_incumbent_before_replacement() {
        let now = Instant::now();
        let old_seen = now.checked_sub(QUESTIONABLE_NODE_AGE * 2).unwrap();
        let stale_seen = now
            .checked_sub(QUESTIONABLE_NODE_AGE + Duration::from_secs(1))
            .unwrap();
        let mut rt = RoutingTable::new([0u8; 20]);
        let mut incumbent_id = [0u8; 20];
        incumbent_id[0] = 0x80;
        incumbent_id[1] = 1;
        let incumbent_addr: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        rt.insert(Node {
            id: incumbent_id,
            addr: incumbent_addr,
            last_seen: old_seen,
        });
        for index in 1..K {
            let mut id = [0u8; 20];
            id[0] = 0x80;
            id[1] = index as u8 + 1;
            rt.insert(Node {
                id,
                addr: format!("10.{index}.0.1:6881").parse().unwrap(),
                last_seen: stale_seen,
            });
        }
        assert_eq!(rt.node_count(), K);

        let mut candidate_id = [0u8; 20];
        candidate_id[0] = 0x80;
        candidate_id[1] = 99;
        let candidate = Node {
            id: candidate_id,
            addr: "172.16.0.1:6881".parse().unwrap(),
            last_seen: now,
        };

        rt.insert(candidate);
        assert!(rt.contains_endpoint(incumbent_addr));
        assert!(!rt.contains_endpoint(candidate.addr));
        assert_eq!(
            rt.questionable_incumbents(candidate)[0].addr,
            incumbent_addr
        );

        fail_pending_query(
            &mut rt,
            PendingQuery {
                kind: PendingKind::ReplaceNode {
                    candidate,
                    attempt: MAX_REPLACEMENT_PROBE_ATTEMPTS,
                    probe_started_at: now,
                },
                addr: incumbent_addr,
                expected_id: Some(incumbent_id),
                sent_at: now,
            },
            &mut HashMap::new(),
            &UdpSocket::bind("127.0.0.1:0").unwrap(),
            &[9u8; 20],
            &mut Vec::new(),
            &mut HashMap::new(),
            None,
        );
        assert!(!rt.contains_endpoint(incumbent_addr));
        assert!(rt.contains_endpoint(candidate.addr));
        assert_eq!(rt.node_count(), K);
    }

    #[test]
    fn questionable_replacement_retries_with_same_transaction_before_eviction() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let incumbent_addr = receiver.local_addr().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let now = Instant::now();
        let stale = now.checked_sub(QUESTIONABLE_NODE_AGE * 2).unwrap();
        let mut rt = RoutingTable::new([0u8; 20]);
        let mut incumbent_id = [0u8; 20];
        incumbent_id[0] = 0x80;
        incumbent_id[1] = 1;
        rt.insert(Node {
            id: incumbent_id,
            addr: incumbent_addr,
            last_seen: stale,
        });
        for index in 1..K {
            let mut id = [0u8; 20];
            id[0] = 0x80;
            id[1] = index as u8 + 1;
            rt.insert(Node {
                id,
                addr: format!("10.{index}.0.1:6881").parse().unwrap(),
                last_seen: stale + Duration::from_secs(index as u64),
            });
        }
        let mut candidate_id = [0u8; 20];
        candidate_id[0] = 0x80;
        candidate_id[1] = 99;
        let candidate = Node {
            id: candidate_id,
            addr: "172.16.0.1:6881".parse().unwrap(),
            last_seen: now,
        };
        let mut deferred = vec![candidate];
        let mut pending = HashMap::new();
        let mut refreshes = HashMap::new();
        maintain_deferred_replacements(&mut deferred, &mut rt, &mut pending, &socket, &[9u8; 20]);
        assert!(deferred.is_empty());
        assert_eq!(pending.len(), 1);
        let tx = pending.keys().next().unwrap().clone();
        let first = pending[&tx];

        expire_pending_queries_at(
            &mut rt,
            &mut pending,
            first.sent_at + MAX_PENDING_AGE + Duration::from_millis(1),
            &socket,
            &[9u8; 20],
            &mut deferred,
            &mut refreshes,
        );
        assert!(rt.contains_endpoint(incumbent_addr));
        assert!(pending.contains_key(&tx));
        assert!(matches!(
            pending[&tx].kind,
            PendingKind::ReplaceNode { attempt: 2, .. }
        ));

        let second = pending[&tx];
        expire_pending_queries_at(
            &mut rt,
            &mut pending,
            second.sent_at + MAX_PENDING_AGE + Duration::from_millis(1),
            &socket,
            &[9u8; 20],
            &mut deferred,
            &mut refreshes,
        );
        assert!(pending.is_empty());
        assert!(!rt.contains_endpoint(incumbent_addr));
        assert!(rt.contains_endpoint(candidate.addr));
    }

    #[test]
    fn refreshed_incumbent_wins_over_waiting_replacement() {
        let base = Instant::now();
        let stale = base.checked_sub(QUESTIONABLE_NODE_AGE * 2).unwrap();
        let incumbent_id = [0x80u8; 20];
        let incumbent_addr: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(Node {
            id: incumbent_id,
            addr: incumbent_addr,
            last_seen: stale,
        });
        let candidate = Node {
            id: [0x81u8; 20],
            addr: "127.0.0.2:6881".parse().unwrap(),
            last_seen: base,
        };
        assert!(rt.refresh_verified(&incumbent_id, incumbent_addr));
        assert!(!rt.replace_questionable(incumbent_id, incumbent_addr, base, candidate));
        assert!(rt.contains_endpoint(incumbent_addr));
        assert!(!rt.contains_endpoint(candidate.addr));
    }

    #[test]
    fn bucket_refresh_targets_stay_inside_the_selected_distance_range() {
        let own_id = [0x5au8; 20];
        let mut rt = RoutingTable::new(own_id);
        for bucket_idx in [0, 1, 7, 8, 79, 158, 159] {
            let target = random_target_for_bucket(&own_id, bucket_idx).unwrap();
            assert_eq!(rt.bucket_index(&target), bucket_idx);
        }

        let mut id = [0u8; 20];
        id[0] = 0x80;
        rt.insert(Node {
            id,
            addr: "127.0.0.1:6881".parse().unwrap(),
            last_seen: Instant::now(),
        });
        let idx = rt.bucket_index(&id);
        let now = Instant::now();
        rt.bucket_refreshed_at[idx] = now.checked_sub(BUCKET_REFRESH_INTERVAL).unwrap();
        rt.bucket_refresh_attempted_at[idx] = now.checked_sub(BUCKET_REFRESH_INTERVAL).unwrap();
        assert_eq!(rt.bucket_needing_refresh(now), Some(idx));
        rt.mark_bucket_refreshed(idx, now);
        assert_eq!(rt.bucket_needing_refresh(now), None);
    }

    #[test]
    fn failed_bucket_refresh_attempt_does_not_starve_other_stale_buckets() {
        let now = Instant::now();
        let stale = now.checked_sub(BUCKET_REFRESH_INTERVAL).unwrap();
        let older_attempt = now.checked_sub(BUCKET_REFRESH_INTERVAL * 2).unwrap();
        let newer_attempt = now
            .checked_sub(BUCKET_REFRESH_INTERVAL + Duration::from_secs(1))
            .unwrap();
        let mut near_id = [0u8; 20];
        near_id[19] = 1;
        let mut far_id = [0u8; 20];
        far_id[0] = 0x80;
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(Node {
            id: near_id,
            addr: "127.0.0.1:6881".parse().unwrap(),
            last_seen: now,
        });
        rt.insert(Node {
            id: far_id,
            addr: "10.1.0.1:6881".parse().unwrap(),
            last_seen: now,
        });
        let near_bucket = rt.bucket_index(&near_id);
        let far_bucket = rt.bucket_index(&far_id);
        rt.bucket_refreshed_at[near_bucket] = stale;
        rt.bucket_refreshed_at[far_bucket] = stale;
        rt.bucket_refresh_attempted_at[near_bucket] = older_attempt;
        rt.bucket_refresh_attempted_at[far_bucket] = newer_attempt;

        assert_eq!(rt.bucket_needing_refresh(now), Some(near_bucket));
        rt.mark_bucket_refresh_attempted(near_bucket, now);
        assert_eq!(rt.bucket_needing_refresh(now), Some(far_bucket));
    }

    #[test]
    fn bucket_refresh_iteratively_queries_returned_closer_nodes() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let initial_receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let returned_receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        initial_receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        returned_receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let initial = Node {
            id: [0x90u8; 20],
            addr: initial_receiver.local_addr().unwrap(),
            last_seen: Instant::now(),
        };
        let returned = Node {
            id: [0x80u8; 20],
            addr: returned_receiver.local_addr().unwrap(),
            last_seen: Instant::now(),
        };
        let target = [0x81u8; 20];
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(initial);
        let mut pending = HashMap::new();
        let mut refreshes = HashMap::from([(
            7,
            RefreshLookup {
                bucket_idx: rt.bucket_index(&initial.id),
                target,
                candidates: vec![initial],
                queried: HashSet::new(),
                outstanding: 0,
                authenticated_responses: 0,
                deadline: Instant::now() + REFRESH_LOOKUP_DEADLINE,
                peers: None,
            },
        )]);
        advance_refresh_lookup(
            7,
            &mut rt,
            &mut pending,
            &socket,
            &[9u8; 20],
            &mut refreshes,
        );
        assert_eq!(pending.len(), 1);
        let mut packet = [0u8; 1500];
        let _ = initial_receiver.recv_from(&mut packet).unwrap();
        let (tx, query) = pending
            .iter()
            .next()
            .map(|(tx, query)| (tx.clone(), *query))
            .unwrap();

        let mut compact = Vec::new();
        compact.extend_from_slice(&returned.id);
        let IpAddr::V4(returned_ip) = returned.addr.ip() else {
            panic!("test returned endpoint was not IPv4");
        };
        compact.extend_from_slice(&returned_ip.octets());
        compact.extend_from_slice(&returned.addr.port().to_be_bytes());
        let response = vec![
            (b"t".to_vec(), Value::Bytes(tx)),
            (
                b"r".to_vec(),
                Value::Dict(vec![
                    (b"id".to_vec(), Value::Bytes(initial.id.to_vec())),
                    (b"nodes".to_vec(), Value::Bytes(compact)),
                ]),
            ),
        ];
        handle_response(
            &response,
            &query.addr,
            &mut rt,
            &mut pending,
            &socket,
            &[9u8; 20],
            &mut PeerStore::new(),
            &HashMap::new(),
            &mut Vec::new(),
            &mut refreshes,
        );

        assert_eq!(pending.len(), 1);
        assert_eq!(pending.values().next().unwrap().addr, returned.addr);
        let (len, _) = returned_receiver.recv_from(&mut packet).unwrap();
        let Value::Dict(query) = bencode::parse(&packet[..len]).unwrap() else {
            panic!("refresh query was not a dictionary");
        };
        let Some(Value::Dict(args)) = dict_get(&query, b"a") else {
            panic!("refresh query had no arguments");
        };
        assert_eq!(
            dict_get(args, b"target"),
            Some(&Value::Bytes(target.to_vec()))
        );
    }

    #[test]
    fn known_query_sender_refreshes_liveness_without_admitting_unknown_nodes() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        let sender_id = [4u8; 20];
        let base = Instant::now();
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(Node {
            id: sender_id,
            addr,
            last_seen: base,
        });
        rt.failures.insert(addr, 1);
        let query = vec![
            (b"t".to_vec(), Value::Bytes(b"ping".to_vec())),
            (b"q".to_vec(), Value::Bytes(b"ping".to_vec())),
            (
                b"a".to_vec(),
                Value::Dict(vec![(b"id".to_vec(), Value::Bytes(sender_id.to_vec()))]),
            ),
        ];
        let token_secrets = TokenSecrets {
            current: [8u8; 20],
            previous: None,
            rotated_at: Instant::now(),
        };

        handle_query(
            &query,
            &addr,
            &socket,
            &[9u8; 20],
            &token_secrets,
            &mut rt,
            &mut PeerStore::new(),
            &HashMap::new(),
        );

        let refreshed = rt
            .buckets
            .iter()
            .flatten()
            .find(|node| node.addr == addr)
            .unwrap();
        assert!(refreshed.last_seen >= base);
        assert!(!rt.failures.contains_key(&addr));
    }

    #[test]
    fn malformed_response_keeps_probe_pending_for_timeout_eviction() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        let mut rt = RoutingTable::new([0u8; 20]);
        let mut pending = HashMap::from([(
            b"bad".to_vec(),
            PendingQuery {
                kind: PendingKind::VerifyNode,
                addr,
                expected_id: Some([7u8; 20]),
                sent_at: Instant::now(),
            },
        )]);
        let response = vec![
            (b"t".to_vec(), Value::Bytes(b"bad".to_vec())),
            (b"r".to_vec(), Value::Dict(Vec::new())),
        ];

        handle_response_test(
            &response,
            &addr,
            &mut rt,
            &mut pending,
            &socket,
            &[9u8; 20],
            &mut PeerStore::new(),
            &HashMap::new(),
        );

        assert!(pending.contains_key(b"bad".as_slice()));
    }

    #[test]
    fn peer_store_coalesces_duplicates_and_caps_source_influence() {
        let mut store = PeerStore::new();
        let hash = [1u8; 20];
        assert!(store.admit(hash, "10.0.0.1:6001".parse().unwrap()));
        assert!(!store.admit(hash, "10.0.0.1:6001".parse().unwrap()));
        assert!(store.admit(hash, "10.0.0.1:6002".parse().unwrap()));
        assert!(!store.admit(hash, "10.0.0.1:6003".parse().unwrap()));

        let mut source_limited = PeerStore::new();
        for index in 0..MAX_STORED_SWARMS_PER_IP {
            let mut info_hash = [0u8; 20];
            info_hash[..8].copy_from_slice(&(index as u64).to_be_bytes());
            assert!(source_limited.admit(info_hash, "10.0.0.9:6881".parse().unwrap()));
        }
        assert!(!source_limited.admit([0xffu8; 20], "10.0.0.9:6881".parse().unwrap()));
    }

    #[test]
    fn bep32_want_controls_returned_node_families() {
        let requester_v4: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        assert_eq!(requested_node_families(&[], requester_v4), (true, false));
        let wants_both = vec![(
            b"want".to_vec(),
            Value::List(vec![
                Value::Bytes(b"n6".to_vec()),
                Value::Bytes(b"n4".to_vec()),
            ]),
        )];
        assert_eq!(
            requested_node_families(&wants_both, requester_v4),
            (true, true)
        );
        let wants_v6 = vec![(
            b"want".to_vec(),
            Value::List(vec![Value::Bytes(b"n6".to_vec())]),
        )];
        assert_eq!(
            requested_node_families(&wants_v6, requester_v4),
            (false, true)
        );
        let mapped_requester: SocketAddr = "[::ffff:127.0.0.1]:6881".parse().unwrap();
        assert_eq!(
            requested_node_families(&[], mapped_requester),
            (true, false)
        );

        let mut mapped_peer = vec![0u8; 18];
        mapped_peer[10] = 0xff;
        mapped_peer[11] = 0xff;
        mapped_peer[12..16].copy_from_slice(&[127, 0, 0, 1]);
        mapped_peer[16..18].copy_from_slice(&6881u16.to_be_bytes());
        let decoded = decode_peer_value(&mapped_peer).unwrap();
        assert_eq!(decoded, "127.0.0.1:6881".parse().unwrap());
        assert!(decoded.is_ipv4());
    }

    #[test]
    fn bootstrap_resolution_collection_discards_late_and_duplicate_results() {
        let (tx, rx) = mpsc::sync_channel(3);
        let addr: SocketAddr = "8.8.8.8:6881".parse().unwrap();
        let now = Instant::now();
        tx.send(BootstrapResolution {
            deadline: now,
            addrs: vec!["127.0.0.1:1".parse().unwrap()],
        })
        .unwrap();
        tx.send(BootstrapResolution {
            deadline: now + Duration::from_secs(2),
            addrs: vec![addr, addr, "127.0.0.1:6881".parse().unwrap()],
        })
        .unwrap();
        let mut addrs = Vec::new();

        collect_bootstrap_resolutions_at(&rx, &mut addrs, now + Duration::from_secs(1));

        assert_eq!(
            addrs.iter().map(|entry| entry.addr).collect::<Vec<_>>(),
            vec![addr]
        );
    }

    #[test]
    fn resolver_slots_are_independent_per_bootstrap_host() {
        let first = AtomicBool::new(false);
        let second = AtomicBool::new(false);
        assert!(acquire_bootstrap_resolver_slot(&first));
        assert!(!acquire_bootstrap_resolver_slot(&first));
        assert!(acquire_bootstrap_resolver_slot(&second));
    }

    #[test]
    fn dht_response_reports_the_requesters_observed_compact_address() {
        let requester: SocketAddr = "127.0.0.1:51413".parse().unwrap();
        let encoded = build_response(&[9u8; 20], b"tx", Vec::new(), requester);
        let Value::Dict(response) = bencode::parse(&encoded).unwrap() else {
            panic!("expected response dictionary");
        };
        assert_eq!(
            dict_get(&response, b"ip"),
            Some(&Value::Bytes(encode_peer(requester)))
        );
    }

    #[test]
    fn get_peers_and_find_node_responses_are_canonical_bencode() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let requester = UdpSocket::bind("127.0.0.1:0").unwrap();
        requester
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let requester_addr = requester.local_addr().unwrap();
        let secrets = TokenSecrets::new().unwrap();
        let mut rt = RoutingTable::new([0u8; 20]);
        rt.insert(node(7, [127, 0, 0, 9], 6881));
        let mut peer_store = PeerStore::new();
        let info_hash = [5u8; 20];
        let stored: SocketAddr = "127.0.0.2:51413".parse().unwrap();
        assert!(peer_store.admit(info_hash, stored));

        let query = |q: &[u8], key: &[u8], value: [u8; 20]| {
            vec![
                (
                    b"a".to_vec(),
                    Value::Dict(vec![
                        (b"id".to_vec(), Value::Bytes([1u8; 20].to_vec())),
                        (key.to_vec(), Value::Bytes(value.to_vec())),
                    ]),
                ),
                (b"q".to_vec(), Value::Bytes(q.to_vec())),
                (b"t".to_vec(), Value::Bytes(b"tx".to_vec())),
                (b"y".to_vec(), Value::Bytes(b"q".to_vec())),
            ]
        };
        let mut packet = [0u8; 1500];
        for (request, expect_values) in [
            (query(b"get_peers", b"info_hash", info_hash), true),
            (query(b"get_peers", b"info_hash", [6u8; 20]), false),
            (query(b"find_node", b"target", [6u8; 20]), false),
        ] {
            handle_query(
                &request,
                &requester_addr,
                &socket,
                &[9u8; 20],
                &secrets,
                &mut rt,
                &mut peer_store,
                &HashMap::new(),
            );
            let (len, _) = requester.recv_from(&mut packet).unwrap();
            let Value::Dict(response) = bencode::parse(&packet[..len]).unwrap() else {
                panic!("response was not a dictionary");
            };
            let Some(Value::Dict(r)) = dict_get(&response, b"r") else {
                panic!("response had no body");
            };
            assert_eq!(dict_get(r, b"id"), Some(&Value::Bytes([9u8; 20].to_vec())));
            if expect_values {
                assert_eq!(
                    dict_get(r, b"values"),
                    Some(&Value::List(vec![Value::Bytes(encode_peer(stored))]))
                );
                assert!(dict_get(r, b"nodes").is_none());
            } else {
                assert!(
                    matches!(dict_get(r, b"nodes"), Some(Value::Bytes(nodes)) if nodes.len() == 26)
                );
            }
        }
    }

    #[test]
    fn queries_are_canonical_bencode() {
        let id = [1u8; 20];
        let queries = [
            (build_ping_query(&id, b"t1"), &b"ping"[..]),
            (build_find_node_query(&id, &[2u8; 20], b"t2"), b"find_node"),
            (build_get_peers_query(&id, [3u8; 20], b"t3"), b"get_peers"),
            (
                build_announce_peer_query(&id, [4u8; 20], 51413, b"token", b"t4"),
                b"announce_peer",
            ),
        ];
        for (bytes, method) in queries {
            // The strict decoder rejects unsorted dictionary keys.
            let Value::Dict(query) = bencode::parse(&bytes).unwrap() else {
                panic!("query was not a dictionary");
            };
            assert_eq!(dict_get(&query, b"q"), Some(&Value::Bytes(method.to_vec())));
            assert_eq!(dict_get(&query, b"y"), Some(&Value::Bytes(b"q".to_vec())));
            let Some(Value::Dict(args)) = dict_get(&query, b"a") else {
                panic!("query had no arguments");
            };
            assert_eq!(dict_get(args, b"id"), Some(&Value::Bytes(id.to_vec())));
        }
    }

    #[test]
    fn type_prefixed_decoder_rejects_partial_records() {
        let mut bytes = Vec::new();
        bytes.push(4u8);
        bytes.extend_from_slice(&[1u8; 10]); // truncated record
        assert!(decode_nodes_type_prefixed(&bytes).is_none());
    }

    #[test]
    fn legacy_data_starting_with_4_does_not_require_type_format() {
        let mut legacy = Vec::new();
        let mut id = [0u8; 20];
        id[0] = 4; // could be misdetected as a marker in ambiguous parser
        legacy.extend_from_slice(&id);
        legacy.extend_from_slice(&[192, 0, 2, 7]);
        legacy.extend_from_slice(&7000u16.to_be_bytes());

        let parsed_prefixed = decode_nodes_type_prefixed(&legacy);
        assert!(parsed_prefixed.is_none());

        let parsed_legacy = decode_legacy_nodes(&legacy);
        assert_eq!(parsed_legacy.len(), 1);
        assert_eq!(parsed_legacy[0].id[0], 4);
        assert_eq!(parsed_legacy[0].addr, "192.0.2.7:7000".parse().unwrap());
    }
}

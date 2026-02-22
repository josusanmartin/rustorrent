use std::collections::HashMap;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::bencode::{self, Value};
use crate::sha1;

const DHT_TIMEOUT: Duration = Duration::from_secs(3);
const QUERY_INTERVAL: Duration = Duration::from_secs(15);
const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(60);
const SAVE_INTERVAL: Duration = Duration::from_secs(300);
const K: usize = 8;
const NUM_BUCKETS: usize = 160;
const MAX_PEERS_PER_TORRENT: usize = 256;

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

pub fn start(bind_port: u16) -> Dht {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    thread::spawn(move || {
        dht_thread(bind_port, cmd_rx);
    });
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

#[derive(Clone)]
struct Node {
    id: [u8; 20],
    addr: SocketAddr,
    last_seen: Instant,
}

struct RoutingTable {
    own_id: [u8; 20],
    buckets: Vec<Vec<Node>>,
}

impl RoutingTable {
    fn new(own_id: [u8; 20]) -> Self {
        let mut buckets = Vec::with_capacity(NUM_BUCKETS);
        for _ in 0..NUM_BUCKETS {
            buckets.push(Vec::new());
        }
        Self { own_id, buckets }
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

    fn insert(&mut self, node: Node) {
        if node.id == self.own_id {
            return;
        }
        let idx = self.bucket_index(&node.id);
        let bucket = &mut self.buckets[idx];
        if let Some(pos) = bucket.iter().position(|n| n.id == node.id) {
            bucket[pos].last_seen = node.last_seen;
            bucket[pos].addr = node.addr;
            return;
        }
        if bucket.len() < K {
            bucket.push(node);
        } else {
            // Replace oldest node if it's been seen more than 15 minutes ago
            if let Some(oldest_pos) = bucket
                .iter()
                .enumerate()
                .max_by_key(|(_, n)| n.last_seen.elapsed())
                .map(|(i, _)| i)
            {
                if bucket[oldest_pos].last_seen.elapsed() > Duration::from_secs(900) {
                    bucket[oldest_pos] = node;
                }
            }
        }
    }

    fn closest(&self, target: &[u8; 20], count: usize) -> Vec<Node> {
        let mut all: Vec<&Node> = self.buckets.iter().flat_map(|b| b.iter()).collect();
        all.sort_by(|a, b| {
            let da = xor_distance(&a.id, target);
            let db = xor_distance(&b.id, target);
            da.cmp(&db)
        });
        all.into_iter().take(count).cloned().collect()
    }

    fn node_count(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    fn all_nodes(&self) -> Vec<&Node> {
        self.buckets.iter().flat_map(|b| b.iter()).collect()
    }

    fn encode_closest_nodes(&self, target: &[u8; 20]) -> Vec<u8> {
        let closest = self.closest(target, 8);
        let mut out = Vec::new();
        for node in closest {
            out.extend_from_slice(&node.id);
            match node.addr.ip() {
                std::net::IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
                std::net::IpAddr::V6(_) => continue,
            }
            out.extend_from_slice(&node.addr.port().to_be_bytes());
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

fn nodes_file_path() -> PathBuf {
    let mut path = PathBuf::from(".rustorrent");
    let _ = fs::create_dir_all(&path);
    path.push("dht_nodes.dat");
    path
}

fn save_nodes(rt: &RoutingTable) {
    let nodes = rt.all_nodes();
    let mut data = Vec::with_capacity(nodes.len() * 26);
    for node in nodes {
        if let std::net::IpAddr::V4(ip) = node.addr.ip() {
            data.extend_from_slice(&node.id);
            data.extend_from_slice(&ip.octets());
            data.extend_from_slice(&node.addr.port().to_be_bytes());
        }
    }
    let _ = fs::write(nodes_file_path(), &data);
}

fn load_nodes(rt: &mut RoutingTable) -> usize {
    let data = match fs::read(nodes_file_path()) {
        Ok(d) => d,
        Err(_) => return 0,
    };
    let mut count = 0;
    let mut i = 0;
    while i + 26 <= data.len() {
        let mut id = [0u8; 20];
        id.copy_from_slice(&data[i..i + 20]);
        let ip = std::net::Ipv4Addr::new(data[i + 20], data[i + 21], data[i + 22], data[i + 23]);
        let port = u16::from_be_bytes([data[i + 24], data[i + 25]]);
        rt.insert(Node {
            id,
            addr: SocketAddr::new(ip.into(), port),
            last_seen: Instant::now(),
        });
        count += 1;
        i += 26;
    }
    count
}

struct TorrentEntry {
    peers_tx: mpsc::Sender<Vec<SocketAddr>>,
    port: u16,
    last_query: Instant,
    last_bootstrap: Instant,
}

struct PendingQuery {
    info_hash: [u8; 20],
    addr: SocketAddr,
}

fn dht_thread(bind_port: u16, cmd_rx: mpsc::Receiver<Command>) {
    let socket = match UdpSocket::bind(("0.0.0.0", bind_port)) {
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
    };
    let _ = socket.set_read_timeout(Some(DHT_TIMEOUT));
    let node_id = random_node_id();
    let secret = random_node_id();

    let mut rt = RoutingTable::new(node_id);
    let loaded = load_nodes(&mut rt);
    if loaded > 0 {
        crate::log_stderr(format_args!("dht: loaded {loaded} nodes from cache"));
    }

    let mut torrents: HashMap<[u8; 20], TorrentEntry> = HashMap::new();
    let mut peer_store: HashMap<[u8; 20], Vec<SocketAddr>> = HashMap::new();
    let mut pending: HashMap<Vec<u8>, PendingQuery> = HashMap::new();

    let mut last_tick = Instant::now();
    let mut last_save = Instant::now();
    let mut query_node_idx = 0usize;

    loop {
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Command::AddTorrent {
                    info_hash,
                    port,
                    peers_tx,
                } => {
                    torrents.insert(
                        info_hash,
                        TorrentEntry {
                            peers_tx,
                            port,
                            last_query: Instant::now() - QUERY_INTERVAL,
                            last_bootstrap: Instant::now() - BOOTSTRAP_INTERVAL,
                        },
                    );
                }
                Command::RemoveTorrent { info_hash } => {
                    torrents.remove(&info_hash);
                    peer_store.remove(&info_hash);
                }
            }
        }

        if last_tick.elapsed() >= Duration::from_millis(200) {
            last_tick = Instant::now();
            for (info_hash, entry) in torrents.iter_mut() {
                if entry.last_bootstrap.elapsed() >= BOOTSTRAP_INTERVAL {
                    bootstrap_nodes(&socket, &node_id, &mut rt);
                    entry.last_bootstrap = Instant::now();
                }

                if entry.last_query.elapsed() >= QUERY_INTERVAL {
                    let closest = rt.closest(info_hash, K);
                    if !closest.is_empty() {
                        let node = &closest[query_node_idx % closest.len()];
                        query_node_idx = query_node_idx.wrapping_add(1);
                        let tx = next_tx_id();
                        let query = build_get_peers_query(&node_id, *info_hash, &tx);
                        if socket.send_to(&query, node.addr).is_ok() {
                            pending.insert(
                                tx,
                                PendingQuery {
                                    info_hash: *info_hash,
                                    addr: node.addr,
                                },
                            );
                        }
                    }
                    entry.last_query = Instant::now();
                }
            }
        }

        if last_save.elapsed() >= SAVE_INTERVAL {
            save_nodes(&rt);
            last_save = Instant::now();
        }

        let mut buf = [0u8; 1500];
        match socket.recv_from(&mut buf) {
            Ok((n, addr)) => {
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
                            ),
                            b"q" => handle_query(
                                &dict,
                                &addr,
                                &socket,
                                &node_id,
                                &secret,
                                &mut rt,
                                &mut peer_store,
                                &torrents,
                            ),
                            _ => {}
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
}

fn handle_response(
    dict: &[(Vec<u8>, Value)],
    addr: &SocketAddr,
    rt: &mut RoutingTable,
    pending: &mut HashMap<Vec<u8>, PendingQuery>,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    peer_store: &mut HashMap<[u8; 20], Vec<SocketAddr>>,
    torrents: &HashMap<[u8; 20], TorrentEntry>,
) {
    let tx = match dict_get(dict, b"t") {
        Some(Value::Bytes(tx)) => tx.clone(),
        _ => return,
    };
    let Some(pending_query) = pending.remove(&tx) else {
        return;
    };
    let Some(Value::Dict(r)) = dict_get(dict, b"r") else {
        return;
    };

    if let Some(Value::Bytes(nodes_bytes)) = dict_get(r, b"nodes") {
        for node in decode_nodes(nodes_bytes) {
            rt.insert(node);
        }
    }
    if let Some(Value::List(values)) = dict_get(r, b"values") {
        let mut peers = Vec::new();
        for value in values {
            if let Value::Bytes(bytes) = value {
                peers.extend(decode_peers(bytes));
            }
        }
        if !peers.is_empty() {
            peer_store
                .entry(pending_query.info_hash)
                .or_default()
                .extend(peers.iter().cloned());
            if let Some(entry) = torrents.get(&pending_query.info_hash) {
                let _ = entry.peers_tx.send(peers);
            }
        }
    }
    if let Some(Value::Bytes(token)) = dict_get(r, b"token") {
        if let Some(entry) = torrents.get(&pending_query.info_hash) {
            let tx = next_tx_id();
            let announce =
                build_announce_peer_query(node_id, pending_query.info_hash, entry.port, token, &tx);
            let _ = socket.send_to(&announce, pending_query.addr);
        }
    }

    if let Some(Value::Bytes(id)) = dict_get(r, b"id") {
        if id.len() == 20 {
            let mut nid = [0u8; 20];
            nid.copy_from_slice(id);
            rt.insert(Node {
                id: nid,
                addr: *addr,
                last_seen: Instant::now(),
            });
        }
    }
}

fn handle_query(
    dict: &[(Vec<u8>, Value)],
    addr: &SocketAddr,
    socket: &UdpSocket,
    node_id: &[u8; 20],
    secret: &[u8; 20],
    rt: &mut RoutingTable,
    peer_store: &mut HashMap<[u8; 20], Vec<SocketAddr>>,
    torrents: &HashMap<[u8; 20], TorrentEntry>,
) {
    let tx = match dict_get(dict, b"t") {
        Some(Value::Bytes(tx)) => tx.clone(),
        _ => return,
    };
    let Some(Value::Bytes(query)) = dict_get(dict, b"q") else {
        return;
    };
    let Some(Value::Dict(args)) = dict_get(dict, b"a") else {
        return;
    };

    if let Some(Value::Bytes(id)) = dict_get(args, b"id") {
        if id.len() == 20 {
            let mut nid = [0u8; 20];
            nid.copy_from_slice(id);
            rt.insert(Node {
                id: nid,
                addr: *addr,
                last_seen: Instant::now(),
            });
        }
    }

    match query.as_slice() {
        b"ping" => {
            let resp = build_response(node_id, &tx, vec![]);
            let _ = socket.send_to(&resp, addr);
        }
        b"find_node" => {
            let target = match dict_get(args, b"target") {
                Some(Value::Bytes(t)) if t.len() == 20 => {
                    let mut arr = [0u8; 20];
                    arr.copy_from_slice(t);
                    arr
                }
                _ => rt.own_id,
            };
            let nodes_bytes = rt.encode_closest_nodes(&target);
            let r = vec![
                (b"id".to_vec(), Value::Bytes(node_id.to_vec())),
                (b"nodes".to_vec(), Value::Bytes(nodes_bytes)),
            ];
            let resp = build_response(node_id, &tx, r);
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
            let token = make_token(secret, addr);
            let mut r = vec![
                (b"id".to_vec(), Value::Bytes(node_id.to_vec())),
                (b"token".to_vec(), Value::Bytes(token.to_vec())),
            ];
            if let Some(peers) = peer_store.get(&info_hash_arr) {
                let mut values = Vec::new();
                for chunk in peers.chunks(50) {
                    values.push(Value::Bytes(encode_peers(chunk)));
                }
                r.push((b"values".to_vec(), Value::List(values)));
            } else {
                let nodes_bytes = rt.encode_closest_nodes(&info_hash_arr);
                r.push((b"nodes".to_vec(), Value::Bytes(nodes_bytes)));
            }
            let resp = build_response(node_id, &tx, r);
            let _ = socket.send_to(&resp, addr);
        }
        b"announce_peer" => {
            let Some(Value::Bytes(info_hash)) = dict_get(args, b"info_hash") else {
                return;
            };
            let Some(Value::Bytes(token)) = dict_get(args, b"token") else {
                return;
            };
            if !verify_token(secret, addr, token) {
                return;
            }
            let port = match dict_get(args, b"port") {
                Some(Value::Int(port)) if *port > 0 && *port <= u16::MAX as i64 => *port as u16,
                _ => return,
            };
            let mut info_hash_arr = [0u8; 20];
            if info_hash.len() != 20 {
                return;
            }
            info_hash_arr.copy_from_slice(info_hash);
            let peer_addr = SocketAddr::new(addr.ip(), port);
            let entry = peer_store.entry(info_hash_arr).or_default();
            if entry.len() < MAX_PEERS_PER_TORRENT {
                entry.push(peer_addr);
            }
            if let Some(entry) = torrents.get(&info_hash_arr) {
                let _ = entry.peers_tx.send(vec![peer_addr]);
            }
            let resp = build_response(node_id, &tx, vec![]);
            let _ = socket.send_to(&resp, addr);
        }
        _ => {}
    }
}

fn build_response(node_id: &[u8; 20], tx: &[u8], extra: Vec<(Vec<u8>, Value)>) -> Vec<u8> {
    let mut r = vec![(b"id".to_vec(), Value::Bytes(node_id.to_vec()))];
    r.extend(extra);
    let dict = Value::Dict(vec![
        (b"t".to_vec(), Value::Bytes(tx.to_vec())),
        (b"y".to_vec(), Value::Bytes(b"r".to_vec())),
        (b"r".to_vec(), Value::Dict(r)),
    ]);
    bencode::encode(&dict)
}

fn build_get_peers_query(node_id: &[u8; 20], info_hash: [u8; 20], tx: &[u8]) -> Vec<u8> {
    let a = Value::Dict(vec![
        (b"id".to_vec(), Value::Bytes(node_id.to_vec())),
        (b"info_hash".to_vec(), Value::Bytes(info_hash.to_vec())),
    ]);
    let dict = Value::Dict(vec![
        (b"t".to_vec(), Value::Bytes(tx.to_vec())),
        (b"y".to_vec(), Value::Bytes(b"q".to_vec())),
        (b"q".to_vec(), Value::Bytes(b"get_peers".to_vec())),
        (b"a".to_vec(), a),
    ]);
    bencode::encode(&dict)
}

fn build_announce_peer_query(
    node_id: &[u8; 20],
    info_hash: [u8; 20],
    port: u16,
    token: &[u8],
    tx: &[u8],
) -> Vec<u8> {
    let a = Value::Dict(vec![
        (b"id".to_vec(), Value::Bytes(node_id.to_vec())),
        (b"info_hash".to_vec(), Value::Bytes(info_hash.to_vec())),
        (b"port".to_vec(), Value::Int(port as i64)),
        (b"token".to_vec(), Value::Bytes(token.to_vec())),
    ]);
    let dict = Value::Dict(vec![
        (b"t".to_vec(), Value::Bytes(tx.to_vec())),
        (b"y".to_vec(), Value::Bytes(b"q".to_vec())),
        (b"q".to_vec(), Value::Bytes(b"announce_peer".to_vec())),
        (b"a".to_vec(), a),
    ]);
    bencode::encode(&dict)
}

fn bootstrap_nodes(socket: &UdpSocket, node_id: &[u8; 20], rt: &mut RoutingTable) {
    if rt.node_count() > K * 2 {
        return;
    }
    for host in BOOTSTRAP_NODES {
        if let Ok(mut addrs) = host.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                let tx = next_tx_id();
                let query = build_find_node_query(node_id, node_id, &tx);
                let _ = socket.send_to(&query, addr);
            }
        }
    }
}

fn build_find_node_query(node_id: &[u8; 20], target: &[u8; 20], tx: &[u8]) -> Vec<u8> {
    let a = Value::Dict(vec![
        (b"id".to_vec(), Value::Bytes(node_id.to_vec())),
        (b"target".to_vec(), Value::Bytes(target.to_vec())),
    ]);
    let dict = Value::Dict(vec![
        (b"t".to_vec(), Value::Bytes(tx.to_vec())),
        (b"y".to_vec(), Value::Bytes(b"q".to_vec())),
        (b"q".to_vec(), Value::Bytes(b"find_node".to_vec())),
        (b"a".to_vec(), a),
    ]);
    bencode::encode(&dict)
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

fn make_token(secret: &[u8; 20], addr: &SocketAddr) -> [u8; 4] {
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
    if token.len() < 4 {
        return false;
    }
    make_token(secret, addr) == [token[0], token[1], token[2], token[3]]
}

fn random_node_id() -> [u8; 20] {
    let mut out = [0u8; 20];
    let mut seed = next_u64();
    for slot in &mut out {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *slot = (seed & 0xff) as u8;
    }
    out
}

fn next_u64() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    static SEED: AtomicU64 = AtomicU64::new(0x8765_4321_1234_5678);
    INIT.get_or_init(|| {
        SEED.store(crate::system_entropy_u64(), Ordering::Relaxed);
    });
    let mut x = SEED.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    SEED.store(x, Ordering::Relaxed);
    x
}

fn next_tx_id() -> Vec<u8> {
    let x = next_u64() as u16;
    x.to_be_bytes().to_vec()
}

fn dict_get<'a>(dict: &'a [(Vec<u8>, Value)], key: &[u8]) -> Option<&'a Value> {
    dict.iter()
        .find_map(|(k, v)| if k.as_slice() == key { Some(v) } else { None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
    fn distance_helpers_work_for_extremes() {
        let a = [0u8; 20];
        let mut b = [0u8; 20];
        b[0] = 0x10;
        let dist = xor_distance(&a, &b);
        assert_eq!(dist[0], 0x10);
        assert_eq!(leading_zeros(&dist), 3);
        assert_eq!(leading_zeros(&[0u8; 20]), 160);
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
    }

    #[test]
    fn routing_table_returns_closest_nodes_and_encoded_limit() {
        let mut rt = RoutingTable::new([0u8; 20]);
        for i in 1..=10u8 {
            rt.insert(node(i, [10, 0, 0, i], 6000 + i as u16));
        }

        let target = [0u8; 20];
        let closest = rt.closest(&target, 3);
        assert_eq!(closest.len(), 3);
        assert!(closest[0].id[0] <= closest[1].id[0]);

        let encoded = rt.encode_closest_nodes(&target);
        assert_eq!(encoded.len(), 26 * 8);
    }
}

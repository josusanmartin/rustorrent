use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const UTP_VERSION: u8 = 1;
const UTP_HEADER_LEN: usize = 20;
const UTP_PAYLOAD_MAX: usize = 1200;
const UTP_ACK_TIMEOUT: Duration = Duration::from_millis(500);
const UTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const UTP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const INITIAL_CWND: usize = 4;
const MAX_CWND: usize = 64;

// LEDBAT constants (BEP 29 / RFC 6817)
const LEDBAT_TARGET_DELAY_US: i64 = 100_000; // 100ms target delay
const MAX_CWND_INCREASE: i64 = 3000; // max bytes gained per RTT
const BASE_DELAY_WINDOW: Duration = Duration::from_secs(120); // 2-minute rolling minimum

// SACK extension type
const EXT_SACK: u8 = 1;

const TYPE_DATA: u8 = 0;
const TYPE_FIN: u8 = 1;
const TYPE_STATE: u8 = 2;
const TYPE_RESET: u8 = 3;
const TYPE_SYN: u8 = 4;

#[derive(Clone)]
pub struct UtpConnector {
    cmd_tx: mpsc::Sender<Command>,
}

pub struct UtpListener {
    accept_rx: mpsc::Receiver<UtpStream>,
}

enum Command {
    Connect {
        addr: SocketAddr,
        resp: mpsc::Sender<Result<UtpStream, String>>,
    },
}

pub fn start(port: u16) -> (UtpConnector, UtpListener) {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (accept_tx, accept_rx) = mpsc::channel();
    thread::spawn(move || {
        let socket = match UdpSocket::bind(("0.0.0.0", port)) {
            Ok(socket) => socket,
            Err(_) => match UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, port)) {
                Ok(socket) => socket,
                Err(_) => return,
            },
        };
        let _ = socket.set_read_timeout(Some(Duration::from_millis(50)));
        utp_loop(socket, cmd_rx, accept_tx);
    });
    (UtpConnector { cmd_tx }, UtpListener { accept_rx })
}

impl UtpConnector {
    pub fn connect(&self, addr: SocketAddr) -> Result<UtpStream, String> {
        let (resp_tx, resp_rx) = mpsc::channel();
        self.cmd_tx
            .send(Command::Connect {
                addr,
                resp: resp_tx,
            })
            .map_err(|_| "utp manager closed".to_string())?;
        resp_rx
            .recv()
            .map_err(|_| "utp connect failed".to_string())?
    }
}

impl UtpListener {
    pub fn try_accept(&self) -> Option<UtpStream> {
        self.accept_rx.try_recv().ok()
    }
}

pub struct UtpStream {
    #[allow(dead_code)]
    addr: SocketAddr,
    send_tx: mpsc::Sender<SendRequest>,
    recv_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: VecDeque<u8>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl UtpStream {
    #[allow(dead_code)]
    pub fn peer_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        self.write_timeout = timeout;
    }
}

impl Read for UtpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.read_buf.is_empty() {
            match self
                .recv_rx
                .recv_timeout(self.read_timeout.unwrap_or(Duration::from_secs(5)))
            {
                Ok(chunk) => self.read_buf.extend(chunk),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "utp read timeout",
                    ));
                }
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "utp closed",
                    ));
                }
            }
        }
        let mut n = 0usize;
        while n < buf.len() && !self.read_buf.is_empty() {
            buf[n] = self.read_buf.pop_front().unwrap();
            n += 1;
        }
        Ok(n)
    }
}

impl Write for UtpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0usize;
        for chunk in buf.chunks(UTP_PAYLOAD_MAX) {
            let (resp_tx, resp_rx) = mpsc::channel();
            let req = SendRequest {
                data: chunk.to_vec(),
                resp: resp_tx,
            };
            self.send_tx
                .send(req)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "utp send"))?;
            let timeout = self.write_timeout.unwrap_or(Duration::from_secs(5));
            match resp_rx.recv_timeout(timeout) {
                Ok(Ok(())) => {
                    written += chunk.len();
                }
                Ok(Err(err)) => {
                    return Err(std::io::Error::other(err));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "utp write timeout",
                    ));
                }
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "utp send failed",
                    ));
                }
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct SendRequest {
    data: Vec<u8>,
    resp: mpsc::Sender<Result<(), String>>,
}

struct ConnState {
    addr: SocketAddr,
    send_id: u16,
    recv_id: Option<u16>,
    seq: u16,
    recv_seq: u16,
    state: ConnStatus,
    inflight: VecDeque<PendingPacket>,
    cwnd: usize,
    send_rx: mpsc::Receiver<SendRequest>,
    recv_tx: mpsc::Sender<Vec<u8>>,
    last_seen: Instant,
    connect_started: Instant,
    connect_resp: Option<mpsc::Sender<Result<UtpStream, String>>>,
    connect_stream: Option<UtpStream>,
    // Timestamp diff tracking (BEP 29)
    peer_timestamp: u32,
    timestamp_diff: u32,
    // Out-of-order received packets for SACK
    ooo_received: HashSet<u16>,
    // LEDBAT delay-based congestion state
    base_delay: Option<u32>,
    base_delay_updated: Instant,
    current_delay: u32,
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum ConnStatus {
    SynSent,
    Connected,
    Closed,
}

struct PendingPacket {
    seq: u16,
    data: Vec<u8>,
    sent_at: Instant,
    resp: mpsc::Sender<Result<(), String>>,
}

fn utp_loop(
    socket: UdpSocket,
    cmd_rx: mpsc::Receiver<Command>,
    accept_tx: mpsc::Sender<UtpStream>,
) {
    let mut conns: HashMap<(SocketAddr, u16), ConnState> = HashMap::new();
    let mut buf = [0u8; 1500];
    loop {
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Command::Connect { addr, resp } => {
                    let send_id = next_u16();
                    let seq = next_u16();
                    let (send_tx, send_rx) = mpsc::channel();
                    let (recv_tx, recv_rx) = mpsc::channel();
                    let stream = UtpStream {
                        addr,
                        send_tx,
                        recv_rx,
                        read_buf: VecDeque::new(),
                        read_timeout: None,
                        write_timeout: None,
                    };
                    let now = Instant::now();
                    let conn = ConnState {
                        addr,
                        send_id,
                        recv_id: None,
                        seq,
                        recv_seq: 0,
                        state: ConnStatus::SynSent,
                        inflight: VecDeque::new(),
                        cwnd: INITIAL_CWND,
                        send_rx,
                        recv_tx,
                        last_seen: now,
                        connect_started: now,
                        connect_resp: Some(resp),
                        connect_stream: Some(stream),
                        peer_timestamp: 0,
                        timestamp_diff: 0,
                        ooo_received: HashSet::new(),
                        base_delay: None,
                        base_delay_updated: now,
                        current_delay: 0,
                    };
                    let packet = build_packet(TYPE_SYN, send_id, seq, 0, &[]);
                    let _ = socket.send_to(&packet, addr);
                    conns.insert((addr, send_id), conn);
                }
            }
        }

        let mut remove_keys = Vec::new();
        for (key, conn) in conns.iter_mut() {
            if matches!(conn.state, ConnStatus::Closed) {
                remove_keys.push(*key);
                continue;
            }
            if conn.state == ConnStatus::SynSent
                && conn.connect_started.elapsed() >= UTP_CONNECT_TIMEOUT
            {
                drain_inflight_err(conn, "utp connect timeout");
                if let Some(resp) = conn.connect_resp.take() {
                    let _ = resp.send(Err("utp connect timeout".to_string()));
                }
                conn.connect_stream.take();
                conn.state = ConnStatus::Closed;
                remove_keys.push(*key);
                continue;
            }

            // Fill send window from send_rx
            while conn.inflight.len() < conn.cwnd && matches!(conn.state, ConnStatus::Connected) {
                match conn.send_rx.try_recv() {
                    Ok(req) => {
                        conn.seq = conn.seq.wrapping_add(1);
                        let packet = build_packet_ext(
                            TYPE_DATA,
                            conn.send_id,
                            conn.seq,
                            conn.recv_seq,
                            conn.timestamp_diff,
                            &[],
                            &req.data,
                        );
                        let _ = socket.send_to(&packet, conn.addr);
                        conn.inflight.push_back(PendingPacket {
                            seq: conn.seq,
                            data: req.data,
                            sent_at: Instant::now(),
                            resp: req.resp,
                        });
                    }
                    Err(_) => break,
                }
            }

            // Retransmit timed-out packets and halve cwnd (timeout fallback)
            let mut did_timeout = false;
            for pending in conn.inflight.iter_mut() {
                if pending.sent_at.elapsed() >= UTP_ACK_TIMEOUT {
                    let packet = build_packet_ext(
                        TYPE_DATA,
                        conn.send_id,
                        pending.seq,
                        conn.recv_seq,
                        conn.timestamp_diff,
                        &[],
                        &pending.data,
                    );
                    let _ = socket.send_to(&packet, conn.addr);
                    pending.sent_at = Instant::now();
                    did_timeout = true;
                }
            }
            if did_timeout {
                conn.cwnd = (conn.cwnd / 2).max(1);
            }

            if conn.last_seen.elapsed() >= UTP_IDLE_TIMEOUT {
                drain_inflight_err(conn, "utp idle timeout");
                if let Some(resp) = conn.connect_resp.take() {
                    let _ = resp.send(Err("utp idle timeout".to_string()));
                }
                conn.connect_stream.take();
                conn.state = ConnStatus::Closed;
                remove_keys.push(*key);
            }
        }
        for key in remove_keys {
            conns.remove(&key);
        }

        if let Ok((n, addr)) = socket.recv_from(&mut buf) {
            if n < UTP_HEADER_LEN {
                continue;
            }
            let pkt = parse_packet(&buf[..n]);
            let (ty, conn_id, seq, ack) = (pkt.ty, pkt.conn_id, pkt.seq, pkt.ack);
            let payload = pkt.payload;
            if ty == TYPE_SYN {
                let recv_id = conn_id;
                let send_id = conn_id.wrapping_add(1);
                let (send_tx, send_rx) = mpsc::channel();
                let (recv_tx, recv_rx) = mpsc::channel();
                let stream = UtpStream {
                    addr,
                    send_tx,
                    recv_rx,
                    read_buf: VecDeque::new(),
                    read_timeout: None,
                    write_timeout: None,
                };
                let now = Instant::now();
                let conn = ConnState {
                    addr,
                    send_id,
                    recv_id: Some(recv_id),
                    seq: next_u16(),
                    recv_seq: seq,
                    state: ConnStatus::Connected,
                    inflight: VecDeque::new(),
                    cwnd: INITIAL_CWND,
                    send_rx,
                    recv_tx,
                    last_seen: now,
                    connect_started: now,
                    connect_resp: None,
                    connect_stream: None,
                    peer_timestamp: pkt.timestamp,
                    timestamp_diff: timestamp().wrapping_sub(pkt.timestamp),
                    ooo_received: HashSet::new(),
                    base_delay: None,
                    base_delay_updated: now,
                    current_delay: 0,
                };
                let state_pkt = build_packet_ext(
                    TYPE_STATE,
                    send_id,
                    conn.seq,
                    seq,
                    conn.timestamp_diff,
                    &[],
                    &[],
                );
                let _ = socket.send_to(&state_pkt, addr);
                let _ = accept_tx.send(stream);
                conns.insert((addr, recv_id), conn);
                continue;
            }

            let key = (addr, conn_id);
            if !conns.contains_key(&key) && ty == TYPE_STATE {
                let mut match_key = None;
                for (conn_key, conn) in conns.iter() {
                    if conn_key.0 != addr {
                        continue;
                    }
                    if conn.state == ConnStatus::SynSent && conn.send_id.wrapping_add(1) == conn_id
                    {
                        match_key = Some(*conn_key);
                        break;
                    }
                }
                if let Some(old_key) = match_key {
                    if let Some(mut conn) = conns.remove(&old_key) {
                        let recv_id = conn_id;
                        conn.recv_id = Some(recv_id);
                        conn.state = ConnStatus::Connected;
                        conn.recv_seq = seq;
                        conn.peer_timestamp = pkt.timestamp;
                        conn.timestamp_diff = timestamp().wrapping_sub(pkt.timestamp);
                        if pkt.timestamp_diff != 0 {
                            conn.current_delay = pkt.timestamp_diff;
                        }
                        if let Some(resp) = conn.connect_resp.take() {
                            if let Some(stream) = conn.connect_stream.take() {
                                let _ = resp.send(Ok(stream));
                            } else {
                                let _ = resp.send(Err("utp connect failed".to_string()));
                            }
                        }
                        let new_key = (addr, recv_id);
                        conns.insert(new_key, conn);
                    }
                }
                continue;
            }

            let conn = match conns.get_mut(&key) {
                Some(conn) => conn,
                None => continue,
            };
            conn.last_seen = Instant::now();

            // Record peer timestamp and compute timestamp_diff for next outgoing packet
            conn.peer_timestamp = pkt.timestamp;
            conn.timestamp_diff = timestamp().wrapping_sub(pkt.timestamp);
            // Record the peer's reported delay for LEDBAT
            if pkt.timestamp_diff != 0 {
                conn.current_delay = pkt.timestamp_diff;
            }

            match ty {
                TYPE_STATE => {
                    // Cumulative ACK: remove all packets with seq <= ack
                    let mut bytes_acked: usize = 0;
                    while let Some(front) = conn.inflight.front() {
                        if front.seq == ack || is_seq_before_or_equal(front.seq, ack) {
                            let p = conn.inflight.pop_front().unwrap();
                            bytes_acked += p.data.len();
                            let _ = p.resp.send(Ok(()));
                        } else {
                            break;
                        }
                    }

                    // Process incoming SACK: mark selectively-acked inflight packets
                    if !pkt.sack.is_empty() {
                        let mut sack_acked = HashSet::new();
                        for (byte_idx, &byte) in pkt.sack.iter().enumerate() {
                            for bit in 0..8u16 {
                                if byte & (1 << bit) != 0 {
                                    let sacked_seq =
                                        ack.wrapping_add(2).wrapping_add(byte_idx as u16 * 8 + bit);
                                    sack_acked.insert(sacked_seq);
                                }
                            }
                        }
                        // Remove SACK-ed inflight packets and complete them
                        let mut remaining = VecDeque::new();
                        while let Some(p) = conn.inflight.pop_front() {
                            if sack_acked.contains(&p.seq) {
                                bytes_acked += p.data.len();
                                let _ = p.resp.send(Ok(()));
                            } else {
                                remaining.push_back(p);
                            }
                        }
                        conn.inflight = remaining;
                    }

                    // LEDBAT congestion control instead of simple additive increase
                    if bytes_acked > 0 {
                        ledbat_update_cwnd(conn, bytes_acked);
                    }
                }
                TYPE_DATA => {
                    if seq == conn.recv_seq.wrapping_add(1) {
                        // In-order: advance recv_seq
                        conn.recv_seq = seq;
                        let _ = conn.recv_tx.send(payload.to_vec());
                        // Deliver any buffered out-of-order packets that are now in sequence
                        // (we only track their seq numbers; actual data re-delivery relies
                        //  on the peer retransmitting, but we advance recv_seq so the SACK
                        //  bitmap shrinks and the peer knows they arrived)
                        while conn.ooo_received.remove(&conn.recv_seq.wrapping_add(1)) {
                            conn.recv_seq = conn.recv_seq.wrapping_add(1);
                        }
                    } else if conn.recv_seq == seq {
                        // Duplicate of last delivered packet; re-ACK but don't deliver again
                    } else {
                        // Out-of-order: track for SACK
                        let offset = seq.wrapping_sub(conn.recv_seq.wrapping_add(2));
                        if (offset as usize) < 32 {
                            conn.ooo_received.insert(seq);
                        }
                    }
                    // Build outgoing STATE with SACK extension if we have OOO packets
                    let sack_ext = build_sack_extension(conn.recv_seq, &conn.ooo_received);
                    let state_pkt = build_packet_ext(
                        TYPE_STATE,
                        conn.send_id,
                        conn.seq,
                        conn.recv_seq,
                        conn.timestamp_diff,
                        &sack_ext,
                        &[],
                    );
                    let _ = socket.send_to(&state_pkt, conn.addr);
                }
                TYPE_FIN => {
                    drain_inflight_err(conn, "utp closed");
                    if let Some(resp) = conn.connect_resp.take() {
                        let _ = resp.send(Err("utp closed".to_string()));
                    }
                    conn.connect_stream.take();
                    conn.state = ConnStatus::Closed;
                    let state_pkt = build_packet_ext(
                        TYPE_STATE,
                        conn.send_id,
                        conn.seq,
                        conn.recv_seq,
                        conn.timestamp_diff,
                        &[],
                        &[],
                    );
                    let _ = socket.send_to(&state_pkt, conn.addr);
                }
                TYPE_RESET => {
                    drain_inflight_err(conn, "utp reset");
                    if let Some(resp) = conn.connect_resp.take() {
                        let _ = resp.send(Err("utp reset".to_string()));
                    }
                    conn.connect_stream.take();
                    conn.state = ConnStatus::Closed;
                }
                _ => {}
            }
        }
    }
}

fn drain_inflight_err(conn: &mut ConnState, msg: &str) {
    while let Some(pkt) = conn.inflight.pop_front() {
        let _ = pkt.resp.send(Err(msg.to_string()));
    }
}

fn is_seq_before_or_equal(seq: u16, ack: u16) -> bool {
    // Handle wrapping: seq is before or equal to ack if the difference is small
    let diff = ack.wrapping_sub(seq);
    diff < 0x8000
}

fn build_packet(ty: u8, conn_id: u16, seq: u16, ack: u16, payload: &[u8]) -> Vec<u8> {
    build_packet_ext(ty, conn_id, seq, ack, 0, &[], payload)
}

fn build_packet_ext(
    ty: u8,
    conn_id: u16,
    seq: u16,
    ack: u16,
    ts_diff: u32,
    extensions: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let has_ext = !extensions.is_empty();
    let mut out = Vec::with_capacity(UTP_HEADER_LEN + extensions.len() + payload.len());
    out.push((ty << 4) | UTP_VERSION);
    // next-extension byte: 0 = no extensions, 1 = SACK follows
    out.push(if has_ext { EXT_SACK } else { 0 });
    out.extend_from_slice(&conn_id.to_be_bytes());
    out.extend_from_slice(&timestamp().to_be_bytes());
    out.extend_from_slice(&ts_diff.to_be_bytes());
    out.extend_from_slice(&0x400000u32.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ack.to_be_bytes());
    out.extend_from_slice(extensions);
    out.extend_from_slice(payload);
    out
}

struct ParsedPacket<'a> {
    ty: u8,
    conn_id: u16,
    timestamp: u32,
    timestamp_diff: u32,
    seq: u16,
    ack: u16,
    sack: Vec<u8>,
    payload: &'a [u8],
}

fn parse_packet(data: &[u8]) -> ParsedPacket<'_> {
    let ty = data[0] >> 4;
    let ext_type = data[1];
    let conn_id = u16::from_be_bytes([data[2], data[3]]);
    let ts = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ts_diff = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let seq = u16::from_be_bytes([data[16], data[17]]);
    let ack = u16::from_be_bytes([data[18], data[19]]);

    // Walk extensions chain starting after the 20-byte header
    let mut sack = Vec::new();
    let mut offset = UTP_HEADER_LEN;
    let mut cur_ext = ext_type;
    while cur_ext != 0 && offset + 2 <= data.len() {
        let next = data[offset];
        let ext_len = data[offset + 1] as usize;
        if cur_ext == EXT_SACK && offset + 2 + ext_len <= data.len() {
            sack.extend_from_slice(&data[offset + 2..offset + 2 + ext_len]);
        }
        offset += 2 + ext_len;
        cur_ext = next;
    }

    let payload = if offset <= data.len() {
        &data[offset..]
    } else {
        &[]
    };

    ParsedPacket {
        ty,
        conn_id,
        timestamp: ts,
        timestamp_diff: ts_diff,
        seq,
        ack,
        sack,
        payload,
    }
}

/// Build SACK extension bytes: [next_ext=0, length, bitmask...]
/// The bitmask indicates which packets after `ack_nr` have been received.
fn build_sack_extension(ack_nr: u16, ooo: &HashSet<u16>) -> Vec<u8> {
    if ooo.is_empty() {
        return Vec::new();
    }
    // SACK bitmask: bit i represents ack_nr + 2 + i  (ack_nr+1 is the first missing)
    // BEP 29 uses 4 bytes (32 bits) as the standard SACK length
    let sack_len: usize = 4;
    let mut bitmask = vec![0u8; sack_len];
    for &s in ooo {
        let offset = s.wrapping_sub(ack_nr.wrapping_add(2));
        let bit_idx = offset as usize;
        if bit_idx < sack_len * 8 {
            bitmask[bit_idx / 8] |= 1 << (bit_idx % 8);
        }
    }
    // Extension header: next_extension=0, length, then bitmask
    let mut ext = Vec::with_capacity(2 + sack_len);
    ext.push(0); // no further extensions
    ext.push(sack_len as u8);
    ext.extend_from_slice(&bitmask);
    ext
}

/// Update LEDBAT congestion window based on delay measurement.
fn ledbat_update_cwnd(conn: &mut ConnState, bytes_acked: usize) {
    if conn.current_delay == 0 {
        return;
    }
    let now = Instant::now();
    // Maintain base_delay as min over last 2 minutes
    match conn.base_delay {
        Some(bd) if now.duration_since(conn.base_delay_updated) < BASE_DELAY_WINDOW => {
            if conn.current_delay < bd {
                conn.base_delay = Some(conn.current_delay);
            }
        }
        _ => {
            conn.base_delay = Some(conn.current_delay);
            conn.base_delay_updated = now;
        }
    }
    let base = conn.base_delay.unwrap_or(conn.current_delay);
    let queuing_delay = (conn.current_delay as i64).saturating_sub(base as i64);
    // LEDBAT formula: cwnd += (TARGET - queuing_delay) / TARGET * MAX_CWND_INCREASE / cwnd
    // We work in packet-count units; approximate packet size as UTP_PAYLOAD_MAX
    let cwnd_bytes = (conn.cwnd as i64) * (UTP_PAYLOAD_MAX as i64);
    if cwnd_bytes <= 0 {
        return;
    }
    let off_target = LEDBAT_TARGET_DELAY_US - queuing_delay;
    let gain = (off_target * MAX_CWND_INCREASE) / LEDBAT_TARGET_DELAY_US;
    // Scale by acked bytes / cwnd_bytes
    let acked = bytes_acked.max(1) as i64;
    let delta_bytes = (gain * acked) / cwnd_bytes;
    let delta_pkts = delta_bytes / (UTP_PAYLOAD_MAX as i64);
    let new_cwnd = (conn.cwnd as i64 + delta_pkts).clamp(1, MAX_CWND as i64);
    conn.cwnd = new_cwnd as usize;
}

fn timestamp() -> u32 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_micros() as u32
}

fn next_u16() -> u16 {
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
    x as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_roundtrip_preserves_fields() {
        let payload = b"hello-utp";
        let packet = build_packet(TYPE_DATA, 42, 100, 99, payload);
        assert_eq!(packet.len(), UTP_HEADER_LEN + payload.len());

        let pkt = parse_packet(&packet);
        assert_eq!(pkt.ty, TYPE_DATA);
        assert_eq!(pkt.conn_id, 42);
        assert_eq!(pkt.seq, 100);
        assert_eq!(pkt.ack, 99);
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn sequence_compare_handles_wraparound() {
        assert!(is_seq_before_or_equal(10, 10));
        assert!(is_seq_before_or_equal(10, 11));
        assert!(!is_seq_before_or_equal(11, 10));
        assert!(is_seq_before_or_equal(65530, 5));
        assert!(!is_seq_before_or_equal(5, 65530));
    }

    #[test]
    fn utp_stream_read_uses_channel_and_internal_buffer() {
        let (send_tx, _send_rx) = mpsc::channel();
        let (recv_tx, recv_rx) = mpsc::channel();
        let mut stream = UtpStream {
            addr: "127.0.0.1:1".parse().unwrap(),
            send_tx,
            recv_rx,
            read_buf: VecDeque::new(),
            read_timeout: Some(Duration::from_millis(200)),
            write_timeout: None,
        };

        recv_tx.send(vec![1, 2, 3]).unwrap();
        let mut first = [0u8; 2];
        let n1 = stream.read(&mut first).unwrap();
        assert_eq!(n1, 2);
        assert_eq!(first, [1, 2]);

        let mut second = [0u8; 2];
        let n2 = stream.read(&mut second).unwrap();
        assert_eq!(n2, 1);
        assert_eq!(second[0], 3);
    }

    #[test]
    fn utp_stream_write_splits_payload_into_packets() {
        let (send_tx, send_rx) = mpsc::channel();
        let (_recv_tx, recv_rx) = mpsc::channel();
        let mut stream = UtpStream {
            addr: "127.0.0.1:1".parse().unwrap(),
            send_tx,
            recv_rx,
            read_buf: VecDeque::new(),
            read_timeout: None,
            write_timeout: Some(Duration::from_secs(1)),
        };

        let handle = thread::spawn(move || {
            let mut sizes = Vec::new();
            for _ in 0..2 {
                let req = send_rx.recv().unwrap();
                sizes.push(req.data.len());
                let _ = req.resp.send(Ok(()));
            }
            sizes
        });

        let total = UTP_PAYLOAD_MAX + 17;
        let written = stream.write(&vec![9u8; total]).unwrap();
        assert_eq!(written, total);
        let sizes = handle.join().unwrap();
        assert_eq!(sizes, vec![UTP_PAYLOAD_MAX, 17]);
    }

    #[test]
    fn utp_stream_write_respects_timeout() {
        let (send_tx, _send_rx) = mpsc::channel::<SendRequest>();
        let (_recv_tx, recv_rx) = mpsc::channel();
        let mut stream = UtpStream {
            addr: "127.0.0.1:1".parse().unwrap(),
            send_tx,
            recv_rx,
            read_buf: VecDeque::new(),
            read_timeout: None,
            write_timeout: Some(Duration::from_millis(10)),
        };

        let err = stream.write(&[1, 2, 3]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn connector_and_listener_exchange_data() {
        fn free_port() -> u16 {
            UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        }

        let port_a = free_port();
        let port_b = free_port();
        let (connector_a, _listener_a) = start(port_a);
        let (_connector_b, listener_b) = start(port_b);

        thread::sleep(Duration::from_millis(50));
        let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
        let mut a = connector_a.connect(addr_b).unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut b = loop {
            if let Some(stream) = listener_b.try_accept() {
                break stream;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for utp accept"
            );
            thread::sleep(Duration::from_millis(10));
        };

        a.set_read_timeout(Some(Duration::from_secs(1)));
        a.set_write_timeout(Some(Duration::from_secs(1)));
        b.set_read_timeout(Some(Duration::from_secs(1)));
        b.set_write_timeout(Some(Duration::from_secs(1)));

        a.write_all(b"abc").unwrap();
        let mut recv = [0u8; 3];
        b.read_exact(&mut recv).unwrap();
        assert_eq!(&recv, b"abc");

        b.write_all(b"ok").unwrap();
        let mut recv2 = [0u8; 2];
        a.read_exact(&mut recv2).unwrap();
        assert_eq!(&recv2, b"ok");
    }

    #[test]
    fn packet_ext_preserves_timestamp_diff() {
        let pkt = build_packet_ext(TYPE_STATE, 10, 5, 4, 12345, &[], &[]);
        let parsed = parse_packet(&pkt);
        assert_eq!(parsed.timestamp_diff, 12345);
        assert_eq!(parsed.ty, TYPE_STATE);
        assert_eq!(parsed.sack.len(), 0);
    }

    #[test]
    fn sack_extension_roundtrip() {
        let mut ooo = HashSet::new();
        // ack_nr = 10, so first missing is 11, bits represent 12, 13, 14...
        ooo.insert(12); // bit 0
        ooo.insert(14); // bit 2
        let ext = build_sack_extension(10, &ooo);
        assert!(!ext.is_empty());
        // Build a packet with that extension
        let pkt_bytes = build_packet_ext(TYPE_STATE, 1, 1, 10, 0, &ext, &[]);
        let parsed = parse_packet(&pkt_bytes);
        assert_eq!(parsed.ty, TYPE_STATE);
        assert_eq!(parsed.ack, 10);
        assert_eq!(parsed.sack.len(), 4);
        // bit 0 and bit 2 should be set
        assert_ne!(parsed.sack[0] & 0b0000_0001, 0); // seq 12
        assert_ne!(parsed.sack[0] & 0b0000_0100, 0); // seq 14
        assert_eq!(parsed.sack[0] & 0b0000_0010, 0); // seq 13 not present
    }

    #[test]
    fn sack_extension_empty_when_no_ooo() {
        let ooo = HashSet::new();
        let ext = build_sack_extension(10, &ooo);
        assert!(ext.is_empty());
    }

    #[test]
    fn ledbat_cwnd_increases_when_delay_below_target() {
        let (_tx, rx) = mpsc::channel();
        let (dtx, _drx) = mpsc::channel();
        let now = Instant::now();
        let mut conn = ConnState {
            addr: "127.0.0.1:1".parse().unwrap(),
            send_id: 1,
            recv_id: Some(2),
            seq: 1,
            recv_seq: 0,
            state: ConnStatus::Connected,
            inflight: VecDeque::new(),
            cwnd: 4,
            send_rx: rx,
            recv_tx: dtx,
            last_seen: now,
            connect_started: now,
            connect_resp: None,
            connect_stream: None,
            peer_timestamp: 0,
            timestamp_diff: 0,
            ooo_received: HashSet::new(),
            base_delay: Some(1000),         // 1ms base delay
            base_delay_updated: now,
            current_delay: 2000,            // 2ms current delay (well below 100ms target)
        };
        let old_cwnd = conn.cwnd;
        ledbat_update_cwnd(&mut conn, 4 * UTP_PAYLOAD_MAX);
        // With very low queuing delay the cwnd should not decrease
        assert!(conn.cwnd >= old_cwnd);
    }

    #[test]
    fn ledbat_cwnd_decreases_when_delay_above_target() {
        let (_tx, rx) = mpsc::channel();
        let (dtx, _drx) = mpsc::channel();
        let now = Instant::now();
        let mut conn = ConnState {
            addr: "127.0.0.1:1".parse().unwrap(),
            send_id: 1,
            recv_id: Some(2),
            seq: 1,
            recv_seq: 0,
            state: ConnStatus::Connected,
            inflight: VecDeque::new(),
            cwnd: 20,
            send_rx: rx,
            recv_tx: dtx,
            last_seen: now,
            connect_started: now,
            connect_resp: None,
            connect_stream: None,
            peer_timestamp: 0,
            timestamp_diff: 0,
            ooo_received: HashSet::new(),
            base_delay: Some(1000),
            base_delay_updated: now,
            current_delay: 500_000,         // 500ms current delay >> 100ms target
        };
        let old_cwnd = conn.cwnd;
        ledbat_update_cwnd(&mut conn, 20 * UTP_PAYLOAD_MAX);
        // With high queuing delay the cwnd should decrease
        assert!(conn.cwnd < old_cwnd);
    }
}

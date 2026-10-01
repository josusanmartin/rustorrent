use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

const UTP_VERSION: u8 = 1;
const UTP_HEADER_LEN: usize = 20;
const UTP_PAYLOAD_MAX: usize = 1200;
/// Largest payload accepted from a peer. We send at most UTP_PAYLOAD_MAX, but
/// libtorrent and others fill the path MTU (about 1450 bytes on Ethernet, and
/// much more on loopback).
const UTP_RECV_PAYLOAD_MAX: usize = 16 * 1024;
/// Room for the header and any extension headers in front of the payload.
const UTP_RECV_DATAGRAM_MAX: usize = UTP_RECV_PAYLOAD_MAX + 1024;
const UTP_ACK_TIMEOUT: Duration = Duration::from_millis(500);
const UTP_SYN_RETRY: Duration = Duration::from_secs(1);
const UTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const UTP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Idle connections exchange ST_STATE keepalives (as libutp does every 29
/// seconds) so neither side's idle timeout fires between application messages.
const UTP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(29);
const UTP_MAX_RETRANSMISSIONS: u8 = 8;
/// Socket poll interval while connections exist; bounds timer granularity.
const ACTIVE_POLL: Duration = Duration::from_millis(50);
/// Socket poll interval with no connections; commands wake the loop anyway.
const IDLE_POLL: Duration = Duration::from_secs(1);
const INITIAL_CWND: usize = 4;
const MAX_CWND: usize = 64;
const MAX_CONNECTIONS: usize = 1024;
const MAX_PENDING_ACCEPTS: usize = 128;
const MAX_PENDING_DHT_DATAGRAMS: usize = 1024;
const MAX_INBOUND_CONNECTIONS: usize = 256;
const MAX_INBOUND_CONNECTIONS_PER_IP: usize = 16;
const RECEIVE_BUFFER_BYTES: usize = 64 * 1024;
const RECEIVE_CHANNEL_CHUNKS: usize = 128;
const SEND_QUEUE_PACKETS: usize = 64;
const MAX_RECEIVE_OVERFLOW_STRIKES: u8 = 8;
const FAST_RETRANSMIT_DUP_ACKS: u8 = 3;

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
    waker: Arc<Waker>,
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

/// Wakes the socket loop out of `recv_from` by sending it an empty datagram
/// over loopback, so queued writes and commands are handled immediately
/// instead of after the next poll timeout.
struct Waker {
    socket: Option<UdpSocket>,
    target: SocketAddr,
}

impl Waker {
    fn new(socket: Option<&UdpSocket>) -> Self {
        let socket = socket.and_then(|socket| socket.try_clone().ok());
        let local = socket.as_ref().and_then(|socket| socket.local_addr().ok());
        let target = match local {
            Some(SocketAddr::V6(addr)) => SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port())),
            Some(addr) => SocketAddr::from((Ipv4Addr::LOCALHOST, addr.port())),
            None => SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        };
        Self { socket, target }
    }

    fn wake(&self) {
        if let Some(socket) = &self.socket {
            let _ = socket.send_to(&[], self.target);
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn start(port: u16) -> (UtpConnector, UtpListener) {
    let (connector, listener, _) = start_inner(port, false);
    (connector, listener)
}

/// uTP's UDP socket lent to the DHT: a clone for sending, and the DHT
/// datagrams the uTP loop receives on it.
#[cfg_attr(not(feature = "dht"), allow(dead_code))]
pub struct SharedUdp {
    pub socket: UdpSocket,
    pub rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
}

/// Starts uTP on `port` and hands DHT traffic arriving on the same socket to
/// the returned channel, so both protocols share one (forwarded) UDP port the
/// way other clients do. None when the socket could not be opened.
pub fn start_shared(port: u16) -> (UtpConnector, UtpListener, Option<SharedUdp>) {
    start_inner(port, true)
}

fn start_inner(port: u16, share: bool) -> (UtpConnector, UtpListener, Option<SharedUdp>) {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (accept_tx, accept_rx) = mpsc::sync_channel(MAX_PENDING_ACCEPTS);
    let socket = UdpSocket::bind(("0.0.0.0", port))
        .or_else(|_| UdpSocket::bind((Ipv6Addr::UNSPECIFIED, port)));
    let waker = Arc::new(Waker::new(socket.as_ref().ok()));
    let mut shared = None;
    if let Ok(socket) = socket {
        let mut dht_tx = None;
        if share {
            if let Ok(send) = socket.try_clone() {
                let (tx, rx) = mpsc::sync_channel(MAX_PENDING_DHT_DATAGRAMS);
                dht_tx = Some(tx);
                shared = Some(SharedUdp { socket: send, rx });
            }
        }
        let waker = Arc::clone(&waker);
        thread::spawn(move || utp_loop(socket, cmd_rx, accept_tx, waker, dht_tx));
    }
    (
        UtpConnector { cmd_tx, waker },
        UtpListener { accept_rx },
        shared,
    )
}

/// DHT messages are bencoded dictionaries, so they start with `d`. A uTP
/// header starts with (type << 4) | version 1, and no uTP type maps to `d`.
fn is_dht_datagram(packet: &[u8]) -> bool {
    packet.first() == Some(&b'd')
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
        self.waker.wake();
        resp_rx
            .recv()
            .map_err(|_| "utp connect failed".to_string())?
    }
}

impl UtpListener {
    /// Waits up to `timeout` for an inbound connection.
    pub fn accept_timeout(&self, timeout: Duration) -> Option<UtpStream> {
        self.accept_rx.recv_timeout(timeout).ok()
    }
}

pub struct UtpStream {
    addr: SocketAddr,
    queue: Arc<SendQueue>,
    recv_rx: mpsc::Receiver<Vec<u8>>,
    recv_budget: Arc<ReceiveBudget>,
    waker: Arc<Waker>,
    chunk: Vec<u8>,
    chunk_pos: usize,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

/// Payload waiting to be sent, shared between a stream and the socket loop.
struct SendQueue {
    state: Mutex<SendState>,
    space: Condvar,
}

#[derive(Default)]
struct SendState {
    packets: VecDeque<Vec<u8>>,
    /// The connection is gone; writes fail.
    closed: bool,
    /// The stream was dropped; the loop closes once queued data is acked.
    writer_gone: bool,
}

impl SendQueue {
    fn lock(&self) -> MutexGuard<'_, SendState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn close(&self) {
        self.lock().closed = true;
        self.space.notify_all();
    }
}

struct ReceiveBudget {
    bytes: AtomicUsize,
    channel_chunks: AtomicUsize,
    /// Set when a small window was advertised; the reader then wakes the
    /// loop after freeing space so the window update is sent promptly.
    window_update_wanted: AtomicBool,
}

/// `fetch_update` under another name. Rust 1.99 deprecates `fetch_update` for
/// `try_update`, which Rust 1.89 (the minimum) lacks; this is the same
/// compare-exchange loop.
fn update_usize(
    atomic: &AtomicUsize,
    set_order: Ordering,
    fetch_order: Ordering,
    mut f: impl FnMut(usize) -> Option<usize>,
) -> Result<usize, usize> {
    let mut prev = atomic.load(fetch_order);
    while let Some(next) = f(prev) {
        match atomic.compare_exchange_weak(prev, next, set_order, fetch_order) {
            Ok(value) => return Ok(value),
            Err(actual) => prev = actual,
        }
    }
    Err(prev)
}

impl ReceiveBudget {
    fn new() -> Self {
        Self {
            bytes: AtomicUsize::new(0),
            channel_chunks: AtomicUsize::new(0),
            window_update_wanted: AtomicBool::new(false),
        }
    }

    fn try_reserve_bytes(&self, amount: usize) -> bool {
        if amount == 0 || amount > RECEIVE_BUFFER_BYTES {
            return false;
        }
        update_usize(
            &self.bytes,
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| {
                current
                    .checked_add(amount)
                    .filter(|next| *next <= RECEIVE_BUFFER_BYTES)
            },
        )
        .is_ok()
    }

    fn release_bytes(&self, amount: usize) {
        let _ = update_usize(
            &self.bytes,
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| Some(current.saturating_sub(amount)),
        );
    }

    fn try_reserve_channel_chunk(&self) -> bool {
        update_usize(
            &self.channel_chunks,
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| (current < RECEIVE_CHANNEL_CHUNKS).then_some(current + 1),
        )
        .is_ok()
    }

    fn release_channel_chunk(&self) {
        let _ = update_usize(
            &self.channel_chunks,
            Ordering::AcqRel,
            Ordering::Acquire,
            |current| Some(current.saturating_sub(1)),
        );
    }

    fn remaining_window(&self) -> usize {
        if self.channel_chunks.load(Ordering::Acquire) >= RECEIVE_CHANNEL_CHUNKS {
            return 0;
        }
        RECEIVE_BUFFER_BYTES.saturating_sub(self.bytes.load(Ordering::Acquire))
    }
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

fn io_error(kind: std::io::ErrorKind, message: &'static str) -> std::io::Error {
    std::io::Error::new(kind, message)
}

impl Read for UtpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.chunk_pos >= self.chunk.len() {
            let received = match self.read_timeout {
                Some(timeout) => self.recv_rx.recv_timeout(timeout),
                None => self
                    .recv_rx
                    .recv()
                    .map_err(|_| mpsc::RecvTimeoutError::Disconnected),
            };
            match received {
                Ok(chunk) => {
                    self.recv_budget.release_channel_chunk();
                    self.chunk = chunk;
                    self.chunk_pos = 0;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    return Err(io_error(std::io::ErrorKind::WouldBlock, "utp read timeout"));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io_error(std::io::ErrorKind::UnexpectedEof, "utp closed"));
                }
            }
        }
        let n = buf.len().min(self.chunk.len() - self.chunk_pos);
        buf[..n].copy_from_slice(&self.chunk[self.chunk_pos..self.chunk_pos + n]);
        self.chunk_pos += n;
        self.recv_budget.release_bytes(n);
        if self
            .recv_budget
            .window_update_wanted
            .swap(false, Ordering::AcqRel)
        {
            self.waker.wake();
        }
        Ok(n)
    }
}

impl Drop for UtpStream {
    fn drop(&mut self) {
        self.recv_budget
            .release_bytes(self.chunk.len().saturating_sub(self.chunk_pos));
        while let Ok(chunk) = self.recv_rx.try_recv() {
            self.recv_budget.release_channel_chunk();
            self.recv_budget.release_bytes(chunk.len());
        }
        self.queue.lock().writer_gone = true;
        self.waker.wake();
    }
}

impl Write for UtpStream {
    /// Queues up to one send window of data for the socket loop and returns
    /// without waiting for acknowledgement; waits (up to the write timeout)
    /// only while the queue is full.
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = self.write_timeout.map(|timeout| Instant::now() + timeout);
        let mut state = self.queue.lock();
        loop {
            if state.closed {
                return Err(io_error(std::io::ErrorKind::BrokenPipe, "utp closed"));
            }
            if state.packets.len() < SEND_QUEUE_PACKETS
                || state
                    .packets
                    .back()
                    .is_some_and(|last| last.len() < UTP_PAYLOAD_MAX)
            {
                break;
            }
            state = match deadline {
                None => self
                    .queue
                    .space
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(io_error(
                            std::io::ErrorKind::WouldBlock,
                            "utp write timeout",
                        ));
                    }
                    self.queue
                        .space
                        .wait_timeout(state, remaining)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
        let was_empty = state.packets.is_empty();
        let mut rest = buf;
        // Coalesce small writes into the last unsent packet.
        if let Some(last) = state.packets.back_mut() {
            let take = (UTP_PAYLOAD_MAX - last.len()).min(rest.len());
            last.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
        while !rest.is_empty() && state.packets.len() < SEND_QUEUE_PACKETS {
            let take = rest.len().min(UTP_PAYLOAD_MAX);
            state.packets.push_back(rest[..take].to_vec());
            rest = &rest[take..];
        }
        drop(state);
        if was_empty {
            self.waker.wake();
        }
        Ok(buf.len() - rest.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ConnStatus {
    SynSent,
    Connected,
    Closed,
}

struct PendingPacket {
    seq: u16,
    data: Vec<u8>,
    sent_at: Instant,
    retransmissions: u8,
}

/// Connection state, following BEP 29's conventions: `seq` is the sequence
/// number of the next packet to send (ST_STATE carries it unchanged) and
/// `recv_seq` is the last in-order sequence number received (our ack_nr).
struct ConnState {
    addr: SocketAddr,
    inbound: bool,
    send_id: u16,
    seq: u16,
    recv_seq: u16,
    state: ConnStatus,
    inflight: VecDeque<PendingPacket>,
    inflight_bytes: usize,
    /// Congestion window in bytes.
    cwnd: usize,
    peer_window: usize,
    queue: Arc<SendQueue>,
    recv_tx: mpsc::SyncSender<Vec<u8>>,
    recv_budget: Arc<ReceiveBudget>,
    last_advertised_window: usize,
    receive_overflow_strikes: u8,
    last_seen: Instant,
    last_sent: Instant,
    connect_started: Instant,
    syn_sent_at: Instant,
    connect_resp: Option<mpsc::Sender<Result<UtpStream, String>>>,
    connect_stream: Option<UtpStream>,
    // Timestamp diff tracking (BEP 29)
    timestamp_diff: u32,
    // Out-of-order received packets for SACK
    ooo_received: HashMap<u16, Vec<u8>>,
    /// Sequence number of a received FIN; the stream ends once every packet
    /// before it has been delivered.
    eof_seq: Option<u16>,
    last_ack: u16,
    dup_acks: u8,
    // LEDBAT delay-based congestion state
    base_delay: Option<u32>,
    base_delay_updated: Instant,
    current_delay: u32,
}

impl ConnState {
    fn new(
        addr: SocketAddr,
        inbound: bool,
        send_id: u16,
        seq: u16,
        recv_seq: u16,
        state: ConnStatus,
        waker: &Arc<Waker>,
    ) -> (Self, UtpStream) {
        let queue = Arc::new(SendQueue {
            state: Mutex::new(SendState::default()),
            space: Condvar::new(),
        });
        let (recv_tx, recv_rx) = mpsc::sync_channel(RECEIVE_CHANNEL_CHUNKS);
        let recv_budget = Arc::new(ReceiveBudget::new());
        let stream = UtpStream {
            addr,
            queue: Arc::clone(&queue),
            recv_rx,
            recv_budget: Arc::clone(&recv_budget),
            waker: Arc::clone(waker),
            chunk: Vec::new(),
            chunk_pos: 0,
            read_timeout: None,
            write_timeout: None,
        };
        let now = Instant::now();
        let conn = Self {
            addr,
            inbound,
            send_id,
            seq,
            recv_seq,
            state,
            inflight: VecDeque::new(),
            inflight_bytes: 0,
            cwnd: INITIAL_CWND * UTP_PAYLOAD_MAX,
            peer_window: RECEIVE_BUFFER_BYTES,
            queue,
            recv_tx,
            recv_budget,
            last_advertised_window: RECEIVE_BUFFER_BYTES,
            receive_overflow_strikes: 0,
            last_seen: now,
            last_sent: now,
            connect_started: now,
            syn_sent_at: now,
            connect_resp: None,
            connect_stream: None,
            timestamp_diff: 0,
            ooo_received: HashMap::new(),
            eof_seq: None,
            last_ack: seq.wrapping_sub(1),
            dup_acks: 0,
            base_delay: None,
            base_delay_updated: now,
            current_delay: 0,
        };
        (conn, stream)
    }

    /// Header for an outgoing packet, advertising the current receive window.
    fn header(&mut self, ty: u8, seq: u16) -> Header {
        self.last_sent = Instant::now();
        let window = self.recv_budget.remaining_window();
        self.last_advertised_window = window;
        if window < 2 * UTP_PAYLOAD_MAX {
            self.recv_budget
                .window_update_wanted
                .store(true, Ordering::Release);
        }
        Header {
            ty,
            conn_id: self.send_id,
            ts_diff: self.timestamp_diff,
            window,
            seq,
            ack: self.recv_seq,
        }
    }

    fn send(&mut self, io: &mut Io<'_>, ty: u8, seq: u16, payload: &[u8]) {
        let header = self.header(ty, seq);
        io.send(self.addr, &header, &[], payload);
    }

    /// Acknowledges everything received in order, with a SACK bitmask for
    /// buffered out-of-order packets.
    fn send_state(&mut self, io: &mut Io<'_>) {
        let header = self.header(TYPE_STATE, self.seq);
        let sack = build_sack(self.recv_seq, &self.ooo_received);
        let sack: &[u8] = match &sack {
            Some(mask) => mask,
            None => &[],
        };
        io.send(self.addr, &header, sack, &[]);
    }

    fn fail(&mut self, msg: &str) {
        self.state = ConnStatus::Closed;
        self.inflight.clear();
        self.inflight_bytes = 0;
        if let Some(resp) = self.connect_resp.take() {
            let _ = resp.send(Err(msg.to_string()));
        }
        self.connect_stream = None;
        self.queue.close();
    }
}

struct Header {
    ty: u8,
    conn_id: u16,
    ts_diff: u32,
    window: usize,
    seq: u16,
    ack: u16,
}

/// The loop's socket plus a reused packet buffer.
struct Io<'a> {
    socket: &'a UdpSocket,
    buf: Vec<u8>,
}

impl Io<'_> {
    fn send(&mut self, addr: SocketAddr, header: &Header, sack: &[u8], payload: &[u8]) {
        encode_packet(&mut self.buf, header, sack, payload);
        let _ = self.socket.send_to(&self.buf, addr);
    }
}

#[derive(Default)]
struct SynLimiter {
    total: usize,
    by_ip: HashMap<IpAddr, usize>,
}

impl SynLimiter {
    fn normalized_ip(addr: SocketAddr) -> IpAddr {
        normalize_ip(addr.ip())
    }

    fn allows(&self, addr: SocketAddr) -> bool {
        self.total < MAX_INBOUND_CONNECTIONS
            && self
                .by_ip
                .get(&Self::normalized_ip(addr))
                .copied()
                .unwrap_or(0)
                < MAX_INBOUND_CONNECTIONS_PER_IP
    }

    fn opened(&mut self, addr: SocketAddr) {
        self.total = self.total.saturating_add(1);
        *self.by_ip.entry(Self::normalized_ip(addr)).or_default() += 1;
    }

    fn closed(&mut self, addr: SocketAddr) {
        self.total = self.total.saturating_sub(1);
        let ip = Self::normalized_ip(addr);
        if let Some(count) = self.by_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.by_ip.remove(&ip);
            }
        }
    }
}

type ConnKey = (SocketAddr, u16);

struct Loop<'a> {
    io: Io<'a>,
    conns: HashMap<ConnKey, ConnState>,
    syn_limiter: SynLimiter,
    accept_tx: mpsc::SyncSender<UtpStream>,
    waker: Arc<Waker>,
}

fn utp_loop(
    socket: UdpSocket,
    cmd_rx: mpsc::Receiver<Command>,
    accept_tx: mpsc::SyncSender<UtpStream>,
    waker: Arc<Waker>,
    dht_tx: Option<mpsc::SyncSender<(Vec<u8>, SocketAddr)>>,
) {
    let mut state = Loop {
        io: Io {
            socket: &socket,
            buf: Vec::with_capacity(UTP_HEADER_LEN + 6 + UTP_PAYLOAD_MAX),
        },
        conns: HashMap::new(),
        syn_limiter: SynLimiter::default(),
        accept_tx,
        waker,
    };
    let mut buf = vec![0u8; UTP_RECV_DATAGRAM_MAX];
    let mut poll = None;
    let mut last_scan = Instant::now();
    let mut scan_due = false;
    loop {
        while let Ok(Command::Connect { addr, resp }) = cmd_rx.try_recv() {
            state.connect(addr, resp);
        }
        if scan_due || last_scan.elapsed() >= ACTIVE_POLL {
            state.scan();
            last_scan = Instant::now();
            scan_due = false;
        }
        let wanted = Some(if state.conns.is_empty() {
            IDLE_POLL
        } else {
            ACTIVE_POLL
        });
        if poll != wanted && socket.set_read_timeout(wanted).is_ok() {
            poll = wanted;
        }
        match socket.recv_from(&mut buf) {
            Ok((0, from)) if normalize_ip(from.ip()).is_loopback() => scan_due = true,
            Ok((n, from)) if dht_tx.is_some() && is_dht_datagram(&buf[..n]) => {
                // A full queue means the DHT is behind; dropping a UDP
                // datagram is what the network would do anyway.
                if let Some(tx) = &dht_tx {
                    let _ = tx.try_send((buf[..n].to_vec(), from));
                }
            }
            Ok((n, from)) => state.handle_datagram(&buf[..n], from),
            Err(_) => scan_due = true,
        }
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        ip => ip,
    }
}

impl Loop<'_> {
    fn connect(&mut self, addr: SocketAddr, resp: mpsc::Sender<Result<UtpStream, String>>) {
        if self.conns.len() >= MAX_CONNECTIONS {
            let _ = resp.send(Err("utp connection limit reached".to_string()));
            return;
        }
        // BEP 29: the initiator receives on a random ID and sends on ID + 1;
        // the SYN carries the receive ID.
        let mut recv_id = next_u16();
        for _ in 0..u16::MAX {
            if !self.conns.contains_key(&(addr, recv_id)) {
                break;
            }
            recv_id = next_u16();
        }
        let syn_seq = next_u16();
        let (mut conn, stream) = ConnState::new(
            addr,
            false,
            recv_id.wrapping_add(1),
            syn_seq.wrapping_add(1),
            0,
            ConnStatus::SynSent,
            &self.waker,
        );
        conn.connect_resp = Some(resp);
        conn.connect_stream = Some(stream);
        send_syn(&mut conn, &mut self.io);
        self.conns.insert((addr, recv_id), conn);
    }

    /// Periodic work for every connection: timeouts, retransmissions,
    /// deferred delivery, window updates and draining send queues.
    fn scan(&mut self) {
        let now = Instant::now();
        for conn in self.conns.values_mut() {
            service_timers(conn, &mut self.io, now);
            if conn.state == ConnStatus::Connected {
                fill_send_window(conn, &mut self.io);
            }
        }
        let limiter = &mut self.syn_limiter;
        self.conns.retain(|_, conn| {
            if conn.state != ConnStatus::Closed {
                return true;
            }
            discard_connection(conn, limiter);
            false
        });
    }

    fn handle_datagram(&mut self, data: &[u8], addr: SocketAddr) {
        let Some(pkt) = parse_packet(data) else {
            return;
        };
        if pkt.ty == TYPE_SYN {
            self.handle_syn(&pkt, addr);
            return;
        }
        let key = if pkt.ty == TYPE_RESET {
            // A reset may name either of our connection IDs.
            [
                pkt.conn_id,
                pkt.conn_id.wrapping_add(1),
                pkt.conn_id.wrapping_sub(1),
            ]
            .into_iter()
            .map(|id| (addr, id))
            .find(|key| {
                self.conns
                    .get(key)
                    .is_some_and(|conn| key.1 == pkt.conn_id || conn.send_id == pkt.conn_id)
            })
        } else {
            Some((addr, pkt.conn_id))
        };
        let Some(key) = key else {
            return;
        };
        let Some(conn) = self.conns.get_mut(&key) else {
            return;
        };
        handle_packet(conn, &mut self.io, &pkt);
        if conn.state == ConnStatus::Connected {
            fill_send_window(conn, &mut self.io);
        }
        if conn.state == ConnStatus::Closed {
            if let Some(mut conn) = self.conns.remove(&key) {
                discard_connection(&mut conn, &mut self.syn_limiter);
            }
        }
    }

    fn handle_syn(&mut self, pkt: &ParsedPacket<'_>, addr: SocketAddr) {
        // BEP 29: the responder sends on the SYN's ID and receives on ID + 1.
        let send_id = pkt.conn_id;
        let recv_id = send_id.wrapping_add(1);
        let reset = Header {
            ty: TYPE_RESET,
            conn_id: send_id,
            ts_diff: 0,
            window: 0,
            seq: 0,
            ack: pkt.seq,
        };
        if !pkt.payload.is_empty() {
            self.io.send(addr, &reset, &[], &[]);
            return;
        }
        if let Some(existing) = self.conns.get_mut(&(addr, recv_id)) {
            // A retransmitted SYN: repeat the acknowledgement.
            if existing.inbound && existing.send_id == send_id {
                existing.send_state(&mut self.io);
            }
            return;
        }
        if self.conns.len() >= MAX_CONNECTIONS || !self.syn_limiter.allows(addr) {
            self.io.send(addr, &reset, &[], &[]);
            return;
        }
        let (mut conn, stream) = ConnState::new(
            addr,
            true,
            send_id,
            next_u16(),
            pkt.seq,
            ConnStatus::Connected,
            &self.waker,
        );
        conn.peer_window = pkt.window_size;
        conn.timestamp_diff = timestamp().wrapping_sub(pkt.timestamp);
        if self.accept_tx.try_send(stream).is_ok() {
            conn.send_state(&mut self.io);
            self.conns.insert((addr, recv_id), conn);
            self.syn_limiter.opened(addr);
        } else {
            self.io.send(addr, &reset, &[], &[]);
        }
    }
}

fn send_syn(conn: &mut ConnState, io: &mut Io<'_>) {
    let mut header = conn.header(TYPE_SYN, conn.seq.wrapping_sub(1));
    header.conn_id = conn.send_id.wrapping_sub(1);
    header.ack = 0;
    io.send(conn.addr, &header, &[], &[]);
    conn.syn_sent_at = Instant::now();
}

fn discard_connection(conn: &mut ConnState, limiter: &mut SynLimiter) {
    discard_receive_buffers(conn);
    conn.queue.close();
    if conn.inbound {
        limiter.closed(conn.addr);
    }
}

fn service_timers(conn: &mut ConnState, io: &mut Io<'_>, now: Instant) {
    match conn.state {
        ConnStatus::Closed => return,
        ConnStatus::SynSent => {
            if now.duration_since(conn.connect_started) >= UTP_CONNECT_TIMEOUT {
                conn.fail("utp connect timeout");
            } else if now.duration_since(conn.syn_sent_at) >= UTP_SYN_RETRY {
                send_syn(conn, io);
            }
            return;
        }
        ConnStatus::Connected => {}
    }
    if now.duration_since(conn.last_seen) >= UTP_IDLE_TIMEOUT {
        conn.fail("utp idle timeout");
        return;
    }

    // Deliver in-order data that was waiting for room in the receive channel.
    let advanced = drain_contiguous_received(conn);
    if conn.state == ConnStatus::Closed {
        conn.fail("utp receive stream closed");
        return;
    }
    let receive_window = conn.recv_budget.remaining_window();
    let window_reopened = receive_window > conn.last_advertised_window
        && (conn.last_advertised_window == 0
            || receive_window - conn.last_advertised_window >= UTP_PAYLOAD_MAX
            || receive_window == RECEIVE_BUFFER_BYTES);
    if advanced || window_reopened || now.duration_since(conn.last_sent) >= UTP_KEEPALIVE_INTERVAL {
        conn.send_state(io);
    }
    if conn.eof_seq.is_some_and(|eof| eof == conn.recv_seq) {
        conn.fail("utp closed");
        return;
    }

    // Retransmit timed-out packets and halve cwnd (timeout fallback).
    let mut header = conn.header(TYPE_DATA, 0);
    let mut timed_out = false;
    for pending in &mut conn.inflight {
        if now.duration_since(pending.sent_at) < UTP_ACK_TIMEOUT {
            continue;
        }
        if pending.retransmissions >= UTP_MAX_RETRANSMISSIONS {
            conn.state = ConnStatus::Closed;
            break;
        }
        header.seq = pending.seq;
        io.send(conn.addr, &header, &[], &pending.data);
        pending.sent_at = now;
        pending.retransmissions += 1;
        timed_out = true;
    }
    if conn.state == ConnStatus::Closed {
        conn.fail("utp acknowledgement timeout");
        return;
    }
    if timed_out {
        conn.cwnd = (conn.cwnd / 2).max(UTP_PAYLOAD_MAX);
    }
}

/// Moves queued payload into flight while the congestion and receive
/// windows allow; closes with FIN once a dropped stream's data is acked.
fn fill_send_window(conn: &mut ConnState, io: &mut Io<'_>) {
    let queue = Arc::clone(&conn.queue);
    let mut state = queue.lock();
    let mut sent_any = false;
    // Never put more unacknowledged bytes in flight than the peer's advertised
    // receive window: overshooting it gets packets dropped at the receiver.
    let limit = conn.cwnd.min(conn.peer_window);
    while state
        .packets
        .front()
        .is_some_and(|next| conn.inflight_bytes + next.len() <= limit)
    {
        let Some(data) = state.packets.pop_front() else {
            break;
        };
        let seq = conn.seq;
        conn.seq = seq.wrapping_add(1);
        conn.send(io, TYPE_DATA, seq, &data);
        conn.inflight_bytes = conn.inflight_bytes.saturating_add(data.len());
        conn.inflight.push_back(PendingPacket {
            seq,
            data,
            sent_at: Instant::now(),
            retransmissions: 0,
        });
        sent_any = true;
    }
    let finished = state.writer_gone && state.packets.is_empty() && conn.inflight.is_empty();
    drop(state);
    if sent_any {
        queue.space.notify_all();
    }
    if finished {
        let seq = conn.seq;
        conn.seq = seq.wrapping_add(1);
        conn.send(io, TYPE_FIN, seq, &[]);
        conn.fail("utp stream dropped");
    }
}

fn handle_packet(conn: &mut ConnState, io: &mut Io<'_>, pkt: &ParsedPacket<'_>) {
    conn.last_seen = Instant::now();
    conn.peer_window = pkt.window_size;
    conn.timestamp_diff = timestamp().wrapping_sub(pkt.timestamp);
    if pkt.timestamp_diff != 0 {
        conn.current_delay = pkt.timestamp_diff;
    }

    if conn.state == ConnStatus::SynSent {
        match pkt.ty {
            // The SYN-ACK (or a first data packet if it was lost) acks our
            // SYN; its sequence number is the peer's next one to send.
            TYPE_STATE | TYPE_DATA if pkt.ack == conn.seq.wrapping_sub(1) => {
                conn.state = ConnStatus::Connected;
                conn.recv_seq = pkt.seq.wrapping_sub(1);
                conn.last_ack = pkt.ack;
                if let Some(resp) = conn.connect_resp.take() {
                    if let Some(stream) = conn.connect_stream.take() {
                        let _ = resp.send(Ok(stream));
                    }
                }
            }
            TYPE_RESET | TYPE_FIN => {
                conn.fail("utp connection refused");
                return;
            }
            _ => return,
        }
    }

    match pkt.ty {
        TYPE_STATE => process_ack(conn, io, pkt, true),
        TYPE_DATA => {
            process_ack(conn, io, pkt, false);
            match handle_data_packet(conn, pkt.seq, pkt.payload) {
                DataPacketOutcome::State => {
                    // The cumulative ACK remains at the last payload actually
                    // admitted to the bounded receive path.
                    conn.send_state(io);
                    if conn.eof_seq.is_some_and(|eof| eof == conn.recv_seq) {
                        conn.fail("utp closed");
                    }
                }
                DataPacketOutcome::Reset => {
                    let mut header = conn.header(TYPE_RESET, conn.seq);
                    header.window = 0;
                    io.send(conn.addr, &header, &[], &[]);
                    conn.fail("utp receive budget exceeded");
                }
            }
        }
        TYPE_FIN => {
            process_ack(conn, io, pkt, false);
            // The FIN occupies a sequence number; the stream ends once all
            // earlier packets have arrived (they may still be reordered).
            conn.eof_seq = Some(pkt.seq);
            if pkt.seq == conn.recv_seq.wrapping_add(1) {
                conn.recv_seq = pkt.seq;
            }
            conn.send_state(io);
            if conn.recv_seq == pkt.seq {
                conn.fail("utp closed");
            }
        }
        TYPE_RESET => conn.fail("utp reset"),
        _ => {}
    }
}

/// Applies a (possibly piggybacked) cumulative ACK and SACK bitmask.
fn process_ack(conn: &mut ConnState, io: &mut Io<'_>, pkt: &ParsedPacket<'_>, is_state: bool) {
    let ack = pkt.ack;
    // Ignore acknowledgements for sequence numbers we have not sent.
    if !is_seq_before_or_equal(ack, conn.seq.wrapping_sub(1)) {
        return;
    }
    let mut bytes_acked = 0usize;
    while conn
        .inflight
        .front()
        .is_some_and(|front| is_seq_before_or_equal(front.seq, ack))
    {
        if let Some(packet) = conn.inflight.pop_front() {
            bytes_acked += packet.data.len();
        }
    }
    if !pkt.sack.is_empty() {
        // Bit i of the mask (least significant bit first) acks ack + 2 + i.
        let base = ack.wrapping_add(2);
        let sack = pkt.sack;
        conn.inflight.retain(|packet| {
            let bit = usize::from(packet.seq.wrapping_sub(base));
            let acked = bit < sack.len() * 8 && sack[bit / 8] & (1 << (bit % 8)) != 0;
            if acked {
                bytes_acked += packet.data.len();
            }
            !acked
        });
    }
    conn.inflight_bytes = conn.inflight_bytes.saturating_sub(bytes_acked);
    if bytes_acked > 0 {
        conn.dup_acks = 0;
        ledbat_update_cwnd(conn, bytes_acked);
    } else if is_state && ack == conn.last_ack && !conn.inflight.is_empty() {
        conn.dup_acks = conn.dup_acks.saturating_add(1);
        if conn.dup_acks == FAST_RETRANSMIT_DUP_ACKS {
            // Fast retransmit the first unacknowledged packet.
            let header = conn.header(TYPE_DATA, 0);
            if let Some(front) = conn.inflight.front_mut() {
                io.send(
                    conn.addr,
                    &Header {
                        seq: front.seq,
                        ..header
                    },
                    &[],
                    &front.data,
                );
                front.sent_at = Instant::now();
            }
            conn.cwnd = (conn.cwnd / 2).max(UTP_PAYLOAD_MAX);
        }
    }
    conn.last_ack = ack;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataPacketOutcome {
    State,
    Reset,
}

enum DeliveryResult {
    Delivered,
    Full(Vec<u8>),
    Closed,
}

fn deliver_reserved_payload(conn: &mut ConnState, data: Vec<u8>) -> DeliveryResult {
    if !conn.recv_budget.try_reserve_channel_chunk() {
        return DeliveryResult::Full(data);
    }
    match conn.recv_tx.try_send(data) {
        Ok(()) => DeliveryResult::Delivered,
        Err(mpsc::TrySendError::Full(data)) => {
            conn.recv_budget.release_channel_chunk();
            DeliveryResult::Full(data)
        }
        Err(mpsc::TrySendError::Disconnected(data)) => {
            conn.recv_budget.release_channel_chunk();
            conn.recv_budget.release_bytes(data.len());
            DeliveryResult::Closed
        }
    }
}

fn drain_contiguous_received(conn: &mut ConnState) -> bool {
    let mut advanced = false;
    loop {
        let next = conn.recv_seq.wrapping_add(1);
        if conn.eof_seq == Some(next) {
            // Everything before the FIN has been delivered.
            conn.recv_seq = next;
            return true;
        }
        let Some(data) = conn.ooo_received.remove(&next) else {
            break;
        };
        match deliver_reserved_payload(conn, data) {
            DeliveryResult::Delivered => {
                conn.recv_seq = next;
                advanced = true;
            }
            DeliveryResult::Full(data) => {
                conn.ooo_received.insert(next, data);
                break;
            }
            DeliveryResult::Closed => {
                conn.state = ConnStatus::Closed;
                break;
            }
        }
    }
    advanced
}

fn receive_overflow(conn: &mut ConnState) -> DataPacketOutcome {
    conn.receive_overflow_strikes = conn.receive_overflow_strikes.saturating_add(1);
    if conn.receive_overflow_strikes >= MAX_RECEIVE_OVERFLOW_STRIKES {
        conn.state = ConnStatus::Closed;
        DataPacketOutcome::Reset
    } else {
        DataPacketOutcome::State
    }
}

fn handle_data_packet(conn: &mut ConnState, seq: u16, payload: &[u8]) -> DataPacketOutcome {
    if payload.is_empty() || payload.len() > UTP_RECV_PAYLOAD_MAX {
        conn.state = ConnStatus::Closed;
        return DataPacketOutcome::Reset;
    }

    drain_contiguous_received(conn);
    if conn.state == ConnStatus::Closed {
        return DataPacketOutcome::Reset;
    }
    if seq == conn.recv_seq {
        return DataPacketOutcome::State;
    }

    let expected = conn.recv_seq.wrapping_add(1);
    let offset = seq.wrapping_sub(expected);
    if offset > 32
        || conn
            .eof_seq
            .is_some_and(|eof| !is_seq_before_or_equal(seq, eof))
    {
        // Old duplicates and packets outside the SACK window are ignored.
        return if conn.recv_budget.remaining_window() == 0 {
            receive_overflow(conn)
        } else {
            DataPacketOutcome::State
        };
    }
    if conn.ooo_received.contains_key(&seq) {
        return if conn.recv_budget.remaining_window() == 0 {
            receive_overflow(conn)
        } else {
            DataPacketOutcome::State
        };
    }
    if conn.recv_budget.remaining_window() == 0 {
        return receive_overflow(conn);
    }
    if !conn.recv_budget.try_reserve_bytes(payload.len()) {
        return receive_overflow(conn);
    }
    conn.ooo_received.insert(seq, payload.to_vec());
    conn.receive_overflow_strikes = 0;
    if seq == expected {
        drain_contiguous_received(conn);
        if conn.state == ConnStatus::Closed {
            return DataPacketOutcome::Reset;
        }
    }
    DataPacketOutcome::State
}

fn discard_receive_buffers(conn: &mut ConnState) {
    let bytes = conn.ooo_received.drain().map(|(_, data)| data.len()).sum();
    conn.recv_budget.release_bytes(bytes);
}

fn is_seq_before_or_equal(seq: u16, ack: u16) -> bool {
    // Handle wrapping: seq is before or equal to ack if the difference is small
    let diff = ack.wrapping_sub(seq);
    diff < 0x8000
}

fn encode_packet(out: &mut Vec<u8>, header: &Header, sack: &[u8], payload: &[u8]) {
    out.clear();
    out.push((header.ty << 4) | UTP_VERSION);
    // next-extension byte: 0 = no extensions, 1 = SACK follows
    out.push(if sack.is_empty() { 0 } else { EXT_SACK });
    out.extend_from_slice(&header.conn_id.to_be_bytes());
    out.extend_from_slice(&timestamp().to_be_bytes());
    out.extend_from_slice(&header.ts_diff.to_be_bytes());
    out.extend_from_slice(&(header.window.min(u32::MAX as usize) as u32).to_be_bytes());
    out.extend_from_slice(&header.seq.to_be_bytes());
    out.extend_from_slice(&header.ack.to_be_bytes());
    if !sack.is_empty() {
        out.extend_from_slice(&[0, sack.len() as u8]);
        out.extend_from_slice(sack);
    }
    out.extend_from_slice(payload);
}

struct ParsedPacket<'a> {
    ty: u8,
    conn_id: u16,
    timestamp: u32,
    timestamp_diff: u32,
    window_size: usize,
    seq: u16,
    ack: u16,
    sack: &'a [u8],
    payload: &'a [u8],
}

fn parse_packet(data: &[u8]) -> Option<ParsedPacket<'_>> {
    if data.len() < UTP_HEADER_LEN || data[0] & 0x0f != UTP_VERSION || data[0] >> 4 > TYPE_SYN {
        return None;
    }
    let be16 = |at: usize| u16::from_be_bytes([data[at], data[at + 1]]);
    let be32 = |at: usize| u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);

    // Walk extensions chain starting after the 20-byte header
    let mut sack: &[u8] = &[];
    let mut offset = UTP_HEADER_LEN;
    let mut ext = data[1];
    while ext != 0 {
        let next = *data.get(offset)?;
        let len = usize::from(*data.get(offset + 1)?);
        let body = data.get(offset + 2..offset + 2 + len)?;
        if ext == EXT_SACK {
            if len == 0 || !len.is_multiple_of(4) {
                return None;
            }
            sack = body;
        }
        offset += 2 + len;
        ext = next;
    }

    Some(ParsedPacket {
        ty: data[0] >> 4,
        conn_id: be16(2),
        timestamp: be32(4),
        timestamp_diff: be32(8),
        window_size: be32(12) as usize,
        seq: be16(16),
        ack: be16(18),
        sack,
        payload: &data[offset..],
    })
}

/// SACK bitmask for out-of-order packets: bit i (least significant bit
/// first) of the 32-bit mask marks ack_nr + 2 + i as received.
fn build_sack(ack_nr: u16, ooo: &HashMap<u16, Vec<u8>>) -> Option<[u8; 4]> {
    if ooo.is_empty() {
        return None;
    }
    let mut mask = [0u8; 4];
    for &seq in ooo.keys() {
        let bit = usize::from(seq.wrapping_sub(ack_nr.wrapping_add(2)));
        if bit < 32 {
            mask[bit / 8] |= 1 << (bit % 8);
        }
    }
    Some(mask)
}

/// Update the LEDBAT congestion window (in bytes) from the delay measurement:
/// cwnd += MAX_CWND_INCREASE * off_target / TARGET * bytes_acked / cwnd.
/// Working in bytes matters: per-packet rounding would truncate every
/// single-packet ACK's increase to zero and pin the window at its start.
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
    let queuing_delay = i64::from(conn.current_delay.wrapping_sub(base).min(i32::MAX as u32));
    let off_target = LEDBAT_TARGET_DELAY_US - queuing_delay;
    let cwnd = conn.cwnd.max(UTP_PAYLOAD_MAX) as i64;
    let delta = off_target * MAX_CWND_INCREASE / LEDBAT_TARGET_DELAY_US * bytes_acked as i64 / cwnd;
    conn.cwnd =
        (cwnd + delta).clamp(UTP_PAYLOAD_MAX as i64, (MAX_CWND * UTP_PAYLOAD_MAX) as i64) as usize;
}

fn timestamp() -> u32 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_micros() as u32
}

fn next_u16() -> u16 {
    use std::sync::atomic::AtomicU32;
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    static SEED: AtomicU32 = AtomicU32::new(0x1234_5678);
    INIT.get_or_init(|| {
        SEED.store(crate::system_entropy_u64() as u32 | 1, Ordering::Relaxed);
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

    fn test_waker() -> Arc<Waker> {
        Arc::new(Waker::new(None))
    }

    fn receive_test_conn(recv_seq: u16) -> (ConnState, UtpStream) {
        ConnState::new(
            "127.0.0.1:1".parse().unwrap(),
            true,
            1,
            10,
            recv_seq,
            ConnStatus::Connected,
            &test_waker(),
        )
    }

    fn header(ty: u8, conn_id: u16, seq: u16, ack: u16) -> Header {
        Header {
            ty,
            conn_id,
            ts_diff: 0,
            window: RECEIVE_BUFFER_BYTES,
            seq,
            ack,
        }
    }

    fn packet(ty: u8, conn_id: u16, seq: u16, ack: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_packet(&mut out, &header(ty, conn_id, seq, ack), &[], payload);
        out
    }

    fn free_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn accept_within(listener: &UtpListener, timeout: Duration) -> UtpStream {
        listener
            .accept_timeout(timeout)
            .expect("timed out waiting for utp accept")
    }

    fn recv_packet(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = socket.recv_from(&mut buf).unwrap();
            if n >= UTP_HEADER_LEN {
                return (buf[..n].to_vec(), from);
            }
        }
    }

    /// Skips acknowledgements and window updates.
    fn recv_data_packet(socket: &UdpSocket) -> Vec<u8> {
        loop {
            let (bytes, _) = recv_packet(socket);
            if bytes[0] >> 4 == TYPE_DATA {
                return bytes;
            }
        }
    }

    #[test]
    fn packet_roundtrip_preserves_fields() {
        let payload = b"hello-utp";
        let bytes = packet(TYPE_DATA, 42, 100, 99, payload);
        assert_eq!(bytes.len(), UTP_HEADER_LEN + payload.len());

        let pkt = parse_packet(&bytes).unwrap();
        assert_eq!(pkt.ty, TYPE_DATA);
        assert_eq!(pkt.conn_id, 42);
        assert_eq!(pkt.seq, 100);
        assert_eq!(pkt.ack, 99);
        assert_eq!(pkt.payload, payload);
        assert_eq!(pkt.window_size, RECEIVE_BUFFER_BYTES);
    }

    #[test]
    fn packet_advertises_the_supplied_receive_window_and_timestamp_diff() {
        let mut bytes = Vec::new();
        let mut state = header(TYPE_STATE, 7, 4, 3);
        state.window = 1234;
        state.ts_diff = 12345;
        encode_packet(&mut bytes, &state, &[], &[]);
        let parsed = parse_packet(&bytes).unwrap();
        assert_eq!(parsed.window_size, 1234);
        assert_eq!(parsed.timestamp_diff, 12345);
        assert!(parsed.sack.is_empty());
    }

    #[test]
    fn packet_parser_rejects_bad_version_and_truncated_extensions() {
        let mut bad_version = packet(TYPE_DATA, 1, 1, 0, b"x");
        bad_version[0] = TYPE_DATA << 4;
        assert!(parse_packet(&bad_version).is_none());

        let mut truncated = packet(TYPE_DATA, 1, 1, 0, b"");
        truncated[1] = EXT_SACK;
        truncated.extend_from_slice(&[0, 4, 1, 2]);
        assert!(parse_packet(&truncated).is_none());

        let mut dangling = packet(TYPE_STATE, 1, 1, 0, b"");
        dangling[1] = 7;
        assert!(parse_packet(&dangling).is_none());
        dangling.push(0);
        assert!(parse_packet(&dangling).is_none());
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
    fn receive_flood_is_byte_bounded_and_never_acks_over_budget_data() {
        let (mut conn, _stream) = receive_test_conn(100);
        let mut seq = 101u16;
        for _ in 0..(RECEIVE_BUFFER_BYTES / UTP_PAYLOAD_MAX) {
            assert_eq!(
                handle_data_packet(&mut conn, seq, &[7; UTP_PAYLOAD_MAX]),
                DataPacketOutcome::State
            );
            assert_eq!(conn.recv_seq, seq);
            seq = seq.wrapping_add(1);
        }
        let tail = RECEIVE_BUFFER_BYTES % UTP_PAYLOAD_MAX;
        assert!(tail > 0);
        assert_eq!(
            handle_data_packet(&mut conn, seq, &vec![8; tail]),
            DataPacketOutcome::State
        );
        assert_eq!(conn.recv_seq, seq);
        assert_eq!(conn.recv_budget.remaining_window(), 0);

        let rejected_seq = seq.wrapping_add(1);
        assert_eq!(
            handle_data_packet(&mut conn, rejected_seq, &[9]),
            DataPacketOutcome::State
        );
        assert_eq!(conn.recv_seq, seq, "over-budget data must not be ACKed");
        let advertised = conn.header(TYPE_STATE, conn.seq);
        assert_eq!(advertised.window, 0);
        assert_eq!(advertised.ack, seq);
        assert!(conn
            .recv_budget
            .window_update_wanted
            .load(Ordering::Acquire));

        for _ in 1..MAX_RECEIVE_OVERFLOW_STRIKES {
            let outcome = handle_data_packet(&mut conn, rejected_seq, &[9]);
            if conn.receive_overflow_strikes < MAX_RECEIVE_OVERFLOW_STRIKES {
                assert_eq!(outcome, DataPacketOutcome::State);
            } else {
                assert_eq!(outcome, DataPacketOutcome::Reset);
            }
        }
        assert_eq!(conn.state, ConnStatus::Closed);
    }

    #[test]
    fn receive_channel_chunk_count_bounds_tiny_packet_floods() {
        let (mut conn, _stream) = receive_test_conn(500);
        for offset in 1..=RECEIVE_CHANNEL_CHUNKS as u16 {
            assert_eq!(
                handle_data_packet(&mut conn, 500u16.wrapping_add(offset), &[1]),
                DataPacketOutcome::State
            );
        }
        assert_eq!(conn.recv_seq, 500 + RECEIVE_CHANNEL_CHUNKS as u16);
        assert_eq!(conn.recv_budget.remaining_window(), 0);

        let blocked = conn.recv_seq.wrapping_add(1);
        assert_eq!(
            handle_data_packet(&mut conn, blocked, &[2]),
            DataPacketOutcome::State
        );
        assert_ne!(conn.recv_seq, blocked);
        assert!(conn.ooo_received.is_empty());
        for attempt in 2..=MAX_RECEIVE_OVERFLOW_STRIKES {
            let outcome = handle_data_packet(&mut conn, blocked, &[2]);
            if attempt < MAX_RECEIVE_OVERFLOW_STRIKES {
                assert_eq!(outcome, DataPacketOutcome::State);
            } else {
                assert_eq!(outcome, DataPacketOutcome::Reset);
            }
            assert!(conn.ooo_received.is_empty());
            assert!(conn.recv_budget.bytes.load(Ordering::Acquire) <= RECEIVE_BUFFER_BYTES);
        }
        assert_eq!(conn.state, ConnStatus::Closed);
    }

    #[test]
    fn syn_limiter_bounds_global_and_per_ip_connection_growth() {
        let addr: SocketAddr = "192.0.2.1:9000".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:192.0.2.1]:9001".parse().unwrap();
        let mut limiter = SynLimiter::default();
        for _ in 0..MAX_INBOUND_CONNECTIONS_PER_IP {
            assert!(limiter.allows(addr));
            limiter.opened(addr);
        }
        assert!(!limiter.allows(addr));
        assert!(!limiter.allows(mapped));
        limiter.closed(addr);
        assert!(limiter.allows(mapped));

        while limiter.total < MAX_INBOUND_CONNECTIONS {
            let index = limiter.total as u16;
            let candidate =
                SocketAddr::from(([198, 51, (index / 250) as u8, (index % 250) as u8], 1));
            if limiter.allows(candidate) {
                limiter.opened(candidate);
            }
        }
        assert!(!limiter.allows("203.0.113.1:1".parse().unwrap()));
    }

    #[test]
    fn malformed_data_payloads_reset_without_buffering() {
        let (mut conn, _stream) = receive_test_conn(0);
        assert_eq!(
            handle_data_packet(&mut conn, 1, &[]),
            DataPacketOutcome::Reset
        );
        assert_eq!(conn.recv_budget.remaining_window(), RECEIVE_BUFFER_BYTES);

        let (mut conn, _stream) = receive_test_conn(0);
        assert_eq!(
            handle_data_packet(&mut conn, 1, &vec![0; UTP_RECV_PAYLOAD_MAX + 1]),
            DataPacketOutcome::Reset
        );
        assert_eq!(conn.recv_budget.remaining_window(), RECEIVE_BUFFER_BYTES);
        // libtorrent fills an Ethernet MTU: 1500 - IP - UDP - uTP headers.
        let (mut conn, _stream) = receive_test_conn(0);
        assert_eq!(
            handle_data_packet(&mut conn, 1, &[3; 1452]),
            DataPacketOutcome::State
        );
        assert_eq!(conn.recv_seq, 1);
    }

    #[test]
    fn fin_waits_for_reordered_data_before_closing() {
        let (mut conn, mut stream) = receive_test_conn(10);
        stream.set_read_timeout(Some(Duration::from_millis(200)));
        // FIN (seq 13) overtakes data packets 11 and 12.
        conn.eof_seq = Some(13);
        assert_eq!(
            handle_data_packet(&mut conn, 12, b"world"),
            DataPacketOutcome::State
        );
        assert_eq!(conn.recv_seq, 10);
        assert_eq!(
            handle_data_packet(&mut conn, 11, b"hello "),
            DataPacketOutcome::State
        );
        assert_eq!(conn.recv_seq, 13, "the FIN is acknowledged after the data");
        // Data after the FIN is never accepted.
        assert_eq!(
            handle_data_packet(&mut conn, 14, b"late"),
            DataPacketOutcome::State
        );
        assert!(conn.ooo_received.is_empty());
        drop(conn);
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap_err();
        assert_eq!(received, b"hello world");
    }

    #[test]
    fn utp_stream_read_uses_channel_and_internal_buffer() {
        let (conn, mut stream) = receive_test_conn(0);
        stream.set_read_timeout(Some(Duration::from_millis(200)));
        let recv_budget = Arc::clone(&conn.recv_budget);
        assert!(recv_budget.try_reserve_bytes(3));
        assert!(recv_budget.try_reserve_channel_chunk());
        conn.recv_tx.send(vec![1, 2, 3]).unwrap();
        let mut first = [0u8; 2];
        assert_eq!(stream.read(&mut first).unwrap(), 2);
        assert_eq!(first, [1, 2]);

        let mut second = [0u8; 2];
        assert_eq!(stream.read(&mut second).unwrap(), 1);
        assert_eq!(second[0], 3);
        assert_eq!(recv_budget.remaining_window(), RECEIVE_BUFFER_BYTES);

        let err = stream.read(&mut second).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }

    #[test]
    fn utp_stream_write_queues_coalesced_packets_without_waiting_for_acks() {
        let (conn, mut stream) = receive_test_conn(0);
        stream.set_write_timeout(Some(Duration::from_secs(1)));
        let total = UTP_PAYLOAD_MAX + 17;
        assert_eq!(stream.write(&vec![9u8; total]).unwrap(), total);
        assert_eq!(stream.write(b"abc").unwrap(), 3);
        let sizes: Vec<usize> = conn.queue.lock().packets.iter().map(Vec::len).collect();
        assert_eq!(sizes, vec![UTP_PAYLOAD_MAX, 20]);
    }

    #[test]
    fn utp_stream_write_respects_timeout_and_closure() {
        let (conn, mut stream) = receive_test_conn(0);
        stream.set_write_timeout(Some(Duration::from_millis(20)));
        let full = vec![1u8; SEND_QUEUE_PACKETS * UTP_PAYLOAD_MAX];
        assert_eq!(stream.write(&full).unwrap(), full.len());
        let err = stream.write(&[1, 2, 3]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);

        conn.queue.close();
        let err = stream.write(&[1]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn send_window_never_exceeds_the_peer_receive_window() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut io = Io {
            socket: &socket,
            buf: Vec::new(),
        };
        let (mut conn, mut stream) = receive_test_conn(0);
        conn.addr = socket.local_addr().unwrap();
        conn.cwnd = MAX_CWND * UTP_PAYLOAD_MAX;
        conn.peer_window = 2 * UTP_PAYLOAD_MAX - 1;
        stream.write_all(&[5u8; 3 * UTP_PAYLOAD_MAX]).unwrap();
        fill_send_window(&mut conn, &mut io);
        assert_eq!(conn.inflight.len(), 1, "a second packet would overshoot");
        assert_eq!(conn.inflight_bytes, UTP_PAYLOAD_MAX);

        conn.peer_window = 3 * UTP_PAYLOAD_MAX;
        fill_send_window(&mut conn, &mut io);
        assert_eq!(conn.inflight.len(), 3);
        // Sequence numbers are consecutive, starting at the next seq_nr.
        let seqs: Vec<u16> = conn.inflight.iter().map(|packet| packet.seq).collect();
        assert_eq!(seqs, vec![10, 11, 12]);
        assert_eq!(conn.seq, 13);
    }

    #[test]
    fn piggybacked_and_selective_acks_release_inflight_packets() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut io = Io {
            socket: &socket,
            buf: Vec::new(),
        };
        let (mut conn, _stream) = receive_test_conn(0);
        conn.addr = socket.local_addr().unwrap();
        for seq in 10..15u16 {
            conn.inflight.push_back(PendingPacket {
                seq,
                data: vec![0; 100],
                sent_at: Instant::now(),
                retransmissions: 0,
            });
        }
        conn.seq = 15;
        conn.inflight_bytes = 500;

        // An ack beyond anything sent is ignored.
        let mut bytes = packet(TYPE_DATA, 1, 1, 40, b"x");
        handle_packet(&mut conn, &mut io, &parse_packet(&bytes).unwrap());
        assert_eq!(conn.inflight.len(), 5);

        // A data packet acks seq 10; its SACK acks 13 (bit 1 of ack + 2).
        bytes.clear();
        encode_packet(
            &mut bytes,
            &header(TYPE_DATA, 1, 2, 10),
            &[2, 0, 0, 0],
            b"y",
        );
        handle_packet(&mut conn, &mut io, &parse_packet(&bytes).unwrap());
        let left: Vec<u16> = conn.inflight.iter().map(|packet| packet.seq).collect();
        assert_eq!(left, vec![11, 12, 14]);
        assert_eq!(conn.inflight_bytes, 300);
    }

    #[test]
    fn shared_socket_hands_dht_datagrams_over_and_keeps_utp() {
        let port = free_port();
        let (_connector, listener, shared) = start_shared(port);
        let shared = shared.expect("shared socket");
        assert_eq!(shared.socket.local_addr().unwrap().port(), port);
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        let ping = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
        peer.send_to(ping, target).unwrap();
        let (received, from) = shared.rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(received, ping);
        assert_eq!(from, peer.local_addr().unwrap());
        // The DHT answers through its clone, from the same port.
        shared.socket.send_to(b"d1:y1:re", from).unwrap();
        let mut reply = [0u8; 16];
        let (n, source) = peer.recv_from(&mut reply).unwrap();
        assert_eq!((&reply[..n], source.port()), (&b"d1:y1:re"[..], port));

        // uTP on the same port still accepts connections.
        peer.send_to(&packet(TYPE_SYN, 700, 1000, 0, &[]), target)
            .unwrap();
        let (bytes, _) = recv_packet(&peer);
        assert_eq!(parse_packet(&bytes).unwrap().ty, TYPE_STATE);
        accept_within(&listener, Duration::from_secs(3));
        assert!(shared.rx.try_recv().is_err(), "uTP stays with uTP");
    }

    #[test]
    fn responder_follows_bep29_connection_ids_and_sequence_numbers() {
        let port = free_port();
        let (_connector, listener) = start(port);
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        // A libutp initiator: SYN carries its receive ID and seq 1000.
        peer.send_to(&packet(TYPE_SYN, 700, 1000, 0, &[]), target)
            .unwrap();
        let (bytes, _) = recv_packet(&peer);
        let syn_ack = parse_packet(&bytes).unwrap();
        assert_eq!(syn_ack.ty, TYPE_STATE);
        assert_eq!(syn_ack.conn_id, 700, "responder sends on the SYN's ID");
        assert_eq!(syn_ack.ack, 1000);
        let responder_seq = syn_ack.seq;

        let mut stream = accept_within(&listener, Duration::from_secs(3));
        stream.set_read_timeout(Some(Duration::from_secs(3)));
        // The initiator sends data on ID + 1 starting after its SYN.
        peer.send_to(
            &packet(TYPE_DATA, 701, 1001, responder_seq.wrapping_sub(1), b"ping"),
            target,
        )
        .unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        let (bytes, _) = recv_packet(&peer);
        let ack = parse_packet(&bytes).unwrap();
        assert_eq!((ack.ty, ack.conn_id, ack.ack), (TYPE_STATE, 700, 1001));

        stream.write_all(b"pong").unwrap();
        let bytes = recv_data_packet(&peer);
        let data = parse_packet(&bytes).unwrap();
        assert_eq!(data.ty, TYPE_DATA);
        assert_eq!(data.conn_id, 700);
        assert_eq!(
            data.seq, responder_seq,
            "first data uses the SYN-ACK seq_nr"
        );
        assert_eq!(data.payload, b"pong");
    }

    #[test]
    fn initiator_follows_bep29_connection_ids_and_sequence_numbers() {
        let (connector, _listener) = start(free_port());
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let connecting = thread::spawn(move || connector.connect(peer_addr));

        let (bytes, from) = recv_packet(&peer);
        let syn = parse_packet(&bytes).unwrap();
        assert_eq!(syn.ty, TYPE_SYN);
        // A libutp responder answers on the SYN's ID with its next seq_nr.
        peer.send_to(&packet(TYPE_STATE, syn.conn_id, 5000, syn.seq, &[]), from)
            .unwrap();
        let mut stream = connecting.join().unwrap().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(3)));

        stream.write_all(b"hello").unwrap();
        let bytes = recv_data_packet(&peer);
        let data = parse_packet(&bytes).unwrap();
        assert_eq!(data.ty, TYPE_DATA);
        assert_eq!(data.conn_id, syn.conn_id.wrapping_add(1));
        assert_eq!(data.seq, syn.seq.wrapping_add(1));
        assert_eq!(data.ack, 4999);
        assert_eq!(data.payload, b"hello");

        peer.send_to(
            &packet(TYPE_DATA, syn.conn_id, 5000, data.seq, b"world"),
            from,
        )
        .unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"world");
    }

    #[test]
    fn connector_and_listener_exchange_data() {
        let port_a = free_port();
        let port_b = free_port();
        let (connector_a, _listener_a) = start(port_a);
        let (_connector_b, listener_b) = start(port_b);

        let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
        let mut a = connector_a.connect(addr_b).unwrap();
        let mut b = accept_within(&listener_b, Duration::from_secs(3));

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

        // Dropping a stream flushes queued data and then closes with FIN.
        a.write_all(b"bye").unwrap();
        drop(a);
        let mut rest = Vec::new();
        b.set_read_timeout(Some(Duration::from_secs(3)));
        let err = b.read_to_end(&mut rest).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        assert_eq!(rest, b"bye");
    }

    #[test]
    fn bulk_transfer_is_pipelined() {
        let port_b = free_port();
        let (connector_a, _listener_a) = start(free_port());
        let (_connector_b, listener_b) = start(port_b);
        let mut a = connector_a
            .connect(format!("127.0.0.1:{port_b}").parse().unwrap())
            .unwrap();
        let mut b = accept_within(&listener_b, Duration::from_secs(3));
        a.set_write_timeout(Some(Duration::from_secs(5)));
        b.set_read_timeout(Some(Duration::from_secs(5)));

        let payload: Vec<u8> = (0..2 * 1024 * 1024u32).map(|i| (i % 253) as u8).collect();
        let expected = payload.clone();
        let started = Instant::now();
        let writer = thread::spawn(move || {
            a.write_all(&payload).unwrap();
            a
        });
        let mut received = vec![0u8; expected.len()];
        b.read_exact(&mut received).unwrap();
        assert!(received == expected);
        // Stop-and-wait delivery would need one round trip plus a poll
        // interval per 1200-byte packet.
        assert!(started.elapsed() < Duration::from_secs(10));
        drop(writer.join().unwrap());
    }

    #[test]
    fn sack_roundtrip() {
        let mut ooo = HashMap::new();
        // ack_nr = 10, so first missing is 11, bits represent 12, 13, 14...
        ooo.insert(12, vec![1]); // bit 0
        ooo.insert(14, vec![2]); // bit 2
        let mask = build_sack(10, &ooo).unwrap();
        let mut bytes = Vec::new();
        encode_packet(&mut bytes, &header(TYPE_STATE, 1, 1, 10), &mask, &[]);
        let parsed = parse_packet(&bytes).unwrap();
        assert_eq!(parsed.ty, TYPE_STATE);
        assert_eq!(parsed.ack, 10);
        assert_eq!(parsed.sack, &[0b0000_0101, 0, 0, 0]);
        assert!(build_sack(10, &HashMap::new()).is_none());
    }

    #[test]
    fn ledbat_cwnd_follows_queuing_delay() {
        let (mut conn, _stream) = receive_test_conn(0);
        conn.base_delay = Some(1000); // 1ms base delay
        conn.current_delay = 2000; // 2ms current delay (well below 100ms target)
        let old_cwnd = conn.cwnd;
        // Even a single-packet ACK must grow the window below target.
        ledbat_update_cwnd(&mut conn, UTP_PAYLOAD_MAX);
        assert!(conn.cwnd > old_cwnd);
        for _ in 0..10_000 {
            ledbat_update_cwnd(&mut conn, UTP_PAYLOAD_MAX);
        }
        assert_eq!(conn.cwnd, MAX_CWND * UTP_PAYLOAD_MAX);

        conn.cwnd = 20 * UTP_PAYLOAD_MAX;
        conn.current_delay = 500_000; // 500ms current delay >> 100ms target
        ledbat_update_cwnd(&mut conn, 20 * UTP_PAYLOAD_MAX);
        assert!(conn.cwnd < 20 * UTP_PAYLOAD_MAX);
        for _ in 0..1_000 {
            ledbat_update_cwnd(&mut conn, 20 * UTP_PAYLOAD_MAX);
        }
        assert_eq!(conn.cwnd, UTP_PAYLOAD_MAX);
    }
}

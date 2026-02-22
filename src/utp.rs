use std::collections::{HashMap, VecDeque};
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
            Err(_) => return,
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
    addr: SocketAddr,
    send_tx: mpsc::Sender<SendRequest>,
    recv_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: VecDeque<u8>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl UtpStream {
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
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
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
                        last_seen: Instant::now(),
                        connect_started: Instant::now(),
                        connect_resp: Some(resp),
                        connect_stream: Some(stream),
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
                        let packet = build_packet(
                            TYPE_DATA,
                            conn.send_id,
                            conn.seq,
                            conn.recv_seq,
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

            // Retransmit timed-out packets and halve cwnd
            let mut did_timeout = false;
            for pending in conn.inflight.iter_mut() {
                if pending.sent_at.elapsed() >= UTP_ACK_TIMEOUT {
                    let packet = build_packet(
                        TYPE_DATA,
                        conn.send_id,
                        pending.seq,
                        conn.recv_seq,
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

        match socket.recv_from(&mut buf) {
            Ok((n, addr)) => {
                if n < UTP_HEADER_LEN {
                    continue;
                }
                let (ty, conn_id, seq, ack, payload) = parse_packet(&buf[..n]);
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
                        last_seen: Instant::now(),
                        connect_started: Instant::now(),
                        connect_resp: None,
                        connect_stream: None,
                    };
                    let state_pkt = build_packet(TYPE_STATE, send_id, conn.seq, seq, &[]);
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
                        if conn.state == ConnStatus::SynSent
                            && conn.send_id.wrapping_add(1) == conn_id
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

                match ty {
                    TYPE_STATE => {
                        // ACK received: remove all packets with seq <= ack
                        let mut acked = false;
                        while let Some(front) = conn.inflight.front() {
                            if front.seq == ack || is_seq_before_or_equal(front.seq, ack) {
                                let pkt = conn.inflight.pop_front().unwrap();
                                let _ = pkt.resp.send(Ok(()));
                                acked = true;
                            } else {
                                break;
                            }
                        }
                        if acked && conn.cwnd < MAX_CWND {
                            conn.cwnd += 1; // Additive increase
                        }
                    }
                    TYPE_DATA => {
                        if seq == conn.recv_seq.wrapping_add(1) || conn.recv_seq == seq {
                            conn.recv_seq = seq;
                            let _ = conn.recv_tx.send(payload.to_vec());
                        }
                        let state_pkt =
                            build_packet(TYPE_STATE, conn.send_id, conn.seq, conn.recv_seq, &[]);
                        let _ = socket.send_to(&state_pkt, conn.addr);
                    }
                    TYPE_FIN => {
                        drain_inflight_err(conn, "utp closed");
                        if let Some(resp) = conn.connect_resp.take() {
                            let _ = resp.send(Err("utp closed".to_string()));
                        }
                        conn.connect_stream.take();
                        conn.state = ConnStatus::Closed;
                        let state_pkt =
                            build_packet(TYPE_STATE, conn.send_id, conn.seq, conn.recv_seq, &[]);
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
            Err(_) => {}
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
    let mut out = Vec::with_capacity(UTP_HEADER_LEN + payload.len());
    out.push((ty << 4) | UTP_VERSION);
    out.push(0);
    out.extend_from_slice(&conn_id.to_be_bytes());
    out.extend_from_slice(&timestamp().to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    out.extend_from_slice(&0x400000u32.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ack.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn parse_packet(data: &[u8]) -> (u8, u16, u16, u16, &[u8]) {
    let ty = data[0] >> 4;
    let conn_id = u16::from_be_bytes([data[2], data[3]]);
    let seq = u16::from_be_bytes([data[16], data[17]]);
    let ack = u16::from_be_bytes([data[18], data[19]]);
    let payload = &data[UTP_HEADER_LEN..];
    (ty, conn_id, seq, ack, payload)
}

fn timestamp() -> u32 {
    use std::sync::OnceLock;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    let micros = epoch.elapsed().as_micros() as u32;
    micros
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

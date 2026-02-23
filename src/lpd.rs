use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const LPD_ADDR_V4: &str = "239.192.152.143:6771";
const LPD_ADDR_V6: &str = "[ff15::efc0:988f]:6771";
const LPD_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct Lpd {
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

struct Entry {
    peers_tx: mpsc::Sender<Vec<SocketAddr>>,
    port: u16,
    last_announce: Instant,
}

pub fn start() -> Lpd {
    let (cmd_tx, cmd_rx) = mpsc::channel();
    thread::spawn(move || {
        lpd_thread(cmd_rx);
    });
    Lpd { cmd_tx }
}

impl Lpd {
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

fn lpd_thread(cmd_rx: mpsc::Receiver<Command>) {
    let socket = match UdpSocket::bind("0.0.0.0:6771") {
        Ok(socket) => socket,
        Err(_) => return,
    };
    let _ = socket.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = socket.join_multicast_v4(
        &Ipv4Addr::new(239, 192, 152, 143),
        &Ipv4Addr::new(0, 0, 0, 0),
    );

    // IPv6 multicast socket (BEP 14)
    let socket6 = UdpSocket::bind("[::]:6771").ok();
    if let Some(ref s6) = socket6 {
        let _ = s6.set_read_timeout(Some(Duration::from_millis(200)));
        let group: Ipv6Addr = "ff15::efc0:988f".parse().unwrap();
        let _ = s6.join_multicast_v6(&group, 0);
    }

    let mut entries: HashMap<[u8; 20], Entry> = HashMap::new();
    let mut buf = [0u8; 1500];
    loop {
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Command::AddTorrent {
                    info_hash,
                    port,
                    peers_tx,
                } => {
                    entries.insert(
                        info_hash,
                        Entry {
                            peers_tx,
                            port,
                            last_announce: Instant::now() - LPD_INTERVAL,
                        },
                    );
                }
                Command::RemoveTorrent { info_hash } => {
                    entries.remove(&info_hash);
                }
            }
        }

        let now = Instant::now();
        for (info_hash, entry) in entries.iter_mut() {
            if entry.last_announce.elapsed() >= LPD_INTERVAL {
                let msg = build_search_message(info_hash, entry.port);
                let _ = socket.send_to(&msg, LPD_ADDR_V4);
                if let Some(ref s6) = socket6 {
                    let _ = s6.send_to(&msg, LPD_ADDR_V6);
                }
                entry.last_announce = now;
            }
        }

        if let Ok((n, addr)) = socket.recv_from(&mut buf) {
            if let Some((info_hash, port)) = parse_search_message(&buf[..n]) {
                if let Some(entry) = entries.get(&info_hash) {
                    let peer = SocketAddr::new(addr.ip(), port);
                    let _ = entry.peers_tx.send(vec![peer]);
                }
            }
        }
        if let Some(ref s6) = socket6 {
            if let Ok((n, addr)) = s6.recv_from(&mut buf) {
                if let Some((info_hash, port)) = parse_search_message(&buf[..n]) {
                    if let Some(entry) = entries.get(&info_hash) {
                        let peer = SocketAddr::new(addr.ip(), port);
                        let _ = entry.peers_tx.send(vec![peer]);
                    }
                }
            }
        }
    }
}

fn build_search_message(info_hash: &[u8; 20], port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"BT-SEARCH * HTTP/1.1\r\n");
    out.extend_from_slice(b"Host: 239.192.152.143:6771\r\n");
    out.extend_from_slice(b"Port: ");
    out.extend_from_slice(port.to_string().as_bytes());
    out.extend_from_slice(b"\r\nInfohash: ");
    out.extend_from_slice(hex(info_hash).as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
    out
}

fn parse_search_message(data: &[u8]) -> Option<([u8; 20], u16)> {
    let text = std::str::from_utf8(data).ok()?;
    let mut info_hash: Option<[u8; 20]> = None;
    let mut port: Option<u16> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("Infohash:") {
            let value = value.trim();
            info_hash = decode_hex_20(value);
        } else if let Some(value) = line.strip_prefix("Port:") {
            let value = value.trim();
            port = value.parse::<u16>().ok();
        }
    }
    Some((info_hash?, port?))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn decode_hex_20(value: &str) -> Option<[u8; 20]> {
    let bytes = value.as_bytes();
    if bytes.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)? as u8;
        let lo = (chunk[1] as char).to_digit(16)? as u8;
        out[idx] = (hi << 4) | lo;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_message_roundtrip() {
        let info_hash = [0xABu8; 20];
        let msg = build_search_message(&info_hash, 6881);
        let (parsed_hash, parsed_port) = parse_search_message(&msg).unwrap();
        assert_eq!(parsed_hash, info_hash);
        assert_eq!(parsed_port, 6881);
    }

    #[test]
    fn parse_search_message_requires_infohash_and_port() {
        assert!(parse_search_message(b"Port: 6881\r\n\r\n").is_none());
        assert!(parse_search_message(b"Infohash: 0123\r\n\r\n").is_none());
        assert!(parse_search_message(b"Infohash: nothex\r\nPort: 6881\r\n").is_none());
    }

    #[test]
    fn decode_hex_20_accepts_uppercase_and_rejects_bad_len() {
        let valid = "0123456789ABCDEF0123456789ABCDEF01234567";
        let parsed = decode_hex_20(valid).unwrap();
        assert_eq!(hex(&parsed), valid.to_ascii_lowercase());
        assert!(decode_hex_20("abcd").is_none());
    }
}

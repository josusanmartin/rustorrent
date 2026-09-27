use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use crate::bencode::{self, Value};
use crate::proxy::ProxyConfig;

const MAX_TRACKER_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TRACKER_FAILURE_REASON_CHARS: usize = 256;
// Keep one tracker response within the application's hard 1024-peer handler ceiling.
const MAX_TRACKER_PEERS: usize = 1024;

pub struct TrackerResponse {
    pub interval: u64,
    pub peers: Vec<SocketAddr>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn announce_with_private_until(
    announce_url: &str,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<&str>,
    numwant: u32,
    private: bool,
    proxy: Option<&ProxyConfig>,
    deadline: Instant,
) -> Result<TrackerResponse, String> {
    let mut query = build_query(
        info_hash,
        peer_id,
        port,
        [uploaded, downloaded, left],
        event,
        numwant,
        proxy.is_none(),
    );
    if private {
        query.push_str("&private=1");
    }
    // Self-hosted and LAN trackers are normal, and UDP trackers already reach
    // them. Through a proxy, local names would resolve on the proxy host, so
    // only public targets are sent there.
    announce_query(announce_url, &query, proxy, deadline, proxy.is_some())
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn announce_local_test(
    announce_url: &str,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<&str>,
    numwant: u32,
) -> Result<TrackerResponse, String> {
    let query = build_query(
        info_hash,
        peer_id,
        port,
        [uploaded, downloaded, left],
        event,
        numwant,
        true,
    );
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    announce_query(announce_url, &query, None, deadline, false)
}

fn announce_query(
    announce_url: &str,
    query: &str,
    proxy: Option<&ProxyConfig>,
    deadline: Instant,
    require_public_target: bool,
) -> Result<TrackerResponse, String> {
    // A fragment would swallow the appended query string.
    let base = announce_url.split('#').next().unwrap_or(announce_url);
    let separator = if base.contains('?') { '&' } else { '?' };
    let url = format!("{base}{separator}{query}");
    let body = crate::http::get_tracker(
        &url,
        MAX_TRACKER_RESPONSE_BYTES,
        deadline,
        proxy,
        require_public_target,
    )?;
    parse_tracker_body(&body)
}

fn build_query(
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    [uploaded, downloaded, left]: [u64; 3],
    event: Option<&str>,
    numwant: u32,
    advertise_local_ipv6: bool,
) -> String {
    let mut query = String::with_capacity(256);
    query.push_str("info_hash=");
    percent_encode_into(&mut query, &info_hash);
    query.push_str("&peer_id=");
    percent_encode_into(&mut query, &peer_id);
    let _ = write!(
        query,
        "&port={port}&uploaded={uploaded}&downloaded={downloaded}&left={left}&compact=1"
    );
    if numwant > 0 {
        let _ = write!(query, "&numwant={numwant}");
    }
    if let Some(event) = event.filter(|event| !event.is_empty()) {
        query.push_str("&event=");
        percent_encode_into(&mut query, event.as_bytes());
    }
    // BEP 7: advertise IPv6 address if available
    if advertise_local_ipv6 {
        if let Some(ipv6) = detect_ipv6_address() {
            query.push_str("&ipv6=");
            percent_encode_into(&mut query, ipv6.to_string().as_bytes());
        }
    }
    query
}

fn detect_ipv6_address() -> Option<Ipv6Addr> {
    let socket = std::net::UdpSocket::bind("[::]:0").ok()?;
    socket.connect("[2001:4860:4860::8888]:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V6(addr) if !addr.is_loopback() && !addr.is_unspecified() => Some(addr),
        _ => None,
    }
}

fn percent_encode_into(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[usize::from(b >> 4)] as char);
            out.push(HEX[usize::from(b & 15)] as char);
        }
    }
}

fn parse_tracker_body(body: &[u8]) -> Result<TrackerResponse, String> {
    let value = bencode::parse(body).map_err(|err| format!("tracker bencode: {err}"))?;
    let Value::Dict(dict) = value else {
        return Err("invalid tracker response".to_string());
    };

    if let Some(Value::Bytes(reason)) = dict_get(&dict, b"failure reason") {
        return Err(format!(
            "tracker failure: {}",
            sanitize_failure_reason(reason)
        ));
    }

    let interval = match dict_get(&dict, b"interval") {
        Some(Value::Int(interval)) if *interval >= 0 => *interval as u64,
        _ => return Err("tracker response missing interval".to_string()),
    };
    let mut peers = Vec::new();
    let mut saw_peers = false;
    for (key, stride) in [(&b"peers"[..], 6), (&b"peers6"[..], 18)] {
        if let Some(value) = dict_get(&dict, key) {
            saw_peers = true;
            let limit = MAX_TRACKER_PEERS.saturating_sub(peers.len());
            match value {
                Value::Bytes(bytes) => parse_compact_peers(bytes, stride, limit, &mut peers)?,
                Value::List(list) => parse_dict_peers(list, limit, &mut peers)?,
                _ => return Err("invalid tracker peers".to_string()),
            }
        }
    }
    if !saw_peers {
        return Err("tracker response missing peers".to_string());
    }
    crate::log_stderr(format_args!("  tracker: {} peers", peers.len()));
    Ok(TrackerResponse { interval, peers })
}

pub(crate) fn sanitize_failure_reason(reason: &[u8]) -> String {
    let sanitized: String = String::from_utf8_lossy(reason)
        .chars()
        .take(MAX_TRACKER_FAILURE_REASON_CHARS)
        .map(|character| {
            if character.is_control()
                || matches!(
                    character,
                    '\u{061c}'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2060}'..='\u{206f}'
                        | '\u{feff}'
                )
            {
                '?'
            } else {
                character
            }
        })
        .collect();
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        "unspecified error".to_string()
    } else {
        sanitized.to_string()
    }
}

/// Parses BEP 23 (IPv4, 6-byte) or BEP 7 (IPv6, 18-byte) compact peers,
/// skipping entries with port 0 rather than rejecting the whole response.
fn parse_compact_peers(
    bytes: &[u8],
    stride: usize,
    limit: usize,
    peers: &mut Vec<SocketAddr>,
) -> Result<(), String> {
    if !bytes.len().is_multiple_of(stride) {
        return Err("invalid compact peers length".to_string());
    }
    for entry in bytes.chunks_exact(stride).take(limit) {
        let (ip, port) = entry.split_at(stride - 2);
        let port = u16::from_be_bytes([port[0], port[1]]);
        if port == 0 {
            continue;
        }
        let ip = match <[u8; 4]>::try_from(ip) {
            Ok(v4) => Ipv4Addr::from(v4).into(),
            Err(_) => {
                let mut v6 = [0u8; 16];
                v6.copy_from_slice(ip);
                Ipv6Addr::from(v6).into()
            }
        };
        peers.push(SocketAddr::new(ip, port));
    }
    Ok(())
}

fn parse_dict_peers(
    list: &[Value],
    limit: usize,
    peers: &mut Vec<SocketAddr>,
) -> Result<(), String> {
    for entry in list.iter().take(limit) {
        let Value::Dict(dict) = entry else {
            return Err("invalid tracker peer entry".to_string());
        };
        let ip = match dict_get(dict, b"ip") {
            Some(Value::Bytes(ip)) => std::str::from_utf8(ip).ok().and_then(|ip| ip.parse().ok()),
            _ => None,
        };
        let port = match dict_get(dict, b"port") {
            Some(Value::Int(port)) => u16::try_from(*port).ok().filter(|port| *port != 0),
            _ => None,
        };
        match (ip, port) {
            (Some(ip), Some(port)) => peers.push(SocketAddr::new(ip, port)),
            _ => return Err("invalid tracker peer entry".to_string()),
        }
    }
    Ok(())
}

fn dict_get<'a>(dict: &'a [(Vec<u8>, Value)], key: &[u8]) -> Option<&'a Value> {
    dict.iter()
        .find_map(|(k, v)| if k.as_slice() == key { Some(v) } else { None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::thread;
    use std::time::Duration;

    fn compact(bytes: &[u8], stride: usize) -> Result<Vec<SocketAddr>, String> {
        let mut peers = Vec::new();
        parse_compact_peers(bytes, stride, MAX_TRACKER_PEERS, &mut peers)?;
        Ok(peers)
    }

    #[test]
    fn percent_encodes_bytes() {
        let mut encoded = String::new();
        percent_encode_into(&mut encoded, b"\x01a z~\xff");
        assert_eq!(encoded, "%01a%20z~%FF");
    }

    #[test]
    fn announce_query_is_appended_before_any_fragment() {
        let query = build_query([0xab; 20], [b'-'; 20], 6881, [1, 2, 3], None, 0, false);
        assert!(query.starts_with("info_hash=%AB%AB"));
        assert!(query.ends_with("&port=6881&uploaded=1&downloaded=2&left=3&compact=1"));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /announce?key=1&info_hash="));
            let body = b"d8:intervali60e5:peers0:e";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let url = format!("http://127.0.0.1:{port}/announce?key=1#fragment");
        let response =
            announce_local_test(&url, [1; 20], [2; 20], 6881, 0, 0, 1, Some("started"), 5).unwrap();
        assert_eq!(response.interval, 60);
        server.join().unwrap();
    }

    #[test]
    fn parse_compact_peer_lists() {
        let peers = compact(&[127, 0, 0, 1, 0x1A, 0xE1, 10, 0, 0, 2, 0x00, 0x50], 6).unwrap();
        assert_eq!(
            peers,
            vec![
                "127.0.0.1:6881".parse().unwrap(),
                "10.0.0.2:80".parse().unwrap()
            ]
        );

        let bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1A, 0xE1,
        ];
        assert_eq!(
            compact(&bytes, 18).unwrap(),
            vec!["[2001:db8::1]:6881".parse::<SocketAddr>().unwrap()]
        );
    }

    #[test]
    fn compact_peers_skip_port_zero_and_reject_partial_entries() {
        let peers = compact(&[127, 0, 0, 1, 0, 0, 10, 0, 0, 2, 0x00, 0x50], 6).unwrap();
        assert_eq!(peers, vec!["10.0.0.2:80".parse().unwrap()]);
        assert!(compact(&[1, 2, 3], 6).is_err());
        assert!(compact(&[0u8; 17], 18).is_err());
    }

    #[test]
    fn compact_peer_bomb_is_truncated_during_parse() {
        let mut bytes = Vec::with_capacity((MAX_TRACKER_PEERS + 100) * 6);
        for index in 0..MAX_TRACKER_PEERS + 100 {
            let octet = (index % 250 + 1) as u8;
            bytes.extend_from_slice(&[10, 0, 0, octet, 0x1A, 0xE1]);
        }
        assert_eq!(compact(&bytes, 6).unwrap().len(), MAX_TRACKER_PEERS);
    }

    #[test]
    fn tracker_body_caps_combined_ipv4_and_ipv6_peers() {
        let mut peers4 = Vec::with_capacity(MAX_TRACKER_PEERS * 6);
        let mut peers6 = Vec::with_capacity(MAX_TRACKER_PEERS * 18);
        for index in 0..MAX_TRACKER_PEERS {
            let octet = (index % 250 + 1) as u8;
            peers4.extend_from_slice(&[10, 0, 0, octet, 0x1A, 0xE1]);
            let mut addr = [0u8; 18];
            addr[0] = 0x20;
            addr[1] = 0x01;
            addr[15] = octet;
            addr[16..].copy_from_slice(&6881u16.to_be_bytes());
            peers6.extend_from_slice(&addr);
        }
        let body = bencode::encode(&Value::Dict(vec![
            (b"interval".to_vec(), Value::Int(1200)),
            (b"peers".to_vec(), Value::Bytes(peers4)),
            (b"peers6".to_vec(), Value::Bytes(peers6)),
        ]));
        let parsed = parse_tracker_body(&body).unwrap();
        assert_eq!(parsed.peers.len(), MAX_TRACKER_PEERS);
        assert!(parsed.peers.iter().all(SocketAddr::is_ipv4));
    }

    #[test]
    fn parse_tracker_body_handles_failure_reason_and_missing_fields() {
        let body = bencode::encode(&Value::Dict(vec![(
            b"failure reason".to_vec(),
            Value::Bytes(b"denied".to_vec()),
        )]));
        let err = parse_tracker_body(&body).err().unwrap();
        assert_eq!(err, "tracker failure: denied");
        assert!(parse_tracker_body(b"d8:intervali60ee").is_err());
        assert!(parse_tracker_body(b"d5:peers0:e").is_err());
        assert!(parse_tracker_body(b"le").is_err());
    }

    #[test]
    fn tracker_failure_reason_is_safe_for_terminal_logs_and_bounded() {
        let mut hostile = b"denied\x1b]0;owned\x07\r\n".to_vec();
        hostile.extend(std::iter::repeat_n(
            b'x',
            MAX_TRACKER_FAILURE_REASON_CHARS + 100,
        ));
        let sanitized = sanitize_failure_reason(&hostile);
        assert!(!sanitized.chars().any(char::is_control));
        assert!(sanitized.chars().count() <= MAX_TRACKER_FAILURE_REASON_CHARS);
        assert!(sanitized.starts_with("denied?]0;owned???"));
        assert_eq!(sanitize_failure_reason(b"\r\n"), "??");
        assert_eq!(
            sanitize_failure_reason("safe\u{202e}evil\u{2060}".as_bytes()),
            "safe?evil?"
        );
    }

    #[test]
    fn http_tracker_uses_proxy_domain_without_local_target_dns() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut connect = Vec::new();
            let mut byte = [0u8; 1];
            while !connect.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                connect.push(byte[0]);
            }
            let connect = String::from_utf8(connect).unwrap();
            assert!(connect.starts_with("CONNECT tracker.invalid:80 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .unwrap();

            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("GET /announce?"));
            assert!(!request.contains("ipv6="));
            let body = bencode::encode(&Value::Dict(vec![
                (b"interval".to_vec(), Value::Int(60)),
                (b"peers".to_vec(), Value::Bytes(Vec::new())),
            ]));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });

        let proxy = ProxyConfig::Http {
            host: "127.0.0.1".to_string(),
            port: proxy_port,
        };
        let response = announce_with_private_until(
            "http://tracker.invalid/announce",
            [1u8; 20],
            [2u8; 20],
            6881,
            0,
            0,
            1,
            Some("started"),
            10,
            false,
            Some(&proxy),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(response.interval, 60);
        assert!(response.peers.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn tracker_policy_rejects_private_targets_and_proxy_redirect_hosts() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let unreachable_proxy = ProxyConfig::Http {
            host: "127.0.0.1".to_string(),
            port: 9,
        };
        for (url, proxy) in [
            ("http://127.0.0.1/announce", None),
            ("http://[::ffff:127.0.0.1]/announce", None),
            ("http://localhost/announce", Some(&unreachable_proxy)),
            (
                "http://service.home.arpa/announce",
                Some(&unreachable_proxy),
            ),
            ("http://10.0.0.1/announce", Some(&unreachable_proxy)),
        ] {
            let err = crate::http::get_tracker(url, 1024, deadline, proxy, true).unwrap_err();
            assert!(err.contains("not publicly routable"), "{url}: {err}");
        }
    }

    #[test]
    fn parse_tracker_body_accepts_dict_peer_entries() {
        let peers_list = Value::List(vec![
            Value::Dict(vec![
                (b"ip".to_vec(), Value::Bytes(b"127.0.0.1".to_vec())),
                (b"port".to_vec(), Value::Int(6881)),
            ]),
            Value::Dict(vec![
                (b"ip".to_vec(), Value::Bytes(b"10.0.0.2".to_vec())),
                (b"port".to_vec(), Value::Int(80)),
            ]),
        ]);
        let body = bencode::encode(&Value::Dict(vec![
            (b"interval".to_vec(), Value::Int(1200)),
            (b"peers".to_vec(), peers_list),
        ]));
        let parsed = parse_tracker_body(&body).unwrap();
        assert_eq!(parsed.interval, 1200);
        assert_eq!(
            parsed.peers,
            vec![
                "127.0.0.1:6881".parse().unwrap(),
                "10.0.0.2:80".parse().unwrap()
            ]
        );
    }
}

use std::fmt;
use std::io::{Read, Write};
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream, ToSocketAddrs,
};
use std::time::Duration;

use native_tls::{TlsConnector, TlsStream};

use crate::bencode::{self, Value};

const TRACKER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TRACKER_IO_TIMEOUT: Duration = Duration::from_secs(10);
const TRACKER_REDIRECT_LIMIT: usize = 5;

#[derive(Debug)]
pub struct TrackerResponse {
    pub interval: u64,
    pub peers: Vec<SocketAddr>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Tls(native_tls::Error),
    UnsupportedScheme,
    InvalidUrl,
    InvalidPort,
    HttpParse,
    HttpStatus(u16),
    Bencode(bencode::Error),
    FailureReason(String),
    MissingField(&'static str),
    InvalidField(&'static str),
    InvalidPeers,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "io error: {err}"),
            Error::Tls(err) => write!(f, "tls error: {err}"),
            Error::UnsupportedScheme => write!(f, "unsupported scheme (only http/https)"),
            Error::InvalidUrl => write!(f, "invalid tracker url"),
            Error::InvalidPort => write!(f, "invalid tracker port"),
            Error::HttpParse => write!(f, "invalid http response"),
            Error::HttpStatus(code) => write!(f, "http status {code}"),
            Error::Bencode(err) => write!(f, "bencode error: {err}"),
            Error::FailureReason(reason) => write!(f, "tracker failure: {reason}"),
            Error::MissingField(field) => write!(f, "missing field: {field}"),
            Error::InvalidField(field) => write!(f, "invalid field: {field}"),
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

impl From<native_tls::Error> for Error {
    fn from(err: native_tls::Error) -> Self {
        Error::Tls(err)
    }
}

impl From<bencode::Error> for Error {
    fn from(err: bencode::Error) -> Self {
        Error::Bencode(err)
    }
}

pub fn announce(
    announce_url: &str,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<&str>,
    numwant: u32,
) -> Result<TrackerResponse, Error> {
    announce_with_private(
        announce_url,
        info_hash,
        peer_id,
        port,
        uploaded,
        downloaded,
        left,
        event,
        numwant,
        false,
    )
}

pub fn announce_with_private(
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
) -> Result<TrackerResponse, Error> {
    let mut query = build_query(
        info_hash, peer_id, port, uploaded, downloaded, left, event, numwant,
    );
    if private {
        push_query(&mut query, "private", "1");
    }
    let mut url = announce_url.to_string();
    for _ in 0..=TRACKER_REDIRECT_LIMIT {
        let parsed = parse_url(&url)?;
        let path = append_query(&parsed.path, &query);

        let mut stream = connect_stream(&parsed)?;
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rustorrent/0.1\r\nConnection: close\r\n\r\n",
            parsed.host
        );
        stream.write_all(request.as_bytes())?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        let response = parse_http_response(&response)?;
        if response.status == 200 {
            return parse_tracker_body(&response.body);
        }
        if is_redirect(response.status) {
            let location = header_value(&response.headers, "location")
                .ok_or(Error::HttpStatus(response.status))?;
            url = resolve_location(&parsed, &location)?;
            continue;
        }
        return Err(Error::HttpStatus(response.status));
    }
    Err(Error::HttpStatus(310))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

struct ParsedUrl {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn parse_url(url: &str) -> Result<ParsedUrl, Error> {
    let (scheme, url) = if let Some(rest) = url.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else if let Some(rest) = url.strip_prefix("https://") {
        (Scheme::Https, rest)
    } else {
        return Err(Error::UnsupportedScheme);
    };
    let (host_port, path) = match url.split_once('/') {
        Some((host_port, path)) => (host_port, format!("/{path}")),
        None => (url, "/".to_string()),
    };

    if host_port.is_empty() {
        return Err(Error::InvalidUrl);
    }

    let default_port = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };

    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port = port.parse::<u16>().map_err(|_| Error::InvalidPort)?;
            (host.to_string(), port)
        }
        _ => (host_port.to_string(), default_port),
    };

    Ok(ParsedUrl {
        scheme,
        host,
        port,
        path,
    })
}

enum TrackerStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
}

impl Read for TrackerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TrackerStream::Plain(stream) => stream.read(buf),
            TrackerStream::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for TrackerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            TrackerStream::Plain(stream) => stream.write(buf),
            TrackerStream::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            TrackerStream::Plain(stream) => stream.flush(),
            TrackerStream::Tls(stream) => stream.flush(),
        }
    }
}

fn connect_stream(parsed: &ParsedUrl) -> Result<TrackerStream, Error> {
    let mut last_err: Option<std::io::Error> = None;
    let addrs = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()
        .map_err(Error::Io)?;
    let mut stream = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, TRACKER_CONNECT_TIMEOUT) {
            Ok(conn) => {
                stream = Some(conn);
                break;
            }
            Err(err) => last_err = Some(err),
        }
    }
    let stream = match stream {
        Some(stream) => stream,
        None => {
            return Err(Error::Io(last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Other, "connect failed")
            })));
        }
    };
    stream.set_read_timeout(Some(TRACKER_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(TRACKER_IO_TIMEOUT))?;
    match parsed.scheme {
        Scheme::Http => Ok(TrackerStream::Plain(stream)),
        Scheme::Https => {
            let connector = TlsConnector::new()?;
            let stream = connector
                .connect(&parsed.host, stream)
                .map_err(|err| match err {
                    native_tls::HandshakeError::Failure(err) => Error::Tls(err),
                    native_tls::HandshakeError::WouldBlock(_) => Error::Io(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "tls handshake would block",
                    )),
                })?;
            Ok(TrackerStream::Tls(stream))
        }
    }
}

fn append_query(path: &str, query: &str) -> String {
    if path.contains('?') {
        format!("{path}&{query}")
    } else {
        format!("{path}?{query}")
    }
}

fn build_query(
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    uploaded: u64,
    downloaded: u64,
    left: u64,
    event: Option<&str>,
    numwant: u32,
) -> String {
    let mut query = String::new();
    push_query(&mut query, "info_hash", &percent_encode(&info_hash));
    push_query(&mut query, "peer_id", &percent_encode(&peer_id));
    push_query(&mut query, "port", &port.to_string());
    push_query(&mut query, "uploaded", &uploaded.to_string());
    push_query(&mut query, "downloaded", &downloaded.to_string());
    push_query(&mut query, "left", &left.to_string());
    push_query(&mut query, "compact", "1");
    if numwant > 0 {
        push_query(&mut query, "numwant", &numwant.to_string());
    }
    if let Some(event) = event {
        if !event.is_empty() {
            push_query(&mut query, "event", event);
        }
    }
    query
}

fn push_query(target: &mut String, key: &str, value: &str) {
    if !target.is_empty() {
        target.push('&');
    }
    target.push_str(key);
    target.push('=');
    target.push_str(value);
}

fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        if is_unreserved(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

fn is_unreserved(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

fn parse_http_response(data: &[u8]) -> Result<HttpResponse, Error> {
    let header_end = find_header_end(data).ok_or(Error::HttpParse)?;
    let (header_bytes, body) = data.split_at(header_end);
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.lines();
    let status_line = lines.next().ok_or(Error::HttpParse)?;
    let status = parse_status(status_line)?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            headers.push((name.clone(), value.to_string()));
            if name == "content-length" {
                content_length = value.parse::<usize>().ok();
            } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }

    let body = &body[4..];
    let body = if chunked {
        decode_chunked(body)?
    } else if let Some(len) = content_length {
        if body.len() < len {
            return Err(Error::HttpParse);
        }
        body[..len].to_vec()
    } else {
        body.to_vec()
    };
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let name = name.to_ascii_lowercase();
    headers.iter().find_map(|(key, value)| {
        if *key == name {
            Some(value.clone())
        } else {
            None
        }
    })
}

fn resolve_location(parsed: &ParsedUrl, location: &str) -> Result<String, Error> {
    let location = location.trim();
    if location.is_empty() {
        return Err(Error::InvalidUrl);
    }
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(location.to_string());
    }
    let scheme = match parsed.scheme {
        Scheme::Http => "http",
        Scheme::Https => "https",
    };
    if let Some(rest) = location.strip_prefix("//") {
        return Ok(format!("{scheme}://{rest}"));
    }
    let base = format_base(parsed, scheme);
    if location.starts_with('/') {
        return Ok(format!("{base}{location}"));
    }
    let base_dir = match parsed.path.rsplit_once('/') {
        Some((dir, _)) if !dir.is_empty() => dir,
        _ => "/",
    };
    let mut path = base_dir.to_string();
    if !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(location);
    Ok(format!("{base}{path}"))
}

fn format_base(parsed: &ParsedUrl, scheme: &str) -> String {
    let default_port = match parsed.scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    if parsed.port == default_port {
        format!("{scheme}://{}", parsed.host)
    } else {
        format!("{scheme}://{}:{}", parsed.host, parsed.port)
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_status(line: &str) -> Result<u16, Error> {
    let mut parts = line.split_whitespace();
    let _http = parts.next().ok_or(Error::HttpParse)?;
    let status = parts.next().ok_or(Error::HttpParse)?;
    status.parse::<u16>().map_err(|_| Error::HttpParse)
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut pos = 0;
    let mut out = Vec::new();
    loop {
        let line_end = find_crlf(body, pos).ok_or(Error::HttpParse)?;
        let line = &body[pos..line_end];
        let line_str = std::str::from_utf8(line).map_err(|_| Error::HttpParse)?;
        let size = usize::from_str_radix(line_str.trim(), 16).map_err(|_| Error::HttpParse)?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        if pos + size > body.len() {
            return Err(Error::HttpParse);
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size;
        if body.get(pos) != Some(&b'\r') || body.get(pos + 1) != Some(&b'\n') {
            return Err(Error::HttpParse);
        }
        pos += 2;
    }
    Ok(out)
}

fn find_crlf(data: &[u8], start: usize) -> Option<usize> {
    data[start..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|pos| start + pos)
}

fn parse_tracker_body(body: &[u8]) -> Result<TrackerResponse, Error> {
    let value = bencode::parse(body)?;
    let dict = match value {
        Value::Dict(items) => items,
        _ => return Err(Error::InvalidField("response")),
    };

    if let Some(reason) = dict_get_bytes(&dict, b"failure reason") {
        let reason = String::from_utf8_lossy(&reason).into_owned();
        return Err(Error::FailureReason(reason));
    }

    let interval = dict_get_int(&dict, b"interval").ok_or(Error::MissingField("interval"))?;
    let mut peers = Vec::new();
    let mut saw_peers = false;

    // Check for "complete" and "incomplete" fields (seeders/leechers)
    if let Some(complete) = dict_get_int(&dict, b"complete") {
        crate::log_stderr(format_args!("  tracker: {} seeders", complete));
    }
    if let Some(incomplete) = dict_get_int(&dict, b"incomplete") {
        crate::log_stderr(format_args!("  tracker: {} leechers", incomplete));
    }

    if let Some(peers_value) = dict_get(&dict, b"peers") {
        saw_peers = true;
        let parsed = parse_peers(peers_value)?;
        crate::log_stderr(format_args!(
            "  tracker: peers field has {} entries",
            parsed.len()
        ));
        peers.extend(parsed);
    }
    if let Some(peers6_value) = dict_get(&dict, b"peers6") {
        saw_peers = true;
        let parsed = parse_peers6(peers6_value)?;
        crate::log_stderr(format_args!(
            "  tracker: peers6 field has {} entries",
            parsed.len()
        ));
        peers.extend(parsed);
    }
    if !saw_peers {
        return Err(Error::MissingField("peers"));
    }

    Ok(TrackerResponse { interval, peers })
}

fn parse_peers(value: &Value) -> Result<Vec<SocketAddr>, Error> {
    match value {
        Value::Bytes(bytes) => parse_compact_peers(bytes),
        Value::List(list) => parse_dict_peers(list),
        _ => Err(Error::InvalidField("peers")),
    }
}

fn parse_compact_peers(bytes: &[u8]) -> Result<Vec<SocketAddr>, Error> {
    if bytes.len() % 6 != 0 {
        return Err(Error::InvalidPeers);
    }
    let mut peers = Vec::with_capacity(bytes.len() / 6);
    for chunk in bytes.chunks_exact(6) {
        let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        let port = u16::from_be_bytes([chunk[4], chunk[5]]);
        peers.push(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }
    Ok(peers)
}

fn parse_peers6(value: &Value) -> Result<Vec<SocketAddr>, Error> {
    match value {
        Value::Bytes(bytes) => parse_compact_peers6(bytes),
        Value::List(list) => parse_dict_peers(list),
        _ => Err(Error::InvalidField("peers6")),
    }
}

fn parse_compact_peers6(bytes: &[u8]) -> Result<Vec<SocketAddr>, Error> {
    if bytes.len() % 18 != 0 {
        return Err(Error::InvalidPeers);
    }
    let mut peers = Vec::with_capacity(bytes.len() / 18);
    for chunk in bytes.chunks_exact(18) {
        let ip = Ipv6Addr::from([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15],
        ]);
        let port = u16::from_be_bytes([chunk[16], chunk[17]]);
        peers.push(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)));
    }
    Ok(peers)
}
fn parse_dict_peers(list: &[Value]) -> Result<Vec<SocketAddr>, Error> {
    let mut peers = Vec::with_capacity(list.len());
    for entry in list {
        let dict = match entry {
            Value::Dict(items) => items,
            _ => return Err(Error::InvalidPeers),
        };
        let ip_value = dict_get(dict, b"ip").ok_or(Error::MissingField("ip"))?;
        let port = dict_get_int(dict, b"port").ok_or(Error::MissingField("port"))?;
        let ip_str = match ip_value {
            Value::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            _ => return Err(Error::InvalidField("ip")),
        };
        let ip = ip_str.parse().map_err(|_| Error::InvalidField("ip"))?;
        peers.push(SocketAddr::new(ip, port as u16));
    }
    Ok(peers)
}

fn dict_get<'a>(dict: &'a [(Vec<u8>, Value)], key: &[u8]) -> Option<&'a Value> {
    dict.iter()
        .find_map(|(k, v)| if k.as_slice() == key { Some(v) } else { None })
}

fn dict_get_bytes(dict: &[(Vec<u8>, Value)], key: &[u8]) -> Option<Vec<u8>> {
    dict_get(dict, key).and_then(|value| match value {
        Value::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    })
}

fn dict_get_int(dict: &[(Vec<u8>, Value)], key: &[u8]) -> Option<u64> {
    dict_get(dict, key).and_then(|value| match value {
        Value::Int(num) if *num >= 0 => Some(*num as u64),
        _ => None,
    })
}

#[derive(Debug, Clone)]
pub struct ScrapeResult {
    pub seeders: u32,
    pub leechers: u32,
    pub completed: u32,
}

pub fn scrape(announce_url: &str, info_hash: [u8; 20]) -> Result<ScrapeResult, Error> {
    let scrape_url = announce_to_scrape_url(announce_url)?;
    let query = format!("info_hash={}", percent_encode(&info_hash));
    let parsed = parse_url(&scrape_url)?;
    let path = append_query(&parsed.path, &query);

    let mut stream = connect_stream(&parsed)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rustorrent/0.1\r\nConnection: close\r\n\r\n",
        parsed.host
    );
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let response = parse_http_response(&response)?;
    if response.status != 200 {
        return Err(Error::HttpStatus(response.status));
    }

    let value = bencode::parse(&response.body)?;
    let dict = match value {
        Value::Dict(items) => items,
        _ => return Err(Error::InvalidField("scrape response")),
    };
    let files = match dict_get(&dict, b"files") {
        Some(Value::Dict(files)) => files,
        _ => return Err(Error::MissingField("files")),
    };

    for (key, val) in files {
        if key.len() == 20 && key.as_slice() == info_hash {
            if let Value::Dict(stats) = val {
                let seeders = dict_get_int(stats, b"complete").unwrap_or(0) as u32;
                let leechers = dict_get_int(stats, b"incomplete").unwrap_or(0) as u32;
                let completed = dict_get_int(stats, b"downloaded").unwrap_or(0) as u32;
                return Ok(ScrapeResult {
                    seeders,
                    leechers,
                    completed,
                });
            }
        }
    }
    Err(Error::MissingField("info_hash in scrape"))
}

fn announce_to_scrape_url(url: &str) -> Result<String, Error> {
    if let Some(pos) = url.rfind("/announce") {
        let prefix = &url[..pos];
        let suffix = &url[pos + 9..]; // skip "/announce"
        Ok(format!("{prefix}/scrape{suffix}"))
    } else {
        Err(Error::InvalidUrl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encodes_bytes() {
        let encoded = percent_encode(b"\x01a z");
        assert_eq!(encoded, "%01a%20z");
    }

    #[test]
    fn parse_compact_peer_list() {
        let bytes = [127, 0, 0, 1, 0x1A, 0xE1, 10, 0, 0, 2, 0x00, 0x50];
        let peers = parse_compact_peers(&bytes).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], "127.0.0.1:6881".parse().unwrap());
        assert_eq!(peers[1], "10.0.0.2:80".parse().unwrap());
    }

    #[test]
    fn parse_compact_peer_list_v6() {
        let bytes = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1A, 0xE1,
        ];
        let peers = parse_compact_peers6(&bytes).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], "[2001:db8::1]:6881".parse().unwrap());
    }

    #[test]
    fn parse_compact_peers_rejects_invalid_length() {
        assert!(matches!(
            parse_compact_peers(&[1, 2, 3]),
            Err(Error::InvalidPeers)
        ));
        assert!(matches!(
            parse_compact_peers6(&[0u8; 17]),
            Err(Error::InvalidPeers)
        ));
    }

    #[test]
    fn parse_tracker_body_handles_failure_reason() {
        let body = bencode::encode(&Value::Dict(vec![(
            b"failure reason".to_vec(),
            Value::Bytes(b"denied".to_vec()),
        )]));
        let err = parse_tracker_body(&body).unwrap_err();
        match err {
            Error::FailureReason(reason) => assert_eq!(reason, "denied"),
            other => panic!("unexpected error: {other}"),
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
        assert_eq!(parsed.peers.len(), 2);
        assert_eq!(parsed.peers[0], "127.0.0.1:6881".parse().unwrap());
        assert_eq!(parsed.peers[1], "10.0.0.2:80".parse().unwrap());
    }

    #[test]
    fn announce_url_maps_to_scrape_url() {
        assert_eq!(
            announce_to_scrape_url("http://tracker.example/announce").unwrap(),
            "http://tracker.example/scrape"
        );
        assert_eq!(
            announce_to_scrape_url("http://tracker.example/announce?x=1").unwrap(),
            "http://tracker.example/scrape?x=1"
        );
        assert!(announce_to_scrape_url("http://tracker.example/a").is_err());
    }

    #[test]
    fn resolve_location_supports_relative_redirects() {
        let parsed = parse_url("http://tracker.example:8080/path/announce").unwrap();
        assert_eq!(
            resolve_location(&parsed, "/new").unwrap(),
            "http://tracker.example:8080/new"
        );
        assert_eq!(
            resolve_location(&parsed, "next").unwrap(),
            "http://tracker.example:8080/path/next"
        );
        assert_eq!(
            resolve_location(&parsed, "//cdn.example/x").unwrap(),
            "http://cdn.example/x"
        );
    }

    #[test]
    fn parse_http_response_supports_chunked_body() {
        let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let response = parse_http_response(data).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"abc");
    }
}

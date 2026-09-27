use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use native_tls::{HandshakeError, TlsConnector, TlsStream};

use crate::proxy::ProxyConfig;

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_IO_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const HTTP_IO_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TLS_HANDSHAKE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_REDIRECTS: usize = 5;
const MAX_RESOLVED_ADDRESSES: usize = 16;
const MAX_RESOLVER_WORKERS: usize = 32;
static ACTIVE_RESOLVERS: AtomicUsize = AtomicUsize::new(0);

struct ResolverGuard;

impl Drop for ResolverGuard {
    fn drop(&mut self) {
        ACTIVE_RESOLVERS.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy)]
struct RequestBudget<'a> {
    deadline: Instant,
    cancel: Option<&'a AtomicBool>,
}

impl<'a> RequestBudget<'a> {
    fn new(deadline: Instant, cancel: Option<&'a AtomicBool>) -> Self {
        Self { deadline, cancel }
    }

    fn remaining(self) -> Result<Duration, String> {
        if self
            .cancel
            .is_some_and(|cancel| cancel.load(Ordering::SeqCst))
        {
            return Err("http request cancelled".to_string());
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "http request deadline exceeded".to_string())
    }

    fn io_timeout(self, idle_deadline: Instant) -> Result<Duration, String> {
        let request_remaining = self.remaining()?;
        let idle_remaining = idle_deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "http I/O timed out".to_string())?;
        Ok(request_remaining
            .min(idle_remaining)
            .min(HTTP_IO_POLL_INTERVAL))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Http,
    Https,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AddressPolicy {
    Any,
    PublicOnly,
}

struct ParsedUrl {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

struct Origin {
    scheme: Scheme,
    host: String,
    port: u16,
}

impl From<&ParsedUrl> for Origin {
    fn from(parsed: &ParsedUrl) -> Self {
        Self {
            scheme: parsed.scheme,
            host: parsed.host.to_ascii_lowercase(),
            port: parsed.port,
        }
    }
}

impl Origin {
    fn matches(&self, parsed: &ParsedUrl) -> bool {
        self.scheme == parsed.scheme
            && self.host.eq_ignore_ascii_case(&parsed.host)
            && self.port == parsed.port
    }
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// One logical request: every redirect hop shares these limits.
struct Request<'a> {
    headers: &'a [(&'a str, String)],
    max_bytes: usize,
    budget: RequestBudget<'a>,
    policy: AddressPolicy,
    same_origin: bool,
    proxy: Option<&'a ProxyConfig>,
}

impl<'a> Request<'a> {
    fn public(max_bytes: usize, budget: RequestBudget<'a>) -> Self {
        Self {
            headers: &[],
            max_bytes,
            budget,
            policy: AddressPolicy::PublicOnly,
            same_origin: false,
            proxy: None,
        }
    }
}

enum HttpStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

trait DeadlineStream: Read + Write {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}

impl HttpStream {
    fn tcp(&self) -> &TcpStream {
        match self {
            HttpStream::Plain(stream) => stream,
            HttpStream::Tls(stream) => stream.get_ref(),
        }
    }
}

impl DeadlineStream for HttpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.tcp().set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.tcp().set_write_timeout(timeout)
    }
}

impl Read for HttpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            HttpStream::Plain(stream) => stream.read(buf),
            HttpStream::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for HttpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            HttpStream::Plain(stream) => stream.write(buf),
            HttpStream::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            HttpStream::Plain(stream) => stream.flush(),
            HttpStream::Tls(stream) => stream.flush(),
        }
    }
}

fn default_budget() -> RequestBudget<'static> {
    RequestBudget::new(Instant::now() + HTTP_REQUEST_TIMEOUT, None)
}

pub fn get_public(url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    get(url, &Request::public(max_bytes, default_budget()))
}

/// Conservative logical heap allowance for one response while the bounded
/// wire representation, parsed body, and copied headers can coexist.
#[cfg_attr(not(feature = "webseed"), allow(dead_code))]
pub(crate) fn response_memory_budget(max_body: usize) -> Option<usize> {
    max_body
        .checked_mul(3)?
        .checked_add(MAX_HTTP_HEADER_BYTES.checked_mul(2)?)
}

#[cfg(feature = "upnp")]
pub fn get_same_origin(url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let request = Request {
        policy: AddressPolicy::Any,
        same_origin: true,
        ..Request::public(max_bytes, default_budget())
    };
    get(url, &request)
}

pub(crate) fn get_public_until(
    url: &str,
    max_bytes: usize,
    deadline: Instant,
    cancel: Option<&AtomicBool>,
) -> Result<Vec<u8>, String> {
    get(
        url,
        &Request::public(max_bytes, RequestBudget::new(deadline, cancel)),
    )
}

/// Tracker announce: optionally tunnelled through a proxy, which then
/// resolves the tracker's name itself.
pub(crate) fn get_tracker(
    url: &str,
    max_bytes: usize,
    deadline: Instant,
    proxy: Option<&ProxyConfig>,
    public_only: bool,
) -> Result<Vec<u8>, String> {
    let request = Request {
        policy: if public_only {
            AddressPolicy::PublicOnly
        } else {
            AddressPolicy::Any
        },
        proxy,
        ..Request::public(max_bytes, RequestBudget::new(deadline, None))
    };
    get(url, &request)
}

#[cfg(feature = "webseed")]
pub fn get_range_public(
    url: &str,
    start: u64,
    end: u64,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let headers = [("Range", format!("bytes={start}-{end}"))];
    let request = Request {
        headers: &headers,
        ..Request::public(max_bytes, default_budget())
    };
    get(url, &request)
}

fn get(url: &str, request: &Request<'_>) -> Result<Vec<u8>, String> {
    let mut url = url.to_string();
    let origin = if request.same_origin {
        Some(Origin::from(&parse_url(&url)?))
    } else {
        None
    };
    for _ in 0..MAX_REDIRECTS {
        request.budget.remaining()?;
        let parsed = parse_url(&url)?;
        let response = request_once(&parsed, "GET", &[], request)?;
        if !is_redirect(response.status) {
            return success_body(response, request.max_bytes);
        }
        let location = header_value(&response.headers, "location")
            .ok_or_else(|| "http redirect missing location".to_string())?;
        let next_url = resolve_location(&parsed, location)?;
        let next = parse_url(&next_url)?;
        validate_redirect_transport(parsed.scheme, next.scheme)?;
        if origin.as_ref().is_some_and(|origin| !origin.matches(&next)) {
            return Err("cross-origin http redirect refused".to_string());
        }
        url = next_url;
    }
    Err("http redirect limit reached".to_string())
}

fn success_body(response: HttpResponse, max_bytes: usize) -> Result<Vec<u8>, String> {
    if response.status != 200 && response.status != 206 {
        return Err(format!("http status {}", response.status));
    }
    if response.body.len() > max_bytes {
        return Err("http response too large".to_string());
    }
    Ok(response.body)
}

fn validate_redirect_transport(current: Scheme, next: Scheme) -> Result<(), String> {
    if current == Scheme::Https && next != Scheme::Https {
        return Err("https redirect downgrade refused".to_string());
    }
    Ok(())
}

fn request_once(
    parsed: &ParsedUrl,
    method: &str,
    body: &[u8],
    request: &Request<'_>,
) -> Result<HttpResponse, String> {
    validate_headers(request.headers)?;
    let budget = request.budget;
    let mut stream = connect_stream(parsed, request)?;
    let mut head = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rustorrent/0.1\r\nConnection: close\r\n",
        parsed.path,
        format_authority(parsed)
    );
    if method != "GET" {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (key, value) in request.headers {
        head.push_str(key);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    write_all_bounded(&mut stream, head.as_bytes(), budget)?;
    write_all_bounded(&mut stream, body, budget)?;

    let response = read_response_limited(&mut stream, request.max_bytes, budget)?;
    budget.remaining()?;
    parse_http_response(&response)
}

fn validate_headers(headers: &[(&str, String)]) -> Result<(), String> {
    for (name, value) in headers {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
        {
            return Err("invalid http header".to_string());
        }
    }
    Ok(())
}

fn is_retryable_io(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
    )
}

fn write_all_bounded<S: DeadlineStream>(
    stream: &mut S,
    mut bytes: &[u8],
    budget: RequestBudget<'_>,
) -> Result<(), String> {
    let mut idle_deadline = Instant::now() + HTTP_IO_TIMEOUT;
    while !bytes.is_empty() {
        let timeout = budget.io_timeout(idle_deadline)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|err| format!("http write failed: {err}"))?;
        match stream.write(bytes) {
            Ok(0) => return Err("http write failed: connection closed".to_string()),
            Ok(written) => {
                bytes = &bytes[written..];
                idle_deadline = Instant::now() + HTTP_IO_TIMEOUT;
            }
            Err(err) if is_retryable_io(&err) => {}
            Err(err) => return Err(format!("http write failed: {err}")),
        }
    }
    Ok(())
}

fn read_response_limited<S: DeadlineStream>(
    reader: &mut S,
    max_body: usize,
    budget: RequestBudget<'_>,
) -> Result<Vec<u8>, String> {
    // Allow bounded framing overhead for headers and chunk delimiters, but never
    // buffer an unbounded response before applying the caller's body limit.
    let wire_limit = max_body
        .saturating_mul(2)
        .saturating_add(MAX_HTTP_HEADER_BYTES);
    let mut response = Vec::with_capacity(wire_limit.min(8 * 1024));
    let mut chunk = [0u8; 8 * 1024];
    let mut idle_deadline = Instant::now() + HTTP_IO_TIMEOUT;
    loop {
        let timeout = budget.io_timeout(idle_deadline)?;
        reader
            .set_read_timeout(Some(timeout))
            .map_err(|err| format!("http read failed: {err}"))?;
        // `response.len() <= wire_limit` holds here: longer responses fail below.
        let read_len = (wire_limit - response.len())
            .saturating_add(1)
            .min(chunk.len());
        match reader.read(&mut chunk[..read_len]) {
            Ok(0) => return Ok(response),
            Ok(read) => {
                response.extend_from_slice(&chunk[..read]);
                if response.len() > wire_limit {
                    return Err("http response too large".to_string());
                }
                idle_deadline = Instant::now() + HTTP_IO_TIMEOUT;
            }
            Err(err) if is_retryable_io(&err) => {}
            Err(err) => return Err(format!("http read failed: {err}")),
        }
    }
}

fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn resolve_location(parsed: &ParsedUrl, location: &str) -> Result<String, String> {
    let location = location.trim();
    if location.is_empty() {
        return Err("http redirect missing location".to_string());
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
    let base = format!("{scheme}://{}", format_authority(parsed));
    if location.starts_with('/') {
        return Ok(format!("{base}{location}"));
    }
    let base_dir = match parsed.path.rsplit_once('/') {
        Some((dir, _)) => dir.trim_end_matches('/'),
        None => "",
    };
    Ok(format!("{base}{base_dir}/{location}"))
}

#[cfg_attr(not(feature = "upnp"), allow(dead_code))]
pub(crate) fn resolve_url(base: &str, location: &str) -> Result<String, String> {
    resolve_location(&parse_url(base)?, location)
}

#[cfg_attr(not(feature = "upnp"), allow(dead_code))]
pub(crate) fn url_host_ip(url: &str) -> Option<IpAddr> {
    parse_url(url).ok()?.host.parse().ok()
}

#[cfg_attr(not(feature = "upnp"), allow(dead_code))]
pub(crate) fn same_origin(first: &str, second: &str) -> bool {
    let (Ok(first), Ok(second)) = (parse_url(first), parse_url(second)) else {
        return false;
    };
    Origin::from(&first).matches(&second)
}

fn format_authority(parsed: &ParsedUrl) -> String {
    let default_port = match parsed.scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    let bracketed = parsed.host.contains(':');
    match (bracketed, parsed.port == default_port) {
        (false, true) => parsed.host.clone(),
        (false, false) => format!("{}:{}", parsed.host, parsed.port),
        (true, true) => format!("[{}]", parsed.host),
        (true, false) => format!("[{}]:{}", parsed.host, parsed.port),
    }
}

#[cfg(feature = "upnp")]
pub fn post(
    url: &str,
    headers: &[(&str, String)],
    body: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let request = Request {
        headers,
        policy: AddressPolicy::Any,
        ..Request::public(max_bytes, default_budget())
    };
    let response = request_once(&parse_url(url)?, "POST", body, &request)?;
    if response.status >= 400 {
        // UPnP routers explain a refusal in a SOAP fault's errorCode.
        let text = String::from_utf8_lossy(&response.body);
        if let Some(code) = text
            .split_once("<errorCode>")
            .and_then(|(_, rest)| rest.split_once("</errorCode>"))
            .and_then(|(code, _)| code.trim().parse::<u16>().ok())
        {
            return Err(format!("upnp error {code}"));
        }
    }
    success_body(response, max_bytes)
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let invalid = || "invalid url".to_string();
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else if let Some(rest) = url.strip_prefix("https://") {
        (Scheme::Https, rest)
    } else {
        return Err("unsupported scheme".to_string());
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (host_port, suffix) = rest.split_at(authority_end);
    let suffix = suffix.split_once('#').map_or(suffix, |(s, _)| s);
    let path = if suffix.is_empty() {
        "/".to_string()
    } else if suffix.starts_with('?') {
        format!("/{suffix}")
    } else {
        suffix.to_string()
    };
    if host_port.is_empty()
        || host_port
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || host_port.contains(['@', '\\'])
        || path.bytes().any(|b| b.is_ascii_control() || b == b' ')
    {
        return Err(invalid());
    }
    let default_port = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    let (host, port) = if let Some(rest) = host_port.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(invalid)?;
        host.parse::<Ipv6Addr>().map_err(|_| invalid())?;
        let port = match tail {
            "" => Some(default_port),
            tail => tail.strip_prefix(':').and_then(|port| port.parse().ok()),
        };
        (host, port)
    } else {
        if host_port.contains(['[', ']']) || host_port.matches(':').count() > 1 {
            return Err(invalid());
        }
        match host_port.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().ok()),
            None => (host_port, Some(default_port)),
        }
    };
    match port {
        Some(port) if port != 0 && !host.is_empty() => Ok(ParsedUrl {
            scheme,
            host: host.to_string(),
            port,
            path,
        }),
        _ => Err(invalid()),
    }
}

fn connect_stream(parsed: &ParsedUrl, request: &Request<'_>) -> Result<HttpStream, String> {
    let budget = request.budget;
    let stream = if let Some(proxy) = request.proxy {
        if request.policy == AddressPolicy::PublicOnly {
            validate_proxy_target_host(&parsed.host)?;
        }
        let timeout = budget.remaining()?.min(HTTP_CONNECT_TIMEOUT);
        crate::proxy::connect_through_proxy_host(proxy, &parsed.host, parsed.port, timeout)?
    } else {
        let connect_deadline = Instant::now() + HTTP_CONNECT_TIMEOUT;
        let mut last_err = "http host resolved to no addresses".to_string();
        let mut connected = None;
        for addr in resolve_http_addrs(&parsed.host, parsed.port, budget, request.policy)? {
            let Some(connect_remaining) = connect_deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
            else {
                break;
            };
            let remaining = budget.remaining()?.min(connect_remaining);
            match TcpStream::connect_timeout(&addr, remaining) {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(err) => last_err = err.to_string(),
            }
        }
        connected.ok_or(last_err)?
    };
    budget.remaining()?;
    match parsed.scheme {
        Scheme::Http => Ok(HttpStream::Plain(stream)),
        Scheme::Https => {
            let connector = TlsConnector::new().map_err(|err| err.to_string())?;
            let stream = connect_tls(&connector, &parsed.host, stream, budget)?;
            Ok(HttpStream::Tls(Box::new(stream)))
        }
    }
}

/// With a proxy the target name is resolved by the proxy, so refuse names
/// that obviously denote local services when only public targets are allowed.
fn validate_proxy_target_host(host: &str) -> Result<(), String> {
    let refused = || Err("http target is not publicly routable".to_string());
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if is_public_http_ip(ip) {
            Ok(())
        } else {
            refused()
        };
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host == "home.arpa"
        || host.ends_with(".home.arpa")
    {
        return refused();
    }
    Ok(())
}

fn resolve_http_addrs(
    host: &str,
    port: u16,
    budget: RequestBudget<'_>,
    policy: AddressPolicy,
) -> Result<Vec<SocketAddr>, String> {
    let addrs: Vec<SocketAddr> = resolve_host_budget(host, port, budget)?
        .into_iter()
        .filter(|addr| policy == AddressPolicy::Any || is_public_http_ip(addr.ip()))
        .collect();
    if addrs.is_empty() {
        return Err("http target is not publicly routable".to_string());
    }
    Ok(addrs)
}

/// Resolves `host:port` with a deadline. Name lookups run on a bounded pool
/// of detached threads because the system resolver cannot be interrupted.
pub(crate) fn resolve_host(
    host: &str,
    port: u16,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, String> {
    resolve_host_budget(host, port, RequestBudget::new(deadline, None))
}

fn resolve_host_budget(
    host: &str,
    port: u16,
    budget: RequestBudget<'_>,
) -> Result<Vec<SocketAddr>, String> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if ACTIVE_RESOLVERS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
            (active < MAX_RESOLVER_WORKERS).then_some(active + 1)
        })
        .is_err()
    {
        return Err("resolver limit reached".to_string());
    }
    let query = (host.to_string(), port);
    let (tx, rx) = mpsc::sync_channel(1);
    let spawned = thread::Builder::new()
        .name("resolver".to_string())
        .spawn(move || {
            let _guard = ResolverGuard;
            let resolved = query
                .to_socket_addrs()
                .map(|addrs| {
                    let mut unique = Vec::new();
                    for addr in addrs.take(MAX_RESOLVED_ADDRESSES) {
                        if !unique.contains(&addr) {
                            unique.push(addr);
                        }
                    }
                    unique
                })
                .map_err(|err| format!("resolve {}: {err}", query.0));
            let _ = tx.try_send(resolved);
        });
    if let Err(err) = spawned {
        ACTIVE_RESOLVERS.fetch_sub(1, Ordering::AcqRel);
        return Err(format!("resolver thread failed: {err}"));
    }
    loop {
        // Poll so a cancellation flag is observed while the lookup runs.
        let wait = budget.remaining()?.min(HTTP_IO_POLL_INTERVAL);
        match rx.recv_timeout(wait) {
            Ok(Ok(addrs)) if addrs.is_empty() => {
                return Err("host resolved to no addresses".to_string());
            }
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("resolver disconnected".to_string());
            }
        }
    }
}

pub(crate) fn is_public_http_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && octets[0] != 0
                && octets[0] < 240
                && !(octets[0] == 100 && (octets[1] & 0xc0) == 0x40)
                && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                && !(octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                && !(octets[0] == 198 && matches!(octets[1], 18 | 19))
                && !(octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                && !(octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return is_public_http_ip(IpAddr::V4(ipv4));
            }
            let segments = ip.segments();
            // Public IPv6 unicast is currently allocated from 2000::/3.
            // Explicitly reject special-purpose subranges that can embed or
            // route to local IPv4, benchmarking, or documentation targets.
            (segments[0] & 0xe000) == 0x2000
                && !(segments[0] == 0x2001 && (segments[1] & 0xfe00) == 0)
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && segments[0] != 0x2002
                && (segments[0] & 0xfff0) != 0x3ff0
        }
    }
}

fn connect_tls(
    connector: &TlsConnector,
    host: &str,
    stream: TcpStream,
    budget: RequestBudget<'_>,
) -> Result<TlsStream<TcpStream>, String> {
    let setup_err = |err: std::io::Error| format!("tls setup failed: {err}");
    stream.set_nonblocking(true).map_err(setup_err)?;
    let mut attempt = connector.connect(host, stream);
    loop {
        match attempt {
            Ok(stream) => {
                stream.get_ref().set_nonblocking(false).map_err(setup_err)?;
                return Ok(stream);
            }
            Err(HandshakeError::Failure(err)) => return Err(err.to_string()),
            Err(HandshakeError::WouldBlock(mid)) => {
                let remaining = budget.remaining()?;
                thread::sleep(remaining.min(TLS_HANDSHAKE_POLL_INTERVAL));
                budget.remaining()?;
                attempt = mid.handshake();
            }
        }
    }
}

fn parse_http_response(data: &[u8]) -> Result<HttpResponse, String> {
    let parse_err = || "http parse error".to_string();
    let header_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(parse_err)?;
    if header_end > MAX_HTTP_HEADER_BYTES {
        return Err("http response headers too large".to_string());
    }
    let body = &data[header_end + 4..];
    let header_str = std::str::from_utf8(&data[..header_end]).map_err(|_| parse_err())?;
    let mut lines = header_str.split("\r\n");
    let status = lines.next().and_then(parse_status).ok_or_else(parse_err)?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or_else(parse_err)?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name.is_empty() || value.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
            return Err(parse_err());
        }
        if name == "content-length" {
            let parsed = value.parse::<usize>().map_err(|_| parse_err())?;
            if content_length
                .replace(parsed)
                .is_some_and(|old| old != parsed)
            {
                return Err(parse_err());
            }
        } else if name == "transfer-encoding"
            && value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
        headers.push((name, value.to_string()));
    }

    let body = if chunked {
        decode_chunked(body).ok_or_else(parse_err)?
    } else if let Some(len) = content_length {
        body.get(..len).ok_or_else(parse_err)?.to_vec()
    } else {
        body.to_vec()
    };
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn parse_status(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    if !matches!(parts.next()?, "HTTP/1.0" | "HTTP/1.1") {
        return None;
    }
    let status = parts.next()?;
    if status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    status.parse().ok()
}

fn decode_chunked(body: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0;
    let mut out = Vec::new();
    loop {
        let line_len = body
            .get(pos..)?
            .windows(2)
            .position(|window| window == b"\r\n")?;
        let line = std::str::from_utf8(&body[pos..pos + line_len]).ok()?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() || !size_text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let size = usize::from_str_radix(size_text, 16).ok()?;
        pos += line_len + 2;
        if size == 0 {
            // Accept an empty trailer section or header-style trailers.
            let rest = &body[pos..];
            return (rest.starts_with(b"\r\n") || rest.windows(4).any(|w| w == b"\r\n\r\n"))
                .then_some(out);
        }
        let end = pos.checked_add(size)?;
        out.extend_from_slice(body.get(pos..end)?);
        if body.get(end..end.checked_add(2)?)? != b"\r\n" {
            return None;
        }
        pos = end + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_memory_budget_is_checked_and_covers_parser_copies() {
        assert_eq!(response_memory_budget(1024), Some(3 * 1024 + 128 * 1024));
        assert_eq!(response_memory_budget(usize::MAX), None);
    }

    struct SlowStream<'a> {
        data: &'a [u8],
        position: usize,
        delay: Duration,
        cancel: Option<&'a AtomicBool>,
        cancel_after: usize,
    }

    impl Read for SlowStream<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.position >= self.data.len() || buf.is_empty() {
                return Ok(0);
            }
            thread::sleep(self.delay);
            buf[0] = self.data[self.position];
            self.position += 1;
            if self.position == self.cancel_after {
                if let Some(cancel) = self.cancel {
                    cancel.store(true, Ordering::SeqCst);
                }
            }
            Ok(1)
        }
    }

    impl Write for SlowStream<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl DeadlineStream for SlowStream<'_> {
        fn set_read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn response_reader_enforces_absolute_deadline_against_slow_trickle() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut stream = SlowStream {
            data,
            position: 0,
            delay: Duration::from_millis(5),
            cancel: None,
            cancel_after: usize::MAX,
        };
        let started = Instant::now();
        let err = read_response_limited(
            &mut stream,
            1024,
            RequestBudget::new(started + Duration::from_millis(35), None),
        )
        .unwrap_err();
        assert!(err.contains("deadline exceeded"), "unexpected error: {err}");
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn response_reader_observes_cancellation_between_reads() {
        let cancel = AtomicBool::new(false);
        let mut stream = SlowStream {
            data: b"HTTP/1.1 200 OK\r\n\r\nbody",
            position: 0,
            delay: Duration::from_millis(1),
            cancel: Some(&cancel),
            cancel_after: 3,
        };
        let err = read_response_limited(
            &mut stream,
            1024,
            RequestBudget::new(Instant::now() + Duration::from_secs(1), Some(&cancel)),
        )
        .unwrap_err();
        assert_eq!(err, "http request cancelled");
    }

    #[test]
    fn parse_url_defaults_port_and_path() {
        let parsed = parse_url("http://example.com").unwrap();
        assert!(matches!(parsed.scheme, Scheme::Http));
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 80);
        assert_eq!(parsed.path, "/");

        let parsed = parse_url("https://example.com/path/to/file").unwrap();
        assert!(matches!(parsed.scheme, Scheme::Https));
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/path/to/file");

        let parsed = parse_url("http://[2001:db8::1]:8080?x=1#ignored").unwrap();
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.path, "/?x=1");
        assert_eq!(format_authority(&parsed), "[2001:db8::1]:8080");
    }

    #[test]
    fn parse_url_rejects_invalid_inputs() {
        assert!(parse_url("ftp://example.com").is_err());
        assert!(parse_url("http://").is_err());
        assert!(parse_url("http://example.com:99999").is_err());
        assert!(parse_url("http://example.com:0").is_err());
        assert!(parse_url("http://user@example.com/").is_err());
        assert!(parse_url("http://example.com/ok\r\nX-Test: bad").is_err());
    }

    #[test]
    fn resolve_location_handles_absolute_and_relative() {
        let parsed = parse_url("https://example.com:8443/dir/file").unwrap();
        assert_eq!(
            resolve_location(&parsed, "https://other/path").unwrap(),
            "https://other/path"
        );
        assert_eq!(
            resolve_location(&parsed, "//mirror/path").unwrap(),
            "https://mirror/path"
        );
        assert_eq!(
            resolve_location(&parsed, "/root").unwrap(),
            "https://example.com:8443/root"
        );
        assert_eq!(
            resolve_location(&parsed, "next.txt").unwrap(),
            "https://example.com:8443/dir/next.txt"
        );
    }

    #[test]
    fn redirects_never_downgrade_https_transport() {
        assert!(validate_redirect_transport(Scheme::Https, Scheme::Https).is_ok());
        assert!(validate_redirect_transport(Scheme::Http, Scheme::Https).is_ok());
        assert!(validate_redirect_transport(Scheme::Http, Scheme::Http).is_ok());
        assert!(validate_redirect_transport(Scheme::Https, Scheme::Http).is_err());
    }

    #[cfg(feature = "upnp")]
    #[test]
    fn same_origin_get_refuses_cross_origin_redirect_before_connecting() {
        let destination = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let destination_addr = destination.local_addr().unwrap();
        let source = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let source_addr = source.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = source.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://{destination_addr}/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let err = get_same_origin(&format!("http://{source_addr}/description"), 1024).unwrap_err();
        assert!(err.contains("cross-origin"));
        server.join().unwrap();
        assert!(matches!(
            destination.accept(),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[test]
    fn public_address_policy_rejects_local_and_special_routes() {
        assert!(is_public_http_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_http_ip("2001:4860:4860::8888".parse().unwrap()));

        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "64:ff9b:1::7f00:1",
            "2001:db8::1",
            "2002:7f00:1::",
            "3fff::1",
        ] {
            assert!(
                !is_public_http_ip(address.parse().unwrap()),
                "special-use address accepted: {address}"
            );
        }

        let budget = RequestBudget::new(Instant::now() + Duration::from_secs(1), None);
        assert!(resolve_http_addrs("127.0.0.1", 80, budget, AddressPolicy::PublicOnly).is_err());
        assert!(
            resolve_http_addrs("::ffff:127.0.0.1", 80, budget, AddressPolicy::PublicOnly).is_err()
        );
    }

    #[test]
    fn parse_http_response_with_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: one\r\n\r\nhelloEXTRA";
        let parsed = parse_http_response(response).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"hello");
        assert_eq!(header_value(&parsed.headers, "x-test"), Some("one"));
    }

    #[test]
    fn parse_http_response_with_chunked_transfer() {
        let response = b"HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let parsed = parse_http_response(response).unwrap();
        assert_eq!(parsed.status, 206);
        assert_eq!(parsed.body, b"Wikipedia");
    }

    #[test]
    fn parse_http_response_rejects_truncated_body() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort";
        assert!(parse_http_response(response).is_err());

        let conflicting = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx";
        assert!(parse_http_response(conflicting).is_err());
    }

    #[test]
    fn decode_chunked_rejects_invalid_chunk_layout() {
        assert!(decode_chunked(b"4\r\nabc\r\n0\r\n\r\n").is_none());
        assert!(decode_chunked(b"ZZ\r\nabc\r\n0\r\n\r\n").is_none());
        assert!(decode_chunked(b"FFFFFFFFFFFFFFFFFFFFFFFF\r\nx\r\n0\r\n\r\n").is_none());
    }
}

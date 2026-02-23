use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum ProxyConfig {
    Socks5 { host: String, port: u16 },
    Http { host: String, port: u16 },
}

impl ProxyConfig {
    pub fn parse(url: &str) -> Result<Self, String> {
        let url = url.trim();
        if let Some(rest) = url.strip_prefix("socks5://") {
            let (host, port) = parse_host_port(rest, 1080)?;
            Ok(ProxyConfig::Socks5 { host, port })
        } else if let Some(rest) = url.strip_prefix("http://") {
            let (host, port) = parse_host_port(rest, 8080)?;
            Ok(ProxyConfig::Http { host, port })
        } else {
            Err(format!("unsupported proxy scheme: {url}"))
        }
    }
}

fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    let s = s.trim_end_matches('/');
    if s.is_empty() {
        return Err("empty proxy address".to_string());
    }
    if s.starts_with('[') {
        let bracket_end = s
            .find(']')
            .ok_or_else(|| "invalid proxy address".to_string())?;
        let host = &s[1..bracket_end];
        if host.is_empty() {
            return Err("invalid proxy address".to_string());
        }
        let tail = &s[bracket_end + 1..];
        let port = if tail.is_empty() {
            default_port
        } else if let Some(rest) = tail.strip_prefix(':') {
            rest.parse::<u16>()
                .map_err(|_| "invalid proxy port".to_string())?
        } else {
            return Err("invalid proxy address".to_string());
        };
        return Ok((host.to_string(), port));
    }
    if s.contains(']') {
        return Err("invalid proxy address".to_string());
    }
    if let Some(pos) = s.rfind(':') {
        if let Ok(port) = s[pos + 1..].parse::<u16>() {
            return Ok((s[..pos].to_string(), port));
        }
    }
    Ok((s.to_string(), default_port))
}

pub fn connect_through_proxy(
    config: &ProxyConfig,
    target: SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, String> {
    match config {
        ProxyConfig::Socks5 { host, port } => socks5_connect(host, *port, target, timeout),
        ProxyConfig::Http { host, port } => {
            let target_host = connect_target_host(target);
            http_connect(host, *port, &target_host, target.port(), timeout)
        }
    }
}

fn connect_target_host(target: SocketAddr) -> String {
    match target.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    }
}

fn socks5_connect(
    proxy_host: &str,
    proxy_port: u16,
    target: SocketAddr,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let proxy_addr = resolve_host(proxy_host, proxy_port)?;
    let mut stream = TcpStream::connect_timeout(&proxy_addr, timeout)
        .map_err(|e| format!("socks5 connect to proxy: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("socks5 set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("socks5 set timeout: {e}"))?;

    // Greeting: version 5, 1 auth method (no-auth)
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("socks5 greeting write: {e}"))?;

    let mut auth_resp = [0u8; 2];
    stream
        .read_exact(&mut auth_resp)
        .map_err(|e| format!("socks5 auth response: {e}"))?;
    if auth_resp[0] != 0x05 || auth_resp[1] != 0x00 {
        return Err("socks5 auth rejected".to_string());
    }

    // Connect request
    let mut req = Vec::with_capacity(22);
    req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER, CMD=CONNECT, RSV
    match target.ip() {
        IpAddr::V4(ip) => {
            req.push(0x01); // ATYP = IPv4
            req.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            req.push(0x04); // ATYP = IPv6
            req.extend_from_slice(&ip.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());

    stream
        .write_all(&req)
        .map_err(|e| format!("socks5 connect request: {e}"))?;

    // Read connect response: VER, REP, RSV, ATYP, BIND.ADDR, BIND.PORT
    let mut resp_header = [0u8; 4];
    stream
        .read_exact(&mut resp_header)
        .map_err(|e| format!("socks5 connect response: {e}"))?;
    if resp_header[0] != 0x05 {
        return Err("socks5 invalid version in response".to_string());
    }
    if resp_header[1] != 0x00 {
        return Err(format!("socks5 connect failed: status {}", resp_header[1]));
    }

    // Skip bound address
    match resp_header[3] {
        0x01 => {
            let mut skip = [0u8; 6]; // 4 IP + 2 port
            stream
                .read_exact(&mut skip)
                .map_err(|e| format!("socks5 skip bind addr: {e}"))?;
        }
        0x04 => {
            let mut skip = [0u8; 18]; // 16 IP + 2 port
            stream
                .read_exact(&mut skip)
                .map_err(|e| format!("socks5 skip bind addr: {e}"))?;
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream
                .read_exact(&mut len_buf)
                .map_err(|e| format!("socks5 skip domain len: {e}"))?;
            let mut skip = vec![0u8; len_buf[0] as usize + 2];
            stream
                .read_exact(&mut skip)
                .map_err(|e| format!("socks5 skip domain: {e}"))?;
        }
        _ => {}
    }

    // Remove timeouts for regular use
    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);

    Ok(stream)
}

fn http_connect(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let proxy_addr = resolve_host(proxy_host, proxy_port)?;
    let mut stream = TcpStream::connect_timeout(&proxy_addr, timeout)
        .map_err(|e| format!("http proxy connect: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("http proxy set timeout: {e}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| format!("http proxy set timeout: {e}"))?;

    let request = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("http proxy write: {e}"))?;

    // Read response line
    let mut response = Vec::with_capacity(256);
    let mut buf = [0u8; 1];
    let mut found_end = false;
    for _ in 0..4096 {
        match stream.read_exact(&mut buf) {
            Ok(()) => {
                response.push(buf[0]);
                if response.ends_with(b"\r\n\r\n") {
                    found_end = true;
                    break;
                }
            }
            Err(e) => return Err(format!("http proxy read: {e}")),
        }
    }
    if !found_end {
        return Err("http proxy response too large".to_string());
    }

    let response_str = String::from_utf8_lossy(&response);
    let status_line = response_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("http proxy invalid response".to_string());
    }
    let status: u16 = parts[1]
        .parse()
        .map_err(|_| "http proxy invalid status".to_string())?;
    if status != 200 {
        return Err(format!("http proxy connect failed: status {status}"));
    }

    let _ = stream.set_read_timeout(None);
    let _ = stream.set_write_timeout(None);

    Ok(stream)
}

fn resolve_host(host: &str, port: u16) -> Result<SocketAddr, String> {
    if let Ok(ip4) = host.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::new(IpAddr::V4(ip4), port));
    }
    if let Ok(ip6) = host.parse::<Ipv6Addr>() {
        return Ok(SocketAddr::new(IpAddr::V6(ip6), port));
    }
    use std::net::ToSocketAddrs;
    let addr_str = format!("{host}:{port}");
    addr_str
        .to_socket_addrs()
        .map_err(|e| format!("proxy resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("proxy resolve {host}: no addresses"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_socks5_url() {
        let config = ProxyConfig::parse("socks5://127.0.0.1:1080").unwrap();
        match config {
            ProxyConfig::Socks5 { host, port } => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 1080);
            }
            _ => panic!("expected socks5"),
        }
    }

    #[test]
    fn parse_http_url() {
        let config = ProxyConfig::parse("http://proxy.local:3128").unwrap();
        match config {
            ProxyConfig::Http { host, port } => {
                assert_eq!(host, "proxy.local");
                assert_eq!(port, 3128);
            }
            _ => panic!("expected http"),
        }
    }

    #[test]
    fn parse_socks5_default_port() {
        let config = ProxyConfig::parse("socks5://myproxy").unwrap();
        match config {
            ProxyConfig::Socks5 { host, port } => {
                assert_eq!(host, "myproxy");
                assert_eq!(port, 1080);
            }
            _ => panic!("expected socks5"),
        }
    }

    #[test]
    fn parse_http_default_port() {
        let config = ProxyConfig::parse("http://myproxy").unwrap();
        match config {
            ProxyConfig::Http { host, port } => {
                assert_eq!(host, "myproxy");
                assert_eq!(port, 8080);
            }
            _ => panic!("expected http"),
        }
    }

    #[test]
    fn parse_unsupported_scheme_fails() {
        assert!(ProxyConfig::parse("ftp://proxy").is_err());
    }

    #[test]
    fn parse_trailing_slash_stripped() {
        let config = ProxyConfig::parse("socks5://host:9050/").unwrap();
        match config {
            ProxyConfig::Socks5 { host, port } => {
                assert_eq!(host, "host");
                assert_eq!(port, 9050);
            }
            _ => panic!("expected socks5"),
        }
    }

    #[test]
    fn parse_invalid_bracketed_proxy_fails() {
        assert!(ProxyConfig::parse("socks5://]").is_err());
        assert!(ProxyConfig::parse("socks5://[").is_err());
        assert!(ProxyConfig::parse("socks5://[::1]x").is_err());
    }

    #[test]
    fn connect_target_host_formats_ipv6_with_brackets() {
        let v4: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let v6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(connect_target_host(v4), "127.0.0.1");
        assert_eq!(connect_target_host(v6), "[2001:db8::1]");
    }
}

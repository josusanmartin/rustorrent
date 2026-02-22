use std::io::{Read, Write};
use std::net::TcpStream;

use native_tls::{TlsConnector, TlsStream};

#[derive(Clone, Copy)]
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

enum HttpStream {
    Plain(TcpStream),
    Tls(TlsStream<TcpStream>),
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

pub fn get(url: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    get_with_headers(url, &[], max_bytes)
}

#[cfg(feature = "webseed")]
pub fn get_range(url: &str, start: u64, end: u64, max_bytes: usize) -> Result<Vec<u8>, String> {
    let header = format!("bytes={start}-{end}");
    get_with_headers(url, &[("Range", header)], max_bytes)
}

pub fn get_with_headers(
    url: &str,
    headers: &[(&str, String)],
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    get_with_headers_inner(url, headers, max_bytes, 5)
}

fn get_with_headers_inner(
    url: &str,
    headers: &[(&str, String)],
    max_bytes: usize,
    redirects_left: usize,
) -> Result<Vec<u8>, String> {
    if redirects_left == 0 {
        return Err("http redirect limit reached".to_string());
    }
    let parsed = parse_url(url)?;
    let response = request_once(&parsed, headers)?;
    if is_redirect(response.status) {
        let location = header_value(&response.headers, "location")
            .ok_or_else(|| "http redirect missing location".to_string())?;
        let next_url = resolve_location(&parsed, &location)?;
        return get_with_headers_inner(&next_url, headers, max_bytes, redirects_left - 1);
    }
    if response.status != 200 && response.status != 206 {
        return Err(format!("http status {}", response.status));
    }
    if response.body.len() > max_bytes {
        return Err("http response too large".to_string());
    }
    Ok(response.body)
}

fn request_once(parsed: &ParsedUrl, headers: &[(&str, String)]) -> Result<HttpResponse, String> {
    let mut stream = connect_stream(parsed)?;
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rustorrent/0.1\r\nConnection: close\r\n",
        parsed.path, parsed.host
    );
    for (key, value) in headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("http write failed: {err}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|err| format!("http read failed: {err}"))?;
    parse_http_response(&response)
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

#[cfg(feature = "upnp")]
pub fn post(
    url: &str,
    headers: &[(&str, String)],
    body: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let parsed = parse_url(url)?;
    let mut stream = connect_stream(&parsed)?;
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: rustorrent/0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        parsed.path,
        parsed.host,
        body.len()
    );
    for (key, value) in headers {
        request.push_str(key);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("http write failed: {err}"))?;
    stream
        .write_all(body)
        .map_err(|err| format!("http write failed: {err}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|err| format!("http read failed: {err}"))?;
    let response = parse_http_response(&response)?;
    if response.status != 200 && response.status != 206 {
        return Err(format!("http status {}", response.status));
    }
    if response.body.len() > max_bytes {
        return Err("http response too large".to_string());
    }
    Ok(response.body)
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("http://") {
        (Scheme::Http, rest)
    } else if let Some(rest) = url.strip_prefix("https://") {
        (Scheme::Https, rest)
    } else {
        return Err("unsupported scheme".to_string());
    };
    let (host_port, path) = match rest.split_once('/') {
        Some((host_port, path)) => (host_port, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if host_port.is_empty() {
        return Err("invalid url".to_string());
    }
    let default_port = match scheme {
        Scheme::Http => 80,
        Scheme::Https => 443,
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port = port
                .parse::<u16>()
                .map_err(|_| "invalid port".to_string())?;
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

fn connect_stream(parsed: &ParsedUrl) -> Result<HttpStream, String> {
    let stream =
        TcpStream::connect((parsed.host.as_str(), parsed.port)).map_err(|err| err.to_string())?;
    match parsed.scheme {
        Scheme::Http => Ok(HttpStream::Plain(stream)),
        Scheme::Https => {
            let connector = TlsConnector::new().map_err(|err| err.to_string())?;
            let stream = connector
                .connect(&parsed.host, stream)
                .map_err(|err| err.to_string())?;
            Ok(HttpStream::Tls(stream))
        }
    }
}

fn parse_http_response(data: &[u8]) -> Result<HttpResponse, String> {
    let header_end = find_header_end(data).ok_or_else(|| "http parse error".to_string())?;
    let (header_bytes, body) = data.split_at(header_end);
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.lines();
    let status_line = lines.next().ok_or_else(|| "http parse error".to_string())?;
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
            return Err("http parse error".to_string());
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

fn parse_status(line: &str) -> Result<u16, String> {
    let mut parts = line.split_whitespace();
    let _http = parts.next().ok_or_else(|| "http parse error".to_string())?;
    let status = parts.next().ok_or_else(|| "http parse error".to_string())?;
    status
        .parse::<u16>()
        .map_err(|_| "http parse error".to_string())
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut pos = 0;
    let mut out = Vec::new();
    loop {
        let line_end = find_crlf(body, pos).ok_or_else(|| "http parse error".to_string())?;
        let line = &body[pos..line_end];
        let line_str = std::str::from_utf8(line).map_err(|_| "http parse error".to_string())?;
        let size = usize::from_str_radix(line_str.trim(), 16)
            .map_err(|_| "http parse error".to_string())?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        if pos + size > body.len() {
            return Err("http parse error".to_string());
        }
        out.extend_from_slice(&body[pos..pos + size]);
        pos += size;
        if body.get(pos) != Some(&b'\r') || body.get(pos + 1) != Some(&b'\n') {
            return Err("http parse error".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn parse_url_rejects_invalid_inputs() {
        assert!(parse_url("ftp://example.com").is_err());
        assert!(parse_url("http://").is_err());
        assert!(parse_url("http://example.com:99999").is_err());
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
    fn parse_http_response_with_content_length() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: one\r\n\r\nhelloEXTRA";
        let parsed = parse_http_response(response).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.body, b"hello");
        assert_eq!(
            header_value(&parsed.headers, "x-test"),
            Some("one".to_string())
        );
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
    }

    #[test]
    fn decode_chunked_rejects_invalid_chunk_layout() {
        assert!(decode_chunked(b"4\r\nabc\r\n0\r\n\r\n").is_err());
        assert!(decode_chunked(b"ZZ\r\nabc\r\n0\r\n\r\n").is_err());
    }
}

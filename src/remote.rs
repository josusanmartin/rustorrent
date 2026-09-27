//! Command-line remote control. `rustorrent remote …` and the terminal UI talk
//! to a running instance through its loopback web API, so every action the
//! browser interface offers is also available from a terminal.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 64;

pub const USAGE: &str = "usage: rustorrent remote [--ui-addr <addr>] <command> [args]

Controls a running rustorrent (started with --ui, --tui or --daemon).
<id> is a transfer id, an info-hash prefix, or `all` where noted.

  list [--json]                     List transfers
  info <id> [--json]                Details, files and trackers
  add <file|magnet> [--dir <d>] [--paused] [--skip <i,j>] [--prealloc]
  pause|resume|stop|recheck|archive <id...|all>
  remove <id...> [--delete-files]   Remove (keeps files unless asked)
  priority <id> <file#...> <skip|low|normal|high>
  rename <id> <file#> <name>        Rename a file
  label <id> [label]                Set or clear a label
  tracker add|remove <id> <url>
  limit <down> <up>                 Global rates, k/m/g suffixes, 0 = unlimited
  ratio <value>                     Stop seeding at ratio (0 = never)
  profile conservative|balanced|aggressive
  session [--json]                  Rates, limits, ports and network status
  search <query> [--category <c>] [--plugins <a,b>]
  get <result#> [--dir <d>]         Add a search result
  plugins                           List search plugins
  plugin install <url|file.py> | plugin remove <module>
  plugin recommended                Install the recommended search plugins
  rss                               List feeds and rules
  rss add-feed <url> [secs] | rss remove-feed <url>
  rss add-rule <name> <pattern> [feed-url] | rss remove-rule <name>
  tui                               Interactive terminal interface";

// ---------------------------------------------------------------- JSON

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

static NULL: Json = Json::Null;

impl Json {
    pub fn parse(text: &str) -> Result<Json, String> {
        let mut p = JsonParser {
            b: text.as_bytes(),
            i: 0,
        };
        let value = p.value(0)?;
        p.ws();
        if p.i != p.b.len() {
            return Err("trailing data in JSON".into());
        }
        Ok(value)
    }

    pub fn get(&self, key: &str) -> &Json {
        match self {
            Json::Obj(fields) => fields
                .iter()
                .find(|(k, _)| k == key)
                .map_or(&NULL, |(_, v)| v),
            _ => &NULL,
        }
    }

    pub fn s(&self, key: &str) -> &str {
        match self.get(key) {
            Json::Str(s) => s,
            _ => "",
        }
    }

    pub fn n(&self, key: &str) -> f64 {
        match self.get(key) {
            Json::Num(n) => *n,
            _ => 0.0,
        }
    }

    pub fn u(&self, key: &str) -> u64 {
        let n = self.n(key);
        if n.is_finite() && n > 0.0 {
            n as u64
        } else {
            0
        }
    }

    pub fn b(&self, key: &str) -> bool {
        matches!(self.get(key), Json::Bool(true))
    }

    pub fn arr(&self, key: &str) -> &[Json] {
        match self.get(key) {
            Json::Arr(items) => items,
            _ => &[],
        }
    }
}

struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl JsonParser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            Err("invalid JSON".into())
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nested too deeply".into());
        }
        self.ws();
        match self.b.get(self.i).copied() {
            Some(b'{') => {
                self.i += 1;
                let mut fields = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Json::Obj(fields));
                }
                loop {
                    self.ws();
                    let key = self.string()?;
                    self.ws();
                    self.eat(":")?;
                    fields.push((key, self.value(depth + 1)?));
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Obj(fields));
                        }
                        _ => return Err("invalid JSON object".into()),
                    }
                }
            }
            Some(b'[') => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Arr(items));
                        }
                        _ => return Err("invalid JSON array".into()),
                    }
                }
            }
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.eat("true").map(|_| Json::Bool(true)),
            Some(b'f') => self.eat("false").map(|_| Json::Bool(false)),
            Some(b'n') => self.eat("null").map(|_| Json::Null),
            Some(_) => {
                let start = self.i;
                while self.i < self.b.len()
                    && matches!(
                        self.b[self.i],
                        b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
                    )
                {
                    self.i += 1;
                }
                std::str::from_utf8(&self.b[start..self.i])
                    .ok()
                    .and_then(|s| s.parse::<f64>().ok())
                    .map(Json::Num)
                    .ok_or_else(|| "invalid JSON number".into())
            }
            None => Err("unexpected end of JSON".into()),
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .b
            .get(self.i..self.i + 4)
            .and_then(|d| std::str::from_utf8(d).ok())
            .and_then(|d| u32::from_str_radix(d, 16).ok())
            .ok_or("invalid JSON escape")?;
        self.i += 4;
        Ok(digits)
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat("\"")?;
        let mut out = Vec::new();
        loop {
            let byte = *self.b.get(self.i).ok_or("unterminated JSON string")?;
            self.i += 1;
            match byte {
                b'"' => return String::from_utf8(out).map_err(|_| "invalid UTF-8".into()),
                b'\\' => {
                    let esc = *self.b.get(self.i).ok_or("unterminated JSON string")?;
                    self.i += 1;
                    let ch = match esc {
                        b'n' => '\n',
                        b't' => '\t',
                        b'r' => '\r',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'u' => {
                            let mut code = self.hex4()?;
                            if (0xD800..0xDC00).contains(&code)
                                && self.b[self.i..].starts_with(b"\\u")
                            {
                                self.i += 2;
                                let low = self.hex4()?;
                                code = 0x10000
                                    + ((code - 0xD800) << 10)
                                    + (low.wrapping_sub(0xDC00) & 0x3FF);
                            }
                            char::from_u32(code).unwrap_or('\u{FFFD}')
                        }
                        other => other as char,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                _ => out.push(byte),
            }
        }
    }
}

// ---------------------------------------------------------------- HTTP client

pub struct Client {
    host: String,
    token: String,
}

impl Client {
    /// Connects to `host` (e.g. `127.0.0.1:8080`). Without a token the
    /// client fetches the one the server hands to its local browser UI.
    pub fn new(host: &str, token: Option<String>) -> Result<Client, String> {
        let mut client = Client {
            host: host.trim().to_string(),
            token: token.unwrap_or_default(),
        };
        if client.token.is_empty() {
            client.token = client.get("/api-token")?.s("token").to_string();
            if client.token.is_empty() {
                return Err(format!("{} did not provide an API token", client.host));
            }
        }
        Ok(client)
    }

    fn send(&self, method: &str, path: &str, ctype: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        let unreachable = |err: std::io::Error| {
            format!(
                "cannot reach rustorrent at {} ({err}); start it with --ui or pass --ui-addr",
                self.host
            )
        };
        let addr = self
            .host
            .to_socket_addrs()
            .map_err(unreachable)?
            .next()
            .ok_or_else(|| format!("invalid address {}", self.host))?;
        let mut stream =
            TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(unreachable)?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n",
            h = self.host
        );
        if method == "POST" {
            head.push_str(&format!(
                "Origin: http://{}\r\nX-Rustorrent-Token: {}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n",
                self.host,
                self.token,
                body.len()
            ));
        }
        head.push_str("\r\n");
        let io = |err: std::io::Error| format!("request to {} failed: {err}", self.host);
        stream.write_all(head.as_bytes()).map_err(io)?;
        stream.write_all(body).map_err(io)?;
        let mut response = Vec::new();
        stream
            .take(MAX_RESPONSE_BYTES)
            .read_to_end(&mut response)
            .map_err(io)?;
        let split = response
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("malformed HTTP response")?;
        let head = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
        let mut body = response[split + 4..].to_vec();
        if head.contains("transfer-encoding: chunked") {
            body = dechunk(&body)?;
        }
        let code = head
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&code) {
            let text = String::from_utf8_lossy(&body);
            let message = Json::parse(&text)
                .ok()
                .map(|j| j.s("error").to_string())
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| format!("HTTP {code}"));
            return Err(message);
        }
        Ok(body)
    }

    pub fn get(&self, path: &str) -> Result<Json, String> {
        Json::parse(&String::from_utf8_lossy(&self.send(
            "GET",
            path,
            "",
            &[],
        )?))
    }

    pub fn post(&self, path: &str, form: &[(&str, &str)]) -> Result<Json, String> {
        let body = form_encode(form);
        let reply = self.send(
            "POST",
            path,
            "application/x-www-form-urlencoded",
            body.as_bytes(),
        )?;
        Json::parse(&String::from_utf8_lossy(&reply)).or(Ok(Json::Null))
    }

    pub fn upload(&self, path: &str, data: &[u8]) -> Result<Json, String> {
        let reply = self.send("POST", path, "application/octet-stream", data)?;
        Json::parse(&String::from_utf8_lossy(&reply)).or(Ok(Json::Null))
    }

    pub fn status(&self) -> Result<Json, String> {
        self.get("/status")
    }
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("bad chunked body")?;
        let size_text = String::from_utf8_lossy(&data[..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "bad chunk size")?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        let chunk = data.get(..size).ok_or("truncated chunk")?;
        out.extend_from_slice(chunk);
        data = data.get(size + 2..).unwrap_or(&[]);
    }
}

pub fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(key);
        out.push('=');
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                out.push(byte as char);
            } else {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

// ---------------------------------------------------------------- formatting

pub fn fmt_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

pub fn fmt_rate(bps: f64) -> String {
    if bps.is_finite() && bps >= 1.0 {
        format!("{}/s", fmt_bytes(bps as u64))
    } else {
        "-".into()
    }
}

pub fn fmt_eta(secs: u64) -> String {
    match secs {
        0 => "-".into(),
        s if s >= 86_400 * 100 => "∞".into(),
        s if s >= 86_400 => format!("{}d{}h", s / 86_400, s % 86_400 / 3600),
        s if s >= 3600 => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
        s => format!("{}m{:02}s", s / 60, s % 60),
    }
}

/// Fraction complete in 0..=1.
pub fn progress(t: &Json) -> f64 {
    let total = t.u("total_bytes");
    if total == 0 {
        0.0
    } else {
        (t.u("completed_bytes") as f64 / total as f64).min(1.0)
    }
}

/// One user-facing state per transfer, matching the browser interface.
pub fn state_label(t: &Json) -> &'static str {
    let status = t.s("status");
    if status == "stopping" {
        "stopping"
    } else if t.b("paused") || status == "paused" {
        "paused"
    } else if status == "stopped" || status == "shutdown" {
        "stopped"
    } else if status.contains("error") || status.contains("failed") {
        "error"
    } else if status == "queued" {
        "queued"
    } else if is_done(t) {
        "seeding"
    } else if status == "fetching metadata" {
        "metadata"
    } else if status == "announcing" || status.contains("waiting") {
        "waiting"
    } else {
        "downloading"
    }
}

pub fn is_done(t: &Json) -> bool {
    let pieces = t.u("total_pieces");
    let bytes = t.u("total_bytes");
    (pieces > 0 && t.u("completed_pieces") >= pieces)
        || (bytes > 0 && t.u("completed_bytes") >= bytes)
}

pub fn priority_name(priority: u64) -> &'static str {
    match priority {
        0 => "skip",
        1 => "low",
        3 => "high",
        _ => "normal",
    }
}

fn parse_priority(text: &str) -> Result<u8, String> {
    Ok(match text {
        "skip" | "0" | "off" => 0,
        "low" | "1" => 1,
        "normal" | "2" => 2,
        "high" | "3" => 3,
        _ => {
            return Err(format!(
                "unknown priority {text:?} (skip, low, normal, high)"
            ))
        }
    })
}

/// Truncates to at most `width` characters, adding an ellipsis when cut.
pub fn clip(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

// ---------------------------------------------------------------- actions

/// Resolves a transfer reference (numeric id or info-hash prefix).
pub fn resolve_id(status: &Json, reference: &str) -> Result<u64, String> {
    let torrents = status.arr("torrents");
    if let Ok(id) = reference.parse::<u64>() {
        if torrents.iter().any(|t| t.u("id") == id) {
            return Ok(id);
        }
    }
    let lower = reference.to_ascii_lowercase();
    let matches: Vec<u64> = torrents
        .iter()
        .filter(|t| lower.len() >= 4 && t.s("info_hash").starts_with(&lower))
        .map(|t| t.u("id"))
        .collect();
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => Err(format!("no transfer matches {reference:?}")),
        _ => Err(format!("{reference:?} matches several transfers")),
    }
}

/// Endpoint for a simple per-transfer action.
pub fn action_path(action: &str) -> Option<&'static str> {
    Some(match action {
        "pause" => "/torrent/pause",
        "resume" | "start" => "/torrent/resume",
        "stop" => "/torrent/stop",
        "recheck" | "verify" => "/torrent/recheck",
        "archive" => "/torrent/archive",
        "remove" | "rm" => "/torrent/delete",
        _ => return None,
    })
}

pub fn torrent_action(
    client: &Client,
    action: &str,
    id: u64,
    delete_files: bool,
) -> Result<(), String> {
    let path = action_path(action).ok_or("unknown action")?;
    let mut url = format!("{path}?id={id}");
    if delete_files {
        url.push_str("&data=1");
    }
    client.post(&url, &[]).map(|_| ())
}

/// Adds a torrent file path, magnet link, or http(s) URL to a .torrent.
pub fn add(
    client: &Client,
    source: &str,
    dir: &str,
    paused: bool,
    skip: &str,
    prealloc: bool,
) -> Result<u64, String> {
    let flag = |b: bool| if b { "1" } else { "0" };
    let reply = if source.starts_with("magnet:") {
        client.post(
            "/add-magnet",
            &[
                ("magnet", source),
                ("dir", dir),
                ("paused", flag(paused)),
                ("skip", skip),
                ("prealloc", flag(prealloc)),
            ],
        )?
    } else {
        let data = std::fs::read(source).map_err(|err| format!("cannot read {source}: {err}"))?;
        let query = form_encode(&[
            ("dir", dir),
            ("paused", flag(paused)),
            ("skip", skip),
            ("prealloc", flag(prealloc)),
        ]);
        client.upload(&format!("/add-torrent?{query}"), &data)?
    };
    Ok(reply.u("torrent_id"))
}

pub fn set_limits(client: &Client, down: &str, up: &str) -> Result<(), String> {
    let kib = |text: &str| -> Result<String, String> {
        let bytes = crate::parse_rate(text)?;
        Ok(bytes.div_ceil(1024).to_string())
    };
    let (down, up) = (kib(down)?, kib(up)?);
    client
        .post(
            "/rate-limits",
            &[("download_kbps", &down), ("upload_kbps", &up)],
        )
        .map(|_| ())
}

// ---------------------------------------------------------------- command line

fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    let before = args.len();
    args.retain(|a| a != flag);
    args.len() != before
}

fn take_value(args: &mut Vec<String>, flag: &str) -> Result<Option<String>, String> {
    match args.iter().position(|a| a == flag) {
        Some(i) if i + 1 < args.len() => {
            let value = args.remove(i + 1);
            args.remove(i);
            Ok(Some(value))
        }
        Some(_) => Err(format!("missing value for {flag}")),
        None => Ok(None),
    }
}

fn need<'a>(args: &'a [String], index: usize, what: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("missing {what}\n\n{USAGE}"))
}

/// Default address of the local web API, overridable by environment.
pub fn default_addr() -> String {
    std::env::var("RUSTORRENT_UI_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into())
}

/// Entry point for `rustorrent remote <command>`. `args` excludes `remote`.
pub fn main(mut args: Vec<String>) -> Result<(), String> {
    let addr = take_value(&mut args, "--ui-addr")?.unwrap_or_else(default_addr);
    let json = take_flag(&mut args, "--json");
    if args.is_empty() || matches!(args[0].as_str(), "help" | "-h" | "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    let command = args.remove(0);
    let client = Client::new(&addr, None)?;
    match command.as_str() {
        "list" | "ls" => {
            let status = client.status()?;
            if json {
                println!("{}", to_json(status.get("torrents")));
            } else {
                print_list(&status);
            }
        }
        "info" | "show" => {
            let status = client.status()?;
            let id = resolve_id(&status, need(&args, 0, "transfer id")?)?;
            let torrent = status
                .arr("torrents")
                .iter()
                .find(|t| t.u("id") == id)
                .ok_or("transfer not found")?;
            if json {
                println!("{}", to_json(torrent));
            } else {
                print_info(torrent);
            }
        }
        "session" | "status" => {
            let status = client.status()?;
            if json {
                let mut session = status.clone();
                if let Json::Obj(fields) = &mut session {
                    fields.retain(|(k, _)| k != "torrents" && k != "files");
                }
                println!("{}", to_json(&session));
            } else {
                print_session(&status);
            }
        }
        "add" => {
            let dir = take_value(&mut args, "--dir")?.unwrap_or_default();
            let skip = take_value(&mut args, "--skip")?.unwrap_or_default();
            let paused = take_flag(&mut args, "--paused");
            let prealloc = take_flag(&mut args, "--prealloc");
            if args.is_empty() {
                return Err(format!("missing torrent file or magnet link\n\n{USAGE}"));
            }
            for source in &args {
                let id = add(&client, source, &dir, paused, &skip, prealloc)?;
                println!("added {} (id {id})", clip(source, 60));
            }
        }
        "pause" | "resume" | "start" | "stop" | "recheck" | "verify" | "archive" | "remove"
        | "rm" => {
            let delete_files = take_flag(&mut args, "--delete-files");
            if args.is_empty() {
                return Err(format!("missing transfer id\n\n{USAGE}"));
            }
            let status = client.status()?;
            let ids: Vec<u64> = if args.len() == 1 && args[0] == "all" {
                if matches!(command.as_str(), "remove" | "rm") {
                    return Err("refusing to remove all transfers; list ids explicitly".into());
                }
                status.arr("torrents").iter().map(|t| t.u("id")).collect()
            } else {
                args.iter()
                    .map(|a| resolve_id(&status, a))
                    .collect::<Result<_, _>>()?
            };
            let mut failed = 0;
            for id in ids {
                match torrent_action(&client, &command, id, delete_files) {
                    Ok(()) => println!("{command}: {id}"),
                    Err(err) => {
                        eprintln!("{command} {id}: {err}");
                        failed += 1;
                    }
                }
            }
            if failed > 0 {
                return Err(format!("{failed} transfer(s) could not be updated"));
            }
        }
        "priority" | "prio" => {
            if args.len() < 3 {
                return Err("usage: priority <id> <file#...> <skip|low|normal|high>".into());
            }
            let status = client.status()?;
            let id = resolve_id(&status, &args[0])?.to_string();
            let level = parse_priority(&args[args.len() - 1])?.to_string();
            for index in &args[1..args.len() - 1] {
                client.post(
                    "/file-priority",
                    &[("id", &id), ("index", index), ("priority", &level)],
                )?;
            }
        }
        "rename" => {
            let status = client.status()?;
            let id = resolve_id(&status, need(&args, 0, "transfer id")?)?.to_string();
            client.post(
                "/rename-file",
                &[
                    ("id", &id),
                    ("index", need(&args, 1, "file number")?),
                    ("name", need(&args, 2, "new name")?),
                ],
            )?;
        }
        "label" => {
            let status = client.status()?;
            let id = resolve_id(&status, need(&args, 0, "transfer id")?)?.to_string();
            let label = args[1..].join(" ");
            client.post("/torrent/set-label", &[("id", &id), ("label", &label)])?;
        }
        "tracker" => {
            let op = need(&args, 0, "add or remove")?;
            let path = match op {
                "add" => "/torrent/add-tracker",
                "remove" | "rm" => "/torrent/remove-tracker",
                _ => return Err("usage: tracker add|remove <id> <url>".into()),
            };
            let status = client.status()?;
            let id = resolve_id(&status, need(&args, 1, "transfer id")?)?.to_string();
            client.post(
                path,
                &[("id", &id), ("url", need(&args, 2, "tracker url")?)],
            )?;
        }
        "limit" | "limits" => {
            set_limits(
                &client,
                need(&args, 0, "download rate")?,
                need(&args, 1, "upload rate")?,
            )?;
        }
        "ratio" => {
            client.post(
                "/settings/seed-ratio",
                &[("ratio", need(&args, 0, "ratio")?)],
            )?;
        }
        "profile" => {
            client.post(
                "/settings/peer-profile",
                &[("profile", need(&args, 0, "profile")?)],
            )?;
        }
        "search" => {
            let category = take_value(&mut args, "--category")?.unwrap_or_else(|| "all".into());
            let engines = take_value(&mut args, "--plugins")?.unwrap_or_default();
            let query = args.join(" ");
            if query.trim().is_empty() {
                return Err("missing search query".into());
            }
            let results = run_search(&client, &query, &category, &engines)?;
            if json {
                println!("{}", to_json(&Json::Arr(results)));
            } else {
                print_search_results(&results);
            }
        }
        "get" => {
            let dir = take_value(&mut args, "--dir")?.unwrap_or_default();
            let reply = client.post(
                "/search/add-result",
                &[("index", need(&args, 0, "result number")?), ("dir", &dir)],
            )?;
            println!("added (id {})", reply.u("torrent_id"));
        }
        "plugins" => print_plugins(&client.get("/search/status")?),
        "plugin" => match need(&args, 0, "install or remove")? {
            "install" => {
                let source = need(&args, 1, "plugin url or file")?;
                if source.starts_with("http://") || source.starts_with("https://") {
                    client.post("/search/install-url", &[("url", source)])?;
                } else {
                    let data = std::fs::read(source)
                        .map_err(|err| format!("cannot read {source}: {err}"))?;
                    let name = std::path::Path::new(source)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("plugin.py");
                    let query = form_encode(&[("filename", name)]);
                    client.upload(&format!("/search/install-plugin?{query}"), &data)?;
                }
            }
            "recommended" => {
                client.post("/search/install-recommended", &[])?;
                print_plugins(&client.get("/search/status")?);
            }
            "remove" | "rm" => {
                client.post(
                    "/search/remove-plugin",
                    &[("module", need(&args, 1, "plugin module")?)],
                )?;
            }
            _ => return Err(
                "usage: plugin install <url|file.py> | plugin remove <module> | plugin recommended"
                    .into(),
            ),
        },
        "rss" => match args.first().map(String::as_str).unwrap_or("list") {
            "list" | "ls" => print_rss(&client.get("/rss/status")?),
            "add-feed" => {
                let interval = args.get(2).map(String::as_str).unwrap_or("900");
                client.post(
                    "/rss/add-feed",
                    &[("url", need(&args, 1, "feed url")?), ("interval", interval)],
                )?;
            }
            "remove-feed" => {
                client.post("/rss/remove-feed", &[("url", need(&args, 1, "feed url")?)])?;
            }
            "add-rule" => {
                let feed = args.get(3).map(String::as_str).unwrap_or("");
                client.post(
                    "/rss/add-rule",
                    &[
                        ("name", need(&args, 1, "rule name")?),
                        ("pattern", need(&args, 2, "pattern")?),
                        ("feed_url", feed),
                    ],
                )?;
            }
            "remove-rule" => {
                client.post(
                    "/rss/remove-rule",
                    &[("name", need(&args, 1, "rule name")?)],
                )?;
            }
            other => return Err(format!("unknown rss command {other:?}\n\n{USAGE}")),
        },
        "tui" => crate::tui::run(client)?,
        other => return Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
    Ok(())
}

/// Starts a search and waits for it to finish (at most two minutes).
pub fn run_search(
    client: &Client,
    query: &str,
    category: &str,
    engines: &str,
) -> Result<Vec<Json>, String> {
    client.post(
        "/search/run",
        &[
            ("query", query),
            ("category", category),
            ("engines", engines),
        ],
    )?;
    let started = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(400));
        let status = client.get("/search/status")?;
        if !status.b("busy") || started.elapsed() > Duration::from_secs(120) {
            let error = status.s("last_error");
            if !error.is_empty() && status.arr("results").is_empty() {
                return Err(error.to_string());
            }
            return Ok(status.arr("results").to_vec());
        }
    }
}

pub fn to_json(value: &Json) -> String {
    let mut out = String::new();
    write_json(value, &mut out);
    out
}

fn write_json(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Num(n) => out.push_str(&n.to_string()),
        Json::Str(s) => {
            out.push('"');
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Json::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        Json::Obj(fields) => {
            out.push('{');
            for (i, (key, item)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(&Json::Str(key.clone()), out);
                out.push(':');
                write_json(item, out);
            }
            out.push('}');
        }
    }
}

fn print_list(status: &Json) {
    let torrents = status.arr("torrents");
    if torrents.is_empty() {
        println!("No transfers. Add one with: rustorrent remote add <file.torrent|magnet>");
        return;
    }
    println!(
        "{:>4}  {:<11} {:>6}  {:>10}  {:>10}  {:>7}  {:>5}  NAME",
        "ID", "STATE", "DONE", "DOWN", "UP", "ETA", "RATIO"
    );
    for t in torrents {
        println!(
            "{:>4}  {:<11} {:>5.1}%  {:>10}  {:>10}  {:>7}  {:>5.2}  {}",
            t.u("id"),
            state_label(t),
            progress(t) * 100.0,
            fmt_rate(t.n("download_rate_bps")),
            fmt_rate(t.n("upload_rate_bps")),
            fmt_eta(t.u("eta_secs")),
            t.n("ratio"),
            t.s("name")
        );
    }
    println!(
        "{} transfers   ↓ {}   ↑ {}",
        torrents.len(),
        fmt_rate(status.n("download_rate_bps")),
        fmt_rate(status.n("upload_rate_bps"))
    );
}

/// Detail lines shared by `remote info` and the terminal UI.
pub fn info_lines(t: &Json) -> Vec<String> {
    let mut lines = vec![
        format!("Name      {}", t.s("name")),
        format!(
            "State     {}{}",
            state_label(t),
            if t.s("last_error").is_empty() {
                String::new()
            } else {
                format!(" ({})", t.s("last_error"))
            }
        ),
        format!(
            "Progress  {:.1}% of {} ({}/{} pieces)",
            progress(t) * 100.0,
            fmt_bytes(t.u("total_bytes")),
            t.u("completed_pieces"),
            t.u("total_pieces")
        ),
        format!(
            "Rates     ↓ {}  ↑ {}  ETA {}",
            fmt_rate(t.n("download_rate_bps")),
            fmt_rate(t.n("upload_rate_bps")),
            fmt_eta(t.u("eta_secs"))
        ),
        format!(
            "Transfer  downloaded {}  uploaded {}  ratio {:.2}",
            fmt_bytes(t.u("downloaded_bytes")),
            fmt_bytes(t.u("uploaded_bytes")),
            t.n("ratio")
        ),
        format!(
            "Peers     {} connected, {} known, {} interested",
            t.u("active_peers"),
            t.u("tracker_peers"),
            t.u("interested_peers")
        ),
        format!("Hash      {}", t.s("info_hash")),
        format!("Folder    {}", t.s("download_dir")),
    ];
    if !t.s("label").is_empty() {
        lines.push(format!("Label     {}", t.s("label")));
    }
    lines
}

pub fn file_line(index: usize, f: &Json) -> String {
    let length = f.u("length");
    let done = if length == 0 {
        100.0
    } else {
        f.u("completed") as f64 * 100.0 / length as f64
    };
    format!(
        "{index:>4}  {:<6} {:>5.1}%  {:>10}  {}",
        priority_name(f.u("priority")),
        done.min(100.0),
        fmt_bytes(length),
        f.s("path")
    )
}

fn print_info(t: &Json) {
    for line in info_lines(t) {
        println!("{line}");
    }
    let files = t.arr("files");
    if !files.is_empty() {
        println!(
            "\nFiles\n{:>4}  {:<6} {:>6}  {:>10}  PATH",
            "#", "PRIO", "DONE", "SIZE"
        );
        for (i, f) in files.iter().enumerate() {
            println!("{}", file_line(i, f));
        }
    }
    let trackers = t.arr("trackers");
    if !trackers.is_empty() {
        println!("\nTrackers");
        for tracker in trackers {
            if let Json::Str(url) = tracker {
                println!("  {url}");
            }
        }
    }
}

pub fn session_lines(s: &Json) -> Vec<String> {
    let limit = |v: u64| {
        if v == 0 {
            "unlimited".to_string()
        } else {
            fmt_rate(v as f64)
        }
    };
    vec![
        format!(
            "Rates        ↓ {}  ↑ {}",
            fmt_rate(s.n("download_rate_bps")),
            fmt_rate(s.n("upload_rate_bps"))
        ),
        format!(
            "Limits       ↓ {}  ↑ {}",
            limit(s.u("global_download_limit_bps")),
            limit(s.u("global_upload_limit_bps"))
        ),
        format!(
            "Session      downloaded {}  uploaded {}",
            fmt_bytes(s.u("session_downloaded_bytes")),
            fmt_bytes(s.u("session_uploaded_bytes"))
        ),
        format!(
            "Seed ratio   {}",
            if s.n("seed_ratio") > 0.0 {
                format!("{:.2}", s.n("seed_ratio"))
            } else {
                "unlimited".into()
            }
        ),
        format!("Peer profile {}", s.s("peer_profile")),
        format!(
            "Port         {}  NAT-PMP: {}  UPnP: {}",
            s.u("incoming_port"),
            s.s("natpmp_status"),
            s.s("upnp_status")
        ),
        format!("Reachable    {}", reachability(s)),
        format!("Version      {}", s.s("version")),
    ]
}

/// Whether other peers can connect to us, mirroring the browser's
/// Connectivity card.
pub fn reachability(s: &Json) -> String {
    let inbound = s.u("inbound_public_peers");
    let port = s.u("incoming_port");
    let (router, tracker) = (s.s("router_external_ip"), s.s("tracker_external_ip"));
    let router_ip = router.parse::<std::net::Ipv4Addr>().ok();
    let second_router = router_ip.is_some_and(|ip| ip.is_private());
    let cgnat = router_ip.is_some_and(|ip| {
        let [a, b, ..] = ip.octets();
        a == 100 && (64..128).contains(&b)
    }) || (router_ip.is_some_and(|ip| !ip.is_private())
        && !tracker.is_empty()
        && !tracker.contains(':')
        && tracker != router);
    let mapped = [s.s("natpmp_status"), s.s("upnp_status")]
        .iter()
        .any(|status| status.starts_with("mapped "));
    match s.s("firewall_status") {
        "block-all" | "blocked" | "unlisted" => {
            "outgoing only: the macOS firewall blocks incoming connections (allow Rustorrent in Settings)"
                .into()
        }
        _ if inbound > 0 => format!(
            "yes: {inbound} peer{} connected in",
            if inbound == 1 { "" } else { "s" }
        ),
        _ if cgnat => "outgoing only: your provider shares one public address between customers \
                       (carrier-grade NAT); ask it for a public IPv4 address"
            .into(),
        _ if second_router && s.s("upstream_status").starts_with("mapped ") => {
            "not confirmed yet: the port is forwarded on both routers".into()
        }
        _ if second_router => format!(
            "outgoing only: a second router or modem sits in front of yours; on it, turn on bridge mode, \
             or forward port {port} to {router}, or make {router} its DMZ host"
        ),
        _ if mapped => "not confirmed yet: the router forwards the port".into(),
        _ if s.s("upnp_status").starts_with("disabled") => {
            format!("outgoing only: automatic port forwarding is off; forward port {port} to this computer")
        }
        _ => format!(
            "outgoing only: the router did not open the port; enable UPnP or NAT-PMP, or forward port {port}"
        ),
    }
}

fn print_session(s: &Json) {
    for line in session_lines(s) {
        println!("{line}");
    }
}

pub fn search_line(r: &Json) -> String {
    format!(
        "{:>4}  {:>6}  {:>6}  {:>10}  {}  [{}]",
        r.u("index"),
        r.u("seeds"),
        r.u("leech"),
        fmt_bytes(r.u("size")),
        r.s("name"),
        r.s("plugin")
    )
}

fn print_search_results(results: &[Json]) {
    if results.is_empty() {
        println!("No results.");
        return;
    }
    println!(
        "{:>4}  {:>6}  {:>6}  {:>10}  NAME",
        "#", "SEEDS", "PEERS", "SIZE"
    );
    for r in results {
        println!("{}", search_line(r));
    }
    println!("\nAdd one with: rustorrent remote get <#>");
}

fn print_plugins(status: &Json) {
    let plugins = status.arr("plugins");
    if status.b("loading") {
        println!("Search plugins are still loading; try again in a moment.");
        return;
    }
    if plugins.is_empty() {
        println!("No search plugins installed. `rustorrent remote plugin recommended` adds the recommended set.");
    }
    for p in plugins {
        println!(
            "{:<20} {:<8} {}{}",
            p.s("module"),
            p.s("version"),
            p.s("display_name"),
            if p.b("healthy") {
                String::new()
            } else {
                format!("  (broken: {})", p.s("broken_reason"))
            }
        );
    }
    if !status.b("python_available") {
        println!("Python 3.9+ is required to run search plugins.");
    }
}

fn print_rss(status: &Json) {
    println!("Feeds");
    for f in status.arr("feeds") {
        println!(
            "  {}  ({} items, every {}s)  {}",
            f.s("url"),
            f.u("items"),
            f.u("interval"),
            f.s("title")
        );
    }
    println!("Rules");
    for r in status.arr("rules") {
        let feed = if r.s("feed_url").is_empty() {
            "any feed"
        } else {
            r.s("feed_url")
        };
        println!("  {}: {}  ({feed})", r.s("name"), r.s("pattern"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_json_with_escapes() {
        let value =
            Json::parse(r#"{"a":[1,2.5,-3e2],"s":"x\"\u00e9\ud83d\ude00\n","t":true,"n":null}"#)
                .unwrap();
        assert_eq!(value.arr("a").len(), 3);
        assert_eq!(value.arr("a")[2], Json::Num(-300.0));
        assert_eq!(value.s("s"), "x\"é😀\n");
        assert!(value.b("t"));
        assert_eq!(value.get("n"), &Json::Null);
        assert_eq!(value.get("missing"), &Json::Null);
        assert_eq!(Json::parse(&to_json(&value)).unwrap(), value);
    }

    #[test]
    fn rejects_malformed_and_deep_json() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\" 1}",
            "\"abc",
            "tru",
            "[1] x",
            "\"\\u12\"",
        ] {
            assert!(Json::parse(bad).is_err(), "{bad}");
        }
        let deep = "[".repeat(200) + &"]".repeat(200);
        assert!(Json::parse(&deep).is_err());
    }

    #[test]
    fn form_encoding_escapes_reserved_bytes() {
        assert_eq!(
            form_encode(&[("q", "a b&c=d/é"), ("x", "")]),
            "q=a%20b%26c%3Dd%2F%C3%A9&x="
        );
    }

    #[test]
    fn dechunks_bodies() {
        assert_eq!(
            dechunk(b"3\r\nabc\r\n2;x\r\nde\r\n0\r\n\r\n").unwrap(),
            b"abcde"
        );
        assert!(dechunk(b"9\r\nabc").is_err());
    }

    #[test]
    fn resolves_ids_and_hash_prefixes() {
        let status = Json::parse(
            r#"{"torrents":[{"id":3,"info_hash":"abcdef01"},{"id":7,"info_hash":"abcd9999"}]}"#,
        )
        .unwrap();
        assert_eq!(resolve_id(&status, "7").unwrap(), 7);
        assert_eq!(resolve_id(&status, "ABCDEF").unwrap(), 3);
        assert!(resolve_id(&status, "abcd").is_err());
        assert!(resolve_id(&status, "9").is_err());
    }

    #[test]
    fn formats_values() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536), "1.5 KB");
        assert_eq!(fmt_rate(0.0), "-");
        assert_eq!(fmt_eta(0), "-");
        assert_eq!(fmt_eta(75), "1m15s");
        assert_eq!(fmt_eta(3700), "1h01m");
        assert_eq!(clip("abcdef", 4), "abc…");
        assert_eq!(parse_priority("high").unwrap(), 3);
        assert!(parse_priority("urgent").is_err());
    }

    #[test]
    fn reachability_explains_each_case() {
        let r = |json: &str| reachability(&Json::parse(json).unwrap());
        assert!(r(r#"{"inbound_public_peers":3}"#).starts_with("yes: 3 peers"));
        assert!(
            r(r#"{"firewall_status":"unlisted","inbound_public_peers":3}"#).contains("firewall")
        );
        assert!(r(r#"{"router_external_ip":"100.72.1.2"}"#).contains("carrier-grade"));
        assert!(
            r(r#"{"router_external_ip":"192.168.100.18","incoming_port":20000}"#)
                .contains("forward port 20000 to 192.168.100.18")
        );
        assert!(r(
            r#"{"router_external_ip":"192.168.100.18","upstream_status":"mapped upstream on port 20000"}"#
        )
        .contains("both routers"));
        assert!(
            r(r#"{"router_external_ip":"198.51.100.2","tracker_external_ip":"203.0.113.9"}"#)
                .contains("carrier-grade")
        );
        assert!(r(r#"{"upnp_status":"mapped upnp on port 20000"}"#).starts_with("not confirmed"));
        assert!(r(r#"{"incoming_port":20000}"#).contains("forward port 20000"));
    }

    #[test]
    fn state_labels_match_the_browser() {
        let t = |s: &str| Json::parse(s).unwrap();
        assert_eq!(
            state_label(&t(r#"{"status":"error","last_error":"x"}"#)),
            "error"
        );
        assert_eq!(
            state_label(&t(r#"{"status":"downloading","last_error":"x"}"#)),
            "downloading"
        );
        assert_eq!(
            state_label(&t(r#"{"status":"downloading","paused":true}"#)),
            "paused"
        );
        assert_eq!(
            state_label(&t(
                r#"{"status":"complete","total_pieces":2,"completed_pieces":2}"#
            )),
            "seeding"
        );
        assert_eq!(
            state_label(&t(r#"{"status":"fetching metadata"}"#)),
            "metadata"
        );
        assert_eq!(
            state_label(&t(r#"{"status":"waiting for peers"}"#)),
            "waiting"
        );
    }
}

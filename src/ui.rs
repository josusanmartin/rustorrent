use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::is_paused;

#[derive(Debug)]
pub enum UiCommand {
    AddTorrent {
        data: Vec<u8>,
        download_dir: String,
        preallocate: bool,
        reply: mpsc::Sender<UiCommandResult>,
    },
    AddMagnet {
        magnet: String,
        download_dir: String,
        preallocate: bool,
        reply: mpsc::Sender<UiCommandResult>,
    },
    PauseTorrent {
        torrent_id: u64,
        reply: mpsc::Sender<UiCommandResult>,
    },
    ResumeTorrent {
        torrent_id: u64,
        reply: mpsc::Sender<UiCommandResult>,
    },
    StopTorrent {
        torrent_id: u64,
        reply: mpsc::Sender<UiCommandResult>,
    },
    DeleteTorrent {
        torrent_id: u64,
        remove_data: bool,
        reply: mpsc::Sender<UiCommandResult>,
    },
    SetFilePriority {
        torrent_id: u64,
        file_index: usize,
        priority: u8,
        reply: mpsc::Sender<UiCommandResult>,
    },
    SetRateLimits {
        download_limit_bps: u64,
        upload_limit_bps: u64,
        reply: mpsc::Sender<UiCommandResult>,
    },
    RecheckTorrent {
        torrent_id: u64,
        reply: mpsc::Sender<UiCommandResult>,
    },
    SetSeedRatio {
        ratio: f64,
        reply: mpsc::Sender<UiCommandResult>,
    },
    SetLabel {
        torrent_id: u64,
        label: String,
        reply: mpsc::Sender<UiCommandResult>,
    },
    AddTracker {
        torrent_id: u64,
        url: String,
        reply: mpsc::Sender<UiCommandResult>,
    },
    RemoveTracker {
        torrent_id: u64,
        url: String,
        reply: mpsc::Sender<UiCommandResult>,
    },
    RenameFile {
        torrent_id: u64,
        file_index: usize,
        new_name: String,
        reply: mpsc::Sender<UiCommandResult>,
    },
    AddRssFeed {
        url: String,
        interval: u64,
        reply: mpsc::Sender<UiCommandResult>,
    },
    RemoveRssFeed {
        url: String,
        reply: mpsc::Sender<UiCommandResult>,
    },
    AddRssRule {
        name: String,
        feed_url: String,
        pattern: String,
        reply: mpsc::Sender<UiCommandResult>,
    },
    RemoveRssRule {
        name: String,
        reply: mpsc::Sender<UiCommandResult>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiCommandSuccess {
    Ok,
    TorrentAdded { torrent_id: u64 },
}

pub type UiCommandResult = Result<UiCommandSuccess, String>;

#[derive(Debug, Default, Clone)]
pub struct UiFile {
    pub path: String,
    pub length: u64,
    pub completed: u64,
    pub priority: u8,
}

#[derive(Debug, Default, Clone)]
pub struct UiState {
    pub name: String,
    pub info_hash: String,
    pub download_dir: String,
    pub total_pieces: usize,
    pub completed_pieces: usize,
    pub total_bytes: u64,
    pub completed_bytes: u64,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
    pub tracker_peers: usize,
    pub active_peers: usize,
    pub status: String,
    pub last_error: String,
    pub preallocate: bool,
    pub paused: bool,
    pub download_rate_bps: f64,
    pub upload_rate_bps: f64,
    pub eta_secs: u64,
    pub files: Vec<UiFile>,
    pub queue_len: usize,
    pub last_added: String,
    pub torrents: Vec<UiTorrent>,
    pub deleted_torrents: HashSet<u64>,
    pub current_id: Option<u64>,
    pub peer_connected: u64,
    pub peer_disconnected: u64,
    pub disk_read_ms_avg: f64,
    pub disk_write_ms_avg: f64,
    pub session_downloaded_bytes: u64,
    pub session_uploaded_bytes: u64,
    pub global_download_limit_bps: u64,
    pub global_upload_limit_bps: u64,
    pub seed_ratio: f64,
    pub proxy_label: String,
}

#[derive(Debug, Default, Clone)]
pub struct UiTorrent {
    pub id: u64,
    pub name: String,
    pub info_hash: String,
    pub download_dir: String,
    pub preallocate: bool,
    pub status: String,
    pub total_bytes: u64,
    pub completed_bytes: u64,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
    pub total_pieces: usize,
    pub completed_pieces: usize,
    pub download_rate_bps: f64,
    pub upload_rate_bps: f64,
    pub eta_secs: u64,
    pub tracker_peers: usize,
    pub active_peers: usize,
    pub paused: bool,
    pub last_error: String,
    pub files: Vec<UiFile>,
    pub label: String,
    pub trackers: Vec<String>,
    pub peer_country_counts: Vec<(String, u32)>,
    pub meta_version: u8,
}

fn lock_state(state: &Arc<Mutex<UiState>>) -> MutexGuard<'_, UiState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            guard.last_error = "ui state lock poisoned; recovered".to_string();
            guard
        }
    }
}

const API_TOKEN_HEADER: &str = "x-rustorrent-token";
static UI_API_TOKEN: OnceLock<String> = OnceLock::new();

fn api_token() -> &'static str {
    UI_API_TOKEN.get_or_init(generate_api_token).as_str()
}

fn generate_api_token() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut file) = File::open("/dev/urandom") {
        if file.read_exact(&mut bytes).is_ok() {
            return hex_bytes(&bytes);
        }
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut seed = nanos as u64 ^ ((nanos >> 64) as u64) ^ std::process::id() as u64;
    for slot in &mut bytes {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *slot = (seed & 0xff) as u8;
    }
    hex_bytes(&bytes)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

struct UiConnectionGuard {
    active: Arc<AtomicUsize>,
}

impl Drop for UiConnectionGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

fn try_acquire_ui_connection_slot(active: &Arc<AtomicUsize>) -> Option<UiConnectionGuard> {
    loop {
        let current = active.load(Ordering::SeqCst);
        if current >= UI_MAX_ACTIVE_CONNECTIONS {
            return None;
        }
        if active
            .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Some(UiConnectionGuard {
                active: Arc::clone(active),
            });
        }
    }
}

pub fn start(
    addr: String,
    state: Arc<Mutex<UiState>>,
    cmd_tx: Option<mpsc::Sender<UiCommand>>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(&addr)?;
    let active_connections = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let Some(slot_guard) = try_acquire_ui_connection_slot(&active_connections) else {
                    let _ = send_api_error_with_status(stream, 503, "ui busy");
                    continue;
                };
                let state = state.clone();
                let cmd_tx = cmd_tx.clone();
                thread::spawn(move || {
                    let _slot_guard = slot_guard;
                    let _ = handle_connection(stream, state, cmd_tx);
                });
            }
        }
    });
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<UiState>>,
    cmd_tx: Option<mpsc::Sender<UiCommand>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(UI_READ_TIMEOUT))?;
    stream.set_write_timeout(Some(UI_WRITE_TIMEOUT))?;
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(_) => {
            return send_api_error(stream, "bad request");
        }
    };
    let (path, query) = split_path_query(&request.path);

    if request.method == "GET" && path == "/api-token" {
        return send_api_token(stream);
    }
    if request.method == "HEAD" && path == "/api-token" {
        return send_head(stream, "application/json");
    }
    if request.method == "GET" && path == "/events" {
        return handle_sse(stream, state);
    }
    if request.method == "HEAD" && path == "/events" {
        return send_head(stream, "text/event-stream");
    }

    if request.method == "POST" {
        if let Err(err) = authorize_mutating_request(&request) {
            return send_api_error_with_status(stream, 403, &err);
        }
        if path == "/torrent/open-folder" {
            if let Err(err) = handle_open_folder(&query, &state) {
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/torrent/pause"
            || path == "/torrent/resume"
            || path == "/torrent/stop"
            || path == "/torrent/delete"
        {
            if let Err(err) = handle_torrent_action(&path, &query, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/add-torrent" {
            let torrent_id = match handle_add_torrent(&request, &query, &state, &cmd_tx) {
                Ok(torrent_id) => torrent_id,
                Err(err) => {
                    update_error(&state, &err);
                    return send_api_error(stream, &err);
                }
            };
            return send_api_ok_with_torrent_id(stream, torrent_id);
        }
        if path == "/add-magnet" {
            let torrent_id = match handle_add_magnet(&request, &state, &cmd_tx) {
                Ok(torrent_id) => torrent_id,
                Err(err) => {
                    update_error(&state, &err);
                    return send_api_error(stream, &err);
                }
            };
            return send_api_ok_with_torrent_id(stream, torrent_id);
        }
        if path == "/select-download-dir" {
            match handle_select_download_dir() {
                Ok(Some(path)) => return send_api_ok_with_path(stream, &path),
                Ok(None) => return send_api_ok_with_path(stream, ""),
                Err(err) => return send_api_error(stream, &err),
            }
        }
        if path == "/file-priority" {
            if let Err(err) = handle_file_priority(&request, &state, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/rename-file" {
            if let Err(err) = handle_rename_file(&request, &state, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/rate-limits" {
            if let Err(err) = handle_rate_limits(&request, &state, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/torrent/recheck" {
            if let Err(err) = handle_torrent_recheck(&query, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/settings/seed-ratio" {
            if let Err(err) = handle_set_seed_ratio(&request, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/torrent/set-label" {
            if let Err(err) = handle_set_label(&request, &state, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/torrent/add-tracker" {
            if let Err(err) = handle_add_tracker(&request, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/torrent/remove-tracker" {
            if let Err(err) = handle_remove_tracker(&request, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/rss/add-feed" {
            if let Err(err) = handle_rss_add_feed(&request, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/rss/remove-feed" {
            if let Err(err) = handle_rss_remove_feed(&request, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/rss/add-rule" {
            if let Err(err) = handle_rss_add_rule(&request, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        if path == "/rss/remove-rule" {
            if let Err(err) = handle_rss_remove_rule(&request, &cmd_tx) {
                update_error(&state, &err);
                return send_api_error(stream, &err);
            }
            return send_api_ok(stream);
        }
        return send_api_error_with_status(stream, 404, "unknown endpoint");
    }

    if path == "/rss/status" {
        let body = rss_status_json();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
        return Ok(());
    }

    let mut guard = lock_state(&state);
    guard.paused = is_paused();
    let (content_type, body) = if path == "/status" {
        ("application/json", status_json(&guard))
    } else {
        ("text/html; charset=utf-8", status_html(&guard))
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const COMMAND_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const UI_MAX_ACTIVE_CONNECTIONS: usize = 64;
const UI_READ_TIMEOUT: Duration = Duration::from_secs(1);
const UI_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(15);

struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header_value(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| key == &name)
            .map(|(_, value)| value.as_str())
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<HttpRequest> {
    let mut buffer = Vec::with_capacity(1024);
    let mut header_end = None;
    let header_deadline = Instant::now() + REQUEST_HEADER_TIMEOUT;
    loop {
        if Instant::now() >= header_deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request header timeout",
            ));
        }
        let mut chunk = [0u8; 1024];
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            Err(err) if is_retryable_io_error(&err) => continue,
            Err(err) => return Err(err),
        };
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.len() > MAX_HEADER_BYTES + MAX_BODY_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        if let Some(pos) = find_header_end(&buffer) {
            header_end = Some(pos);
            break;
        }
    }

    let header_end = header_end
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid request"))?;
    let header_str = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = header_str.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid request"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid path"))?
        .to_string();
    if !path.starts_with('/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid path",
        ));
    }

    let mut content_length = 0usize;
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let header_name = name.trim().to_ascii_lowercase();
            let header_value = value.trim().to_string();
            headers.push((header_name.clone(), header_value.clone()));
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = header_value.parse::<usize>().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid content length")
                })?;
            }
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }

    let mut body = buffer[header_end + 4..].to_vec();
    let body_deadline = Instant::now() + REQUEST_BODY_TIMEOUT;
    while body.len() < content_length {
        if Instant::now() >= body_deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request body timeout",
            ));
        }
        let mut chunk = [0u8; 1024];
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            Err(err) if is_retryable_io_error(&err) => continue,
            Err(err) => return Err(err),
        };
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > content_length {
            body.truncate(content_length);
            break;
        }
    }
    if body.len() < content_length {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "request body truncated",
        ));
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn is_retryable_io_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

fn split_path_query(path: &str) -> (String, Vec<(String, String)>) {
    match path.split_once('?') {
        Some((path, query)) => (path.to_string(), parse_query_pairs(query)),
        None => (path.to_string(), Vec::new()),
    }
}

fn dispatch_command(
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
    build: impl FnOnce(mpsc::Sender<UiCommandResult>) -> UiCommand,
) -> Result<UiCommandSuccess, String> {
    let Some(tx) = cmd_tx.as_ref() else {
        return Err("ui command channel closed".to_string());
    };
    let (reply_tx, reply_rx) = mpsc::channel::<UiCommandResult>();
    tx.send(build(reply_tx))
        .map_err(|_| "ui command channel closed".to_string())?;
    match reply_rx.recv_timeout(COMMAND_WAIT_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err("ui command timeout".to_string()),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("ui command response channel closed".to_string())
        }
    }
}

fn dispatch_command_ok(
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
    build: impl FnOnce(mpsc::Sender<UiCommandResult>) -> UiCommand,
) -> Result<(), String> {
    let _ = dispatch_command(cmd_tx, build)?;
    Ok(())
}

fn handle_add_torrent(
    request: &HttpRequest,
    query: &[(String, String)],
    state: &Arc<Mutex<UiState>>,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<u64, String> {
    if request.body.is_empty() {
        return Err("empty torrent upload".to_string());
    }
    let download_dir = query_value(query, "dir").unwrap_or("").to_string();
    let preallocate = query_value(query, "prealloc")
        .map(parse_bool)
        .unwrap_or(false);

    let command_result = dispatch_command(cmd_tx, |reply| UiCommand::AddTorrent {
        data: request.body.clone(),
        download_dir,
        preallocate,
        reply,
    })?;
    let torrent_id = match command_result {
        UiCommandSuccess::TorrentAdded { torrent_id } => torrent_id,
        UiCommandSuccess::Ok => {
            return Err("ui command response missing torrent id".to_string());
        }
    };

    if let Ok(mut guard) = state.lock() {
        guard.last_added = "torrent upload".to_string();
        guard.status = "queued".to_string();
    }
    Ok(torrent_id)
}

fn handle_add_magnet(
    request: &HttpRequest,
    state: &Arc<Mutex<UiState>>,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<u64, String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let magnet = query_value(&form, "magnet").unwrap_or("").to_string();
    if magnet.trim().is_empty() {
        return Err("magnet link is empty".to_string());
    }
    let download_dir = query_value(&form, "dir").unwrap_or("").to_string();
    let preallocate = query_value(&form, "prealloc")
        .map(parse_bool)
        .unwrap_or(false);

    let command_result = dispatch_command(cmd_tx, |reply| UiCommand::AddMagnet {
        magnet,
        download_dir,
        preallocate,
        reply,
    })?;
    let torrent_id = match command_result {
        UiCommandSuccess::TorrentAdded { torrent_id } => torrent_id,
        UiCommandSuccess::Ok => {
            return Err("ui command response missing torrent id".to_string());
        }
    };

    if let Ok(mut guard) = state.lock() {
        guard.last_added = "magnet link".to_string();
        guard.status = "queued".to_string();
    }
    Ok(torrent_id)
}

fn handle_file_priority(
    request: &HttpRequest,
    state: &Arc<Mutex<UiState>>,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let index = query_value(&form, "index")
        .ok_or_else(|| "missing index".to_string())?
        .parse::<usize>()
        .map_err(|_| "invalid index".to_string())?;
    let priority = query_value(&form, "priority")
        .ok_or_else(|| "missing priority".to_string())?
        .parse::<u8>()
        .map_err(|_| "invalid priority".to_string())?;
    let torrent_id = query_value(&form, "id")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "missing torrent id".to_string())?;

    dispatch_command_ok(cmd_tx, |reply| UiCommand::SetFilePriority {
        torrent_id,
        file_index: index,
        priority,
        reply,
    })?;

    let mut guard = lock_state(state);
    if let Some(torrent) = guard
        .torrents
        .iter_mut()
        .find(|torrent| torrent.id == torrent_id)
    {
        if let Some(file) = torrent.files.get_mut(index) {
            file.priority = priority;
        }
    }
    if guard.current_id == Some(torrent_id) {
        if let Some(file) = guard.files.get_mut(index) {
            file.priority = priority;
        }
    }
    Ok(())
}

fn handle_rename_file(
    request: &HttpRequest,
    state: &Arc<Mutex<UiState>>,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let index = query_value(&form, "index")
        .ok_or_else(|| "missing index".to_string())?
        .parse::<usize>()
        .map_err(|_| "invalid index".to_string())?;
    let new_name = query_value(&form, "name")
        .ok_or_else(|| "missing name".to_string())?
        .to_string();
    if new_name.is_empty()
        || new_name.contains('/')
        || new_name.contains('\\')
        || new_name.contains('\0')
        || new_name == "."
        || new_name == ".."
    {
        return Err("invalid file name".to_string());
    }
    let torrent_id = query_value(&form, "id")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "missing torrent id".to_string())?;

    dispatch_command_ok(cmd_tx, |reply| UiCommand::RenameFile {
        torrent_id,
        file_index: index,
        new_name: new_name.clone(),
        reply,
    })?;

    let mut guard = lock_state(state);
    if let Some(torrent) = guard
        .torrents
        .iter_mut()
        .find(|torrent| torrent.id == torrent_id)
    {
        if let Some(file) = torrent.files.get_mut(index) {
            if let Some(pos) = file.path.rfind('/') {
                file.path = format!("{}/{}", &file.path[..pos], new_name);
            } else {
                file.path = new_name.clone();
            }
        }
    }
    if guard.current_id == Some(torrent_id) {
        if let Some(file) = guard.files.get_mut(index) {
            if let Some(pos) = file.path.rfind('/') {
                file.path = format!("{}/{}", &file.path[..pos], new_name);
            } else {
                file.path = new_name;
            }
        }
    }
    Ok(())
}

fn handle_rss_add_feed(
    request: &HttpRequest,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let url = query_value(&form, "url")
        .ok_or_else(|| "missing url".to_string())?
        .to_string();
    if url.is_empty() {
        return Err("empty url".to_string());
    }
    let interval = query_value(&form, "interval")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(900);
    dispatch_command_ok(cmd_tx, |reply| UiCommand::AddRssFeed {
        url: url.clone(),
        interval,
        reply,
    })
}

fn handle_rss_remove_feed(
    request: &HttpRequest,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let url = query_value(&form, "url")
        .ok_or_else(|| "missing url".to_string())?
        .to_string();
    dispatch_command_ok(cmd_tx, |reply| UiCommand::RemoveRssFeed {
        url: url.clone(),
        reply,
    })
}

fn handle_rss_add_rule(
    request: &HttpRequest,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let name = query_value(&form, "name")
        .ok_or_else(|| "missing name".to_string())?
        .to_string();
    let feed_url = query_value(&form, "feed_url").unwrap_or("").to_string();
    let pattern = query_value(&form, "pattern")
        .ok_or_else(|| "missing pattern".to_string())?
        .to_string();
    dispatch_command_ok(cmd_tx, |reply| UiCommand::AddRssRule {
        name: name.clone(),
        feed_url: feed_url.clone(),
        pattern: pattern.clone(),
        reply,
    })
}

fn handle_rss_remove_rule(
    request: &HttpRequest,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let name = query_value(&form, "name")
        .ok_or_else(|| "missing name".to_string())?
        .to_string();
    dispatch_command_ok(cmd_tx, |reply| UiCommand::RemoveRssRule {
        name: name.clone(),
        reply,
    })
}

fn rss_status_json() -> String {
    use crate::RSS_STATE;

    let lock = match RSS_STATE.get() {
        Some(lock) => lock,
        None => return "{\"feeds\":[],\"rules\":[]}".to_string(),
    };
    let state = match lock.lock() {
        Ok(guard) => guard,
        Err(_) => return "{\"feeds\":[],\"rules\":[]}".to_string(),
    };
    let mut out = String::from("{\"feeds\":[");
    for (i, feed) in state.feeds.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"url\":\"{}\",\"title\":\"{}\",\"items\":{},\"last_poll\":{},\"interval\":{}}}",
            escape_json(&feed.url),
            escape_json(&feed.title),
            feed.items.len(),
            feed.last_poll,
            feed.poll_interval_secs,
        ));
    }
    out.push_str("],\"rules\":[");
    for (i, rule) in state.rules.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"name\":\"{}\",\"feed_url\":\"{}\",\"pattern\":\"{}\"}}",
            escape_json(&rule.name),
            escape_json(&rule.feed_url),
            escape_json(&rule.pattern),
        ));
    }
    out.push_str("]}");
    out
}

fn handle_rate_limits(
    request: &HttpRequest,
    state: &Arc<Mutex<UiState>>,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let download_kbps = query_value(&form, "download_kbps")
        .ok_or_else(|| "missing download_kbps".to_string())?
        .parse::<u64>()
        .map_err(|_| "invalid download_kbps".to_string())?;
    let upload_kbps = query_value(&form, "upload_kbps")
        .ok_or_else(|| "missing upload_kbps".to_string())?
        .parse::<u64>()
        .map_err(|_| "invalid upload_kbps".to_string())?;
    let download_limit_bps = download_kbps.saturating_mul(1024);
    let upload_limit_bps = upload_kbps.saturating_mul(1024);

    dispatch_command_ok(cmd_tx, |reply| UiCommand::SetRateLimits {
        download_limit_bps,
        upload_limit_bps,
        reply,
    })?;

    let mut guard = lock_state(state);
    guard.global_download_limit_bps = download_limit_bps;
    guard.global_upload_limit_bps = upload_limit_bps;
    Ok(())
}

fn handle_torrent_recheck(
    query: &[(String, String)],
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let torrent_id = query_value(query, "id")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "missing torrent id".to_string())?;
    dispatch_command_ok(cmd_tx, |reply| UiCommand::RecheckTorrent {
        torrent_id,
        reply,
    })
}

fn handle_set_seed_ratio(
    request: &HttpRequest,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let ratio = query_value(&form, "ratio")
        .ok_or_else(|| "missing ratio".to_string())?
        .parse::<f64>()
        .map_err(|_| "invalid ratio".to_string())?;
    if ratio < 0.0 {
        return Err("ratio must be >= 0".to_string());
    }
    dispatch_command_ok(cmd_tx, |reply| UiCommand::SetSeedRatio { ratio, reply })
}

fn handle_set_label(
    request: &HttpRequest,
    state: &Arc<Mutex<UiState>>,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let torrent_id = query_value(&form, "id")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| "missing torrent id".to_string())?;
    let label = query_value(&form, "label").unwrap_or("").to_string();

    dispatch_command_ok(cmd_tx, |reply| UiCommand::SetLabel {
        torrent_id,
        label: label.clone(),
        reply,
    })?;

    let mut guard = lock_state(state);
    if let Some(torrent) = guard.torrents.iter_mut().find(|t| t.id == torrent_id) {
        torrent.label = label;
    }
    Ok(())
}

fn handle_add_tracker(
    request: &HttpRequest,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let torrent_id = query_value(&form, "id")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| "missing torrent id".to_string())?;
    let url = query_value(&form, "url")
        .ok_or_else(|| "missing tracker url".to_string())?
        .to_string();
    if url.trim().is_empty() {
        return Err("tracker url is empty".to_string());
    }
    dispatch_command_ok(cmd_tx, |reply| UiCommand::AddTracker {
        torrent_id,
        url,
        reply,
    })
}

fn handle_remove_tracker(
    request: &HttpRequest,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(&request.body);
    let form = parse_query_pairs(&body_str);
    let torrent_id = query_value(&form, "id")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| "missing torrent id".to_string())?;
    let url = query_value(&form, "url")
        .ok_or_else(|| "missing tracker url".to_string())?
        .to_string();
    dispatch_command_ok(cmd_tx, |reply| UiCommand::RemoveTracker {
        torrent_id,
        url,
        reply,
    })
}

fn handle_select_download_dir() -> Result<Option<String>, String> {
    select_download_dir()
}

#[cfg(target_os = "macos")]
fn select_download_dir() -> Result<Option<String>, String> {
    let output = Command::new("osascript")
        .args([
            "-e",
            "set chosenFolder to POSIX path of (choose folder with prompt \"Select download folder\")",
            "-e",
            "return chosenFolder",
        ])
        .output()
        .map_err(|err| format!("failed to launch folder picker: {err}"))?;

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("user canceled") || lower.contains("user cancelled") || lower.contains("-128")
    {
        return Ok(None);
    }
    if !output.status.success() {
        let detail = stderr.trim();
        if detail.is_empty() {
            return Err("failed to open folder picker".to_string());
        }
        return Err(format!("failed to open folder picker: {detail}"));
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return Err("folder picker returned empty path".to_string());
    }
    Ok(Some(path))
}

#[cfg(not(target_os = "macos"))]
fn select_download_dir() -> Result<Option<String>, String> {
    Err("folder picker not available on this platform".to_string())
}

fn handle_torrent_action(
    path: &str,
    query: &[(String, String)],
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let torrent_id = query_value(query, "id")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "missing torrent id".to_string())?;
    enum TorrentActionKind {
        Pause,
        Resume,
        Stop,
        Delete { remove_data: bool },
    }
    let action = match path {
        "/torrent/pause" => TorrentActionKind::Pause,
        "/torrent/resume" => TorrentActionKind::Resume,
        "/torrent/stop" => TorrentActionKind::Stop,
        "/torrent/delete" => TorrentActionKind::Delete {
            remove_data: query_value(query, "data").map(parse_bool).unwrap_or(false),
        },
        _ => return Err("unknown action".to_string()),
    };
    dispatch_command_ok(cmd_tx, |reply| match action {
        TorrentActionKind::Pause => UiCommand::PauseTorrent { torrent_id, reply },
        TorrentActionKind::Resume => UiCommand::ResumeTorrent { torrent_id, reply },
        TorrentActionKind::Stop => UiCommand::StopTorrent { torrent_id, reply },
        TorrentActionKind::Delete { remove_data } => UiCommand::DeleteTorrent {
            torrent_id,
            remove_data,
            reply,
        },
    })
}

fn handle_open_folder(
    query: &[(String, String)],
    state: &Arc<Mutex<UiState>>,
) -> Result<(), String> {
    let torrent_id = query_value(query, "id")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "missing torrent id".to_string())?;
    let guard = lock_state(state);
    let torrent = guard
        .torrents
        .iter()
        .find(|t| t.id == torrent_id)
        .ok_or_else(|| "torrent not found".to_string())?;
    let dir = torrent.download_dir.clone();
    drop(guard);
    if dir.is_empty() {
        return Err("no download directory".to_string());
    }
    if !std::path::Path::new(&dir).exists() {
        return Err("directory does not exist".to_string());
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(&dir)
            .spawn()
            .map_err(|err| format!("open failed: {err}"))?;
    }
    #[cfg(target_os = "linux")]
    {
        Command::new("xdg-open")
            .arg(&dir)
            .spawn()
            .map_err(|err| format!("open failed: {err}"))?;
    }
    #[cfg(target_os = "windows")]
    {
        Command::new("explorer")
            .arg(&dir)
            .spawn()
            .map_err(|err| format!("open failed: {err}"))?;
    }
    Ok(())
}

fn query_value<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn parse_query_pairs(query: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        out.push((percent_decode(key), percent_decode(value)));
    }
    out
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        match bytes[idx] {
            b'%' if idx + 2 < bytes.len() => {
                let hi = bytes[idx + 1] as char;
                let lo = bytes[idx + 2] as char;
                if let (Some(hi), Some(lo)) = (hi.to_digit(16), lo.to_digit(16)) {
                    out.push((hi * 16 + lo) as u8 as char);
                    idx += 3;
                    continue;
                }
            }
            b'+' => {
                out.push(' ');
                idx += 1;
                continue;
            }
            _ => {}
        }
        out.push(bytes[idx] as char);
        idx += 1;
    }
    out
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn extract_origin_host(origin: &str) -> Option<String> {
    let rest = origin
        .trim()
        .strip_prefix("http://")
        .or_else(|| origin.trim().strip_prefix("https://"))?;
    let host = rest.split('/').next()?.trim().to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn request_origin_matches_host(request: &HttpRequest) -> bool {
    let Some(origin) = request.header_value("origin") else {
        return true;
    };
    let Some(origin_host) = extract_origin_host(origin) else {
        return false;
    };
    let request_host = request
        .header_value("host")
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    !request_host.is_empty() && request_host == origin_host
}

fn has_valid_api_token(request: &HttpRequest) -> bool {
    request
        .header_value(API_TOKEN_HEADER)
        .map(|value| value == api_token())
        .unwrap_or(false)
}

fn authorize_mutating_request(request: &HttpRequest) -> Result<(), String> {
    if !has_valid_api_token(request) {
        return Err("missing or invalid api token".to_string());
    }
    if !request_origin_matches_host(request) {
        return Err("forbidden origin".to_string());
    }
    Ok(())
}

fn update_error(state: &Arc<Mutex<UiState>>, message: &str) {
    let mut guard = lock_state(state);
    guard.last_error = message.to_string();
    if guard.status != "downloading" {
        guard.status = "error".to_string();
    }
}

fn reason_phrase(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    }
}

fn status_for_error(message: &str) -> u16 {
    let lower = message.to_ascii_lowercase();
    if lower.contains("timeout") {
        504
    } else if lower.contains("invalid api token")
        || lower.contains("missing api token")
        || lower.contains("forbidden origin")
    {
        403
    } else if lower.contains("unknown torrent") {
        404
    } else if lower.contains("already added") {
        409
    } else if lower.contains("not ready")
        || lower.contains("service unavailable")
        || lower.contains("channel closed")
    {
        503
    } else if lower.contains("invalid")
        || lower.contains("missing")
        || lower.contains("empty")
        || lower.contains("unknown action")
        || lower.contains("bad request")
    {
        400
    } else {
        409
    }
}

fn send_json_body(mut stream: TcpStream, code: u16, body: &str) -> std::io::Result<()> {
    let reason = reason_phrase(code);
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

fn send_api_ok(stream: TcpStream) -> std::io::Result<()> {
    send_json_body(stream, 200, r#"{"ok":true}"#)
}

fn send_api_ok_with_torrent_id(stream: TcpStream, torrent_id: u64) -> std::io::Result<()> {
    let body = format!(r#"{{"ok":true,"torrent_id":{torrent_id}}}"#);
    send_json_body(stream, 200, &body)
}

fn send_api_ok_with_path(stream: TcpStream, path: &str) -> std::io::Result<()> {
    let body = format!(r#"{{"ok":true,"path":"{}"}}"#, escape_json(path));
    send_json_body(stream, 200, &body)
}

fn send_api_error(stream: TcpStream, message: &str) -> std::io::Result<()> {
    send_api_error_with_status(stream, status_for_error(message), message)
}

fn send_api_error_with_status(stream: TcpStream, code: u16, message: &str) -> std::io::Result<()> {
    let body = format!("{{\"ok\":false,\"error\":\"{}\"}}", escape_json(message));
    send_json_body(stream, code, &body)
}

fn send_head(mut stream: TcpStream, content_type: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream.write_all(response.as_bytes())
}

fn send_api_token(stream: TcpStream) -> std::io::Result<()> {
    let body = format!(r#"{{"token":"{}"}}"#, escape_json(api_token()));
    send_json_body(stream, 200, &body)
}

fn handle_sse(mut stream: TcpStream, state: Arc<Mutex<UiState>>) -> std::io::Result<()> {
    let response = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(response.as_bytes())?;
    stream.flush()?;

    let mut last_payload = String::new();
    let mut last_ping = Instant::now();
    loop {
        let payload = {
            let guard = lock_state(&state);
            app_body_html(&guard)
        };
        if payload != last_payload {
            if write_sse_event(&mut stream, "status", &payload).is_err() {
                break;
            }
            last_payload = payload;
            last_ping = Instant::now();
        } else if last_ping.elapsed() > Duration::from_secs(15) {
            if write_sse_comment(&mut stream, "ping").is_err() {
                break;
            }
            last_ping = Instant::now();
        }
        thread::sleep(Duration::from_millis(450));
    }
    Ok(())
}

fn write_sse_event(stream: &mut TcpStream, event: &str, data: &str) -> std::io::Result<()> {
    stream.write_all(format!("event: {event}\n").as_bytes())?;
    for line in data.split('\n') {
        stream.write_all(b"data: ")?;
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\n")?;
    }
    stream.write_all(b"\n")?;
    stream.flush()
}

fn write_sse_comment(stream: &mut TcpStream, comment: &str) -> std::io::Result<()> {
    stream.write_all(format!(": {comment}\n\n").as_bytes())?;
    stream.flush()
}

fn status_html(state: &UiState) -> String {
    let mut out = String::with_capacity(5200 + state.torrents.len() * 2200);
    out.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    out.push_str("<title>rustorrent</title>");
    out.push_str("<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">");
    out.push_str("<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>");
    out.push_str("<link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap\" rel=\"stylesheet\">");
    out.push_str("<link href=\"https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200\" rel=\"stylesheet\">");
    out.push_str(&format!(
        "<meta name=\"rustorrent-api-token\" content=\"{}\">",
        escape_html(api_token())
    ));
    out.push_str("<script>try{var t=localStorage.getItem('rustorrent-theme');if(t!=='light'&&t!=='dark'){t='light';}document.documentElement.setAttribute('data-theme',t);}catch(e){}</script>");
    out.push_str(r#"<style>
.material-symbols-rounded{font-variation-settings:'FILL' 0,'wght' 500,'GRAD' 0,'opsz' 24;vertical-align:middle}
:root{
  color-scheme:dark;
  --bg:#111318;
  --surface:#1b1f27;
  --surface-cont:#222730;
  --surface-cont-high:#2a303a;
  --surface-cont-highest:#323842;
  --on-surface:#e3e3e8;
  --on-surface-var:#c4c6cf;
  --primary:#a8c7fa;
  --on-primary:#0a305f;
  --primary-cont:#1b4b8a;
  --on-primary-cont:#d3e3fd;
  --secondary:#bec6dc;
  --on-secondary:#283141;
  --secondary-cont:#3e4758;
  --on-secondary-cont:#dae2f9;
  --tertiary:#9ecaff;
  --error:#ffb4ab;
  --on-error:#690005;
  --error-cont:#93000a;
  --on-error-cont:#ffdad6;
  --outline:#8e9199;
  --outline-var:#44474e;
  --success:#81d994;
  --success-cont:rgba(76,175,80,.16);
  --warning:#ffd66b;
  --warning-cont:rgba(251,192,45,.16);
  --danger-cont:rgba(244,67,54,.14);
  --inverse-surface:#e3e3e8;
  --inverse-on-surface:#2f3036;
  --elevation-1:0 1px 3px 1px rgba(0,0,0,.15),0 1px 2px rgba(0,0,0,.3);
  --elevation-2:0 2px 6px 2px rgba(0,0,0,.15),0 1px 2px rgba(0,0,0,.3);
  --elevation-3:0 4px 8px 3px rgba(0,0,0,.15),0 1px 3px rgba(0,0,0,.3);
  --state-hover:rgba(168,199,250,.08);
  --state-press:rgba(168,199,250,.12);
}
:root[data-theme="light"]{
  color-scheme:light;
  --bg:#f8f9fc;
  --surface:#fff;
  --surface-cont:#f0f1f6;
  --surface-cont-high:#e8eaef;
  --surface-cont-highest:#e1e3e9;
  --on-surface:#1b1f27;
  --on-surface-var:#44474e;
  --primary:#0b57d0;
  --on-primary:#fff;
  --primary-cont:#d3e3fd;
  --on-primary-cont:#062e6f;
  --secondary:#565f71;
  --on-secondary:#fff;
  --secondary-cont:#dae2f9;
  --on-secondary-cont:#131c2b;
  --tertiary:#0842a0;
  --error:#ba1a1a;
  --on-error:#fff;
  --error-cont:#ffdad6;
  --on-error-cont:#410002;
  --outline:#74777f;
  --outline-var:#c4c6cf;
  --success:#1b8726;
  --success-cont:rgba(76,175,80,.12);
  --warning:#7c5800;
  --warning-cont:rgba(251,192,45,.14);
  --danger-cont:rgba(244,67,54,.1);
  --inverse-surface:#2f3036;
  --inverse-on-surface:#f1f0f7;
  --elevation-1:0 1px 3px 1px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.04);
  --elevation-2:0 2px 6px 2px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.04);
  --elevation-3:0 4px 8px 3px rgba(0,0,0,.08),0 1px 3px rgba(0,0,0,.04);
  --state-hover:rgba(11,87,208,.08);
  --state-press:rgba(11,87,208,.12);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%}
body{
  font:14px/1.5 "Inter",system-ui,-apple-system,sans-serif;
  color:var(--on-surface);
  background:var(--bg);
  -webkit-font-smoothing:antialiased;
}
.app{width:100%;max-width:1600px;margin:0 auto;padding:16px 24px 48px}
.appbar{
  position:sticky;
  top:0;
  z-index:20;
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:16px;
  padding:12px 24px;
  background:var(--surface);
  border-bottom:1px solid var(--outline-var);
  margin:-16px -24px 0;
  box-shadow:var(--elevation-1);
}
.brand{display:flex;align-items:center;gap:12px}
.brand-icon{
  width:36px;height:36px;
  border-radius:12px;
  background:var(--primary);
  color:var(--on-primary);
  display:grid;place-items:center;
  font-size:20px;
}
.brand .title{font:700 20px/1 "Inter",sans-serif;letter-spacing:-.02em}
.brand .sub{font:500 12px/1 "Inter",sans-serif;color:var(--on-surface-var);margin-top:2px}
.app-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.chip{
  display:inline-flex;align-items:center;gap:4px;
  height:32px;padding:0 12px;
  border-radius:8px;
  background:var(--surface-cont);
  color:var(--on-surface-var);
  font:500 12px "Inter",sans-serif;
  border:1px solid var(--outline-var);
}
.chip .material-symbols-rounded{font-size:16px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap}
.btn{
  display:inline-flex;align-items:center;gap:6px;
  height:36px;
  padding:0 16px;
  border-radius:20px;
  border:none;
  font:500 13px/1 "Inter",sans-serif;
  letter-spacing:.02em;
  cursor:pointer;
  transition:all .2s cubic-bezier(.2,0,0,1);
  background:var(--surface-cont-high);
  color:var(--on-surface);
}
.btn .material-symbols-rounded{font-size:18px}
.btn:hover{background:var(--surface-cont-highest);box-shadow:var(--elevation-1)}
.btn:active{transform:scale(.97)}
.btn:disabled{opacity:.38;cursor:not-allowed;transform:none;box-shadow:none}
.btn.primary{background:var(--primary);color:var(--on-primary);font-weight:600}
.btn.primary:hover{box-shadow:var(--elevation-2);filter:brightness(1.06)}
.btn.danger{background:var(--danger-cont);color:var(--error)}
.btn.ghost{background:transparent;color:var(--on-surface-var)}
.btn.ghost:hover{background:var(--state-hover)}
.btn.icon-btn{width:40px;height:40px;padding:0;border-radius:20px;justify-content:center}
.btn.icon-btn .material-symbols-rounded{font-size:20px}
:root.theme-switching,:root.theme-switching *{transition:none!important;animation:none!important}
.layout{
  display:flex;
  align-items:flex-start;
  gap:24px;
  margin-top:24px;
}
.panel{
  background:var(--surface);
  border:1px solid var(--outline-var);
  border-radius:16px;
  padding:16px;
  box-shadow:var(--elevation-1);
}
.panel-title{
  font:600 11px/1 "Inter",sans-serif;
  text-transform:uppercase;
  letter-spacing:.1em;
  color:var(--on-surface-var);
}
.sidebar{
  flex:0 0 260px;
  width:260px;
  position:sticky;
  top:72px;
  align-self:start;
  display:flex;flex-direction:column;gap:16px;
}
.nav{display:flex;flex-direction:column;gap:2px;margin-top:12px}
.nav-item{
  display:flex;align-items:center;justify-content:space-between;
  height:40px;
  padding:0 12px;
  border-radius:100px;
  color:var(--on-surface-var);
  text-decoration:none;
  border:none;
  background:transparent;
  font:500 13px/1 "Inter",sans-serif;
  cursor:pointer;
  width:100%;
  text-align:left;
  transition:background .15s ease,color .15s ease;
}
.nav-item .nav-label{display:flex;align-items:center;gap:10px}
.nav-item .material-symbols-rounded{font-size:20px}
.nav-item:focus-visible{outline:2px solid var(--primary);outline-offset:-2px;border-radius:100px}
.nav-item:hover{background:var(--state-hover)}
.nav-item.active{
  background:var(--primary-cont);
  color:var(--on-primary-cont);
  font-weight:600;
}
.count{
  min-width:24px;height:20px;
  display:inline-flex;align-items:center;justify-content:center;
  border-radius:100px;
  padding:0 6px;
  font:600 11px "Inter",sans-serif;
  background:var(--surface-cont-high);
  color:var(--on-surface-var);
}
.nav-item.active .count{background:rgba(168,199,250,.18);color:var(--on-primary-cont)}
:root[data-theme="light"] .nav-item.active .count{background:rgba(11,87,208,.12)}
.small{font:400 12px/1.5 "Inter",sans-serif;color:var(--on-surface-var)}
.small + .small{margin-top:2px}
.session-stats{display:flex;flex-direction:column;gap:4px;margin-top:10px}
.session-row{
  display:flex;align-items:center;justify-content:space-between;
  font:400 12px "Inter",sans-serif;
  color:var(--on-surface-var);
  padding:4px 0;
}
.session-row .session-value{font-weight:600;color:var(--on-surface)}
.limit-controls{
  margin-top:12px;
  padding-top:12px;
  border-top:1px solid var(--outline-var);
}
.limit-row{display:flex;align-items:center;justify-content:space-between;gap:8px}
.limit-label{font:500 11px "Inter",sans-serif;letter-spacing:.04em;text-transform:uppercase;color:var(--on-surface-var)}
.limit-value{font:600 12px "Inter",sans-serif;color:var(--on-surface)}
.limit-slider{
  -webkit-appearance:none;appearance:none;
  width:100%;height:4px;
  border-radius:2px;
  background:var(--outline-var);
  outline:none;margin:8px 0;
  cursor:pointer;
}
.limit-slider::-webkit-slider-thumb{
  -webkit-appearance:none;appearance:none;
  width:20px;height:20px;
  border-radius:50%;
  background:var(--primary);
  border:2px solid var(--surface);
  box-shadow:var(--elevation-1);
  cursor:pointer;
  transition:transform .15s ease;
}
.limit-slider::-webkit-slider-thumb:hover{transform:scale(1.2)}
.torrent-list{
  flex:1 1 0;
  display:flex;
  flex-direction:column;
  gap:12px;
  min-width:0;
  align-self:start;
}
.torrent-card{
  position:relative;
  padding:20px;
  overflow:hidden;
  transition:box-shadow .2s ease;
}
.torrent-card:hover{box-shadow:var(--elevation-2)}
.torrent-card::before{
  content:"";position:absolute;left:0;top:0;bottom:0;width:4px;
  background:var(--card-accent);border-radius:0 4px 4px 0;
}
.torrent-card[data-status="downloading"]{--card-accent:var(--primary)}
.torrent-card[data-status="complete"]{--card-accent:var(--success)}
.torrent-card[data-status="seeding"]{--card-accent:var(--success)}
.torrent-card[data-status="paused"]{--card-accent:var(--warning)}
.torrent-card[data-status="queued"]{--card-accent:var(--outline)}
.torrent-card[data-status="error"]{--card-accent:var(--error)}
.torrent-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap}
.torrent-title{
  font:600 18px/1.3 "Inter",sans-serif;
  letter-spacing:-.01em;
  word-break:break-word;
}
.torrent-sub{
  margin-top:6px;
  font-size:12px;
  color:var(--on-surface-var);
  display:flex;align-items:center;gap:8px;flex-wrap:wrap;
}
.status-pill{
  display:inline-flex;align-items:center;gap:5px;
  height:24px;padding:0 10px;
  border-radius:100px;
  font:600 11px "Inter",sans-serif;
  letter-spacing:.04em;
  text-transform:uppercase;
}
.status-pill .material-symbols-rounded{font-size:14px}
.status-pill.status-downloading{background:rgba(168,199,250,.16);color:var(--primary)}
.status-pill.status-complete,.status-pill.status-seeding{background:var(--success-cont);color:var(--success)}
.status-pill.status-paused{background:var(--warning-cont);color:var(--warning)}
.status-pill.status-queued{background:var(--surface-cont-high);color:var(--on-surface-var)}
.status-pill.status-error{background:var(--danger-cont);color:var(--error)}
:root[data-theme="light"] .status-pill.status-downloading{color:var(--primary)}
:root[data-theme="light"] .status-pill.status-complete,:root[data-theme="light"] .status-pill.status-seeding{color:var(--success)}
:root[data-theme="light"] .status-pill.status-paused{color:var(--warning)}
:root[data-theme="light"] .status-pill.status-error{color:var(--error)}
.torrent-size{font:500 13px "Inter",sans-serif;color:var(--on-surface-var)}
.torrent-actions{display:flex;gap:4px;flex-wrap:wrap}
.torrent-progress{margin-top:14px}
.meta{font:400 12px "Inter",sans-serif;color:var(--on-surface-var)}
.meta.error{color:var(--error)}
.progress{
  margin-top:8px;
  height:8px;
  background:var(--surface-cont-high);
  border-radius:4px;
  overflow:hidden;
}
.progress .fill{
  height:100%;
  background:var(--primary);
  border-radius:4px;
  position:relative;
  overflow:hidden;
  transition:width .4s cubic-bezier(.2,0,0,1);
}
.progress .fill::after{
  content:"";position:absolute;inset:0;
  background:linear-gradient(90deg,transparent,rgba(255,255,255,.2),transparent);
  animation:progressSheen 2s ease-in-out infinite;
}
.progress.good .fill{background:var(--success)}
.torrent-quick{display:none;margin-top:10px;gap:16px;flex-wrap:wrap;font:500 12px "Inter",sans-serif;color:var(--on-surface-var)}
.torrent-quick .material-symbols-rounded{font-size:16px;vertical-align:-3px;margin-right:2px;opacity:.7}
.torrent-stats{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
  gap:8px;
  margin-top:14px;
}
.stat{
  border-radius:12px;
  padding:10px 14px;
  background:var(--surface-cont);
  border:1px solid var(--outline-var);
}
.stat .k{
  display:flex;align-items:center;gap:4px;
  color:var(--on-surface-var);
  text-transform:uppercase;
  letter-spacing:.06em;
  font:600 10px "Inter",sans-serif;
  margin-bottom:4px;
}
.stat .k .material-symbols-rounded{font-size:14px}
.stat .v{font:600 14px "Inter",sans-serif;color:var(--on-surface)}
.torrent-grid{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:12px;
  margin-top:14px;
}
.subpanel{
  background:var(--surface-cont);
  border:1px solid var(--outline-var);
  border-radius:12px;
  padding:14px 16px;
}
.kv{
  display:grid;
  grid-template-columns:120px 1fr;
  gap:6px 12px;
  font:400 13px "Inter",sans-serif;
  margin-top:10px;
}
.k{
  color:var(--on-surface-var);
  text-transform:uppercase;
  letter-spacing:.06em;
  font:600 10px "Inter",sans-serif;
  padding-top:2px;
}
.table{width:100%;border-collapse:collapse;font:400 13px "Inter",sans-serif}
.table th,.table td{padding:10px 8px;border-bottom:1px solid var(--outline-var);text-align:left;vertical-align:middle}
.table th{
  font:600 10px "Inter",sans-serif;
  text-transform:uppercase;letter-spacing:.06em;
  color:var(--on-surface-var);
}
.file-bar{height:4px;background:var(--surface-cont-high);border-radius:2px;overflow:hidden}
.file-bar .fill{height:100%;background:var(--success);border-radius:2px}
.input{
  width:100%;
  height:40px;
  padding:0 14px;
  border:1px solid var(--outline-var);
  border-radius:12px;
  background:var(--surface-cont);
  color:var(--on-surface);
  font:400 14px "Inter",sans-serif;
  transition:border-color .2s ease,box-shadow .2s ease;
}
.input:hover{border-color:var(--outline)}
.input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 2px rgba(168,199,250,.24)}
:root[data-theme="light"] .input:focus{box-shadow:0 0 0 2px rgba(11,87,208,.16)}
.input:disabled{opacity:.38;cursor:not-allowed}
.modal{
  position:fixed;inset:0;z-index:100;
  display:none;align-items:center;justify-content:center;
  background:rgba(0,0,0,.6);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);
  padding:24px;
}
.modal.open{display:flex;animation:modalFade .2s cubic-bezier(.2,0,0,1)}
.modal-card{
  width:min(560px,100%);
  max-height:85vh;
  overflow-y:auto;
  background:var(--surface-cont);
  border:1px solid var(--outline-var);
  border-radius:24px;
  box-shadow:var(--elevation-3);
  padding:28px 28px 20px;
}
.modal-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.modal-title{font:700 20px/1.2 "Inter",sans-serif;letter-spacing:-.02em}
.modal-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:20px;padding-top:16px;border-top:1px solid var(--outline-var)}
.add-grid{display:flex;flex-direction:column;gap:16px}
.drop-zone{
  position:relative;
  border:2px dashed var(--outline-var);border-radius:16px;
  padding:32px 24px;
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;
  text-align:center;cursor:pointer;
  transition:border-color .2s,background .2s;
}
.drop-zone:hover{border-color:var(--primary);background:rgba(168,199,250,.06)}
.drop-zone.drag-over{border-color:var(--primary);border-style:solid;background:rgba(168,199,250,.1)}
.drop-zone.has-file{border-style:solid;border-color:var(--primary);padding:16px 20px}
.drop-zone .dz-icon{font-size:36px;color:var(--on-surface-var);opacity:.5}
.drop-zone.has-file .dz-icon{font-size:22px;opacity:.7}
.drop-zone .dz-text{font:500 14px "Inter",sans-serif;color:var(--on-surface-var)}
.drop-zone .dz-hint{font:400 12px "Inter",sans-serif;color:var(--on-surface-var);opacity:.6}
.drop-zone.has-file .dz-hint{display:none}
.drop-zone .dz-file-info{display:none;align-items:center;gap:10px;width:100%}
.drop-zone.has-file .dz-file-info{display:flex}
.drop-zone.has-file .dz-text{display:none}
.dz-file-name{flex:1;font:500 13px "Inter",sans-serif;color:var(--on-surface);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;text-align:left}
.dz-file-remove{
  background:none;border:none;cursor:pointer;padding:4px;border-radius:50%;
  color:var(--on-surface-var);display:flex;align-items:center;
  transition:background .15s;
}
.dz-file-remove:hover{background:var(--surface-cont-high)}
.drop-zone input[type="file"]{position:absolute;inset:0;opacity:0;cursor:pointer}
.add-divider{display:flex;align-items:center;gap:12px;color:var(--on-surface-var);font:500 11px "Inter",sans-serif;letter-spacing:.08em;text-transform:uppercase}
.add-divider::before,.add-divider::after{content:'';flex:1;height:1px;background:var(--outline-var)}
.add-summary{padding:10px 14px;border-radius:10px;background:var(--surface-cont-high);font:400 13px "Inter",sans-serif;color:var(--on-surface-var)}
.add-review{border:1px solid var(--outline-var);border-radius:14px;padding:14px;background:var(--surface)}
.add-review-title{font:600 14px "Inter",sans-serif;color:var(--on-surface)}
.add-review-meta{display:flex;gap:12px;flex-wrap:wrap;color:var(--on-surface-var);font-size:12px;margin-top:4px}
.add-file-list{
  margin-top:10px;max-height:220px;overflow:auto;
  border:1px solid var(--outline-var);border-radius:10px;background:var(--surface-cont);
}
.add-file-head,.add-file-row{display:grid;grid-template-columns:32px 1fr 80px;gap:6px;align-items:center;padding:6px 12px}
.add-file-head{
  position:sticky;top:0;
  background:var(--surface-cont-high);
  border-bottom:1px solid var(--outline-var);
  font:600 10px "Inter",sans-serif;
  letter-spacing:.06em;text-transform:uppercase;color:var(--on-surface-var);
}
.add-file-row{border-bottom:1px solid var(--outline-var)}
.add-file-row:last-child{border-bottom:none}
.add-file-name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12px}
.add-file-size{text-align:right;color:var(--on-surface-var);font-size:11px}
.add-file-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:8px}
.add-opts{display:flex;flex-direction:column;gap:12px}
.add-field-label{font:500 12px "Inter",sans-serif;color:var(--on-surface-var);margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}
.add-download-row{display:flex;gap:8px;align-items:center}
.add-download-row .input{flex:1;min-width:0}
.add-prefs{display:flex;gap:16px;flex-wrap:wrap}
.add-check{
  display:flex;align-items:center;gap:6px;
  font:400 13px "Inter",sans-serif;color:var(--on-surface-var);
  cursor:pointer;
}
.add-check input[type="checkbox"]{
  width:16px;height:16px;
  accent-color:var(--primary);
  cursor:pointer;
}
.page-drop-overlay{
  position:fixed;inset:0;z-index:200;
  display:none;align-items:center;justify-content:center;
  background:rgba(0,0,0,.7);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);
  pointer-events:none;
}
.page-drop-overlay.active{display:flex}
.page-drop-overlay-inner{
  display:flex;flex-direction:column;align-items:center;gap:12px;
  padding:48px 64px;border:3px dashed var(--primary);border-radius:28px;
  background:var(--surface-cont);
}
.page-drop-overlay-inner .material-symbols-rounded{font-size:56px;color:var(--primary)}
.page-drop-overlay-inner p{font:600 18px "Inter",sans-serif;color:var(--on-surface)}
.torrent-card[data-collapsed="true"] .torrent-grid,
.torrent-card[data-collapsed="true"] .torrent-stats{display:none}
.torrent-card[data-collapsed="true"] .torrent-quick{display:flex}
.empty-state{
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  padding:64px 24px;text-align:center;
}
.empty-state .material-symbols-rounded{font-size:48px;color:var(--on-surface-var);opacity:.5;margin-bottom:12px}
.empty-state p{font:400 14px "Inter",sans-serif;color:var(--on-surface-var);max-width:320px}
.rss-form{display:flex;gap:6px;margin-top:10px}
.rss-form .input{height:32px;padding:0 10px;font-size:12px;flex:1;min-width:0}
.rss-form .btn{height:32px;padding:0 12px;font-size:12px;flex-shrink:0}
.rss-list{margin-top:10px;display:flex;flex-direction:column;gap:2px}
.rss-item{
  display:flex;align-items:center;justify-content:space-between;
  padding:6px 10px;border-radius:8px;font-size:12px;
  background:var(--surface-cont);transition:background .15s;
}
.rss-item:hover{background:var(--surface-cont-high)}
.rss-item-info{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rss-item-meta{color:var(--on-surface-var);font-size:11px;margin-left:8px;flex-shrink:0}
.rss-item .remove-btn{
  background:none;border:none;color:var(--on-surface-var);cursor:pointer;
  padding:2px 6px;border-radius:4px;font-size:14px;line-height:1;margin-left:4px;
  transition:color .15s,background .15s;
}
.rss-item .remove-btn:hover{color:var(--error);background:var(--danger-cont)}
.rss-section-label{
  font:600 10px "Inter",sans-serif;text-transform:uppercase;
  letter-spacing:.06em;color:var(--on-surface-var);margin-top:12px;margin-bottom:4px;
}
.country-tags{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.country-tag{
  display:inline-flex;align-items:center;gap:4px;padding:4px 10px;
  background:var(--surface-cont-high);border:1px solid var(--outline-var);
  border-radius:8px;font-size:12px;
}
.country-tag b{font-weight:700;color:var(--on-surface)}
.inline-form{display:flex;gap:6px;align-items:center;margin-top:8px}
.inline-form .input{
  flex:1;min-width:0;height:30px;padding:0 8px;font-size:12px;border-radius:8px;
}
.inline-form .btn{
  height:30px;padding:0 10px;font-size:12px;border-radius:8px;flex-shrink:0;
}
.tracker-item{
  display:flex;align-items:center;justify-content:space-between;
  padding:4px 0;font-size:12px;word-break:break-all;
}
.tracker-item .remove-btn{
  background:none;border:none;color:var(--on-surface-var);cursor:pointer;
  padding:2px 6px;border-radius:4px;font-size:14px;line-height:1;
  flex-shrink:0;margin-left:8px;transition:color .15s,background .15s;
}
.tracker-item .remove-btn:hover{color:var(--error);background:var(--danger-cont)}
@keyframes progressSheen{0%{transform:translateX(-100%)}100%{transform:translateX(200%)}}
@keyframes modalFade{from{opacity:0;transform:scale(.96)}to{opacity:1;transform:scale(1)}}
@media(max-width:900px){
  .layout{gap:16px}
  .sidebar{flex-basis:240px;width:240px}
}
@media(max-width:520px){
  .layout{flex-direction:column}
  .sidebar{position:static;flex-basis:auto;width:100%}
  .torrent-grid{grid-template-columns:1fr}
  .appbar{flex-direction:column;align-items:flex-start;gap:12px}
}
@media(max-width:700px){
  .app{padding:0 16px 32px}
  .appbar{margin:0 -16px;padding:12px 16px;border-radius:0}
  .torrent-title{font-size:16px}
  .add-prefs{flex-direction:column}
  .add-download-row{flex-direction:column}
  .torrent-stats{grid-template-columns:repeat(2,1fr)}
}
</style></head><body>"#);
    out.push_str("<div class=\"app\" id=\"appRoot\">");
    out.push_str(&app_body_html(state));
    out.push_str("</div>");
    out.push_str("<script>");
    out.push_str(r#"const themeKey='rustorrent-theme';
const filterKey='rustorrent-library-filter';
const searchKey='rustorrent-library-search';
const collapsePrefix='rustorrent-collapse:';
let pendingHtml=null;
let activeTheme=null;
let queuedLiveHtml=null;
let liveRenderTimer=null;
const liveRenderIntervalMs=450;
const MAX_RATE_LIMIT_KBPS=102400;
const apiTokenMeta=document.querySelector('meta[name="rustorrent-api-token"]');
let apiToken=apiTokenMeta?String(apiTokenMeta.getAttribute('content')||'').trim():'';
function syncApiTokenMeta(){
  if(!apiTokenMeta){return;}
  const value=String(apiTokenMeta.getAttribute('content')||'').trim();
  if(value){apiToken=value;}
}
async function refreshApiToken(){
  try{
    const res=await fetch('/api-token',{cache:'no-store',headers:{'Accept':'application/json'}});
    if(!res.ok){return false;}
    const data=await res.json();
    const token=data&&typeof data.token==='string'?data.token.trim():'';
    if(!token){return false;}
    apiToken=token;
    if(apiTokenMeta){apiTokenMeta.setAttribute('content',token);}
    return true;
  }catch(e){
    return false;
  }
}
syncApiTokenMeta();
function resolveTheme(){
  let theme='light';
  try{
    const stored=localStorage.getItem(themeKey);
    if(stored==='light'||stored==='dark'){theme=stored;}
  }catch(e){}
  return theme;
}
function applyTheme(theme){
  const root=document.documentElement;
  if(activeTheme!==theme){
    root.classList.add('theme-switching');
    root.setAttribute('data-theme',theme);
    activeTheme=theme;
    requestAnimationFrame(()=>requestAnimationFrame(()=>root.classList.remove('theme-switching')));
  }
  const themeBtn=document.getElementById('themeToggle');
  if(themeBtn){themeBtn.innerHTML='<span class="material-symbols-rounded">'+(theme==='light'?'light_mode':'dark_mode')+'</span>';}
}
function resolveFilter(){
  let filter='all';
  try{const stored=localStorage.getItem(filterKey);if(stored){filter=stored;}}catch(e){}
  return filter;
}
function resolveSearch(){
  try{return localStorage.getItem(searchKey)||'';}catch(e){}
  return '';
}
function applyFilter(filter){
  const searchRaw=resolveSearch();
  const search=searchRaw.trim().toLowerCase();
  const searchInput=document.getElementById('librarySearch');
  if(searchInput&&searchInput.value!==searchRaw){searchInput.value=searchRaw;}
  const buttons=Array.from(document.querySelectorAll('.nav-item[data-filter]'));
  buttons.forEach(btn=>{const active=btn.dataset.filter===filter;btn.classList.toggle('active',active);});
  const cards=Array.from(document.querySelectorAll('.torrent-card'));
  cards.forEach(card=>{
    const status=card.dataset.status||'downloading';
    const name=(card.dataset.name||'').toLowerCase();
    const cardLabel=card.dataset.label||'';
    let matchesFilter;
    if(filter==='all'){matchesFilter=true;}
    else if(filter.startsWith('label:')){matchesFilter=cardLabel===filter.slice(6);}
    else{matchesFilter=status===filter;}
    const matchesSearch=!search||name.includes(search);
    if(matchesFilter&&matchesSearch){card.style.display='';}else{card.style.display='none';}
  });
}
function collapseKey(hash){return collapsePrefix+hash;}
function applyCollapseState(){
  const cards=Array.from(document.querySelectorAll('.torrent-card'));
  cards.forEach(card=>{
    const hash=card.dataset.infoHash||'';
    let collapsed=true;
    try{
      const stored=localStorage.getItem(collapseKey(hash));
      if(stored==='0'){collapsed=false;}
      if(stored==='1'){collapsed=true;}
    }catch(e){}
    card.dataset.collapsed=collapsed?'true':'false';
    const toggle=card.querySelector("[data-action='toggle-expand']");
    if(toggle){toggle.innerHTML=collapsed?'<span class="material-symbols-rounded">unfold_more</span>Expand':'<span class="material-symbols-rounded">unfold_less</span>Collapse';toggle.setAttribute('aria-expanded',collapsed?'false':'true');}
  });
}
function syncAttributes(current,next){
  const isModal=current.id==='addModal';
  const hadOpen=isModal&&current.classList.contains('open');
  const isDz=current.id==='dropZone';
  const dzHasFile=isDz&&current.classList.contains('has-file');
  const toRemove=[];
  for(const attr of Array.from(current.attributes||[])){
    if(!next.hasAttribute(attr.name)){toRemove.push(attr.name);}
  }
  toRemove.forEach(name=>current.removeAttribute(name));
  for(const attr of Array.from(next.attributes||[])){
    if(current.getAttribute(attr.name)!==attr.value){current.setAttribute(attr.name,attr.value);}
  }
  if(hadOpen){current.classList.add('open');}
  if(dzHasFile){current.classList.add('has-file');}
}
function syncElementValue(current,next){
  if(current===document.activeElement){return;}
  const tag=current.tagName;
  if(tag==='INPUT'){
    const type=String(current.type||'').toLowerCase();
    if(type==='checkbox'||type==='radio'){
      if(current.checked!==next.checked){current.checked=next.checked;}
    }else if(current.value!==next.value){
      current.value=next.value;
    }
    return;
  }
  if(tag==='TEXTAREA'){
    if(current.value!==next.value){current.value=next.value;}
    return;
  }
  if(tag==='SELECT'){
    if(current.value!==next.value){current.value=next.value;}
  }
}
function morphNode(current,next){
  if(!current||!next){return;}
  if(current.nodeType!==next.nodeType||current.nodeName!==next.nodeName){
    current.replaceWith(next.cloneNode(true));
    return;
  }
  if(current.nodeType===Node.TEXT_NODE||current.nodeType===Node.COMMENT_NODE){
    if(current.nodeValue!==next.nodeValue){current.nodeValue=next.nodeValue;}
    return;
  }
  syncAttributes(current,next);
  syncElementValue(current,next);
  morphChildren(current,next);
}
function morphChildren(current,next){
  const currentChildren=Array.from(current.childNodes);
  const nextChildren=Array.from(next.childNodes);
  const max=Math.max(currentChildren.length,nextChildren.length);
  for(let i=0;i<max;i+=1){
    const curr=current.childNodes[i];
    const nxt=nextChildren[i];
    if(!curr&&nxt){
      current.appendChild(nxt.cloneNode(true));
      continue;
    }
    if(curr&&!nxt){
      curr.remove();
      continue;
    }
    morphNode(curr,nxt);
  }
}
function renderApp(html){
  const root=document.getElementById('appRoot');
  if(!root){return;}
  if(!root.firstChild){
    root.innerHTML=html;
  }else{
    const tpl=document.createElement('template');
    tpl.innerHTML=html;
    morphChildren(root,tpl.content);
  }
  applyTheme(activeTheme||resolveTheme());
  applyFilter(resolveFilter());
  applyCollapseState();
  updateRateLimitLabels();
}
function scheduleLiveRender(html){
  queuedLiveHtml=html;
  if(liveRenderTimer!==null){return;}
  liveRenderTimer=setTimeout(()=>{
    liveRenderTimer=null;
    const nextHtml=queuedLiveHtml;
    queuedLiveHtml=null;
    if(nextHtml){renderApp(nextHtml);}
  },liveRenderIntervalMs);
}
function applyUpdate(html){
  const modal=document.getElementById('addModal');
  if(modal&&modal.classList.contains('open')){pendingHtml=html;return;}
  scheduleLiveRender(html);
  pendingHtml=null;
}
let addParseToken=0;
let addDraft={kind:'none',name:'',fileName:'',files:[],totalBytes:0,infoHash:'',bytes:null,parseError:'',parsing:false};
const textDecoder=new TextDecoder();
function resetAddDraft(){
  addParseToken+=1;
  addDraft={kind:'none',name:'',fileName:'',files:[],totalBytes:0,infoHash:'',bytes:null,parseError:'',parsing:false};
}
function openAdd(){
  const modal=document.getElementById('addModal');
  if(!modal){return;}
  modal.classList.add('open');
  resetAddDraft();
  const fileInput=document.getElementById('torrentFile');
  const magnetInput=document.getElementById('magnet');
  const startWhenAdded=document.getElementById('startWhenAdded');
  if(fileInput){fileInput.value='';}
  if(magnetInput){magnetInput.value='';}
  if(startWhenAdded){startWhenAdded.checked=true;}
  updateDropZoneState();
  renderAddReview();
}
function closeAdd(){
  const modal=document.getElementById('addModal');
  if(modal){modal.classList.remove('open')}
  resetAddDraft();
  if(pendingHtml){
    const html=pendingHtml;
    pendingHtml=null;
    queuedLiveHtml=null;
    if(liveRenderTimer!==null){
      clearTimeout(liveRenderTimer);
      liveRenderTimer=null;
    }
    renderApp(html);
  }
}
function maybeClose(e){if(e.target&&e.target.id==='addModal'){closeAdd()}}
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeAdd()}});
async function chooseDownloadDir(){
  const input=document.getElementById('downloadDir');
  if(!input){return;}
  const current=(input.value||'').trim();
  try{
    const data=await apiPostJson('/select-download-dir');
    const path=data&&typeof data.path==='string'?data.path.trim():'';
    if(path){input.value=path;}
    return;
  }catch(err){
    const message=actionErrorMessage(err);
    const unsupported=message.toLowerCase().includes('not available on this platform');
    if(!unsupported){
      alert('Folder picker failed: '+message);
      return;
    }
  }
  const next=prompt('Download directory path:',current||'');
  if(next===null){return;}
  const value=next.trim();
  if(value){input.value=value;}
}
function actionErrorMessage(err){
  if(err&&err.message){return err.message;}
  return String(err||'unknown error');
}
function showActionError(err){
  alert('Action failed: '+actionErrorMessage(err));
}
async function apiPost(url,options){
  if(!apiToken){await refreshApiToken();}
  let attemptedRefresh=false;
  while(true){
    const req=Object.assign({method:'POST',cache:'no-store'},options||{});
    const headers=new Headers(req.headers||{});
    if(apiToken){headers.set('X-Rustorrent-Token',apiToken);}
    req.headers=headers;

    const res=await fetch(url,req);
    if(res.ok){return res;}

    let message='HTTP '+res.status;
    try{
      const type=(res.headers.get('content-type')||'').toLowerCase();
      if(type.includes('application/json')){
        const data=await res.json();
        if(data&&typeof data.error==='string'&&data.error.trim()){message=data.error.trim();}
      }else{
        const text=(await res.text()).trim();
        if(text){message=text;}
      }
    }catch(e){}

    const lower=String(message||'').toLowerCase();
    const tokenError=lower.includes('invalid api token')||(lower.includes('missing')&&lower.includes('api token'));
    if(!attemptedRefresh&&res.status===403&&tokenError){
      attemptedRefresh=true;
      if(await refreshApiToken()){continue;}
    }
    throw new Error(message);
  }
}
async function apiPostJson(url,options){
  const res=await apiPost(url,options);
  const type=(res.headers.get('content-type')||'').toLowerCase();
  if(type.includes('application/json')){
    try{
      const data=await res.json();
      if(data&&typeof data==='object'){return data;}
    }catch(e){}
  }
  return {ok:true};
}
function escapeHtml(value){
  return String(value||'')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}
function formatBytes(value){
  const units=['B','KB','MB','GB','TB'];
  let size=Math.max(0,Number(value)||0);
  let unit=0;
  while(size>=1024&&unit+1<units.length){size/=1024;unit+=1;}
  if(unit===0){return Math.round(size)+' '+units[unit];}
  return size.toFixed(2)+' '+units[unit];
}
function formatRateLimitKbps(kbps){
  const value=Math.max(0,Number(kbps)||0);
  if(value===0){return 'Unlimited';}
  return formatBytes(value*1024)+'/s';
}
function updateRateLimitLabels(){
  const down=document.getElementById('downloadLimit');
  const up=document.getElementById('uploadLimit');
  const downLabel=document.getElementById('downloadLimitValue');
  const upLabel=document.getElementById('uploadLimitValue');
  if(down&&downLabel){
    const next=Math.max(0,Math.min(MAX_RATE_LIMIT_KBPS,Number(down.value)||0));
    down.value=String(next);
    downLabel.textContent=formatRateLimitKbps(next);
  }
  if(up&&upLabel){
    const next=Math.max(0,Math.min(MAX_RATE_LIMIT_KBPS,Number(up.value)||0));
    up.value=String(next);
    upLabel.textContent=formatRateLimitKbps(next);
  }
}
function sleep(ms){return new Promise(resolve=>setTimeout(resolve,ms));}
function decodeUtf8(bytes){
  try{return textDecoder.decode(bytes);}catch(e){return '';}
}
function parseBencode(bytes){
  function parseAt(offset){
    if(offset>=bytes.length){throw new Error('unexpected end of file');}
    const marker=bytes[offset];
    if(marker===100){
      let idx=offset+1;
      const dict={};
      while(idx<bytes.length&&bytes[idx]!==101){
        const keyNode=parseAt(idx);
        if(keyNode.t!=='bytes'){throw new Error('invalid dictionary key');}
        const key=decodeUtf8(keyNode.v);
        const valueNode=parseAt(keyNode.end);
        dict[key]=valueNode;
        idx=valueNode.end;
      }
      if(bytes[idx]!==101){throw new Error('unterminated dictionary');}
      return {t:'dict',v:dict,start:offset,end:idx+1};
    }
    if(marker===108){
      let idx=offset+1;
      const list=[];
      while(idx<bytes.length&&bytes[idx]!==101){
        const valueNode=parseAt(idx);
        list.push(valueNode);
        idx=valueNode.end;
      }
      if(bytes[idx]!==101){throw new Error('unterminated list');}
      return {t:'list',v:list,start:offset,end:idx+1};
    }
    if(marker===105){
      let idx=offset+1;
      while(idx<bytes.length&&bytes[idx]!==101){idx+=1;}
      if(bytes[idx]!==101){throw new Error('unterminated integer');}
      const raw=String.fromCharCode.apply(null,Array.from(bytes.slice(offset+1,idx)));
      const value=Number(raw);
      if(!Number.isFinite(value)){throw new Error('invalid integer');}
      return {t:'int',v:value,start:offset,end:idx+1};
    }
    if(marker>=48&&marker<=57){
      let colon=offset;
      while(colon<bytes.length&&bytes[colon]!==58){
        if(bytes[colon]<48||bytes[colon]>57){throw new Error('invalid byte string length');}
        colon+=1;
      }
      if(bytes[colon]!==58){throw new Error('invalid byte string');}
      const lenRaw=String.fromCharCode.apply(null,Array.from(bytes.slice(offset,colon)));
      const len=Number(lenRaw);
      if(!Number.isInteger(len)||len<0){throw new Error('invalid byte string length');}
      const start=colon+1;
      const end=start+len;
      if(end>bytes.length){throw new Error('byte string exceeds buffer');}
      return {t:'bytes',v:bytes.slice(start,end),start:offset,end:end};
    }
    throw new Error('invalid bencode token');
  }
  const root=parseAt(0);
  if(root.end!==bytes.length){throw new Error('trailing data');}
  return root;
}
function nodeString(node){
  if(!node||node.t!=='bytes'){return '';}
  return decodeUtf8(node.v);
}
function nodeInt(node){
  if(!node||node.t!=='int'){return 0;}
  return Math.max(0,Math.floor(node.v));
}
function extractInfoHashFromMagnet(magnet){
  const match=/[?&]xt=urn:btih:([^&]+)/i.exec(String(magnet||''));
  if(!match){return '';}
  let value='';
  try{value=decodeURIComponent(match[1]);}catch(e){value=match[1];}
  if(/^[a-f0-9]{40}$/i.test(value)){return value.toLowerCase();}
  return '';
}
async function sha1Hex(bytes){
  const digest=await crypto.subtle.digest('SHA-1',bytes);
  return Array.from(new Uint8Array(digest)).map(v=>v.toString(16).padStart(2,'0')).join('');
}
async function parseTorrentPreview(bytes,fallbackName){
  const root=parseBencode(bytes);
  if(!root||root.t!=='dict'){throw new Error('invalid torrent file');}
  const info=root.v.info;
  if(!info||info.t!=='dict'){throw new Error('missing info dictionary');}
  const name=nodeString(info.v['name.utf-8']||info.v.name)||fallbackName||'torrent';
  const files=[];
  const fileList=info.v.files;
  if(fileList&&fileList.t==='list'&&fileList.v.length>0){
    fileList.v.forEach((entry,idx)=>{
      if(!entry||entry.t!=='dict'){return;}
      const length=nodeInt(entry.v.length);
      const pathNode=entry.v['path.utf-8']||entry.v.path;
      const segments=(pathNode&&pathNode.t==='list')?pathNode.v.map(nodeString).filter(Boolean):[];
      const relPath=segments.join('/');
      files.push({index:idx,path:relPath?name+'/'+relPath:name,length:length,selected:true});
    });
  }else{
    files.push({index:0,path:name,length:nodeInt(info.v.length),selected:true});
  }
  const totalBytes=files.reduce((acc,file)=>acc+file.length,0);
  const infoHash=await sha1Hex(bytes.slice(info.start,info.end));
  return {name:name,files:files,totalBytes:totalBytes,infoHash:infoHash};
}
function renderAddReview(){
  const summary=document.getElementById('addSummary');
  const review=document.getElementById('addReview');
  const fileInput=document.getElementById('torrentFile');
  const magnetInput=document.getElementById('magnet');
  const addBtn=document.querySelector('#addModal .btn.primary');
  if(!summary||!review||!addBtn){return;}
  const hasFile=!!(fileInput&&fileInput.files&&fileInput.files[0]);
  const magnet=magnetInput?magnetInput.value.trim():'';
  if(addDraft.parsing){
    summary.textContent='Reading torrent metadata...';
    review.style.display='none';
    addBtn.disabled=true;
    return;
  }
  if(hasFile){
    if(addDraft.parseError){
      summary.textContent='Could not read this .torrent file. '+addDraft.parseError;
      review.style.display='none';
      addBtn.disabled=true;
      return;
    }
    if(addDraft.kind==='file'&&addDraft.bytes&&addDraft.files.length>0){
      const selected=addDraft.files.filter(file=>file.selected).length;
      summary.textContent='Adding 1 torrent';
      const rows=addDraft.files.map((file,idx)=>(
        '<div class=\"add-file-row\">'
        +'<div><input type=\"checkbox\" '+(file.selected?'checked ':'')+'onchange=\"toggleReviewFile('+idx+',this.checked)\"></div>'
        +'<div class=\"add-file-name\" title=\"'+escapeHtml(file.path)+'\">'+escapeHtml(file.path)+'</div>'
        +'<div class=\"add-file-size\">'+formatBytes(file.length)+'</div>'
        +'</div>'
      )).join('');
      review.innerHTML=''
        +'<div class=\"add-review-title\">'+escapeHtml(addDraft.name||addDraft.fileName||'torrent')+'</div>'
        +'<div class=\"add-review-meta\"><span>'+addDraft.files.length+' files</span><span>'+formatBytes(addDraft.totalBytes)+'</span><span>'+selected+' selected</span></div>'
        +'<div class=\"add-file-actions\"><button class=\"btn\" type=\"button\" onclick=\"toggleAllReviewFiles(true)\">Select all</button><button class=\"btn\" type=\"button\" onclick=\"toggleAllReviewFiles(false)\">Clear all</button></div>'
        +'<div class=\"add-file-list\"><div class=\"add-file-head\"><div></div><div>Name</div><div class=\"add-file-size\">Size</div></div>'+rows+'</div>';
      review.style.display='block';
      addBtn.disabled=selected===0;
      return;
    }
    summary.textContent='Select a valid .torrent file.';
    review.style.display='none';
    addBtn.disabled=true;
    return;
  }
  if(magnet){
    summary.textContent='Magnet link ready to add.';
    review.style.display='none';
    addBtn.disabled=false;
    return;
  }
  summary.textContent='Select a .torrent file or paste a magnet link.';
  review.style.display='none';
  addBtn.disabled=true;
}
function toggleReviewFile(index,checked){
  if(addDraft.kind!=='file'||!addDraft.files[index]){return;}
  addDraft.files[index].selected=!!checked;
  renderAddReview();
}
function toggleAllReviewFiles(checked){
  if(addDraft.kind!=='file'){return;}
  addDraft.files.forEach(file=>{file.selected=!!checked;});
  renderAddReview();
}
async function handleTorrentInputChange(){
  const fileInput=document.getElementById('torrentFile');
  const magnetInput=document.getElementById('magnet');
  const file=fileInput&&fileInput.files?fileInput.files[0]:null;
  if(file&&magnetInput){magnetInput.value='';}
  const token=addParseToken+1;
  addParseToken=token;
  updateDropZoneState();
  if(!file){
    resetAddDraft();
    renderAddReview();
    return;
  }
  addDraft={kind:'file',name:file.name,fileName:file.name,files:[],totalBytes:file.size||0,infoHash:'',bytes:null,parseError:'',parsing:true};
  renderAddReview();
  try{
    const bytes=new Uint8Array(await file.arrayBuffer());
    if(token!==addParseToken){return;}
    const parsed=await parseTorrentPreview(bytes,file.name);
    if(token!==addParseToken){return;}
    addDraft={kind:'file',name:parsed.name,fileName:file.name,files:parsed.files,totalBytes:parsed.totalBytes,infoHash:parsed.infoHash,bytes:bytes,parseError:'',parsing:false};
  }catch(err){
    if(token!==addParseToken){return;}
    addDraft={kind:'file',name:file.name,fileName:file.name,files:[],totalBytes:file.size||0,infoHash:'',bytes:null,parseError:actionErrorMessage(err),parsing:false};
  }
  renderAddReview();
}
function handleMagnetInput(){
  const magnetInput=document.getElementById('magnet');
  const fileInput=document.getElementById('torrentFile');
  const magnet=magnetInput?magnetInput.value.trim():'';
  addParseToken+=1;
  if(magnet&&fileInput){fileInput.value='';}
  if(magnet){
    addDraft={kind:'magnet',name:'',fileName:'',files:[],totalBytes:0,infoHash:extractInfoHashFromMagnet(magnet),bytes:null,parseError:'',parsing:false};
  }else{
    resetAddDraft();
  }
  updateDropZoneState();
  renderAddReview();
}
function clearTorrentFile(){
  const fileInput=document.getElementById('torrentFile');
  if(fileInput){fileInput.value='';}
  resetAddDraft();
  updateDropZoneState();
  renderAddReview();
}
function updateDropZoneState(){
  const dz=document.getElementById('dropZone');
  const nameEl=document.getElementById('dzFileName');
  if(!dz){return;}
  const fileInput=document.getElementById('torrentFile');
  const hasFile=!!(fileInput&&fileInput.files&&fileInput.files[0]);
  if(hasFile){
    dz.classList.add('has-file');
    if(nameEl){nameEl.textContent=fileInput.files[0].name;}
  }else{
    dz.classList.remove('has-file');
    if(nameEl){nameEl.textContent='';}
  }
}
(function initDragDrop(){
  let dragCount=0;
  const overlay=()=>document.getElementById('pageDropOverlay');
  function isTorrentDrag(e){
    if(!e.dataTransfer||!e.dataTransfer.types){return false;}
    return e.dataTransfer.types.indexOf('Files')!==-1;
  }
  document.addEventListener('dragenter',e=>{
    if(!isTorrentDrag(e)){return;}
    e.preventDefault();
    dragCount+=1;
    const ov=overlay();
    if(ov){ov.classList.add('active');}
  });
  document.addEventListener('dragleave',e=>{
    dragCount-=1;
    if(dragCount<=0){
      dragCount=0;
      const ov=overlay();
      if(ov){ov.classList.remove('active');}
    }
  });
  document.addEventListener('dragover',e=>{
    if(!isTorrentDrag(e)){return;}
    e.preventDefault();
    e.dataTransfer.dropEffect='copy';
  });
  document.addEventListener('drop',e=>{
    e.preventDefault();
    dragCount=0;
    const ov=overlay();
    if(ov){ov.classList.remove('active');}
    const files=e.dataTransfer&&e.dataTransfer.files;
    if(!files||files.length===0){return;}
    let torrentFile=null;
    for(let i=0;i<files.length;i+=1){
      if(files[i].name.endsWith('.torrent')){torrentFile=files[i];break;}
    }
    if(!torrentFile){return;}
    const modal=document.getElementById('addModal');
    if(!modal||!modal.classList.contains('open')){openAdd();}
    const fileInput=document.getElementById('torrentFile');
    if(fileInput){
      const dt=new DataTransfer();
      dt.items.add(torrentFile);
      fileInput.files=dt.files;
      updateDropZoneState();
      handleTorrentInputChange();
    }
  });
  const dzEl=document.getElementById('dropZone');
  if(dzEl){
    dzEl.addEventListener('dragenter',e=>{e.preventDefault();dzEl.classList.add('drag-over');});
    dzEl.addEventListener('dragleave',e=>{dzEl.classList.remove('drag-over');});
    dzEl.addEventListener('dragover',e=>{e.preventDefault();e.dataTransfer.dropEffect='copy';});
    dzEl.addEventListener('drop',e=>{dzEl.classList.remove('drag-over');});
  }
})();
async function fetchStatusJson(){
  const response=await fetch('/status',{cache:'no-store'});
  if(!response.ok){throw new Error('status request failed');}
  return response.json();
}
async function waitForTorrentIdByHash(infoHash,timeoutMs){
  const target=String(infoHash||'').toLowerCase();
  if(!target){return null;}
  const endAt=Date.now()+timeoutMs;
  while(Date.now()<endAt){
    try{
      const status=await fetchStatusJson();
      if(status&&Array.isArray(status.torrents)){
        const match=status.torrents.find(t=>String(t.info_hash||'').toLowerCase()===target);
        if(match&&typeof match.id!=='undefined'){return match.id;}
      }
    }catch(e){}
    await sleep(250);
  }
  return null;
}
document.addEventListener('click',e=>{
  const target=e.target;
  if(target&&target.closest('#themeToggle')){
    let theme=activeTheme||resolveTheme();
    theme=theme==='dark'?'light':'dark';
    try{localStorage.setItem(themeKey,theme);}catch(e){}
    applyTheme(theme);
  }
  const navItem=target.closest('.nav-item[data-filter]');
  if(navItem){
    const filter=navItem.dataset.filter||'all';
    try{localStorage.setItem(filterKey,filter);}catch(e){}
    applyFilter(filter);
  }
  const actionBtn=target.closest('[data-action]');
  if(actionBtn){
    const card=actionBtn.closest('.torrent-card');
    const id=card?card.dataset.id:'';
    if(!id){return;}
    const action=actionBtn.dataset.action;
    const paused=card.dataset.paused==='true';
    if(action==='toggle-pause'){togglePause(id,paused).catch(showActionError);}
    else if(action==='stop'){torrentAction('stop',id).catch(showActionError);}
    else if(action==='delete'){confirmDelete(id,card.dataset.name||'torrent').catch(showActionError);}
    else if(action==='open-folder'){torrentAction('open-folder',id).catch(showActionError);}
    else if(action==='recheck'){torrentAction('recheck',id).catch(showActionError);}
    else if(action==='toggle-expand'){toggleExpand(card);}
    else if(action==='add-tracker'){
      const input=card.querySelector('.tracker-add-input');
      if(input&&input.value.trim()){
        apiPost('/torrent/add-tracker',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+encodeURIComponent(id)+'&url='+encodeURIComponent(input.value.trim())}).then(()=>{input.value='';}).catch(showActionError);
      }
    }
    else if(action==='remove-tracker'){
      const url=actionBtn.dataset.url||'';
      if(url){apiPost('/torrent/remove-tracker',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+encodeURIComponent(id)+'&url='+encodeURIComponent(url)}).catch(showActionError);}
    }
    else if(action==='set-label'){
      const input=card.querySelector('.label-input');
      if(input){apiPost('/torrent/set-label',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'id='+encodeURIComponent(id)+'&label='+encodeURIComponent(input.value.trim())}).catch(showActionError);}
    }
  }
});
document.addEventListener('input',e=>{
  const target=e.target;
  if(target&&target.id==='librarySearch'){
    const search=String(target.value||'');
    try{localStorage.setItem(searchKey,search);}catch(e){}
    applyFilter(resolveFilter());
    return;
  }
  if(target&&(target.id==='downloadLimit'||target.id==='uploadLimit')){
    updateRateLimitLabels();
  }
  if(target&&target.id==='seedRatio'){
    const v=Number(target.value)/10;
    const label=document.getElementById('seedRatioValue');
    if(label){label.textContent=v>0?v.toFixed(2):'unlimited';}
  }
});
document.addEventListener('change',e=>{
  const target=e.target;
  if(target&&(target.id==='downloadLimit'||target.id==='uploadLimit')){
    setGlobalRateLimits().catch(showActionError);
  }
  if(target&&target.id==='seedRatio'){
    const v=Number(target.value)/10;
    const body='ratio='+encodeURIComponent(v);
    apiPost('/settings/seed-ratio',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body}).catch(showActionError);
  }
});
function toggleExpand(card){
  if(!card){return;}
  const collapsed=card.dataset.collapsed==='true';
  const nextCollapsed=!collapsed;
  card.dataset.collapsed=nextCollapsed?'true':'false';
  const toggle=card.querySelector("[data-action='toggle-expand']");
  if(toggle){toggle.innerHTML=nextCollapsed?'<span class="material-symbols-rounded">unfold_more</span>Expand':'<span class="material-symbols-rounded">unfold_less</span>Collapse';toggle.setAttribute('aria-expanded',nextCollapsed?'false':'true');}
  try{localStorage.setItem(collapseKey(card.dataset.infoHash||''),nextCollapsed?'1':'0');}catch(e){}
}
async function setGlobalRateLimits(){
  const down=document.getElementById('downloadLimit');
  const up=document.getElementById('uploadLimit');
  if(!down||!up){return;}
  const downloadKbps=Math.max(0,Math.min(MAX_RATE_LIMIT_KBPS,Math.round(Number(down.value)||0)));
  const uploadKbps=Math.max(0,Math.min(MAX_RATE_LIMIT_KBPS,Math.round(Number(up.value)||0)));
  down.value=String(downloadKbps);
  up.value=String(uploadKbps);
  updateRateLimitLabels();
  const body='download_kbps='+encodeURIComponent(downloadKbps)+'&upload_kbps='+encodeURIComponent(uploadKbps);
  await apiPost('/rate-limits',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body});
}
async function applyPostAddPlan(plan){
  if(!plan){return;}
  let torrentId=Number(plan.torrentId);
  if(!Number.isFinite(torrentId)||torrentId<=0){
    if(plan.infoHash){
      torrentId=await waitForTorrentIdByHash(plan.infoHash,12000);
    }
  }
  if(!Number.isFinite(torrentId)||torrentId<=0){
    throw new Error('torrent appeared too late for follow-up actions');
  }
  for(const fileIndex of (plan.skipFiles||[])){
    await setPriorityRequest(torrentId,fileIndex,0);
  }
  if(plan.startPaused){
    await torrentAction('pause',torrentId);
  }
}
async function submitAdd(){
  const fileInput=document.getElementById('torrentFile');
  const file=fileInput&&fileInput.files?fileInput.files[0]:null;
  const magnet=document.getElementById('magnet').value.trim();
  const dir=document.getElementById('downloadDir').value.trim();
  const prealloc=document.getElementById('preallocate').checked?'1':'0';
  const startWhenAdded=document.getElementById('startWhenAdded').checked;
  const addBtn=document.querySelector('#addModal .btn.primary');
  if(addBtn){addBtn.disabled=true;addBtn.textContent='Adding...';}
  try{
    if(file){
      if(addDraft.parsing){
        alert('Please wait until torrent metadata is loaded.');
        return false;
      }
      if(addDraft.kind==='file'&&addDraft.files.length>0&&addDraft.files.every(file=>!file.selected)){
        alert('Select at least one file to download.');
        return false;
      }
      const bytes=(addDraft.kind==='file'&&addDraft.bytes)?addDraft.bytes:new Uint8Array(await file.arrayBuffer());
      const postPlan={
        torrentId:null,
        infoHash:addDraft.infoHash||'',
        skipFiles:(addDraft.kind==='file'&&addDraft.files.length>0)?addDraft.files.filter(file=>!file.selected).map(file=>file.index):[],
        startPaused:!startWhenAdded,
      };
      const addResponse=await apiPostJson('/add-torrent?dir='+encodeURIComponent(dir)+'&prealloc='+prealloc,{headers:{'Content-Type':'application/x-bittorrent'},body:bytes});
      const torrentId=Number(addResponse&&addResponse.torrent_id);
      postPlan.torrentId=Number.isFinite(torrentId)&&torrentId>0?torrentId:null;
      closeAdd();
      scheduleRefreshFallback();
      if((postPlan.torrentId!==null||postPlan.infoHash)&&(postPlan.skipFiles.length>0||postPlan.startPaused)){
        applyPostAddPlan(postPlan).catch(err=>alert('Torrent added, but follow-up settings failed: '+actionErrorMessage(err)));
      }else if(!startWhenAdded){
        alert('Torrent added. Use Pause once it appears.');
      }
      return false;
    }
    if(magnet){
      const infoHash=extractInfoHashFromMagnet(magnet);
      const body='magnet='+encodeURIComponent(magnet)+'&dir='+encodeURIComponent(dir)+'&prealloc='+prealloc;
      const addResponse=await apiPostJson('/add-magnet',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body});
      const torrentId=Number(addResponse&&addResponse.torrent_id);
      closeAdd();
      scheduleRefreshFallback();
      if(!startWhenAdded){
        const plan={torrentId:Number.isFinite(torrentId)&&torrentId>0?torrentId:null,infoHash:infoHash,skipFiles:[],startPaused:true};
        if(plan.torrentId!==null||plan.infoHash){
          applyPostAddPlan(plan).catch(err=>alert('Magnet added, but auto-pause failed: '+actionErrorMessage(err)));
        }else{
          alert('Magnet added. Pause it after metadata is available.');
        }
      }
      return false;
    }
    alert('Select a .torrent file or paste a magnet link.');
    return false;
  }catch(err){
    alert('Add failed: '+(err&&err.message?err.message:String(err)));
    return false;
  }finally{
    if(addBtn){addBtn.disabled=false;addBtn.textContent='Add';}
  }
}

function scheduleRefreshFallback(){
  setTimeout(()=>{
    const stale=Date.now()-lastUpdateAt>1200;
    if(stale&&(!source||source.readyState!==1)){
      location.reload();
    }
  },1200);
}
async function torrentAction(action,id){
  await apiPost('/torrent/'+action+'?id='+encodeURIComponent(id));
}
async function togglePause(id,paused){
  const action=paused?'resume':'pause';
  await torrentAction(action,id);
}
async function confirmDelete(id,name){
  const safeName=name||'torrent';
  const ok=confirm('Delete '+safeName+'?');
  if(!ok){return;}
  const removeData=confirm('Remove downloaded data for '+safeName+'?');
  await apiPost('/torrent/delete?id='+encodeURIComponent(id)+'&data='+(removeData?'1':'0'));
}
async function setPriorityRequest(torrentId,index,priority){
  const body='id='+encodeURIComponent(torrentId)+'&index='+encodeURIComponent(index)+'&priority='+encodeURIComponent(priority);
  await apiPost('/file-priority',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body});
}
async function setPriority(torrentId,index,priority){
  try{
    await setPriorityRequest(torrentId,index,priority);
  }catch(err){
    alert('Priority update failed: '+actionErrorMessage(err));
  }
}
function startRename(torrentId,index,cell){
  const oldText=cell.textContent;
  const parts=oldText.split('/');
  const basename=parts[parts.length-1];
  const input=document.createElement('input');
  input.type='text';input.className='input';input.value=basename;
  input.style.cssText='width:100%;box-sizing:border-box;font-size:12px';
  cell.textContent='';cell.appendChild(input);input.focus();input.select();
  let done=false;
  function finish(save){
    if(done)return;done=true;
    const val=input.value.trim();
    cell.textContent=oldText;
    if(save&&val&&val!==basename&&!val.includes('/')&&!val.includes('\\\\')&&val!=='.'&&val!=='..'){
      const newPath=parts.length>1?parts.slice(0,-1).join('/')+'/'+val:val;
      cell.textContent=newPath;
      const body='id='+encodeURIComponent(torrentId)+'&index='+encodeURIComponent(index)+'&name='+encodeURIComponent(val);
      apiPost('/rename-file',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body}).catch(function(err){
        cell.textContent=oldText;
        alert('Rename failed: '+actionErrorMessage(err));
      });
    }
  }
  input.addEventListener('keydown',function(e){if(e.key==='Enter'){finish(true)}else if(e.key==='Escape'){finish(false)}});
  input.addEventListener('blur',function(){finish(true)});
}
function addRssFeed(e){
  e.preventDefault();
  const url=document.getElementById('rssUrl').value.trim();
  if(!url)return;
  apiPost('/rss/add-feed',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'url='+encodeURIComponent(url)}).then(()=>location.reload()).catch(err=>alert('Add feed failed: '+actionErrorMessage(err)));
}
function removeRssFeed(url){
  apiPost('/rss/remove-feed',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'url='+encodeURIComponent(url)}).then(()=>location.reload()).catch(err=>alert('Remove feed failed: '+actionErrorMessage(err)));
}
function removeRssRule(name){
  apiPost('/rss/remove-rule',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'name='+encodeURIComponent(name)}).then(()=>location.reload()).catch(err=>alert('Remove rule failed: '+actionErrorMessage(err)));
}
function addRssRule(e){
  e.preventDefault();
  var name=document.getElementById('rssRuleName').value.trim();
  var pattern=document.getElementById('rssRulePattern').value.trim();
  if(!name||!pattern)return;
  var body='name='+encodeURIComponent(name)+'&pattern='+encodeURIComponent(pattern);
  apiPost('/rss/add-rule',{headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body}).then(function(){location.reload()}).catch(function(err){alert('Add rule failed: '+actionErrorMessage(err))});
}
applyTheme(resolveTheme());
applyFilter(resolveFilter());
applyCollapseState();
updateRateLimitLabels();
renderAddReview();
let lastUpdateAt=Date.now();
const source=new EventSource('/events');
source.addEventListener('status',event=>{if(event&&event.data){applyUpdate(event.data);lastUpdateAt=Date.now();}});
source.onerror=()=>{console.warn('event source disconnected');};
"#);
    out.push_str("</script>");
    out.push_str("</body></html>");
    out
}

fn app_body_html(state: &UiState) -> String {
    let mut out = String::with_capacity(4200 + state.torrents.len() * 2000);
    let queue_len = state.queue_len;
    let _last_added = escape_html(&state.last_added);
    let total_torrents = state.torrents.len();
    let download_dir = escape_html(&state.download_dir);
    let total_downloaded_bytes: u64 = state.torrents.iter().map(|t| t.downloaded_bytes).sum();
    let total_uploaded_bytes: u64 = state.torrents.iter().map(|t| t.uploaded_bytes).sum();
    let total_downloaded = human_bytes(total_downloaded_bytes);
    let total_uploaded = human_bytes(total_uploaded_bytes);
    let download_limit_kbps = state.global_download_limit_bps / 1024;
    let upload_limit_kbps = state.global_upload_limit_bps / 1024;
    let total_tracker_peers: usize = state.torrents.iter().map(|t| t.tracker_peers).sum();
    let total_active_peers: usize = state.torrents.iter().map(|t| t.active_peers).sum();

    let mut downloading = 0usize;
    let mut complete = 0usize;
    let mut paused = 0usize;
    let mut errored = 0usize;
    let mut queued = 0usize;
    let bucket_for = |torrent: &UiTorrent| -> &'static str {
        let status = torrent.status.as_str();
        if matches!(status, "paused" | "stopped") {
            return "paused";
        }
        if status == "queued" {
            return "queued";
        }
        if status == "error" {
            return "error";
        }
        if matches!(status, "complete" | "seeding")
            || (torrent.total_bytes > 0 && torrent.completed_bytes >= torrent.total_bytes)
        {
            return "complete";
        }
        "downloading"
    };
    for torrent in &state.torrents {
        match bucket_for(torrent) {
            "downloading" => downloading += 1,
            "complete" => complete += 1,
            "paused" => paused += 1,
            "error" => errored += 1,
            "queued" => queued += 1,
            _ => {}
        }
    }

    out.push_str("<header class=\"appbar\">");
    out.push_str("<div class=\"brand\">");
    out.push_str("<div class=\"brand-icon\"><span class=\"material-symbols-rounded\">downloading</span></div>");
    out.push_str("<div><div class=\"title\">rustorrent</div>");
    out.push_str("<div class=\"sub\">BitTorrent client</div></div>");
    out.push_str("</div>");
    out.push_str("<div class=\"app-actions\">");
    out.push_str(&format!(
        "<span class=\"chip\"><span class=\"material-symbols-rounded\">folder</span>{total_torrents} torrents</span>"
    ));
    out.push_str(&format!("<span class=\"chip\"><span class=\"material-symbols-rounded\">queue</span>{queue_len} queued</span>"));
    out.push_str("<div class=\"toolbar\">");
    out.push_str(
        "<button class=\"btn primary\" type=\"button\" onclick=\"openAdd()\"><span class=\"material-symbols-rounded\">add</span>Add Torrent</button>",
    );
    out.push_str(
        "<button class=\"btn icon-btn ghost\" id=\"themeToggle\" type=\"button\" title=\"Toggle theme\"><span class=\"material-symbols-rounded\">dark_mode</span></button>",
    );
    out.push_str("</div>");
    out.push_str("</div>");
    out.push_str("</header>");

    out.push_str("<div class=\"layout\">");

    out.push_str("<aside class=\"sidebar\">");
    out.push_str("<div class=\"panel\">");
    out.push_str("<div class=\"panel-title\">Library</div>");
    out.push_str(
        "<input id=\"librarySearch\" class=\"input\" type=\"search\" placeholder=\"Search torrents\" autocomplete=\"off\" style=\"margin-top:8px\">",
    );
    out.push_str("<div class=\"nav\">");
    out.push_str(&format!(
        "<button class=\"nav-item active\" type=\"button\" data-filter=\"all\"><span class=\"nav-label\"><span class=\"material-symbols-rounded\">list</span>All</span><span class=\"count\">{}</span></button>",
        state.torrents.len()
    ));
    out.push_str(&format!(
        "<button class=\"nav-item\" type=\"button\" data-filter=\"downloading\"><span class=\"nav-label\"><span class=\"material-symbols-rounded\">download</span>Downloading</span><span class=\"count\">{downloading}</span></button>"
    ));
    out.push_str(&format!(
        "<button class=\"nav-item\" type=\"button\" data-filter=\"complete\"><span class=\"nav-label\"><span class=\"material-symbols-rounded\">check_circle</span>Complete</span><span class=\"count\">{complete}</span></button>"
    ));
    out.push_str(&format!(
        "<button class=\"nav-item\" type=\"button\" data-filter=\"paused\"><span class=\"nav-label\"><span class=\"material-symbols-rounded\">pause_circle</span>Paused</span><span class=\"count\">{paused}</span></button>"
    ));
    out.push_str(&format!(
        "<button class=\"nav-item\" type=\"button\" data-filter=\"queued\"><span class=\"nav-label\"><span class=\"material-symbols-rounded\">schedule</span>Queued</span><span class=\"count\">{queued}</span></button>"
    ));
    out.push_str(&format!(
        "<button class=\"nav-item\" type=\"button\" data-filter=\"error\"><span class=\"nav-label\"><span class=\"material-symbols-rounded\">error</span>Errors</span><span class=\"count\">{errored}</span></button>"
    ));
    // Label filter buttons
    {
        let mut labels: Vec<String> = state
            .torrents
            .iter()
            .filter(|t| !t.label.is_empty())
            .map(|t| t.label.clone())
            .collect();
        labels.sort();
        labels.dedup();
        for lbl in &labels {
            let count = state.torrents.iter().filter(|t| t.label == *lbl).count();
            out.push_str(&format!(
                "<button class=\"nav-item\" type=\"button\" data-filter=\"label:{}\" style=\"margin-top:2px\"><span class=\"nav-label\"><span class=\"material-symbols-rounded\">label</span>{}</span><span class=\"count\">{count}</span></button>",
                escape_html(lbl),
                escape_html(lbl)
            ));
        }
    }
    out.push_str("</div></div>");
    out.push_str("<div class=\"panel\">");
    out.push_str("<div class=\"panel-title\">Session</div>");
    out.push_str("<div class=\"session-stats\">");
    out.push_str(&format!("<div class=\"session-row\"><span>Downloaded</span><span class=\"session-value\">{total_downloaded}</span></div>"));
    out.push_str(&format!("<div class=\"session-row\"><span>Uploaded</span><span class=\"session-value\">{total_uploaded}</span></div>"));
    out.push_str(&format!(
        "<div class=\"session-row\"><span>Peers</span><span class=\"session-value\">{total_active_peers} / {total_tracker_peers}</span></div>"
    ));
    out.push_str(&format!(
        "<div class=\"session-row\"><span>Connections</span><span class=\"session-value\">+{} / -{}</span></div>",
        state.peer_connected, state.peer_disconnected
    ));
    out.push_str(&format!(
        "<div class=\"session-row\"><span>Disk I/O</span><span class=\"session-value\">{:.1}ms / {:.1}ms</span></div>",
        state.disk_read_ms_avg, state.disk_write_ms_avg
    ));
    if !state.proxy_label.is_empty() {
        out.push_str(&format!(
            "<div class=\"session-row\"><span>Proxy</span><span class=\"session-value\">{}</span></div>",
            escape_html(&state.proxy_label)
        ));
    }
    out.push_str("</div>");
    out.push_str("<div class=\"limit-controls\">");
    out.push_str("<div class=\"limit-row\">");
    out.push_str("<div class=\"limit-label\">Max download</div>");
    out.push_str(&format!(
        "<div class=\"limit-value\" id=\"downloadLimitValue\">{}</div>",
        human_rate(state.global_download_limit_bps as f64)
    ));
    out.push_str("</div>");
    out.push_str(&format!(
        "<input id=\"downloadLimit\" class=\"limit-slider\" type=\"range\" min=\"0\" max=\"102400\" step=\"128\" value=\"{download_limit_kbps}\">"
    ));
    out.push_str("<div class=\"limit-row\" style=\"margin-top:8px\">");
    out.push_str("<div class=\"limit-label\">Max upload</div>");
    out.push_str(&format!(
        "<div class=\"limit-value\" id=\"uploadLimitValue\">{}</div>",
        human_rate(state.global_upload_limit_bps as f64)
    ));
    out.push_str("</div>");
    out.push_str(&format!(
        "<input id=\"uploadLimit\" class=\"limit-slider\" type=\"range\" min=\"0\" max=\"102400\" step=\"64\" value=\"{upload_limit_kbps}\">"
    ));
    out.push_str("</div>");
    out.push_str("<div class=\"limit-group\">");
    out.push_str("<div class=\"limit-label\">Seed Ratio</div>");
    out.push_str(&format!(
        "<div class=\"limit-value\" id=\"seedRatioValue\">{}</div>",
        if state.seed_ratio > 0.0 {
            format!("{:.2}", state.seed_ratio)
        } else {
            "unlimited".to_string()
        }
    ));
    out.push_str("</div>");
    out.push_str(&format!(
        "<input id=\"seedRatio\" class=\"limit-slider\" type=\"range\" min=\"0\" max=\"100\" step=\"1\" value=\"{}\" title=\"0 = unlimited\">",
        (state.seed_ratio * 10.0).round() as u32
    ));
    out.push_str("</div>");

    // RSS panel
    out.push_str("<div class=\"panel\">");
    out.push_str("<div class=\"panel-title\"><span class=\"material-symbols-rounded\" style=\"font-size:16px;vertical-align:-3px;margin-right:4px\">rss_feed</span>RSS Feeds</div>");
    out.push_str("<form class=\"rss-form\" onsubmit=\"addRssFeed(event)\">");
    out.push_str("<input id=\"rssUrl\" class=\"input\" placeholder=\"Feed URL\">");
    out.push_str("<button type=\"submit\" class=\"btn primary\">Add</button>");
    out.push_str("</form>");
    {
        use crate::RSS_STATE;
        if let Some(lock) = RSS_STATE.get() {
            if let Ok(rss_state) = lock.lock() {
                if !rss_state.feeds.is_empty() {
                    out.push_str("<div class=\"rss-list\">");
                    for feed in &rss_state.feeds {
                        let title = if feed.title.is_empty() {
                            &feed.url
                        } else {
                            &feed.title
                        };
                        out.push_str(&format!(
                            "<div class=\"rss-item\"><span class=\"rss-item-info\" title=\"{}\">{}</span><span class=\"rss-item-meta\">{} items</span><button class=\"remove-btn\" onclick=\"removeRssFeed('{}')\" title=\"Remove\">\u{00d7}</button></div>",
                            escape_html(&feed.url),
                            escape_html(title),
                            feed.items.len(),
                            escape_html(&feed.url),
                        ));
                    }
                    out.push_str("</div>");
                }
                // Rules section
                out.push_str("<div class=\"rss-section-label\">Rules</div>");
                if !rss_state.rules.is_empty() {
                    out.push_str("<div class=\"rss-list\">");
                    for rule in &rss_state.rules {
                        out.push_str(&format!(
                            "<div class=\"rss-item\"><span class=\"rss-item-info\">{}: {}</span><button class=\"remove-btn\" onclick=\"removeRssRule('{}')\" title=\"Remove\">\u{00d7}</button></div>",
                            escape_html(&rule.name),
                            escape_html(&rule.pattern),
                            escape_html(&rule.name),
                        ));
                    }
                    out.push_str("</div>");
                }
                // Add rule form
                out.push_str("<form class=\"rss-form\" onsubmit=\"addRssRule(event)\">");
                out.push_str(
                    "<input id=\"rssRuleName\" class=\"input\" placeholder=\"Rule name\">",
                );
                out.push_str(
                    "<input id=\"rssRulePattern\" class=\"input\" placeholder=\"Pattern\">",
                );
                out.push_str("<button type=\"submit\" class=\"btn primary\">Add</button>");
                out.push_str("</form>");
            }
        }
    }
    out.push_str("</div>");

    out.push_str("</aside>");

    out.push_str("<main class=\"torrent-list\">");
    if state.torrents.is_empty() {
        out.push_str("<div class=\"panel empty-state\">");
        out.push_str("<span class=\"material-symbols-rounded\">cloud_download</span>");
        out.push_str("<p>No torrents yet. Click <b>Add Torrent</b> to get started.</p>");
        out.push_str("</div>");
    } else {
        for (card_index, torrent) in state.torrents.iter().enumerate() {
            let name = if torrent.name.is_empty() {
                "(unknown)"
            } else {
                &torrent.name
            };
            let name = escape_html(name);
            let status_raw = torrent.status.as_str();
            let bucket = bucket_for(torrent);
            let status_display = if bucket == "complete" {
                "seeding"
            } else {
                status_raw
            };
            let status = escape_html(status_display);
            let status_class = format!("status-{bucket}");
            let info_hash = escape_html(&torrent.info_hash);
            let download_dir = escape_html(&torrent.download_dir);
            let total_bytes = human_bytes(torrent.total_bytes);
            let mut completed_bytes = if torrent.completed_bytes > 0 || torrent.total_pieces == 0 {
                torrent.completed_bytes
            } else {
                torrent
                    .total_bytes
                    .saturating_mul(torrent.completed_pieces as u64)
                    / torrent.total_pieces.max(1) as u64
            };
            if bucket == "complete" && torrent.total_bytes > 0 {
                completed_bytes = torrent.total_bytes;
            }
            let completed_label = human_bytes(completed_bytes.min(torrent.total_bytes));
            let downloaded_label = human_bytes(torrent.downloaded_bytes);
            let uploaded_label = human_bytes(torrent.uploaded_bytes);
            let ratio = format_ratio(torrent.uploaded_bytes, torrent.downloaded_bytes);
            let speed = human_rate(torrent.download_rate_bps);
            let upload_rate = human_rate(torrent.upload_rate_bps);
            let eta = format_eta_secs(torrent.eta_secs);
            let pct = percent(completed_bytes, torrent.total_bytes);
            let pct_value = (pct as f64 / 100.0).min(100.0);
            let peers = format!("{} / {}", torrent.active_peers, torrent.tracker_peers);
            let pieces = format!("{}/{}", torrent.completed_pieces, torrent.total_pieces);
            let progress_class =
                if torrent.total_bytes > 0 && completed_bytes >= torrent.total_bytes {
                    "progress good"
                } else {
                    "progress"
                };
            let preallocate = if torrent.preallocate { "true" } else { "false" };
            let paused = if torrent.paused { "true" } else { "false" };
            let pause_label = if torrent.paused { "Resume" } else { "Pause" };
            let pause_disabled = matches!(status_raw, "queued" | "loading" | "fetching metadata");
            let pause_attrs = if pause_disabled {
                " disabled title=\"Not available while torrent is initializing\""
            } else {
                ""
            };
            let stop_disabled = matches!(status_raw, "loading" | "fetching metadata");
            let stop_attrs = if stop_disabled {
                " disabled title=\"Not available while metadata is loading\""
            } else {
                ""
            };
            let priority_disabled =
                matches!(status_raw, "queued" | "loading" | "fetching metadata");
            let priority_attrs = if priority_disabled {
                " disabled title=\"Priority can be changed after metadata is ready\""
            } else {
                ""
            };

            out.push_str(&format!(
                "<section class=\"panel torrent-card\" style=\"--card-index:{card_index}\" data-status=\"{bucket}\" data-id=\"{id}\" data-info-hash=\"{info_hash}\" data-name=\"{name}\" data-paused=\"{paused}\" data-label=\"{label}\" data-collapsed=\"true\">",
                id = torrent.id,
                card_index = card_index,
                label = escape_html(&torrent.label)
            ));
            out.push_str("<div class=\"torrent-head\">");
            out.push_str("<div>");
            out.push_str(&format!("<div class=\"torrent-title\">{name}</div>"));
            out.push_str(&format!(
                "<div class=\"torrent-sub\"><span class=\"status-pill {status_class}\">{status}</span><span class=\"torrent-size\">{total_bytes}</span></div>"
            ));
            out.push_str("</div>");
            let pause_icon = if torrent.paused {
                "play_arrow"
            } else {
                "pause"
            };
            out.push_str("<div class=\"torrent-actions\">");
            out.push_str(&format!(
                "<button class=\"btn ghost\" type=\"button\" data-action=\"toggle-pause\"{pause_attrs}><span class=\"material-symbols-rounded\">{pause_icon}</span>{pause_label}</button>"
            ));
            out.push_str("<button class=\"btn ghost\" type=\"button\" data-action=\"toggle-expand\"><span class=\"material-symbols-rounded\">unfold_more</span>Expand</button>");
            out.push_str("<button class=\"btn ghost\" type=\"button\" data-action=\"open-folder\"><span class=\"material-symbols-rounded\">folder_open</span>Open Folder</button>");
            out.push_str("<button class=\"btn ghost\" type=\"button\" data-action=\"recheck\"><span class=\"material-symbols-rounded\">verified</span>Recheck</button>");
            out.push_str(&format!(
                "<button class=\"btn ghost\" type=\"button\" data-action=\"stop\"{stop_attrs}><span class=\"material-symbols-rounded\">stop</span>Stop</button>"
            ));
            out.push_str("<button class=\"btn danger\" type=\"button\" data-action=\"delete\"><span class=\"material-symbols-rounded\">delete</span>Delete</button>");
            out.push_str("</div>");
            out.push_str("</div>");

            out.push_str(&format!(
                "<div class=\"torrent-progress\"><div class=\"meta\">Progress {completed_label} / {total_bytes} ({:.2}%)</div>",
                pct_value
            ));
            out.push_str(&format!(
                "<div class=\"{progress_class}\"><div class=\"fill\" style=\"width:{:.2}%\"></div></div></div>",
                pct_value
            ));
            out.push_str(&format!(
                "<div class=\"torrent-quick\"><span><span class=\"material-symbols-rounded\">download</span>{speed}</span><span><span class=\"material-symbols-rounded\">upload</span>{upload_rate}</span><span><span class=\"material-symbols-rounded\">group</span>{peers}</span><span><span class=\"material-symbols-rounded\">schedule</span>{eta}</span></div>"
            ));
            out.push_str("<div class=\"torrent-stats\">");
            out.push_str(&format!(
                "<div class=\"stat\"><span class=\"k\"><span class=\"material-symbols-rounded\">download</span>Down</span><span class=\"v\">{speed}</span></div>"
            ));
            out.push_str(&format!(
                "<div class=\"stat\"><span class=\"k\"><span class=\"material-symbols-rounded\">upload</span>Up</span><span class=\"v\">{upload_rate}</span></div>"
            ));
            out.push_str(&format!(
                "<div class=\"stat\"><span class=\"k\"><span class=\"material-symbols-rounded\">swap_vert</span>Ratio</span><span class=\"v\">{ratio}</span></div>"
            ));
            out.push_str(&format!(
                "<div class=\"stat\"><span class=\"k\"><span class=\"material-symbols-rounded\">schedule</span>ETA</span><span class=\"v\">{eta}</span></div>"
            ));
            out.push_str(&format!(
                "<div class=\"stat\"><span class=\"k\"><span class=\"material-symbols-rounded\">group</span>Peers</span><span class=\"v\">{peers}</span></div>"
            ));
            out.push_str(&format!(
                "<div class=\"stat\"><span class=\"k\"><span class=\"material-symbols-rounded\">grid_view</span>Pieces</span><span class=\"v\">{pieces}</span></div>"
            ));
            out.push_str("</div>");

            out.push_str("<div class=\"torrent-grid\">");
            out.push_str("<div class=\"subpanel\">");
            out.push_str("<div class=\"panel-title\">General</div>");
            out.push_str("<div class=\"kv\">");
            out.push_str(&format!(
                "<div class=\"k\">Info hash</div><div>{info_hash}</div>"
            ));
            {
                let version_label = match torrent.meta_version {
                    2 => "v2",
                    3 => "Hybrid",
                    _ => "v1",
                };
                out.push_str(&format!(
                    "<div class=\"k\">Version</div><div>{version_label}</div>"
                ));
            }
            out.push_str(&format!(
                "<div class=\"k\">Download dir</div><div>{download_dir}</div>"
            ));
            out.push_str(&format!(
                "<div class=\"k\">Preallocate</div><div>{preallocate}</div>"
            ));
            out.push_str(&format!(
                "<div class=\"k\">Downloaded</div><div>{downloaded_label}</div>"
            ));
            out.push_str(&format!(
                "<div class=\"k\">Uploaded</div><div>{uploaded_label}</div>"
            ));
            out.push_str(&format!("<div class=\"k\">Ratio</div><div>{ratio}</div>"));
            out.push_str(&format!(
                "<div class=\"k\">Label</div><div class=\"inline-form\"><input class=\"label-input input\" type=\"text\" value=\"{}\" placeholder=\"none\"><button class=\"btn\" data-action=\"set-label\">Set</button></div>",
                escape_html(&torrent.label)
            ));
            out.push_str("</div>");
            out.push_str("</div>");

            // Peer countries panel
            if !torrent.peer_country_counts.is_empty() {
                out.push_str("<div class=\"subpanel\">");
                out.push_str("<div class=\"panel-title\">Peers by Country</div>");
                out.push_str("<div class=\"country-tags\">");
                for (cc, count) in &torrent.peer_country_counts {
                    let flag = crate::geoip::country_flag(cc);
                    out.push_str(&format!(
                        "<span class=\"country-tag\">{flag} {cc} <b>{count}</b></span>"
                    ));
                }
                out.push_str("</div></div>");
            }

            // Trackers panel
            out.push_str("<div class=\"subpanel\">");
            out.push_str("<div class=\"panel-title\">Trackers</div>");
            if !torrent.trackers.is_empty() {
                for tracker in &torrent.trackers {
                    out.push_str(&format!(
                        "<div class=\"tracker-item\"><span>{}</span><button class=\"remove-btn\" data-action=\"remove-tracker\" data-url=\"{}\" title=\"Remove\">\u{00d7}</button></div>",
                        escape_html(tracker),
                        escape_html(tracker)
                    ));
                }
            }
            out.push_str("<div class=\"inline-form\"><input class=\"tracker-add-input input\" type=\"text\" placeholder=\"https://... or udp://...\"><button class=\"btn\" data-action=\"add-tracker\">Add</button></div>");
            out.push_str("</div>");

            out.push_str("<div class=\"subpanel\">");
            out.push_str("<div class=\"panel-title\">Files</div>");
            if torrent.files.is_empty() {
                out.push_str("<div class=\"small\" style=\"margin-top:8px\">No files.</div>");
            } else {
                out.push_str("<table class=\"table\"><thead><tr><th>File</th><th>Size</th><th>Done</th><th>Progress</th><th>Priority</th></tr></thead><tbody>");
                for (idx, file) in torrent.files.iter().enumerate() {
                    let file_name = escape_html(&file.path);
                    let size = human_bytes(file.length);
                    let done = human_bytes(file.completed);
                    let file_pct = percent(file.completed, file.length);
                    let file_pct_value = (file_pct as f64 / 100.0).min(100.0);
                    let priority = file.priority;
                    let priority_select = format!(
                        "<select class=\"input\" onchange=\"setPriority({id},{idx}, this.value)\"{priority_attrs}><option value=\"0\"{}>Skip</option><option value=\"1\"{}>Low</option><option value=\"2\"{}>Normal</option><option value=\"3\"{}>High</option></select>",
                        if priority == 0 { " selected" } else { "" },
                        if priority == 1 { " selected" } else { "" },
                        if priority == 2 { " selected" } else { "" },
                        if priority == 3 { " selected" } else { "" },
                        priority_attrs = priority_attrs,
                        id = torrent.id,
                        idx = idx
                    );
                    let tid = torrent.id;
                    out.push_str(&format!(
                        "<tr><td class=\"file-cell\" ondblclick=\"startRename({tid},{idx},this)\" title=\"Double-click to rename\">{file_name}</td><td>{size}</td><td>{done}</td><td><div class=\"file-bar\"><div class=\"fill\" style=\"width:{file_pct_value:.2}%\"></div></div></td><td>{priority_select}</td></tr>"
                    ));
                }
                out.push_str("</tbody></table>");
            }
            out.push_str("</div>");
            out.push_str("</div>");
            out.push_str("</section>");
        }
    }
    out.push_str("</main>");

    out.push_str("</div>");
    out.push_str("<div id=\"addModal\" class=\"modal\" onclick=\"maybeClose(event)\">");
    out.push_str("<div class=\"modal-card\">");
    out.push_str("<div class=\"modal-head\"><div class=\"modal-title\">Add Torrent</div><button class=\"btn icon-btn ghost\" type=\"button\" onclick=\"closeAdd()\"><span class=\"material-symbols-rounded\">close</span></button></div>");
    out.push_str("<div class=\"add-grid\">");
    // Drop zone for .torrent file
    out.push_str("<div id=\"dropZone\" class=\"drop-zone\" onclick=\"document.getElementById('torrentFile').click()\">");
    out.push_str("<input id=\"torrentFile\" type=\"file\" accept=\".torrent\" onchange=\"handleTorrentInputChange()\" onclick=\"event.stopPropagation()\">");
    out.push_str("<span class=\"material-symbols-rounded dz-icon\">upload_file</span>");
    out.push_str("<span class=\"dz-text\">Drop .torrent file here or click to browse</span>");
    out.push_str("<span class=\"dz-hint\">.torrent files only</span>");
    out.push_str("<div class=\"dz-file-info\"><span class=\"material-symbols-rounded dz-icon\">description</span><span id=\"dzFileName\" class=\"dz-file-name\"></span><button type=\"button\" class=\"dz-file-remove\" onclick=\"event.stopPropagation();clearTorrentFile()\" title=\"Remove file\"><span class=\"material-symbols-rounded\" style=\"font-size:18px\">close</span></button></div>");
    out.push_str("</div>");
    // Divider
    out.push_str("<div class=\"add-divider\">or paste a magnet link</div>");
    // Magnet input
    out.push_str("<input id=\"magnet\" class=\"input\" type=\"text\" placeholder=\"magnet:?xt=urn:btih:...\" autocomplete=\"off\" oninput=\"handleMagnetInput()\">");
    // Summary & review
    out.push_str("<div id=\"addSummary\" class=\"add-summary\">Select a .torrent file or paste a magnet link.</div>");
    out.push_str("<div id=\"addReview\" class=\"add-review\" style=\"display:none\"></div>");
    // Options section
    out.push_str("<div class=\"add-opts\">");
    out.push_str("<div><div class=\"add-field-label\">Save to</div>");
    out.push_str("<div class=\"add-download-row\">");
    out.push_str(&format!(
        "<input id=\"downloadDir\" class=\"input\" type=\"text\" placeholder=\"Download directory\" value=\"{download_dir}\">"
    ));
    out.push_str("<button class=\"btn ghost\" type=\"button\" onclick=\"chooseDownloadDir()\"><span class=\"material-symbols-rounded\" style=\"font-size:18px\">folder_open</span></button>");
    out.push_str("</div></div>");
    out.push_str(&format!(
        "<div class=\"add-prefs\"><label class=\"add-check\"><input id=\"preallocate\" type=\"checkbox\" {}> Preallocate</label><label class=\"add-check\"><input id=\"startWhenAdded\" type=\"checkbox\" checked> Start immediately</label></div>",
        if state.preallocate { "checked" } else { "" }
    ));
    out.push_str("</div>");
    // Actions
    out.push_str("<div class=\"modal-actions\"><button class=\"btn ghost\" type=\"button\" onclick=\"closeAdd()\">Cancel</button><button class=\"btn primary\" type=\"button\" onclick=\"return submitAdd();\"><span class=\"material-symbols-rounded\" style=\"font-size:18px\">add</span> Add Torrent</button></div>");
    out.push_str("</div>");
    out.push_str("</div>");
    out.push_str("</div>");
    // Page-level drop overlay
    out.push_str("<div id=\"pageDropOverlay\" class=\"page-drop-overlay\"><div class=\"page-drop-overlay-inner\"><span class=\"material-symbols-rounded\">cloud_upload</span><p>Drop to add torrent</p></div></div>");
    out
}

fn status_json(state: &UiState) -> String {
    let overall_percent = percent(state.completed_bytes, state.total_bytes);
    let ratio = ratio_value(state.uploaded_bytes, state.downloaded_bytes);
    let current_id_json = state
        .current_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "null".to_string());
    let mut files_json = String::new();
    files_json.push('[');
    for (idx, file) in state.files.iter().enumerate() {
        if idx > 0 {
            files_json.push(',');
        }
        let file_percent = percent(file.completed, file.length);
        files_json.push_str(&format!(
            "{{\"path\":\"{}\",\"length\":{},\"completed\":{},\"percent\":{},\"priority\":{}}}",
            escape_json(&file.path),
            file.length,
            file.completed,
            file_percent,
            file.priority
        ));
    }
    files_json.push(']');
    let mut torrents_json = String::new();
    torrents_json.push('[');
    for (idx, torrent) in state.torrents.iter().enumerate() {
        if idx > 0 {
            torrents_json.push(',');
        }
        let percent_done = percent(torrent.completed_bytes, torrent.total_bytes);
        let ratio = ratio_value(torrent.uploaded_bytes, torrent.downloaded_bytes);
        let mut torrent_files_json = String::new();
        torrent_files_json.push('[');
        for (file_idx, file) in torrent.files.iter().enumerate() {
            if file_idx > 0 {
                torrent_files_json.push(',');
            }
            let file_percent = percent(file.completed, file.length);
            torrent_files_json.push_str(&format!(
                "{{\"path\":\"{}\",\"length\":{},\"completed\":{},\"percent\":{},\"priority\":{}}}",
                escape_json(&file.path),
                file.length,
                file.completed,
                file_percent,
                file.priority
            ));
        }
        torrent_files_json.push(']');
        let mut trackers_json = String::from("[");
        for (ti, t) in torrent.trackers.iter().enumerate() {
            if ti > 0 {
                trackers_json.push(',');
            }
            trackers_json.push('"');
            trackers_json.push_str(&escape_json(t));
            trackers_json.push('"');
        }
        trackers_json.push(']');
        let mut countries_json = String::from("[");
        for (ci, (cc, count)) in torrent.peer_country_counts.iter().enumerate() {
            if ci > 0 {
                countries_json.push(',');
            }
            countries_json.push_str(&format!(
                "{{\"code\":\"{}\",\"count\":{}}}",
                escape_json(cc),
                count
            ));
        }
        countries_json.push(']');
        torrents_json.push_str(&format!(
            "{{\"id\":{},\"name\":\"{}\",\"info_hash\":\"{}\",\"download_dir\":\"{}\",\"preallocate\":{},\"status\":\"{}\",\"total_bytes\":{},\"completed_bytes\":{},\"downloaded_bytes\":{},\"uploaded_bytes\":{},\"ratio\":{:.3},\"total_pieces\":{},\"completed_pieces\":{},\"percent\":{},\"download_rate_bps\":{:.2},\"upload_rate_bps\":{:.2},\"eta_secs\":{},\"tracker_peers\":{},\"active_peers\":{},\"paused\":{},\"last_error\":\"{}\",\"label\":\"{}\",\"trackers\":{},\"files\":{},\"peer_countries\":{}}}",
            torrent.id,
            escape_json(&torrent.name),
            escape_json(&torrent.info_hash),
            escape_json(&torrent.download_dir),
            torrent.preallocate,
            escape_json(&torrent.status),
            torrent.total_bytes,
            torrent.completed_bytes,
            torrent.downloaded_bytes,
            torrent.uploaded_bytes,
            ratio,
            torrent.total_pieces,
            torrent.completed_pieces,
            percent_done,
            torrent.download_rate_bps,
            torrent.upload_rate_bps,
            torrent.eta_secs,
            torrent.tracker_peers,
            torrent.active_peers,
            torrent.paused,
            escape_json(&torrent.last_error),
            escape_json(&torrent.label),
            trackers_json,
            torrent_files_json,
            countries_json
        ));
    }
    torrents_json.push(']');
    format!(
        "{{\"name\":\"{}\",\"info_hash\":\"{}\",\"download_dir\":\"{}\",\"status\":\"{}\",\"last_error\":\"{}\",\"total_pieces\":{},\"completed_pieces\":{},\"total_bytes\":{},\"completed_bytes\":{},\"downloaded_bytes\":{},\"uploaded_bytes\":{},\"ratio\":{:.3},\"percent\":{},\"tracker_peers\":{},\"active_peers\":{},\"preallocate\":{},\"paused\":{},\"download_rate_bps\":{:.2},\"upload_rate_bps\":{:.2},\"eta_secs\":{},\"queue_len\":{},\"last_added\":\"{}\",\"current_id\":{},\"peer_connected\":{},\"peer_disconnected\":{},\"disk_read_ms_avg\":{:.3},\"disk_write_ms_avg\":{:.3},\"session_downloaded_bytes\":{},\"session_uploaded_bytes\":{},\"global_download_limit_bps\":{},\"global_upload_limit_bps\":{},\"seed_ratio\":{:.2},\"files\":{},\"torrents\":{}}}",
        escape_json(&state.name),
        escape_json(&state.info_hash),
        escape_json(&state.download_dir),
        escape_json(&state.status),
        escape_json(&state.last_error),
        state.total_pieces,
        state.completed_pieces,
        state.total_bytes,
        state.completed_bytes,
        state.downloaded_bytes,
        state.uploaded_bytes,
        ratio,
        overall_percent,
        state.tracker_peers,
        state.active_peers,
        state.preallocate,
        state.paused,
        state.download_rate_bps,
        state.upload_rate_bps,
        state.eta_secs,
        state.queue_len,
        escape_json(&state.last_added),
        current_id_json,
        state.peer_connected,
        state.peer_disconnected,
        state.disk_read_ms_avg,
        state.disk_write_ms_avg,
        state.session_downloaded_bytes,
        state.session_uploaded_bytes,
        state.global_download_limit_bps,
        state.global_upload_limit_bps,
        state.seed_ratio,
        files_json,
        torrents_json
    )
}

fn percent(done: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        (done.saturating_mul(10_000)) / total
    }
}

fn ratio_value(uploaded: u64, downloaded: u64) -> f64 {
    if downloaded == 0 {
        0.0
    } else {
        uploaded as f64 / downloaded as f64
    }
}

fn format_ratio(uploaded: u64, downloaded: u64) -> String {
    if downloaded == 0 {
        if uploaded == 0 {
            "0.00".to_string()
        } else {
            "inf".to_string()
        }
    } else {
        format!("{:.2}", uploaded as f64 / downloaded as f64)
    }
}

fn human_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} {}", UNITS[unit])
    } else {
        format!("{:.2} {}", size, UNITS[unit])
    }
}

fn human_rate(bps: f64) -> String {
    const UNITS: [&str; 5] = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
    if !bps.is_finite() || bps <= 0.0 {
        return "0 B/s".to_string();
    }
    let mut size = bps;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{:.0} {}", size, UNITS[unit])
    } else {
        format!("{:.2} {}", size, UNITS[unit])
    }
}

fn format_eta_secs(secs: u64) -> String {
    if secs == 0 {
        return "--:--".to_string();
    }
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    } else {
        format!("{:02}:{:02}", minutes, seconds)
    }
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;

    fn torrent_list_is_inside_layout(html: &str) -> bool {
        let mut index = 0usize;
        let mut div_stack: Vec<&'static str> = Vec::new();
        while let Some(start_rel) = html[index..].find('<') {
            let start = index + start_rel;
            let Some(end_rel) = html[start..].find('>') else {
                break;
            };
            let end = start + end_rel + 1;
            let tag = &html[start..end];
            if tag.starts_with("<div") {
                if tag.contains("class=\"layout\"") {
                    div_stack.push("layout");
                } else {
                    div_stack.push("div");
                }
            } else if tag.starts_with("</div") {
                if div_stack.pop().is_none() {
                    return false;
                }
            } else if tag.starts_with("<main") && tag.contains("class=\"torrent-list\"") {
                return div_stack.iter().any(|kind| *kind == "layout");
            }
            index = end;
        }
        false
    }

    fn run_single_request(request_bytes: &[u8], cmd_tx: Option<mpsc::Sender<UiCommand>>) -> String {
        let state = Arc::new(Mutex::new(UiState::default()));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server_state = Arc::clone(&state);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connection");
            handle_connection(stream, server_state, cmd_tx).expect("handle request");
        });

        let mut client = TcpStream::connect(addr).expect("connect test listener");
        client.write_all(request_bytes).expect("write request");
        client.shutdown(Shutdown::Write).expect("shutdown write");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");
        server.join().expect("join server");
        String::from_utf8_lossy(&response).into_owned()
    }

    #[test]
    fn status_json_uses_null_for_missing_current_id() {
        let state = UiState::default();
        let json = status_json(&state);
        assert!(json.contains("\"current_id\":null"));
    }

    #[test]
    fn status_for_error_maps_common_cases() {
        assert_eq!(status_for_error("unknown torrent"), 404);
        assert_eq!(status_for_error("torrent already added"), 409);
        assert_eq!(status_for_error("invalid priority"), 400);
        assert_eq!(status_for_error("ui command timeout"), 504);
    }

    #[test]
    fn post_without_token_is_forbidden() {
        let request = b"POST /torrent/pause?id=1 HTTP/1.1\r\nHost: 127.0.0.1:19001\r\nContent-Length: 0\r\n\r\n";
        let response = run_single_request(request, None);
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("missing or invalid api token"));
    }

    #[test]
    fn post_with_origin_mismatch_is_forbidden() {
        let request = format!(
            "POST /torrent/pause?id=1 HTTP/1.1\r\nHost: 127.0.0.1:19002\r\nOrigin: http://127.0.0.1:19003\r\nX-Rustorrent-Token: {}\r\nContent-Length: 0\r\n\r\n",
            api_token()
        );
        let response = run_single_request(request.as_bytes(), None);
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("forbidden origin"));
    }

    #[test]
    fn add_torrent_returns_torrent_id_in_json() {
        let (cmd_tx, cmd_rx) = mpsc::channel::<UiCommand>();
        let command_thread = thread::spawn(move || {
            let cmd = cmd_rx.recv().expect("receive add command");
            match cmd {
                UiCommand::AddTorrent { reply, .. } => {
                    let _ = reply.send(Ok(UiCommandSuccess::TorrentAdded { torrent_id: 77 }));
                }
                _ => panic!("expected add torrent command"),
            }
        });

        let host = "127.0.0.1:19004";
        let body = b"test";
        let mut request = format!(
            "POST /add-torrent?dir=%2Ftmp&prealloc=0 HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nX-Rustorrent-Token: {}\r\nContent-Type: application/x-bittorrent\r\nContent-Length: {}\r\n\r\n",
            api_token(),
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);

        let response = run_single_request(&request, Some(cmd_tx));
        command_thread.join().expect("join command thread");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"ok\":true"));
        assert!(response.contains("\"torrent_id\":77"));
    }

    #[test]
    fn split_path_query_and_percent_decode_work() {
        let (path, query) = split_path_query("/add?name=hello+world&x=%2Ftmp&empty=");
        assert_eq!(path, "/add");
        assert_eq!(
            query,
            vec![
                ("name".to_string(), "hello world".to_string()),
                ("x".to_string(), "/tmp".to_string()),
                ("empty".to_string(), "".to_string())
            ]
        );
    }

    #[test]
    fn authorize_mutating_request_allows_valid_token_and_origin() {
        let request = HttpRequest {
            method: "POST".to_string(),
            path: "/torrent/pause?id=1".to_string(),
            headers: vec![
                ("host".to_string(), "127.0.0.1:8080".to_string()),
                ("origin".to_string(), "http://127.0.0.1:8080".to_string()),
                (API_TOKEN_HEADER.to_string(), api_token().to_string()),
            ],
            body: Vec::new(),
        };
        assert!(authorize_mutating_request(&request).is_ok());
    }

    #[test]
    fn parse_bool_and_origin_extraction() {
        assert!(parse_bool("true"));
        assert!(parse_bool("YES"));
        assert!(parse_bool("1"));
        assert!(!parse_bool("0"));
        assert!(!parse_bool("no"));
        assert_eq!(
            extract_origin_host("https://Example.com:8443/path"),
            Some("example.com:8443".to_string())
        );
        assert_eq!(extract_origin_host("invalid"), None);
    }

    #[test]
    fn formatting_helpers_are_stable() {
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1024), "1.00 KB");
        assert_eq!(human_rate(0.0), "0 B/s");
        assert_eq!(human_rate(1536.0), "1.50 KB/s");
        assert_eq!(format_eta_secs(0), "--:--");
        assert_eq!(format_eta_secs(61), "01:01");
        assert_eq!(format_eta_secs(3661), "01:01:01");
        assert_eq!(escape_html("<a&\"'>"), "&lt;a&amp;&quot;&#39;&gt;");
        assert_eq!(escape_json("a\"b\\\n"), "a\\\"b\\\\\\n");
    }

    #[test]
    fn desktop_layout_breakpoints_keep_two_columns_until_small_widths() {
        let html = status_html(&UiState::default());
        assert!(html.contains(".app{width:100%;max-width:1600px"));
        assert!(html.contains(".layout{"));
        assert!(html.contains("display:flex;"));
        assert!(html.contains(".sidebar{"));
        assert!(html.contains("flex:0 0 260px;"));
        assert!(html.contains("width:260px;"));
        assert!(html.contains("@media(max-width:900px){"));
        assert!(html.contains(".layout{gap:16px}"));
        assert!(html.contains(".sidebar{flex-basis:240px;width:240px}"));
        assert!(html.contains("@media(max-width:520px){"));
        assert!(html.contains(".layout{flex-direction:column}"));
    }

    #[test]
    fn theme_defaults_to_light_without_saved_preference() {
        let html = status_html(&UiState::default());
        assert!(html.contains("if(t!=='light'&&t!=='dark'){t='light';}"));
        assert!(html.contains("function resolveTheme(){"));
        assert!(html.contains("let theme='light';"));
    }

    #[test]
    fn torrent_list_is_nested_inside_layout_container() {
        let html = app_body_html(&UiState::default());
        assert!(torrent_list_is_inside_layout(&html));
    }

    #[test]
    fn seeding_bucket_renders_full_progress_even_if_bytes_lag() {
        let mut state = UiState::default();
        state.torrents.push(UiTorrent {
            id: 7,
            name: "ubuntu.iso".to_string(),
            status: "seeding".to_string(),
            total_bytes: 1000,
            completed_bytes: 998,
            total_pieces: 10,
            completed_pieces: 9,
            ..UiTorrent::default()
        });

        let html = app_body_html(&state);
        assert!(html.contains("Progress 1000 B / 1000 B (100.00%)"));
    }
}

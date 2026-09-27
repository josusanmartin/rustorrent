use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
#[cfg(unix)]
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::is_paused;

#[derive(Debug)]
pub enum UiCommand {
    AddTorrent {
        data: Vec<u8>,
        download_dir: String,
        preallocate: bool,
        options: AddOptions,
        reply: mpsc::Sender<UiCommandResult>,
    },
    AddMagnet {
        magnet: String,
        download_dir: String,
        preallocate: bool,
        options: AddOptions,
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
    ArchiveTorrent {
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
    SetPeerProfile {
        profile: String,
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

#[derive(Debug, Clone, Default)]
pub struct AddOptions {
    pub paused: bool,
    pub skip_files: Vec<usize>,
}

fn add_options(form: &[(String, String)]) -> Result<AddOptions, String> {
    let skip = query_value(form, "skip").unwrap_or("");
    let mut skip_files = Vec::new();
    if !skip.is_empty() {
        for value in skip.split(',') {
            if skip_files.len() >= 4096 {
                return Err("too many selected files".to_string());
            }
            skip_files.push(
                value
                    .parse::<usize>()
                    .map_err(|_| "invalid file selection".to_string())?,
            );
        }
        crate::util::sort(&mut skip_files);
        skip_files.dedup();
    }
    Ok(AddOptions {
        paused: query_value(form, "paused").is_some_and(parse_bool),
        skip_files,
    })
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
    pub interested_peers: usize,
    pub status: String,
    pub last_error: String,
    pub preallocate: bool,
    pub paused: bool,
    pub download_rate_bps: f64,
    pub upload_rate_bps: f64,
    pub upload_requests_served: u64,
    pub eta_secs: u64,
    pub incoming_port: u16,
    pub natpmp_status: String,
    pub upnp_status: String,
    /// Port mapping on the router in front of ours, when there are two.
    pub upstream_status: String,
    /// The public address the router reports for itself.
    pub router_external_ip: String,
    /// The public address trackers saw our announces come from (BEP 24).
    pub tracker_external_ip: String,
    pub inbound_public_peers: u64,
    pub firewall_status: String,
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
    pub peer_profile: String,
    pub peer_profile_global_limit: usize,
    pub peer_profile_torrent_limit: usize,
    pub peer_profile_numwant: u32,
    pub proxy_label: String,
    pub download_history_bps: Vec<f64>,
    pub upload_history_bps: Vec<f64>,
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
    pub interested_peers: usize,
    pub paused: bool,
    pub last_error: String,
    pub upload_requests_served: u64,
    pub files: Vec<UiFile>,
    pub label: String,
    pub trackers: Vec<String>,
    pub peer_country_counts: Vec<(String, u32)>,
    pub meta_version: u8,
}

/// One connected peer, as the Peers tab shows it.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct UiPeer {
    pub addr: String,
    pub client: String,
    pub utp: bool,
    pub incoming: bool,
    pub encrypted: bool,
    /// Share of the torrent the peer has, 0.0 to 1.0.
    pub progress: f64,
    pub download_bps: f64,
    pub upload_bps: f64,
    /// The peer wants data from us.
    pub interested: bool,
    /// We let the peer download from us (unchoked).
    pub uploading_to: bool,
    /// The peer lets us download from it.
    pub downloading_from: bool,
    pub downloaded: u64,
    pub uploaded: u64,
}

/// Connected peers per torrent, keyed by connection. Kept apart from the
/// status snapshot, which every client polls, and served only on request.
static PEERS: Mutex<std::collections::BTreeMap<u64, HashMap<u64, UiPeer>>> =
    Mutex::new(std::collections::BTreeMap::new());

fn lock_peers() -> MutexGuard<'static, std::collections::BTreeMap<u64, HashMap<u64, UiPeer>>> {
    PEERS.lock().unwrap_or_else(|err| err.into_inner())
}

pub fn set_peer(torrent_id: u64, connection: u64, peer: UiPeer) {
    lock_peers()
        .entry(torrent_id)
        .or_default()
        .insert(connection, peer);
}

pub fn remove_peer(torrent_id: u64, connection: u64) {
    let mut peers = lock_peers();
    if let Some(torrent) = peers.get_mut(&torrent_id) {
        torrent.remove(&connection);
        if torrent.is_empty() {
            peers.remove(&torrent_id);
        }
    }
}

/// Peers of one torrent, busiest first.
fn torrent_peers_json(torrent_id: u64) -> String {
    let mut peers: Vec<UiPeer> = lock_peers()
        .get(&torrent_id)
        .map(|peers| peers.values().cloned().collect())
        .unwrap_or_default();
    peers.sort_by(|a, b| {
        (b.download_bps + b.upload_bps)
            .total_cmp(&(a.download_bps + a.upload_bps))
            .then_with(|| a.addr.cmp(&b.addr))
    });
    let mut out = String::with_capacity(64 + peers.len() * 256);
    let mut json = JsonObject::new(&mut out);
    json.num("id", torrent_id);
    let list = json.key("peers");
    list.push('[');
    for (index, peer) in peers.iter().enumerate() {
        if index > 0 {
            list.push(',');
        }
        let mut item = JsonObject::new(list);
        item.str("addr", &peer.addr)
            .str("client", &peer.client)
            .num("utp", u8::from(peer.utp))
            .num("incoming", u8::from(peer.incoming))
            .num("encrypted", u8::from(peer.encrypted))
            .float("progress", peer.progress, 4)
            .float("download_bps", peer.download_bps, 0)
            .float("upload_bps", peer.upload_bps, 0)
            .num("interested", u8::from(peer.interested))
            .num("uploading_to", u8::from(peer.uploading_to))
            .num("downloading_from", u8::from(peer.downloading_from))
            .num("downloaded", peer.downloaded)
            .num("uploaded", peer.uploaded);
        item.finish();
    }
    list.push(']');
    json.finish();
    out
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
const UI_OWNER_SECRET_ENV: &str = "RUSTORRENT_UI_OWNER_SECRET";
const UI_OWNER_SECRET_HEX_LEN: usize = 64;
static UI_API_TOKEN: OnceLock<String> = OnceLock::new();
static UI_OWNER_SECRET: OnceLock<String> = OnceLock::new();
static API_TOKEN_RATE: OnceLock<Mutex<HashMap<IpAddr, (u32, Instant)>>> = OnceLock::new();
static SSE_ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

const API_TOKEN_RATE_MAX: u32 = 180;
const API_TOKEN_RATE_WINDOW: Duration = Duration::from_secs(60);
const SSE_MAX_ACTIVE_CONNECTIONS: usize = 24;

pub(crate) fn api_token() -> &'static str {
    UI_API_TOKEN.get_or_init(generate_api_token).as_str()
}

fn generate_api_token() -> String {
    let mut bytes = [0u8; 16];
    if let Err(err) = fill_secure_random(&mut bytes) {
        eprintln!("fatal: failed to generate secure API token: {err}");
        std::process::abort();
    }
    hex_bytes(&bytes)
}

fn valid_ui_owner_secret(value: &str) -> bool {
    value.len() == UI_OWNER_SECRET_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn read_ui_owner_secret() -> std::io::Result<String> {
    match std::env::var(UI_OWNER_SECRET_ENV) {
        Ok(value) if valid_ui_owner_secret(&value) => Ok(value),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{UI_OWNER_SECRET_ENV} must be a {UI_OWNER_SECRET_HEX_LEN}-character hexadecimal secret"
            ),
        )),
        Err(std::env::VarError::NotPresent) => Ok(String::new()),
        Err(std::env::VarError::NotUnicode(_)) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{UI_OWNER_SECRET_ENV} must be valid UTF-8"),
        )),
    }
}

fn configure_ui_owner_secret() -> std::io::Result<()> {
    let secret = read_ui_owner_secret()?;
    if let Some(existing) = UI_OWNER_SECRET.get() {
        if existing == &secret {
            return Ok(());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "UI owner secret was already configured with a different value",
        ));
    }
    let _ = UI_OWNER_SECRET.set(secret);
    Ok(())
}

fn ui_owner_secret() -> &'static str {
    UI_OWNER_SECRET
        .get_or_init(|| read_ui_owner_secret().unwrap_or_default())
        .as_str()
}

#[cfg(unix)]
fn fill_secure_random(bytes: &mut [u8]) -> std::io::Result<()> {
    if let Ok(mut file) = File::open("/dev/urandom") {
        if file.read_exact(bytes).is_ok() {
            return Ok(());
        }
    }
    Err(std::io::Error::other(
        "operating-system random source unavailable",
    ))
}

#[cfg(windows)]
fn fill_secure_random(bytes: &mut [u8]) -> std::io::Result<()> {
    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    let length = u32::try_from(bytes.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "random request too large")
    })?;
    // SAFETY: `bytes` is writable for `length` bytes and a null algorithm handle is
    // required when requesting the system-preferred RNG.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "BCryptGenRandom failed with status {status:#x}"
        )))
    }
}

#[cfg(not(any(unix, windows)))]
fn fill_secure_random(_bytes: &mut [u8]) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no secure random implementation for this platform",
    ))
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

struct SseConnectionGuard;

impl Drop for SseConnectionGuard {
    fn drop(&mut self) {
        SSE_ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

fn try_acquire_sse_connection_slot() -> Option<SseConnectionGuard> {
    loop {
        let current = SSE_ACTIVE_CONNECTIONS.load(Ordering::SeqCst);
        if current >= SSE_MAX_ACTIVE_CONNECTIONS {
            return None;
        }
        if SSE_ACTIVE_CONNECTIONS
            .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Some(SseConnectionGuard);
        }
    }
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
) -> std::io::Result<std::net::SocketAddr> {
    configure_ui_owner_secret()?;
    let listener = TcpListener::bind(&addr)?;
    let local_addr = listener.local_addr()?;
    let active_connections = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = stream.set_write_timeout(Some(UI_WRITE_TIMEOUT));
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
    });
    Ok(local_addr)
}

fn handle_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<UiState>>,
    cmd_tx: Option<mpsc::Sender<UiCommand>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(UI_READ_TIMEOUT))?;
    stream.set_write_timeout(Some(UI_WRITE_TIMEOUT))?;
    let mut pending = match read_request_head(&mut stream) {
        Ok(request) => request,
        Err(_) => {
            return send_api_error(stream, "bad request");
        }
    };
    // The API token is intentionally delivered to the local UI. Restricting
    // Host to localhost or an IP literal prevents a hostile DNS name that has
    // rebound to this listener from reading that token and issuing same-origin
    // mutations through the victim's browser.
    if !request_has_safe_host(&pending.request) {
        return send_api_error_with_status(stream, 403, "forbidden host");
    }
    let (path, query) = split_path_query(&pending.request.path);

    if pending.request.method == "POST" {
        if let Err(err) = authorize_mutating_request(&pending.request) {
            return send_api_error_with_status(stream, 403, &err);
        }
        let Some(body_limit) = post_body_limit(&path) else {
            return send_api_error_with_status(stream, 404, "unknown endpoint");
        };
        if finish_request_body(&mut stream, &mut pending, body_limit).is_err() {
            return send_api_error(stream, "bad request");
        }
    }
    let request = pending.request;

    if request.method == "GET" && path == "/api-token" {
        if let Ok(peer) = stream.peer_addr() {
            if !check_api_token_rate(peer.ip()) {
                return send_api_error_with_status(stream, 429, "too many requests");
            }
        }
        return send_api_token(stream);
    }
    if request.method == "HEAD" && path == "/api-token" {
        return send_head(stream, "application/json");
    }
    if request.method == "GET" && path == "/events" {
        let Some(sse_guard) = try_acquire_sse_connection_slot() else {
            return send_api_error_with_status(stream, 503, "too many event streams");
        };
        let _sse_guard = sse_guard;
        return handle_sse(stream, state);
    }
    if request.method == "HEAD" && path == "/events" {
        return send_head(stream, "text/event-stream");
    }

    if request.method == "POST" {
        // Ok(Some(id)) reports a new transfer id; errors other than from the
        // folder helpers are also surfaced in the UI state.
        let result: Result<Option<u64>, String> = match path.as_str() {
            "/torrent/open-folder" => {
                return match handle_open_folder(&query, &state) {
                    Ok(()) => send_api_ok(stream),
                    Err(err) => send_api_error(stream, &err),
                }
            }
            "/network/allow-firewall" => {
                return match crate::firewall::allow() {
                    Ok(_) => {
                        let status = crate::firewall::status();
                        lock_state(&state).firewall_status = status.to_string();
                        send_api_ok(stream)
                    }
                    Err(err) => send_api_error(stream, &err),
                };
            }
            "/select-download-dir" => {
                return match handle_select_download_dir() {
                    Ok(path) => send_api_ok_with_path(stream, path.as_deref().unwrap_or("")),
                    Err(err) => send_api_error(stream, &err),
                }
            }
            "/torrent/pause" | "/torrent/resume" | "/torrent/stop" | "/torrent/archive"
            | "/torrent/delete" => handle_torrent_action(&path, &query, &cmd_tx).map(|_| None),
            "/add-torrent" => handle_add_torrent(&request, &query, &state, &cmd_tx).map(Some),
            "/add-magnet" => handle_add_magnet(&request, &state, &cmd_tx).map(Some),
            "/file-priority" => handle_file_priority(&request, &state, &cmd_tx).map(|_| None),
            "/rename-file" => handle_rename_file(&request, &state, &cmd_tx).map(|_| None),
            "/rate-limits" => handle_rate_limits(&request, &state, &cmd_tx).map(|_| None),
            "/torrent/recheck" => handle_torrent_recheck(&query, &cmd_tx).map(|_| None),
            "/settings/seed-ratio" => handle_set_seed_ratio(&request, &cmd_tx).map(|_| None),
            "/settings/peer-profile" => handle_set_peer_profile(&request, &cmd_tx).map(|_| None),
            "/torrent/set-label" => handle_set_label(&request, &state, &cmd_tx).map(|_| None),
            "/torrent/add-tracker" => handle_add_tracker(&request, &cmd_tx).map(|_| None),
            "/torrent/remove-tracker" => handle_remove_tracker(&request, &cmd_tx).map(|_| None),
            "/rss/add-feed" => handle_rss_add_feed(&request, &cmd_tx).map(|_| None),
            "/rss/remove-feed" => handle_rss_remove_feed(&request, &cmd_tx).map(|_| None),
            "/rss/add-rule" => handle_rss_add_rule(&request, &cmd_tx).map(|_| None),
            "/rss/remove-rule" => handle_rss_remove_rule(&request, &cmd_tx).map(|_| None),
            "/search/install-url" => handle_search_install_url(&request).map(|_| None),
            "/search/install-recommended" => {
                crate::search::install_recommended_plugins().map(|_| None)
            }
            "/search/install-plugin" => {
                handle_search_install_plugin(&request, &query).map(|_| None)
            }
            "/search/remove-plugin" => handle_search_remove_plugin(&request).map(|_| None),
            "/search/run" => handle_search_run(&request).map(|_| None),
            "/search/add-result" => handle_search_add_result(&request, &state, &cmd_tx).map(Some),
            _ => return send_api_error_with_status(stream, 404, "unknown endpoint"),
        };
        return match result {
            Ok(Some(torrent_id)) => send_api_ok_with_torrent_id(stream, torrent_id),
            Ok(None) => send_api_ok(stream),
            Err(err) => {
                update_error(&state, &err);
                send_api_error(stream, &err)
            }
        };
    }

    if let Some(index) = UI_ASSETS.iter().position(|(asset, _, _)| *asset == path) {
        if request.method == "GET" || request.method == "HEAD" {
            return send_asset(stream, &request, index);
        }
    }

    if request.method == "HEAD" {
        let content_type = match path.as_str() {
            "/" | "/index.html" => "text/html; charset=utf-8",
            "/status" | "/search/status" | "/search/catalog" | "/rss/status" | "/torrent/files"
            | "/torrent/peers" => "application/json",
            _ => return send_api_error_with_status(stream, 404, "unknown endpoint"),
        };
        return send_head(stream, content_type);
    }

    if path == "/search/status" {
        let body = crate::search::status_json();
        return send_json_body(stream, 200, &body);
    }
    if path == "/search/catalog" {
        let refresh = query_value(&query, "refresh")
            .map(parse_bool)
            .unwrap_or(false);
        if refresh && !has_valid_api_token(&request) {
            return send_api_error_with_status(stream, 403, "missing or invalid api token");
        }
        let body = crate::search::catalog_json(refresh);
        return send_json_body(stream, 200, &body);
    }
    if path == "/rss/status" {
        let body = rss_status_json();
        return send_json_body(stream, 200, &body);
    }

    if path == "/torrent/peers" {
        let id = query_value(&query, "id").and_then(|value| value.parse::<u64>().ok());
        let known = id.is_some_and(|id| {
            lock_state(&state)
                .torrents
                .iter()
                .any(|torrent| torrent.id == id)
        });
        return match id.filter(|_| known) {
            Some(id) => send_json_body(stream, 200, &torrent_peers_json(id)),
            None => send_api_error_with_status(stream, 404, "unknown torrent"),
        };
    }
    if path == "/torrent/files" {
        let body = query_value(&query, "id")
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|id| {
                let guard = lock_state(&state);
                guard
                    .torrents
                    .iter()
                    .find(|torrent| torrent.id == id)
                    .map(torrent_files_json)
            });
        return match body {
            Some(body) => send_json_body(stream, 200, &body),
            None => send_api_error_with_status(stream, 404, "unknown torrent"),
        };
    }

    let (content_type, body) = match path.as_str() {
        "/status" => {
            let mut guard = lock_state(&state);
            guard.paused = is_paused();
            ("application/json", status_json(&guard))
        }
        "/" | "/index.html" => ("text/html; charset=utf-8", shell_html()),
        _ => return send_api_error_with_status(stream, 404, "unknown endpoint"),
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\n{SECURITY_HEADERS}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

const MAX_REQUEST_BODY_BYTES: usize = crate::MAX_TORRENT_BYTES;
const MAX_FORM_BODY_BYTES: usize = 64 * 1024;
const MAX_PLUGIN_BODY_BYTES: usize = 512 * 1024;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 1024;
const MAX_RATE_LIMIT_KBPS: u64 = 102_400;
const MAX_LABEL_BYTES: usize = 128;
const MAX_USER_URL_BYTES: usize = 2_048;
const MAX_RSS_RULE_BYTES: usize = 512;
const COMMAND_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const UI_MAX_ACTIVE_CONNECTIONS: usize = 64;
const UI_READ_TIMEOUT: Duration = Duration::from_secs(1);
const UI_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(15);
const SECURITY_HEADERS: &str = concat!(
    "X-Content-Type-Options: nosniff\r\n",
    "X-Frame-Options: DENY\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Cross-Origin-Resource-Policy: same-origin\r\n",
    "Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n",
    "Content-Security-Policy: default-src 'self'; base-uri 'none'; object-src 'none'; ",
    "frame-ancestors 'none'; img-src 'self' data:; connect-src 'self'; ",
    "style-src 'self'; script-src 'self' 'sha256-zYHSzMDcF6ayyMRW5P7uibEVSRGbs8AikYgdvoLIdvo='\r\n",
);

fn post_body_limit(path: &str) -> Option<usize> {
    match path {
        "/add-torrent" => Some(crate::MAX_TORRENT_BYTES),
        "/search/install-plugin" => Some(MAX_PLUGIN_BODY_BYTES),
        "/add-magnet"
        | "/file-priority"
        | "/rename-file"
        | "/rate-limits"
        | "/settings/seed-ratio"
        | "/settings/peer-profile"
        | "/torrent/set-label"
        | "/torrent/add-tracker"
        | "/torrent/remove-tracker"
        | "/rss/add-feed"
        | "/rss/remove-feed"
        | "/rss/add-rule"
        | "/rss/remove-rule"
        | "/search/install-url"
        | "/search/remove-plugin"
        | "/search/run"
        | "/search/add-result" => Some(MAX_FORM_BODY_BYTES),
        "/torrent/open-folder"
        | "/torrent/pause"
        | "/torrent/resume"
        | "/torrent/stop"
        | "/torrent/archive"
        | "/torrent/delete"
        | "/select-download-dir"
        | "/network/allow-firewall"
        | "/search/install-recommended"
        | "/torrent/recheck" => Some(0),
        _ => None,
    }
}

struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Clone, Copy)]
enum RequestBodyFraming {
    Fixed(usize),
    Chunked,
}

struct PendingHttpRequest {
    request: HttpRequest,
    buffered_body: Vec<u8>,
    framing: RequestBodyFraming,
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

fn read_request_head(stream: &mut TcpStream) -> std::io::Result<PendingHttpRequest> {
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
        if let Some(pos) = find_header_end(&buffer) {
            if pos + 4 > MAX_HEADER_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request headers too large",
                ));
            }
            header_end = Some(pos);
            break;
        }
        if buffer.len() > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request headers too large",
            ));
        }
    }

    let header_end = header_end
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid request"))?;
    let header_str = std::str::from_utf8(&buffer[..header_end]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request headers are not utf-8",
        )
    })?;
    let mut lines = header_str.split("\r\n");
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
    let version = parts.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid http version")
    })?;
    if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid request line",
        ));
    }
    if !matches!(method.as_str(), "GET" | "HEAD" | "POST") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported method",
        ));
    }
    if !path.starts_with('/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid path",
        ));
    }

    if path.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid path",
        ));
    }

    let mut content_length = None;
    let mut transfer_encoding = None;
    let mut host_seen = false;
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed request header")
        })?;
        if name.is_empty() || !name.bytes().all(is_http_token_byte) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid request header name",
            ));
        }
        let header_name = name.to_ascii_lowercase();
        let header_value = value.trim_matches([' ', '\t']);
        if header_value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid request header value",
            ));
        }
        if header_name == "content-length" {
            if content_length.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate content length",
                ));
            }
            content_length = Some(header_value.parse::<usize>().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid content length")
            })?);
        }
        if header_name == "transfer-encoding" {
            if transfer_encoding.is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate transfer encoding",
                ));
            }
            transfer_encoding = Some(header_value.to_string());
        }
        if header_name == "host" {
            if host_seen {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "duplicate host",
                ));
            }
            host_seen = true;
        }
        headers.push((header_name, header_value.to_string()));
    }
    if version == "HTTP/1.1" && !host_seen {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing host",
        ));
    }
    if content_length.is_some() && transfer_encoding.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ambiguous request body framing",
        ));
    }
    let chunked_body = match transfer_encoding.as_deref() {
        None => false,
        Some(value) if value.eq_ignore_ascii_case("chunked") => true,
        Some(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported transfer encoding",
            ));
        }
    };
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_REQUEST_BODY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }

    let mut buffered_body = buffer[header_end + 4..].to_vec();
    if !chunked_body && buffered_body.len() > content_length {
        buffered_body.truncate(content_length);
    }
    Ok(PendingHttpRequest {
        request: HttpRequest {
            method,
            path,
            headers,
            body: Vec::new(),
        },
        buffered_body,
        framing: if chunked_body {
            RequestBodyFraming::Chunked
        } else {
            RequestBodyFraming::Fixed(content_length)
        },
    })
}

fn finish_request_body(
    stream: &mut TcpStream,
    pending: &mut PendingHttpRequest,
    limit: usize,
) -> std::io::Result<()> {
    match pending.framing {
        RequestBodyFraming::Chunked => {
            pending.request.body =
                read_chunked_body(stream, std::mem::take(&mut pending.buffered_body), limit)?;
            Ok(())
        }
        RequestBodyFraming::Fixed(content_length) => {
            if content_length > limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request body too large",
                ));
            }
            let mut body = std::mem::take(&mut pending.buffered_body);
            if body.len() > content_length {
                body.truncate(content_length);
            }
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

            pending.request.body = body;
            Ok(())
        }
    }
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn read_chunked_body(
    stream: &mut TcpStream,
    mut encoded: Vec<u8>,
    limit: usize,
) -> std::io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut cursor = 0usize;
    let body_deadline = Instant::now() + REQUEST_BODY_TIMEOUT;

    loop {
        let line_end = loop {
            if let Some(relative) = find_crlf(&encoded[cursor..]) {
                if relative > MAX_CHUNK_LINE_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "chunk header too large",
                    ));
                }
                break cursor + relative;
            }
            if encoded.len().saturating_sub(cursor) > MAX_CHUNK_LINE_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "chunk header too large",
                ));
            }
            read_more_body(stream, &mut encoded, body_deadline, limit)?;
        };

        let size = parse_chunk_size(&encoded[cursor..line_end])?;
        cursor = line_end + 2;

        if size == 0 {
            loop {
                if encoded.len() >= cursor + 2 && &encoded[cursor..cursor + 2] == b"\r\n" {
                    return Ok(decoded);
                }
                if find_header_end(&encoded[cursor..]).is_some() {
                    return Ok(decoded);
                }
                read_more_body(stream, &mut encoded, body_deadline, limit)?;
            }
        }

        let next_len = decoded.len().checked_add(size).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "request body too large")
        })?;
        if next_len > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request body too large",
            ));
        }

        let chunk_end = cursor.checked_add(size).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "request body too large")
        })?;
        let framed_end = chunk_end.checked_add(2).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "request body too large")
        })?;
        while encoded.len() < framed_end {
            read_more_body(stream, &mut encoded, body_deadline, limit)?;
        }
        decoded.extend_from_slice(&encoded[cursor..chunk_end]);
        cursor = chunk_end;
        if encoded.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid chunk terminator",
            ));
        }
        cursor += 2;
    }
}

fn read_more_body(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    deadline: Instant,
    limit: usize,
) -> std::io::Result<()> {
    if Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "request body timeout",
        ));
    }
    let mut chunk = [0u8; 1024];
    let n = match stream.read(&mut chunk) {
        Ok(n) => n,
        Err(err) if is_retryable_io_error(&err) => return Ok(()),
        Err(err) => return Err(err),
    };
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "request body truncated",
        ));
    }
    buffer.extend_from_slice(&chunk[..n]);
    if buffer.len() > MAX_HEADER_BYTES + limit.saturating_mul(2) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }
    Ok(())
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

fn parse_chunk_size(line: &[u8]) -> std::io::Result<usize> {
    let mut size_part = line.split(|byte| *byte == b';').next().unwrap_or(&[]);
    while size_part.first().is_some_and(u8::is_ascii_whitespace) {
        size_part = &size_part[1..];
    }
    while size_part.last().is_some_and(u8::is_ascii_whitespace) {
        size_part = &size_part[..size_part.len() - 1];
    }
    if size_part.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid chunk size",
        ));
    }
    if !size_part.iter().all(u8::is_ascii_hexdigit) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid chunk size",
        ));
    }
    let text = std::str::from_utf8(size_part)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk size"))?;
    usize::from_str_radix(text, 16)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk size"))
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

    let options = add_options(query)?;
    let command_result = dispatch_command(cmd_tx, |reply| UiCommand::AddTorrent {
        data: request.body.clone(),
        download_dir,
        preallocate,
        options,
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
    let form = form_pairs(request);
    let magnet = query_value(&form, "magnet").unwrap_or("").to_string();
    if magnet.trim().is_empty() {
        return Err("magnet link is empty".to_string());
    }
    let download_dir = query_value(&form, "dir").unwrap_or("").to_string();
    let preallocate = query_value(&form, "prealloc")
        .map(parse_bool)
        .unwrap_or(false);

    let options = add_options(&form)?;
    let command_result = dispatch_command(cmd_tx, |reply| UiCommand::AddMagnet {
        magnet,
        download_dir,
        preallocate,
        options,
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
    let form = form_pairs(request);
    let index = required(&form, "index")?
        .parse::<usize>()
        .map_err(|_| "invalid index".to_string())?;
    let priority = required(&form, "priority")?
        .parse::<u8>()
        .map_err(|_| "invalid priority".to_string())?;
    if priority > 3 {
        return Err("invalid priority (expected 0 through 3)".to_string());
    }
    let torrent_id = torrent_id(&form)?;

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
    let form = form_pairs(request);
    let index = required(&form, "index")?
        .parse::<usize>()
        .map_err(|_| "invalid index".to_string())?;
    let new_name = required(&form, "name")?.to_string();
    if new_name.is_empty()
        || new_name.len() > 255
        || new_name.contains('/')
        || new_name.contains('\\')
        || new_name.contains('\0')
        || new_name.chars().any(char::is_control)
        || new_name == "."
        || new_name == ".."
    {
        return Err("invalid file name".to_string());
    }
    let torrent_id = torrent_id(&form)?;

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
    let form = form_pairs(request);
    let url = required(&form, "url")?.to_string();
    if url.is_empty() {
        return Err("empty url".to_string());
    }
    if url.len() > MAX_USER_URL_BYTES
        || !(url.starts_with("http://") || url.starts_with("https://"))
    {
        return Err("invalid feed url (expected http:// or https://)".to_string());
    }
    let interval = query_value(&form, "interval")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(900);
    if !(60..=7 * 24 * 60 * 60).contains(&interval) {
        return Err("invalid feed interval (expected 60 to 604800 seconds)".to_string());
    }
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
    let form = form_pairs(request);
    let url = required(&form, "url")?.to_string();
    dispatch_command_ok(cmd_tx, |reply| UiCommand::RemoveRssFeed {
        url: url.clone(),
        reply,
    })
}

fn handle_rss_add_rule(
    request: &HttpRequest,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let form = form_pairs(request);
    let name = required(&form, "name")?.to_string();
    let feed_url = query_value(&form, "feed_url").unwrap_or("").to_string();
    let pattern = required(&form, "pattern")?.to_string();
    if name.trim().is_empty() || name.len() > 128 {
        return Err("invalid rule name".to_string());
    }
    if pattern.trim().is_empty() || pattern.len() > MAX_RSS_RULE_BYTES {
        return Err("invalid rule pattern".to_string());
    }
    if feed_url.len() > MAX_USER_URL_BYTES {
        return Err("invalid rule feed url".to_string());
    }
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
    let form = form_pairs(request);
    let name = required(&form, "name")?.to_string();
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

fn handle_search_install_url(request: &HttpRequest) -> Result<(), String> {
    let form = form_pairs(request);
    let url = required(&form, "url")?.trim().to_string();
    if url.is_empty() {
        return Err("empty url".to_string());
    }
    let _ = crate::search::install_plugin_from_url(&url)?;
    Ok(())
}

fn handle_search_install_plugin(
    request: &HttpRequest,
    query: &[(String, String)],
) -> Result<(), String> {
    if request.body.is_empty() {
        return Err("empty plugin upload".to_string());
    }
    let filename = required(query, "filename")?.to_string();
    let _ = crate::search::install_plugin_from_bytes(&filename, &request.body)?;
    Ok(())
}

fn handle_search_remove_plugin(request: &HttpRequest) -> Result<(), String> {
    let form = form_pairs(request);
    let module = required(&form, "module")?.trim().to_string();
    if module.is_empty() {
        return Err("empty module".to_string());
    }
    crate::search::remove_plugin(&module)
}

fn handle_search_run(request: &HttpRequest) -> Result<(), String> {
    let form = form_pairs(request);
    let query = required(&form, "query")?.trim().to_string();
    let category = query_value(&form, "category").unwrap_or("all").to_string();
    let engines = query_value(&form, "engines")
        .unwrap_or("")
        .split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    crate::search::start_search(&query, &category, &engines)
}

fn handle_search_add_result(
    request: &HttpRequest,
    state: &Arc<Mutex<UiState>>,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<u64, String> {
    let form = form_pairs(request);
    let index = required(&form, "index")?
        .parse::<u64>()
        .map_err(|_| "invalid index".to_string())?;
    let download_dir = query_value(&form, "dir").unwrap_or("").to_string();
    let preallocate = query_value(&form, "prealloc")
        .map(parse_bool)
        .unwrap_or(false);

    let result = crate::search::resolve_result(index)?;
    let command_result = match result {
        crate::search::SearchDownload::Magnet(magnet) => {
            dispatch_command(cmd_tx, |reply| UiCommand::AddMagnet {
                magnet,
                download_dir,
                preallocate,
                options: AddOptions::default(),
                reply,
            })?
        }
        crate::search::SearchDownload::TorrentBytes(data) => {
            dispatch_command(cmd_tx, |reply| UiCommand::AddTorrent {
                data,
                download_dir,
                preallocate,
                options: AddOptions::default(),
                reply,
            })?
        }
    };
    let torrent_id = match command_result {
        UiCommandSuccess::TorrentAdded { torrent_id } => torrent_id,
        UiCommandSuccess::Ok => {
            return Err("ui command response missing torrent id".to_string());
        }
    };

    if let Ok(mut guard) = state.lock() {
        guard.last_added = "search result".to_string();
        guard.status = "queued".to_string();
    }
    Ok(torrent_id)
}

fn handle_rate_limits(
    request: &HttpRequest,
    state: &Arc<Mutex<UiState>>,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let form = form_pairs(request);
    let download_kbps = required(&form, "download_kbps")?
        .parse::<u64>()
        .map_err(|_| "invalid download_kbps".to_string())?;
    let upload_kbps = required(&form, "upload_kbps")?
        .parse::<u64>()
        .map_err(|_| "invalid upload_kbps".to_string())?;
    if download_kbps > MAX_RATE_LIMIT_KBPS || upload_kbps > MAX_RATE_LIMIT_KBPS {
        return Err(format!(
            "rate limit exceeds maximum of {MAX_RATE_LIMIT_KBPS} KiB/s"
        ));
    }
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
    let torrent_id = torrent_id(query)?;
    dispatch_command_ok(cmd_tx, |reply| UiCommand::RecheckTorrent {
        torrent_id,
        reply,
    })
}

fn handle_set_seed_ratio(
    request: &HttpRequest,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let form = form_pairs(request);
    let ratio = required(&form, "ratio")?
        .parse::<f64>()
        .map_err(|_| "invalid ratio".to_string())?;
    if !ratio.is_finite() || !(0.0..=10.0).contains(&ratio) {
        return Err("ratio must be finite and between 0 and 10".to_string());
    }
    dispatch_command_ok(cmd_tx, |reply| UiCommand::SetSeedRatio { ratio, reply })
}

fn handle_set_peer_profile(
    request: &HttpRequest,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let form = form_pairs(request);
    let profile = query_value(&form, "profile")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "missing profile".to_string())?
        .to_string();
    if !matches!(profile.as_str(), "conservative" | "balanced" | "aggressive") {
        return Err("invalid peer profile".to_string());
    }
    dispatch_command_ok(cmd_tx, |reply| UiCommand::SetPeerProfile { profile, reply })
}

fn handle_set_label(
    request: &HttpRequest,
    state: &Arc<Mutex<UiState>>,
    cmd_tx: &Option<mpsc::Sender<UiCommand>>,
) -> Result<(), String> {
    let form = form_pairs(request);
    let torrent_id = torrent_id(&form)?;
    let label = query_value(&form, "label").unwrap_or("").to_string();
    if label.len() > MAX_LABEL_BYTES || label.chars().any(char::is_control) {
        return Err("invalid label".to_string());
    }

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
    let form = form_pairs(request);
    let torrent_id = torrent_id(&form)?;
    let url = required(&form, "url")?.to_string();
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
    let form = form_pairs(request);
    let torrent_id = torrent_id(&form)?;
    let url = required(&form, "url")?.to_string();
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
    let torrent_id = torrent_id(query)?;
    enum TorrentActionKind {
        Pause,
        Resume,
        Stop,
        Archive,
        Delete { remove_data: bool },
    }
    let action = match path {
        "/torrent/pause" => TorrentActionKind::Pause,
        "/torrent/resume" => TorrentActionKind::Resume,
        "/torrent/stop" => TorrentActionKind::Stop,
        "/torrent/archive" => TorrentActionKind::Archive,
        "/torrent/delete" => TorrentActionKind::Delete {
            remove_data: query_value(query, "data").map(parse_bool).unwrap_or(false),
        },
        _ => return Err("unknown action".to_string()),
    };
    dispatch_command_ok(cmd_tx, |reply| match action {
        TorrentActionKind::Pause => UiCommand::PauseTorrent { torrent_id, reply },
        TorrentActionKind::Resume => UiCommand::ResumeTorrent { torrent_id, reply },
        TorrentActionKind::Stop => UiCommand::StopTorrent { torrent_id, reply },
        TorrentActionKind::Archive => UiCommand::ArchiveTorrent { torrent_id, reply },
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
    let torrent_id = torrent_id(query)?;
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

fn form_pairs(request: &HttpRequest) -> Vec<(String, String)> {
    parse_query_pairs(&String::from_utf8_lossy(&request.body))
}

fn required<'a>(pairs: &'a [(String, String)], key: &str) -> Result<&'a str, String> {
    query_value(pairs, key).ok_or_else(|| format!("missing {key}"))
}

fn torrent_id(pairs: &[(String, String)]) -> Result<u64, String> {
    query_value(pairs, "id")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "missing torrent id".to_string())
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
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        match bytes[idx] {
            b'%' if idx + 2 < bytes.len() => {
                let hi = bytes[idx + 1] as char;
                let lo = bytes[idx + 2] as char;
                if let (Some(hi), Some(lo)) = (hi.to_digit(16), lo.to_digit(16)) {
                    out.push((hi * 16 + lo) as u8);
                    idx += 3;
                    continue;
                }
            }
            b'+' => {
                out.push(b' ');
                idx += 1;
                continue;
            }
            _ => {}
        }
        out.push(bytes[idx]);
        idx += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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

fn authority_host(authority: &str) -> Option<&str> {
    let authority = authority.trim();
    if authority.is_empty() || authority.contains(['/', '\\', '@', '?', '#']) {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if !tail.is_empty()
            && (!tail.starts_with(':')
                || tail[1..].is_empty()
                || tail[1..]
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port > 0)
                    .is_none())
        {
            return None;
        }
        return (!host.is_empty()).then_some(host);
    }
    if authority.contains(['[', ']']) || authority.matches(':').count() > 1 {
        return None;
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => (!host.is_empty()
            && port.parse::<u16>().ok().filter(|port| *port > 0).is_some())
        .then_some(host),
        None => Some(authority),
    }
}

fn request_has_safe_host(request: &HttpRequest) -> bool {
    let Some(host) = request.header_value("host").and_then(authority_host) else {
        // HTTP/1.0 clients may omit Host, but the browser UI and API require it
        // so accepting a hostless request provides no useful compatibility.
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| !ip.is_unspecified())
            .unwrap_or(false)
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
        .map(|value| constant_time_eq(value.as_bytes(), api_token().as_bytes()))
        .unwrap_or(false)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn authorize_mutating_request(request: &HttpRequest) -> Result<(), String> {
    if !has_valid_api_token(request) {
        return Err("missing or invalid api token".to_string());
    }
    if request.header_value("origin").is_none() {
        return Err("origin header required".to_string());
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
        429 => "Too Many Requests",
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
        || lower.contains("forbidden host")
        || lower.contains("origin header required")
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
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n{SECURITY_HEADERS}Content-Length: {}\r\nConnection: close\r\n\r\n",
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

fn check_api_token_rate(ip: IpAddr) -> bool {
    let lock = API_TOKEN_RATE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let now = Instant::now();
    map.retain(|_, (_, ts)| now.duration_since(*ts) < API_TOKEN_RATE_WINDOW);
    let entry = map.entry(ip).or_insert((0, now));
    entry.0 += 1;
    entry.0 <= API_TOKEN_RATE_MAX
}

fn send_head(mut stream: TcpStream, content_type: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: no-store, no-cache, must-revalidate\r\nPragma: no-cache\r\nExpires: 0\r\n{SECURITY_HEADERS}Connection: close\r\nContent-Length: 0\r\n\r\n"
    );
    stream.write_all(response.as_bytes())
}

fn send_api_token(stream: TcpStream) -> std::io::Result<()> {
    let body = api_token_json(api_token(), ui_owner_secret());
    send_json_body(stream, 200, &body)
}

fn api_token_json(token: &str, owner_secret: &str) -> String {
    format!(
        r#"{{"token":"{}","owner_secret":"{}"}}"#,
        escape_json(token),
        escape_json(owner_secret)
    )
}

const SSE_INTERVAL: Duration = Duration::from_millis(450);

/// Streams `status` events whose JSON payload is a delta against the previous
/// event: `g` holds session fields, `t` the torrents that changed (without file
/// lists) and `ids` the library order whenever it changes. The first event of a
/// connection carries all three.
fn handle_sse(mut stream: TcpStream, state: Arc<Mutex<UiState>>) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n{SECURITY_HEADERS}Connection: keep-alive\r\n\r\nretry: 1500\n\n"
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;

    let mut snapshot = SseSnapshot::default();
    let mut last_write = Instant::now();
    loop {
        let delta = sse_delta(&lock_state(&state), &mut snapshot);
        if let Some(payload) = delta {
            write_sse_event(&mut stream, "status", &payload)?;
            last_write = Instant::now();
        } else if last_write.elapsed() > Duration::from_secs(15) {
            write_sse_comment(&mut stream, "ping")?;
            last_write = Instant::now();
        }
        thread::sleep(SSE_INTERVAL);
    }
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

#[derive(Default)]
struct SseSnapshot {
    session: String,
    torrents: HashMap<u64, String>,
    ids: Option<Vec<u64>>,
}

fn sse_delta(state: &UiState, previous: &mut SseSnapshot) -> Option<String> {
    let mut session = String::new();
    let mut fields = JsonObject::new(&mut session);
    push_session_fields(&mut fields, state);
    fields.finish();

    let ids: Vec<u64> = state.torrents.iter().map(|torrent| torrent.id).collect();
    let mut torrents = HashMap::with_capacity(ids.len());
    let mut changed = String::new();
    for torrent in &state.torrents {
        let mut json = String::new();
        push_torrent_json(&mut json, torrent, false);
        if previous.torrents.get(&torrent.id) != Some(&json) {
            changed.push(if changed.is_empty() { '[' } else { ',' });
            changed.push_str(&json);
        }
        torrents.insert(torrent.id, json);
    }

    let mut payload = String::new();
    let mut delta = JsonObject::new(&mut payload);
    if previous.session != session {
        delta.key("g").push_str(&session);
    }
    if !changed.is_empty() {
        changed.push(']');
        delta.key("t").push_str(&changed);
    }
    if previous.ids.as_ref() != Some(&ids) {
        let out = delta.key("ids");
        out.push('[');
        for (index, id) in ids.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            let _ = write!(out, "{id}");
        }
        out.push(']');
    }
    let unchanged = delta.empty;
    delta.finish();
    previous.session = session;
    previous.torrents = torrents;
    previous.ids = Some(ids);
    (!unchanged).then_some(payload)
}

/// Runs before first paint so the saved or system appearance applies without a
/// flash. Its SHA-256 is allowed by `script-src` in `SECURITY_HEADERS`; a unit
/// test keeps the two in sync.
const THEME_BOOTSTRAP: &str = "try{var t=localStorage.getItem('rustorrent-theme');if(t!=='light'&&t!=='dark')t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';document.documentElement.dataset.theme=t}catch(e){}";

/// The page is a small shell; `app.js` renders everything from `/events`.
fn shell_html() -> String {
    format!(
        concat!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
            "<meta name=\"rustorrent-api-token\" content=\"{token}\">",
            "<title>Rustorrent</title>",
            "<link rel=\"icon\" href=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='8 6 112 112'>",
            "<linearGradient id='g' x2='1' y2='1'><stop stop-color='%23ff8a4c'/>",
            "<stop offset='1' stop-color='%23c2410c'/></linearGradient>",
            "<rect x='8' y='6' width='112' height='112' rx='28' fill='url(%23g)'/>",
            "<g fill='%23fff' stroke='%23fff' opacity='.25'>",
            "<rect x='59' y='15' width='10' height='13' rx='3'/>",
            "<rect x='59' y='15' width='10' height='13' rx='3' transform='rotate(36 64 62)'/>",
            "<rect x='59' y='15' width='10' height='13' rx='3' transform='rotate(72 64 62)'/>",
            "<rect x='59' y='15' width='10' height='13' rx='3' transform='rotate(108 64 62)'/>",
            "<rect x='59' y='15' width='10' height='13' rx='3' transform='rotate(144 64 62)'/>",
            "<rect x='59' y='15' width='10' height='13' rx='3' transform='rotate(180 64 62)'/>",
            "<rect x='59' y='15' width='10' height='13' rx='3' transform='rotate(216 64 62)'/>",
            "<rect x='59' y='15' width='10' height='13' rx='3' transform='rotate(252 64 62)'/>",
            "<rect x='59' y='15' width='10' height='13' rx='3' transform='rotate(288 64 62)'/>",
            "<rect x='59' y='15' width='10' height='13' rx='3' transform='rotate(324 64 62)'/>",
            "<circle cx='64' cy='62' r='38' fill='none' stroke-width='6'/></g>",
            "<path d='M54.5 37v45M46.5 74l8 8 8-8M54.5 37h13a12 12 0 0 1 0 24h-13M68.5 61l13 21' fill='none' stroke='%23fff' stroke-width='10' stroke-linecap='round' stroke-linejoin='round'/>",
            "</svg>\">",
            "<script>{boot}</script><link rel=\"stylesheet\" href=\"/app.css\">",
            "<script src=\"/app.js\" defer></script></head>",
            "<body><div id=\"app\"></div><noscript>Rustorrent needs JavaScript.</noscript></body></html>"
        ),
        token = api_token(),
        boot = THEME_BOOTSTRAP
    )
}

/// Embedded UI assets as `(path, content type, gzip body)`. build.rs
/// compresses them; every browser accepts gzip, so they are always sent
/// compressed.
const UI_ASSETS: [(&str, &str, &[u8]); 2] = [
    (
        "/app.css",
        "text/css; charset=utf-8",
        include_bytes!(concat!(env!("OUT_DIR"), "/app.css.gz")),
    ),
    (
        "/app.js",
        "text/javascript; charset=utf-8",
        include_bytes!(concat!(env!("OUT_DIR"), "/app.js.gz")),
    ),
];

/// Strong validator derived at build time from the compressed assets.
const UI_ASSET_ETAG: &str = concat!("\"", env!("UI_ASSET_TAG"), "\"");

fn etag_matches(if_none_match: Option<&str>, etag: &str) -> bool {
    if_none_match.is_some_and(|value| {
        value
            .split(',')
            .map(str::trim)
            .any(|tag| tag == "*" || tag.strip_prefix("W/").unwrap_or(tag) == etag)
    })
}

/// Serves an embedded asset. Browsers revalidate on every load (`no-cache`)
/// and receive `304 Not Modified` while the strong ETag still matches.
fn send_asset(mut stream: TcpStream, request: &HttpRequest, index: usize) -> std::io::Result<()> {
    let (_, content_type, body) = UI_ASSETS[index];
    let etag = UI_ASSET_ETAG;
    let fresh = etag_matches(request.header_value("if-none-match"), etag);
    let (status, length) = if fresh {
        ("304 Not Modified", String::new())
    } else {
        ("200 OK", format!("Content-Length: {}\r\n", body.len()))
    };
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Encoding: gzip\r\nCache-Control: no-cache\r\nETag: {etag}\r\n{SECURITY_HEADERS}{length}Connection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes())?;
    if !fresh && request.method == "GET" {
        stream.write_all(body)?;
    }
    Ok(())
}

/// Minimal JSON object writer that appends straight into a `String`.
struct JsonObject<'a> {
    out: &'a mut String,
    empty: bool,
}

impl<'a> JsonObject<'a> {
    fn new(out: &'a mut String) -> Self {
        out.push('{');
        Self { out, empty: true }
    }

    /// Writes `"key":` and returns the buffer for the value.
    fn key(&mut self, key: &str) -> &mut String {
        if !self.empty {
            self.out.push(',');
        }
        self.empty = false;
        self.out.push('"');
        self.out.push_str(key);
        self.out.push_str("\":");
        self.out
    }

    fn num(&mut self, key: &str, value: impl std::fmt::Display) -> &mut Self {
        let _ = write!(self.key(key), "{value}");
        self
    }

    fn float(&mut self, key: &str, value: f64, decimals: usize) -> &mut Self {
        push_float(self.key(key), value, decimals);
        self
    }

    fn str(&mut self, key: &str, value: &str) -> &mut Self {
        push_json_string(self.key(key), value);
        self
    }

    fn finish(self) {
        self.out.push('}');
    }
}

fn push_float(out: &mut String, value: f64, decimals: usize) {
    if value.is_finite() {
        let _ = write!(out, "{value:.decimals$}");
    } else {
        out.push('0');
    }
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    escape_json_into(out, value);
    out.push('"');
}

fn push_session_fields(json: &mut JsonObject<'_>, state: &UiState) {
    json.str("version", env!("CARGO_PKG_VERSION"))
        .str("download_dir", &state.download_dir)
        .num("preallocate", state.preallocate)
        .float("download_rate_bps", state.download_rate_bps, 0)
        .float("upload_rate_bps", state.upload_rate_bps, 0)
        .num("session_downloaded_bytes", state.session_downloaded_bytes)
        .num("session_uploaded_bytes", state.session_uploaded_bytes)
        .num("global_download_limit_bps", state.global_download_limit_bps)
        .num("global_upload_limit_bps", state.global_upload_limit_bps)
        .float("seed_ratio", state.seed_ratio, 2)
        .str("peer_profile", &state.peer_profile)
        .num("peer_profile_global_limit", state.peer_profile_global_limit)
        .num(
            "peer_profile_torrent_limit",
            state.peer_profile_torrent_limit,
        )
        .num("peer_profile_numwant", state.peer_profile_numwant)
        .num("incoming_port", state.incoming_port)
        .str("natpmp_status", &state.natpmp_status)
        .str("upnp_status", &state.upnp_status)
        .str("upstream_status", &state.upstream_status)
        .str("router_external_ip", &state.router_external_ip)
        .str("tracker_external_ip", &state.tracker_external_ip)
        .num("inbound_public_peers", state.inbound_public_peers)
        .str("firewall_status", &state.firewall_status)
        .num("peer_connected", state.peer_connected)
        .num("peer_disconnected", state.peer_disconnected)
        .float("disk_read_ms_avg", state.disk_read_ms_avg, 3)
        .float("disk_write_ms_avg", state.disk_write_ms_avg, 3)
        .str("proxy_label", &state.proxy_label);
    for (key, values) in [
        ("download_history_bps", &state.download_history_bps),
        ("upload_history_bps", &state.upload_history_bps),
    ] {
        let out = json.key(key);
        out.push('[');
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            push_float(out, *value, 0);
        }
        out.push(']');
    }
}

/// Cheap fingerprint of a torrent's file list so the UI can tell when to
/// refetch `/torrent/files` without the stream carrying every file.
fn files_rev(files: &[UiFile]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    let mut mix = |bytes: &[u8]| {
        for byte in bytes {
            hash = (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193);
        }
    };
    for file in files {
        mix(file.path.as_bytes());
        mix(&file.completed.to_le_bytes());
        mix(&[file.priority]);
    }
    hash
}

fn push_files_json(out: &mut String, files: &[UiFile]) {
    out.push('[');
    for (index, file) in files.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let mut json = JsonObject::new(out);
        json.str("path", &file.path)
            .num("length", file.length)
            .num("completed", file.completed)
            .num("percent", percent(file.completed, file.length))
            .num("priority", file.priority);
        json.finish();
    }
    out.push(']');
}

fn push_torrent_json(out: &mut String, torrent: &UiTorrent, with_files: bool) {
    let mut json = JsonObject::new(out);
    json.num("id", torrent.id)
        .str("name", &torrent.name)
        .str("info_hash", &torrent.info_hash)
        .str("download_dir", &torrent.download_dir)
        .num("preallocate", torrent.preallocate)
        .str("status", &torrent.status)
        .num("total_bytes", torrent.total_bytes)
        .num("completed_bytes", torrent.completed_bytes)
        .num("downloaded_bytes", torrent.downloaded_bytes)
        .num("uploaded_bytes", torrent.uploaded_bytes)
        .float(
            "ratio",
            ratio_value(torrent.uploaded_bytes, torrent.downloaded_bytes),
            3,
        )
        .num("total_pieces", torrent.total_pieces)
        .num("completed_pieces", torrent.completed_pieces)
        .num(
            "percent",
            percent(torrent.completed_bytes, torrent.total_bytes),
        )
        .float("download_rate_bps", torrent.download_rate_bps, 0)
        .float("upload_rate_bps", torrent.upload_rate_bps, 0)
        .num("eta_secs", torrent.eta_secs)
        .num("tracker_peers", torrent.tracker_peers)
        .num("active_peers", torrent.active_peers)
        .num("interested_peers", torrent.interested_peers)
        .num("upload_requests_served", torrent.upload_requests_served)
        .num("paused", torrent.paused)
        .str("last_error", &torrent.last_error)
        .str("label", &torrent.label)
        .num("meta_version", torrent.meta_version)
        .num("file_count", torrent.files.len())
        .num("files_rev", files_rev(&torrent.files));
    let trackers = json.key("trackers");
    trackers.push('[');
    for (index, tracker) in torrent.trackers.iter().enumerate() {
        if index > 0 {
            trackers.push(',');
        }
        push_json_string(trackers, tracker);
    }
    trackers.push(']');
    let countries = json.key("peer_countries");
    countries.push('[');
    for (index, (code, count)) in torrent.peer_country_counts.iter().enumerate() {
        if index > 0 {
            countries.push(',');
        }
        let mut country = JsonObject::new(countries);
        country
            .str("code", code)
            .num("count", count)
            .str("flag", &crate::geoip::country_flag(code));
        country.finish();
    }
    countries.push(']');
    if with_files {
        push_files_json(json.key("files"), &torrent.files);
    }
    json.finish();
}

fn torrent_files_json(torrent: &UiTorrent) -> String {
    let mut out = String::new();
    let mut json = JsonObject::new(&mut out);
    json.num("id", torrent.id)
        .num("files_rev", files_rev(&torrent.files));
    push_files_json(json.key("files"), &torrent.files);
    json.finish();
    out
}

/// Full status for API clients: session fields, the legacy "current torrent"
/// fields, and every torrent including its files.
fn status_json(state: &UiState) -> String {
    let mut out = String::with_capacity(1024 + state.torrents.len() * 1024);
    let mut json = JsonObject::new(&mut out);
    push_session_fields(&mut json, state);
    json.str("name", &state.name)
        .str("info_hash", &state.info_hash)
        .str("status", &state.status)
        .str("last_error", &state.last_error)
        .num("total_pieces", state.total_pieces)
        .num("completed_pieces", state.completed_pieces)
        .num("total_bytes", state.total_bytes)
        .num("completed_bytes", state.completed_bytes)
        .num("downloaded_bytes", state.downloaded_bytes)
        .num("uploaded_bytes", state.uploaded_bytes)
        .float(
            "ratio",
            ratio_value(state.uploaded_bytes, state.downloaded_bytes),
            3,
        )
        .num("percent", percent(state.completed_bytes, state.total_bytes))
        .num("tracker_peers", state.tracker_peers)
        .num("active_peers", state.active_peers)
        .num("interested_peers", state.interested_peers)
        .num("upload_requests_served", state.upload_requests_served)
        .num("paused", state.paused)
        .num("eta_secs", state.eta_secs)
        .num("queue_len", state.queue_len)
        .str("last_added", &state.last_added);
    match state.current_id {
        Some(id) => json.num("current_id", id),
        None => json.num("current_id", "null"),
    };
    push_files_json(json.key("files"), &state.files);
    let torrents = json.key("torrents");
    torrents.push('[');
    for (index, torrent) in state.torrents.iter().enumerate() {
        if index > 0 {
            torrents.push(',');
        }
        push_torrent_json(torrents, torrent, true);
    }
    torrents.push(']');
    json.finish();
    out
}

fn percent(done: u64, total: u64) -> u64 {
    done.saturating_mul(10_000).checked_div(total).unwrap_or(0)
}

fn ratio_value(uploaded: u64, downloaded: u64) -> f64 {
    if downloaded == 0 {
        0.0
    } else {
        uploaded as f64 / downloaded as f64
    }
}

fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    escape_json_into(&mut out, input);
    out
}

fn escape_json_into(out: &mut String, input: &str) {
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            _ => out.push(ch),
        }
    }
}
#[cfg(test)]
mod tests {

    #[test]
    fn peers_are_listed_busiest_first_and_removed_on_disconnect() {
        let torrent = 987_654;
        let peer = |addr: &str, down: f64| UiPeer {
            addr: addr.to_string(),
            client: "qBittorrent 4.6.5".to_string(),
            download_bps: down,
            progress: 1.0,
            ..UiPeer::default()
        };
        set_peer(torrent, 1, peer("1.1.1.1:1", 10.0));
        set_peer(torrent, 2, peer("2.2.2.2:2", 500.0));
        let json = torrent_peers_json(torrent);
        assert!(json.find("2.2.2.2:2").unwrap() < json.find("1.1.1.1:1").unwrap());
        assert!(json.contains("\"client\":\"qBittorrent 4.6.5\""));
        assert!(json.contains("\"progress\":1.0000"));
        remove_peer(torrent, 1);
        remove_peer(torrent, 2);
        assert_eq!(
            torrent_peers_json(torrent),
            format!("{{\"id\":{torrent},\"peers\":[]}}")
        );
    }
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;

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
    fn status_json_exposes_seed_upload_diagnostics() {
        let mut state = UiState {
            incoming_port: 6881,
            natpmp_status: "mapped".to_string(),
            upnp_status: "failed: no gateway".to_string(),
            interested_peers: 2,
            upload_requests_served: 7,
            ..Default::default()
        };
        state.torrents.push(UiTorrent {
            id: 1,
            interested_peers: 1,
            upload_requests_served: 3,
            ..Default::default()
        });

        let json = status_json(&state);

        assert!(json.contains("\"incoming_port\":6881"));
        assert!(json.contains("\"natpmp_status\":\"mapped\""));
        assert!(json.contains("\"upnp_status\":\"failed: no gateway\""));
        assert!(json.contains("\"interested_peers\":2"));
        assert!(json.contains("\"upload_requests_served\":7"));
        assert!(json.contains("\"interested_peers\":1"));
        assert!(json.contains("\"upload_requests_served\":3"));
    }

    #[test]
    fn status_for_error_maps_common_cases() {
        assert_eq!(status_for_error("unknown torrent"), 404);
        assert_eq!(status_for_error("torrent already added"), 409);
        assert_eq!(status_for_error("invalid priority"), 400);
        assert_eq!(status_for_error("ui command timeout"), 504);
    }

    #[test]
    fn api_token_json_exposes_the_launcher_owner_secret() {
        let owner_secret = "a1".repeat(32);
        let json = api_token_json("0123456789abcdef0123456789abcdef", &owner_secret);

        assert_eq!(
            json,
            format!(
                "{{\"token\":\"0123456789abcdef0123456789abcdef\",\"owner_secret\":\"{owner_secret}\"}}"
            )
        );
    }

    #[test]
    fn launcher_owner_secret_requires_256_bit_hex() {
        assert!(valid_ui_owner_secret(&"ab".repeat(32)));
        assert!(valid_ui_owner_secret(&"AB".repeat(32)));
        assert!(!valid_ui_owner_secret(&"ab".repeat(31)));
        assert!(!valid_ui_owner_secret(&"ag".repeat(32)));
    }

    #[test]
    fn dns_rebinding_host_cannot_read_api_token() {
        let request = b"GET /api-token HTTP/1.1\r\nHost: attacker.example:8080\r\n\r\n";
        let response = run_single_request(request, None);
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("forbidden host"));
        assert!(!response.contains(api_token()));
    }

    #[test]
    fn dns_rebinding_host_cannot_mutate_with_a_stolen_token() {
        let request = format!(
            "POST /torrent/pause?id=1 HTTP/1.1\r\nHost: attacker.example:8080\r\nOrigin: http://attacker.example:8080\r\nX-Rustorrent-Token: {}\r\nContent-Length: 0\r\n\r\n",
            api_token()
        );
        let response = run_single_request(request.as_bytes(), None);
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("forbidden host"));
    }

    #[test]
    fn safe_host_validation_accepts_ip_literals_and_localhost_only() {
        for host in [
            "127.0.0.1:8080",
            "[::1]:8080",
            "192.168.1.4",
            "localhost:8080",
        ] {
            let request = HttpRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![("host".to_string(), host.to_string())],
                body: Vec::new(),
            };
            assert!(request_has_safe_host(&request), "host rejected: {host}");
        }
        for host in [
            "attacker.example:8080",
            "0.0.0.0:8080",
            "[::]:8080",
            "user@127.0.0.1",
        ] {
            let request = HttpRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                headers: vec![("host".to_string(), host.to_string())],
                body: Vec::new(),
            };
            assert!(
                !request_has_safe_host(&request),
                "unsafe host accepted: {host}"
            );
        }
    }

    #[test]
    fn post_without_token_is_forbidden() {
        let request = b"POST /torrent/pause?id=1 HTTP/1.1\r\nHost: 127.0.0.1:19001\r\nContent-Length: 0\r\n\r\n";
        let response = run_single_request(request, None);
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("missing or invalid api token"));
    }

    #[test]
    fn unauthorized_post_is_rejected_before_its_declared_body_is_read() {
        let state = Arc::new(Mutex::new(UiState::default()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_state = Arc::clone(&state);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, server_state, None).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let request = format!(
            "POST /add-torrent HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Length: {MAX_REQUEST_BODY_BYTES}\r\n\r\n",
            addr.port()
        );
        client.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        server.join().unwrap();

        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("missing or invalid api token"));
    }

    #[test]
    fn endpoint_body_limit_is_checked_before_waiting_for_the_body() {
        let state = Arc::new(Mutex::new(UiState::default()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_state = Arc::clone(&state);
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_connection(stream, server_state, None).unwrap();
        });

        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let host = format!("127.0.0.1:{}", addr.port());
        let request = format!(
            "POST /add-magnet HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nX-Rustorrent-Token: {}\r\nContent-Length: {}\r\n\r\n",
            api_token(),
            MAX_FORM_BODY_BYTES + 1
        );
        client.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        server.join().unwrap();

        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
        assert!(response.contains("bad request"));
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
    fn post_with_valid_token_but_missing_origin_is_forbidden() {
        let request = format!(
            "POST /torrent/pause?id=1 HTTP/1.1\r\nHost: 127.0.0.1:19002\r\nX-Rustorrent-Token: {}\r\nContent-Length: 0\r\n\r\n",
            api_token()
        );
        let response = run_single_request(request.as_bytes(), None);
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(response.contains("origin header required"));
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
    fn add_torrent_accepts_chunked_upload_body() {
        let (cmd_tx, cmd_rx) = mpsc::channel::<UiCommand>();
        let (captured_tx, captured_rx) = mpsc::channel::<Vec<u8>>();
        let command_thread = thread::spawn(move || {
            let cmd = cmd_rx.recv().expect("receive add command");
            match cmd {
                UiCommand::AddTorrent { data, reply, .. } => {
                    captured_tx.send(data).expect("send captured body");
                    let _ = reply.send(Ok(UiCommandSuccess::TorrentAdded { torrent_id: 88 }));
                }
                _ => panic!("expected add torrent command"),
            }
        });

        let host = "127.0.0.1:19014";
        let request = format!(
            "POST /add-torrent?dir=%2Ftmp&prealloc=0 HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nX-Rustorrent-Token: {}\r\nContent-Type: application/x-bittorrent\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n",
            api_token(),
        );

        let response = run_single_request(request.as_bytes(), Some(cmd_tx));
        command_thread.join().expect("join command thread");
        let captured = captured_rx.recv().expect("receive captured body");
        assert_eq!(captured, b"test");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"ok\":true"));
        assert!(response.contains("\"torrent_id\":88"));
    }

    #[test]
    fn chunk_header_limit_applies_when_the_terminator_arrives_later() {
        let host = "127.0.0.1:19015";
        let mut request = format!(
            "POST /add-torrent HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nX-Rustorrent-Token: {}\r\nTransfer-Encoding: chunked\r\n\r\n0;",
            api_token()
        )
        .into_bytes();
        request.extend(std::iter::repeat_n(b'a', MAX_CHUNK_LINE_BYTES + 1));
        request.extend_from_slice(b"\r\n\r\n");

        let response = run_single_request(&request, None);
        assert!(response.starts_with("HTTP/1.1 400 Bad Request"));
    }

    #[test]
    fn archive_action_dispatches_archive_command() {
        let (cmd_tx, cmd_rx) = mpsc::channel::<UiCommand>();
        let command_thread = thread::spawn(move || {
            let cmd = cmd_rx.recv().expect("receive archive command");
            match cmd {
                UiCommand::ArchiveTorrent { torrent_id, reply } => {
                    assert_eq!(torrent_id, 7);
                    let _ = reply.send(Ok(UiCommandSuccess::Ok));
                }
                _ => panic!("expected archive torrent command"),
            }
        });

        let host = "127.0.0.1:19005";
        let request = format!(
            "POST /torrent/archive?id=7 HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nX-Rustorrent-Token: {}\r\nContent-Length: 0\r\n\r\n",
            api_token()
        );
        let response = run_single_request(request.as_bytes(), Some(cmd_tx));
        command_thread.join().expect("join archive command thread");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"ok\":true"));
    }

    #[test]
    fn peer_profile_setting_dispatches_command() {
        let (cmd_tx, cmd_rx) = mpsc::channel::<UiCommand>();
        let command_thread = thread::spawn(move || {
            let cmd = cmd_rx.recv().expect("receive peer profile command");
            match cmd {
                UiCommand::SetPeerProfile { profile, reply } => {
                    assert_eq!(profile, "aggressive");
                    let _ = reply.send(Ok(UiCommandSuccess::Ok));
                }
                _ => panic!("expected set peer profile command"),
            }
        });

        let host = "127.0.0.1:19006";
        let body = "profile=aggressive";
        let request = format!(
            "POST /settings/peer-profile HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\nX-Rustorrent-Token: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
            api_token(),
            body.len(),
            body
        );
        let response = run_single_request(request.as_bytes(), Some(cmd_tx));
        command_thread.join().expect("join peer profile command");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"ok\":true"));
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
    fn percent_decode_preserves_utf8_paths_and_names() {
        assert_eq!(percent_decode("Espa%C3%B1a+%F0%9F%9A%80"), "España 🚀");
        assert_eq!(percent_decode("café"), "café");
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

    fn run_request_with_state(request_bytes: &[u8], state: UiState) -> String {
        let state = Arc::new(Mutex::new(state));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept connection");
            handle_connection(stream, state, None).expect("handle request");
        });
        let mut client = TcpStream::connect(addr).expect("connect test listener");
        client.write_all(request_bytes).expect("write request");
        client.shutdown(Shutdown::Write).expect("shutdown write");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");
        server.join().expect("join server");
        String::from_utf8_lossy(&response).into_owned()
    }

    fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
        let head = response.split("\r\n\r\n").next()?;
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn body(response: &str) -> &str {
        response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
    }

    fn base64(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for (index, shift) in [18, 12, 6, 0].into_iter().enumerate() {
                if index <= chunk.len() {
                    out.push(TABLE[((n >> shift) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn sample_torrent(id: u64, name: &str) -> UiTorrent {
        UiTorrent {
            id,
            name: name.to_string(),
            info_hash: format!("{id:040x}"),
            status: "downloading".to_string(),
            total_bytes: 2048,
            completed_bytes: 1024,
            files: vec![UiFile {
                path: format!("{name}/a.bin"),
                length: 2048,
                completed: 1024,
                priority: 2,
            }],
            trackers: vec!["udp://tracker.example:1337/announce".to_string()],
            peer_country_counts: vec![("US".to_string(), 3)],
            ..UiTorrent::default()
        }
    }

    #[test]
    fn json_escaping_is_stable() {
        assert_eq!(escape_json("a\"b\\\n"), "a\\\"b\\\\\\n");
        assert_eq!(escape_json("\u{1}\u{2028}"), "\\u0001\\u2028");
        let mut out = String::new();
        push_float(&mut out, f64::NAN, 2);
        assert_eq!(out, "0");
    }

    #[test]
    fn shell_is_small_and_loads_external_assets() {
        let html = shell_html();
        assert!(html.len() < 2048, "shell grew to {} bytes", html.len());
        assert!(html.contains(&format!(
            "<meta name=\"rustorrent-api-token\" content=\"{}\">",
            api_token()
        )));
        assert!(html.contains("<link rel=\"stylesheet\" href=\"/app.css\">"));
        assert!(html.contains("<script src=\"/app.js\" defer></script>"));
        assert!(html.contains("<div id=\"app\"></div>"));
        assert!(html.contains(&format!("<script>{THEME_BOOTSTRAP}</script>")));
        assert!(!html.contains("<style"));
    }

    #[test]
    fn content_security_policy_allows_only_the_theme_bootstrap_inline() {
        let hash = base64(&crate::sha256::sha256(THEME_BOOTSTRAP.as_bytes()));
        let policy = SECURITY_HEADERS
            .lines()
            .find(|line| line.starts_with("Content-Security-Policy:"))
            .expect("csp header");
        assert!(
            policy.contains(&format!("script-src 'self' 'sha256-{hash}'")),
            "update the script-src hash to 'sha256-{hash}'"
        );
        assert!(!policy.contains("unsafe-inline"));
    }

    #[test]
    fn root_serves_the_shell_without_caching() {
        let response = run_single_request(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:9473\r\n\r\n", None);
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(
            header(&response, "content-type"),
            Some("text/html; charset=utf-8")
        );
        assert!(header(&response, "cache-control")
            .unwrap_or("")
            .contains("no-store"));
        assert_eq!(body(&response), shell_html());
    }

    #[test]
    fn assets_are_served_with_strong_etags_and_revalidate() {
        for (path, content_type, asset) in UI_ASSETS {
            let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:9473\r\n\r\n");
            let response = run_single_request(request.as_bytes(), None);
            assert!(response.starts_with("HTTP/1.1 200 OK"), "{path}");
            assert_eq!(header(&response, "content-type"), Some(content_type));
            assert_eq!(header(&response, "cache-control"), Some("no-cache"));
            assert_eq!(header(&response, "x-content-type-options"), Some("nosniff"));
            assert_eq!(header(&response, "content-encoding"), Some("gzip"));
            let etag = header(&response, "etag").expect("etag").to_string();
            assert_eq!(etag, UI_ASSET_ETAG);
            assert!(etag.starts_with('"') && etag.len() == 10);
            let length = asset.len().to_string();
            assert_eq!(header(&response, "content-length"), Some(length.as_str()));
            assert_eq!(&asset[..3], &[0x1f, 0x8b, 8]);

            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:9473\r\nIf-None-Match: \"stale\", {etag}\r\n\r\n"
            );
            let response = run_single_request(request.as_bytes(), None);
            assert!(response.starts_with("HTTP/1.1 304 Not Modified"), "{path}");
            assert_eq!(header(&response, "etag"), Some(etag.as_str()));
            assert_eq!(header(&response, "content-length"), None);
            assert!(body(&response).is_empty());

            let request = format!(
                "HEAD {path} HTTP/1.1\r\nHost: 127.0.0.1:9473\r\nIf-None-Match: \"stale\"\r\n\r\n"
            );
            let response = run_single_request(request.as_bytes(), None);
            assert!(response.starts_with("HTTP/1.1 200 OK"));
            let length = asset.len().to_string();
            assert_eq!(header(&response, "content-length"), Some(length.as_str()));
            assert!(body(&response).is_empty());
        }
    }

    #[test]
    fn etag_matching_accepts_lists_weak_tags_and_wildcards() {
        assert!(etag_matches(Some("\"a\""), "\"a\""));
        assert!(etag_matches(Some("W/\"a\""), "\"a\""));
        assert!(etag_matches(Some("\"b\" , \"a\""), "\"a\""));
        assert!(etag_matches(Some("*"), "\"a\""));
        assert!(!etag_matches(Some("\"b\""), "\"a\""));
        assert!(!etag_matches(None, "\"a\""));
    }

    #[test]
    fn asset_requests_still_require_a_safe_host() {
        let response = run_single_request(
            b"GET /app.js HTTP/1.1\r\nHost: attacker.example\r\n\r\n",
            None,
        );
        assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    }

    #[test]
    fn sse_delta_sends_a_snapshot_then_only_changes() {
        let mut state = UiState {
            download_dir: "/downloads".to_string(),
            ..UiState::default()
        };
        state.torrents.push(sample_torrent(1, "alpha"));
        state.torrents.push(sample_torrent(2, "beta"));
        let mut snapshot = SseSnapshot::default();

        let first = sse_delta(&state, &mut snapshot).expect("initial snapshot");
        assert!(first.starts_with("{\"g\":{\"version\":"));
        assert!(first.contains("\"download_dir\":\"/downloads\""));
        assert!(first.contains("\"name\":\"alpha\"") && first.contains("\"name\":\"beta\""));
        assert!(first.ends_with(",\"ids\":[1,2]}"));
        assert!(!first.contains("\"files\""), "stream omits file lists");
        assert!(first.contains("\"file_count\":1"));
        assert!(first.contains("\"flag\":\"\u{1F1FA}\u{1F1F8}\""));
        assert_eq!(sse_delta(&state, &mut snapshot), None);

        state.torrents[1].download_rate_bps = 2048.4;
        let second = sse_delta(&state, &mut snapshot).expect("torrent change");
        assert!(second.starts_with("{\"t\":[{\"id\":2,"));
        assert!(second.contains("\"download_rate_bps\":2048"));
        assert!(!second.contains("\"g\"") && !second.contains("\"ids\""));

        state.upload_rate_bps = 10.0;
        state.torrents.remove(0);
        let third = sse_delta(&state, &mut snapshot).expect("session and order change");
        assert!(third.starts_with("{\"g\":{"));
        assert!(third.ends_with("\"ids\":[2]}"));
        assert!(!third.contains("\"t\""));
    }

    #[test]
    fn files_revision_tracks_progress_priority_and_names() {
        let mut torrent = sample_torrent(1, "alpha");
        let original = files_rev(&torrent.files);
        torrent.files[0].completed += 1;
        let progressed = files_rev(&torrent.files);
        assert_ne!(original, progressed);
        torrent.files[0].priority = 3;
        let prioritized = files_rev(&torrent.files);
        assert_ne!(progressed, prioritized);
        torrent.files[0].path = "alpha/b.bin".to_string();
        assert_ne!(prioritized, files_rev(&torrent.files));
    }

    #[test]
    fn torrent_files_endpoint_returns_one_torrents_files() {
        let mut state = UiState::default();
        state.torrents.push(sample_torrent(7, "gamma \"quoted\""));
        let rev = files_rev(&state.torrents[0].files);
        let response = run_request_with_state(
            b"GET /torrent/files?id=7 HTTP/1.1\r\nHost: localhost\r\n\r\n",
            state.clone(),
        );
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert_eq!(
            body(&response),
            format!(
                "{{\"id\":7,\"files_rev\":{rev},\"files\":[{{\"path\":\"gamma \\\"quoted\\\"/a.bin\",\"length\":2048,\"completed\":1024,\"percent\":5000,\"priority\":2}}]}}"
            )
        );
        let response = run_request_with_state(
            b"GET /torrent/files?id=8 HTTP/1.1\r\nHost: localhost\r\n\r\n",
            state,
        );
        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    }

    #[test]
    fn status_json_keeps_api_fields_and_adds_ui_fields() {
        let mut state = UiState {
            peer_profile: "balanced".to_string(),
            peer_profile_global_limit: 200,
            download_history_bps: vec![1.4, 2.6],
            ..UiState::default()
        };
        state.torrents.push(UiTorrent {
            meta_version: 3,
            label: "work".to_string(),
            paused: true,
            ..sample_torrent(3, "delta")
        });
        let json = status_json(&state);
        for field in [
            "\"torrents\":[{\"id\":3,",
            "\"percent\":5000",
            "\"paused\":true",
            "\"files\":[{\"path\":\"delta/a.bin\"",
            "\"priority\":2",
            "\"trackers\":[\"udp://tracker.example:1337/announce\"]",
            "\"peer_countries\":[{\"code\":\"US\",\"count\":3,",
            "\"meta_version\":3",
            "\"label\":\"work\"",
            "\"peer_profile\":\"balanced\"",
            "\"peer_profile_global_limit\":200",
            "\"download_history_bps\":[1,3]",
            "\"session_downloaded_bytes\":0",
        ] {
            assert!(json.contains(field), "missing {field} in {json}");
        }
        assert_eq!(json.matches('{').count(), json.matches('}').count());
    }
}

mod bencode;
#[cfg(feature = "dht")]
mod dht;
mod geoip;
mod http;
mod ip_filter;
#[cfg(feature = "lpd")]
mod lpd;
#[cfg(feature = "mse")]
mod mse;
#[cfg(feature = "natpmp")]
mod natpmp;
mod peer;
mod peer_stream;
mod piece;
mod proxy;
mod rss;
mod sha1;
mod sha256;
mod storage;
mod torrent;
mod tracker;
#[cfg(feature = "udp_tracker")]
mod udp_tracker;
mod ui;
#[cfg(feature = "upnp")]
mod upnp;
#[cfg(feature = "utp")]
mod utp;
mod xml;

#[cfg(not(feature = "dht"))]
mod dht {
    use std::net::SocketAddr;
    use std::sync::mpsc;

    #[derive(Clone)]
    pub struct Dht;

    pub fn start(_port: u16) -> Dht {
        Dht
    }

    impl Dht {
        pub fn add_torrent(
            &self,
            _info_hash: [u8; 20],
            _port: u16,
            _peers_tx: mpsc::Sender<Vec<SocketAddr>>,
        ) {
        }

        pub fn remove_torrent(&self, _info_hash: [u8; 20]) {}
    }
}

#[cfg(not(feature = "lpd"))]
mod lpd {
    use std::net::SocketAddr;
    use std::sync::mpsc;

    #[derive(Clone)]
    pub struct Lpd;

    pub fn start() -> Lpd {
        Lpd
    }

    impl Lpd {
        pub fn add_torrent(
            &self,
            _info_hash: [u8; 20],
            _port: u16,
            _peers_tx: mpsc::Sender<Vec<SocketAddr>>,
        ) {
        }

        pub fn remove_torrent(&self, _info_hash: [u8; 20]) {}
    }
}

#[cfg(not(feature = "udp_tracker"))]
mod udp_tracker {
    use std::fmt;

    use crate::tracker::TrackerResponse;

    #[derive(Debug)]
    pub struct Error;

    impl fmt::Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "udp tracker disabled")
        }
    }

    impl std::error::Error for Error {}

    #[derive(Debug, Clone)]
    pub struct ScrapeResult {
        pub seeders: u32,
        pub leechers: u32,
        pub completed: u32,
    }

    pub fn announce(
        _url: &str,
        _info_hash: [u8; 20],
        _peer_id: [u8; 20],
        _port: u16,
        _uploaded: u64,
        _downloaded: u64,
        _left: u64,
        _event: Option<&str>,
        _numwant: u32,
    ) -> Result<TrackerResponse, Error> {
        Err(Error)
    }

    pub fn scrape(_url: &str, _info_hash: [u8; 20]) -> Result<ScrapeResult, Error> {
        Err(Error)
    }
}

#[cfg(not(feature = "natpmp"))]
mod natpmp {
    pub fn map_port(_port: u16, _lifetime: u32) -> Result<(), String> {
        Err("natpmp disabled".to_string())
    }
}

#[cfg(not(feature = "upnp"))]
mod upnp {
    pub fn map_port(_port: u16) -> Result<(), String> {
        Err("upnp disabled".to_string())
    }
}

#[cfg(not(feature = "utp"))]
mod utp {
    use std::io::{Read, Write};
    use std::net::SocketAddr;
    use std::time::Duration;

    #[derive(Clone)]
    pub struct UtpConnector;

    pub struct UtpListener;

    #[derive(Clone)]
    pub struct UtpStream;

    pub fn start(_port: u16) -> (UtpConnector, UtpListener) {
        (UtpConnector, UtpListener)
    }

    impl UtpConnector {
        pub fn connect(&self, _addr: SocketAddr) -> Result<UtpStream, String> {
            Err("utp disabled".to_string())
        }
    }

    impl UtpListener {
        pub fn try_accept(&self) -> Option<UtpStream> {
            None
        }
    }

    impl UtpStream {
        pub fn peer_addr(&self) -> SocketAddr {
            SocketAddr::from(([0, 0, 0, 0], 0))
        }

        pub fn set_read_timeout(&mut self, _timeout: Option<Duration>) {}

        pub fn set_write_timeout(&mut self, _timeout: Option<Duration>) {}
    }

    impl Read for UtpStream {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "utp disabled",
            ))
        }
    }

    impl Write for UtpStream {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "utp disabled",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(not(feature = "mse"))]
mod mse {
    use std::io::{Read, Write};

    #[derive(Clone, Copy)]
    #[allow(dead_code)]
    pub enum CryptoMode {
        Plaintext,
    }

    #[derive(Clone)]
    pub struct CipherState;

    impl CipherState {
        pub fn encrypt(&mut self, _data: &mut [u8]) {}
        pub fn decrypt(&mut self, _data: &mut [u8]) {}
    }

    pub fn initiate<RW: Read + Write>(
        _stream: &mut RW,
        _info_hash: [u8; 20],
        _allow_plain: bool,
        _initial_payload: &[u8],
    ) -> Result<(CryptoMode, Option<CipherState>), String> {
        Err("mse disabled".to_string())
    }

    pub fn accept<RW: Read + Write>(
        _stream: &mut RW,
        _info_hashes: &[[u8; 20]],
        _first_byte: u8,
        _allow_plain: bool,
    ) -> Result<(CryptoMode, Option<CipherState>, [u8; 20], Vec<u8>), String> {
        Err("mse disabled".to_string())
    }
}

use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::bencode::Value;
use crate::ip_filter::IpFilter;
use crate::peer_stream::PeerStream;
const PIPELINE_DEPTH: usize = 4;
const MIN_PIPELINE_DEPTH: usize = 2;
const MAX_PIPELINE_DEPTH: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_UPLOAD_BLOCK_LEN: u32 = 64 * 1024;
const MAX_IDLE_TICKS: u32 = 180;
const MAX_IDLE_TICKS_SEED: u32 = 720;
const SNUB_TIMEOUT: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(90);
const ENDGAME_BLOCKS: usize = 32;
const ENDGAME_DUP_TIMEOUT: Duration = Duration::from_secs(5);
const RESUME_SAVE_INTERVAL: Duration = Duration::from_secs(30);
const LOW_PEER_THRESHOLD: usize = 8;
const UPLOAD_SLOTS: usize = 4;
const UNCHOKE_INTERVAL: Duration = Duration::from_secs(10);
const OPTIMISTIC_UNCHOKE_INTERVAL: Duration = Duration::from_secs(30);
const RTT_TARGET_MS: f64 = 800.0;
const MAX_PEER_RETRIES: u32 = 2;
const PEER_RETRY_BASE_SECS: u64 = 5;
const NO_PEER_REANNOUNCE_SECS: u64 = 10;
const PEER_BAN_SECS: u64 = 120;
const MAX_TORRENT_BYTES: usize = 2 * 1024 * 1024;
const MIN_INBOUND_HANDLER_SLOTS: usize = 64;
const MAX_INBOUND_HANDLER_SLOTS: usize = 1024;
const METADATA_PIECE_LEN: usize = 16 * 1024;
const METADATA_FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const METADATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(90);
const METADATA_PEER_LIMIT: usize = 80;
const METADATA_REQUEST_RETRY: Duration = Duration::from_secs(3);
const METADATA_PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const MAGNET_CACHE_URLS: [&str; 2] = [
    "https://itorrents.org/torrent/",
    "https://torrage.info/torrent/",
];
const HANDSHAKE_LEN: usize = 68;
const SHUTDOWN_SLEEP_SLICE_MS: u64 = 50;

#[cfg(unix)]
const SIGINT: i32 = 2;
#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SIGPIPE: i32 = 13;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static PAUSED: AtomicBool = AtomicBool::new(false);
static PROGRESS_ACTIVE: AtomicBool = AtomicBool::new(false);
static PROGRESS_LINE_LEN: AtomicUsize = AtomicUsize::new(0);
static LOG_LOCK: Mutex<()> = Mutex::new(());
static LOG_FILE: OnceLock<Mutex<std::fs::File>> = OnceLock::new();
static SESSION_DOWNLOADED_BYTES: AtomicU64 = AtomicU64::new(0);
static SESSION_UPLOADED_BYTES: AtomicU64 = AtomicU64::new(0);
static PEER_CONNECTED: AtomicU64 = AtomicU64::new(0);
static PEER_DISCONNECTED: AtomicU64 = AtomicU64::new(0);
static SEED_RATIO_BITS: AtomicU64 = AtomicU64::new(0);
static MAX_SEED_TIME_SECS: AtomicU64 = AtomicU64::new(0);
static SUPER_SEED: AtomicBool = AtomicBool::new(false);
static ON_COMPLETE_SCRIPT: OnceLock<PathBuf> = OnceLock::new();

#[allow(dead_code)]
struct ThrottleGroup {
    name: String,
    down: Arc<RateLimiter>,
    up: Arc<RateLimiter>,
}

static THROTTLE_GROUPS: OnceLock<Mutex<Vec<ThrottleGroup>>> = OnceLock::new();

struct RatioGroup {
    name: String,
    ratio: f64,
    action: String,
}

static RATIO_GROUPS: OnceLock<Mutex<Vec<RatioGroup>>> = OnceLock::new();

struct ScheduleEntry {
    interval_secs: u64,
    command: String,
    last_run: Instant,
}

static SCHEDULES: OnceLock<Mutex<Vec<ScheduleEntry>>> = OnceLock::new();
static GEOIP_DB: OnceLock<geoip::GeoIpDb> = OnceLock::new();
static RSS_STATE: OnceLock<Mutex<rss::RssState>> = OnceLock::new();

struct RssPollResult {
    url: String,
    parsed: Result<(String, Vec<rss::FeedItem>), String>,
}

struct RssDownloadResult {
    guid: String,
    url: String,
    title: String,
    data: Result<Vec<u8>, String>,
}

#[derive(Clone)]
enum TorrentSource {
    Path(String),
    Bytes(Vec<u8>),
    Magnet(String),
}

#[derive(Clone)]
struct TorrentRequest {
    id: u64,
    source: TorrentSource,
    download_dir: PathBuf,
    preallocate: bool,
    initial_label: String,
}

#[derive(Clone)]
struct SessionEntry {
    info_hash: [u8; 20],
    name: String,
    torrent_bytes: Vec<u8>,
    download_dir: PathBuf,
    preallocate: bool,
    label: String,
}

struct SessionStore {
    path: PathBuf,
    entries: Mutex<HashMap<[u8; 20], SessionEntry>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncryptionMode {
    Disable,
    Prefer,
    Require,
}

#[derive(Clone)]
struct ConnectionConfig {
    encryption: EncryptionMode,
    utp: Option<utp::UtpConnector>,
    ip_filter: Option<Arc<IpFilter>>,
    proxy: Option<proxy::ProxyConfig>,
}

#[derive(Clone)]
struct InboundConfig {
    encryption: EncryptionMode,
    ip_filter: Option<Arc<IpFilter>>,
    max_handlers: usize,
    active_handlers: Arc<AtomicUsize>,
}

struct InboundHandlerGuard {
    active: Option<Arc<AtomicUsize>>,
}

struct RateLimiter {
    limit_bps: AtomicU64,
    state: Mutex<RateState>,
}

struct RateState {
    allowance: f64,
    last: Instant,
}

#[derive(Clone)]
struct TransferLimits {
    global_down: Arc<RateLimiter>,
    global_up: Arc<RateLimiter>,
    torrent_down: Arc<RateLimiter>,
    torrent_up: Arc<RateLimiter>,
}

struct PeerSlots {
    max: usize,
    active: AtomicUsize,
}

struct ActiveTorrentGuard {
    counter: Arc<AtomicUsize>,
}

struct UploadManager {
    inner: Mutex<UploadState>,
    max_unchoked: usize,
}

struct UploadState {
    peers: HashMap<u64, PeerUploadInfo>,
    unchoked: HashSet<u64>,
    last_schedule: Instant,
    last_optimistic: Instant,
    optimistic_peer: Option<u64>,
    rng: u64,
}

struct PeerUploadInfo {
    interested: bool,
    uploaded_total: u64,
    last_uploaded_total: u64,
    rate: u64,
}

struct TorrentContext {
    id: u64,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    download_dir: PathBuf,
    pieces: Arc<Mutex<piece::PieceManager>>,
    storage: Arc<Mutex<storage::Storage>>,
    completed_log: Arc<Mutex<Vec<u32>>>,
    base_piece_length: u64,
    file_spans: Arc<Vec<FileSpan>>,
    file_priorities: Arc<Mutex<Vec<u8>>>,
    limits: TransferLimits,
    downloaded: Arc<AtomicU64>,
    uploaded: Arc<AtomicU64>,
    paused: Arc<AtomicBool>,
    stop_requested: Arc<AtomicBool>,
    upload_manager: Arc<UploadManager>,
    peer_tags: Arc<AtomicU64>,
    label: Arc<Mutex<String>>,
    trackers: Arc<Mutex<TrackerSet>>,
    #[allow(dead_code)]
    throttle_group: Arc<Mutex<Option<String>>>,
    ratio_group: Arc<Mutex<Option<String>>>,
    file_renames: Arc<Mutex<HashMap<usize, String>>>,
}

type SessionRegistry = Arc<Mutex<HashMap<[u8; 20], Arc<TorrentContext>>>>;

macro_rules! log_info {
    ($($t:tt)*) => {
        crate::log_stdout(format_args!($($t)*));
    };
}

macro_rules! log_warn {
    ($($t:tt)*) => {
        crate::log_stderr(format_args!($($t)*));
    };
}

macro_rules! log_debug {
    ($($t:tt)*) => {
        #[cfg(feature = "verbose")]
        {
            crate::log_stderr(format_args!($($t)*));
        }
    };
}

fn clear_progress_line() {
    if !PROGRESS_ACTIVE.load(Ordering::SeqCst) {
        return;
    }
    let len = PROGRESS_LINE_LEN.load(Ordering::SeqCst);
    if len == 0 {
        return;
    }
    eprint!("\r{} \r", " ".repeat(len));
    let _ = io::stderr().flush();
}

fn log_timestamp() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Days since 1970-01-01 to Y-M-D
    let mut y = 1970i64;
    let mut rem = days as i64;
    loop {
        let ylen = if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
            366
        } else {
            365
        };
        if rem < ylen {
            break;
        }
        rem -= ylen;
        y += 1;
    }
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut mo = 0usize;
    for &ml in &mdays {
        if rem < ml as i64 {
            break;
        }
        rem -= ml as i64;
        mo += 1;
    }
    format!("[{y:04}-{:02}-{:02} {h:02}:{m:02}:{s:02}]", mo + 1, rem + 1)
}

fn write_to_log_file(args: std::fmt::Arguments) {
    if let Some(file) = LOG_FILE.get() {
        if let Ok(mut f) = file.lock() {
            let ts = log_timestamp();
            let _ = write!(f, "{ts} {args}\n");
            let _ = f.flush();
        }
    }
}

pub(crate) fn log_stdout(args: std::fmt::Arguments) {
    let _guard = LOG_LOCK.lock().ok();
    clear_progress_line();
    println!("{args}");
    write_to_log_file(args);
}

pub(crate) fn log_stderr(args: std::fmt::Arguments) {
    let _guard = LOG_LOCK.lock().ok();
    clear_progress_line();
    eprintln!("{args}");
    write_to_log_file(args);
}

pub(crate) fn system_entropy_u64() -> u64 {
    use std::sync::OnceLock;
    static BASE: OnceLock<u64> = OnceLock::new();
    let base = *BASE.get_or_init(|| {
        let mut buf = [0u8; 8];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            if std::io::Read::read_exact(&mut f, &mut buf).is_ok() {
                return u64::from_ne_bytes(buf);
            }
        }
        let time_part = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let pid = std::process::id() as u64;
        let stack_addr = &buf as *const _ as u64;
        time_part ^ (pid.wrapping_mul(0x9E3779B97F4A7C15)) ^ stack_addr
    });
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let c = CTR.fetch_add(1, Ordering::Relaxed);
    let mut x = base ^ c.wrapping_mul(0x9E3779B97F4A7C15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58476D1CE4E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D049BB133111EB);
    x ^= x >> 31;
    x
}

fn install_panic_logger() {
    std::panic::set_hook(Box::new(|info| {
        let payload = if let Some(msg) = info.payload().downcast_ref::<&str>() {
            *msg
        } else if let Some(msg) = info.payload().downcast_ref::<String>() {
            msg.as_str()
        } else {
            "panic"
        };
        let location = info
            .location()
            .map(|loc| format!("{}:{}", loc.file(), loc.line()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let message = format!("panic: {payload} at {location}");
        eprintln!("{message}");
        let _ = fs::create_dir_all(".rustorrent");
        if let Ok(mut file) = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(".rustorrent/panic.log")
        {
            let _ = writeln!(file, "{message}");
        }
    }));
}

fn main() {
    if let Err(err) = run() {
        log_warn!("error: {err}");
        std::process::exit(1);
    }
}

#[cfg(unix)]
extern "C" fn handle_signal(_: i32) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
extern "C" fn handle_sigpipe(_: i32) {}

#[cfg(unix)]
extern "C" {
    fn signal(sig: i32, handler: extern "C" fn(i32)) -> usize;
}

#[cfg(unix)]
fn install_signal_handlers() {
    unsafe {
        let _ = signal(SIGINT, handle_signal);
        let _ = signal(SIGTERM, handle_signal);
        let _ = signal(SIGPIPE, handle_sigpipe);
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

pub fn set_paused(paused: bool) {
    PAUSED.store(paused, Ordering::SeqCst);
}

pub fn is_paused() -> bool {
    PAUSED.load(Ordering::SeqCst)
}

fn torrent_paused(paused: &AtomicBool) -> bool {
    is_paused() || paused.load(Ordering::SeqCst)
}

fn torrent_stop_requested(stop_flag: &AtomicBool) -> bool {
    shutdown_requested() || stop_flag.load(Ordering::SeqCst)
}

fn sleep_with_shutdown(duration: Duration) {
    if duration.is_zero() {
        return;
    }
    let deadline = Instant::now() + duration;
    loop {
        if shutdown_requested() {
            break;
        }
        let now = Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        let slice = remaining.min(Duration::from_millis(SHUTDOWN_SLEEP_SLICE_MS));
        thread::sleep(slice);
    }
}

fn sleep_with_shutdown_or_stop(duration: Duration, stop_flag: &AtomicBool) {
    if duration.is_zero() {
        return;
    }
    let deadline = Instant::now() + duration;
    loop {
        if torrent_stop_requested(stop_flag) {
            break;
        }
        let now = Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }
        let slice = remaining.min(Duration::from_millis(SHUTDOWN_SLEEP_SLICE_MS));
        thread::sleep(slice);
    }
}

impl SessionStore {
    fn load(root: &Path) -> Self {
        let path = session_path(root);
        let entries = match load_session_entries_with_recovery(&path, root) {
            Ok(entries) => entries,
            Err(err) => {
                log_warn!("{err}");
                HashMap::new()
            }
        };
        Self {
            path,
            entries: Mutex::new(entries),
        }
    }

    fn list(&self) -> Vec<SessionEntry> {
        let guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.values().cloned().collect()
    }

    fn contains(&self, info_hash: [u8; 20]) -> bool {
        let guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.contains_key(&info_hash)
    }

    fn upsert(
        &self,
        info_hash: [u8; 20],
        name: String,
        torrent_bytes: Vec<u8>,
        download_dir: &Path,
        preallocate: bool,
    ) {
        let mut guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.insert(
            info_hash,
            SessionEntry {
                info_hash,
                name,
                torrent_bytes,
                download_dir: download_dir.to_path_buf(),
                preallocate,
                label: String::new(),
            },
        );
        if let Err(err) = save_session(&self.path, &guard) {
            log_warn!("session save failed: {err}");
        }
    }

    fn set_label(&self, info_hash: [u8; 20], label: &str) {
        let mut guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(entry) = guard.get_mut(&info_hash) {
            entry.label = label.to_string();
            if let Err(err) = save_session(&self.path, &guard) {
                log_warn!("session save failed: {err}");
            }
        }
    }

    fn remove(&self, info_hash: [u8; 20]) {
        let mut guard = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.remove(&info_hash).is_none() {
            return;
        }
        if let Err(err) = save_session(&self.path, &guard) {
            log_warn!("session save failed: {err}");
        }
    }
}

impl RateLimiter {
    fn new(limit_bps: u64) -> Self {
        Self {
            limit_bps: AtomicU64::new(limit_bps),
            state: Mutex::new(RateState {
                allowance: limit_bps as f64,
                last: Instant::now(),
            }),
        }
    }

    fn limit_bps(&self) -> u64 {
        self.limit_bps.load(Ordering::SeqCst)
    }

    fn set_limit_bps(&self, limit_bps: u64) {
        self.limit_bps.store(limit_bps, Ordering::SeqCst);
        if let Ok(mut state) = self.state.lock() {
            let capacity = limit_bps as f64;
            state.allowance = state.allowance.min(capacity);
            state.last = Instant::now();
        }
    }

    fn throttle(&self, bytes: usize) {
        let limit_bps = self.limit_bps();
        if limit_bps == 0 || bytes == 0 {
            return;
        }
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return,
        };
        let now = Instant::now();
        let elapsed = now.duration_since(state.last).as_secs_f64();
        let capacity = limit_bps as f64;
        state.allowance = (state.allowance + elapsed * capacity).min(capacity);
        if state.allowance >= bytes as f64 {
            state.allowance -= bytes as f64;
            state.last = now;
            return;
        }
        let needed = bytes as f64 - state.allowance;
        state.allowance = 0.0;
        state.last = now;
        drop(state);
        let sleep_secs = needed / capacity;
        if sleep_secs > 0.0 {
            sleep_with_shutdown(Duration::from_secs_f64(sleep_secs));
        }
    }
}

impl InboundConfig {
    fn try_acquire_handler_slot(&self) -> Option<InboundHandlerGuard> {
        if self.max_handlers == 0 {
            return Some(InboundHandlerGuard { active: None });
        }
        loop {
            let current = self.active_handlers.load(Ordering::SeqCst);
            if current >= self.max_handlers {
                return None;
            }
            if self
                .active_handlers
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(InboundHandlerGuard {
                    active: Some(Arc::clone(&self.active_handlers)),
                });
            }
        }
    }
}

impl Drop for InboundHandlerGuard {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl PeerSlots {
    fn new(max: usize) -> Self {
        Self {
            max,
            active: AtomicUsize::new(0),
        }
    }

    fn acquire(&self, stop_flag: &AtomicBool) -> bool {
        if self.max == 0 {
            return true;
        }
        loop {
            if torrent_stop_requested(stop_flag) {
                return false;
            }
            let current = self.active.load(Ordering::SeqCst);
            if current < self.max {
                if self
                    .active
                    .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    return true;
                }
            } else {
                sleep_with_shutdown_or_stop(Duration::from_millis(50), stop_flag);
            }
        }
    }

    fn release(&self) {
        if self.max == 0 {
            return;
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ActiveTorrentGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        Self { counter }
    }
}

impl Drop for ActiveTorrentGuard {
    fn drop(&mut self) {
        let _ = self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

impl UploadManager {
    fn new(max_unchoked: usize) -> Self {
        let now = Instant::now();
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0);
        Self {
            inner: Mutex::new(UploadState {
                peers: HashMap::new(),
                unchoked: HashSet::new(),
                last_schedule: now,
                last_optimistic: now - OPTIMISTIC_UNCHOKE_INTERVAL,
                optimistic_peer: None,
                rng: seed ^ 0x9e37_79b9_7f4a_7c15,
            }),
            max_unchoked: max_unchoked.max(1),
        }
    }

    fn register(&self, peer_id: u64) {
        if let Ok(mut state) = self.inner.lock() {
            state.peers.insert(
                peer_id,
                PeerUploadInfo {
                    interested: false,
                    uploaded_total: 0,
                    last_uploaded_total: 0,
                    rate: 0,
                },
            );
        }
    }

    fn unregister(&self, peer_id: u64) {
        if let Ok(mut state) = self.inner.lock() {
            state.peers.remove(&peer_id);
            state.unchoked.remove(&peer_id);
            if state.optimistic_peer == Some(peer_id) {
                state.optimistic_peer = None;
            }
        }
    }

    fn set_interested(&self, peer_id: u64, interested: bool) {
        if let Ok(mut state) = self.inner.lock() {
            if let Some(info) = state.peers.get_mut(&peer_id) {
                let was_interested = info.interested;
                info.interested = interested;
                // Immediately reschedule when a new peer becomes interested
                // so they get unchoked without waiting for the 10-second timer
                if interested && !was_interested {
                    let now = Instant::now();
                    reschedule_uploads(&mut state, self.max_unchoked, now);
                }
            }
        }
    }

    fn record_upload(&self, peer_id: u64, bytes: u64) {
        if bytes == 0 {
            return;
        }
        if let Ok(mut state) = self.inner.lock() {
            if let Some(info) = state.peers.get_mut(&peer_id) {
                info.uploaded_total = info.uploaded_total.saturating_add(bytes);
            }
        }
    }

    fn should_unchoke(&self, peer_id: u64) -> bool {
        let mut state = match self.inner.lock() {
            Ok(state) => state,
            Err(_) => return false,
        };
        let now = Instant::now();
        if now.duration_since(state.last_schedule) >= UNCHOKE_INTERVAL {
            reschedule_uploads(&mut state, self.max_unchoked, now);
        }
        state.unchoked.contains(&peer_id)
    }
}

fn reschedule_uploads(state: &mut UploadState, max_unchoked: usize, now: Instant) {
    state.last_schedule = now;
    let mut candidates: Vec<(u64, u64)> = Vec::new();
    for (peer_id, info) in state.peers.iter_mut() {
        info.rate = info.uploaded_total.saturating_sub(info.last_uploaded_total);
        info.last_uploaded_total = info.uploaded_total;
        if info.interested {
            candidates.push((*peer_id, info.rate));
        }
    }
    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    state.unchoked.clear();
    for (peer_id, _) in candidates.iter().take(max_unchoked) {
        state.unchoked.insert(*peer_id);
    }

    let remaining = if candidates.len() > max_unchoked {
        &candidates[max_unchoked..]
    } else {
        &[]
    };
    if now.duration_since(state.last_optimistic) >= OPTIMISTIC_UNCHOKE_INTERVAL {
        state.optimistic_peer = if remaining.is_empty() {
            None
        } else {
            let idx = (next_rng(state) as usize) % remaining.len();
            Some(remaining[idx].0)
        };
        state.last_optimistic = now;
    }

    if let Some(peer_id) = state.optimistic_peer {
        if state
            .peers
            .get(&peer_id)
            .map(|info| info.interested)
            .unwrap_or(false)
        {
            state.unchoked.insert(peer_id);
        } else {
            state.optimistic_peer = None;
        }
    }
}

fn next_rng(state: &mut UploadState) -> u64 {
    let mut x = state.rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state.rng = x;
    x
}

fn inbound_handler_slots(max_peers_global: usize) -> usize {
    if max_peers_global == 0 {
        return 0;
    }
    max_peers_global
        .saturating_mul(2)
        .clamp(MIN_INBOUND_HANDLER_SLOTS, MAX_INBOUND_HANDLER_SLOTS)
}

fn run() -> Result<(), String> {
    install_signal_handlers();
    install_panic_logger();
    let args = parse_args()?;

    // Initialize log file if --log was specified
    if let Some(log_path) = args.log_path.as_ref() {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .map_err(|err| format!("failed to open log file: {err}"))?;
        let _ = LOG_FILE.set(Mutex::new(file));
    }

    // Daemon mode: fork and detach on Unix
    #[cfg(unix)]
    if args.daemon {
        extern "C" {
            fn fork() -> i32;
            fn setsid() -> i32;
        }
        let pid = unsafe { fork() };
        if pid < 0 {
            return Err("fork failed".to_string());
        }
        if pid > 0 {
            // Parent: exit immediately
            std::process::exit(0);
        }
        // Child: create new session
        if unsafe { setsid() } < 0 {
            return Err("setsid failed".to_string());
        }
        // Redirect stdin to /dev/null
        if let Ok(devnull) = std::fs::File::open("/dev/null") {
            use std::os::unix::io::AsRawFd;
            extern "C" {
                fn dup2(oldfd: i32, newfd: i32) -> i32;
            }
            unsafe {
                dup2(devnull.as_raw_fd(), 0);
            }
        }
    }

    // Write PID file if requested
    if let Some(pid_path) = args.pid_file.as_ref() {
        let pid = std::process::id();
        fs::write(pid_path, format!("{pid}\n"))
            .map_err(|err| format!("failed to write pid file: {err}"))?;
    }

    // Session locking: prevent multiple instances using same data directory
    #[cfg(unix)]
    let _lock_file = {
        let lock_path = args.download_dir.join(".rustorrent.lock");
        if lock_path.exists() {
            if let Ok(contents) = fs::read_to_string(&lock_path) {
                if let Ok(pid) = contents.trim().parse::<i32>() {
                    extern "C" {
                        fn kill(pid: i32, sig: i32) -> i32;
                    }
                    if unsafe { kill(pid, 0) } == 0 && pid != std::process::id() as i32 {
                        return Err(format!(
                            "another instance (PID {pid}) is using {}",
                            args.download_dir.display()
                        ));
                    }
                }
            }
        }
        let mut f = fs::File::create(&lock_path).map_err(|e| format!("lock: {e}"))?;
        write!(f, "{}", std::process::id()).map_err(|e| format!("lock: {e}"))?;
        Some((f, lock_path))
    };
    #[cfg(not(unix))]
    let _lock_file: Option<(fs::File, PathBuf)> = None;

    // Initialize seed ratio from CLI args
    if args.seed_ratio > 0.0 {
        SEED_RATIO_BITS.store(args.seed_ratio.to_bits(), Ordering::SeqCst);
    }
    if args.max_seed_time > 0 {
        MAX_SEED_TIME_SECS.store(args.max_seed_time * 60, Ordering::SeqCst);
    }
    if let Some(script) = args.on_complete.clone() {
        let _ = ON_COMPLETE_SCRIPT.set(script);
    }
    if args.super_seed {
        SUPER_SEED.store(true, Ordering::SeqCst);
    }
    if !args.throttle_groups.is_empty() {
        let groups = args
            .throttle_groups
            .iter()
            .map(|(name, down, up)| ThrottleGroup {
                name: name.clone(),
                down: Arc::new(RateLimiter::new(*down)),
                up: Arc::new(RateLimiter::new(*up)),
            })
            .collect();
        let _ = THROTTLE_GROUPS.set(Mutex::new(groups));
    }
    if !args.ratio_groups.is_empty() {
        let groups = args
            .ratio_groups
            .iter()
            .map(|(name, ratio, action)| RatioGroup {
                name: name.clone(),
                ratio: *ratio,
                action: action.clone(),
            })
            .collect();
        let _ = RATIO_GROUPS.set(Mutex::new(groups));
    }
    if !args.schedules.is_empty() {
        let entries = args
            .schedules
            .iter()
            .map(|(interval, command)| ScheduleEntry {
                interval_secs: *interval,
                command: command.clone(),
                last_run: Instant::now(),
            })
            .collect();
        let _ = SCHEDULES.set(Mutex::new(entries));
    }

    let global_down = Arc::new(RateLimiter::new(args.download_rate));
    let global_up = Arc::new(RateLimiter::new(args.upload_rate));
    let peer_slots = Arc::new(PeerSlots::new(args.max_peers_global));
    let active_torrents = Arc::new(AtomicUsize::new(0));
    let session_store = Arc::new(SessionStore::load(&args.download_dir));

    let state = Arc::new(Mutex::new(ui::UiState::default()));
    let (cmd_tx, cmd_rx) = mpsc::channel::<ui::UiCommand>();
    if args.ui {
        if let Err(err) = ui::start(args.ui_addr.clone(), state.clone(), Some(cmd_tx.clone())) {
            log_warn!("ui error: {err}");
        } else {
            log_info!("ui: http://{}", args.ui_addr);
        }
    }
    let ui_state = Some(state.clone());
    update_ui(&ui_state, |ui| {
        ui.global_download_limit_bps = args.download_rate;
        ui.global_upload_limit_bps = args.upload_rate;
        ui.seed_ratio = args.seed_ratio;
        ui.proxy_label = match &args.proxy {
            Some(proxy::ProxyConfig::Socks5 { host, port }) => format!("socks5://{host}:{port}"),
            Some(proxy::ProxyConfig::Http { host, port }) => format!("http://{host}:{port}"),
            None => String::new(),
        };
    });

    let registry: SessionRegistry = Arc::new(Mutex::new(HashMap::new()));
    let progress_handle = if !args.daemon && !args.tui {
        Some(start_console_progress(state.clone(), registry.clone()))
    } else {
        None
    };
    let tui_handle = if args.tui {
        Some(start_tui(state.clone(), cmd_tx.clone()))
    } else {
        None
    };
    let ip_filter = if let Some(path) = args.blocklist_path.as_ref() {
        match IpFilter::from_file(path) {
            Ok(filter) => Some(Arc::new(filter)),
            Err(err) => {
                log_warn!("blocklist error: {err}");
                None
            }
        }
    } else {
        None
    };
    if let Some(path) = args.geoip_db.as_ref() {
        match geoip::GeoIpDb::load(path) {
            Ok(db) => {
                log_info!("geoip loaded {} entries from {}", db.len(), path.display());
                let _ = GEOIP_DB.set(db);
            }
            Err(err) => {
                log_warn!("geoip error: {err}");
            }
        }
    }
    {
        let rss_path = args.download_dir.join(".rustorrent").join("rss.benc");
        let mut rss_state = if rss_path.exists() {
            rss::load_rss_state(&rss_path).unwrap_or_else(|err| {
                log_warn!("rss load error: {err}");
                rss::RssState::new()
            })
        } else {
            rss::RssState::new()
        };
        for url in &args.rss_feeds {
            if !rss_state.feeds.iter().any(|f| f.url == *url) {
                rss_state.feeds.push(rss::RssFeed {
                    url: url.clone(),
                    title: String::new(),
                    items: Vec::new(),
                    last_poll: 0,
                    poll_interval_secs: args.rss_interval,
                });
                log_info!("rss added feed: {url}");
            }
        }
        for (feed_url, pattern) in &args.rss_rules {
            rss_state.rules.push(rss::RssRule {
                name: pattern.clone(),
                feed_url: feed_url.clone(),
                pattern: pattern.clone(),
            });
        }
        let _ = RSS_STATE.set(Mutex::new(rss_state));
    }
    let inbound = InboundConfig {
        encryption: args.encryption,
        ip_filter: ip_filter.clone(),
        max_handlers: inbound_handler_slots(args.max_peers_global),
        active_handlers: Arc::new(AtomicUsize::new(0)),
    };
    start_inbound_listener(args.port, registry.clone(), inbound.clone());
    let utp_connector = if args.enable_utp {
        let (connector, listener) = utp::start(args.port);
        start_utp_listener(listener, registry.clone(), inbound.clone());
        Some(connector)
    } else {
        None
    };
    let dht = dht::start(args.port);
    let lpd = lpd::start();
    let port = args.port;
    thread::spawn(move || {
        let _ = natpmp::map_port(port, 3600);
    });
    let port = args.port;
    thread::spawn(move || {
        let _ = upnp::map_port(port);
    });

    let mut queue: VecDeque<TorrentRequest> = VecDeque::new();
    let mut next_id = 1u64;
    let (rss_poll_tx, rss_poll_rx) = mpsc::channel::<RssPollResult>();
    let (rss_download_tx, rss_download_rx) = mpsc::channel::<RssDownloadResult>();
    let mut rss_poll_inflight: HashSet<String> = HashSet::new();
    let mut rss_download_inflight: HashSet<String> = HashSet::new();
    for entry in session_store.list() {
        let label = if entry.name.is_empty() {
            let short = hex(&entry.info_hash);
            format!("resume {}", short.get(0..8).unwrap_or(&short))
        } else {
            entry.name.clone()
        };
        let request = TorrentRequest {
            id: next_id,
            source: TorrentSource::Bytes(entry.torrent_bytes.clone()),
            download_dir: entry.download_dir.clone(),
            preallocate: entry.preallocate,
            initial_label: entry.label.clone(),
        };
        next_id = next_id.saturating_add(1);
        enqueue_request_with_label(&mut queue, &ui_state, request, label);
    }
    if let Some(link) = args.magnet.clone() {
        let request = TorrentRequest {
            id: next_id,
            source: TorrentSource::Magnet(link),
            download_dir: args.download_dir.clone(),
            preallocate: args.preallocate,
            initial_label: String::new(),
        };
        next_id = next_id.saturating_add(1);
        enqueue_request(&mut queue, &ui_state, request);
    }

    if let Some(path) = args.torrent_path.clone() {
        let request = TorrentRequest {
            id: next_id,
            source: TorrentSource::Path(path),
            download_dir: args.download_dir.clone(),
            preallocate: args.preallocate,
            initial_label: String::new(),
        };
        next_id = next_id.saturating_add(1);
        enqueue_request(&mut queue, &ui_state, request);
    }

    update_idle_state(&ui_state, &args, queue.len());

    let mut handles: Vec<thread::JoinHandle<()>> = Vec::new();
    let mut last_watch_scan = Instant::now();

    loop {
        if !args.watch_dirs.is_empty() && last_watch_scan.elapsed() >= Duration::from_secs(5) {
            for watch_dir in &args.watch_dirs {
                scan_watch_dir(
                    watch_dir,
                    &mut queue,
                    &ui_state,
                    &mut next_id,
                    &args.download_dir,
                    args.preallocate,
                );
            }
            last_watch_scan = Instant::now();
        }

        drain_ui_commands(
            &cmd_rx,
            &mut queue,
            &ui_state,
            &args,
            &mut next_id,
            &registry,
            &session_store,
            &global_down,
            &global_up,
        );

        // Scheduled commands
        if let Some(schedules) = SCHEDULES.get() {
            if let Ok(mut sched) = schedules.lock() {
                for entry in sched.iter_mut() {
                    if entry.last_run.elapsed().as_secs() >= entry.interval_secs {
                        execute_schedule_command(
                            &entry.command,
                            &global_down,
                            &global_up,
                            &registry,
                        );
                        entry.last_run = Instant::now();
                    }
                }
            }
        }

        // RSS feed polling
        schedule_rss_polls(&args, &rss_poll_tx, &mut rss_poll_inflight);
        drain_rss_poll_results(
            &args,
            &rss_poll_rx,
            &rss_download_tx,
            &mut queue,
            &ui_state,
            &mut next_id,
            &mut rss_poll_inflight,
            &mut rss_download_inflight,
        );
        drain_rss_download_results(
            &args,
            &rss_download_rx,
            &mut queue,
            &ui_state,
            &mut next_id,
            &mut rss_download_inflight,
        );

        let can_start = args.max_active_torrents == 0
            || active_torrents.load(Ordering::SeqCst) < args.max_active_torrents;
        if can_start {
            if let Some(request) = queue.pop_front() {
                let request_id = request.id;
                let is_magnet = matches!(request.source, TorrentSource::Magnet(_));
                let load_status = if is_magnet {
                    "fetching metadata"
                } else {
                    "loading"
                };
                update_ui(&ui_state, |state| {
                    state.queue_len = queue.len();
                    state.status = load_status.to_string();
                    state.last_error.clear();
                    update_torrent_entry(state, request_id, |torrent| {
                        torrent.status = load_status.to_string();
                        torrent.last_error.clear();
                    });
                });
                active_torrents.fetch_add(1, Ordering::SeqCst);
                let active_guard = ActiveTorrentGuard::new(active_torrents.clone());
                let args_clone = args.clone();
                let ui_clone = ui_state.clone();
                let registry_clone = registry.clone();
                let dht_clone = dht.clone();
                let lpd_clone = lpd.clone();
                let session_clone = session_store.clone();
                let utp_clone = utp_connector.clone();
                let filter_clone = ip_filter.clone();
                let global_down = global_down.clone();
                let global_up = global_up.clone();
                let peer_slots = peer_slots.clone();
                let handle = thread::spawn(move || {
                    let _guard = active_guard;
                    if let Err(err) = run_torrent(
                        request,
                        &args_clone,
                        &ui_clone,
                        &registry_clone,
                        &session_clone,
                        &dht_clone,
                        &lpd_clone,
                        utp_clone,
                        filter_clone,
                        global_down,
                        global_up,
                        peer_slots,
                    ) {
                        log_warn!("torrent error: {err}");
                        update_ui(&ui_clone, |state| {
                            state.status = "error".to_string();
                            state.last_error = err;
                            let last_error = state.last_error.clone();
                            update_torrent_entry(state, request_id, |torrent| {
                                torrent.status = "error".to_string();
                                torrent.last_error = last_error;
                            });
                        });
                    }
                });
                handles.push(handle);
                continue;
            }
        }

        if shutdown_requested() {
            break;
        }

        update_idle_state(&ui_state, &args, queue.len());
        sleep_with_shutdown(Duration::from_millis(200));
    }

    for handle in handles {
        let _ = handle.join();
    }
    if let Some(handle) = progress_handle {
        let _ = handle.join();
    }
    if let Some(handle) = tui_handle {
        let _ = handle.join();
    }

    // Clean up lock file
    #[cfg(unix)]
    if let Some((_, lock_path)) = _lock_file.as_ref() {
        let _ = fs::remove_file(lock_path);
    }

    Ok(())
}

fn drain_ui_commands(
    rx: &mpsc::Receiver<ui::UiCommand>,
    queue: &mut VecDeque<TorrentRequest>,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    args: &Args,
    next_id: &mut u64,
    registry: &SessionRegistry,
    session_store: &Arc<SessionStore>,
    global_down: &Arc<RateLimiter>,
    global_up: &Arc<RateLimiter>,
) {
    loop {
        match rx.try_recv() {
            Ok(cmd) => match cmd {
                ui::UiCommand::AddTorrent {
                    data,
                    download_dir,
                    preallocate,
                    reply,
                } => {
                    let request = TorrentRequest {
                        id: *next_id,
                        source: TorrentSource::Bytes(data),
                        download_dir: normalize_download_dir(download_dir, &args.download_dir),
                        preallocate,
                        initial_label: String::new(),
                    };
                    if let Ok(info_hash) = info_hash_for_source(&request.source) {
                        if is_duplicate_torrent(registry, queue, session_store, info_hash) {
                            let message = "torrent already added".to_string();
                            update_ui(ui_state, |state| {
                                state.last_error = message.clone();
                            });
                            let _ = reply.send(Err(message));
                            continue;
                        }
                    }
                    *next_id = next_id.saturating_add(1);
                    let torrent_id = request.id;
                    enqueue_request_with_label(
                        queue,
                        ui_state,
                        request,
                        "torrent upload".to_string(),
                    );
                    let _ = reply.send(Ok(ui::UiCommandSuccess::TorrentAdded { torrent_id }));
                }
                ui::UiCommand::AddMagnet {
                    magnet,
                    download_dir,
                    preallocate,
                    reply,
                } => {
                    let request = TorrentRequest {
                        id: *next_id,
                        source: TorrentSource::Magnet(magnet),
                        download_dir: normalize_download_dir(download_dir, &args.download_dir),
                        preallocate,
                        initial_label: String::new(),
                    };
                    if let Ok(info_hash) = info_hash_for_source(&request.source) {
                        if is_duplicate_torrent(registry, queue, session_store, info_hash) {
                            let message = "torrent already added".to_string();
                            update_ui(ui_state, |state| {
                                state.last_error = message.clone();
                            });
                            let _ = reply.send(Err(message));
                            continue;
                        }
                    }
                    *next_id = next_id.saturating_add(1);
                    let torrent_id = request.id;
                    enqueue_request_with_label(queue, ui_state, request, "magnet link".to_string());
                    let _ = reply.send(Ok(ui::UiCommandSuccess::TorrentAdded { torrent_id }));
                }
                ui::UiCommand::PauseTorrent { torrent_id, reply } => {
                    let result = set_torrent_paused(registry, ui_state, torrent_id, true)
                        .map(|_| ui::UiCommandSuccess::Ok);
                    if let Err(err) = result.as_ref() {
                        log_warn!("pause torrent error: {err}");
                        update_ui(ui_state, |state| {
                            state.last_error = err.clone();
                        });
                    }
                    let _ = reply.send(result);
                }
                ui::UiCommand::ResumeTorrent { torrent_id, reply } => {
                    let result = set_torrent_paused(registry, ui_state, torrent_id, false)
                        .map(|_| ui::UiCommandSuccess::Ok);
                    if let Err(err) = result.as_ref() {
                        log_warn!("resume torrent error: {err}");
                        update_ui(ui_state, |state| {
                            state.last_error = err.clone();
                        });
                    }
                    let _ = reply.send(result);
                }
                ui::UiCommand::StopTorrent { torrent_id, reply } => {
                    let result = stop_torrent(registry, ui_state, queue, torrent_id, session_store)
                        .map(|_| ui::UiCommandSuccess::Ok);
                    if let Err(err) = result.as_ref() {
                        log_warn!("stop torrent error: {err}");
                        update_ui(ui_state, |state| {
                            state.last_error = err.clone();
                        });
                    }
                    let _ = reply.send(result);
                }
                ui::UiCommand::DeleteTorrent {
                    torrent_id,
                    remove_data,
                    reply,
                } => {
                    let result = delete_torrent(
                        registry,
                        ui_state,
                        queue,
                        torrent_id,
                        remove_data,
                        session_store,
                    );
                    if let Err(err) = result.as_ref() {
                        log_warn!("delete torrent error: {err}");
                        update_ui(ui_state, |state| {
                            state.last_error = err.clone();
                        });
                    }
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::SetFilePriority {
                    torrent_id,
                    file_index,
                    priority,
                    reply,
                } => {
                    let result =
                        apply_file_priority(registry, ui_state, torrent_id, file_index, priority);
                    if let Err(err) = result.as_ref() {
                        log_warn!("file priority error: {err}");
                        update_ui(ui_state, |state| {
                            state.last_error = err.clone();
                        });
                    }
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::RenameFile {
                    torrent_id,
                    file_index,
                    new_name,
                    reply,
                } => {
                    let result = apply_file_rename(registry, torrent_id, file_index, &new_name);
                    if let Err(err) = result.as_ref() {
                        log_warn!("file rename error: {err}");
                        update_ui(ui_state, |state| {
                            state.last_error = err.clone();
                        });
                    }
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::SetRateLimits {
                    download_limit_bps,
                    upload_limit_bps,
                    reply,
                } => {
                    global_down.set_limit_bps(download_limit_bps);
                    global_up.set_limit_bps(upload_limit_bps);
                    update_ui(ui_state, |state| {
                        state.global_download_limit_bps = download_limit_bps;
                        state.global_upload_limit_bps = upload_limit_bps;
                    });
                    let _ = reply.send(Ok(ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::RecheckTorrent { torrent_id, reply } => {
                    let result = recheck_torrent(registry, ui_state, torrent_id);
                    if let Err(err) = result.as_ref() {
                        log_warn!("recheck torrent error: {err}");
                        update_ui(ui_state, |state| {
                            state.last_error = err.clone();
                        });
                    }
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::SetSeedRatio { ratio, reply } => {
                    SEED_RATIO_BITS.store(ratio.to_bits(), Ordering::SeqCst);
                    update_ui(ui_state, |state| {
                        state.seed_ratio = ratio;
                    });
                    let _ = reply.send(Ok(ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::SetLabel {
                    torrent_id,
                    label,
                    reply,
                } => {
                    let result =
                        set_torrent_label(registry, ui_state, session_store, torrent_id, &label);
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::AddTracker {
                    torrent_id,
                    url,
                    reply,
                } => {
                    let result = add_torrent_tracker(registry, ui_state, torrent_id, &url);
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::RemoveTracker {
                    torrent_id,
                    url,
                    reply,
                } => {
                    let result = remove_torrent_tracker(registry, ui_state, torrent_id, &url);
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::AddRssFeed {
                    url,
                    interval,
                    reply,
                } => {
                    let result = rss_add_feed(&url, interval, &args.download_dir);
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::RemoveRssFeed { url, reply } => {
                    let result = rss_remove_feed(&url, &args.download_dir);
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::AddRssRule {
                    name,
                    feed_url,
                    pattern,
                    reply,
                } => {
                    let result = rss_add_rule(&name, &feed_url, &pattern, &args.download_dir);
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
                ui::UiCommand::RemoveRssRule { name, reply } => {
                    let result = rss_remove_rule(&name, &args.download_dir);
                    let _ = reply.send(result.map(|_| ui::UiCommandSuccess::Ok));
                }
            },
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => break,
        }
    }
}

fn is_duplicate_torrent(
    registry: &SessionRegistry,
    queue: &VecDeque<TorrentRequest>,
    session_store: &SessionStore,
    info_hash: [u8; 20],
) -> bool {
    if let Ok(guard) = registry.lock() {
        if guard.contains_key(&info_hash) {
            return true;
        }
    }
    if session_store.contains(info_hash) {
        return true;
    }
    queue.iter().any(|request| {
        info_hash_for_source(&request.source)
            .map(|hash| hash == info_hash)
            .unwrap_or(false)
    })
}

fn normalize_download_dir(value: String, fallback: &PathBuf) -> PathBuf {
    if value.trim().is_empty() {
        fallback.clone()
    } else {
        PathBuf::from(value)
    }
}

fn enqueue_request(
    queue: &mut VecDeque<TorrentRequest>,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    request: TorrentRequest,
) {
    let label = label_for_source(&request.source);
    enqueue_request_with_label(queue, ui_state, request, label);
}

fn enqueue_request_with_label(
    queue: &mut VecDeque<TorrentRequest>,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    request: TorrentRequest,
    label: String,
) {
    let id = request.id;
    let download_dir = request.download_dir.display().to_string();
    let preallocate = request.preallocate;
    queue.push_back(request);
    update_ui(ui_state, |state| {
        state.queue_len = queue.len();
        state.last_added = label.clone();
        update_torrent_entry(state, id, |torrent| {
            if torrent.name.is_empty() {
                torrent.name = label.clone();
            }
            if torrent.download_dir.is_empty() {
                torrent.download_dir = download_dir.clone();
            }
            torrent.preallocate = preallocate;
            torrent.status = "queued".to_string();
            torrent.last_error.clear();
        });
    });
}

fn label_for_source(source: &TorrentSource) -> String {
    match source {
        TorrentSource::Path(path) => PathBuf::from(path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "torrent".to_string()),
        TorrentSource::Bytes(_) => "torrent upload".to_string(),
        TorrentSource::Magnet(link) => match parse_magnet(link) {
            Ok(meta) => {
                let hash = hex(&meta.info_hash);
                let short = hash.get(0..8).unwrap_or(&hash);
                format!("magnet {short}")
            }
            Err(_) => "magnet link".to_string(),
        },
    }
}

fn update_idle_state(ui_state: &Option<Arc<Mutex<ui::UiState>>>, args: &Args, queue_len: usize) {
    update_ui(ui_state, |state| {
        if state.status.is_empty()
            || state.status == "idle"
            || state.status == "queued"
            || state.status == "waiting for torrent"
        {
            state.status = if queue_len > 0 {
                "queued".to_string()
            } else {
                "waiting for torrent".to_string()
            };
        }
        state.queue_len = queue_len;
        if queue_len == 0 && state.status == "waiting for torrent" {
            state.current_id = None;
        }
        if state.download_dir.is_empty() {
            state.download_dir = args.download_dir.display().to_string();
        }
        if state.total_pieces == 0 {
            state.preallocate = args.preallocate;
        }
    });
}

fn run_torrent(
    request: TorrentRequest,
    args: &Args,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    registry: &SessionRegistry,
    session_store: &Arc<SessionStore>,
    dht: &dht::Dht,
    lpd: &lpd::Lpd,
    utp: Option<utp::UtpConnector>,
    ip_filter: Option<Arc<IpFilter>>,
    global_down: Arc<RateLimiter>,
    global_up: Arc<RateLimiter>,
    peer_slots: Arc<PeerSlots>,
) -> Result<(), String> {
    let connect_cfg = ConnectionConfig {
        encryption: args.encryption,
        utp,
        ip_filter: ip_filter.clone(),
        proxy: args.proxy.clone(),
    };
    if args.proxy.is_some() {
        log_info!("proxy: configured, disabling DHT/UTP/UDP trackers");
    }
    let data = resolve_torrent_data(&request, args.port, dht, &connect_cfg)?;
    let meta = torrent::parse_torrent(&data).map_err(|err| format!("parse error: {err}"))?;
    let file_spans = Arc::new(build_file_spans(&meta));
    let resume_path = resume_path(&request.download_dir, meta.info_hash);
    let resume_data = load_resume_data_with_recovery(&resume_path).and_then(|data| {
        if data.info_hash == meta.info_hash {
            Some(data)
        } else {
            log_warn!(
                "resume info hash mismatch; ignoring {}",
                resume_path.display()
            );
            None
        }
    });
    let mut file_priorities = vec![piece::PRIORITY_NORMAL; file_spans.len()];
    if let Some(resume) = resume_data.as_ref() {
        if resume.file_priorities.len() == file_priorities.len() {
            file_priorities.clone_from(&resume.file_priorities);
        }
    }
    let mut pieces =
        piece::PieceManager::new(&meta).map_err(|err| format!("piece error: {err}"))?;
    pieces.set_sequential(args.sequential);
    apply_file_priorities(
        &mut pieces,
        &file_spans,
        &file_priorities,
        meta.info.piece_length,
    )
    .map_err(|err| format!("priority error: {err}"))?;
    let mut storage = storage::Storage::new(
        &meta,
        &request.download_dir,
        storage::StorageOptions {
            preallocate: request.preallocate,
            write_cache_bytes: args.write_cache_bytes,
        },
    )
    .map_err(|err| format!("storage error: {err}"))?;
    let peer_id = generate_peer_id();

    let resume = resume_from_storage(
        &mut pieces,
        &mut storage,
        meta.info.piece_length,
        &file_spans,
        &request.download_dir,
        resume_data.as_ref(),
    )
    .map_err(|err| format!("resume error: {err}"))?;
    let resume_downloaded = resume.completed_bytes.max(
        resume_data
            .as_ref()
            .map(|data| data.downloaded)
            .unwrap_or(0),
    );
    let resume_uploaded = resume_data.as_ref().map(|data| data.uploaded).unwrap_or(0);
    let torrent_down = Arc::new(RateLimiter::new(args.torrent_download_rate));
    let torrent_up = Arc::new(RateLimiter::new(args.torrent_upload_rate));
    let limits = TransferLimits {
        global_down: global_down.clone(),
        global_up: global_up.clone(),
        torrent_down,
        torrent_up,
    };

    let name = String::from_utf8_lossy(&meta.info.name).into_owned();
    session_store.upsert(
        meta.info_hash,
        name.clone(),
        data.clone(),
        &request.download_dir,
        request.preallocate,
    );
    let file_priorities = Arc::new(Mutex::new(file_priorities));
    let downloaded = Arc::new(AtomicU64::new(resume_downloaded));
    let uploaded = Arc::new(AtomicU64::new(resume_uploaded));
    let paused_flag = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::new(AtomicBool::new(false));
    let peer_queue = Arc::new(Mutex::new(PeerQueue::new(ip_filter.clone())));
    if let Some(resume) = resume_data.as_ref() {
        if !resume.peers.is_empty() {
            if let Ok(mut queue) = peer_queue.lock() {
                let restored =
                    queue.enqueue_with_source(resume.peers.iter().copied(), PeerSource::Tracker);
                if restored > 0 {
                    log_info!("restored {restored} peers from resume data");
                }
            }
        }
    }
    let ui_files = build_ui_files(
        &file_spans,
        &pieces,
        meta.info.piece_length,
        &file_priorities.lock().unwrap(),
    );
    let announce = meta
        .announce
        .as_ref()
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_else(|| "<none>".to_string());
    let trackers = collect_trackers(&meta);
    let web_seeds = collect_web_seeds(&meta);

    log_info!("name: {name}");
    log_info!("announce: {announce}");
    log_info!(
        "trackers: {} (http={}, udp={})",
        trackers.http.len() + trackers.udp.len(),
        trackers.http.len(),
        trackers.udp.len()
    );
    log_info!("piece length: {}", meta.info.piece_length);
    log_info!("pieces: {}", meta.info.pieces.len());
    let wanted_bytes = pieces.wanted_bytes();
    let wanted_pieces = pieces.wanted_pieces();
    let completed_pieces = pieces.completed_pieces();
    let completed_bytes = pieces.completed_bytes();
    log_info!("total size: {}", meta.info.total_length());
    if wanted_bytes != meta.info.total_length() {
        log_info!("wanted size: {wanted_bytes}");
    }
    log_info!("info hash: {}", hex(&meta.info_hash));
    log_info!("bitfield bytes: {}", pieces.bitfield_len());
    log_info!("files: {}", storage.file_count());
    log_info!("preallocate: {}", request.preallocate);
    log_info!("web seeds: {}", web_seeds.len());
    if completed_pieces > 0 {
        log_info!(
            "resumed: {}/{} pieces",
            completed_pieces,
            meta.info.pieces.len()
        );
    }

    let paused = torrent_paused(&paused_flag);
    update_ui(ui_state, |state| {
        state.name = name.clone();
        state.info_hash = hex(&meta.info_hash);
        state.download_dir = request.download_dir.display().to_string();
        state.total_pieces = wanted_pieces;
        state.completed_pieces = completed_pieces;
        state.total_bytes = wanted_bytes;
        state.completed_bytes = completed_bytes;
        state.downloaded_bytes = resume_downloaded;
        state.uploaded_bytes = resume_uploaded;
        state.tracker_peers = 0;
        state.status = "ready".to_string();
        state.last_error.clear();
        state.preallocate = request.preallocate;
        state.paused = is_paused();
        state.files = ui_files.clone();
        state.current_id = Some(request.id);
        update_torrent_entry(state, request.id, |torrent| {
            torrent.name = name.clone();
            torrent.info_hash = hex(&meta.info_hash);
            torrent.download_dir = request.download_dir.display().to_string();
            torrent.preallocate = request.preallocate;
            torrent.status = "ready".to_string();
            torrent.total_bytes = wanted_bytes;
            torrent.completed_bytes = completed_bytes;
            torrent.downloaded_bytes = resume_downloaded;
            torrent.uploaded_bytes = resume_uploaded;
            torrent.total_pieces = wanted_pieces;
            torrent.completed_pieces = completed_pieces;
            torrent.tracker_peers = 0;
            torrent.active_peers = 0;
            torrent.paused = paused;
            torrent.last_error.clear();
            torrent.files = ui_files.clone();
            torrent.trackers = trackers
                .http
                .iter()
                .chain(trackers.udp.iter())
                .cloned()
                .collect();
            torrent.label = request.initial_label.clone();
            torrent.meta_version = meta.meta_version;
        });
    });

    let pieces = Arc::new(Mutex::new(pieces));
    let storage = Arc::new(Mutex::new(storage));
    let completed_log = Arc::new(Mutex::new(Vec::new()));
    let peer_tags = Arc::new(AtomicU64::new(1));
    let upload_manager = Arc::new(UploadManager::new(UPLOAD_SLOTS));
    let shared_trackers = Arc::new(Mutex::new(trackers.clone()));
    let initial_renames: HashMap<usize, String> = resume_data
        .as_ref()
        .map(|r| r.file_renames.iter().cloned().collect())
        .unwrap_or_default();
    let context = Arc::new(TorrentContext {
        id: request.id,
        info_hash: meta.info_hash,
        peer_id,
        download_dir: request.download_dir.clone(),
        pieces: Arc::clone(&pieces),
        storage: Arc::clone(&storage),
        completed_log: Arc::clone(&completed_log),
        base_piece_length: meta.info.piece_length,
        file_spans: Arc::clone(&file_spans),
        file_priorities: Arc::clone(&file_priorities),
        limits: limits.clone(),
        downloaded: Arc::clone(&downloaded),
        uploaded: Arc::clone(&uploaded),
        paused: Arc::clone(&paused_flag),
        stop_requested: Arc::clone(&stop_flag),
        upload_manager: Arc::clone(&upload_manager),
        peer_tags: Arc::clone(&peer_tags),
        label: Arc::new(Mutex::new(request.initial_label.clone())),
        trackers: Arc::clone(&shared_trackers),
        throttle_group: Arc::new(Mutex::new(None)),
        ratio_group: Arc::new(Mutex::new(None)),
        file_renames: Arc::new(Mutex::new(initial_renames)),
    });
    register_session(registry, Arc::clone(&context));
    let resume_handle = start_resume_worker(
        resume_path.clone(),
        meta.info_hash,
        meta.info.piece_length,
        Arc::clone(&pieces),
        Arc::clone(&file_priorities),
        Arc::clone(&file_spans),
        request.download_dir.clone(),
        Arc::clone(&downloaded),
        Arc::clone(&uploaded),
        Arc::clone(&peer_queue),
        Arc::clone(&stop_flag),
        Arc::clone(&context.file_renames),
    );
    let webseed_handle = start_webseed_worker(
        web_seeds.clone(),
        Arc::clone(&pieces),
        Arc::clone(&storage),
        Arc::clone(&completed_log),
        Arc::clone(&file_spans),
        meta.info.piece_length,
        limits.clone(),
        Arc::clone(&downloaded),
        Arc::clone(&stop_flag),
        ui_state.clone(),
        request.id,
    );

    let has_network_sources = !trackers.http.is_empty()
        || !trackers.udp.is_empty()
        || !meta.info.private
        || !web_seeds.is_empty();
    if has_network_sources {
        let total_length = wanted_bytes;
        let mut started = true;
        let mut completed_sent = false;
        let mut interval = 1800u64; // Default to 30 minutes
        let mut last_announce = Instant::now() - Duration::from_secs(interval + 1); // Force first announce
        let mut rate_last_at = Instant::now();
        let mut last_downloaded = downloaded.load(Ordering::SeqCst);
        let mut last_uploaded = uploaded.load(Ordering::SeqCst);
        let mut down_rate = 0.0;
        let mut up_rate = 0.0;
        let mut eta_secs = 0u64;
        let has_trackers = !trackers.http.is_empty() || !trackers.udp.is_empty();
        let active_peers = Arc::new(AtomicUsize::new(0));
        let peer_tags = Arc::clone(&peer_tags);
        let torrent_id = request.id;
        let allow_pex = !meta.info.private;
        if meta.info.private {
            log_info!("private torrent: DHT/PEX/LPD disabled");
        }
        let dht_rx = if !meta.info.private {
            let (tx, rx) = mpsc::channel();
            dht.add_torrent(meta.info_hash, args.port, tx);
            Some(rx)
        } else {
            None
        };
        if let Some(rx) = dht_rx {
            let queue_clone = Arc::clone(&peer_queue);
            thread::spawn(move || {
                for peers in rx {
                    let mut queue = queue_clone.lock().unwrap();
                    queue.enqueue_with_source(peers, PeerSource::Dht);
                }
            });
        }
        let lpd_rx = if !meta.info.private {
            let (tx, rx) = mpsc::channel();
            lpd.add_torrent(meta.info_hash, args.port, tx);
            Some(rx)
        } else {
            None
        };
        if let Some(rx) = lpd_rx {
            let queue_clone = Arc::clone(&peer_queue);
            thread::spawn(move || {
                for peers in rx {
                    let mut queue = queue_clone.lock().unwrap();
                    queue.enqueue_with_source(peers, PeerSource::Lpd);
                }
            });
        }

        let mut handles = Vec::new();
        for _ in 0..args.max_peers_torrent {
            let pieces_clone = Arc::clone(&pieces);
            let storage_clone = Arc::clone(&storage);
            let completed_clone = Arc::clone(&completed_log);
            let queue_clone = Arc::clone(&peer_queue);
            let active_clone = Arc::clone(&active_peers);
            let tags_clone = Arc::clone(&peer_tags);
            let file_spans = Arc::clone(&file_spans);
            let downloaded = Arc::clone(&downloaded);
            let uploaded = Arc::clone(&uploaded);
            let upload_manager = Arc::clone(&upload_manager);
            let paused_flag = Arc::clone(&paused_flag);
            let stop_flag = Arc::clone(&stop_flag);
            let ui_clone = ui_state.clone();
            let info_hash = meta.info_hash;
            let peer_id = peer_id;
            let base_piece_length = meta.info.piece_length;
            let torrent_id = torrent_id;
            let allow_pex = allow_pex;
            let connect_cfg = connect_cfg.clone();
            let limits = limits.clone();
            let peer_slots = Arc::clone(&peer_slots);

            let handle = thread::spawn(move || {
                peer_worker_loop(
                    info_hash,
                    peer_id,
                    torrent_id,
                    &tags_clone,
                    &pieces_clone,
                    &storage_clone,
                    &completed_clone,
                    &queue_clone,
                    allow_pex,
                    &active_clone,
                    &file_spans,
                    base_piece_length,
                    connect_cfg,
                    limits,
                    &downloaded,
                    &uploaded,
                    &upload_manager,
                    &paused_flag,
                    &stop_flag,
                    peer_slots,
                    &ui_clone,
                );
            });
            handles.push(handle);
        }

        let mut seed_start: Option<Instant> = None;
        while !torrent_stop_requested(&stop_flag) {
            let (is_complete, completed_pieces, completed_bytes) = {
                let p = pieces.lock().unwrap();
                (p.is_complete(), p.completed_pieces(), p.completed_bytes())
            };
            let downloaded = downloaded.load(Ordering::SeqCst);
            let uploaded = uploaded.load(Ordering::SeqCst);
            let left = total_length.saturating_sub(completed_bytes);
            let completed_pending = is_complete && !completed_sent;
            let now = Instant::now();
            let dt = now.duration_since(rate_last_at).as_secs_f64();
            if dt >= 0.2 {
                let delta_down = downloaded.saturating_sub(last_downloaded) as f64;
                let delta_up = uploaded.saturating_sub(last_uploaded) as f64;
                let instant_down = delta_down / dt;
                let instant_up = delta_up / dt;
                down_rate = if down_rate <= 0.0 {
                    instant_down
                } else {
                    (down_rate * 0.7) + (instant_down * 0.3)
                };
                up_rate = if up_rate <= 0.0 {
                    instant_up
                } else {
                    (up_rate * 0.7) + (instant_up * 0.3)
                };
                eta_secs = if down_rate > 1.0 {
                    (left as f64 / down_rate).round() as u64
                } else {
                    0
                };
                last_downloaded = downloaded;
                last_uploaded = uploaded;
                rate_last_at = now;
            }

            let (known_count, queue_len) = {
                let q = peer_queue.lock().unwrap();
                (q.known_len(), q.len())
            };
            let active_count = active_peers.load(Ordering::SeqCst);

            // Only announce if enough time has passed OR we have no peers/low activity
            let time_since_announce = last_announce.elapsed().as_secs();
            let no_peers = active_count == 0 && queue_len == 0;
            let need_peers =
                active_count < LOW_PEER_THRESHOLD || queue_len == 0 || known_count == 0;
            let should_announce = has_trackers
                && (started
                    || completed_pending
                    || time_since_announce >= interval
                    || (need_peers && time_since_announce >= args.retry_interval)
                    || (no_peers && time_since_announce >= NO_PEER_REANNOUNCE_SECS));

            let mut last_error: Option<String> = None;
            let mut any_success = false;
            let paused = torrent_paused(&paused_flag);

            if should_announce {
                if !paused && !is_complete {
                    update_ui(ui_state, |state| {
                        state.status = "announcing".to_string();
                        update_torrent_entry(state, request.id, |torrent| {
                            torrent.status = "announcing".to_string();
                        });
                    });
                }
                let event = if started {
                    Some("started")
                } else if completed_pending {
                    Some("completed")
                } else {
                    None
                };
                log_info!("announcing to trackers...");

                let current_trackers = shared_trackers.lock().unwrap().clone();
                for tracker_url in &current_trackers.http {
                    match tracker::announce_with_private(
                        tracker_url,
                        meta.info_hash,
                        peer_id,
                        args.port,
                        uploaded,
                        downloaded,
                        left,
                        event,
                        args.numwant,
                        meta.info.private,
                    ) {
                        Ok(response) => {
                            any_success = true;
                            interval = response.interval.max(60);
                            if started {
                                log_info!("tracker interval: {}", response.interval);
                            }
                            log_info!(
                                "tracker {} returned {} peers",
                                tracker_url,
                                response.peers.len()
                            );
                            let mut queue = peer_queue.lock().unwrap();
                            queue.enqueue_with_source(response.peers, PeerSource::Tracker);
                        }
                        Err(err) => {
                            let err = format!("{tracker_url}: {err}");
                            log_warn!("tracker error: {err}");
                            last_error = Some(err);
                        }
                    }
                    if let Ok(scrape) = tracker::scrape(tracker_url, meta.info_hash) {
                        log_info!(
                            "scrape {}: {} seeders, {} leechers",
                            tracker_url,
                            scrape.seeders,
                            scrape.leechers
                        );
                    }
                }

                for tracker_url in &current_trackers.udp {
                    match udp_tracker::announce(
                        tracker_url,
                        meta.info_hash,
                        peer_id,
                        args.port,
                        uploaded,
                        downloaded,
                        left,
                        event,
                        args.numwant,
                    ) {
                        Ok(response) => {
                            any_success = true;
                            interval = response.interval.max(60);
                            if started {
                                log_info!("tracker interval: {}", response.interval);
                            }
                            log_info!(
                                "udp tracker {} returned {} peers",
                                tracker_url,
                                response.peers.len()
                            );
                            let mut queue = peer_queue.lock().unwrap();
                            queue.enqueue_with_source(response.peers, PeerSource::Tracker);
                        }
                        Err(err) => {
                            let err = format!("{tracker_url}: {err}");
                            log_warn!("udp tracker error: {err}");
                            last_error = Some(err);
                        }
                    }
                    if let Ok(scrape) = udp_tracker::scrape(tracker_url, meta.info_hash) {
                        log_info!(
                            "udp scrape {}: {} seeders, {} leechers",
                            tracker_url,
                            scrape.seeders,
                            scrape.leechers
                        );
                    }
                }
                last_announce = Instant::now();
                started = false;
                if completed_pending && any_success {
                    completed_sent = true;
                }
            }

            let (known_count, queue_len) = {
                let q = peer_queue.lock().unwrap();
                (q.known_len(), q.len())
            };

            let torrent_status = if paused {
                "paused"
            } else if is_complete {
                "seeding"
            } else if should_announce && !any_success {
                "error"
            } else if active_count == 0 && queue_len == 0 {
                "waiting for peers"
            } else {
                "downloading"
            };
            update_ui(ui_state, |state| {
                set_torrent_completion_ui(state, request.id, completed_pieces, completed_bytes);
                if state.current_id == Some(request.id) {
                    state.tracker_peers = known_count;
                    state.paused = is_paused();
                    state.downloaded_bytes = downloaded;
                    state.uploaded_bytes = uploaded;
                    state.status = torrent_status.to_string();
                    if let Some(err) = &last_error {
                        state.last_error = err.clone();
                    }
                }
                let last_error = last_error.clone();
                update_torrent_entry(state, request.id, |torrent| {
                    torrent.tracker_peers = known_count;
                    torrent.active_peers = active_count;
                    torrent.paused = paused;
                    torrent.status = torrent_status.to_string();
                    torrent.completed_pieces = completed_pieces;
                    torrent.completed_bytes = completed_bytes;
                    torrent.downloaded_bytes = downloaded;
                    torrent.uploaded_bytes = uploaded;
                    torrent.download_rate_bps = down_rate;
                    torrent.upload_rate_bps = up_rate;
                    torrent.eta_secs = eta_secs;
                    if let Some(err) = last_error {
                        torrent.last_error = err;
                    }
                });
            });

            // Max seed time check
            if is_complete {
                if seed_start.is_none() {
                    seed_start = Some(Instant::now());
                }
                if let Some(start) = seed_start {
                    let max = MAX_SEED_TIME_SECS.load(Ordering::SeqCst);
                    if max > 0 && start.elapsed().as_secs() >= max {
                        log_info!("max seed time reached, stopping");
                        stop_flag.store(true, Ordering::SeqCst);
                    }
                }
                // Check ratio group
                let rg = context.ratio_group.lock().unwrap().clone();
                check_ratio_group(
                    &rg,
                    &context.uploaded,
                    &context.downloaded,
                    &stop_flag,
                    &paused_flag,
                );
            }

            sleep_with_shutdown_or_stop(Duration::from_secs(1), &stop_flag);
        }

        if has_trackers {
            let completed_bytes = {
                let p = pieces.lock().unwrap();
                p.completed_bytes()
            };
            let downloaded = downloaded.load(Ordering::SeqCst);
            let uploaded = uploaded.load(Ordering::SeqCst);
            let left = total_length.saturating_sub(completed_bytes);
            let stop_trackers = shared_trackers.lock().unwrap().clone();
            log_info!("sending tracker stopped event...");
            for tracker_url in &stop_trackers.http {
                let _ = tracker::announce_with_private(
                    tracker_url,
                    meta.info_hash,
                    peer_id,
                    args.port,
                    uploaded,
                    downloaded,
                    left,
                    Some("stopped"),
                    args.numwant,
                    meta.info.private,
                );
            }
            for tracker_url in &stop_trackers.udp {
                let _ = udp_tracker::announce(
                    tracker_url,
                    meta.info_hash,
                    peer_id,
                    args.port,
                    uploaded,
                    downloaded,
                    left,
                    Some("stopped"),
                    args.numwant,
                );
            }
        }

        for handle in handles {
            let _ = handle.join();
        }
    }

    if let Some(handle) = webseed_handle {
        let _ = handle.join();
    }

    let _ = resume_handle.join();

    let finished_complete = {
        let p = pieces.lock().unwrap();
        p.is_complete()
    };
    let finished_status = if shutdown_requested() {
        "shutdown"
    } else if stop_flag.load(Ordering::SeqCst) {
        "stopped"
    } else if finished_complete {
        "complete"
    } else {
        "stopped"
    };
    let paused = torrent_paused(&paused_flag);
    update_ui(ui_state, |state| {
        if state.current_id == Some(request.id) {
            state.status = finished_status.to_string();
            state.paused = is_paused();
            state.current_id = None;
        }
        update_torrent_entry(state, request.id, |torrent| {
            torrent.status = finished_status.to_string();
            torrent.paused = paused;
        });
    });

    if finished_complete {
        if let Some(dest) = args.move_completed.as_ref() {
            move_completed_files(&meta, &request.download_dir, dest);
        }
        if let Some(script) = ON_COMPLETE_SCRIPT.get() {
            let script = script.clone();
            let torrent_name = name.clone();
            let torrent_dir = request.download_dir.display().to_string();
            let torrent_hash = hex(&meta.info_hash);
            let torrent_size = meta.info.total_length();
            thread::spawn(move || {
                match std::process::Command::new(&script)
                    .env("TORRENT_NAME", &torrent_name)
                    .env("TORRENT_DIR", &torrent_dir)
                    .env("TORRENT_HASH", &torrent_hash)
                    .env("TORRENT_SIZE", torrent_size.to_string())
                    .output()
                {
                    Ok(out) => {
                        if !out.status.success() {
                            log_warn!("on-complete script exited {}", out.status);
                        }
                    }
                    Err(err) => {
                        log_warn!("on-complete script error: {err}");
                    }
                }
            });
        }
    }

    if !meta.info.private {
        dht.remove_torrent(meta.info_hash);
        lpd.remove_torrent(meta.info_hash);
    }
    unregister_session(registry, meta.info_hash);

    Ok(())
}

fn resolve_torrent_data(
    request: &TorrentRequest,
    port: u16,
    dht: &dht::Dht,
    connect_cfg: &ConnectionConfig,
) -> Result<Vec<u8>, String> {
    let data = match &request.source {
        TorrentSource::Path(path) => {
            fs::read(path).map_err(|err| format!("failed to read {}: {err}", path))?
        }
        TorrentSource::Bytes(data) => data.clone(),
        TorrentSource::Magnet(link) => fetch_torrent_from_magnet(link, port, dht, connect_cfg)?,
    };
    if data.len() > MAX_TORRENT_BYTES {
        return Err("torrent file too large".to_string());
    }
    Ok(data)
}

struct MagnetMeta {
    info_hash: [u8; 20],
    info_hash_v2: Option<[u8; 32]>,
    sources: Vec<String>,
    trackers: Vec<String>,
    web_seeds: Vec<String>,
    peers: Vec<SocketAddr>,
}

fn fetch_torrent_from_magnet(
    link: &str,
    port: u16,
    dht: &dht::Dht,
    connect_cfg: &ConnectionConfig,
) -> Result<Vec<u8>, String> {
    let meta = parse_magnet(link)?;
    let deadline = Instant::now() + METADATA_TOTAL_TIMEOUT;
    let hash = hex(&meta.info_hash);
    log_info!(
        "magnet: info_hash={} trackers={} sources={} web_seeds={} peers={}",
        hash,
        meta.trackers.len(),
        meta.sources.len(),
        meta.web_seeds.len(),
        meta.peers.len()
    );
    for (idx, tracker) in meta.trackers.iter().enumerate() {
        log_info!("magnet: tracker[{idx}]={tracker}");
    }
    for (idx, source) in meta.sources.iter().enumerate() {
        log_info!("magnet: source[{idx}]={source}");
    }
    for (idx, seed) in meta.web_seeds.iter().enumerate() {
        log_info!("magnet: webseed[{idx}]={seed}");
    }
    for (idx, peer) in meta.peers.iter().enumerate() {
        log_info!("magnet: peer[{idx}]={peer}");
    }
    let mut source_err: Option<String> = None;
    let mut metadata_err: Option<String> = None;
    for source in &meta.sources {
        log_info!("magnet: fetching source {source}");
        match http::get(source, MAX_TORRENT_BYTES) {
            Ok(data) => {
                log_info!("magnet: source fetch ok ({source})");
                return Ok(data);
            }
            Err(err) => {
                log_warn!("magnet: source fetch failed ({source}): {err}");
                if source_err.is_none() {
                    source_err = Some(err);
                }
            }
        }
    }
    let info_hash = hash;
    for base in MAGNET_CACHE_URLS {
        let url = format!("{base}{info_hash}.torrent");
        log_info!("magnet: fetching cache {url}");
        match http::get(&url, MAX_TORRENT_BYTES) {
            Ok(data) => {
                log_info!("magnet: cache fetch ok ({url})");
                return Ok(data);
            }
            Err(err) => {
                log_warn!("magnet: cache fetch failed ({url}): {err}");
                if source_err.is_none() {
                    source_err = Some(err);
                }
            }
        }
    }
    if !meta.peers.is_empty() {
        let peer_id = generate_peer_id();
        log_info!("magnet: fetching metadata from explicit peers");
        for addr in &meta.peers {
            if Instant::now() >= deadline {
                break;
            }
            log_info!("metadata: trying explicit peer {addr}");
            match fetch_metadata_from_peer(*addr, meta.info_hash, peer_id, deadline, connect_cfg) {
                Ok(info_bytes) => {
                    log_info!("metadata: explicit peer {addr} delivered metadata");
                    let data = wrap_torrent_with_info(&info_bytes, &meta.trackers, &meta.web_seeds);
                    return Ok(data);
                }
                Err(err) => {
                    log_warn!("metadata: explicit peer {addr} failed: {err}");
                    if metadata_err.is_none() {
                        metadata_err = Some(err);
                    }
                }
            }
        }
    }
    if !meta.trackers.is_empty() {
        let peer_id = generate_peer_id();
        log_info!("magnet: fetching metadata from trackers");
        match fetch_metadata_from_trackers(
            meta.info_hash,
            peer_id,
            port,
            &meta.trackers,
            deadline,
            connect_cfg,
        ) {
            Ok(info_bytes) => {
                log_info!("magnet: metadata fetched from trackers");
                let data = wrap_torrent_with_info(&info_bytes, &meta.trackers, &meta.web_seeds);
                return Ok(data);
            }
            Err(err) => {
                log_warn!("magnet: tracker metadata failed: {err}");
                if metadata_err.is_none() {
                    metadata_err = Some(err);
                }
            }
        }
    }
    let peer_id = generate_peer_id();
    log_info!("magnet: fetching metadata from dht");
    match fetch_metadata_from_dht(meta.info_hash, peer_id, port, deadline, dht, connect_cfg) {
        Ok(info_bytes) => {
            log_info!("magnet: metadata fetched from dht");
            let data = wrap_torrent_with_info(&info_bytes, &meta.trackers, &meta.web_seeds);
            return Ok(data);
        }
        Err(err) => {
            log_warn!("magnet: dht metadata failed: {err}");
            if metadata_err.is_none() {
                metadata_err = Some(err);
            }
        }
    }
    if let Some(err) = metadata_err {
        return Err(err);
    }
    Err(source_err
        .unwrap_or_else(|| "magnet metadata not found (no sources, caches, or peers)".to_string()))
}

fn parse_magnet(link: &str) -> Result<MagnetMeta, String> {
    let trimmed = link.trim();
    let query = trimmed
        .strip_prefix("magnet:?")
        .ok_or_else(|| "invalid magnet link".to_string())?;
    let mut info_hash: Option<[u8; 20]> = None;
    let mut info_hash_v2: Option<[u8; 32]> = None;
    let mut sources = Vec::new();
    let mut trackers = Vec::new();
    let mut web_seeds = Vec::new();
    let mut peers = Vec::new();
    for (key, value) in parse_query_pairs(query) {
        match key.as_str() {
            "xt" => {
                let lower = value.to_ascii_lowercase();
                if let Some(rest) = lower.strip_prefix("urn:btih:") {
                    info_hash = parse_info_hash(rest);
                } else if let Some(rest) = lower.strip_prefix("urn:btmh:") {
                    if let Some(hash) = parse_multihash_sha256(rest) {
                        if info_hash.is_none() {
                            let mut truncated = [0u8; 20];
                            truncated.copy_from_slice(&hash[..20]);
                            info_hash = Some(truncated);
                        }
                        info_hash_v2 = Some(hash);
                    }
                }
            }
            "xs" | "as" => {
                if !value.is_empty() {
                    sources.push(value);
                }
            }
            "tr" => {
                if !value.is_empty() {
                    trackers.push(value);
                }
            }
            "ws" => {
                if !value.is_empty() {
                    web_seeds.push(value);
                }
            }
            "x.pe" => {
                if let Ok(addr) = value.parse::<SocketAddr>() {
                    peers.push(addr);
                }
            }
            _ => {}
        }
    }
    let info_hash = info_hash.ok_or_else(|| "magnet missing info hash".to_string())?;
    Ok(MagnetMeta {
        info_hash,
        info_hash_v2,
        sources,
        trackers,
        web_seeds,
        peers,
    })
}

fn parse_info_hash(value: &str) -> Option<[u8; 20]> {
    let value = value.trim();
    if value.len() == 40 {
        decode_hex_20(value)
    } else if value.len() == 32 {
        decode_base32_20(value)
    } else {
        None
    }
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

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)? as u8;
        let lo = (chunk[1] as char).to_digit(16)? as u8;
        out[idx] = (hi << 4) | lo;
    }
    Some(out)
}

fn parse_multihash_sha256(value: &str) -> Option<[u8; 32]> {
    // Multihash format: 1220<64 hex chars>
    // 12 = SHA-256 function code, 20 = 32 bytes (0x20) digest length
    let rest = value.strip_prefix("1220")?;
    decode_hex_32(rest)
}

fn decode_base32_20(value: &str) -> Option<[u8; 20]> {
    let mut out = Vec::with_capacity(20);
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;
    for ch in value.chars() {
        if ch == '=' {
            break;
        }
        let val = base32_value(ch)?;
        buffer = (buffer << 5) | (val as u32);
        bits = bits.saturating_add(5);
        while bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if out.len() != 20 {
        return None;
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&out);
    Some(arr)
}

fn base32_value(ch: char) -> Option<u8> {
    let ch = ch.to_ascii_uppercase();
    match ch {
        'A'..='Z' => Some((ch as u8) - b'A'),
        '2'..='7' => Some((ch as u8) - b'2' + 26),
        _ => None,
    }
}

fn fetch_metadata_from_trackers(
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    trackers: &[String],
    deadline: Instant,
    connect_cfg: &ConnectionConfig,
) -> Result<Vec<u8>, String> {
    log_info!(
        "metadata: tracker announce start (trackers={}, deadline={}s)",
        trackers.len(),
        deadline.saturating_duration_since(Instant::now()).as_secs()
    );
    let mut peers = Vec::new();
    let mut last_err: Option<String> = None;
    for tracker_url in trackers {
        if tracker_url.starts_with("udp://") {
            log_info!("metadata: udp tracker announce {tracker_url}");
            match udp_tracker::announce(
                tracker_url,
                info_hash,
                peer_id,
                port,
                0,
                0,
                1,
                Some("started"),
                METADATA_PEER_LIMIT as u32,
            ) {
                Ok(response) => {
                    log_info!(
                        "metadata: udp tracker {tracker_url} returned {} peers",
                        response.peers.len()
                    );
                    peers.extend(response.peers)
                }
                Err(err) => last_err = Some(format!("{tracker_url}: {err}")),
            }
        } else {
            log_info!("metadata: http tracker announce {tracker_url}");
            match tracker::announce(
                tracker_url,
                info_hash,
                peer_id,
                port,
                0,
                0,
                1,
                Some("started"),
                METADATA_PEER_LIMIT as u32,
            ) {
                Ok(response) => {
                    log_info!(
                        "metadata: http tracker {tracker_url} returned {} peers",
                        response.peers.len()
                    );
                    peers.extend(response.peers);
                }
                Err(err) => {
                    last_err = Some(format!("{tracker_url}: {err}"));
                }
            }
        }
    }

    let mut unique = Vec::new();
    let mut seen = HashSet::new();
    for peer in peers {
        if seen.insert(peer) {
            unique.push(peer);
            if unique.len() >= METADATA_PEER_LIMIT {
                break;
            }
        }
    }
    if unique.is_empty() {
        return Err(last_err.unwrap_or_else(|| "no peers returned for magnet".to_string()));
    }
    log_info!("metadata: {} unique peers from trackers", unique.len());

    for addr in unique {
        if Instant::now() >= deadline {
            break;
        }
        log_info!("metadata: trying peer {addr}");
        match fetch_metadata_from_peer(addr, info_hash, peer_id, deadline, connect_cfg) {
            Ok(data) => {
                log_info!("metadata: peer {addr} delivered metadata");
                return Ok(data);
            }
            Err(err) => {
                log_warn!("metadata: peer {addr} failed: {err}");
                last_err = Some(err)
            }
        }
    }

    Err(last_err.unwrap_or_else(|| "metadata fetch timed out".to_string()))
}

fn fetch_metadata_from_dht(
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    port: u16,
    deadline: Instant,
    dht: &dht::Dht,
    connect_cfg: &ConnectionConfig,
) -> Result<Vec<u8>, String> {
    if !cfg!(feature = "dht") {
        let _ = dht;
        return Err("dht disabled".to_string());
    }
    if Instant::now() >= deadline {
        return Err("metadata fetch timed out".to_string());
    }
    let (tx, rx) = mpsc::channel();
    log_info!("metadata: dht add torrent for discovery");
    dht.add_torrent(info_hash, port, tx);
    let mut last_err: Option<String> = None;
    let mut queue = VecDeque::new();
    let mut seen = HashSet::new();
    let mut result: Option<Vec<u8>> = None;
    let mut total_seen = 0usize;

    while Instant::now() < deadline {
        if shutdown_requested() {
            last_err = Some("shutdown requested".to_string());
            break;
        }

        while let Some(addr) = queue.pop_front() {
            if Instant::now() >= deadline {
                break;
            }
            log_info!("metadata: trying dht peer {addr}");
            match fetch_metadata_from_peer(addr, info_hash, peer_id, deadline, connect_cfg) {
                Ok(data) => {
                    log_info!("metadata: dht peer {addr} delivered metadata");
                    result = Some(data);
                    break;
                }
                Err(err) => {
                    log_warn!("metadata: dht peer {addr} failed: {err}");
                    last_err = Some(err)
                }
            }
        }

        if result.is_some() {
            break;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait = remaining.min(Duration::from_millis(500));
        if wait.is_zero() {
            break;
        }
        match rx.recv_timeout(wait) {
            Ok(peers) => {
                if !peers.is_empty() {
                    log_info!("metadata: dht peers received batch size={}", peers.len());
                }
                for peer in peers {
                    if seen.len() >= METADATA_PEER_LIMIT {
                        break;
                    }
                    if seen.insert(peer) {
                        total_seen += 1;
                        queue.push_back(peer);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    dht.remove_torrent(info_hash);
    log_info!("metadata: dht done (peers_seen={total_seen})");
    if let Some(data) = result {
        return Ok(data);
    }
    Err(last_err.unwrap_or_else(|| "metadata fetch timed out".to_string()))
}

fn fetch_metadata_from_peer(
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    deadline: Instant,
    connect_cfg: &ConnectionConfig,
) -> Result<Vec<u8>, String> {
    log_info!(
        "metadata: peer {addr} connect (deadline={}s)",
        deadline.saturating_duration_since(Instant::now()).as_secs()
    );
    let mut stream = connect_peer_for_metadata(addr, connect_cfg)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("read timeout failed: {err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("write timeout failed: {err}"))?;

    let handshake = if connect_cfg.encryption == EncryptionMode::Require {
        outbound_handshake(&mut stream, info_hash, peer_id, connect_cfg.encryption)?
    } else {
        match plaintext_handshake(&mut stream, info_hash, peer_id) {
            Ok(handshake) => handshake,
            Err(_err) if connect_cfg.encryption == EncryptionMode::Prefer => {
                let mut retry = connect_peer_for_metadata(addr, connect_cfg)?;
                retry
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|err| format!("read timeout failed: {err}"))?;
                retry
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .map_err(|err| format!("write timeout failed: {err}"))?;
                let handshake =
                    outbound_handshake(&mut retry, info_hash, peer_id, EncryptionMode::Prefer)?;
                stream = retry;
                handshake
            }
            Err(err) => return Err(format!("handshake failed: {err}")),
        }
    };
    if !handshake.supports_extensions() {
        return Err("peer does not support extensions".to_string());
    }
    log_info!("metadata: peer {addr} handshake ok, extensions supported");

    let ext_handshake = build_ext_handshake(None, false);
    peer::write_message(
        &mut stream,
        &peer::Message::Extended {
            ext_id: 0,
            payload: ext_handshake,
        },
    )
    .map_err(|err| format!("ext handshake failed: {err}"))?;
    let _ = peer::write_message(&mut stream, &peer::Message::Interested);

    let start = Instant::now();
    let mut reader = peer::MessageReader::new();
    let mut ut_metadata_id: Option<u8> = None;
    let mut metadata_size: Option<usize> = None;
    let mut pieces: Vec<Option<Vec<u8>>> = Vec::new();
    let mut requested = HashSet::new();
    let mut fallback_sent = false;
    let mut fallback_used = false;
    let mut received = 0usize;
    let mut last_progress_log = 0usize;
    let mut requested_any = false;
    let mut last_progress = Instant::now();
    let mut last_request = Instant::now() - METADATA_REQUEST_RETRY;
    let mut last_receive = Instant::now();

    while start.elapsed() < METADATA_FETCH_TIMEOUT && Instant::now() < deadline {
        if shutdown_requested() {
            return Err("shutdown requested".to_string());
        }
        match reader.read_message(&mut stream) {
            Ok(Some(message)) => {
                log_debug!("metadata: peer {addr} msg {}", message_summary(&message));
                match message {
                    peer::Message::Extended { ext_id, payload } => {
                        if ext_id == 0 {
                            let (ut_id, _ut_pex, size) = parse_extended_handshake(&payload)?;
                            if let Some(id) = ut_id {
                                if ut_metadata_id != Some(id) {
                                    ut_metadata_id = Some(id);
                                    if fallback_used {
                                        requested.clear();
                                        last_request = Instant::now() - METADATA_REQUEST_RETRY;
                                    }
                                    log_info!("metadata: peer {addr} ut_metadata id={id}");
                                }
                            }
                            if let Some(size) = size {
                                if metadata_size.is_none() {
                                    metadata_size = Some(size);
                                    pieces = vec![None; metadata_piece_count(size)];
                                    log_info!(
                                        "metadata: peer {addr} metadata_size={size} pieces={}",
                                        pieces.len()
                                    );
                                }
                            }
                            if let Some(id) = ut_metadata_id {
                                let sent = request_metadata_pieces(
                                    &mut stream,
                                    id,
                                    &pieces,
                                    &mut requested,
                                    false,
                                )?;
                                if sent > 0 {
                                    if !requested_any {
                                        requested_any = true;
                                        last_progress = Instant::now();
                                    }
                                    log_info!("metadata: peer {addr} requesting {sent} pieces");
                                    last_request = Instant::now();
                                }
                            }
                        } else {
                            let msg = match parse_metadata_message(&payload) {
                                Ok(msg) => msg,
                                Err(_) => {
                                    continue;
                                }
                            };
                            if Some(ext_id) != ut_metadata_id {
                                log_info!("metadata: peer {addr} ut_metadata override id={ext_id}");
                                ut_metadata_id = Some(ext_id);
                                requested.clear();
                                last_request = Instant::now() - METADATA_REQUEST_RETRY;
                            }
                            if msg.msg_type == 2 {
                                log_warn!("metadata: peer {addr} rejected piece {}", msg.piece);
                                return Err("metadata rejected".to_string());
                            }
                            if msg.msg_type == 1 {
                                if metadata_size.is_none() {
                                    if let Some(total) = msg.total_size {
                                        metadata_size = Some(total);
                                        pieces = vec![None; metadata_piece_count(total)];
                                        log_info!(
                                            "metadata: peer {addr} metadata_size={total} pieces={}",
                                            pieces.len()
                                        );
                                        if let Some(id) = ut_metadata_id {
                                            let sent = request_metadata_pieces(
                                                &mut stream,
                                                id,
                                                &pieces,
                                                &mut requested,
                                                false,
                                            )?;
                                            if sent > 0 {
                                                if !requested_any {
                                                    requested_any = true;
                                                    last_progress = Instant::now();
                                                }
                                                log_info!(
                                            "metadata: peer {addr} requesting {sent} pieces"
                                        );
                                                last_request = Instant::now();
                                            }
                                        }
                                    }
                                }
                                if !pieces.is_empty() {
                                    let idx = msg.piece as usize;
                                    if idx < pieces.len() && pieces[idx].is_none() {
                                        pieces[idx] = Some(msg.data);
                                        received += 1;
                                        last_receive = Instant::now();
                                        last_progress = Instant::now();
                                        if received == 1
                                            || received == pieces.len()
                                            || received - last_progress_log >= 5
                                        {
                                            last_progress_log = received;
                                            log_info!(
                                                "metadata: peer {addr} received {}/{} pieces",
                                                received,
                                                pieces.len()
                                            );
                                        }
                                    }
                                }
                                if let Some(total) = metadata_size {
                                    if pieces.iter().all(|piece| piece.is_some()) {
                                        let info = assemble_metadata(&pieces, total);
                                        let actual = sha1::sha1(&info);
                                        if actual != info_hash {
                                            log_warn!(
                                                "metadata: peer {addr} metadata hash mismatch"
                                            );
                                            return Err("metadata hash mismatch".to_string());
                                        }
                                        log_info!("metadata: peer {addr} metadata hash ok");
                                        return Ok(info);
                                    }
                                }
                            }
                        }
                    }
                    peer::Message::Unchoke => {
                        if let Some(id) = ut_metadata_id {
                            let sent = request_metadata_pieces(
                                &mut stream,
                                id,
                                &pieces,
                                &mut requested,
                                true,
                            )?;
                            if sent > 0 {
                                if !requested_any {
                                    requested_any = true;
                                    last_progress = Instant::now();
                                }
                                log_info!("metadata: peer {addr} re-requesting {sent} pieces");
                                last_request = Instant::now();
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(None) => continue,
            Err(err) => return Err(format!("message read failed: {err}")),
        }

        if ut_metadata_id.is_none() && !fallback_sent && start.elapsed() >= Duration::from_secs(1) {
            ut_metadata_id = Some(1);
            if requested.insert(0usize) {
                log_info!("metadata: peer {addr} fallback ut_metadata=1 request piece 0");
                let _ = send_metadata_request(&mut stream, 1, 0);
                last_request = Instant::now();
                if !requested_any {
                    requested_any = true;
                    last_progress = Instant::now();
                }
            }
            fallback_sent = true;
            fallback_used = true;
        }

        if let Some(id) = ut_metadata_id {
            let complete = !pieces.is_empty() && pieces.iter().all(|piece| piece.is_some());
            if !complete
                && last_receive.elapsed() >= METADATA_REQUEST_RETRY
                && last_request.elapsed() >= METADATA_REQUEST_RETRY
            {
                let sent = request_metadata_pieces(&mut stream, id, &pieces, &mut requested, true)?;
                if sent > 0 {
                    if !requested_any {
                        requested_any = true;
                        last_progress = Instant::now();
                    }
                    log_info!("metadata: peer {addr} re-requesting {sent} pieces");
                    last_request = Instant::now();
                }
            }
        }

        if requested_any && last_progress.elapsed() >= METADATA_PEER_IDLE_TIMEOUT {
            return Err("metadata peer stalled".to_string());
        }
    }

    if let Some(total) = metadata_size {
        log_warn!("metadata: peer {addr} timeout (received {received}/{total} bytes?)");
    } else {
        log_warn!("metadata: peer {addr} timeout (no metadata size)");
    }
    Err("metadata fetch timed out".to_string())
}

fn metadata_piece_count(total: usize) -> usize {
    (total + METADATA_PIECE_LEN - 1) / METADATA_PIECE_LEN
}

fn build_ext_handshake(metadata_size: Option<usize>, allow_pex: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(b'd');
    out.extend_from_slice(b"1:m");
    out.push(b'd');
    out.extend_from_slice(b"11:ut_metadatai1e");
    if allow_pex {
        out.extend_from_slice(b"6:ut_pexi2e");
    }
    out.push(b'e');
    if let Some(size) = metadata_size {
        out.extend_from_slice(b"13:metadata_sizei");
        out.extend_from_slice(size.to_string().as_bytes());
        out.push(b'e');
    }
    out.push(b'e');
    out
}

fn send_metadata_request<W: Write>(
    stream: &mut W,
    ut_metadata_id: u8,
    piece: u32,
) -> Result<(), String> {
    log_debug!(
        "metadata: request piece {} (ext_id={})",
        piece,
        ut_metadata_id
    );
    let mut payload = Vec::with_capacity(32);
    payload.extend_from_slice(b"d8:msg_typei0e5:piecei");
    payload.extend_from_slice(piece.to_string().as_bytes());
    payload.extend_from_slice(b"ee");
    peer::write_message(
        stream,
        &peer::Message::Extended {
            ext_id: ut_metadata_id,
            payload,
        },
    )
    .map_err(|err| format!("metadata request failed: {err}"))
}

fn request_metadata_pieces<W: Write>(
    stream: &mut W,
    ut_metadata_id: u8,
    pieces: &[Option<Vec<u8>>],
    requested: &mut HashSet<usize>,
    force: bool,
) -> Result<usize, String> {
    let mut sent = 0usize;
    if pieces.is_empty() {
        if force || requested.insert(0) {
            send_metadata_request(stream, ut_metadata_id, 0)?;
            sent += 1;
        }
        return Ok(sent);
    }
    for (idx, piece) in pieces.iter().enumerate() {
        if piece.is_some() {
            continue;
        }
        if !force && !requested.insert(idx) {
            continue;
        }
        if force {
            requested.insert(idx);
        }
        send_metadata_request(stream, ut_metadata_id, idx as u32)?;
        sent += 1;
    }
    Ok(sent)
}

fn parse_extended_handshake(
    payload: &[u8],
) -> Result<(Option<u8>, Option<u8>, Option<usize>), String> {
    let (dict, _) = parse_bencode_dict(payload)?;
    let mut ut_metadata = None;
    let mut ut_pex = None;
    let mut metadata_size = None;
    if let Some(Value::Dict(items)) = dict_get(&dict, b"m") {
        for (key, value) in items {
            if key == b"ut_metadata" {
                if let Value::Int(id) = value {
                    if *id >= 0 && *id <= u8::MAX as i64 {
                        ut_metadata = Some(*id as u8);
                    }
                }
            } else if key == b"ut_pex" {
                if let Value::Int(id) = value {
                    if *id >= 0 && *id <= u8::MAX as i64 {
                        ut_pex = Some(*id as u8);
                    }
                }
            }
        }
    }
    if let Some(Value::Int(size)) = dict_get(&dict, b"metadata_size") {
        if *size > 0 {
            metadata_size = Some(*size as usize);
        }
    }
    Ok((ut_metadata, ut_pex, metadata_size))
}

struct MetadataMessage {
    msg_type: u8,
    piece: u32,
    total_size: Option<usize>,
    data: Vec<u8>,
}

fn parse_metadata_message(payload: &[u8]) -> Result<MetadataMessage, String> {
    let (dict, used) = parse_bencode_dict(payload)?;
    let msg_type = dict_get_int(&dict, b"msg_type").unwrap_or(-1);
    let piece = dict_get_int(&dict, b"piece").unwrap_or(-1);
    if msg_type < 0 || piece < 0 {
        return Err("invalid metadata message".to_string());
    }
    let total_size = dict_get_int(&dict, b"total_size").and_then(|size| {
        if size > 0 {
            Some(size as usize)
        } else {
            None
        }
    });
    let data = if msg_type == 1 {
        payload[used..].to_vec()
    } else {
        Vec::new()
    };
    Ok(MetadataMessage {
        msg_type: msg_type as u8,
        piece: piece as u32,
        total_size,
        data,
    })
}

fn parse_bencode_dict(data: &[u8]) -> Result<(Vec<(Vec<u8>, Value)>, usize), String> {
    let (value, used) = bencode::parse_value(data, 0).map_err(|err| err.to_string())?;
    match value {
        Value::Dict(items) => Ok((items, used)),
        _ => Err("expected dict".to_string()),
    }
}

fn dict_get<'a>(dict: &'a [(Vec<u8>, Value)], key: &[u8]) -> Option<&'a Value> {
    dict.iter()
        .find_map(|(k, v)| if k.as_slice() == key { Some(v) } else { None })
}

fn dict_get_int(dict: &[(Vec<u8>, Value)], key: &[u8]) -> Option<i64> {
    match dict_get(dict, key) {
        Some(Value::Int(num)) => Some(*num),
        _ => None,
    }
}

fn assemble_metadata(pieces: &[Option<Vec<u8>>], total: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(total);
    for piece in pieces.iter().flatten() {
        out.extend_from_slice(piece);
    }
    out.truncate(total);
    out
}

fn wrap_torrent_with_info(info: &[u8], trackers: &[String], web_seeds: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(info.len() + 128);
    out.push(b'd');
    if !trackers.is_empty() {
        out.extend_from_slice(b"8:announce");
        bencode_bytes(trackers[0].as_bytes(), &mut out);
        out.extend_from_slice(b"13:announce-list");
        out.push(b'l');
        for tracker in trackers {
            out.push(b'l');
            bencode_bytes(tracker.as_bytes(), &mut out);
            out.push(b'e');
        }
        out.push(b'e');
    }
    if !web_seeds.is_empty() {
        out.extend_from_slice(b"8:url-list");
        out.push(b'l');
        for seed in web_seeds {
            bencode_bytes(seed.as_bytes(), &mut out);
        }
        out.push(b'e');
    }
    out.extend_from_slice(b"4:info");
    out.extend_from_slice(info);
    out.push(b'e');
    out
}

fn bencode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(bytes.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(bytes);
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

struct PeerQueue {
    known: HashSet<SocketAddr>,
    queued: HashSet<SocketAddr>,
    inflight: HashSet<SocketAddr>,
    queue: VecDeque<SocketAddr>,
    deferred: VecDeque<DeferredPeer>,
    failures: HashMap<SocketAddr, u32>,
    banned: HashMap<SocketAddr, Instant>,
    filter: Option<Arc<IpFilter>>,
}

enum PeerSource {
    Tracker,
    Dht,
    Lpd,
    Pex,
}

struct DeferredPeer {
    addr: SocketAddr,
    ready_at: Instant,
}

impl PeerQueue {
    fn new(filter: Option<Arc<IpFilter>>) -> Self {
        Self {
            known: HashSet::new(),
            queued: HashSet::new(),
            inflight: HashSet::new(),
            queue: VecDeque::new(),
            deferred: VecDeque::new(),
            failures: HashMap::new(),
            banned: HashMap::new(),
            filter,
        }
    }

    fn enqueue_with_source<I: IntoIterator<Item = SocketAddr>>(
        &mut self,
        peers: I,
        source: PeerSource,
    ) -> usize {
        let mut added = 0usize;
        let high_priority = matches!(source, PeerSource::Tracker);
        for addr in peers {
            if self.is_filtered(addr) {
                continue;
            }
            if self.is_banned(addr) {
                continue;
            }
            self.known.insert(addr);
            if self.queued.contains(&addr) || self.inflight.contains(&addr) {
                continue;
            }
            if self.is_deferred(addr) {
                continue;
            }
            if let Some(delay) = self.delay_for_failure(addr) {
                self.schedule_retry(addr, delay);
                continue;
            }
            self.queued.insert(addr);
            if high_priority {
                self.queue.push_front(addr);
            } else {
                self.queue.push_back(addr);
            }
            added += 1;
        }
        added
    }

    fn pop(&mut self) -> Option<SocketAddr> {
        self.promote_ready();
        while let Some(addr) = self.queue.pop_front() {
            if self.is_filtered(addr) || self.is_banned(addr) {
                self.queued.remove(&addr);
                continue;
            }
            self.queued.remove(&addr);
            self.inflight.insert(addr);
            return Some(addr);
        }
        None
    }

    fn finish(&mut self, addr: SocketAddr) {
        self.inflight.remove(&addr);
    }

    fn note_failure(&mut self, addr: SocketAddr) -> Option<Duration> {
        let attempts = self.failures.entry(addr).or_insert(0);
        *attempts = attempts.saturating_add(1);
        if *attempts >= MAX_PEER_RETRIES {
            let until = Instant::now() + Duration::from_secs(PEER_BAN_SECS);
            self.banned.insert(addr, until);
            return None;
        }
        let delay = PEER_RETRY_BASE_SECS.saturating_mul(*attempts as u64);
        Some(Duration::from_secs(delay))
    }

    fn schedule_retry(&mut self, addr: SocketAddr, delay: Duration) {
        if self.is_filtered(addr) || self.is_banned(addr) {
            return;
        }
        if self.queued.contains(&addr) || self.inflight.contains(&addr) {
            return;
        }
        if self.deferred.iter().any(|entry| entry.addr == addr) {
            return;
        }
        let ready_at = Instant::now() + delay;
        self.deferred.push_back(DeferredPeer { addr, ready_at });
    }

    fn promote_ready(&mut self) {
        if self.deferred.is_empty() {
            return;
        }
        let now = Instant::now();
        let mut ready = Vec::new();
        self.deferred.retain(|entry| {
            if entry.ready_at <= now {
                ready.push(entry.addr);
                false
            } else {
                true
            }
        });
        for addr in ready {
            if self.is_filtered(addr) || self.is_banned(addr) {
                continue;
            }
            if self.queued.contains(&addr) || self.inflight.contains(&addr) {
                continue;
            }
            self.queued.insert(addr);
            self.queue.push_back(addr);
        }
    }

    fn clear_failure(&mut self, addr: SocketAddr) {
        self.failures.remove(&addr);
        self.deferred.retain(|entry| entry.addr != addr);
        self.banned.remove(&addr);
    }

    fn ban(&mut self, addr: SocketAddr) {
        let until = Instant::now() + Duration::from_secs(PEER_BAN_SECS);
        self.banned.insert(addr, until);
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn known_len(&self) -> usize {
        self.known.len()
    }

    fn sample(&self, max: usize) -> Vec<SocketAddr> {
        self.known
            .iter()
            .filter(|addr| !self.is_filtered(**addr))
            .take(max)
            .cloned()
            .collect()
    }

    fn is_deferred(&self, addr: SocketAddr) -> bool {
        self.deferred.iter().any(|entry| entry.addr == addr)
    }

    fn delay_for_failure(&self, addr: SocketAddr) -> Option<Duration> {
        let attempts = *self.failures.get(&addr)?;
        if attempts == 0 {
            return None;
        }
        let delay = PEER_RETRY_BASE_SECS.saturating_mul(attempts as u64);
        Some(Duration::from_secs(delay))
    }

    fn is_banned(&mut self, addr: SocketAddr) -> bool {
        match self.banned.get(&addr) {
            Some(until) if *until > Instant::now() => true,
            Some(_) => {
                self.banned.remove(&addr);
                false
            }
            None => false,
        }
    }

    fn is_filtered(&self, addr: SocketAddr) -> bool {
        self.filter
            .as_ref()
            .map(|filter| filter.is_blocked(addr.ip()))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
struct FileSpan {
    path: String,
    offset: u64,
    length: u64,
}

fn build_file_spans(meta: &torrent::TorrentMeta) -> Vec<FileSpan> {
    let name = String::from_utf8_lossy(&meta.info.name).into_owned();
    if let Some(length) = meta.info.length {
        return vec![FileSpan {
            path: name,
            offset: 0,
            length,
        }];
    }

    let mut spans = if !meta.info.files.is_empty() {
        Vec::with_capacity(meta.info.files.len())
    } else {
        Vec::with_capacity(meta.info.file_tree.len())
    };
    let mut offset = 0u64;
    if !meta.info.files.is_empty() {
        for file in &meta.info.files {
            let mut path = name.clone();
            for segment in &file.path {
                path.push('/');
                path.push_str(&String::from_utf8_lossy(segment));
            }
            spans.push(FileSpan {
                path,
                offset,
                length: file.length,
            });
            offset = offset.saturating_add(file.length);
        }
    } else {
        for file in &meta.info.file_tree {
            let mut path = name.clone();
            for segment in &file.path {
                path.push('/');
                path.push_str(&String::from_utf8_lossy(segment));
            }
            spans.push(FileSpan {
                path,
                offset,
                length: file.length,
            });
            offset = offset.saturating_add(file.length);
        }
    }
    spans
}

fn build_ui_files(
    spans: &[FileSpan],
    pieces: &piece::PieceManager,
    base_piece_length: u64,
    file_priorities: &[u8],
) -> Vec<ui::UiFile> {
    let mut files: Vec<ui::UiFile> = spans
        .iter()
        .enumerate()
        .map(|(idx, span)| ui::UiFile {
            path: span.path.clone(),
            length: span.length,
            completed: 0,
            priority: file_priorities.get(idx).copied().unwrap_or(0),
        })
        .collect();

    let piece_count = pieces.piece_count();
    for index in 0..piece_count {
        let index = index as u32;
        if !pieces.is_piece_complete(index) {
            continue;
        }
        let piece_len = match pieces.piece_length(index) {
            Some(len) => len as u64,
            None => continue,
        };
        let piece_start = (index as u64).saturating_mul(base_piece_length);
        apply_piece_to_files(&mut files, spans, piece_start, piece_len);
    }

    files
}

fn apply_file_priorities(
    pieces: &mut piece::PieceManager,
    spans: &[FileSpan],
    file_priorities: &[u8],
    base_piece_length: u64,
) -> Result<(), String> {
    let priorities = compute_piece_priorities(
        spans,
        file_priorities,
        base_piece_length,
        pieces.piece_count(),
    );
    pieces
        .set_piece_priorities(&priorities)
        .map_err(|err| err.to_string())
}

fn compute_piece_priorities(
    spans: &[FileSpan],
    file_priorities: &[u8],
    base_piece_length: u64,
    piece_count: usize,
) -> Vec<u8> {
    if piece_count == 0 {
        return Vec::new();
    }
    let mut priorities = vec![piece::PRIORITY_SKIP; piece_count];
    if base_piece_length == 0 {
        return priorities;
    }
    for (idx, span) in spans.iter().enumerate() {
        let priority = file_priorities
            .get(idx)
            .copied()
            .unwrap_or(piece::PRIORITY_NORMAL);
        if priority == piece::PRIORITY_SKIP {
            continue;
        }
        let start_piece = span.offset / base_piece_length;
        let end_offset = span.offset.saturating_add(span.length).saturating_sub(1);
        let end_piece = end_offset / base_piece_length;
        for piece_index in start_piece..=end_piece {
            if let Some(slot) = priorities.get_mut(piece_index as usize) {
                if priority > *slot {
                    *slot = priority;
                }
            }
        }
    }
    priorities
}

#[cfg(feature = "webseed")]
fn collect_web_seeds(meta: &torrent::TorrentMeta) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for url in meta.url_list.iter().chain(meta.httpseeds.iter()) {
        if let Ok(url_str) = std::str::from_utf8(url) {
            if seen.insert(url_str.to_string()) {
                out.push(url_str.to_string());
            }
        }
    }
    out
}

#[cfg(feature = "webseed")]
fn start_webseed_worker(
    web_seeds: Vec<String>,
    pieces: Arc<Mutex<piece::PieceManager>>,
    storage: Arc<Mutex<storage::Storage>>,
    completed_log: Arc<Mutex<Vec<u32>>>,
    file_spans: Arc<Vec<FileSpan>>,
    base_piece_length: u64,
    limits: TransferLimits,
    downloaded: Arc<AtomicU64>,
    stop_flag: Arc<AtomicBool>,
    ui_state: Option<Arc<Mutex<ui::UiState>>>,
    torrent_id: u64,
) -> Option<thread::JoinHandle<()>> {
    if web_seeds.is_empty() {
        return None;
    }
    Some(thread::spawn(move || loop {
        if torrent_stop_requested(&stop_flag) {
            break;
        }
        let (index, piece_len, expected) = {
            let p = pieces.lock().unwrap();
            let index = match p.next_missing_piece() {
                Some(index) => index,
                None => break,
            };
            let length = match p.piece_length(index) {
                Some(length) => length,
                None => break,
            };
            let expected = match p.piece_hash(index) {
                Some(hash) => hash.clone(),
                None => break,
            };
            (index, length, expected)
        };

        let data = match fetch_piece_from_web_seeds(
            &web_seeds,
            &file_spans,
            base_piece_length,
            index,
            piece_len,
        ) {
            Ok(data) => data,
            Err(_) => {
                sleep_with_shutdown_or_stop(Duration::from_secs(1), &stop_flag);
                continue;
            }
        };
        if !verify_piece_hash(&data, &expected) {
            sleep_with_shutdown_or_stop(Duration::from_secs(1), &stop_flag);
            continue;
        }
        let offset = (index as u64).saturating_mul(base_piece_length);
        {
            let mut s = storage.lock().unwrap();
            if s.write_at(offset, &data).is_err() {
                continue;
            }
        }
        {
            let mut p = pieces.lock().unwrap();
            if let Ok(true) = p.mark_piece_complete(index) {
                SESSION_DOWNLOADED_BYTES.fetch_add(piece_len as u64, Ordering::SeqCst);
                downloaded.fetch_add(piece_len as u64, Ordering::SeqCst);
                limits.global_down.throttle(piece_len as usize);
                limits.torrent_down.throttle(piece_len as usize);
            }
        }
        if let Ok(mut log) = completed_log.lock() {
            log.push(index);
        }
        let piece_start = (index as u64).saturating_mul(base_piece_length);
        let piece_len_u64 = piece_len as u64;
        let completed_pieces = {
            let p = pieces.lock().unwrap();
            p.completed_pieces()
        };
        update_ui(&ui_state, |state| {
            apply_piece_completion_ui(
                state,
                torrent_id,
                completed_pieces,
                &file_spans,
                piece_start,
                piece_len_u64,
                true,
            );
        });
    }))
}

#[cfg(not(feature = "webseed"))]
fn collect_web_seeds(_meta: &torrent::TorrentMeta) -> Vec<String> {
    Vec::new()
}

#[cfg(not(feature = "webseed"))]
fn start_webseed_worker(
    _web_seeds: Vec<String>,
    _pieces: Arc<Mutex<piece::PieceManager>>,
    _storage: Arc<Mutex<storage::Storage>>,
    _completed_log: Arc<Mutex<Vec<u32>>>,
    _file_spans: Arc<Vec<FileSpan>>,
    _base_piece_length: u64,
    _limits: TransferLimits,
    _downloaded: Arc<AtomicU64>,
    _stop_flag: Arc<AtomicBool>,
    _ui_state: Option<Arc<Mutex<ui::UiState>>>,
    _torrent_id: u64,
) -> Option<thread::JoinHandle<()>> {
    None
}

fn start_resume_worker(
    resume_path: PathBuf,
    info_hash: [u8; 20],
    base_piece_length: u64,
    pieces: Arc<Mutex<piece::PieceManager>>,
    file_priorities: Arc<Mutex<Vec<u8>>>,
    file_spans: Arc<Vec<FileSpan>>,
    download_dir: PathBuf,
    downloaded: Arc<AtomicU64>,
    uploaded: Arc<AtomicU64>,
    peer_queue: Arc<Mutex<PeerQueue>>,
    stop_flag: Arc<AtomicBool>,
    file_renames: Arc<Mutex<HashMap<usize, String>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut last_save = Instant::now() - RESUME_SAVE_INTERVAL;
        loop {
            if torrent_stop_requested(&stop_flag) {
                break;
            }
            let complete = {
                let p = pieces.lock().unwrap();
                p.is_complete()
            };
            if last_save.elapsed() >= RESUME_SAVE_INTERVAL || complete {
                let priorities = match file_priorities.lock() {
                    Ok(priorities) => priorities.clone(),
                    Err(_) => Vec::new(),
                };
                let downloaded = downloaded.load(Ordering::SeqCst);
                let uploaded = uploaded.load(Ordering::SeqCst);
                let peers = peer_queue
                    .lock()
                    .map(|queue| queue.sample(256))
                    .unwrap_or_default();
                let renames: Vec<(usize, String)> = file_renames
                    .lock()
                    .map(|map| map.iter().map(|(k, v)| (*k, v.clone())).collect())
                    .unwrap_or_default();
                if let Ok(p) = pieces.lock() {
                    let _ = save_resume_snapshot(
                        &resume_path,
                        info_hash,
                        base_piece_length,
                        &p,
                        &priorities,
                        &file_spans,
                        &download_dir,
                        downloaded,
                        uploaded,
                        peers,
                        &renames,
                    );
                }
                last_save = Instant::now();
            }
            if complete {
                break;
            }
            sleep_with_shutdown_or_stop(Duration::from_secs(1), &stop_flag);
        }
    })
}

#[cfg(feature = "webseed")]
fn fetch_piece_from_web_seeds(
    web_seeds: &[String],
    file_spans: &[FileSpan],
    base_piece_length: u64,
    index: u32,
    piece_len: u32,
) -> Result<Vec<u8>, String> {
    let piece_start = (index as u64).saturating_mul(base_piece_length);
    let piece_end = piece_start.saturating_add(piece_len as u64);
    for base in web_seeds {
        let mut out = Vec::with_capacity(piece_len as usize);
        let is_multi = file_spans.len() > 1;
        let mut ok = true;
        for span in file_spans {
            let file_start = span.offset;
            let file_end = span.offset.saturating_add(span.length);
            let overlap_start = piece_start.max(file_start);
            let overlap_end = piece_end.min(file_end);
            if overlap_end <= overlap_start {
                continue;
            }
            let range_start = overlap_start.saturating_sub(file_start);
            let range_end = overlap_end.saturating_sub(file_start).saturating_sub(1);
            let url = build_webseed_url(base, &span.path, is_multi);
            let data = match http::get_range(
                &url,
                range_start,
                range_end,
                (overlap_end - overlap_start) as usize + 1024,
            ) {
                Ok(data) => data,
                Err(_) => {
                    ok = false;
                    break;
                }
            };
            if data.len() != (overlap_end - overlap_start) as usize {
                ok = false;
                break;
            }
            out.extend_from_slice(&data);
        }
        if ok && out.len() == piece_len as usize {
            return Ok(out);
        }
    }
    Err("web seed fetch failed".to_string())
}

#[cfg(feature = "webseed")]
fn build_webseed_url(base: &str, path: &str, multi: bool) -> String {
    if !multi {
        return base.to_string();
    }
    let mut out = base.trim_end_matches('/').to_string();
    out.push('/');
    out.push_str(&percent_encode_path(path));
    out
}

#[cfg(feature = "webseed")]
fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        if is_unreserved(b) || b == b'/' {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

#[cfg(feature = "webseed")]
fn is_unreserved(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

fn apply_piece_to_files(
    files: &mut [ui::UiFile],
    spans: &[FileSpan],
    piece_start: u64,
    piece_len: u64,
) {
    let piece_end = piece_start.saturating_add(piece_len);
    for (idx, span) in spans.iter().enumerate() {
        let file_start = span.offset;
        let file_end = span.offset.saturating_add(span.length);
        let overlap_start = piece_start.max(file_start);
        let overlap_end = piece_end.min(file_end);
        if overlap_end <= overlap_start {
            continue;
        }
        let delta = overlap_end - overlap_start;
        if let Some(file) = files.get_mut(idx) {
            file.completed = (file.completed + delta).min(file.length);
        }
    }
}

fn peer_worker_loop(
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    torrent_id: u64,
    peer_tags: &Arc<AtomicU64>,
    pieces: &Arc<Mutex<piece::PieceManager>>,
    storage: &Arc<Mutex<storage::Storage>>,
    completed_log: &Arc<Mutex<Vec<u32>>>,
    peer_queue: &Arc<Mutex<PeerQueue>>,
    allow_pex: bool,
    active_peers: &Arc<AtomicUsize>,
    file_spans: &Arc<Vec<FileSpan>>,
    base_piece_length: u64,
    connect_cfg: ConnectionConfig,
    limits: TransferLimits,
    downloaded: &Arc<AtomicU64>,
    uploaded: &Arc<AtomicU64>,
    upload_manager: &Arc<UploadManager>,
    paused_flag: &Arc<AtomicBool>,
    stop_flag: &Arc<AtomicBool>,
    peer_slots: Arc<PeerSlots>,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
) {
    loop {
        if torrent_stop_requested(stop_flag) {
            break;
        }

        let addr = {
            let mut queue = peer_queue.lock().unwrap();
            queue.pop()
        };

        let addr = match addr {
            Some(addr) => addr,
            None => {
                sleep_with_shutdown_or_stop(Duration::from_millis(250), stop_flag);
                continue;
            }
        };

        if !peer_slots.acquire(stop_flag) {
            let mut queue = peer_queue.lock().unwrap();
            queue.finish(addr);
            break;
        }
        active_peers.fetch_add(1, Ordering::SeqCst);
        let geo_cc = GEOIP_DB
            .get()
            .and_then(|db| db.lookup(addr.ip()))
            .map(|cc| cc.to_string());
        update_ui(ui_state, |state| {
            let active_count = active_peers.load(Ordering::SeqCst);
            if state.current_id == Some(torrent_id) {
                state.active_peers = active_count;
            }
            update_torrent_entry(state, torrent_id, |torrent| {
                torrent.active_peers = active_count;
                if let Some(cc) = geo_cc.as_deref() {
                    add_peer_country(torrent, cc);
                }
            });
        });
        log_info!("connecting to peer {addr}...");

        let peer_tag = peer_tags.fetch_add(1, Ordering::SeqCst);
        let result = download_from_peer_concurrent(
            addr,
            info_hash,
            peer_id,
            torrent_id,
            peer_tag,
            pieces,
            storage,
            completed_log,
            peer_queue,
            allow_pex,
            file_spans,
            base_piece_length,
            &connect_cfg,
            &limits,
            downloaded,
            uploaded,
            upload_manager,
            paused_flag,
            stop_flag,
            ui_state,
        );

        active_peers.fetch_sub(1, Ordering::SeqCst);
        peer_slots.release();
        update_ui(ui_state, |state| {
            let active_count = active_peers.load(Ordering::SeqCst);
            if state.current_id == Some(torrent_id) {
                state.active_peers = active_count;
            }
            update_torrent_entry(state, torrent_id, |torrent| {
                torrent.active_peers = active_count;
                if let Some(cc) = geo_cc.as_deref() {
                    remove_peer_country(torrent, cc);
                }
            });
        });

        {
            let mut queue = peer_queue.lock().unwrap();
            queue.finish(addr);
            match &result {
                Ok(()) => {
                    queue.clear_failure(addr);
                }
                Err(err) => {
                    if is_retryable_peer_error(err) {
                        if let Some(delay) = queue.note_failure(addr) {
                            queue.schedule_retry(addr, delay);
                        }
                    } else {
                        queue.clear_failure(addr);
                    }
                }
            }
        }

        if let Err(err) = &result {
            log_warn!("peer {addr} error: {err}");
            update_ui(ui_state, |state| {
                state.last_error = err.clone();
                update_torrent_entry(state, torrent_id, |torrent| {
                    torrent.last_error = err.clone();
                });
            });
        }
    }
}

struct ResumeStats {
    completed_bytes: u64,
}

struct ResumeData {
    info_hash: [u8; 20],
    piece_length: u64,
    bitfield: Vec<u8>,
    file_priorities: Vec<u8>,
    files: Vec<ResumeFileStat>,
    downloaded: u64,
    uploaded: u64,
    peers: Vec<SocketAddr>,
    file_renames: Vec<(usize, String)>,
}

struct ResumeFileStat {
    length: u64,
    mtime: u64,
}

fn resume_from_storage(
    pieces: &mut piece::PieceManager,
    storage: &mut storage::Storage,
    base_piece_length: u64,
    file_spans: &[FileSpan],
    download_dir: &Path,
    resume: Option<&ResumeData>,
) -> Result<ResumeStats, String> {
    let piece_count = pieces.piece_count();
    if piece_count == 0 {
        return Ok(ResumeStats { completed_bytes: 0 });
    }
    if let Some(resume) = resume {
        if resume.piece_length == base_piece_length
            && resume.bitfield.len() == pieces.bitfield_len()
            && resume.files.len() == file_spans.len()
        {
            let mut needs_verify = vec![false; piece_count];
            for (idx, span) in file_spans.iter().enumerate() {
                let expected = &resume.files[idx];
                let actual = file_stat(download_dir, span);
                let changed = match actual {
                    Some(actual) => {
                        actual.length != expected.length || actual.mtime != expected.mtime
                    }
                    None => true,
                };
                if changed {
                    let start_piece = span.offset / base_piece_length;
                    let end_offset = span.offset.saturating_add(span.length).saturating_sub(1);
                    let end_piece = end_offset / base_piece_length;
                    for piece_index in start_piece..=end_piece {
                        if let Some(slot) = needs_verify.get_mut(piece_index as usize) {
                            *slot = true;
                        }
                    }
                }
            }
            let max_len = base_piece_length
                .try_into()
                .map_err(|_| "piece length too large".to_string())?;
            let mut buffer = vec![0u8; max_len];
            for index in 0..piece_count {
                if !bitfield_has(&resume.bitfield, index) {
                    continue;
                }
                if needs_verify[index] {
                    if verify_piece(
                        storage,
                        pieces,
                        index as u32,
                        base_piece_length,
                        &mut buffer,
                    )? {
                        continue;
                    }
                } else {
                    pieces
                        .mark_piece_complete(index as u32)
                        .map_err(|err| format!("resume mark failed: {err}"))?;
                }
            }
            return Ok(ResumeStats {
                completed_bytes: pieces.completed_bytes(),
            });
        }
    }

    full_recheck(pieces, storage, base_piece_length)
}

fn full_recheck(
    pieces: &mut piece::PieceManager,
    storage: &mut storage::Storage,
    base_piece_length: u64,
) -> Result<ResumeStats, String> {
    let piece_count = pieces.piece_count();
    let max_len = base_piece_length
        .try_into()
        .map_err(|_| "piece length too large".to_string())?;
    let mut buffer = vec![0u8; max_len];
    for index in 0..piece_count {
        let _ = verify_piece(
            storage,
            pieces,
            index as u32,
            base_piece_length,
            &mut buffer,
        );
    }
    Ok(ResumeStats {
        completed_bytes: pieces.completed_bytes(),
    })
}

fn verify_piece(
    storage: &mut storage::Storage,
    pieces: &mut piece::PieceManager,
    index: u32,
    base_piece_length: u64,
    buffer: &mut [u8],
) -> Result<bool, String> {
    let length = pieces
        .piece_length(index)
        .ok_or_else(|| "missing piece length".to_string())? as usize;
    let offset = (index as u64).saturating_mul(base_piece_length);
    let target = &mut buffer[..length];
    if storage.read_at(offset, target).is_err() {
        return Ok(false);
    }
    let expected = pieces
        .piece_hash(index)
        .ok_or_else(|| "missing piece hash".to_string())?;
    if verify_piece_hash(target, expected) {
        pieces
            .mark_piece_complete(index)
            .map_err(|err| format!("resume mark failed: {err}"))?;
        return Ok(true);
    }
    Ok(false)
}

fn resume_path(download_dir: &Path, info_hash: [u8; 20]) -> PathBuf {
    let mut dir = download_dir.join(".rustorrent");
    dir.push(format!("{}.resume", hex(&info_hash)));
    dir
}

fn session_path(download_dir: &Path) -> PathBuf {
    download_dir.join(".rustorrent").join("session.benc")
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut out = path.as_os_str().to_owned();
    out.push(suffix);
    PathBuf::from(out)
}

fn write_atomic_file(
    path: &Path,
    data: &[u8],
    label: &str,
    keep_backup: bool,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("{label} dir failed: {err}"))?;
    }
    if keep_backup && path.exists() {
        let backup_path = sidecar_path(path, ".bak");
        let _ = fs::copy(path, &backup_path);
    }
    let tmp_path = sidecar_path(path, ".tmp");
    fs::write(&tmp_path, data).map_err(|err| format!("{label} write failed: {err}"))?;
    fs::rename(&tmp_path, path).map_err(|err| format!("{label} rename failed: {err}"))?;
    Ok(())
}

fn parse_session_entries(
    data: &[u8],
    root: &Path,
) -> Result<HashMap<[u8; 20], SessionEntry>, String> {
    let value = bencode::parse(data).map_err(|err| err.to_string())?;
    let list = match value {
        Value::List(items) => items,
        _ => return Err("invalid format".to_string()),
    };
    let mut entries: HashMap<[u8; 20], SessionEntry> = HashMap::new();
    for item in list {
        let Value::Dict(items) = item else {
            continue;
        };
        let info_hash = match dict_get(&items, b"info_hash") {
            Some(Value::Bytes(bytes)) if bytes.len() == 20 => {
                let mut out = [0u8; 20];
                out.copy_from_slice(bytes);
                out
            }
            _ => continue,
        };
        let torrent_bytes = match dict_get(&items, b"torrent") {
            Some(Value::Bytes(bytes)) if !bytes.is_empty() => bytes.clone(),
            _ => continue,
        };
        let name = match dict_get(&items, b"name") {
            Some(Value::Bytes(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
            _ => String::new(),
        };
        let download_dir = match dict_get(&items, b"download_dir") {
            Some(Value::Bytes(bytes)) if !bytes.is_empty() => {
                PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
            }
            _ => root.to_path_buf(),
        };
        let preallocate = dict_get_int(&items, b"preallocate").unwrap_or(0) != 0;
        let label = match dict_get(&items, b"label") {
            Some(Value::Bytes(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
            _ => String::new(),
        };
        entries.insert(
            info_hash,
            SessionEntry {
                info_hash,
                name,
                torrent_bytes,
                download_dir,
                preallocate,
                label,
            },
        );
    }
    Ok(entries)
}

fn load_session_entries_with_recovery(
    path: &Path,
    root: &Path,
) -> Result<HashMap<[u8; 20], SessionEntry>, String> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(err) => return Err(format!("session read failed: {err}")),
    };
    match parse_session_entries(&data, root) {
        Ok(entries) => Ok(entries),
        Err(primary_err) => {
            let backup_path = sidecar_path(path, ".bak");
            let backup_data = match fs::read(&backup_path) {
                Ok(data) => data,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    return Err(format!("session load failed: {primary_err}"));
                }
                Err(err) => {
                    return Err(format!(
                        "session load failed: {primary_err}; backup read failed: {err}"
                    ));
                }
            };
            let recovered = parse_session_entries(&backup_data, root).map_err(|backup_err| {
                format!("session load failed: {primary_err}; backup invalid: {backup_err}")
            })?;
            let _ = write_atomic_file(path, &backup_data, "session restore", false);
            log_warn!("session load recovered from backup");
            Ok(recovered)
        }
    }
}

fn save_session(path: &Path, entries: &HashMap<[u8; 20], SessionEntry>) -> Result<(), String> {
    let mut list = Vec::with_capacity(entries.len());
    for entry in entries.values() {
        let mut dict = Vec::new();
        dict.push((
            b"info_hash".to_vec(),
            Value::Bytes(entry.info_hash.to_vec()),
        ));
        dict.push((
            b"name".to_vec(),
            Value::Bytes(entry.name.as_bytes().to_vec()),
        ));
        dict.push((
            b"torrent".to_vec(),
            Value::Bytes(entry.torrent_bytes.clone()),
        ));
        dict.push((
            b"download_dir".to_vec(),
            Value::Bytes(entry.download_dir.display().to_string().into_bytes()),
        ));
        dict.push((
            b"preallocate".to_vec(),
            Value::Int(if entry.preallocate { 1 } else { 0 }),
        ));
        if !entry.label.is_empty() {
            dict.push((
                b"label".to_vec(),
                Value::Bytes(entry.label.as_bytes().to_vec()),
            ));
        }
        list.push(Value::Dict(dict));
    }
    let value = Value::List(list);
    let data = bencode::encode(&value);
    write_atomic_file(path, &data, "session", true)
}

fn load_resume_data(path: &Path) -> Result<ResumeData, String> {
    let data = fs::read(path).map_err(|err| format!("resume read failed: {err}"))?;
    parse_resume_data(&data)
}

fn parse_resume_data(data: &[u8]) -> Result<ResumeData, String> {
    let value = bencode::parse(data).map_err(|err| err.to_string())?;
    let dict = match value {
        Value::Dict(items) => items,
        _ => return Err("resume format invalid".to_string()),
    };
    let info_hash = match dict_get(&dict, b"info_hash") {
        Some(Value::Bytes(bytes)) if bytes.len() == 20 => {
            let mut out = [0u8; 20];
            out.copy_from_slice(bytes);
            out
        }
        _ => return Err("resume info hash missing".to_string()),
    };
    let piece_length = dict_get_int(&dict, b"piece_length")
        .ok_or_else(|| "resume piece length missing".to_string())?;
    let bitfield = match dict_get(&dict, b"pieces") {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err("resume pieces missing".to_string()),
    };
    let file_priorities = match dict_get(&dict, b"file_priority") {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|item| match item {
                Value::Int(value) if *value >= 0 => Some(*value as u8),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    let files = match dict_get(&dict, b"files") {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|item| match item {
                Value::Dict(values) => {
                    let length = dict_get_int(values, b"length")?;
                    let mtime = dict_get_int(values, b"mtime").unwrap_or(0);
                    Some(ResumeFileStat {
                        length: length as u64,
                        mtime: mtime as u64,
                    })
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    let downloaded = dict_get_int(&dict, b"downloaded")
        .and_then(|value| if value >= 0 { Some(value as u64) } else { None })
        .unwrap_or(0);
    let uploaded = dict_get_int(&dict, b"uploaded")
        .and_then(|value| if value >= 0 { Some(value as u64) } else { None })
        .unwrap_or(0);
    let peers = match dict_get(&dict, b"peers") {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|item| match item {
                Value::Bytes(bytes) => String::from_utf8(bytes.clone())
                    .ok()
                    .and_then(|raw| raw.parse::<SocketAddr>().ok()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    let file_renames = match dict_get(&dict, b"file_renames") {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|item| match item {
                Value::Dict(values) => {
                    let idx = dict_get_int(values, b"index")?;
                    let name = match dict_get(values, b"name") {
                        Some(Value::Bytes(bytes)) => String::from_utf8(bytes.clone()).ok()?,
                        _ => return None,
                    };
                    Some((idx as usize, name))
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(ResumeData {
        info_hash,
        piece_length: piece_length as u64,
        bitfield,
        file_priorities,
        files,
        downloaded,
        uploaded,
        peers,
        file_renames,
    })
}

fn load_resume_data_with_recovery(path: &Path) -> Option<ResumeData> {
    if path.exists() {
        match load_resume_data(path) {
            Ok(resume) => return Some(resume),
            Err(err) => {
                log_warn!("resume load failed: {err}");
            }
        }
    }

    let backup_path = sidecar_path(path, ".bak");
    let backup_data = match fs::read(&backup_path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return None,
        Err(err) => {
            log_warn!("resume backup read failed: {err}");
            return None;
        }
    };
    let resume = match parse_resume_data(&backup_data) {
        Ok(resume) => resume,
        Err(err) => {
            log_warn!("resume backup invalid: {err}");
            return None;
        }
    };
    let _ = write_atomic_file(path, &backup_data, "resume restore", false);
    log_warn!("resume load recovered from backup");
    Some(resume)
}

fn save_resume_snapshot(
    path: &Path,
    info_hash: [u8; 20],
    base_piece_length: u64,
    pieces: &piece::PieceManager,
    file_priorities: &[u8],
    file_spans: &[FileSpan],
    download_dir: &Path,
    downloaded: u64,
    uploaded: u64,
    peers: Vec<SocketAddr>,
    file_renames: &[(usize, String)],
) -> Result<(), String> {
    let bitfield = build_bitfield(pieces);
    let files = collect_file_stats(file_spans, download_dir);
    save_resume_data(
        path,
        info_hash,
        base_piece_length,
        bitfield,
        file_priorities,
        files,
        downloaded,
        uploaded,
        peers,
        file_renames,
    )
}

fn save_resume_data(
    path: &Path,
    info_hash: [u8; 20],
    base_piece_length: u64,
    bitfield: Vec<u8>,
    file_priorities: &[u8],
    files: Vec<ResumeFileStat>,
    downloaded: u64,
    uploaded: u64,
    peers: Vec<SocketAddr>,
    file_renames: &[(usize, String)],
) -> Result<(), String> {
    let mut dict = Vec::new();
    dict.push((b"info_hash".to_vec(), Value::Bytes(info_hash.to_vec())));
    dict.push((
        b"piece_length".to_vec(),
        Value::Int(base_piece_length as i64),
    ));
    let downloaded_i64 = downloaded.min(i64::MAX as u64) as i64;
    let uploaded_i64 = uploaded.min(i64::MAX as u64) as i64;
    dict.push((b"downloaded".to_vec(), Value::Int(downloaded_i64)));
    dict.push((b"uploaded".to_vec(), Value::Int(uploaded_i64)));
    dict.push((b"pieces".to_vec(), Value::Bytes(bitfield)));
    let priorities = file_priorities
        .iter()
        .map(|value| Value::Int(*value as i64))
        .collect::<Vec<_>>();
    dict.push((b"file_priority".to_vec(), Value::List(priorities)));
    let files_list = files
        .into_iter()
        .map(|stat| {
            Value::Dict(vec![
                (b"length".to_vec(), Value::Int(stat.length as i64)),
                (b"mtime".to_vec(), Value::Int(stat.mtime as i64)),
            ])
        })
        .collect();
    dict.push((b"files".to_vec(), Value::List(files_list)));
    let peers_list = peers
        .into_iter()
        .map(|addr| Value::Bytes(addr.to_string().into_bytes()))
        .collect();
    dict.push((b"peers".to_vec(), Value::List(peers_list)));
    if !file_renames.is_empty() {
        let renames_list = file_renames
            .iter()
            .map(|(idx, name)| {
                Value::Dict(vec![
                    (b"index".to_vec(), Value::Int(*idx as i64)),
                    (b"name".to_vec(), Value::Bytes(name.as_bytes().to_vec())),
                ])
            })
            .collect();
        dict.push((b"file_renames".to_vec(), Value::List(renames_list)));
    }
    let data = bencode::encode(&Value::Dict(dict));
    write_atomic_file(path, &data, "resume", true)
}

fn collect_file_stats(spans: &[FileSpan], download_dir: &Path) -> Vec<ResumeFileStat> {
    spans
        .iter()
        .map(|span| {
            file_stat(download_dir, span).unwrap_or(ResumeFileStat {
                length: span.length,
                mtime: 0,
            })
        })
        .collect()
}

fn file_stat(download_dir: &Path, span: &FileSpan) -> Option<ResumeFileStat> {
    let path = download_dir.join(&span.path);
    let meta = fs::metadata(&path).ok()?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    Some(ResumeFileStat {
        length: meta.len(),
        mtime,
    })
}

#[derive(Clone)]
struct Args {
    torrent_path: Option<String>,
    magnet: Option<String>,
    download_dir: std::path::PathBuf,
    preallocate: bool,
    ui: bool,
    ui_addr: String,
    retry_interval: u64,
    numwant: u32,
    port: u16,
    enable_utp: bool,
    encryption: EncryptionMode,
    blocklist_path: Option<PathBuf>,
    max_peers_global: usize,
    max_peers_torrent: usize,
    max_active_torrents: usize,
    download_rate: u64,
    upload_rate: u64,
    torrent_download_rate: u64,
    torrent_upload_rate: u64,
    write_cache_bytes: usize,
    sequential: bool,
    move_completed: Option<PathBuf>,
    log_path: Option<PathBuf>,
    daemon: bool,
    pid_file: Option<PathBuf>,
    seed_ratio: f64,
    max_seed_time: u64,
    on_complete: Option<PathBuf>,
    watch_dirs: Vec<PathBuf>,
    super_seed: bool,
    tui: bool,
    proxy: Option<proxy::ProxyConfig>,
    geoip_db: Option<PathBuf>,
    rss_feeds: Vec<String>,
    rss_rules: Vec<(String, String)>,
    rss_interval: u64,
    throttle_groups: Vec<(String, u64, u64)>,
    ratio_groups: Vec<(String, f64, String)>,
    schedules: Vec<(u64, String)>,
}

#[derive(Default)]
struct ConfigOverrides {
    download_dir: Option<PathBuf>,
    preallocate: Option<bool>,
    ui: Option<bool>,
    ui_addr: Option<String>,
    retry_interval: Option<u64>,
    numwant: Option<u32>,
    port: Option<u16>,
    enable_utp: Option<bool>,
    encryption: Option<EncryptionMode>,
    blocklist_path: Option<PathBuf>,
    max_peers_global: Option<usize>,
    max_peers_torrent: Option<usize>,
    max_active_torrents: Option<usize>,
    download_rate: Option<u64>,
    upload_rate: Option<u64>,
    torrent_download_rate: Option<u64>,
    torrent_upload_rate: Option<u64>,
    write_cache_bytes: Option<usize>,
    geoip_db: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let args_list = env::args().skip(1).collect::<Vec<_>>();
    let mut config_path = env::var("RUSTORRENT_CONFIG").ok();
    if let Some(idx) = args_list.iter().position(|arg| arg == "--config") {
        let value = args_list
            .get(idx + 1)
            .ok_or_else(|| "missing value for --config".to_string())?;
        config_path = Some(value.clone());
    }
    let config_overrides = match config_path {
        Some(path) => Some(load_config_overrides(Path::new(&path))?),
        None => None,
    };
    let env_overrides = load_env_overrides();

    let mut torrent_path: Option<String> = None;
    let mut magnet: Option<String> = None;
    let mut download_dir = env::current_dir().map_err(|err| format!("cwd error: {err}"))?;
    let mut preallocate = false;
    let mut ui = false;
    let mut ui_addr = "127.0.0.1:8080".to_string();
    let mut retry_interval = 60u64;
    let mut numwant = 200u32;
    let mut port = 6881u16;
    let mut enable_utp = true;
    let mut encryption = EncryptionMode::Prefer;
    let mut blocklist_path: Option<PathBuf> = None;
    let mut max_peers_global = 200usize;
    let mut max_peers_torrent = 30usize;
    let mut max_active_torrents = 4usize;
    let mut download_rate = 0u64;
    let mut upload_rate = 0u64;
    let mut torrent_download_rate = 0u64;
    let mut torrent_upload_rate = 0u64;
    let mut write_cache_bytes = 0usize;
    let mut sequential = false;
    let mut move_completed: Option<PathBuf> = None;
    let mut log_path: Option<PathBuf> = None;
    let mut daemon = false;
    let mut pid_file: Option<PathBuf> = None;
    let mut seed_ratio = 0.0f64;
    let mut max_seed_time = 0u64;
    let mut on_complete: Option<PathBuf> = None;
    let mut watch_dirs: Vec<PathBuf> = Vec::new();
    let mut super_seed = false;
    let mut tui = false;
    let mut proxy_config: Option<proxy::ProxyConfig> = None;
    let mut geoip_path: Option<PathBuf> = None;
    let mut rss_feeds: Vec<String> = Vec::new();
    let mut rss_rules: Vec<(String, String)> = Vec::new();
    let mut rss_interval = 900u64;
    let mut throttle_groups: Vec<(String, u64, u64)> = Vec::new();
    let mut ratio_groups: Vec<(String, f64, String)> = Vec::new();
    let mut schedules: Vec<(u64, String)> = Vec::new();

    if let Some(cfg) = config_overrides.as_ref() {
        apply_overrides(
            cfg,
            &mut download_dir,
            &mut preallocate,
            &mut ui,
            &mut ui_addr,
            &mut retry_interval,
            &mut numwant,
            &mut port,
            &mut enable_utp,
            &mut encryption,
            &mut blocklist_path,
            &mut max_peers_global,
            &mut max_peers_torrent,
            &mut max_active_torrents,
            &mut download_rate,
            &mut upload_rate,
            &mut torrent_download_rate,
            &mut torrent_upload_rate,
            &mut write_cache_bytes,
            &mut geoip_path,
        );
    }
    apply_overrides(
        &env_overrides,
        &mut download_dir,
        &mut preallocate,
        &mut ui,
        &mut ui_addr,
        &mut retry_interval,
        &mut numwant,
        &mut port,
        &mut enable_utp,
        &mut encryption,
        &mut blocklist_path,
        &mut max_peers_global,
        &mut max_peers_torrent,
        &mut max_active_torrents,
        &mut download_rate,
        &mut upload_rate,
        &mut torrent_download_rate,
        &mut torrent_upload_rate,
        &mut write_cache_bytes,
        &mut geoip_path,
    );

    let mut idx = 0usize;
    while idx < args_list.len() {
        let arg = &args_list[idx];
        if arg == "--config" {
            idx += 2;
            continue;
        }
        if arg == "--download-dir" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --download-dir".to_string())?;
            download_dir = value.into();
            idx += 2;
            continue;
        }
        if arg == "--magnet" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --magnet".to_string())?;
            magnet = Some(value.clone());
            idx += 2;
            continue;
        }
        if arg == "--preallocate" {
            preallocate = true;
            idx += 1;
            continue;
        }
        if arg == "--ui" {
            ui = true;
            // Accept optional port number: --ui 8080 sets ui_addr to 127.0.0.1:8080
            if let Some(next) = args_list.get(idx + 1) {
                if !next.starts_with("--") {
                    if let Ok(port) = next.parse::<u16>() {
                        ui_addr = format!("127.0.0.1:{port}");
                        idx += 2;
                        continue;
                    }
                }
            }
            idx += 1;
            continue;
        }
        if arg == "--ui-addr" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --ui-addr".to_string())?;
            ui_addr = value.clone();
            idx += 2;
            continue;
        }
        if arg == "--retry-interval" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --retry-interval".to_string())?;
            retry_interval = value
                .parse::<u64>()
                .map_err(|_| "invalid value for --retry-interval".to_string())?;
            if retry_interval == 0 {
                return Err("retry interval must be > 0".to_string());
            }
            idx += 2;
            continue;
        }
        if arg == "--numwant" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --numwant".to_string())?;
            numwant = value
                .parse::<u32>()
                .map_err(|_| "invalid value for --numwant".to_string())?;
            idx += 2;
            continue;
        }
        if arg == "--port" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --port".to_string())?;
            port = value
                .parse::<u16>()
                .map_err(|_| "invalid value for --port".to_string())?;
            idx += 2;
            continue;
        }
        if arg == "--encryption" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --encryption".to_string())?;
            encryption = parse_encryption_mode(value)?;
            idx += 2;
            continue;
        }
        if arg == "--no-encryption" {
            encryption = EncryptionMode::Disable;
            idx += 1;
            continue;
        }
        if arg == "--utp" {
            enable_utp = true;
            idx += 1;
            continue;
        }
        if arg == "--no-utp" {
            enable_utp = false;
            idx += 1;
            continue;
        }
        if arg == "--blocklist" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --blocklist".to_string())?;
            blocklist_path = Some(PathBuf::from(value));
            idx += 2;
            continue;
        }
        if arg == "--max-active" || arg == "--max-active-torrents" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --max-active".to_string())?;
            max_active_torrents = value
                .parse::<usize>()
                .map_err(|_| "invalid value for --max-active".to_string())?;
            idx += 2;
            continue;
        }
        if arg == "--max-peers" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --max-peers".to_string())?;
            max_peers_global = value
                .parse::<usize>()
                .map_err(|_| "invalid value for --max-peers".to_string())?;
            idx += 2;
            continue;
        }
        if arg == "--max-peers-torrent" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --max-peers-torrent".to_string())?;
            max_peers_torrent = value
                .parse::<usize>()
                .map_err(|_| "invalid value for --max-peers-torrent".to_string())?;
            idx += 2;
            continue;
        }
        if arg == "--download-rate" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --download-rate".to_string())?;
            download_rate = parse_rate(value)?;
            idx += 2;
            continue;
        }
        if arg == "--upload-rate" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --upload-rate".to_string())?;
            upload_rate = parse_rate(value)?;
            idx += 2;
            continue;
        }
        if arg == "--torrent-download-rate" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --torrent-download-rate".to_string())?;
            torrent_download_rate = parse_rate(value)?;
            idx += 2;
            continue;
        }
        if arg == "--torrent-upload-rate" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --torrent-upload-rate".to_string())?;
            torrent_upload_rate = parse_rate(value)?;
            idx += 2;
            continue;
        }
        if arg == "--write-cache" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --write-cache".to_string())?;
            write_cache_bytes = parse_rate(value)? as usize;
            idx += 2;
            continue;
        }
        if arg == "--sequential" {
            sequential = true;
            idx += 1;
            continue;
        }
        if arg == "--log" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --log".to_string())?;
            log_path = Some(PathBuf::from(value));
            idx += 2;
            continue;
        }
        if arg == "--daemon" {
            daemon = true;
            idx += 1;
            continue;
        }
        if arg == "--pid-file" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --pid-file".to_string())?;
            pid_file = Some(PathBuf::from(value));
            idx += 2;
            continue;
        }
        if arg == "--seed-ratio" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --seed-ratio".to_string())?;
            seed_ratio = value
                .parse::<f64>()
                .map_err(|_| "invalid value for --seed-ratio".to_string())?;
            if seed_ratio < 0.0 {
                return Err("seed ratio must be >= 0".to_string());
            }
            idx += 2;
            continue;
        }
        if arg == "--max-seed-time" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --max-seed-time".to_string())?;
            max_seed_time = value
                .parse::<u64>()
                .map_err(|_| "invalid value for --max-seed-time".to_string())?;
            idx += 2;
            continue;
        }
        if arg == "--on-complete" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --on-complete".to_string())?;
            on_complete = Some(PathBuf::from(value));
            idx += 2;
            continue;
        }
        if arg == "--super-seed" {
            super_seed = true;
            idx += 1;
            continue;
        }
        if arg == "--proxy" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --proxy".to_string())?;
            proxy_config = Some(proxy::ProxyConfig::parse(value)?);
            idx += 2;
            continue;
        }
        if arg == "--geoip-db" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --geoip-db".to_string())?;
            geoip_path = Some(PathBuf::from(value));
            idx += 2;
            continue;
        }
        if arg == "--rss" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --rss".to_string())?;
            rss_feeds.push(value.clone());
            idx += 2;
            continue;
        }
        if arg == "--rss-rule" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --rss-rule".to_string())?;
            let (feed_url, pattern) = parse_rss_rule_arg(value)?;
            rss_rules.push((feed_url.to_string(), pattern.to_string()));
            idx += 2;
            continue;
        }
        if arg == "--rss-interval" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --rss-interval".to_string())?;
            rss_interval = value
                .parse::<u64>()
                .map_err(|_| "invalid value for --rss-interval".to_string())?;
            idx += 2;
            continue;
        }
        if arg == "--tui" {
            tui = true;
            idx += 1;
            continue;
        }
        if arg == "--throttle" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --throttle".to_string())?;
            let parts: Vec<&str> = value.splitn(3, ':').collect();
            if parts.len() != 3 {
                return Err("--throttle format: name:down_kbps:up_kbps".to_string());
            }
            let down = parts[1]
                .parse::<u64>()
                .map_err(|_| "invalid throttle down rate".to_string())?
                * 1024;
            let up = parts[2]
                .parse::<u64>()
                .map_err(|_| "invalid throttle up rate".to_string())?
                * 1024;
            throttle_groups.push((parts[0].to_string(), down, up));
            idx += 2;
            continue;
        }
        if arg == "--ratio-group" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --ratio-group".to_string())?;
            let parts: Vec<&str> = value.splitn(3, ':').collect();
            if parts.len() != 3 {
                return Err("--ratio-group format: name:ratio:action".to_string());
            }
            let ratio = parts[1]
                .parse::<f64>()
                .map_err(|_| "invalid ratio-group ratio".to_string())?;
            let action = parts[2].to_string();
            if !matches!(action.as_str(), "stop" | "pause" | "none") {
                return Err("ratio-group action must be stop, pause, or none".to_string());
            }
            ratio_groups.push((parts[0].to_string(), ratio, action));
            idx += 2;
            continue;
        }
        if arg == "--schedule" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --schedule".to_string())?;
            let (interval, command) = parse_schedule_arg(value)?;
            schedules.push((interval, command.to_string()));
            idx += 2;
            continue;
        }
        if arg == "--create" {
            let source = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --create".to_string())?
                .clone();
            let mut create_tracker = String::new();
            let mut create_output = String::new();
            let mut create_piece_length = 256 * 1024u64;
            let mut j = idx + 2;
            while j < args_list.len() {
                if args_list[j] == "--tracker" {
                    create_tracker = args_list
                        .get(j + 1)
                        .ok_or_else(|| "missing value for --tracker".to_string())?
                        .clone();
                    j += 2;
                } else if args_list[j] == "--output" {
                    create_output = args_list
                        .get(j + 1)
                        .ok_or_else(|| "missing value for --output".to_string())?
                        .clone();
                    j += 2;
                } else if args_list[j] == "--piece-length" {
                    create_piece_length = args_list
                        .get(j + 1)
                        .ok_or_else(|| "missing value for --piece-length".to_string())?
                        .parse::<u64>()
                        .map_err(|_| "invalid --piece-length".to_string())?;
                    j += 2;
                } else {
                    break;
                }
            }
            if create_output.is_empty() {
                create_output = format!("{}.torrent", source);
            }
            create_torrent(
                &PathBuf::from(&source),
                &create_tracker,
                &PathBuf::from(&create_output),
                create_piece_length,
            )?;
            std::process::exit(0);
        }
        if arg == "--move-completed" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --move-completed".to_string())?;
            move_completed = Some(PathBuf::from(value));
            idx += 2;
            continue;
        }
        if arg == "--watch" {
            let value = args_list
                .get(idx + 1)
                .ok_or_else(|| "missing value for --watch".to_string())?;
            watch_dirs.push(PathBuf::from(value));
            idx += 2;
            continue;
        }
        if !arg.starts_with("--") && torrent_path.is_none() {
            torrent_path = Some(arg.clone());
            idx += 1;
            continue;
        }
        return Err(format!("unknown argument: {arg}"));
    }
    if !cfg!(feature = "mse") {
        encryption = EncryptionMode::Disable;
    }
    if !cfg!(feature = "utp") {
        enable_utp = false;
    }
    if retry_interval == 0 {
        return Err("retry interval must be > 0".to_string());
    }

    if daemon {
        ui = true;
        if log_path.is_none() {
            log_path = Some(download_dir.join("rustorrent.log"));
        }
    }

    if torrent_path.is_none()
        && magnet.is_none()
        && !ui
        && !tui
        && watch_dirs.is_empty()
        && rss_feeds.is_empty()
    {
        return Err(
            "usage: rustorrent [path.torrent] [--magnet <link>] [--config <path>] [--download-dir <dir>] [--preallocate] [--sequential] [--move-completed <dir>] [--watch <dir>] [--ui] [--ui-addr <addr>] [--tui] [--retry-interval <secs>] [--numwant <n>] [--port <port>] [--encryption <disable|prefer|require>] [--no-encryption] [--utp|--no-utp] [--blocklist <path>] [--max-active <n>] [--max-peers <n>] [--max-peers-torrent <n>] [--download-rate <bps>] [--upload-rate <bps>] [--torrent-download-rate <bps>] [--torrent-upload-rate <bps>] [--write-cache <bytes>] [--log <path>] [--daemon] [--pid-file <path>] [--seed-ratio <ratio>] [--max-seed-time <minutes>] [--on-complete <script>] [--super-seed] [--throttle <name:down_kbps:up_kbps>] [--ratio-group <name:ratio:action>] [--schedule <interval_secs:command>] [--rss <url>] [--rss-rule <feed_url:pattern>] [--rss-interval <secs>] [--create <path> --tracker <url> --output <file>]".to_string(),
        );
    }
    if max_peers_torrent == 0 {
        return Err("max peers per torrent must be > 0".to_string());
    }

    Ok(Args {
        torrent_path,
        magnet,
        download_dir,
        preallocate,
        ui,
        ui_addr,
        retry_interval,
        numwant,
        port,
        enable_utp,
        encryption,
        blocklist_path,
        max_peers_global,
        max_peers_torrent,
        max_active_torrents,
        download_rate,
        upload_rate,
        torrent_download_rate,
        torrent_upload_rate,
        write_cache_bytes,
        sequential,
        move_completed,
        watch_dirs,
        log_path,
        daemon,
        pid_file,
        seed_ratio,
        max_seed_time,
        on_complete,
        super_seed,
        tui,
        proxy: proxy_config,
        geoip_db: geoip_path,
        rss_feeds,
        rss_rules,
        rss_interval,
        throttle_groups,
        ratio_groups,
        schedules,
    })
}

fn parse_encryption_mode(value: &str) -> Result<EncryptionMode, String> {
    match value.to_ascii_lowercase().as_str() {
        "disable" | "off" | "none" => Ok(EncryptionMode::Disable),
        "prefer" | "on" => Ok(EncryptionMode::Prefer),
        "require" | "force" => Ok(EncryptionMode::Require),
        _ => Err("invalid encryption mode".to_string()),
    }
}

fn parse_rate(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("invalid rate".to_string());
    }
    if trimmed.eq_ignore_ascii_case("unlimited") {
        return Ok(0);
    }
    let mut multiplier = 1u64;
    let mut number = trimmed;
    if let Some(last) = trimmed.chars().last() {
        if last.is_ascii_alphabetic() {
            multiplier = match last.to_ascii_lowercase() {
                'k' => 1024,
                'm' => 1024 * 1024,
                'g' => 1024 * 1024 * 1024,
                _ => return Err("invalid rate suffix".to_string()),
            };
            number = &trimmed[..trimmed.len() - 1];
        }
    }
    let base = number
        .trim()
        .parse::<u64>()
        .map_err(|_| "invalid rate".to_string())?;
    Ok(base.saturating_mul(multiplier))
}

fn parse_rss_rule_arg(value: &str) -> Result<(&str, &str), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("missing value for --rss-rule".to_string());
    }
    if let Some((feed_url, pattern)) = trimmed.rsplit_once(':') {
        if pattern.trim().is_empty() {
            return Err("rss rule pattern is empty".to_string());
        }
        Ok((feed_url, pattern))
    } else {
        Ok(("", trimmed))
    }
}

fn parse_schedule_arg(value: &str) -> Result<(u64, &str), String> {
    if let Some((interval_str, command)) = value.split_once(':') {
        let interval = interval_str
            .parse::<u64>()
            .map_err(|_| "invalid schedule interval".to_string())?;
        if interval == 0 {
            return Err("schedule interval must be > 0".to_string());
        }
        Ok((interval, command))
    } else {
        Err("--schedule format: interval_secs:command".to_string())
    }
}

fn apply_overrides(
    cfg: &ConfigOverrides,
    download_dir: &mut PathBuf,
    preallocate: &mut bool,
    ui: &mut bool,
    ui_addr: &mut String,
    retry_interval: &mut u64,
    numwant: &mut u32,
    port: &mut u16,
    enable_utp: &mut bool,
    encryption: &mut EncryptionMode,
    blocklist_path: &mut Option<PathBuf>,
    max_peers_global: &mut usize,
    max_peers_torrent: &mut usize,
    max_active_torrents: &mut usize,
    download_rate: &mut u64,
    upload_rate: &mut u64,
    torrent_download_rate: &mut u64,
    torrent_upload_rate: &mut u64,
    write_cache_bytes: &mut usize,
    geoip_path: &mut Option<PathBuf>,
) {
    if let Some(dir) = cfg.download_dir.clone() {
        *download_dir = dir;
    }
    if let Some(value) = cfg.preallocate {
        *preallocate = value;
    }
    if let Some(value) = cfg.ui {
        *ui = value;
    }
    if let Some(value) = cfg.ui_addr.clone() {
        *ui_addr = value;
    }
    if let Some(value) = cfg.retry_interval {
        *retry_interval = value;
    }
    if let Some(value) = cfg.numwant {
        *numwant = value;
    }
    if let Some(value) = cfg.port {
        *port = value;
    }
    if let Some(value) = cfg.enable_utp {
        *enable_utp = value;
    }
    if let Some(value) = cfg.encryption {
        *encryption = value;
    }
    if let Some(value) = cfg.blocklist_path.clone() {
        *blocklist_path = Some(value);
    }
    if let Some(value) = cfg.max_peers_global {
        *max_peers_global = value;
    }
    if let Some(value) = cfg.max_peers_torrent {
        *max_peers_torrent = value;
    }
    if let Some(value) = cfg.max_active_torrents {
        *max_active_torrents = value;
    }
    if let Some(value) = cfg.download_rate {
        *download_rate = value;
    }
    if let Some(value) = cfg.upload_rate {
        *upload_rate = value;
    }
    if let Some(value) = cfg.torrent_download_rate {
        *torrent_download_rate = value;
    }
    if let Some(value) = cfg.torrent_upload_rate {
        *torrent_upload_rate = value;
    }
    if let Some(value) = cfg.write_cache_bytes {
        *write_cache_bytes = value;
    }
    if let Some(value) = cfg.geoip_db.clone() {
        *geoip_path = Some(value);
    }
}

fn load_config_overrides(path: &Path) -> Result<ConfigOverrides, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("config read failed: {err}"))?;
    let mut cfg = ConfigOverrides::default();
    for (line_no, raw) in text.lines().enumerate() {
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((left, _)) = line.split_once('#') {
            line = left.trim();
        }
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("config line {} invalid", line_no + 1))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "download_dir" => cfg.download_dir = Some(PathBuf::from(value)),
            "preallocate" => cfg.preallocate = parse_bool_value(value),
            "ui" => cfg.ui = parse_bool_value(value),
            "ui_addr" => cfg.ui_addr = Some(value.to_string()),
            "retry_interval" => {
                cfg.retry_interval = value.parse::<u64>().ok();
            }
            "numwant" => cfg.numwant = value.parse::<u32>().ok(),
            "port" => cfg.port = value.parse::<u16>().ok(),
            "utp" => cfg.enable_utp = parse_bool_value(value),
            "encryption" => cfg.encryption = parse_encryption_mode(value).ok(),
            "blocklist" => cfg.blocklist_path = Some(PathBuf::from(value)),
            "max_peers" => cfg.max_peers_global = value.parse::<usize>().ok(),
            "max_peers_torrent" => cfg.max_peers_torrent = value.parse::<usize>().ok(),
            "max_active_torrents" | "max_active" => {
                cfg.max_active_torrents = value.parse::<usize>().ok();
            }
            "download_rate" => cfg.download_rate = parse_rate(value).ok(),
            "upload_rate" => cfg.upload_rate = parse_rate(value).ok(),
            "torrent_download_rate" => cfg.torrent_download_rate = parse_rate(value).ok(),
            "torrent_upload_rate" => cfg.torrent_upload_rate = parse_rate(value).ok(),
            "write_cache" => cfg.write_cache_bytes = parse_rate(value).ok().map(|v| v as usize),
            "geoip_db" | "geoip" => cfg.geoip_db = Some(PathBuf::from(value)),
            _ => return Err(format!("config line {} unknown key", line_no + 1)),
        }
    }
    Ok(cfg)
}

fn load_env_overrides() -> ConfigOverrides {
    let mut cfg = ConfigOverrides::default();
    if let Ok(value) = env::var("RUSTORRENT_DOWNLOAD_DIR") {
        cfg.download_dir = Some(PathBuf::from(value));
    }
    if let Ok(value) = env::var("RUSTORRENT_PREALLOCATE") {
        cfg.preallocate = parse_bool_value(&value);
    }
    if let Ok(value) = env::var("RUSTORRENT_UI") {
        cfg.ui = parse_bool_value(&value);
    }
    if let Ok(value) = env::var("RUSTORRENT_UI_ADDR") {
        cfg.ui_addr = Some(value);
    }
    if let Ok(value) = env::var("RUSTORRENT_RETRY_INTERVAL") {
        cfg.retry_interval = value.parse::<u64>().ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_NUMWANT") {
        cfg.numwant = value.parse::<u32>().ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_PORT") {
        cfg.port = value.parse::<u16>().ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_UTP") {
        cfg.enable_utp = parse_bool_value(&value);
    }
    if let Ok(value) = env::var("RUSTORRENT_ENCRYPTION") {
        cfg.encryption = parse_encryption_mode(&value).ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_BLOCKLIST") {
        cfg.blocklist_path = Some(PathBuf::from(value));
    }
    if let Ok(value) = env::var("RUSTORRENT_MAX_PEERS") {
        cfg.max_peers_global = value.parse::<usize>().ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_MAX_PEERS_TORRENT") {
        cfg.max_peers_torrent = value.parse::<usize>().ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_MAX_ACTIVE_TORRENTS") {
        cfg.max_active_torrents = value.parse::<usize>().ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_DOWNLOAD_RATE") {
        cfg.download_rate = parse_rate(&value).ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_UPLOAD_RATE") {
        cfg.upload_rate = parse_rate(&value).ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_TORRENT_DOWNLOAD_RATE") {
        cfg.torrent_download_rate = parse_rate(&value).ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_TORRENT_UPLOAD_RATE") {
        cfg.torrent_upload_rate = parse_rate(&value).ok();
    }
    if let Ok(value) = env::var("RUSTORRENT_WRITE_CACHE") {
        cfg.write_cache_bytes = parse_rate(&value).ok().map(|v| v as usize);
    }
    cfg
}

fn parse_bool_value(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn verify_piece_hash(data: &[u8], expected: &piece::PieceHash) -> bool {
    match expected {
        piece::PieceHash::Sha1(h) => sha1::sha1(data) == *h,
        piece::PieceHash::Sha256(h) => sha256::sha256(data) == *h,
    }
}

#[derive(Clone)]
struct TrackerSet {
    http: Vec<String>,
    udp: Vec<String>,
}

fn collect_trackers(meta: &torrent::TorrentMeta) -> TrackerSet {
    let mut http = Vec::new();
    let mut udp = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |url: &str| {
        if !seen.insert(url.to_string()) {
            return;
        }
        if url.starts_with("http://") || url.starts_with("https://") {
            http.push(url.to_string());
        } else if url.starts_with("udp://") {
            udp.push(url.to_string());
        }
    };

    // Add trackers from torrent file
    for url in &meta.announce_list {
        if let Ok(url_str) = std::str::from_utf8(url) {
            push(url_str);
        }
    }
    if let Some(url) = meta.announce.as_ref() {
        if let Ok(url_str) = std::str::from_utf8(url) {
            push(url_str);
        }
    }

    if !meta.info.private {
        // Add open public trackers as fallbacks
        // These are well-known open trackers that don't rate-limit as aggressively
        let open_trackers = [
            "http://tracker.opentrackr.org:1337/announce",
            "http://open.tracker.cl:1337/announce",
            "http://tracker.openbittorrent.com:80/announce",
            "http://exodus.desync.com:6969/announce",
            "http://tracker.moeking.me:6969/announce",
        ];

        for tracker in open_trackers {
            push(tracker);
        }
    }

    TrackerSet { http, udp }
}

fn generate_peer_id() -> [u8; 20] {
    let mut out = [0u8; 20];
    out[..8].copy_from_slice(b"-RT0001-");
    let mut seed = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_nanos() as u64,
        Err(_) => 0,
    };
    seed ^= std::process::id() as u64;
    for slot in &mut out[8..] {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *slot = (seed & 0xff) as u8;
    }
    out
}

/// Concurrent version of download_from_peer that works with Arc<Mutex<>> shared state
fn download_from_peer_concurrent(
    addr: SocketAddr,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    torrent_id: u64,
    peer_tag: u64,
    pieces: &Arc<Mutex<piece::PieceManager>>,
    storage: &Arc<Mutex<storage::Storage>>,
    completed_log: &Arc<Mutex<Vec<u32>>>,
    peer_queue: &Arc<Mutex<PeerQueue>>,
    allow_pex: bool,
    file_spans: &Arc<Vec<FileSpan>>,
    base_piece_length: u64,
    connect_cfg: &ConnectionConfig,
    limits: &TransferLimits,
    downloaded: &Arc<AtomicU64>,
    uploaded: &Arc<AtomicU64>,
    upload_manager: &Arc<UploadManager>,
    paused_flag: &Arc<AtomicBool>,
    stop_flag: &Arc<AtomicBool>,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
) -> Result<(), String> {
    let mut stream = connect_peer(addr, connect_cfg)?;
    // Use a longer timeout for the handshake phase (peers may be slow to respond)
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("read timeout failed: {err}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("write timeout failed: {err}"))?;

    let handshake = if connect_cfg.encryption == EncryptionMode::Require {
        outbound_handshake(&mut stream, info_hash, peer_id, connect_cfg.encryption)?
    } else {
        match plaintext_handshake(&mut stream, info_hash, peer_id) {
            Ok(handshake) => handshake,
            Err(err) if connect_cfg.encryption == EncryptionMode::Prefer => {
                let _ = err;
                log_debug!("plaintext failed, retrying mse: {err}");
                let mut retry = connect_peer(addr, connect_cfg)?;
                retry
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|err| format!("read timeout failed: {err}"))?;
                retry
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .map_err(|err| format!("write timeout failed: {err}"))?;
                let handshake =
                    outbound_handshake(&mut retry, info_hash, peer_id, EncryptionMode::Prefer)
                        .map_err(|err| format!("handshake failed: {err}"))?;
                stream = retry;
                handshake
            }
            Err(err) => return Err(format!("handshake failed: {err}")),
        }
    };
    // Reduce timeout for the main peer loop (need responsiveness for piece requests)
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));

    log_debug!("peer: {addr}");
    log_debug!("peer id: {}", hex(&handshake.peer_id));
    upload_manager.register(peer_tag);
    PEER_CONNECTED.fetch_add(1, Ordering::SeqCst);

    // Send bitfield first (BEP 3: must be first message after handshake)
    let (local_bitfield, have_pieces, mut seed_mode) = {
        let p = pieces.lock().unwrap();
        let bits = build_bitfield(&p);
        let have = p.completed_pieces() > 0;
        let seed = p.is_complete();
        (bits, have, seed)
    };
    let super_seed_mode = seed_mode && SUPER_SEED.load(Ordering::SeqCst);
    let mut super_seed_piece: Option<u32> = None;
    if super_seed_mode && have_pieces {
        // BEP 16: send HAVE for only one piece instead of full bitfield
        let piece_count = {
            let p = pieces.lock().unwrap();
            p.piece_count()
        };
        if piece_count > 0 {
            // Pick a random piece to advertise
            let mut seed_val = std::process::id() as u64;
            seed_val ^= Instant::now().elapsed().as_nanos() as u64;
            seed_val ^= seed_val << 13;
            seed_val ^= seed_val >> 7;
            let idx = (seed_val % piece_count as u64) as u32;
            peer::write_message(&mut stream, &peer::Message::Have(idx))
                .map_err(|err| format!("super-seed have write failed: {err}"))?;
            super_seed_piece = Some(idx);
        }
    } else if have_pieces {
        peer::write_message(&mut stream, &peer::Message::Bitfield(local_bitfield))
            .map_err(|err| format!("bitfield write failed: {err}"))?;
    }

    let mut peer_ut_pex: Option<u8> = None;
    let mut last_pex = Instant::now();
    if handshake.supports_extensions() {
        let ext_handshake = build_ext_handshake(None, allow_pex);
        peer::write_message(
            &mut stream,
            &peer::Message::Extended {
                ext_id: 0,
                payload: ext_handshake,
            },
        )
        .map_err(|err| format!("ext handshake failed: {err}"))?;
    }

    if seed_mode {
        let _ = peer::write_message(&mut stream, &peer::Message::NotInterested);
    } else {
        peer::write_message(&mut stream, &peer::Message::Interested)
            .map_err(|err| format!("interested write failed: {err}"))?;
    }

    let mut reader = peer::MessageReader::new();
    let mut bitfield: Option<Vec<u8>> = None;
    let mut choked = true;
    let mut peer_interested = false;
    let mut am_choking = true;
    let mut pending: Vec<PendingRequest> = Vec::new();
    let mut active_piece: Option<piece::PieceBuffer> = None;
    let mut idle = 0u32;
    let mut last_sent = Instant::now();
    let mut endgame_announced = false;
    let mut timed_out: Vec<piece::BlockRequest> = Vec::new();
    let mut pause_sent = false;
    let mut pipeline_depth = PIPELINE_DEPTH;
    let mut rtt_ema_ms: Option<f64> = None;
    let mut choke_since: Option<Instant> = None;
    let mut last_piece_data = Instant::now();
    let mut completed_cursor = {
        let log = completed_log.lock().unwrap();
        log.len()
    };
    let ban_peer = |reason: &str| {
        if let Ok(mut queue) = peer_queue.lock() {
            queue.ban(addr);
        }
        let _ = reason;
        log_debug!("banned peer {addr}: {reason}");
    };

    let result = (|| -> Result<(), String> {
        loop {
            if torrent_stop_requested(stop_flag) {
                cancel_pending(&mut stream, &pending)?;
                return Ok(());
            }
            let idle_limit = if seed_mode {
                MAX_IDLE_TICKS_SEED
            } else {
                MAX_IDLE_TICKS
            };
            if idle > idle_limit {
                return Err("peer timed out".to_string());
            }

            // Release stale reserved piece after prolonged choke (60s)
            if choked {
                if let Some(since) = choke_since {
                    if since.elapsed() > Duration::from_secs(60) {
                        if let Some(active) = active_piece.take() {
                            let mut p = pieces.lock().unwrap();
                            if !active.is_complete() {
                                let _ = p.reset_piece(active.index());
                            }
                            p.release_piece(peer_tag, active.index());
                            log_debug!(
                                "released stale piece {} from choked peer {addr}",
                                active.index()
                            );
                        }
                        choke_since = None;
                    }
                }
            }

            // Snub detection: disconnect peer if no data for 60s while unchoked
            if !choked
                && !seed_mode
                && active_piece.is_some()
                && last_piece_data.elapsed() > SNUB_TIMEOUT
            {
                return Err("peer snubbed (no data for 60s while unchoked)".to_string());
            }

            // Check completion with lock
            let now_complete = {
                let p = pieces.lock().unwrap();
                p.is_complete()
            };
            if now_complete && !seed_mode {
                seed_mode = true;
                log_info!("download complete");
                if !pending.is_empty() {
                    cancel_pending(&mut stream, &pending)?;
                    pending.clear();
                }
                if let Some(active) = active_piece.take() {
                    let mut p = pieces.lock().unwrap();
                    p.release_piece(peer_tag, active.index());
                }
                let _ = peer::write_message(&mut stream, &peer::Message::NotInterested);
                update_ui(ui_state, |state| {
                    if state.current_id == Some(torrent_id) {
                        state.status = "seeding".to_string();
                    }
                    update_torrent_entry(state, torrent_id, |torrent| {
                        torrent.status = "seeding".to_string();
                    });
                });
            }

            // Check endgame mode
            let endgame = {
                let p = pieces.lock().unwrap();
                p.remaining_blocks() <= ENDGAME_BLOCKS
            };
            if endgame && !endgame_announced {
                log_debug!("endgame mode");
                endgame_announced = true;
            }

            let paused = torrent_paused(paused_flag);
            if !seed_mode {
                if paused && !pause_sent {
                    if !pending.is_empty() {
                        cancel_pending(&mut stream, &pending)?;
                        let mut p = pieces.lock().unwrap();
                        for entry in pending.drain(..) {
                            p.mark_block_missing(entry.request.index, entry.request.begin)
                                .map_err(|err| format!("block timeout: {err}"))?;
                        }
                    }
                    peer::write_message(&mut stream, &peer::Message::NotInterested)
                        .map_err(|err| format!("not-interested write failed: {err}"))?;
                    pause_sent = true;
                } else if !paused && pause_sent {
                    peer::write_message(&mut stream, &peer::Message::Interested)
                        .map_err(|err| format!("interested write failed: {err}"))?;
                    pause_sent = false;
                }
            }
            if paused && !am_choking {
                if peer::write_message(&mut stream, &peer::Message::Choke).is_ok() {
                    am_choking = true;
                    last_sent = Instant::now();
                }
            } else if !paused {
                let should_unchoke = upload_manager.should_unchoke(peer_tag);
                if should_unchoke && am_choking {
                    if peer::write_message(&mut stream, &peer::Message::Unchoke).is_ok() {
                        am_choking = false;
                        last_sent = Instant::now();
                    }
                } else if !should_unchoke && !am_choking {
                    if peer::write_message(&mut stream, &peer::Message::Choke).is_ok() {
                        am_choking = true;
                        last_sent = Instant::now();
                    }
                }
            }

            if !seed_mode && !choked && !paused {
                if active_piece.is_none() {
                    if let Some(bits) = bitfield.as_ref() {
                        let (selected, has_needed) = {
                            let mut p = pieces.lock().unwrap();
                            let selected = p.reserve_piece_for_peer(peer_tag, bits, endgame);
                            let has_needed = selected.is_some()
                                || p.has_needed_piece(bits)
                                || (endgame && p.remaining_blocks() > 0);
                            (selected, has_needed)
                        };
                        if let Some(index) = selected {
                            let length = {
                                let p = pieces.lock().unwrap();
                                p.piece_length(index)
                            };
                            let length = match length {
                                Some(length) => length,
                                None => {
                                    let mut p = pieces.lock().unwrap();
                                    p.release_piece(peer_tag, index);
                                    return Err("invalid piece length".to_string());
                                }
                            };
                            let buffer = match piece::PieceBuffer::new(index, length) {
                                Ok(buffer) => buffer,
                                Err(err) => {
                                    let mut p = pieces.lock().unwrap();
                                    p.release_piece(peer_tag, index);
                                    return Err(format!("piece buffer error: {err}"));
                                }
                            };
                            log_debug!("selected piece {index} from {addr}");
                            active_piece = Some(buffer);
                        } else if !has_needed {
                            log_debug!("peer {addr} has no needed pieces");
                            return Ok(());
                        }
                    }
                }

                if let Some(active_index) = active_piece.as_ref().map(|piece| piece.index()) {
                    while pending.len() < pipeline_depth {
                        let req = {
                            let mut p = pieces.lock().unwrap();
                            p.next_request_for_piece(active_index, endgame)
                        };
                        let req = if let Some(req) = req {
                            req
                        } else {
                            if endgame {
                                if let Some(entry) = oldest_pending(&pending) {
                                    if entry.sent_at.elapsed() > ENDGAME_DUP_TIMEOUT {
                                        peer::write_message(
                                            &mut stream,
                                            &peer::Message::Request {
                                                index: entry.request.index,
                                                begin: entry.request.begin,
                                                length: entry.request.length,
                                            },
                                        )
                                        .map_err(|err| format!("request write failed: {err}"))?;
                                        log_debug!(
                                            "endgame duplicate: piece={} begin={} length={}",
                                            entry.request.index,
                                            entry.request.begin,
                                            entry.request.length
                                        );
                                    }
                                }
                            }
                            break;
                        };
                        peer::write_message(
                            &mut stream,
                            &peer::Message::Request {
                                index: req.index,
                                begin: req.begin,
                                length: req.length,
                            },
                        )
                        .map_err(|err| format!("request write failed: {err}"))?;
                        log_debug!(
                            "requested block: piece={} begin={} length={}",
                            req.index,
                            req.begin,
                            req.length
                        );
                        pending.push(PendingRequest {
                            request: req,
                            sent_at: Instant::now(),
                        });
                    }
                }
            }

            if last_sent.elapsed() >= KEEPALIVE_INTERVAL {
                if peer::write_message(&mut stream, &peer::Message::KeepAlive).is_ok() {
                    last_sent = Instant::now();
                    idle = 0;
                }
            }

            if let Err(err) =
                send_completed_updates(&mut stream, completed_log, &mut completed_cursor)
            {
                return Err(err);
            }

            if allow_pex {
                if let Some(ext_id) = peer_ut_pex {
                    if last_pex.elapsed() > Duration::from_secs(60) {
                        let peers = {
                            let queue = peer_queue.lock().unwrap();
                            queue.sample(50)
                        };
                        if !peers.is_empty() {
                            let payload = build_ut_pex_payload(&peers);
                            let _ = peer::write_message(
                                &mut stream,
                                &peer::Message::Extended { ext_id, payload },
                            );
                        }
                        last_pex = Instant::now();
                    }
                }
            }

            match reader.read_message(&mut stream) {
                Ok(Some(message)) => {
                    log_debug!("peer msg: {}", message_summary(&message));
                    idle = 0;
                    match message {
                        peer::Message::Extended { ext_id, payload } => {
                            if ext_id == 0 {
                                if let Ok((_ut_meta, ut_pex, _size)) =
                                    parse_extended_handshake(&payload)
                                {
                                    if allow_pex {
                                        peer_ut_pex = ut_pex;
                                    }
                                }
                            } else if allow_pex && Some(ext_id) == peer_ut_pex {
                                if let Ok(peers) = parse_ut_pex(&payload) {
                                    if !peers.is_empty() {
                                        let mut queue = peer_queue.lock().unwrap();
                                        queue.enqueue_with_source(peers, PeerSource::Pex);
                                    }
                                }
                            }
                        }
                        peer::Message::Bitfield(bits) => {
                            let mut p = pieces.lock().unwrap();
                            if let Some(existing) = bitfield.as_ref() {
                                if existing.len() != bits.len() {
                                    ban_peer("bitfield length mismatch");
                                    return Err("bitfield length mismatch".to_string());
                                }
                                for idx in 0..p.piece_count() {
                                    if bitfield_has(&bits, idx) && !bitfield_has(existing, idx) {
                                        if let Err(err) = p.apply_have(idx as u32) {
                                            ban_peer("invalid have in bitfield");
                                            return Err(format!("have error: {err}"));
                                        }
                                    }
                                }
                            } else if let Err(err) = p.apply_peer_bitfield(&bits) {
                                ban_peer("invalid bitfield");
                                return Err(format!("bitfield error: {err}"));
                            }
                            bitfield = Some(bits);
                        }
                        peer::Message::Have(index) => {
                            let mut p = pieces.lock().unwrap();
                            let len = p.bitfield_len();
                            if bitfield.is_none() {
                                bitfield = Some(vec![0u8; len]);
                            }
                            if let Some(bits) = bitfield.as_mut() {
                                let idx = index as usize;
                                if !bitfield_has(bits, idx) {
                                    if let Err(err) = p.apply_have(index) {
                                        ban_peer("invalid have");
                                        return Err(format!("have error: {err}"));
                                    }
                                    if let Err(err) = set_bit(bits, idx) {
                                        ban_peer("invalid have index");
                                        return Err(err);
                                    }
                                }
                            }
                            // Super seed: peer redistributed our piece, advertise next
                            if super_seed_mode {
                                if super_seed_piece == Some(index) {
                                    let piece_count = p.piece_count();
                                    if piece_count > 0 {
                                        let next = (index + 1) % piece_count as u32;
                                        let _ = peer::write_message(
                                            &mut stream,
                                            &peer::Message::Have(next),
                                        );
                                        super_seed_piece = Some(next);
                                    }
                                }
                            }
                        }
                        peer::Message::Interested => {
                            peer_interested = true;
                            upload_manager.set_interested(peer_tag, true);
                            // Immediately unchoke if eligible (don't wait for next loop)
                            if am_choking && !paused {
                                if upload_manager.should_unchoke(peer_tag) {
                                    if peer::write_message(&mut stream, &peer::Message::Unchoke)
                                        .is_ok()
                                    {
                                        am_choking = false;
                                        last_sent = Instant::now();
                                    }
                                }
                            }
                        }
                        peer::Message::NotInterested => {
                            peer_interested = false;
                            upload_manager.set_interested(peer_tag, false);
                        }
                        peer::Message::Choke => {
                            choked = true;
                            choke_since = Some(Instant::now());
                            log_debug!(
                                "choked by {addr}, had {} pending, active_piece={}",
                                pending.len(),
                                active_piece
                                    .as_ref()
                                    .map(|a| a.index() as i64)
                                    .unwrap_or(-1)
                            );
                            cancel_pending(&mut stream, &pending)?;
                            {
                                let mut p = pieces.lock().unwrap();
                                for entry in pending.drain(..) {
                                    p.mark_block_missing(entry.request.index, entry.request.begin)
                                        .map_err(|err| format!("block timeout: {err}"))?;
                                }
                            }
                        }
                        peer::Message::Unchoke => {
                            choked = false;
                            choke_since = None;
                            last_piece_data = Instant::now();
                            log_debug!("unchoked by {addr}");
                        }
                        peer::Message::Request {
                            index,
                            begin,
                            length,
                        } => {
                            if !am_choking && peer_interested {
                                if let Err(err) = handle_upload_request(
                                    &mut stream,
                                    pieces,
                                    storage,
                                    base_piece_length,
                                    index,
                                    begin,
                                    length,
                                    limits,
                                    uploaded,
                                    upload_manager,
                                    peer_tag,
                                ) {
                                    let _ = err;
                                    log_debug!("upload request rejected: {err}");
                                } else {
                                    last_sent = Instant::now();
                                    check_seed_ratio(uploaded, downloaded, stop_flag);
                                }
                            }
                        }
                        peer::Message::Piece {
                            index,
                            begin,
                            block,
                        } => {
                            last_piece_data = Instant::now();
                            if let Some(active) = active_piece.as_mut() {
                                if active.index() != index {
                                    continue;
                                }
                                let complete = active
                                    .add_block(begin, &block)
                                    .map_err(|err| format!("block error: {err}"))?;
                                let was_new = {
                                    let mut p = pieces.lock().unwrap();
                                    p.mark_block_complete(index, begin, block.len() as u32)
                                        .map_err(|err| format!("block state error: {err}"))?
                                };
                                if was_new {
                                    SESSION_DOWNLOADED_BYTES
                                        .fetch_add(block.len() as u64, Ordering::SeqCst);
                                    downloaded.fetch_add(block.len() as u64, Ordering::SeqCst);
                                }
                                limits.global_down.throttle(block.len());
                                limits.torrent_down.throttle(block.len());
                                if let Some(pos) = pending.iter().position(|entry| {
                                    entry.request.index == index && entry.request.begin == begin
                                }) {
                                    let sent_at = pending[pos].sent_at;
                                    let rtt_ms =
                                        Instant::now().duration_since(sent_at).as_millis() as f64;
                                    pending.swap_remove(pos);
                                    let next = match rtt_ema_ms {
                                        Some(prev) => (prev * 0.8) + (rtt_ms * 0.2),
                                        None => rtt_ms,
                                    };
                                    rtt_ema_ms = Some(next);
                                    if next.is_finite() && next > 1.0 {
                                        let desired = ((RTT_TARGET_MS / next).round() as usize)
                                            .clamp(MIN_PIPELINE_DEPTH, MAX_PIPELINE_DEPTH);
                                        if desired > pipeline_depth {
                                            pipeline_depth = (pipeline_depth + 1).min(desired);
                                        } else if desired < pipeline_depth {
                                            pipeline_depth =
                                                pipeline_depth.saturating_sub(1).max(desired);
                                        }
                                    }
                                }
                                if complete {
                                    let expected = {
                                        let p = pieces.lock().unwrap();
                                        p.piece_hash(index)
                                            .ok_or_else(|| "missing piece hash".to_string())?
                                            .clone()
                                    };
                                    if verify_piece_hash(active.data(), &expected) {
                                        let offset =
                                            (index as u64).saturating_mul(base_piece_length);
                                        {
                                            let mut s = storage.lock().unwrap();
                                            s.write_at(offset, active.data())
                                                .map_err(|err| format!("write failed: {err}"))?;
                                        }
                                        log_debug!(
                                            "piece complete: index={} bytes={} from {addr}",
                                            index,
                                            active.length()
                                        );
                                        let (completed, was_new) = {
                                            let mut p = pieces.lock().unwrap();
                                            let was_new =
                                                p.mark_piece_complete(index).map_err(|err| {
                                                    format!("mark complete failed: {err}")
                                                })?;
                                            p.release_piece(peer_tag, index);
                                            (p.completed_pieces(), was_new)
                                        };
                                        let piece_start =
                                            (index as u64).saturating_mul(base_piece_length);
                                        let piece_len = active.length() as u64;
                                        if was_new {
                                            if let Ok(mut log) = completed_log.lock() {
                                                log.push(index);
                                            }
                                            let paused = torrent_paused(paused_flag);
                                            let complete_now = {
                                                let p = pieces.lock().unwrap();
                                                p.is_complete()
                                            };
                                            let status = if paused {
                                                "paused"
                                            } else if complete_now {
                                                "seeding"
                                            } else {
                                                "downloading"
                                            };
                                            update_ui(ui_state, |state| {
                                                apply_piece_completion_ui(
                                                    state,
                                                    torrent_id,
                                                    completed,
                                                    file_spans,
                                                    piece_start,
                                                    piece_len,
                                                    true,
                                                );
                                                update_torrent_entry(
                                                    state,
                                                    torrent_id,
                                                    |torrent| {
                                                        torrent.paused = paused;
                                                        torrent.status = status.to_string();
                                                    },
                                                );
                                                if state.current_id == Some(torrent_id) {
                                                    state.paused = is_paused();
                                                    state.status = status.to_string();
                                                }
                                            });
                                        } else {
                                            let paused = torrent_paused(paused_flag);
                                            let complete_now = {
                                                let p = pieces.lock().unwrap();
                                                p.is_complete()
                                            };
                                            let status = if paused {
                                                "paused"
                                            } else if complete_now {
                                                "seeding"
                                            } else {
                                                "downloading"
                                            };
                                            update_ui(ui_state, |state| {
                                                apply_piece_completion_ui(
                                                    state,
                                                    torrent_id,
                                                    completed,
                                                    file_spans,
                                                    piece_start,
                                                    piece_len,
                                                    false,
                                                );
                                                update_torrent_entry(
                                                    state,
                                                    torrent_id,
                                                    |torrent| {
                                                        torrent.paused = paused;
                                                        torrent.status = status.to_string();
                                                    },
                                                );
                                                if state.current_id == Some(torrent_id) {
                                                    state.paused = is_paused();
                                                    state.status = status.to_string();
                                                }
                                            });
                                        }
                                        active_piece = None;
                                        pending.clear();
                                    } else {
                                        log_warn!("piece hash mismatch: index={index}");
                                        ban_peer("piece hash mismatch");
                                        let piece_len = active.length() as u64;
                                        let _ = SESSION_DOWNLOADED_BYTES.fetch_update(
                                            Ordering::SeqCst,
                                            Ordering::SeqCst,
                                            |value| Some(value.saturating_sub(piece_len)),
                                        );
                                        let _ = downloaded.fetch_update(
                                            Ordering::SeqCst,
                                            Ordering::SeqCst,
                                            |value| Some(value.saturating_sub(piece_len)),
                                        );
                                        {
                                            let mut p = pieces.lock().unwrap();
                                            p.reset_piece(index)
                                                .map_err(|err| format!("reset failed: {err}"))?;
                                        }
                                        cancel_pending(&mut stream, &pending)?;
                                        pending.clear();
                                        return Err("piece hash mismatch".to_string());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(None) => {
                    idle += 1;
                }
                Err(err) => return Err(format!("message read failed: {err}")),
            }

            if !pending.is_empty() {
                let now = Instant::now();
                timed_out.clear();
                pending.retain(|entry| {
                    if now.duration_since(entry.sent_at) > REQUEST_TIMEOUT {
                        timed_out.push(entry.request);
                        false
                    } else {
                        true
                    }
                });
                if !timed_out.is_empty() {
                    log_debug!(
                        "{} requests timed out for {addr}, pipeline_depth={pipeline_depth}",
                        timed_out.len()
                    );
                    pipeline_depth = pipeline_depth.saturating_sub(1).max(MIN_PIPELINE_DEPTH);
                }
                for req in timed_out.drain(..) {
                    peer::write_message(
                        &mut stream,
                        &peer::Message::Cancel {
                            index: req.index,
                            begin: req.begin,
                            length: req.length,
                        },
                    )
                    .map_err(|err| format!("cancel write failed: {err}"))?;
                    {
                        let mut p = pieces.lock().unwrap();
                        p.mark_block_missing(req.index, req.begin)
                            .map_err(|err| format!("block timeout: {err}"))?;
                    }
                }
            }
        }
    })();

    if result.is_err() {
        let mut p = pieces.lock().unwrap();
        abandon_inflight(&mut p, &mut pending, &active_piece);
    }

    if let Some(bits) = bitfield {
        let mut p = pieces.lock().unwrap();
        let _ = p.remove_peer_bitfield(&bits);
    }

    upload_manager.unregister(peer_tag);
    PEER_DISCONNECTED.fetch_add(1, Ordering::SeqCst);

    result
}

fn bind_tcp_dual_stack(port: u16) -> Result<TcpListener, String> {
    use std::net::Ipv6Addr;
    let v6_addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
    match TcpListener::bind(v6_addr) {
        Ok(listener) => {
            log_info!("listening on [::] (dual-stack) port {port}");
            Ok(listener)
        }
        Err(_) => {
            let v4_addr = SocketAddr::from(([0, 0, 0, 0], port));
            TcpListener::bind(v4_addr).map_err(|e| format!("bind port {port}: {e}"))
        }
    }
}

fn connect_peer(addr: SocketAddr, connect_cfg: &ConnectionConfig) -> Result<PeerStream, String> {
    connect_peer_for_metadata(addr, connect_cfg)
}

fn connect_peer_for_metadata(
    addr: SocketAddr,
    connect_cfg: &ConnectionConfig,
) -> Result<PeerStream, String> {
    if let Some(filter) = connect_cfg.ip_filter.as_ref() {
        if filter.is_blocked(addr.ip()) {
            return Err("peer blocked".to_string());
        }
    }

    if let Some(proxy_cfg) = connect_cfg.proxy.as_ref() {
        let stream = proxy::connect_through_proxy(proxy_cfg, addr, Duration::from_secs(10))
            .map_err(|err| format!("proxy connect {addr} failed: {err}"))?;
        let _ = stream.set_nodelay(true);
        return Ok(PeerStream::tcp(stream));
    }

    let tcp_result = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|err| format!("connect {addr} failed: {err}"));
    if let Ok(stream) = tcp_result {
        let _ = stream.set_nodelay(true);
        return Ok(PeerStream::tcp(stream));
    }
    let tcp_err = tcp_result.err();

    if let Some(connector) = connect_cfg.utp.as_ref() {
        if let Ok(stream) = connector.connect(addr) {
            return Ok(PeerStream::utp(stream));
        }
    }

    Err(tcp_err.unwrap_or_else(|| "connect failed".to_string()))
}

fn outbound_handshake(
    stream: &mut PeerStream,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    encryption: EncryptionMode,
) -> Result<peer::Handshake, String> {
    match encryption {
        EncryptionMode::Disable => plaintext_handshake(stream, info_hash, peer_id),
        EncryptionMode::Prefer | EncryptionMode::Require => {
            mse_outbound_handshake(stream, info_hash, peer_id, encryption)
        }
    }
}

fn plaintext_handshake(
    stream: &mut PeerStream,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
) -> Result<peer::Handshake, String> {
    peer::write_handshake(stream, info_hash, peer_id, true)
        .map_err(|err| format!("handshake write failed: {err}"))?;
    let handshake =
        peer::read_handshake(stream).map_err(|err| format!("handshake read failed: {err}"))?;
    if handshake.info_hash != info_hash {
        return Err("peer returned wrong info hash".to_string());
    }
    Ok(handshake)
}

fn mse_outbound_handshake(
    stream: &mut PeerStream,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    encryption: EncryptionMode,
) -> Result<peer::Handshake, String> {
    let allow_plain = encryption != EncryptionMode::Require;
    let handshake_bytes = peer::build_handshake(info_hash, peer_id, true);
    let (crypto, cipher) = mse::initiate(stream, info_hash, allow_plain, &handshake_bytes)?;
    if let Some(cipher) = cipher {
        stream.enable_encryption(cipher);
    } else if matches!(crypto, mse::CryptoMode::Plaintext) && encryption == EncryptionMode::Require
    {
        return Err("peer selected plaintext".to_string());
    }
    // Peer's BT handshake is the first thing in the encrypted payload stream
    let handshake =
        peer::read_handshake(stream).map_err(|err| format!("mse handshake read: {err}"))?;
    if handshake.info_hash != info_hash {
        return Err("peer returned wrong info hash".to_string());
    }
    Ok(handshake)
}

fn inbound_handshake(
    stream: &mut PeerStream,
    registry: &SessionRegistry,
    encryption: EncryptionMode,
) -> Result<(peer::Handshake, Arc<TorrentContext>), String> {
    let mut first = [0u8; 1];
    stream
        .read_exact(&mut first)
        .map_err(|err| err.to_string())?;
    if first[0] == 19 {
        if encryption == EncryptionMode::Require {
            return Err("plaintext handshake not allowed".to_string());
        }
        let handshake = read_handshake_with_first(stream, first[0])?;
        let context = find_context(registry, handshake.info_hash)?;
        peer::write_handshake(stream, context.info_hash, context.peer_id, true)
            .map_err(|err| err.to_string())?;
        return Ok((handshake, context));
    }
    if encryption == EncryptionMode::Disable {
        return Err("encryption disabled".to_string());
    }
    let info_hashes = list_info_hashes(registry)?;
    let (crypto, cipher, info_hash, peer_ia) = mse::accept(
        stream,
        &info_hashes,
        first[0],
        encryption != EncryptionMode::Require,
    )?;
    if let Some(cipher) = cipher {
        stream.enable_encryption(cipher);
    } else if matches!(crypto, mse::CryptoMode::Plaintext) && encryption == EncryptionMode::Require
    {
        return Err("peer selected plaintext".to_string());
    }
    let handshake = peer::parse_handshake(&peer_ia).map_err(|err| err.to_string())?;
    if handshake.info_hash != info_hash {
        return Err("peer returned wrong info hash".to_string());
    }
    let context = find_context(registry, info_hash)?;
    let response = peer::build_handshake(context.info_hash, context.peer_id, true);
    stream
        .write_all(&response)
        .map_err(|err| format!("mse response write: {err}"))?;
    Ok((handshake, context))
}

fn read_handshake_with_first(
    stream: &mut PeerStream,
    first: u8,
) -> Result<peer::Handshake, String> {
    let mut buf = [0u8; HANDSHAKE_LEN];
    buf[0] = first;
    stream
        .read_exact(&mut buf[1..])
        .map_err(|err| err.to_string())?;
    peer::parse_handshake(&buf).map_err(|err| err.to_string())
}

fn list_info_hashes(registry: &SessionRegistry) -> Result<Vec<[u8; 20]>, String> {
    let guard = registry
        .lock()
        .map_err(|_| "registry lock failed".to_string())?;
    if guard.is_empty() {
        return Err("no torrents available".to_string());
    }
    Ok(guard.keys().copied().collect())
}

fn find_context(
    registry: &SessionRegistry,
    info_hash: [u8; 20],
) -> Result<Arc<TorrentContext>, String> {
    let guard = registry
        .lock()
        .map_err(|_| "registry lock failed".to_string())?;
    guard
        .get(&info_hash)
        .cloned()
        .ok_or_else(|| "unknown info hash".to_string())
}

fn find_context_by_id(registry: &SessionRegistry, torrent_id: u64) -> Option<Arc<TorrentContext>> {
    let guard = registry.lock().ok()?;
    guard.values().find(|ctx| ctx.id == torrent_id).cloned()
}

fn set_torrent_label(
    registry: &SessionRegistry,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    session_store: &Arc<SessionStore>,
    torrent_id: u64,
    label: &str,
) -> Result<(), String> {
    let context =
        find_context_by_id(registry, torrent_id).ok_or_else(|| "torrent not found".to_string())?;
    *context.label.lock().unwrap() = label.to_string();
    session_store.set_label(context.info_hash, label);
    update_ui(ui_state, |state| {
        update_torrent_entry(state, torrent_id, |torrent| {
            torrent.label = label.to_string();
        });
    });
    Ok(())
}

fn add_torrent_tracker(
    registry: &SessionRegistry,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    torrent_id: u64,
    url: &str,
) -> Result<(), String> {
    let context =
        find_context_by_id(registry, torrent_id).ok_or_else(|| "torrent not found".to_string())?;
    let mut trackers = context.trackers.lock().unwrap();
    if url.starts_with("udp://") {
        if !trackers.udp.contains(&url.to_string()) {
            trackers.udp.push(url.to_string());
        }
    } else if url.starts_with("http://") || url.starts_with("https://") {
        if !trackers.http.contains(&url.to_string()) {
            trackers.http.push(url.to_string());
        }
    } else {
        return Err("invalid tracker URL scheme".to_string());
    }
    let all: Vec<String> = trackers
        .http
        .iter()
        .chain(trackers.udp.iter())
        .cloned()
        .collect();
    drop(trackers);
    update_ui(ui_state, |state| {
        update_torrent_entry(state, torrent_id, |torrent| {
            torrent.trackers = all.clone();
        });
    });
    Ok(())
}

fn remove_torrent_tracker(
    registry: &SessionRegistry,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    torrent_id: u64,
    url: &str,
) -> Result<(), String> {
    let context =
        find_context_by_id(registry, torrent_id).ok_or_else(|| "torrent not found".to_string())?;
    let mut trackers = context.trackers.lock().unwrap();
    trackers.http.retain(|u| u != url);
    trackers.udp.retain(|u| u != url);
    let all: Vec<String> = trackers
        .http
        .iter()
        .chain(trackers.udp.iter())
        .cloned()
        .collect();
    drop(trackers);
    update_ui(ui_state, |state| {
        update_torrent_entry(state, torrent_id, |torrent| {
            torrent.trackers = all.clone();
        });
    });
    Ok(())
}

fn recheck_torrent(
    registry: &SessionRegistry,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    torrent_id: u64,
) -> Result<(), String> {
    let context =
        find_context_by_id(registry, torrent_id).ok_or_else(|| "torrent not found".to_string())?;
    let pieces_arc = Arc::clone(&context.pieces);
    let storage_arc = Arc::clone(&context.storage);
    let base_piece_length = context.base_piece_length;
    let ui_clone = ui_state.clone();
    update_ui(ui_state, |state| {
        state.status = "checking".to_string();
        update_torrent_entry(state, torrent_id, |torrent| {
            torrent.status = "checking".to_string();
        });
    });
    thread::spawn(move || {
        {
            let mut p = pieces_arc.lock().unwrap();
            p.reset_verified();
        }
        {
            let mut p = pieces_arc.lock().unwrap();
            let mut s = storage_arc.lock().unwrap();
            let _ = full_recheck(&mut p, &mut s, base_piece_length);
        }
        let (completed, total, completed_bytes) = {
            let p = pieces_arc.lock().unwrap();
            (p.completed_pieces(), p.piece_count(), p.completed_bytes())
        };
        let status = if completed == total {
            "seeding"
        } else {
            "downloading"
        };
        update_ui(&ui_clone, |state| {
            state.status = status.to_string();
            state.completed_pieces = completed;
            state.completed_bytes = completed_bytes;
            update_torrent_entry(state, torrent_id, |torrent| {
                torrent.status = status.to_string();
                torrent.completed_pieces = completed;
                torrent.completed_bytes = completed_bytes;
            });
        });
        log_info!("recheck complete: {completed}/{total} pieces valid");
    });
    Ok(())
}

#[cfg(feature = "verbose")]
fn message_summary(message: &peer::Message) -> String {
    match message {
        peer::Message::KeepAlive => "keep-alive".to_string(),
        peer::Message::Choke => "choke".to_string(),
        peer::Message::Unchoke => "unchoke".to_string(),
        peer::Message::Interested => "interested".to_string(),
        peer::Message::NotInterested => "not-interested".to_string(),
        peer::Message::Have(index) => format!("have index={index}"),
        peer::Message::Bitfield(bits) => format!("bitfield len={}", bits.len()),
        peer::Message::Request {
            index,
            begin,
            length,
        } => {
            format!("request index={index} begin={begin} length={length}")
        }
        peer::Message::Piece {
            index,
            begin,
            block,
        } => {
            format!("piece index={index} begin={begin} block={}", block.len())
        }
        peer::Message::Cancel {
            index,
            begin,
            length,
        } => {
            format!("cancel index={index} begin={begin} length={length}")
        }
        peer::Message::Port(port) => format!("port {port}"),
        peer::Message::Extended { ext_id, payload } => {
            format!("extended id={} len={}", ext_id, payload.len())
        }
    }
}

struct PendingRequest {
    request: piece::BlockRequest,
    sent_at: Instant,
}

fn is_retryable_peer_error(err: &str) -> bool {
    let err = err.to_ascii_lowercase();
    if err.contains("wrong info hash") || err.contains("no needed pieces") {
        return false;
    }
    err.contains("connect")
        || err.contains("timeout")
        || err.contains("timed out")
        || err.contains("connection refused")
        || err.contains("connection reset")
        || err.contains("handshake read failed")
        || err.contains("handshake write failed")
        || err.contains("message read failed")
        || err.contains("peer timed out")
}

fn bitfield_has(bitfield: &[u8], index: usize) -> bool {
    let byte = bitfield[index / 8];
    let offset = index % 8;
    let mask = 0x80 >> offset;
    (byte & mask) != 0
}

fn set_bit(bitfield: &mut [u8], index: usize) -> Result<(), String> {
    if index >= bitfield.len() * 8 {
        return Err("bitfield index out of range".to_string());
    }
    let byte = index / 8;
    let offset = index % 8;
    let mask = 0x80 >> offset;
    bitfield[byte] |= mask;
    Ok(())
}

fn build_bitfield(pieces: &piece::PieceManager) -> Vec<u8> {
    let mut bitfield = vec![0u8; pieces.bitfield_len()];
    for idx in 0..pieces.piece_count() {
        if pieces.is_piece_complete(idx as u32) {
            let byte = idx / 8;
            let offset = idx % 8;
            bitfield[byte] |= 0x80 >> offset;
        }
    }
    bitfield
}

fn build_ut_pex_payload(peers: &[SocketAddr]) -> Vec<u8> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for peer in peers {
        match peer.ip() {
            std::net::IpAddr::V4(ip) => {
                v4.extend_from_slice(&ip.octets());
                v4.extend_from_slice(&peer.port().to_be_bytes());
            }
            std::net::IpAddr::V6(ip) => {
                v6.extend_from_slice(&ip.octets());
                v6.extend_from_slice(&peer.port().to_be_bytes());
            }
        }
    }
    let mut dict = Vec::new();
    if !v4.is_empty() {
        dict.push((b"added".to_vec(), Value::Bytes(v4)));
    }
    if !v6.is_empty() {
        dict.push((b"added6".to_vec(), Value::Bytes(v6)));
    }
    bencode::encode(&Value::Dict(dict))
}

fn parse_ut_pex(payload: &[u8]) -> Result<Vec<SocketAddr>, String> {
    let (dict, _) = parse_bencode_dict(payload)?;
    let mut peers = Vec::new();
    if let Some(Value::Bytes(bytes)) = dict_get(&dict, b"added") {
        peers.extend(decode_compact_peers(bytes));
    }
    if let Some(Value::Bytes(bytes)) = dict_get(&dict, b"added6") {
        peers.extend(decode_compact_peers6(bytes));
    }
    Ok(peers)
}

fn decode_compact_peers(bytes: &[u8]) -> Vec<SocketAddr> {
    let mut peers = Vec::new();
    if bytes.len() % 6 != 0 {
        return peers;
    }
    for chunk in bytes.chunks_exact(6) {
        let ip = std::net::Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        let port = u16::from_be_bytes([chunk[4], chunk[5]]);
        peers.push(SocketAddr::new(ip.into(), port));
    }
    peers
}

fn decode_compact_peers6(bytes: &[u8]) -> Vec<SocketAddr> {
    let mut peers = Vec::new();
    if bytes.len() % 18 != 0 {
        return peers;
    }
    for chunk in bytes.chunks_exact(18) {
        let ip = std::net::Ipv6Addr::from([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            chunk[8], chunk[9], chunk[10], chunk[11], chunk[12], chunk[13], chunk[14], chunk[15],
        ]);
        let port = u16::from_be_bytes([chunk[16], chunk[17]]);
        peers.push(SocketAddr::new(ip.into(), port));
    }
    peers
}

fn send_completed_updates<W: Write>(
    stream: &mut W,
    completed_log: &Arc<Mutex<Vec<u32>>>,
    cursor: &mut usize,
) -> Result<(), String> {
    let updates = {
        let log = completed_log.lock().unwrap();
        if *cursor >= log.len() {
            return Ok(());
        }
        let slice = log[*cursor..].to_vec();
        *cursor = log.len();
        slice
    };

    for index in updates {
        peer::write_message(stream, &peer::Message::Have(index))
            .map_err(|err| format!("have write failed: {err}"))?;
    }
    Ok(())
}

fn register_session(registry: &SessionRegistry, context: Arc<TorrentContext>) {
    if let Ok(mut guard) = registry.lock() {
        guard.insert(context.info_hash, context);
    }
}

fn unregister_session(registry: &SessionRegistry, info_hash: [u8; 20]) {
    if let Ok(mut guard) = registry.lock() {
        guard.remove(&info_hash);
    }
}

fn start_utp_listener(
    listener: utp::UtpListener,
    registry: SessionRegistry,
    inbound: InboundConfig,
) {
    thread::spawn(move || loop {
        if shutdown_requested() {
            break;
        }
        if let Some(stream) = listener.try_accept() {
            if let Some(slot_guard) = inbound.try_acquire_handler_slot() {
                let registry = Arc::clone(&registry);
                let inbound = inbound.clone();
                thread::spawn(move || {
                    let _slot_guard = slot_guard;
                    handle_incoming_peer(PeerStream::utp(stream), registry, inbound);
                });
            } else {
                log_debug!("dropping inbound uTP peer: handler capacity reached");
            }
        } else {
            sleep_with_shutdown(Duration::from_millis(20));
        }
    });
}

fn start_inbound_listener(port: u16, registry: SessionRegistry, inbound: InboundConfig) {
    thread::spawn(move || {
        let listener = match bind_tcp_dual_stack(port) {
            Ok(listener) => listener,
            Err(err) => {
                log_warn!("inbound listener failed: {err}");
                return;
            }
        };
        for stream in listener.incoming() {
            if shutdown_requested() {
                break;
            }
            match stream {
                Ok(stream) => {
                    if let Some(slot_guard) = inbound.try_acquire_handler_slot() {
                        let registry = Arc::clone(&registry);
                        let inbound = inbound.clone();
                        thread::spawn(move || {
                            let _slot_guard = slot_guard;
                            handle_incoming_peer(PeerStream::tcp(stream), registry, inbound);
                        });
                    } else {
                        log_debug!("dropping inbound TCP peer: handler capacity reached");
                    }
                }
                Err(err) => {
                    log_warn!("inbound accept failed: {err}");
                }
            }
        }
    });
}

fn handle_incoming_peer(mut stream: PeerStream, registry: SessionRegistry, inbound: InboundConfig) {
    let addr = match stream.peer_addr() {
        Some(addr) => addr,
        None => return,
    };
    if let Some(filter) = inbound.ip_filter.as_ref() {
        if filter.is_blocked(addr.ip()) {
            log_debug!("peer {addr} blocked by filter");
            return;
        }
    }
    if let Err(err) = stream.set_read_timeout(Some(Duration::from_secs(5))) {
        let _ = err;
        log_debug!("peer {addr} timeout failed: {err}");
        return;
    }
    if let Err(err) = stream.set_write_timeout(Some(Duration::from_secs(5))) {
        let _ = err;
        log_debug!("peer {addr} timeout failed: {err}");
        return;
    }

    let (_handshake, context) = match inbound_handshake(&mut stream, &registry, inbound.encryption)
    {
        Ok(result) => result,
        Err(err) => {
            let _ = err;
            log_debug!("peer {addr} handshake failed: {err}");
            return;
        }
    };
    let peer_tag = context.peer_tags.fetch_add(1, Ordering::SeqCst);
    context.upload_manager.register(peer_tag);
    PEER_CONNECTED.fetch_add(1, Ordering::SeqCst);

    let mut reader = peer::MessageReader::new();
    let mut peer_interested = false;
    let mut am_choking = true;
    let mut last_sent = Instant::now();
    let mut idle: u32 = 0;
    let mut completed_cursor = {
        let log = context.completed_log.lock().unwrap();
        log.len()
    };

    let (local_bitfield, have_pieces) = {
        let p = context.pieces.lock().unwrap();
        let bits = build_bitfield(&p);
        (bits, p.completed_pieces() > 0)
    };
    let inbound_super_seed = have_pieces && SUPER_SEED.load(Ordering::SeqCst);
    if inbound_super_seed {
        // BEP 16: send single HAVE instead of full bitfield
        let piece_count = {
            let p = context.pieces.lock().unwrap();
            p.piece_count()
        };
        if piece_count > 0 {
            let mut sv = std::process::id() as u64 ^ peer_tag;
            sv ^= sv << 13;
            sv ^= sv >> 7;
            let idx = (sv % piece_count as u64) as u32;
            let _ = peer::write_message(&mut stream, &peer::Message::Have(idx));
        }
    } else if have_pieces {
        let _ = peer::write_message(&mut stream, &peer::Message::Bitfield(local_bitfield));
    }

    loop {
        if torrent_stop_requested(&context.stop_requested) {
            break;
        }
        if idle > MAX_IDLE_TICKS_SEED {
            break;
        }

        let paused = torrent_paused(&context.paused);
        if paused && !am_choking {
            if peer::write_message(&mut stream, &peer::Message::Choke).is_ok() {
                am_choking = true;
                last_sent = Instant::now();
            }
        } else if !paused {
            let should_unchoke = context.upload_manager.should_unchoke(peer_tag);
            if should_unchoke && am_choking {
                if peer::write_message(&mut stream, &peer::Message::Unchoke).is_ok() {
                    am_choking = false;
                    last_sent = Instant::now();
                }
            } else if !should_unchoke && !am_choking {
                if peer::write_message(&mut stream, &peer::Message::Choke).is_ok() {
                    am_choking = true;
                    last_sent = Instant::now();
                }
            }
        }

        if last_sent.elapsed() >= KEEPALIVE_INTERVAL {
            if peer::write_message(&mut stream, &peer::Message::KeepAlive).is_ok() {
                last_sent = Instant::now();
                idle = 0;
            }
        }

        if send_completed_updates(&mut stream, &context.completed_log, &mut completed_cursor)
            .is_err()
        {
            break;
        }

        match reader.read_message(&mut stream) {
            Ok(Some(message)) => {
                idle = 0;
                match message {
                    peer::Message::Interested => {
                        peer_interested = true;
                        context.upload_manager.set_interested(peer_tag, true);
                        // Immediately unchoke if eligible
                        if am_choking && !paused {
                            if context.upload_manager.should_unchoke(peer_tag) {
                                if peer::write_message(&mut stream, &peer::Message::Unchoke).is_ok()
                                {
                                    am_choking = false;
                                    last_sent = Instant::now();
                                }
                            }
                        }
                    }
                    peer::Message::NotInterested => {
                        peer_interested = false;
                        context.upload_manager.set_interested(peer_tag, false);
                    }
                    peer::Message::Request {
                        index,
                        begin,
                        length,
                    } => {
                        if !am_choking && peer_interested {
                            if let Err(err) = handle_upload_request(
                                &mut stream,
                                &context.pieces,
                                &context.storage,
                                context.base_piece_length,
                                index,
                                begin,
                                length,
                                &context.limits,
                                &context.uploaded,
                                &context.upload_manager,
                                peer_tag,
                            ) {
                                let _ = err;
                                log_debug!("inbound upload rejected: {err}");
                            } else {
                                last_sent = Instant::now();
                                check_seed_ratio(
                                    &context.uploaded,
                                    &context.downloaded,
                                    &context.stop_requested,
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(None) => {
                idle += 1;
            }
            Err(_) => break,
        }
    }

    context.upload_manager.unregister(peer_tag);
    PEER_DISCONNECTED.fetch_add(1, Ordering::SeqCst);
}

fn handle_upload_request<W: Write>(
    stream: &mut W,
    pieces: &Arc<Mutex<piece::PieceManager>>,
    storage: &Arc<Mutex<storage::Storage>>,
    base_piece_length: u64,
    index: u32,
    begin: u32,
    length: u32,
    limits: &TransferLimits,
    uploaded: &Arc<AtomicU64>,
    upload_manager: &Arc<UploadManager>,
    peer_tag: u64,
) -> Result<(), String> {
    if length == 0 || length > MAX_UPLOAD_BLOCK_LEN {
        return Err("invalid request length".to_string());
    }

    let piece_len = {
        let p = pieces.lock().unwrap();
        if !p.is_piece_complete(index) {
            return Err("requested piece not available".to_string());
        }
        p.piece_length(index)
            .ok_or_else(|| "missing piece length".to_string())?
    };

    let end = begin
        .checked_add(length)
        .ok_or_else(|| "invalid request offset".to_string())?;
    if end > piece_len {
        return Err("request out of bounds".to_string());
    }

    let offset = (index as u64)
        .saturating_mul(base_piece_length)
        .saturating_add(begin as u64);
    let mut buf = vec![0u8; length as usize];
    {
        let mut s = storage.lock().unwrap();
        s.read_at(offset, &mut buf)
            .map_err(|err| format!("read failed: {err}"))?;
    }

    limits.global_up.throttle(length as usize);
    limits.torrent_up.throttle(length as usize);
    peer::write_message(
        stream,
        &peer::Message::Piece {
            index,
            begin,
            block: buf,
        },
    )
    .map_err(|err| format!("piece write failed: {err}"))?;
    uploaded.fetch_add(length as u64, Ordering::SeqCst);
    SESSION_UPLOADED_BYTES.fetch_add(length as u64, Ordering::SeqCst);
    upload_manager.record_upload(peer_tag, length as u64);
    Ok(())
}

fn check_seed_ratio(
    uploaded: &Arc<AtomicU64>,
    downloaded: &Arc<AtomicU64>,
    stop_flag: &Arc<AtomicBool>,
) {
    let ratio_bits = SEED_RATIO_BITS.load(Ordering::SeqCst);
    if ratio_bits == 0 {
        return;
    }
    let ratio = f64::from_bits(ratio_bits);
    let up = uploaded.load(Ordering::SeqCst) as f64;
    let down = downloaded.load(Ordering::SeqCst).max(1) as f64;
    if up / down >= ratio {
        stop_flag.store(true, Ordering::SeqCst);
        log_info!("seed ratio {:.2} reached, stopping torrent", ratio);
    }
}

fn check_ratio_group(
    ratio_group_name: &Option<String>,
    uploaded: &Arc<AtomicU64>,
    downloaded: &Arc<AtomicU64>,
    stop_flag: &Arc<AtomicBool>,
    paused_flag: &Arc<AtomicBool>,
) {
    let group_name = match ratio_group_name {
        Some(name) => name,
        None => return,
    };
    let groups = match RATIO_GROUPS.get() {
        Some(g) => g,
        None => return,
    };
    let guard = match groups.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let group = match guard.iter().find(|g| g.name == *group_name) {
        Some(g) => g,
        None => return,
    };
    let up = uploaded.load(Ordering::SeqCst) as f64;
    let down = downloaded.load(Ordering::SeqCst).max(1) as f64;
    if up / down >= group.ratio {
        match group.action.as_str() {
            "stop" => {
                stop_flag.store(true, Ordering::SeqCst);
                log_info!(
                    "ratio group '{}' ratio {:.2} reached, stopping",
                    group_name,
                    group.ratio
                );
            }
            "pause" => {
                paused_flag.store(true, Ordering::SeqCst);
                log_info!(
                    "ratio group '{}' ratio {:.2} reached, pausing",
                    group_name,
                    group.ratio
                );
            }
            _ => {
                log_info!(
                    "ratio group '{}' ratio {:.2} reached (no action)",
                    group_name,
                    group.ratio
                );
            }
        }
    }
}

fn execute_schedule_command(
    command: &str,
    global_down: &Arc<RateLimiter>,
    global_up: &Arc<RateLimiter>,
    registry: &SessionRegistry,
) {
    if let Some(rest) = command.strip_prefix("throttle_down:") {
        if let Ok(bps) = rest.parse::<u64>() {
            global_down.set_limit_bps(bps);
            log_info!("schedule: download throttle set to {bps} B/s");
        }
    } else if let Some(rest) = command.strip_prefix("throttle_up:") {
        if let Ok(bps) = rest.parse::<u64>() {
            global_up.set_limit_bps(bps);
            log_info!("schedule: upload throttle set to {bps} B/s");
        }
    } else if command == "pause_all" {
        PAUSED.store(true, Ordering::SeqCst);
        log_info!("schedule: paused all torrents");
    } else if command == "resume_all" {
        PAUSED.store(false, Ordering::SeqCst);
        log_info!("schedule: resumed all torrents");
    } else if command == "stop_ratio_reached" {
        if let Ok(guard) = registry.lock() {
            for ctx in guard.values() {
                check_seed_ratio(&ctx.uploaded, &ctx.downloaded, &ctx.stop_requested);
            }
        }
        log_info!("schedule: checked seed ratios");
    } else {
        log_warn!("schedule: unknown command '{command}'");
    }
}

fn rss_add_feed(url: &str, interval: u64, download_dir: &Path) -> Result<(), String> {
    let lock = RSS_STATE.get().ok_or("rss not initialized")?;
    let mut state = lock.lock().map_err(|_| "rss lock failed".to_string())?;
    if state.feeds.iter().any(|f| f.url == url) {
        return Err("feed already exists".to_string());
    }
    state.feeds.push(rss::RssFeed {
        url: url.to_string(),
        title: String::new(),
        items: Vec::new(),
        last_poll: 0,
        poll_interval_secs: if interval > 0 { interval } else { 900 },
    });
    let rss_path = download_dir.join(".rustorrent").join("rss.benc");
    rss::save_rss_state(&rss_path, &state)?;
    log_info!("rss added feed: {url}");
    Ok(())
}

fn rss_remove_feed(url: &str, download_dir: &Path) -> Result<(), String> {
    let lock = RSS_STATE.get().ok_or("rss not initialized")?;
    let mut state = lock.lock().map_err(|_| "rss lock failed".to_string())?;
    let before = state.feeds.len();
    state.feeds.retain(|f| f.url != url);
    if state.feeds.len() == before {
        return Err("feed not found".to_string());
    }
    let rss_path = download_dir.join(".rustorrent").join("rss.benc");
    rss::save_rss_state(&rss_path, &state)?;
    log_info!("rss removed feed: {url}");
    Ok(())
}

fn rss_add_rule(
    name: &str,
    feed_url: &str,
    pattern: &str,
    download_dir: &Path,
) -> Result<(), String> {
    let lock = RSS_STATE.get().ok_or("rss not initialized")?;
    let mut state = lock.lock().map_err(|_| "rss lock failed".to_string())?;
    state.rules.push(rss::RssRule {
        name: name.to_string(),
        feed_url: feed_url.to_string(),
        pattern: pattern.to_string(),
    });
    let rss_path = download_dir.join(".rustorrent").join("rss.benc");
    rss::save_rss_state(&rss_path, &state)?;
    log_info!("rss added rule: {name} (pattern: {pattern})");
    Ok(())
}

fn rss_remove_rule(name: &str, download_dir: &Path) -> Result<(), String> {
    let lock = RSS_STATE.get().ok_or("rss not initialized")?;
    let mut state = lock.lock().map_err(|_| "rss lock failed".to_string())?;
    let before = state.rules.len();
    state.rules.retain(|r| r.name != name);
    if state.rules.len() == before {
        return Err("rule not found".to_string());
    }
    let rss_path = download_dir.join(".rustorrent").join("rss.benc");
    rss::save_rss_state(&rss_path, &state)?;
    log_info!("rss removed rule: {name}");
    Ok(())
}

fn schedule_rss_polls(
    args: &Args,
    poll_tx: &mpsc::Sender<RssPollResult>,
    inflight: &mut HashSet<String>,
) {
    let rss_lock = match RSS_STATE.get() {
        Some(lock) => lock,
        None => return,
    };
    let mut state = match rss_lock.lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };

    let now = rss::now_secs();
    let mut due_urls = Vec::new();
    for feed in &mut state.feeds {
        let interval = feed.poll_interval_secs.max(1);
        if now < feed.last_poll.saturating_add(interval) || inflight.contains(&feed.url) {
            continue;
        }
        feed.last_poll = now;
        inflight.insert(feed.url.clone());
        due_urls.push(feed.url.clone());
    }
    if !due_urls.is_empty() {
        let rss_path = args.download_dir.join(".rustorrent").join("rss.benc");
        let _ = rss::save_rss_state(&rss_path, &state);
    }
    drop(state);

    for url in due_urls {
        let tx = poll_tx.clone();
        thread::spawn(move || {
            let parsed = match http::get(&url, 2 * 1024 * 1024) {
                Ok(bytes) => rss::parse_feed(&bytes),
                Err(err) => Err(err.to_string()),
            };
            let _ = tx.send(RssPollResult { url, parsed });
        });
    }
}

fn drain_rss_poll_results(
    args: &Args,
    poll_rx: &mpsc::Receiver<RssPollResult>,
    download_tx: &mpsc::Sender<RssDownloadResult>,
    queue: &mut VecDeque<TorrentRequest>,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    next_id: &mut u64,
    poll_inflight: &mut HashSet<String>,
    download_inflight: &mut HashSet<String>,
) {
    while let Ok(result) = poll_rx.try_recv() {
        poll_inflight.remove(&result.url);

        let rss_lock = match RSS_STATE.get() {
            Some(lock) => lock,
            None => continue,
        };
        let mut state = match rss_lock.lock() {
            Ok(guard) => guard,
            Err(_) => continue,
        };
        let feed_idx = match state.feeds.iter().position(|feed| feed.url == result.url) {
            Some(idx) => idx,
            None => continue,
        };

        let mut download_jobs: Vec<(String, String, String)> = Vec::new();
        let mut should_save = false;
        match result.parsed {
            Ok((title, items)) => {
                if !title.is_empty() && state.feeds[feed_idx].title.is_empty() {
                    state.feeds[feed_idx].title = title;
                }
                let matches =
                    rss::match_rules(&items, &state.rules, &state.seen_guids, &result.url);
                let mut new_guids = Vec::new();
                for (item, rule) in &matches {
                    if download_inflight.contains(&item.guid) {
                        continue;
                    }
                    log_info!("rss match: '{}' (rule: '{}')", item.title, rule.name);
                    new_guids.push(item.guid.clone());
                    download_jobs.push((item.guid.clone(), item.link.clone(), item.title.clone()));
                }
                state.seen_guids.extend(new_guids);
                state.feeds[feed_idx].items = items;
                should_save = true;
            }
            Err(err) => {
                log_warn!("rss poll {}: {err}", result.url);
            }
        }
        if should_save {
            let rss_path = args.download_dir.join(".rustorrent").join("rss.benc");
            let _ = rss::save_rss_state(&rss_path, &state);
        }
        drop(state);

        for (guid, url, title) in download_jobs {
            if url.starts_with("magnet:?") {
                let request = TorrentRequest {
                    id: *next_id,
                    source: TorrentSource::Magnet(url.clone()),
                    download_dir: args.download_dir.clone(),
                    preallocate: args.preallocate,
                    initial_label: String::new(),
                };
                *next_id = next_id.saturating_add(1);
                enqueue_request_with_label(queue, ui_state, request, format!("rss: {title}"));
                log_info!("rss queued magnet: {title}");
                continue;
            }
            if !download_inflight.insert(guid.clone()) {
                continue;
            }
            let tx = download_tx.clone();
            thread::spawn(move || {
                let data = http::get(&url, 10 * 1024 * 1024).map_err(|err| err.to_string());
                let _ = tx.send(RssDownloadResult {
                    guid,
                    url,
                    title,
                    data,
                });
            });
        }
    }
}

fn drain_rss_download_results(
    args: &Args,
    download_rx: &mpsc::Receiver<RssDownloadResult>,
    queue: &mut VecDeque<TorrentRequest>,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    next_id: &mut u64,
    download_inflight: &mut HashSet<String>,
) {
    while let Ok(result) = download_rx.try_recv() {
        download_inflight.remove(&result.guid);
        match result.data {
            Ok(data) => {
                let request = TorrentRequest {
                    id: *next_id,
                    source: TorrentSource::Bytes(data),
                    download_dir: args.download_dir.clone(),
                    preallocate: args.preallocate,
                    initial_label: String::new(),
                };
                *next_id = next_id.saturating_add(1);
                enqueue_request_with_label(
                    queue,
                    ui_state,
                    request,
                    format!("rss: {}", result.title),
                );
                log_info!("rss queued torrent: {}", result.title);
            }
            Err(err) => {
                log_warn!("rss download {}: {err}", result.url);
            }
        }
    }
}

fn cancel_pending<W: Write>(stream: &mut W, pending: &[PendingRequest]) -> Result<(), String> {
    for entry in pending {
        peer::write_message(
            stream,
            &peer::Message::Cancel {
                index: entry.request.index,
                begin: entry.request.begin,
                length: entry.request.length,
            },
        )
        .map_err(|err| format!("cancel write failed: {err}"))?;
    }
    Ok(())
}

fn oldest_pending(pending: &[PendingRequest]) -> Option<&PendingRequest> {
    pending.iter().min_by_key(|entry| entry.sent_at)
}

fn abandon_inflight(
    pieces: &mut piece::PieceManager,
    pending: &mut Vec<PendingRequest>,
    active_piece: &Option<piece::PieceBuffer>,
) {
    if let Some(piece) = active_piece.as_ref() {
        pieces.clear_reservation(piece.index());
        if !piece.is_complete() {
            let _ = pieces.reset_piece(piece.index());
        }
        pending.clear();
        return;
    }

    for entry in pending.drain(..) {
        let _ = pieces.mark_block_missing(entry.request.index, entry.request.begin);
    }
}

fn update_ui<F>(state: &Option<Arc<Mutex<ui::UiState>>>, update: F)
where
    F: FnOnce(&mut ui::UiState),
{
    if let Some(state) = state {
        let mut guard = match state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.last_error = "ui state lock poisoned; recovered".to_string();
                guard
            }
        };
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| update(&mut guard))).is_err() {
            guard.last_error = "ui update panicked".to_string();
        }
    }
}

fn add_peer_country(torrent: &mut ui::UiTorrent, cc: &str) {
    if let Some(entry) = torrent
        .peer_country_counts
        .iter_mut()
        .find(|(c, _)| c == cc)
    {
        entry.1 += 1;
    } else {
        torrent.peer_country_counts.push((cc.to_string(), 1));
    }
    torrent.peer_country_counts.sort_by(|a, b| b.1.cmp(&a.1));
}

fn remove_peer_country(torrent: &mut ui::UiTorrent, cc: &str) {
    if let Some(entry) = torrent
        .peer_country_counts
        .iter_mut()
        .find(|(c, _)| c == cc)
    {
        entry.1 = entry.1.saturating_sub(1);
    }
    torrent.peer_country_counts.retain(|(_, count)| *count > 0);
}

fn update_torrent_entry<F>(state: &mut ui::UiState, torrent_id: u64, update: F)
where
    F: FnOnce(&mut ui::UiTorrent),
{
    if state.deleted_torrents.contains(&torrent_id) {
        return;
    }
    if let Some(pos) = state
        .torrents
        .iter()
        .position(|torrent| torrent.id == torrent_id)
    {
        update(&mut state.torrents[pos]);
        return;
    }
    let mut entry = ui::UiTorrent {
        id: torrent_id,
        ..ui::UiTorrent::default()
    };
    update(&mut entry);
    state.torrents.push(entry);
}

fn set_torrent_completion_ui(
    state: &mut ui::UiState,
    torrent_id: u64,
    completed_pieces: usize,
    completed_bytes: u64,
) {
    update_torrent_entry(state, torrent_id, |torrent| {
        torrent.completed_pieces = completed_pieces;
        torrent.completed_bytes = completed_bytes;
    });
    if state.current_id == Some(torrent_id) {
        state.completed_pieces = completed_pieces;
        state.completed_bytes = completed_bytes;
    }
}

fn apply_piece_completion_ui(
    state: &mut ui::UiState,
    torrent_id: u64,
    completed_pieces: usize,
    file_spans: &[FileSpan],
    piece_start: u64,
    piece_len: u64,
    increment_bytes: bool,
) {
    update_torrent_entry(state, torrent_id, |torrent| {
        torrent.completed_pieces = completed_pieces;
        if increment_bytes {
            torrent.completed_bytes = torrent.completed_bytes.saturating_add(piece_len);
            apply_piece_to_files(&mut torrent.files, file_spans, piece_start, piece_len);
        }
    });
    if state.current_id == Some(torrent_id) {
        state.completed_pieces = completed_pieces;
        if increment_bytes {
            state.completed_bytes = state.completed_bytes.saturating_add(piece_len);
            apply_piece_to_files(&mut state.files, file_spans, piece_start, piece_len);
        }
    }
}

#[cfg(test)]
mod ui_progress_tests {
    use super::*;

    fn torrent_entry(id: u64, completed_pieces: usize, completed_bytes: u64) -> ui::UiTorrent {
        ui::UiTorrent {
            id,
            completed_pieces,
            completed_bytes,
            ..ui::UiTorrent::default()
        }
    }

    #[test]
    fn piece_completion_updates_only_matching_torrent_bytes() {
        let mut state = ui::UiState {
            current_id: Some(2),
            completed_pieces: 2,
            completed_bytes: 200,
            torrents: vec![torrent_entry(1, 1, 100), torrent_entry(2, 2, 200)],
            ..ui::UiState::default()
        };

        apply_piece_completion_ui(&mut state, 2, 3, &[], 0, 16, true);

        let torrent1 = state
            .torrents
            .iter()
            .find(|torrent| torrent.id == 1)
            .unwrap();
        let torrent2 = state
            .torrents
            .iter()
            .find(|torrent| torrent.id == 2)
            .unwrap();
        assert_eq!(torrent1.completed_pieces, 1);
        assert_eq!(torrent1.completed_bytes, 100);
        assert_eq!(torrent2.completed_pieces, 3);
        assert_eq!(torrent2.completed_bytes, 216);
        assert_eq!(state.completed_pieces, 3);
        assert_eq!(state.completed_bytes, 216);
    }

    #[test]
    fn piece_completion_does_not_mutate_root_for_non_current_torrent() {
        let mut state = ui::UiState {
            current_id: Some(1),
            completed_pieces: 1,
            completed_bytes: 100,
            torrents: vec![torrent_entry(1, 1, 100), torrent_entry(2, 2, 200)],
            ..ui::UiState::default()
        };

        apply_piece_completion_ui(&mut state, 2, 3, &[], 0, 16, true);

        let torrent2 = state
            .torrents
            .iter()
            .find(|torrent| torrent.id == 2)
            .unwrap();
        assert_eq!(torrent2.completed_pieces, 3);
        assert_eq!(torrent2.completed_bytes, 216);
        assert_eq!(state.completed_pieces, 1);
        assert_eq!(state.completed_bytes, 100);
    }

    #[test]
    fn completion_sync_updates_current_torrent_and_root_fields() {
        let mut state = ui::UiState {
            current_id: Some(2),
            completed_pieces: 1,
            completed_bytes: 100,
            torrents: vec![torrent_entry(1, 1, 100), torrent_entry(2, 2, 200)],
            ..ui::UiState::default()
        };

        set_torrent_completion_ui(&mut state, 2, 4, 400);

        let torrent2 = state
            .torrents
            .iter()
            .find(|torrent| torrent.id == 2)
            .unwrap();
        assert_eq!(torrent2.completed_pieces, 4);
        assert_eq!(torrent2.completed_bytes, 400);
        assert_eq!(state.completed_pieces, 4);
        assert_eq!(state.completed_bytes, 400);
    }

    #[test]
    fn completion_sync_does_not_mutate_root_for_non_current_torrent() {
        let mut state = ui::UiState {
            current_id: Some(1),
            completed_pieces: 1,
            completed_bytes: 100,
            torrents: vec![torrent_entry(1, 1, 100), torrent_entry(2, 2, 200)],
            ..ui::UiState::default()
        };

        set_torrent_completion_ui(&mut state, 2, 4, 400);

        let torrent2 = state
            .torrents
            .iter()
            .find(|torrent| torrent.id == 2)
            .unwrap();
        assert_eq!(torrent2.completed_pieces, 4);
        assert_eq!(torrent2.completed_bytes, 400);
        assert_eq!(state.completed_pieces, 1);
        assert_eq!(state.completed_bytes, 100);
    }
}

#[cfg(test)]
mod parsing_tests {
    use super::*;

    #[test]
    fn query_pairs_decode_percent_and_plus() {
        let pairs = parse_query_pairs("dn=hello+world&tr=http%3A%2F%2Ftracker&x=1");
        assert_eq!(pairs[0], ("dn".to_string(), "hello world".to_string()));
        assert_eq!(pairs[1], ("tr".to_string(), "http://tracker".to_string()));
        assert_eq!(pairs[2], ("x".to_string(), "1".to_string()));
    }

    #[test]
    fn info_hash_parsing_supports_hex_and_base32() {
        let hex = "00112233445566778899aabbccddeeff00112233";
        let parsed_hex = parse_info_hash(hex).unwrap();
        assert_eq!(parsed_hex[0], 0x00);
        assert_eq!(parsed_hex[1], 0x11);
        assert_eq!(parsed_hex[19], 0x33);

        let parsed_base32 = parse_info_hash("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(parsed_base32, [0u8; 20]);
        assert!(parse_info_hash("invalid").is_none());
    }

    #[test]
    fn magnet_parser_extracts_trackers_sources_and_peers() {
        let link = "\
magnet:?xt=urn:btih:00112233445566778899AABBCCDDEEFF00112233\
&tr=http%3A%2F%2Ftracker.example%2Fannounce\
&ws=http%3A%2F%2Fseed.example%2Ffile\
&xs=http%3A%2F%2Fmirror.example%2Fmeta.torrent\
&x.pe=127.0.0.1:6881";
        let parsed = parse_magnet(link).unwrap();
        assert_eq!(
            parsed.info_hash,
            parse_info_hash("00112233445566778899aabbccddeeff00112233").unwrap()
        );
        assert_eq!(parsed.trackers, vec!["http://tracker.example/announce"]);
        assert_eq!(parsed.web_seeds, vec!["http://seed.example/file"]);
        assert_eq!(parsed.sources, vec!["http://mirror.example/meta.torrent"]);
        assert_eq!(parsed.peers, vec!["127.0.0.1:6881".parse().unwrap()]);
    }

    #[test]
    fn magnet_parser_requires_info_hash() {
        let err = match parse_magnet("magnet:?tr=http%3A%2F%2Ftracker") {
            Ok(_) => panic!("expected parse error"),
            Err(err) => err,
        };
        assert!(err.contains("missing info hash"));
    }

    #[test]
    fn extended_handshake_roundtrip() {
        let payload = build_ext_handshake(Some(4096), true);
        let (ut_metadata, ut_pex, metadata_size) = parse_extended_handshake(&payload).unwrap();
        assert_eq!(ut_metadata, Some(1));
        assert_eq!(ut_pex, Some(2));
        assert_eq!(metadata_size, Some(4096));
    }

    #[test]
    fn metadata_message_parsing_validates_required_fields() {
        let valid = b"d8:msg_typei1e5:piecei0e10:total_sizei5eehello";
        let msg = parse_metadata_message(valid).unwrap();
        assert_eq!(msg.msg_type, 1);
        assert_eq!(msg.piece, 0);
        assert_eq!(msg.total_size, Some(5));
        assert_eq!(msg.data, b"hello");

        assert!(parse_metadata_message(b"d5:piecei0ee").is_err());
        assert!(parse_metadata_message(b"d8:msg_typei1ee").is_err());
    }

    #[test]
    fn wrap_torrent_with_info_produces_parseable_torrent() {
        let info = b"d6:lengthi5e4:name4:test12:piece lengthi5e6:pieces20:aaaaaaaaaaaaaaaaaaaae";
        let wrapped = wrap_torrent_with_info(
            info,
            &["http://tracker.example/announce".to_string()],
            &["http://seed.example/file".to_string()],
        );
        let meta = torrent::parse_torrent(&wrapped).unwrap();
        assert_eq!(
            meta.announce,
            Some(b"http://tracker.example/announce".to_vec())
        );
        assert_eq!(meta.url_list, vec![b"http://seed.example/file".to_vec()]);
        assert_eq!(meta.info.total_length(), 5);
    }
}

#[cfg(test)]
mod core_helpers_tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rustorrent-main-test-{label}-{nanos}"))
    }

    fn tracker_meta(private: bool) -> torrent::TorrentMeta {
        torrent::TorrentMeta {
            announce: Some(b"http://tracker.local/announce".to_vec()),
            announce_list: vec![
                b"http://tracker.local/announce".to_vec(),
                b"udp://tracker.local:6969/announce".to_vec(),
            ],
            url_list: Vec::new(),
            httpseeds: Vec::new(),
            info_hash: [1u8; 20],
            info_hash_v2: None,
            piece_layers: Vec::new(),
            meta_version: 1,
            info: torrent::InfoDict {
                name: b"t".to_vec(),
                piece_length: 16,
                pieces: vec![[0u8; 20]],
                length: Some(16),
                files: Vec::new(),
                private,
                file_tree: Vec::new(),
            },
        }
    }

    #[test]
    fn parse_rate_and_encryption_mode_cover_common_variants() {
        assert_eq!(parse_rate("0").unwrap(), 0);
        assert_eq!(parse_rate("10k").unwrap(), 10 * 1024);
        assert_eq!(parse_rate("2M").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_rate("3g").unwrap(), 3 * 1024 * 1024 * 1024);
        assert_eq!(parse_rate(" unlimited ").unwrap(), 0);
        assert!(parse_rate("1x").is_err());
        assert!(parse_rate("").is_err());

        assert_eq!(
            parse_encryption_mode("disable").unwrap(),
            EncryptionMode::Disable
        );
        assert_eq!(
            parse_encryption_mode("prefer").unwrap(),
            EncryptionMode::Prefer
        );
        assert_eq!(
            parse_encryption_mode("force").unwrap(),
            EncryptionMode::Require
        );
        assert!(parse_encryption_mode("unknown").is_err());
    }

    #[test]
    fn parse_rss_rule_arg_handles_feed_urls_and_pattern_only() {
        let (feed, pattern) = parse_rss_rule_arg("http://feed.example/rss:*ubuntu*").unwrap();
        assert_eq!(feed, "http://feed.example/rss");
        assert_eq!(pattern, "*ubuntu*");

        let (feed, pattern) = parse_rss_rule_arg("http://feed.example:8080/rss:*ubuntu*").unwrap();
        assert_eq!(feed, "http://feed.example:8080/rss");
        assert_eq!(pattern, "*ubuntu*");

        let (feed, pattern) = parse_rss_rule_arg("*debian*").unwrap();
        assert_eq!(feed, "");
        assert_eq!(pattern, "*debian*");

        assert!(parse_rss_rule_arg("http://feed:").is_err());
    }

    #[test]
    fn parse_schedule_arg_rejects_zero_interval() {
        let (interval, command) = parse_schedule_arg("60:resume_all").unwrap();
        assert_eq!(interval, 60);
        assert_eq!(command, "resume_all");
        assert!(parse_schedule_arg("0:resume_all").is_err());
        assert!(parse_schedule_arg("abc:resume_all").is_err());
        assert!(parse_schedule_arg("60").is_err());
    }

    #[test]
    fn parse_bool_value_handles_truthy_and_falsy_inputs() {
        assert_eq!(parse_bool_value("true"), Some(true));
        assert_eq!(parse_bool_value("YES"), Some(true));
        assert_eq!(parse_bool_value("off"), Some(false));
        assert_eq!(parse_bool_value("0"), Some(false));
        assert_eq!(parse_bool_value("maybe"), None);
    }

    #[test]
    fn collect_trackers_deduplicates_and_respects_private_flag() {
        let private_meta = tracker_meta(true);
        let private_trackers = collect_trackers(&private_meta);
        assert_eq!(private_trackers.http, vec!["http://tracker.local/announce"]);
        assert_eq!(
            private_trackers.udp,
            vec!["udp://tracker.local:6969/announce"]
        );

        let public_meta = tracker_meta(false);
        let public_trackers = collect_trackers(&public_meta);
        assert!(public_trackers
            .http
            .contains(&"http://tracker.local/announce".to_string()));
        assert!(public_trackers
            .udp
            .contains(&"udp://tracker.local:6969/announce".to_string()));
        assert!(public_trackers
            .http
            .contains(&"http://tracker.opentrackr.org:1337/announce".to_string()));
    }

    #[test]
    fn pex_payload_roundtrip_includes_v4_and_v6() {
        let peers = vec![
            "127.0.0.1:6881".parse().unwrap(),
            "[2001:db8::1]:51413".parse().unwrap(),
        ];
        let payload = build_ut_pex_payload(&peers);
        let parsed = parse_ut_pex(&payload).unwrap();
        assert_eq!(parsed, peers);
    }

    #[test]
    fn bitfield_helpers_set_bits_and_validate_bounds() {
        let mut bits = [0u8; 1];
        set_bit(&mut bits, 0).unwrap();
        set_bit(&mut bits, 7).unwrap();
        assert_eq!(bits[0], 0b1000_0001);
        assert!(set_bit(&mut bits, 8).is_err());
    }

    #[test]
    fn delete_torrent_data_removes_only_safe_relative_paths() {
        let root = temp_path("delete-root");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sub")).unwrap();
        let inside = root.join("sub").join("file.bin");
        fs::write(&inside, b"x").unwrap();

        let parent = root.parent().unwrap().to_path_buf();
        let outside = parent.join("outside-keep.bin");
        fs::write(&outside, b"y").unwrap();

        delete_torrent_data(
            Some(&root),
            &[
                "sub/file.bin".to_string(),
                "../outside-keep.bin".to_string(),
                "/absolute/path.bin".to_string(),
            ],
        );

        assert!(!inside.exists());
        assert!(outside.exists());
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resume_data_roundtrip_preserves_fields() {
        let path = temp_path("resume").join("state.resume");
        let info_hash = [2u8; 20];
        let bitfield = vec![0b1010_0000];
        let priorities = vec![0, 2, 3];
        let files = vec![
            ResumeFileStat {
                length: 10,
                mtime: 100,
            },
            ResumeFileStat {
                length: 20,
                mtime: 200,
            },
        ];
        let peers = vec!["127.0.0.1:6881".parse().unwrap()];

        save_resume_data(
            &path,
            info_hash,
            16384,
            bitfield.clone(),
            &priorities,
            files,
            1234,
            5678,
            peers.clone(),
            &[(0, "renamed.txt".to_string())],
        )
        .unwrap();
        let loaded = load_resume_data(&path).unwrap();
        assert_eq!(loaded.info_hash, info_hash);
        assert_eq!(loaded.piece_length, 16384);
        assert_eq!(loaded.bitfield, bitfield);
        assert_eq!(loaded.file_priorities, priorities);
        assert_eq!(loaded.downloaded, 1234);
        assert_eq!(loaded.file_renames, vec![(0, "renamed.txt".to_string())]);
        assert_eq!(loaded.uploaded, 5678);
        assert_eq!(loaded.peers, peers);
        let _ = fs::remove_file(&path);
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn resume_load_recovers_from_backup_when_primary_is_corrupt() {
        let path = temp_path("resume-recover").join("state.resume");
        let info_hash = [4u8; 20];
        save_resume_data(
            &path,
            info_hash,
            16384,
            vec![0b1000_0000],
            &[1, 2],
            vec![ResumeFileStat {
                length: 8,
                mtime: 9,
            }],
            100,
            50,
            vec!["127.0.0.1:6881".parse().unwrap()],
            &[],
        )
        .unwrap();
        let backup_path = sidecar_path(&path, ".bak");
        fs::copy(&path, &backup_path).unwrap();
        fs::write(&path, b"corrupt").unwrap();

        let loaded = load_resume_data_with_recovery(&path).expect("expected backup recovery");
        assert_eq!(loaded.info_hash, info_hash);
        let restored = load_resume_data(&path).expect("restored primary should parse");
        assert_eq!(restored.info_hash, info_hash);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&backup_path);
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn session_save_writes_bencode_file() {
        let path = temp_path("session").join("session.benc");
        let mut entries = HashMap::new();
        entries.insert(
            [3u8; 20],
            SessionEntry {
                info_hash: [3u8; 20],
                name: "demo".to_string(),
                torrent_bytes: b"torrent-data".to_vec(),
                download_dir: PathBuf::from("/tmp/downloads"),
                preallocate: true,
                label: String::new(),
            },
        );
        save_session(&path, &entries).unwrap();

        let bytes = fs::read(&path).unwrap();
        let value = bencode::parse(&bytes).unwrap();
        match value {
            Value::List(items) => assert_eq!(items.len(), 1),
            _ => panic!("expected list"),
        }

        let _ = fs::remove_file(&path);
        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir_all(parent);
        }
    }

    #[test]
    fn session_load_recovers_from_backup_when_primary_is_corrupt() {
        let root = temp_path("session-recover");
        let path = session_path(&root);
        let mut entries = HashMap::new();
        let info_hash = [5u8; 20];
        entries.insert(
            info_hash,
            SessionEntry {
                info_hash,
                name: "demo".to_string(),
                torrent_bytes: b"torrent-data".to_vec(),
                download_dir: root.clone(),
                preallocate: false,
                label: String::new(),
            },
        );
        save_session(&path, &entries).unwrap();
        let backup_path = sidecar_path(&path, ".bak");
        fs::copy(&path, &backup_path).unwrap();
        fs::write(&path, b"corrupt").unwrap();

        let store = SessionStore::load(&root);
        assert!(store.contains(info_hash));
        let loaded_bytes = fs::read(&path).unwrap();
        assert!(bencode::parse(&loaded_bytes).is_ok());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn inbound_handler_slots_enforce_capacity() {
        assert_eq!(inbound_handler_slots(0), 0);
        assert_eq!(inbound_handler_slots(1), MIN_INBOUND_HANDLER_SLOTS);
        assert_eq!(inbound_handler_slots(600), MAX_INBOUND_HANDLER_SLOTS);

        let inbound = InboundConfig {
            encryption: EncryptionMode::Disable,
            ip_filter: None,
            max_handlers: 2,
            active_handlers: Arc::new(AtomicUsize::new(0)),
        };
        let guard_a = inbound.try_acquire_handler_slot().unwrap();
        let guard_b = inbound.try_acquire_handler_slot().unwrap();
        assert!(inbound.try_acquire_handler_slot().is_none());
        drop(guard_a);
        assert!(inbound.try_acquire_handler_slot().is_some());
        drop(guard_b);
    }

    #[test]
    fn path_helpers_place_state_under_rustorrent_dir() {
        let root = Path::new("/tmp/downloads");
        let info_hash = [0xABu8; 20];
        let resume = resume_path(root, info_hash);
        let session = session_path(root);
        assert!(resume.to_string_lossy().contains(".rustorrent"));
        assert!(resume.to_string_lossy().ends_with(".resume"));
        assert!(session
            .to_string_lossy()
            .ends_with(".rustorrent/session.benc"));
    }

    #[test]
    fn apply_overrides_updates_selected_fields() {
        let cfg = ConfigOverrides {
            download_dir: Some(PathBuf::from("/tmp/alt")),
            preallocate: Some(true),
            ui: Some(true),
            ui_addr: Some("127.0.0.1:9090".to_string()),
            retry_interval: Some(30),
            numwant: Some(80),
            port: Some(7000),
            enable_utp: Some(false),
            encryption: Some(EncryptionMode::Require),
            blocklist_path: Some(PathBuf::from("/tmp/blocklist.txt")),
            max_peers_global: Some(111),
            max_peers_torrent: Some(22),
            max_active_torrents: Some(3),
            download_rate: Some(10),
            upload_rate: Some(20),
            torrent_download_rate: Some(30),
            torrent_upload_rate: Some(40),
            write_cache_bytes: Some(50),
            geoip_db: None,
        };

        let mut download_dir = PathBuf::from(".");
        let mut preallocate = false;
        let mut ui = false;
        let mut ui_addr = "127.0.0.1:8080".to_string();
        let mut retry_interval = 60;
        let mut numwant = 200;
        let mut port = 6881;
        let mut enable_utp = true;
        let mut encryption = EncryptionMode::Prefer;
        let mut blocklist_path = None;
        let mut max_peers_global = 200;
        let mut max_peers_torrent = 30;
        let mut max_active_torrents = 4;
        let mut download_rate = 0;
        let mut upload_rate = 0;
        let mut torrent_download_rate = 0;
        let mut torrent_upload_rate = 0;
        let mut write_cache_bytes = 0;
        let mut geoip_path = None;
        apply_overrides(
            &cfg,
            &mut download_dir,
            &mut preallocate,
            &mut ui,
            &mut ui_addr,
            &mut retry_interval,
            &mut numwant,
            &mut port,
            &mut enable_utp,
            &mut encryption,
            &mut blocklist_path,
            &mut max_peers_global,
            &mut max_peers_torrent,
            &mut max_active_torrents,
            &mut download_rate,
            &mut upload_rate,
            &mut torrent_download_rate,
            &mut torrent_upload_rate,
            &mut write_cache_bytes,
            &mut geoip_path,
        );

        assert_eq!(download_dir, PathBuf::from("/tmp/alt"));
        assert!(preallocate);
        assert!(ui);
        assert_eq!(ui_addr, "127.0.0.1:9090");
        assert_eq!(retry_interval, 30);
        assert_eq!(numwant, 80);
        assert_eq!(port, 7000);
        assert!(!enable_utp);
        assert_eq!(encryption, EncryptionMode::Require);
        assert_eq!(blocklist_path, Some(PathBuf::from("/tmp/blocklist.txt")));
        assert_eq!(max_peers_global, 111);
        assert_eq!(max_peers_torrent, 22);
        assert_eq!(max_active_torrents, 3);
        assert_eq!(download_rate, 10);
        assert_eq!(upload_rate, 20);
        assert_eq!(torrent_download_rate, 30);
        assert_eq!(torrent_upload_rate, 40);
        assert_eq!(write_cache_bytes, 50);
    }

    #[test]
    fn load_config_overrides_parses_and_rejects_unknown_keys() {
        let path = temp_path("config-ok");
        fs::write(
            &path,
            "\
download_dir=/tmp/dl
preallocate=yes
ui=true
port=7001
encryption=require
download_rate=2M
write_cache=64k
",
        )
        .unwrap();
        let cfg = load_config_overrides(&path).unwrap();
        assert_eq!(cfg.download_dir, Some(PathBuf::from("/tmp/dl")));
        assert_eq!(cfg.preallocate, Some(true));
        assert_eq!(cfg.ui, Some(true));
        assert_eq!(cfg.port, Some(7001));
        assert_eq!(cfg.encryption, Some(EncryptionMode::Require));
        assert_eq!(cfg.download_rate, Some(2 * 1024 * 1024));
        assert_eq!(cfg.write_cache_bytes, Some(64 * 1024));
        let _ = fs::remove_file(&path);

        let bad_path = temp_path("config-bad");
        fs::write(&bad_path, "unknown_key=value\n").unwrap();
        let err = match load_config_overrides(&bad_path) {
            Ok(_) => panic!("expected unknown key error"),
            Err(err) => err,
        };
        assert!(err.contains("unknown key"));
        let _ = fs::remove_file(&bad_path);
    }

    #[cfg(feature = "webseed")]
    #[test]
    fn webseed_url_builder_encodes_paths_for_multi_file_mode() {
        assert_eq!(
            build_webseed_url("https://seed.example/base", "ignored", false),
            "https://seed.example/base"
        );
        assert_eq!(
            build_webseed_url("https://seed.example/base/", "dir/file name#.bin", true),
            "https://seed.example/base/dir/file%20name%23.bin"
        );
    }
}

#[cfg(test)]
mod local_harness_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    fn free_udp_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn compact_peer(addr: SocketAddr) -> Vec<u8> {
        match addr {
            SocketAddr::V4(v4) => {
                let mut out = Vec::with_capacity(6);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
                out
            }
            SocketAddr::V6(_) => Vec::new(),
        }
    }

    #[test]
    fn local_http_tracker_fixture_serves_announce() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        let body = bencode::encode(&Value::Dict(vec![
            (b"interval".to_vec(), Value::Int(60)),
            (b"peers".to_vec(), Value::Bytes(compact_peer(peer_addr))),
        ]));
        let body_for_server = body.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut req = [0u8; 2048];
            let n = stream.read(&mut req).unwrap();
            let request = String::from_utf8_lossy(&req[..n]);
            assert!(request.starts_with("GET /announce?"));
            assert!(request.contains("info_hash="));
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body_for_server.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(&body_for_server).unwrap();
        });

        let url = format!("http://127.0.0.1:{}/announce", addr.port());
        let response = tracker::announce(
            &url,
            [1u8; 20],
            [2u8; 20],
            6881,
            0,
            0,
            1,
            Some("started"),
            5,
        )
        .unwrap();
        assert_eq!(response.interval, 60);
        assert_eq!(response.peers, vec![peer_addr]);
        server.join().unwrap();
    }

    #[cfg(feature = "udp_tracker")]
    #[test]
    fn local_udp_tracker_fixture_serves_announce() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let peer_addr: SocketAddr = "127.0.0.1:6881".parse().unwrap();
        let server = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let (n, src) = socket.recv_from(&mut buf).unwrap();
            assert_eq!(n, 16);
            let tx = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
            let mut connect_resp = [0u8; 16];
            connect_resp[0..4].copy_from_slice(&0u32.to_be_bytes());
            connect_resp[4..8].copy_from_slice(&tx.to_be_bytes());
            connect_resp[8..16].copy_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
            socket.send_to(&connect_resp, src).unwrap();

            let (n2, src2) = socket.recv_from(&mut buf).unwrap();
            assert!(n2 >= 98);
            let tx2 = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
            let mut resp = Vec::new();
            resp.extend_from_slice(&1u32.to_be_bytes()); // announce action
            resp.extend_from_slice(&tx2.to_be_bytes());
            resp.extend_from_slice(&30u32.to_be_bytes()); // interval
            resp.extend_from_slice(&0u32.to_be_bytes()); // leechers
            resp.extend_from_slice(&1u32.to_be_bytes()); // seeders
            resp.extend_from_slice(&compact_peer(peer_addr));
            socket.send_to(&resp, src2).unwrap();
        });

        let url = format!("udp://127.0.0.1:{port}/announce");
        let response = udp_tracker::announce(
            &url,
            [3u8; 20],
            [4u8; 20],
            6881,
            0,
            0,
            1,
            Some("started"),
            10,
        )
        .unwrap();
        assert_eq!(response.interval, 30);
        assert_eq!(response.peers, vec![peer_addr]);
        server.join().unwrap();
    }

    #[test]
    fn local_peer_fixture_completes_plaintext_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let info_hash = [9u8; 20];
        let local_peer_id = [7u8; 20];
        let remote_peer_id = [8u8; 20];

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut peer_stream = PeerStream::tcp(stream);
            let request = peer::read_handshake(&mut peer_stream).unwrap();
            assert_eq!(request.info_hash, info_hash);
            assert!(request.supports_extensions());
            peer::write_handshake(&mut peer_stream, info_hash, remote_peer_id, true).unwrap();
        });

        let cfg = ConnectionConfig {
            encryption: EncryptionMode::Disable,
            utp: None,
            ip_filter: None,
            proxy: None,
        };
        let mut stream = connect_peer_for_metadata(addr, &cfg).unwrap();
        let handshake = plaintext_handshake(&mut stream, info_hash, local_peer_id).unwrap();
        assert_eq!(handshake.peer_id, remote_peer_id);
        assert_eq!(handshake.info_hash, info_hash);
        server.join().unwrap();
    }

    #[cfg(feature = "dht")]
    #[test]
    fn local_dht_fixture_node_returns_peers() {
        let dht_port = free_udp_port();
        let fixture = UdpSocket::bind("127.0.0.1:0").unwrap();
        fixture
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let fixture_addr = fixture.local_addr().unwrap();

        let cache_path = PathBuf::from(".rustorrent").join("dht_nodes.dat");
        let backup = fs::read(&cache_path).ok();
        let mut entry = Vec::new();
        entry.extend_from_slice(&[0x22u8; 20]);
        entry.extend_from_slice(&[127, 0, 0, 1]);
        entry.extend_from_slice(&fixture_addr.port().to_be_bytes());
        if let Some(parent) = cache_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        fs::write(&cache_path, entry).unwrap();

        let fixture_thread = thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, src) = fixture.recv_from(&mut buf).unwrap();
            let parsed = bencode::parse(&buf[..n]).unwrap();
            let Value::Dict(dict) = parsed else {
                panic!("expected dict");
            };
            let tx = match dict_get(&dict, b"t") {
                Some(Value::Bytes(tx)) => tx.clone(),
                _ => panic!("missing tx id"),
            };
            let peer = compact_peer("127.0.0.1:6881".parse().unwrap());
            let response = bencode::encode(&Value::Dict(vec![
                (b"t".to_vec(), Value::Bytes(tx)),
                (b"y".to_vec(), Value::Bytes(b"r".to_vec())),
                (
                    b"r".to_vec(),
                    Value::Dict(vec![
                        (b"id".to_vec(), Value::Bytes(vec![0x33u8; 20])),
                        (b"values".to_vec(), Value::List(vec![Value::Bytes(peer)])),
                    ]),
                ),
            ]));
            fixture.send_to(&response, src).unwrap();
        });

        let dht = dht::start(dht_port);
        thread::sleep(Duration::from_millis(300));
        let (tx, rx) = mpsc::channel();
        let info_hash = [1u8; 20];
        dht.add_torrent(info_hash, 6881, tx);
        let peers = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(peers.contains(&"127.0.0.1:6881".parse().unwrap()));
        dht.remove_torrent(info_hash);
        fixture_thread.join().unwrap();
        match backup {
            Some(data) => {
                let _ = fs::write(&cache_path, data);
            }
            None => {
                let _ = fs::remove_file(&cache_path);
            }
        }
    }
}

fn apply_file_priority(
    registry: &SessionRegistry,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    torrent_id: u64,
    file_index: usize,
    priority: u8,
) -> Result<(), String> {
    if priority > piece::PRIORITY_HIGH {
        return Err("invalid priority".to_string());
    }
    let context =
        find_context_by_id(registry, torrent_id).ok_or_else(|| "unknown torrent".to_string())?;
    let priorities_snapshot = {
        let mut priorities = context
            .file_priorities
            .lock()
            .map_err(|_| "priority lock failed".to_string())?;
        if file_index >= priorities.len() {
            return Err("file index out of range".to_string());
        }
        priorities[file_index] = priority;
        priorities.clone()
    };
    let piece_priorities = compute_piece_priorities(
        &context.file_spans,
        &priorities_snapshot,
        context.base_piece_length,
        context.pieces.lock().unwrap().piece_count(),
    );
    let (wanted_bytes, wanted_pieces, completed_bytes, completed_pieces) = {
        let mut pieces = context
            .pieces
            .lock()
            .map_err(|_| "piece lock failed".to_string())?;
        pieces
            .set_piece_priorities(&piece_priorities)
            .map_err(|err| err.to_string())?;
        (
            pieces.wanted_bytes(),
            pieces.wanted_pieces(),
            pieces.completed_bytes(),
            pieces.completed_pieces(),
        )
    };
    update_ui(ui_state, |state| {
        if state.current_id == Some(torrent_id) {
            state.total_bytes = wanted_bytes;
            state.total_pieces = wanted_pieces;
            state.completed_bytes = completed_bytes;
            state.completed_pieces = completed_pieces;
            if let Some(file) = state.files.get_mut(file_index) {
                file.priority = priority;
            }
        }
        update_torrent_entry(state, torrent_id, |torrent| {
            torrent.total_bytes = wanted_bytes;
            torrent.total_pieces = wanted_pieces;
            torrent.completed_bytes = completed_bytes;
            torrent.completed_pieces = completed_pieces;
            if let Some(file) = torrent.files.get_mut(file_index) {
                file.priority = priority;
            }
        });
    });
    Ok(())
}

fn apply_file_rename(
    registry: &SessionRegistry,
    torrent_id: u64,
    file_index: usize,
    new_name: &str,
) -> Result<(), String> {
    if new_name.is_empty()
        || new_name.contains('/')
        || new_name.contains('\\')
        || new_name.contains('\0')
        || new_name == "."
        || new_name == ".."
    {
        return Err("invalid file name".to_string());
    }
    let context =
        find_context_by_id(registry, torrent_id).ok_or_else(|| "unknown torrent".to_string())?;
    let spans = &context.file_spans;
    if file_index >= spans.len() {
        return Err("file index out of range".to_string());
    }
    let old_rel = &spans[file_index].path;
    let old_path = context.download_dir.join(old_rel);
    let new_rel = if let Some(pos) = old_rel.rfind('/') {
        format!("{}/{}", &old_rel[..pos], new_name)
    } else {
        new_name.to_string()
    };
    let new_path = context.download_dir.join(&new_rel);
    if old_path == new_path {
        return Ok(());
    }
    {
        let mut storage = context
            .storage
            .lock()
            .map_err(|_| "storage lock failed".to_string())?;
        storage
            .rename_file(file_index, &old_path, &new_path)
            .map_err(|err| format!("rename failed: {err}"))?;
    }
    {
        let mut renames = context
            .file_renames
            .lock()
            .map_err(|_| "renames lock failed".to_string())?;
        renames.insert(file_index, new_name.to_string());
    }
    Ok(())
}

fn set_torrent_paused(
    registry: &SessionRegistry,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    torrent_id: u64,
    paused: bool,
) -> Result<(), String> {
    let context =
        find_context_by_id(registry, torrent_id).ok_or_else(|| "unknown torrent".to_string())?;
    context.paused.store(paused, Ordering::SeqCst);
    update_ui(ui_state, |state| {
        update_torrent_entry(state, torrent_id, |torrent| {
            torrent.paused = paused;
            if paused {
                torrent.status = "paused".to_string();
            } else if torrent.status == "paused" {
                let complete =
                    torrent.total_bytes > 0 && torrent.completed_bytes >= torrent.total_bytes;
                torrent.status = if complete {
                    "seeding".to_string()
                } else {
                    "downloading".to_string()
                };
            }
        });
        if state.current_id == Some(torrent_id) {
            if let Some(torrent) = state
                .torrents
                .iter()
                .find(|torrent| torrent.id == torrent_id)
            {
                state.status = torrent.status.clone();
            }
            state.paused = is_paused();
        }
    });
    Ok(())
}

fn stop_torrent(
    registry: &SessionRegistry,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    queue: &mut VecDeque<TorrentRequest>,
    torrent_id: u64,
    session_store: &Arc<SessionStore>,
) -> Result<(), String> {
    if let Some(context) = find_context_by_id(registry, torrent_id) {
        context.stop_requested.store(true, Ordering::SeqCst);
        unregister_session(registry, context.info_hash);
        session_store.remove(context.info_hash);
        update_ui(ui_state, |state| {
            update_torrent_entry(state, torrent_id, |torrent| {
                torrent.status = "stopped".to_string();
                torrent.paused = false;
            });
            if state.current_id == Some(torrent_id) {
                state.status = "stopped".to_string();
                state.paused = is_paused();
            }
        });
        return Ok(());
    }

    let mut removed = false;
    let mut removed_info_hash: Option<[u8; 20]> = None;
    queue.retain(|request| {
        if request.id == torrent_id {
            removed_info_hash = info_hash_for_source(&request.source).ok();
            removed = true;
            false
        } else {
            true
        }
    });
    if removed {
        if let Some(info_hash) = removed_info_hash {
            session_store.remove(info_hash);
        }
        update_ui(ui_state, |state| {
            state.queue_len = queue.len();
            update_torrent_entry(state, torrent_id, |torrent| {
                torrent.status = "stopped".to_string();
                torrent.paused = false;
            });
            if state.current_id == Some(torrent_id) {
                state.status = "stopped".to_string();
                state.paused = is_paused();
            }
        });
        return Ok(());
    }

    Err("unknown torrent".to_string())
}

fn delete_torrent(
    registry: &SessionRegistry,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    queue: &mut VecDeque<TorrentRequest>,
    torrent_id: u64,
    remove_data: bool,
    session_store: &Arc<SessionStore>,
) -> Result<(), String> {
    let mut delete_dir: Option<PathBuf> = None;
    let mut delete_files: Vec<String> = Vec::new();
    if let Some(context) = find_context_by_id(registry, torrent_id) {
        context.stop_requested.store(true, Ordering::SeqCst);
        unregister_session(registry, context.info_hash);
        session_store.remove(context.info_hash);
        if remove_data {
            delete_dir = Some(context.download_dir.clone());
            delete_files = context
                .file_spans
                .iter()
                .map(|span| span.path.clone())
                .collect();
        }
        update_ui(ui_state, |state| {
            state.deleted_torrents.insert(torrent_id);
            state.torrents.retain(|torrent| torrent.id != torrent_id);
            state.queue_len = queue.len();
            if state.current_id == Some(torrent_id) {
                state.current_id = None;
                state.status = if queue.is_empty() {
                    "waiting for torrent".to_string()
                } else {
                    "queued".to_string()
                };
                state.paused = is_paused();
                state.files.clear();
                state.total_bytes = 0;
                state.completed_bytes = 0;
                state.total_pieces = 0;
                state.completed_pieces = 0;
            }
        });
        if remove_data {
            delete_torrent_data(delete_dir.as_ref(), &delete_files);
        }
        return Ok(());
    }

    let mut removed = false;
    let mut removed_info_hash: Option<[u8; 20]> = None;
    let mut queued_request: Option<TorrentRequest> = None;
    queue.retain(|request| {
        if request.id == torrent_id {
            removed_info_hash = info_hash_for_source(&request.source).ok();
            queued_request = Some(request.clone());
            removed = true;
            false
        } else {
            true
        }
    });
    if removed {
        if let Some(info_hash) = removed_info_hash {
            session_store.remove(info_hash);
        }
        if remove_data {
            if let Some(request) = queued_request {
                if let Ok((dir, files)) = delete_info_from_request(&request) {
                    delete_torrent_data(Some(&dir), &files);
                }
            }
        }
        update_ui(ui_state, |state| {
            state.queue_len = queue.len();
            state.deleted_torrents.insert(torrent_id);
            state.torrents.retain(|torrent| torrent.id != torrent_id);
            if state.current_id == Some(torrent_id) {
                state.current_id = None;
                state.status = if queue.is_empty() {
                    "waiting for torrent".to_string()
                } else {
                    "queued".to_string()
                };
                state.paused = is_paused();
                state.files.clear();
                state.total_bytes = 0;
                state.completed_bytes = 0;
                state.total_pieces = 0;
                state.completed_pieces = 0;
            }
        });
        return Ok(());
    }

    let ui_info = if remove_data {
        delete_info_from_ui(ui_state, torrent_id)
    } else {
        None
    };
    if let Some((dir, files)) = ui_info {
        delete_torrent_data(Some(&dir), &files);
    }
    if let Some(info_hash) = info_hash_from_ui(ui_state, torrent_id) {
        session_store.remove(info_hash);
    }
    update_ui(ui_state, |state| {
        state.deleted_torrents.insert(torrent_id);
        state.torrents.retain(|torrent| torrent.id != torrent_id);
        state.queue_len = queue.len();
        if state.current_id == Some(torrent_id) {
            state.current_id = None;
            state.status = if queue.is_empty() {
                "waiting for torrent".to_string()
            } else {
                "queued".to_string()
            };
            state.paused = is_paused();
            state.files.clear();
            state.total_bytes = 0;
            state.completed_bytes = 0;
            state.total_pieces = 0;
            state.completed_pieces = 0;
        }
    });
    Ok(())
}

fn delete_info_from_request(request: &TorrentRequest) -> Result<(PathBuf, Vec<String>), String> {
    let data = match &request.source {
        TorrentSource::Path(path) => fs::read(path).map_err(|err| format!("read failed: {err}"))?,
        TorrentSource::Bytes(data) => data.clone(),
        TorrentSource::Magnet(_) => return Err("magnet metadata unavailable".to_string()),
    };
    let meta = torrent::parse_torrent(&data).map_err(|err| format!("parse error: {err}"))?;
    let spans = build_file_spans(&meta);
    let files = spans.into_iter().map(|span| span.path).collect();
    Ok((request.download_dir.clone(), files))
}

fn delete_info_from_ui(
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    torrent_id: u64,
) -> Option<(PathBuf, Vec<String>)> {
    let state = ui_state.as_ref()?.lock().ok()?;
    let torrent = state
        .torrents
        .iter()
        .find(|torrent| torrent.id == torrent_id)?;
    let dir = PathBuf::from(&torrent.download_dir);
    let files = torrent.files.iter().map(|file| file.path.clone()).collect();
    Some((dir, files))
}

fn info_hash_from_ui(
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    torrent_id: u64,
) -> Option<[u8; 20]> {
    let state = ui_state.as_ref()?.lock().ok()?;
    let torrent = state
        .torrents
        .iter()
        .find(|torrent| torrent.id == torrent_id)?;
    parse_hex_20(&torrent.info_hash)
}

fn parse_hex_20(value: &str) -> Option<[u8; 20]> {
    let bytes = value.as_bytes();
    if bytes.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for idx in 0..20 {
        let hi = hex_nibble(bytes[idx * 2])?;
        let lo = hex_nibble(bytes[idx * 2 + 1])?;
        out[idx] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn delete_torrent_data(download_dir: Option<&PathBuf>, files: &[String]) {
    let Some(download_dir) = download_dir else {
        return;
    };
    for file in files {
        if file.trim().is_empty() {
            continue;
        }
        let rel_path = Path::new(file);
        if rel_path.is_absolute()
            || rel_path.components().any(|comp| match comp {
                std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_) => true,
                _ => false,
            })
        {
            log_warn!("delete skipped unsafe path: {file}");
            continue;
        }
        let full_path = download_dir.join(rel_path);
        if let Err(err) = fs::remove_file(&full_path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                log_warn!("delete file failed: {err}");
            }
        }
        cleanup_empty_dirs(&full_path, download_dir);
    }
}

fn cleanup_empty_dirs(path: &Path, root: &Path) {
    let mut current = path.parent();
    while let Some(dir) = current {
        if dir == root {
            break;
        }
        match fs::remove_dir(dir) {
            Ok(_) => {
                current = dir.parent();
            }
            Err(_) => break,
        }
    }
}

fn info_hash_for_source(source: &TorrentSource) -> Result<[u8; 20], String> {
    match source {
        TorrentSource::Bytes(data) => torrent::parse_torrent(data)
            .map(|meta| meta.info_hash)
            .map_err(|err| format!("parse error: {err}")),
        TorrentSource::Path(path) => {
            let data = fs::read(path).map_err(|err| format!("read failed: {err}"))?;
            torrent::parse_torrent(&data)
                .map(|meta| meta.info_hash)
                .map_err(|err| format!("parse error: {err}"))
        }
        TorrentSource::Magnet(link) => parse_magnet(link)
            .map(|meta| meta.info_hash)
            .map_err(|err| format!("magnet parse error: {err}")),
    }
}

struct ProgressStats {
    last_bytes: u64,
    last_at: Option<Instant>,
    speed_bps: f64,
    last_line_len: usize,
}

#[derive(Default)]
struct ProgressSnapshot {
    downloaded_bytes: u64,
    completed_bytes: u64,
    total_bytes: u64,
    active_peers: usize,
    tracker_peers: usize,
    status: String,
}

impl ProgressStats {
    fn new() -> Self {
        Self {
            last_bytes: 0,
            last_at: None,
            speed_bps: 0.0,
            last_line_len: 0,
        }
    }

    fn update_speed(&mut self, current: u64) {
        let now = Instant::now();
        let last_at = match self.last_at {
            Some(at) => at,
            None => {
                self.last_at = Some(now);
                self.last_bytes = current;
                return;
            }
        };

        let dt = now.duration_since(last_at).as_secs_f64();
        if dt <= 0.01 {
            return;
        }
        let delta = current.saturating_sub(self.last_bytes) as f64;
        let instant = delta / dt;
        if self.speed_bps <= 0.0 {
            self.speed_bps = instant;
        } else {
            self.speed_bps = (self.speed_bps * 0.7) + (instant * 0.3);
        }
        self.last_at = Some(now);
        self.last_bytes = current;
    }

    fn render_line(&mut self, state: &ProgressSnapshot) -> (String, f64, u64) {
        self.update_speed(state.downloaded_bytes);

        let total = state.total_bytes.max(1);
        let completed_bytes = state.completed_bytes.min(state.total_bytes);
        let pct = (completed_bytes as f64 / total as f64).clamp(0.0, 1.0);
        let bar_width = 30usize;
        let filled = ((pct * bar_width as f64).round() as usize).min(bar_width);
        let bar = format!("{}{}", "#".repeat(filled), "-".repeat(bar_width - filled));

        let completed = human_bytes(completed_bytes);
        let total = human_bytes(state.total_bytes);
        let speed = human_rate(self.speed_bps);
        let eta_secs = if self.speed_bps > 1.0 {
            let remaining = state.total_bytes.saturating_sub(completed_bytes);
            (remaining as f64 / self.speed_bps).round() as u64
        } else {
            0
        };
        let eta = if eta_secs > 0 {
            format_eta(eta_secs as f64)
        } else {
            "--:--".to_string()
        };

        let mut line = format!(
            "[{bar}] {:>6.2}% {completed}/{total} {speed} ETA {eta} peers {}/{}",
            pct * 100.0,
            state.active_peers,
            state.tracker_peers
        );
        if !state.status.is_empty() {
            line.push(' ');
            line.push_str(&state.status);
        }
        (line, self.speed_bps, eta_secs)
    }

    fn current_speed(&self) -> f64 {
        self.speed_bps
    }
}

fn start_console_progress(
    state: Arc<Mutex<ui::UiState>>,
    registry: SessionRegistry,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut download_stats = ProgressStats::new();
        let mut upload_stats = ProgressStats::new();
        PROGRESS_ACTIVE.store(true, Ordering::SeqCst);
        loop {
            if shutdown_requested() {
                break;
            }
            let (mut snapshot, current_id) = match state.lock() {
                Ok(guard) => (
                    ProgressSnapshot {
                        downloaded_bytes: 0,
                        completed_bytes: guard.completed_bytes,
                        total_bytes: guard.total_bytes,
                        active_peers: guard.active_peers,
                        tracker_peers: guard.tracker_peers,
                        status: guard.status.clone(),
                    },
                    guard.current_id,
                ),
                Err(_) => (ProgressSnapshot::default(), None),
            };
            let (downloaded_bytes, uploaded_bytes) = current_id
                .and_then(|id| find_context_by_id(&registry, id))
                .map(|ctx| {
                    (
                        ctx.downloaded.load(Ordering::SeqCst),
                        ctx.uploaded.load(Ordering::SeqCst),
                    )
                })
                .unwrap_or((0, 0));
            snapshot.downloaded_bytes = downloaded_bytes;

            let (mut line, speed_bps, eta_secs) = download_stats.render_line(&snapshot);
            upload_stats.update_speed(uploaded_bytes);
            let upload_speed = upload_stats.current_speed();
            if line.len() < download_stats.last_line_len {
                line.push_str(&" ".repeat(download_stats.last_line_len - line.len()));
            }
            download_stats.last_line_len = line.len();
            PROGRESS_LINE_LEN.store(download_stats.last_line_len, Ordering::SeqCst);
            let _guard = LOG_LOCK.lock().ok();
            eprint!("\r{line}");
            let _ = io::stderr().flush();

            let metrics = storage::metrics_snapshot();
            let read_ms = if metrics.read_ops > 0 {
                metrics.read_ns as f64 / metrics.read_ops as f64 / 1_000_000.0
            } else {
                0.0
            };
            let write_ms = if metrics.write_ops > 0 {
                metrics.write_ns as f64 / metrics.write_ops as f64 / 1_000_000.0
            } else {
                0.0
            };
            if let Ok(mut guard) = state.lock() {
                guard.download_rate_bps = speed_bps;
                guard.upload_rate_bps = upload_speed;
                guard.eta_secs = eta_secs;
                guard.paused = is_paused();
                guard.downloaded_bytes = downloaded_bytes;
                guard.uploaded_bytes = uploaded_bytes;
                guard.session_downloaded_bytes = SESSION_DOWNLOADED_BYTES.load(Ordering::SeqCst);
                guard.session_uploaded_bytes = SESSION_UPLOADED_BYTES.load(Ordering::SeqCst);
                guard.peer_connected = PEER_CONNECTED.load(Ordering::SeqCst);
                guard.peer_disconnected = PEER_DISCONNECTED.load(Ordering::SeqCst);
                guard.disk_read_ms_avg = read_ms;
                guard.disk_write_ms_avg = write_ms;
            }

            sleep_with_shutdown(Duration::from_secs(1));
        }
        PROGRESS_ACTIVE.store(false, Ordering::SeqCst);
        eprintln!();
    })
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

fn format_eta(secs: f64) -> String {
    if !secs.is_finite() || secs <= 0.0 {
        return "--:--".to_string();
    }
    let total = secs.round() as u64;
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    if hours > 0 {
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    } else {
        format!("{:02}:{:02}", minutes, seconds)
    }
}

fn move_completed_files(meta: &torrent::TorrentMeta, src_dir: &Path, dest_dir: &Path) {
    if let Err(err) = fs::create_dir_all(dest_dir) {
        log_warn!(
            "move-completed: failed to create {}: {err}",
            dest_dir.display()
        );
        return;
    }
    let name = String::from_utf8_lossy(&meta.info.name);
    let src_path = src_dir.join(name.as_ref());
    let dest_path = dest_dir.join(name.as_ref());
    if src_path == dest_path {
        return;
    }
    match fs::rename(&src_path, &dest_path) {
        Ok(()) => {
            log_info!(
                "moved completed: {} -> {}",
                src_path.display(),
                dest_path.display()
            );
        }
        Err(_) => {
            // Cross-device: try copy + delete
            if src_path.is_dir() {
                if let Err(err) = copy_dir_recursive(&src_path, &dest_path) {
                    log_warn!("move-completed copy failed: {err}");
                    return;
                }
                let _ = fs::remove_dir_all(&src_path);
            } else {
                match fs::copy(&src_path, &dest_path) {
                    Ok(_) => {
                        let _ = fs::remove_file(&src_path);
                    }
                    Err(err) => {
                        log_warn!("move-completed copy failed: {err}");
                        return;
                    }
                }
            }
            log_info!(
                "moved completed: {} -> {}",
                src_path.display(),
                dest_path.display()
            );
        }
    }
}

fn copy_dir_recursive(src: &Path, dest: &Path) -> Result<(), String> {
    fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    let entries = fs::read_dir(src).map_err(|e| e.to_string())?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let ft = entry.file_type().map_err(|e| e.to_string())?;
        let dest_path = dest.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            fs::copy(entry.path(), &dest_path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn create_torrent(
    source_path: &Path,
    tracker_url: &str,
    output_path: &Path,
    piece_length: u64,
) -> Result<(), String> {
    let name = source_path
        .file_name()
        .ok_or("invalid source path")?
        .to_string_lossy();

    let mut files_data: Vec<(Vec<Vec<u8>>, u64)> = Vec::new();
    let mut all_data = Vec::new();

    if source_path.is_dir() {
        collect_files(source_path, &[], &mut files_data)?;
        files_data.sort_by(|a, b| a.0.cmp(&b.0));
        for (path_segments, _) in &files_data {
            let mut full = source_path.to_path_buf();
            for seg in path_segments {
                full.push(String::from_utf8_lossy(seg).as_ref());
            }
            let data = fs::read(&full).map_err(|e| format!("read {}: {e}", full.display()))?;
            all_data.extend_from_slice(&data);
        }
    } else {
        let data =
            fs::read(source_path).map_err(|e| format!("read {}: {e}", source_path.display()))?;
        all_data = data;
    }

    let total_length = all_data.len() as u64;
    if total_length == 0 {
        return Err("empty source".to_string());
    }

    let mut pieces_bytes = Vec::new();
    let mut offset = 0usize;
    while offset < all_data.len() {
        let end = (offset + piece_length as usize).min(all_data.len());
        let hash = sha1::sha1(&all_data[offset..end]);
        pieces_bytes.extend_from_slice(&hash);
        offset = end;
    }

    let mut info_items = vec![
        (
            b"name".to_vec(),
            bencode::Value::Bytes(name.as_bytes().to_vec()),
        ),
        (
            b"piece length".to_vec(),
            bencode::Value::Int(piece_length as i64),
        ),
        (b"pieces".to_vec(), bencode::Value::Bytes(pieces_bytes)),
    ];

    if source_path.is_dir() {
        let file_list: Vec<bencode::Value> = files_data
            .iter()
            .map(|(path_segments, length)| {
                let path_values: Vec<bencode::Value> = path_segments
                    .iter()
                    .map(|s| bencode::Value::Bytes(s.clone()))
                    .collect();
                bencode::Value::Dict(vec![
                    (b"length".to_vec(), bencode::Value::Int(*length as i64)),
                    (b"path".to_vec(), bencode::Value::List(path_values)),
                ])
            })
            .collect();
        info_items.push((b"files".to_vec(), bencode::Value::List(file_list)));
    } else {
        info_items.push((b"length".to_vec(), bencode::Value::Int(total_length as i64)));
    }

    info_items.sort_by(|a, b| a.0.cmp(&b.0));
    let info = bencode::Value::Dict(info_items);
    let info_encoded = bencode::encode(&info);
    let info_hash = sha1::sha1(&info_encoded);

    let mut torrent_items = vec![
        (
            b"announce".to_vec(),
            bencode::Value::Bytes(tracker_url.as_bytes().to_vec()),
        ),
        (b"info".to_vec(), info),
    ];
    torrent_items.sort_by(|a, b| a.0.cmp(&b.0));
    let torrent = bencode::Value::Dict(torrent_items);
    let encoded = bencode::encode(&torrent);

    fs::write(output_path, &encoded)
        .map_err(|e| format!("write {}: {e}", output_path.display()))?;

    log_info!(
        "created torrent: {} ({} bytes, {} pieces, info_hash: {})",
        output_path.display(),
        total_length,
        (total_length + piece_length - 1) / piece_length,
        hex(&info_hash)
    );
    Ok(())
}

fn collect_files(
    dir: &Path,
    prefix: &[Vec<u8>],
    out: &mut Vec<(Vec<Vec<u8>>, u64)>,
) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let ft = entry.file_type().map_err(|e| e.to_string())?;
        let name_bytes = entry.file_name().to_string_lossy().as_bytes().to_vec();
        let mut path_segments = prefix.to_vec();
        path_segments.push(name_bytes);
        if ft.is_dir() {
            collect_files(&entry.path(), &path_segments, out)?;
        } else if ft.is_file() {
            let meta = entry.metadata().map_err(|e| e.to_string())?;
            out.push((path_segments, meta.len()));
        }
    }
    Ok(())
}

fn scan_watch_dir(
    watch_dir: &Path,
    queue: &mut VecDeque<TorrentRequest>,
    ui_state: &Option<Arc<Mutex<ui::UiState>>>,
    next_id: &mut u64,
    download_dir: &PathBuf,
    preallocate: bool,
) {
    let entries = match fs::read_dir(watch_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let processed_dir = watch_dir.join("processed");
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str());
        if ext != Some("torrent") {
            continue;
        }
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let request = TorrentRequest {
            id: *next_id,
            source: TorrentSource::Bytes(data),
            download_dir: download_dir.clone(),
            preallocate,
            initial_label: String::new(),
        };
        *next_id = next_id.saturating_add(1);
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "watch".to_string());
        enqueue_request_with_label(queue, ui_state, request, label);
        // Move to processed
        let _ = fs::create_dir_all(&processed_dir);
        if let Some(name) = path.file_name() {
            let _ = fs::rename(&path, processed_dir.join(name));
        }
    }
}

// ---- TUI (--tui) ----

struct TuiState {
    selected: usize,
    scroll_offset: usize,
    show_detail: bool,
    confirm_delete: Option<u64>,
}

fn tui_terminal_size() -> (u16, u16) {
    #[repr(C)]
    struct Winsize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    }
    extern "C" {
        fn ioctl(fd: i32, request: u64, ...) -> i32;
    }
    #[cfg(target_os = "macos")]
    const TIOCGWINSZ: u64 = 0x40087468;
    #[cfg(target_os = "linux")]
    const TIOCGWINSZ: u64 = 0x5413;
    let mut ws = Winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        ioctl(1, TIOCGWINSZ, &mut ws as *mut Winsize);
    }
    (ws.ws_row, ws.ws_col)
}

fn tui_set_raw_mode() -> Option<[u8; 128]> {
    #[cfg(target_os = "macos")]
    const TERMIOS_SIZE: usize = 72;
    #[cfg(target_os = "linux")]
    const TERMIOS_SIZE: usize = 60;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    const TERMIOS_SIZE: usize = 72;

    extern "C" {
        fn tcgetattr(fd: i32, termios: *mut u8) -> i32;
        fn tcsetattr(fd: i32, action: i32, termios: *const u8) -> i32;
    }
    let mut original = [0u8; 128];
    let mut raw = [0u8; 128];
    if unsafe { tcgetattr(0, original.as_mut_ptr()) } != 0 {
        return None;
    }
    raw[..TERMIOS_SIZE].copy_from_slice(&original[..TERMIOS_SIZE]);
    // Clear ICANON and ECHO (both in c_lflag)
    // c_lflag offset: macOS=16, Linux=12
    #[cfg(target_os = "macos")]
    const LFLAG_OFFSET: usize = 16;
    #[cfg(target_os = "linux")]
    const LFLAG_OFFSET: usize = 12;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    const LFLAG_OFFSET: usize = 16;

    let lflag = u64::from_ne_bytes([
        raw[LFLAG_OFFSET],
        raw[LFLAG_OFFSET + 1],
        raw.get(LFLAG_OFFSET + 2).copied().unwrap_or(0),
        raw.get(LFLAG_OFFSET + 3).copied().unwrap_or(0),
        0,
        0,
        0,
        0,
    ]) as u32;
    // ICANON=0x100, ECHO=0x8 on macOS; ICANON=2, ECHO=8 on Linux
    #[cfg(target_os = "macos")]
    let new_lflag = lflag & !(0x100 | 0x8);
    #[cfg(target_os = "linux")]
    let new_lflag = lflag & !(0x2 | 0x8);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let new_lflag = lflag & !(0x100 | 0x8);

    let bytes = new_lflag.to_ne_bytes();
    raw[LFLAG_OFFSET..LFLAG_OFFSET + 4].copy_from_slice(&bytes);
    // Set VMIN=1, VTIME=0 for non-blocking-ish reads
    // c_cc offset: macOS=20, Linux=17
    #[cfg(target_os = "macos")]
    {
        raw[20 + 16] = 0; // VMIN index=16 on macOS -> set to 0 for non-blocking
        raw[20 + 17] = 1; // VTIME index=17 -> 0.1s timeout
    }
    #[cfg(target_os = "linux")]
    {
        raw[17 + 6] = 0; // VMIN
        raw[17 + 5] = 1; // VTIME
    }

    if unsafe { tcsetattr(0, 0, raw.as_ptr()) } != 0 {
        return None;
    }
    Some(original)
}

fn tui_restore_mode(original: &[u8; 128]) {
    extern "C" {
        fn tcsetattr(fd: i32, action: i32, termios: *const u8) -> i32;
    }
    unsafe {
        tcsetattr(0, 0, original.as_ptr());
    }
}

fn tui_read_key() -> Option<u8> {
    extern "C" {
        fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    }
    let mut buf = [0u8; 1];
    let n = unsafe { read(0, buf.as_mut_ptr(), 1) };
    if n == 1 {
        Some(buf[0])
    } else {
        None
    }
}

fn tui_read_escape_seq() -> Vec<u8> {
    let mut seq = Vec::new();
    for _ in 0..4 {
        if let Some(b) = tui_read_key() {
            seq.push(b);
            if b.is_ascii_alphabetic() || b == b'~' {
                break;
            }
        } else {
            break;
        }
    }
    seq
}

fn tui_format_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value}{}", UNITS[unit])
    } else {
        format!("{:.1}{}", size, UNITS[unit])
    }
}

fn tui_format_rate(bps: f64) -> String {
    if bps <= 0.0 || !bps.is_finite() {
        return "0B/s".to_string();
    }
    let formatted = tui_format_bytes(bps as u64);
    format!("{formatted}/s")
}

fn tui_progress_bar(percent: f64, width: usize) -> String {
    let filled = ((percent / 100.0) * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    let mut bar = String::with_capacity(width * 3);
    for _ in 0..filled {
        bar.push('\u{2588}');
    }
    for _ in 0..empty {
        bar.push('\u{2591}');
    }
    bar
}

fn tui_status_color(status: &str) -> &'static str {
    match status {
        "seeding" | "complete" => "\x1b[32m", // green
        "downloading" => "\x1b[33m",          // yellow
        "error" => "\x1b[31m",                // red
        "paused" => "\x1b[90m",               // gray
        "announcing" | "loading" | "fetching metadata" => "\x1b[36m", // cyan
        _ => "\x1b[0m",
    }
}

fn tui_status_icon(status: &str, paused: bool) -> &'static str {
    if paused {
        "\u{23f8}"
    } else {
        match status {
            "seeding" | "complete" => "\u{25b2}",
            "downloading" | "announcing" => "\u{25b6}",
            "error" => "\u{2717}",
            _ => " ",
        }
    }
}

fn start_tui(
    state: Arc<Mutex<ui::UiState>>,
    cmd_tx: mpsc::Sender<ui::UiCommand>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let original = match tui_set_raw_mode() {
            Some(orig) => orig,
            None => {
                log_warn!("tui: failed to set raw mode");
                return;
            }
        };
        // Enter alternate screen, hide cursor
        let stdout = io::stdout();
        {
            let mut out = stdout.lock();
            let _ = out.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J");
            let _ = out.flush();
        }

        let mut tui = TuiState {
            selected: 0,
            scroll_offset: 0,
            show_detail: false,
            confirm_delete: None,
        };

        loop {
            if shutdown_requested() {
                break;
            }

            // Read keyboard input
            if let Some(key) = tui_read_key() {
                match key {
                    b'q' | 3 => {
                        // q or Ctrl-C
                        SHUTDOWN.store(true, Ordering::SeqCst);
                        break;
                    }
                    b'j' | b'B' => {
                        // down (j or arrow down sequence starts with ESC)
                        tui.selected = tui.selected.saturating_add(1);
                        tui.confirm_delete = None;
                    }
                    b'k' | b'A' => {
                        // up
                        tui.selected = tui.selected.saturating_sub(1);
                        tui.confirm_delete = None;
                    }
                    0x1b => {
                        // ESC - start of escape sequence
                        let seq = tui_read_escape_seq();
                        if seq == [b'[', b'A'] {
                            tui.selected = tui.selected.saturating_sub(1);
                        } else if seq == [b'[', b'B'] {
                            tui.selected = tui.selected.saturating_add(1);
                        }
                        tui.confirm_delete = None;
                    }
                    b'\r' | b'\n' => {
                        tui.show_detail = !tui.show_detail;
                    }
                    b'p' => {
                        // Pause/resume selected torrent
                        let guard = state.lock().unwrap();
                        if let Some(torrent) = guard.torrents.get(tui.selected) {
                            let id = torrent.id;
                            let paused = torrent.paused;
                            drop(guard);
                            let (reply_tx, _) = mpsc::channel();
                            if paused {
                                let _ = cmd_tx.send(ui::UiCommand::ResumeTorrent {
                                    torrent_id: id,
                                    reply: reply_tx,
                                });
                            } else {
                                let _ = cmd_tx.send(ui::UiCommand::PauseTorrent {
                                    torrent_id: id,
                                    reply: reply_tx,
                                });
                            }
                        }
                    }
                    b's' => {
                        // Stop selected torrent
                        let guard = state.lock().unwrap();
                        if let Some(torrent) = guard.torrents.get(tui.selected) {
                            let id = torrent.id;
                            drop(guard);
                            let (reply_tx, _) = mpsc::channel();
                            let _ = cmd_tx.send(ui::UiCommand::StopTorrent {
                                torrent_id: id,
                                reply: reply_tx,
                            });
                        }
                    }
                    b'd' => {
                        // Delete selected torrent (requires confirmation)
                        let guard = state.lock().unwrap();
                        if let Some(torrent) = guard.torrents.get(tui.selected) {
                            if tui.confirm_delete == Some(torrent.id) {
                                // Already confirming - ignore, wait for y/n
                            } else {
                                tui.confirm_delete = Some(torrent.id);
                            }
                        }
                    }
                    b'y' => {
                        if let Some(id) = tui.confirm_delete.take() {
                            let (reply_tx, _) = mpsc::channel();
                            let _ = cmd_tx.send(ui::UiCommand::DeleteTorrent {
                                torrent_id: id,
                                remove_data: false,
                                reply: reply_tx,
                            });
                        }
                    }
                    b'n' => {
                        tui.confirm_delete = None;
                    }
                    b'r' => {
                        // Recheck selected torrent
                        let guard = state.lock().unwrap();
                        if let Some(torrent) = guard.torrents.get(tui.selected) {
                            let id = torrent.id;
                            drop(guard);
                            let (reply_tx, _) = mpsc::channel();
                            let _ = cmd_tx.send(ui::UiCommand::RecheckTorrent {
                                torrent_id: id,
                                reply: reply_tx,
                            });
                        }
                    }
                    _ => {}
                }
            }

            // Render frame
            let (rows, cols) = tui_terminal_size();
            let cols = cols as usize;
            let rows = rows as usize;
            if rows < 5 || cols < 30 {
                thread::sleep(Duration::from_millis(100));
                continue;
            }

            let guard = state.lock().unwrap();
            let torrent_count = guard.torrents.len();
            if torrent_count > 0 && tui.selected >= torrent_count {
                tui.selected = torrent_count - 1;
            }

            // Calculate layout
            let header_rows = 1;
            let footer_rows = 1;
            let detail_rows = if tui.show_detail { 6.min(rows / 3) } else { 0 };
            let list_rows = rows.saturating_sub(header_rows + footer_rows + detail_rows);

            // Adjust scroll
            if tui.selected < tui.scroll_offset {
                tui.scroll_offset = tui.selected;
            }
            if tui.selected >= tui.scroll_offset + list_rows {
                tui.scroll_offset = tui.selected.saturating_sub(list_rows - 1);
            }

            let mut frame = String::with_capacity(cols * rows * 3);

            // Header: status bar
            frame.push_str("\x1b[H");
            let total_down_rate: f64 = guard.torrents.iter().map(|t| t.download_rate_bps).sum();
            let total_up_rate: f64 = guard.torrents.iter().map(|t| t.upload_rate_bps).sum();
            let active = guard
                .torrents
                .iter()
                .filter(|t| t.status == "downloading" || t.status == "seeding")
                .count();
            let header = format!(
                " \x1b[1mRustorrent 0.1.0\x1b[0m  \x1b[32m\u{2193}\x1b[0m {} \x1b[36m\u{2191}\x1b[0m {}  [{}/{}]",
                tui_format_rate(total_down_rate),
                tui_format_rate(total_up_rate),
                active,
                torrent_count,
            );
            frame.push_str(&header);
            let header_visible = strip_ansi_len(&header);
            if header_visible < cols {
                for _ in 0..(cols - header_visible) {
                    frame.push(' ');
                }
            }

            // Torrent list
            for row in 0..list_rows {
                let idx = tui.scroll_offset + row;
                frame.push_str(&format!("\x1b[{};1H", header_rows + row + 1));
                if idx < torrent_count {
                    let t = &guard.torrents[idx];
                    let selected = idx == tui.selected;
                    let pct = if t.total_bytes > 0 {
                        (t.completed_bytes as f64 / t.total_bytes as f64) * 100.0
                    } else {
                        0.0
                    };
                    let bar_width = 10.min(cols / 5);
                    let bar = tui_progress_bar(pct, bar_width);
                    let icon = tui_status_icon(&t.status, t.paused);
                    let color = tui_status_color(&t.status);
                    let reset = "\x1b[0m";

                    let right = if t.status == "seeding" || t.status == "complete" {
                        format!("seeding \u{2191}{}", tui_format_rate(t.upload_rate_bps))
                    } else if t.status == "downloading" {
                        format!(
                            "{:.0}% \u{2193}{}",
                            pct,
                            tui_format_rate(t.download_rate_bps)
                        )
                    } else {
                        t.status.clone()
                    };

                    let name_max = cols.saturating_sub(bar_width + right.len() + 8);
                    let name: String = if t.name.len() > name_max {
                        t.name
                            .chars()
                            .take(name_max.saturating_sub(1))
                            .collect::<String>()
                            + "\u{2026}"
                    } else {
                        t.name.clone()
                    };
                    let name_pad = name_max.saturating_sub(name.len());

                    let sel_start = if selected { "\x1b[7m" } else { "" };
                    let sel_end = if selected { "\x1b[0m" } else { "" };

                    let line = format!(
                        "{sel_start} {icon} {color}{name}{reset}{sel_start}{:name_pad$} [{bar}] {right} {sel_end}",
                        "",
                        name_pad = name_pad,
                    );
                    frame.push_str(&line);
                    let visible_len = strip_ansi_len(&line);
                    if visible_len < cols {
                        for _ in 0..(cols - visible_len) {
                            frame.push(' ');
                        }
                    }
                    if selected {
                        frame.push_str("\x1b[0m");
                    }
                } else {
                    // Empty row
                    for _ in 0..cols {
                        frame.push(' ');
                    }
                }
            }

            // Detail panel
            if tui.show_detail && tui.selected < torrent_count {
                let t = &guard.torrents[tui.selected];
                let detail_start = header_rows + list_rows + 1;
                let ratio_val = if t.downloaded_bytes > 0 {
                    t.uploaded_bytes as f64 / t.downloaded_bytes as f64
                } else {
                    0.0
                };
                let eta = if t.eta_secs > 0 {
                    let h = t.eta_secs / 3600;
                    let m = (t.eta_secs % 3600) / 60;
                    let s = t.eta_secs % 60;
                    if h > 0 {
                        format!("{h}h{m:02}m{s:02}s")
                    } else {
                        format!("{m}m{s:02}s")
                    }
                } else {
                    "--:--".to_string()
                };

                let details = [
                    format!(" Name: {}", t.name),
                    format!(
                        " Size: {}  Down: {}  Up: {}",
                        tui_format_bytes(t.total_bytes),
                        tui_format_bytes(t.downloaded_bytes),
                        tui_format_bytes(t.uploaded_bytes)
                    ),
                    format!(
                        " Ratio: {:.2}  ETA: {}  Peers: {}/{}",
                        ratio_val, eta, t.active_peers, t.tracker_peers
                    ),
                    format!(" Hash: {}", t.info_hash),
                    format!(" Dir: {}", t.download_dir),
                    format!(" Files: {}", t.files.len()),
                ];

                for (i, detail) in details.iter().enumerate() {
                    if i >= detail_rows {
                        break;
                    }
                    frame.push_str(&format!("\x1b[{};1H\x1b[90m", detail_start + i));
                    let truncated: String = detail.chars().take(cols).collect();
                    frame.push_str(&truncated);
                    let pad = cols.saturating_sub(truncated.len());
                    for _ in 0..pad {
                        frame.push(' ');
                    }
                    frame.push_str("\x1b[0m");
                }
            }

            // Footer: keybinds
            frame.push_str(&format!("\x1b[{};1H", rows));
            let confirm_msg = if let Some(id) = tui.confirm_delete {
                format!(" Delete torrent {id}? [y/n] ")
            } else {
                String::new()
            };
            if !confirm_msg.is_empty() {
                frame.push_str("\x1b[33;1m");
                frame.push_str(&confirm_msg);
                let pad = cols.saturating_sub(confirm_msg.len());
                for _ in 0..pad {
                    frame.push(' ');
                }
                frame.push_str("\x1b[0m");
            } else {
                let footer =
                    " [q]uit [p]ause [r]echeck [s]top [d]elete [Enter]detail [\u{2191}\u{2193}]nav";
                frame.push_str("\x1b[7m");
                let truncated: String = footer.chars().take(cols).collect();
                frame.push_str(&truncated);
                let flen = strip_ansi_len(&truncated);
                for _ in 0..cols.saturating_sub(flen) {
                    frame.push(' ');
                }
                frame.push_str("\x1b[0m");
            }

            drop(guard);

            // Write frame
            {
                let mut out = stdout.lock();
                let _ = out.write_all(frame.as_bytes());
                let _ = out.flush();
            }

            thread::sleep(Duration::from_millis(100));
        }

        // Restore terminal
        {
            let mut out = stdout.lock();
            let _ = out.write_all(b"\x1b[?25h\x1b[?1049l");
            let _ = out.flush();
        }
        tui_restore_mode(&original);
    })
}

fn strip_ansi_len(s: &str) -> usize {
    let mut len = 0usize;
    let mut in_escape = false;
    for ch in s.chars() {
        if in_escape {
            if ch.is_ascii_alphabetic() || ch == 'm' {
                in_escape = false;
            }
        } else if ch == '\x1b' {
            in_escape = true;
        } else {
            len += 1;
        }
    }
    len
}

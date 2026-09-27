use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{http, xml};

const SEARCH_TIMEOUT: Duration = Duration::from_secs(60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);
const CAPABILITIES_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_PLUGIN_BYTES: usize = 512 * 1024;
const MAX_TORRENT_BYTES: usize = crate::MAX_TORRENT_BYTES;
const MAX_CATALOG_BYTES: usize = 768 * 1024;
const MAX_SEARCH_QUERY_BYTES: usize = 1024;
const MAX_SELECTED_PLUGINS: usize = 16;
const MAX_RESULTS_PER_PLUGIN: usize = 1_000;
const MAX_PROCESS_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROCESS_STDERR_BYTES: usize = 512 * 1024;
const MAX_RUNTIME_FILE_BYTES: usize = 128 * 1024;
const PROCESS_READER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const CATALOG_CACHE_SECS: u64 = 6 * 60 * 60;
const CATALOG_URL: &str =
    "https://raw.githubusercontent.com/qbittorrent/search-plugins/master/wiki/Unofficial-search-plugins.mediawiki";
static NETWORK_ENABLED: AtomicBool = AtomicBool::new(true);
/// The plugins qBittorrent itself installs, maintained by the qBittorrent
/// project. Jackett is left out because it needs a separately run server.
pub const RECOMMENDED_PLUGINS: [&str; 7] = [
    "piratebay",
    "limetorrents",
    "eztv",
    "solidtorrents",
    "torlock",
    "torrentproject",
    "torrentscsv",
];
const OFFICIAL_PLUGIN_BASE: &str =
    "https://raw.githubusercontent.com/qbittorrent/search-plugins/master/nova3/engines/";

pub fn set_network_enabled(enabled: bool) {
    NETWORK_ENABLED.store(enabled, Ordering::Release);
}

fn require_network() -> Result<(), String> {
    if NETWORK_ENABLED.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err("search networking is disabled while proxy mode is active".to_string())
    }
}

#[derive(Clone, Default)]
pub struct SearchPlugin {
    pub module: String,
    pub display_name: String,
    pub site_url: String,
    pub version: String,
    pub categories: Vec<String>,
    pub healthy: bool,
    pub broken_reason: String,
}

#[derive(Clone, Default)]
pub struct SearchResult {
    pub result_id: u64,
    pub plugin: String,
    pub site_url: String,
    pub link: String,
    pub name: String,
    pub size_bytes: i64,
    pub seeds: i64,
    pub leech: i64,
    pub desc_link: String,
    pub pub_date: i64,
}

#[derive(Clone, Default)]
pub struct SearchCatalogEntry {
    pub module: String,
    pub name: String,
    pub author: String,
    pub version: String,
    pub updated: String,
    pub download_url: String,
    pub comment: String,
    pub private_site: bool,
}

#[derive(Clone, Default)]
struct SearchState {
    plugins: Vec<SearchPlugin>,
    results: Vec<SearchResult>,
    catalog: Vec<SearchCatalogEntry>,
    busy: bool,
    generation: u64,
    next_result_id: u64,
    python_available: bool,
    plugin_error: String,
    last_error: String,
    last_query: String,
    last_category: String,
    last_started_at: u64,
    last_finished_at: u64,
    catalog_error: String,
    catalog_fetched_at: u64,
    /// Set once the installed plugins have been scanned; until then the
    /// list is not known to be empty.
    plugins_scanned: bool,
}

#[derive(Clone)]
struct SearchRuntime {
    root: PathBuf,
    python: Option<String>,
}
#[cfg_attr(test, derive(Debug))]
struct ProcessOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

struct ProcessTree {
    child: Child,
    cleanup_attempted: bool,
    #[cfg(unix)]
    process_group: i32,
    #[cfg(windows)]
    job: WindowsJob,
}

impl ProcessTree {
    fn spawn(command: &mut Command) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }

        #[cfg(windows)]
        let job = WindowsJob::new().map_err(|err| format!("create process job: {err}"))?;

        let child = command
            .spawn()
            .map_err(|err| format!("spawn process: {err}"))?;

        #[cfg(windows)]
        if let Err(err) = job.assign(&child) {
            let mut child = child;
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("assign process job: {err}"));
        }

        #[cfg(unix)]
        // Unix process identifiers are `pid_t` (a signed integer), so a
        // successfully spawned child's public u32 ID is representable here.
        let process_group = child.id() as i32;

        Ok(Self {
            child,
            cleanup_attempted: false,
            #[cfg(unix)]
            process_group,
            #[cfg(windows)]
            job,
        })
    }

    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    fn terminate_and_reap(&mut self) -> Result<(), String> {
        if self.cleanup_attempted {
            return Ok(());
        }
        self.cleanup_attempted = true;

        let terminate_result = self.terminate_tree();
        let wait_result = self
            .child
            .wait()
            .map(|_| ())
            .map_err(|err| format!("reap process: {err}"));
        terminate_result.and(wait_result)
    }

    fn terminate_tree(&mut self) -> Result<(), String> {
        #[cfg(unix)]
        {
            // The leader may already have exited, but any descendants that
            // inherited its stdout/stderr pipes remain in this process group.
            // SAFETY: `process_group` is the positive PID returned for the
            // spawned child; negating it addresses that isolated group.
            let result = unsafe { libc::kill(-self.process_group, libc::SIGKILL) };
            let group_error = if result == 0 {
                None
            } else {
                let err = std::io::Error::last_os_error();
                (err.raw_os_error() != Some(libc::ESRCH)).then_some(err)
            };
            // Also target the leader directly in case it changed its process
            // group before cleanup. Descendant readers are still bounded.
            let _ = self.child.kill();
            if let Some(err) = group_error {
                return Err(format!("terminate process group: {err}"));
            }
        }

        #[cfg(windows)]
        {
            let job_result = self.job.terminate();
            let _ = self.child.kill();
            job_result.map_err(|err| format!("terminate process job: {err}"))?;
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = self.child.kill();
        }

        Ok(())
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}

struct ReaderTask {
    receiver: mpsc::Receiver<(Vec<u8>, bool)>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ReaderTask {
    fn spawn(mut reader: Box<dyn Read + Send>, limit: usize) -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        let handle = thread::spawn(move || {
            let _ = sender.send(read_limited(&mut *reader, limit));
        });
        Self {
            receiver,
            handle: Some(handle),
        }
    }

    fn collect(mut self, deadline: Instant) -> (Vec<u8>, bool) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = match self.receiver.recv_timeout(remaining) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Disconnected) => (Vec::new(), true),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Never let a descendant that escaped containment turn reader
                // cleanup into an unbounded join. Dropping the handle detaches
                // the already-isolated reader thread.
                self.handle.take();
                return (Vec::new(), true);
            }
        };
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        result
    }
}

fn collect_reader_tasks(
    stdout: Option<ReaderTask>,
    stderr: Option<ReaderTask>,
) -> ((Vec<u8>, bool), (Vec<u8>, bool)) {
    let deadline = Instant::now() + PROCESS_READER_CLEANUP_TIMEOUT;
    let stdout = stdout
        .map(|reader| reader.collect(deadline))
        .unwrap_or_default();
    let stderr = stderr
        .map(|reader| reader.collect(deadline))
        .unwrap_or_default();
    (stdout, stderr)
}

#[cfg(windows)]
struct WindowsJob {
    handle: *mut std::ffi::c_void,
}

#[cfg(windows)]
impl WindowsJob {
    fn new() -> std::io::Result<Self> {
        // SAFETY: null attributes and name request an unnamed job with default
        // security, as documented by CreateJobObjectW.
        let handle = unsafe { create_job_object(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let job = Self { handle };
        // SAFETY: this C-compatible information structure contains only
        // integer fields and Windows defines zero as the default for limits.
        let mut information = unsafe { std::mem::zeroed::<JobObjectExtendedLimitInformation>() };
        information.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the job handle is live and the pointer/length describe the
        // complete information structure for this call.
        let information_size =
            u32::try_from(std::mem::size_of::<JobObjectExtendedLimitInformation>())
                .map_err(|_| std::io::Error::other("Windows job information is too large"))?;
        let configured = unsafe {
            set_information_job_object(
                job.handle,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                (&information as *const JobObjectExtendedLimitInformation).cast(),
                information_size,
            )
        };
        if configured == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(job)
    }

    fn assign(&self, child: &Child) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle;

        // SAFETY: both handles remain live for the duration of this call.
        let assigned =
            unsafe { assign_process_to_job_object(self.handle, child.as_raw_handle().cast()) };
        if assigned == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn terminate(&self) -> std::io::Result<()> {
        // SAFETY: `self.handle` remains a live job handle until Drop.
        let terminated = unsafe { terminate_job_object(self.handle, 1) };
        if terminated == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsJob {
    fn drop(&mut self) {
        // SAFETY: this is the unique owned handle and is closed exactly once.
        let _ = unsafe { close_handle(self.handle) };
    }
}

#[cfg(windows)]
const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
#[cfg(windows)]
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

#[cfg(windows)]
#[repr(C)]
struct JobObjectBasicLimitInformation {
    _per_process_user_time_limit: i64,
    _per_job_user_time_limit: i64,
    limit_flags: u32,
    _minimum_working_set_size: usize,
    _maximum_working_set_size: usize,
    _active_process_limit: u32,
    _affinity: usize,
    _priority_class: u32,
    _scheduling_class: u32,
}

#[cfg(windows)]
#[repr(C)]
struct IoCounters {
    _read_operation_count: u64,
    _write_operation_count: u64,
    _other_operation_count: u64,
    _read_transfer_count: u64,
    _write_transfer_count: u64,
    _other_transfer_count: u64,
}

#[cfg(windows)]
#[repr(C)]
struct JobObjectExtendedLimitInformation {
    basic_limit_information: JobObjectBasicLimitInformation,
    _io_info: IoCounters,
    _process_memory_limit: usize,
    _job_memory_limit: usize,
    _peak_process_memory_used: usize,
    _peak_job_memory_used: usize,
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "CreateJobObjectW"]
    fn create_job_object(
        job_attributes: *const std::ffi::c_void,
        name: *const u16,
    ) -> *mut std::ffi::c_void;
    #[link_name = "SetInformationJobObject"]
    fn set_information_job_object(
        job: *mut std::ffi::c_void,
        information_class: i32,
        information: *const std::ffi::c_void,
        information_length: u32,
    ) -> i32;
    #[link_name = "AssignProcessToJobObject"]
    fn assign_process_to_job_object(
        job: *mut std::ffi::c_void,
        process: *mut std::ffi::c_void,
    ) -> i32;
    #[link_name = "TerminateJobObject"]
    fn terminate_job_object(job: *mut std::ffi::c_void, exit_code: u32) -> i32;
    #[link_name = "CloseHandle"]
    fn close_handle(object: *mut std::ffi::c_void) -> i32;
}

pub enum SearchDownload {
    Magnet(String),
    TorrentBytes(Vec<u8>),
}

static SEARCH_RUNTIME: OnceLock<SearchRuntime> = OnceLock::new();
static SEARCH_STATE: OnceLock<Mutex<SearchState>> = OnceLock::new();

const PYTHON_MISSING: &str =
    "Python 3.9 or newer was not found. Install a supported python3 to use qBittorrent-style search plugins.";

fn no_plugins_message() -> &'static str {
    "No search plugins are installed yet. Open Plugins or Community Catalog to add one."
}

pub fn prepare(download_dir: &Path) -> Result<(), String> {
    crate::ensure_private_state_directory(download_dir)?;
    // Python runs inside the runtime folder, so its paths must be absolute.
    let download_dir =
        std::path::absolute(download_dir).map_err(|err| format!("search runtime path: {err}"))?;
    let root = download_dir
        .join(".rustorrent")
        .join("search")
        .join("nova3");
    ensure_runtime(&root)?;
    let runtime = SearchRuntime {
        root,
        python: detect_python(),
    };
    let runtime = SEARCH_RUNTIME.get_or_init(|| runtime);
    let state = SEARCH_STATE.get_or_init(|| Mutex::new(SearchState::default()));
    let mut guard = lock_state(state);
    guard.python_available = runtime.python.is_some();
    if !guard.python_available {
        guard.plugin_error = PYTHON_MISSING.to_string();
    } else if guard.plugins.is_empty() && guard.plugins_scanned {
        guard.plugin_error = no_plugins_message().to_string();
    }
    Ok(())
}

#[allow(dead_code)]
pub fn init(download_dir: &Path) -> Result<(), String> {
    prepare(download_dir)?;
    refresh_plugins()
}

pub fn refresh_plugins() -> Result<(), String> {
    let runtime = runtime()?;
    let state = SEARCH_STATE.get_or_init(|| Mutex::new(SearchState::default()));
    let loaded = load_plugins(runtime);
    let mut guard = lock_state(state);
    guard.plugins_scanned = true;
    let (plugins, plugin_error) = match loaded {
        Ok(loaded) => loaded,
        Err(err) => {
            guard.plugin_error = err.clone();
            return Err(err);
        }
    };
    guard.plugins = plugins;
    guard.python_available = runtime.python.is_some();
    guard.plugin_error = plugin_error;
    if !guard.python_available && guard.plugin_error.is_empty() {
        guard.plugin_error = PYTHON_MISSING.to_string();
    } else if guard.python_available && guard.plugins.is_empty() && guard.plugin_error.is_empty() {
        guard.plugin_error = no_plugins_message().to_string();
    }
    Ok(())
}

pub fn status_json() -> String {
    let Some(lock) = SEARCH_STATE.get() else {
        return "{\"busy\":false,\"python_available\":false,\"plugin_error\":\"search not initialized\",\"last_error\":\"\",\"query\":\"\",\"category\":\"all\",\"last_started_at\":0,\"last_finished_at\":0,\"plugins\":[],\"results\":[]}".to_string();
    };
    let state = lock_state(lock);
    let mut out = Json(String::with_capacity(256 + state.results.len() * 256));
    out.open("", '{');
    out.raw("busy", &state.busy);
    out.raw("python_available", &state.python_available);
    out.raw(
        "loading",
        &(state.python_available && !state.plugins_scanned),
    );
    out.raw(
        "recommended_missing",
        &RECOMMENDED_PLUGINS
            .iter()
            .filter(|module| !state.plugins.iter().any(|plugin| plugin.module == **module))
            .count(),
    );
    out.str("plugin_error", &state.plugin_error);
    out.str("last_error", &state.last_error);
    out.str("query", &state.last_query);
    out.str("category", &state.last_category);
    out.raw("last_started_at", &state.last_started_at);
    out.raw("last_finished_at", &state.last_finished_at);
    out.open("plugins", '[');
    for plugin in &state.plugins {
        out.open("", '{');
        out.str("module", &plugin.module);
        out.str("display_name", &plugin.display_name);
        out.str("site_url", &plugin.site_url);
        out.str("version", &plugin.version);
        out.raw("healthy", &plugin.healthy);
        out.str("broken_reason", &plugin.broken_reason);
        out.open("categories", '[');
        for category in &plugin.categories {
            out.str("", category);
        }
        out.0.push_str("]}");
    }
    out.0.push(']');
    out.open("results", '[');
    for result in &state.results {
        out.open("", '{');
        out.raw("index", &result.result_id);
        out.str("plugin", &result.plugin);
        out.str("site_url", &result.site_url);
        out.str("link", &result.link);
        out.str("name", &result.name);
        out.raw("size", &result.size_bytes);
        out.raw("seeds", &result.seeds);
        out.raw("leech", &result.leech);
        out.str("desc_link", &result.desc_link);
        out.raw("pub_date", &result.pub_date);
        out.0.push('}');
    }
    out.0.push_str("]}");
    out.0
}

pub fn catalog_json(force_refresh: bool) -> String {
    let fetch_error = update_catalog(force_refresh).err();
    let Some(lock) = SEARCH_STATE.get() else {
        return "{\"entries\":[],\"error\":\"search not initialized\"}".to_string();
    };
    let mut state = lock_state(lock);
    if let Some(err) = fetch_error {
        state.catalog_error = err;
    }
    let mut out = Json(String::with_capacity(256 + state.catalog.len() * 512));
    out.open("", '{');
    out.str("error", &state.catalog_error);
    out.str("source_url", CATALOG_URL);
    out.raw("fetched_at", &state.catalog_fetched_at);
    out.open("entries", '[');
    append_catalog_entries_json(&mut out, &state.catalog, &state.plugins);
    out.0.push_str("]}");
    out.0
}

/// Adult-only sites are left out of the catalog; they can still be
/// installed from a URL or a file.
fn is_adult_site(entry: &SearchCatalogEntry) -> bool {
    const MARKERS: [&str; 6] = ["porn", "xxx", "sukebei", "hentai", "nsfw", "adult"];
    [&entry.name, &entry.module, &entry.download_url]
        .iter()
        .any(|text| {
            let text = text.to_ascii_lowercase();
            MARKERS.iter().any(|marker| text.contains(marker))
        })
}

fn append_catalog_entries_json(
    out: &mut Json,
    entries: &[SearchCatalogEntry],
    installed_plugins: &[SearchPlugin],
) {
    for entry in entries
        .iter()
        .filter(|entry| !entry.private_site && !is_adult_site(entry))
    {
        let installed = installed_plugins
            .iter()
            .find(|plugin| plugin.module == entry.module);
        out.open("", '{');
        out.str("module", &entry.module);
        out.str("name", &entry.name);
        out.str("author", &entry.author);
        out.str("version", &entry.version);
        out.str("updated", &entry.updated);
        out.str("download_url", &entry.download_url);
        out.str("comment", &entry.comment);
        out.raw("private_site", &entry.private_site);
        out.raw("installed", &installed.is_some());
        out.str(
            "installed_version",
            installed.map_or("", |plugin| plugin.version.as_str()),
        );
        out.str(
            "installed_name",
            installed.map_or("", |plugin| plugin.display_name.as_str()),
        );
        out.raw(
            "installed_healthy",
            &installed.is_some_and(|plugin| plugin.healthy),
        );
        out.0.push('}');
    }
}

/// Minimal JSON writer. `key` inserts the separating comma unless the
/// previous byte opened an object or array; an empty key writes an array
/// element.
struct Json(String);

impl Json {
    fn key(&mut self, key: &str) {
        if !matches!(self.0.as_bytes().last(), None | Some(b'{' | b'[')) {
            self.0.push(',');
        }
        if !key.is_empty() {
            push_json_string(&mut self.0, key);
            self.0.push(':');
        }
    }

    fn str(&mut self, key: &str, value: &str) {
        self.key(key);
        push_json_string(&mut self.0, value);
    }

    fn raw(&mut self, key: &str, value: &dyn std::fmt::Display) {
        use std::fmt::Write;
        self.key(key);
        let _ = write!(self.0, "{value}");
    }

    fn open(&mut self, key: &str, bracket: char) {
        self.key(key);
        self.0.push(bracket);
    }
}

pub fn install_plugin_from_url(url: &str) -> Result<String, String> {
    require_network()?;
    let trimmed = url.trim();
    if !trimmed.starts_with("https://") {
        return Err("plugin url must use https://".to_string());
    }
    let filename = filename_from_url(trimmed)?;
    let module = plugin_module_from_filename(&filename)
        .ok_or_else(|| "plugin filename must be a valid python module name".to_string())?;
    let bytes = http::get_public(trimmed, MAX_PLUGIN_BYTES)
        .map_err(|err| format!("plugin download: {err}"))?;
    install_plugin_bytes(&filename, &bytes)?;
    Ok(module)
}

/// Installs the recommended plugins that are missing and returns how many
/// were added. One failed download does not stop the others.
pub fn install_recommended_plugins() -> Result<usize, String> {
    require_network()?;
    let runtime = runtime()?;
    let installed = current_plugins();
    let mut added = 0;
    let mut errors = Vec::new();
    for module in RECOMMENDED_PLUGINS {
        if installed.iter().any(|plugin| plugin.module == module) {
            continue;
        }
        let url = format!("{OFFICIAL_PLUGIN_BASE}{module}.py");
        let written = http::get_public(&url, MAX_PLUGIN_BYTES)
            .map_err(|err| format!("download: {err}"))
            .and_then(|bytes| write_plugin_file(runtime, &format!("{module}.py"), &bytes));
        match written {
            Ok(_) => added += 1,
            Err(err) => errors.push(format!("{module}: {err}")),
        }
    }
    if added > 0 {
        refresh_plugins()?;
    }
    if added == 0 && !errors.is_empty() {
        return Err(errors.join("; "));
    }
    Ok(added)
}

pub fn install_plugin_from_bytes(filename: &str, bytes: &[u8]) -> Result<String, String> {
    install_plugin_bytes(filename, bytes)
}

pub fn remove_plugin(module: &str) -> Result<(), String> {
    let module = sanitize_module_name(module)?;
    let runtime = runtime()?;
    let path = runtime.root.join("engines").join(format!("{module}.py"));
    ensure_real_directory(
        path.parent()
            .ok_or_else(|| "plugin path has no parent".to_string())?,
    )?;
    if !path.exists() {
        return Err("unknown search plugin".to_string());
    }
    fs::remove_file(&path).map_err(|err| format!("remove plugin: {err}"))?;
    refresh_plugins()
}

pub fn start_search(query: &str, category: &str, engines: &[String]) -> Result<(), String> {
    require_network()?;
    let runtime = runtime()?.clone();
    if runtime.python.is_none() {
        set_last_error(PYTHON_MISSING);
        return Err(PYTHON_MISSING.to_string());
    }

    let query = query.trim();
    if query.is_empty() {
        return Err("search query is empty".to_string());
    }
    if query.len() > MAX_SEARCH_QUERY_BYTES {
        return Err(format!(
            "search query is too long (maximum {MAX_SEARCH_QUERY_BYTES} bytes)"
        ));
    }
    let category = normalize_category(category)?;
    let available_plugins = current_plugins();
    let selected = resolve_selected_engines(&available_plugins, engines)?;
    if selected.is_empty() {
        return Err("no working search plugins are installed".to_string());
    }

    let state = SEARCH_STATE.get_or_init(|| Mutex::new(SearchState::default()));
    {
        let mut guard = lock_state(state);
        // Allow restarting: clear previous results even if busy
        guard.generation += 1;
        guard.busy = true;
        guard.last_error.clear();
        guard.results.clear();
        guard.last_query = query.to_string();
        guard.last_category = category.clone();
        guard.last_started_at = now_secs();
        guard.last_finished_at = 0;
    }

    let query_owned = query.to_string();
    let generation = {
        let guard = lock_state(state);
        guard.generation
    };
    // Launch one thread per plugin for parallel, incremental results
    let coordinator = thread::Builder::new()
        .name("rustorrent-search".to_string())
        .stack_size(512 * 1024)
        .spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel::<(Vec<SearchResult>, String)>();
            for plugin in &selected {
                let runtime = runtime.clone();
                let query = query_owned.clone();
                let category = category.clone();
                let plugin = plugin.clone();
                let plugin_name = plugin.clone();
                let worker_tx = tx.clone();
                if let Err(err) = thread::Builder::new()
                    .name(format!("search-{plugin_name}"))
                    .stack_size(512 * 1024)
                    .spawn(move || {
                        let result = run_search_process(&runtime, &query, &category, &[plugin]);
                        match result {
                            Ok((results, warning)) => {
                                let _ = worker_tx.send((results, warning));
                            }
                            Err(err) => {
                                let _ = worker_tx.send((Vec::new(), err));
                            }
                        }
                    })
                {
                    let _ = tx.send((
                        Vec::new(),
                        format!("{plugin_name}: could not start search worker: {err}"),
                    ));
                }
            }
            drop(tx);
            let plugins_by_url = current_plugins();
            let mut warnings = Vec::new();
            for (mut results, warning) in rx {
                let warning = summarize_search_warning(&warning);
                if !warning.is_empty() {
                    warnings.push(warning);
                }
                // Merge results incrementally, but only if this search is still current
                let state = SEARCH_STATE.get_or_init(|| Mutex::new(SearchState::default()));
                let mut guard = lock_state(state);
                if guard.generation != generation {
                    // A newer search started; discard our results
                    continue;
                }
                // Re-map plugin names from site_url
                for result in &mut results {
                    if result.plugin.is_empty() {
                        if let Some(name) =
                            plugin_name_by_site_url(&result.site_url, &plugins_by_url)
                        {
                            result.plugin = name;
                        }
                    }
                    result.result_id = guard.next_result_id;
                    guard.next_result_id = guard.next_result_id.saturating_add(1);
                }
                guard.results.extend(results);
                sort_results(&mut guard.results);
            }
            // Always finalize the current generation, including when a worker could not be spawned.
            let state = SEARCH_STATE.get_or_init(|| Mutex::new(SearchState::default()));
            let mut guard = lock_state(state);
            if guard.generation == generation {
                guard.busy = false;
                guard.last_finished_at = now_secs();
                guard.last_error = warnings.join("; ");
            }
        });

    if let Err(err) = coordinator {
        let mut guard = lock_state(state);
        if guard.generation == generation {
            guard.busy = false;
            guard.last_finished_at = now_secs();
            guard.last_error = format!("could not start search: {err}");
        }
        return Err(format!("could not start search: {err}"));
    }

    Ok(())
}

pub fn resolve_result(result_id: u64) -> Result<SearchDownload, String> {
    let runtime = runtime()?;
    let result = {
        let lock = SEARCH_STATE
            .get()
            .ok_or_else(|| "search not initialized".to_string())?;
        let state = lock_state(lock);
        state
            .results
            .iter()
            .find(|result| result.result_id == result_id)
            .cloned()
            .ok_or_else(|| "unknown search result".to_string())?
    };

    if result.link.starts_with("magnet:?") {
        return Ok(SearchDownload::Magnet(result.link));
    }
    require_network()?;
    if !result.link.starts_with("http://") && !result.link.starts_with("https://") {
        return Err("unsupported search result link".to_string());
    }

    if !result.plugin.is_empty() && runtime.python.is_some() {
        if let Ok(bytes) = download_through_plugin(runtime, &result.plugin, &result.link) {
            return validate_torrent_download(bytes).map(SearchDownload::TorrentBytes);
        }
    }

    let bytes = http::get_public(&result.link, MAX_TORRENT_BYTES)
        .map_err(|err| format!("torrent download: {err}"))?;
    validate_torrent_download(bytes).map(SearchDownload::TorrentBytes)
}

fn validate_torrent_download(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    crate::torrent::parse_torrent(&bytes)
        .map_err(|err| format!("downloaded torrent is invalid: {err}"))?;
    Ok(bytes)
}

fn update_catalog(force_refresh: bool) -> Result<(), String> {
    require_network()?;
    let state = SEARCH_STATE.get_or_init(|| Mutex::new(SearchState::default()));
    let should_refresh = {
        let guard = lock_state(state);
        force_refresh
            || guard.catalog.is_empty()
            || now_secs().saturating_sub(guard.catalog_fetched_at) >= CATALOG_CACHE_SECS
    };
    if !should_refresh {
        return Ok(());
    }

    let bytes = http::get_public(CATALOG_URL, MAX_CATALOG_BYTES)
        .map_err(|err| format!("catalog download: {err}"))?;
    let text = String::from_utf8(bytes).map_err(|_| "catalog is not valid utf-8".to_string())?;
    let entries = parse_unofficial_catalog(&text);
    let mut guard = lock_state(state);
    guard.catalog = entries;
    guard.catalog_error.clear();
    guard.catalog_fetched_at = now_secs();
    Ok(())
}

/// Each runtime module is stored gzip-compressed next to a one-line loader
/// with the original name; Python decompresses and runs it in place.
fn ensure_runtime(root: &Path) -> Result<(), String> {
    macro_rules! module {
        ($name:literal) => {
            (
                $name,
                include_bytes!(concat!(env!("OUT_DIR"), "/", $name, ".gz")).as_slice(),
            )
        };
    }
    const MODULES: [(&str, &[u8]); 5] = [
        module!("helpers.py"),
        module!("nova2.py"),
        module!("nova2dl.py"),
        module!("novaprinter.py"),
        module!("socks.py"),
    ];
    ensure_real_directory(root)?;
    ensure_real_directory(&root.join("engines"))?;
    write_if_changed(&root.join("__init__.py"), b"")?;
    write_if_changed(&root.join("engines/__init__.py"), b"")?;
    for (name, compressed) in MODULES {
        write_if_changed(&root.join(format!("{name}.gz")), compressed)?;
        let loader = format!(
            "import gzip,os;exec(compile(gzip.decompress(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),'{name}.gz'),'rb').read()),__file__,'exec'))\n"
        );
        write_if_changed(&root.join(name), loader.as_bytes())?;
    }
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(format!(
                    "search runtime path is not a real directory: {}",
                    path.display()
                ));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(format!(
                        "search runtime path is a reparse point: {}",
                        path.display()
                    ));
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|err| format!("secure search runtime directory: {err}"))?;
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| "search runtime directory has no parent".to_string())?;
            ensure_real_directory(parent)?;
            #[allow(unused_mut)]
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(path) {
                Ok(()) => ensure_real_directory(path),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    ensure_real_directory(path)
                }
                Err(err) => Err(format!("create search runtime directory: {err}")),
            }
        }
        Err(err) => Err(format!("inspect search runtime directory: {err}")),
    }
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "search runtime: refusing to read symlink {}",
                path.display()
            ));
        }
    }
    if let Ok(existing) =
        read_regular_file_limited(path, MAX_RUNTIME_FILE_BYTES, "read search runtime file")
    {
        if existing == bytes {
            return Ok(());
        }
    }
    write_file_atomic(path, bytes, "search runtime")
}

fn read_regular_file_limited(path: &Path, limit: usize, label: &str) -> Result<Vec<u8>, String> {
    let path_metadata = fs::symlink_metadata(path).map_err(|err| format!("{label}: {err}"))?;
    validate_regular_file_metadata(&path_metadata, label)?;
    if path_metadata.len() > limit as u64 {
        return Err(format!("{label}: file is too large"));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|err| format!("{label}: {err}"))?;
    let opened_metadata = file
        .metadata()
        .map_err(|err| format!("{label}: inspect open file: {err}"))?;
    validate_regular_file_metadata(&opened_metadata, label)?;
    if opened_metadata.len() > limit as u64 {
        return Err(format!("{label}: file is too large"));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened_metadata.nlink() != 1 {
            return Err(format!("{label}: file must not be hard-linked"));
        }
        if path_metadata.dev() != opened_metadata.dev()
            || path_metadata.ino() != opened_metadata.ino()
        {
            return Err(format!("{label}: file changed while opening"));
        }
    }

    let mut bytes = Vec::with_capacity((opened_metadata.len() as usize).min(limit));
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|err| format!("{label}: {err}"))?;
    if bytes.len() > limit {
        return Err(format!("{label}: file is too large"));
    }
    Ok(bytes)
}

fn validate_regular_file_metadata(metadata: &fs::Metadata, label: &str) -> Result<(), String> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label}: path is not a regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{label}: path is a reparse point"));
        }
    }
    Ok(())
}

fn write_file_atomic(path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{label}: destination has no parent"))?;
    ensure_real_directory(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "{label}: refusing to replace symlink {}",
                path.display()
            ));
        }
    }
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{label}: invalid destination filename"))?;
    let temp = path.with_file_name(format!(".{file_name}.tmp-{}-{suffix}", std::process::id()));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .map_err(|err| format!("{label}: create temp file: {err}"))?;
        std::io::Write::write_all(&mut file, bytes)
            .map_err(|err| format!("{label}: write temp file: {err}"))?;
        file.sync_all()
            .map_err(|err| format!("{label}: sync temp file: {err}"))?;
        fs::rename(&temp, path).map_err(|err| format!("{label}: rename: {err}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn detect_python() -> Option<String> {
    if let Ok(value) = std::env::var("RUSTORRENT_SEARCH_PYTHON") {
        if !value.trim().is_empty() && command_available(value.trim()) {
            return Some(value.trim().to_string());
        }
    }
    [
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python",
        "/usr/local/bin/python",
        "python3",
        "python",
    ]
    .iter()
    .find(|candidate| command_available(candidate))
    .map(|candidate| candidate.to_string())
}

fn command_available(command: &str) -> bool {
    const PROBE_MARKER: &[u8] = b"rustorrent-python-3.9+";
    let mut command = Command::new(command);
    command
        .arg("-I")
        .arg("-c")
        .arg("import sys; print('rustorrent-python-3.9+') if sys.version_info >= (3, 9) else sys.exit(1)")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let Ok(output) = run_command_with_timeout(
        &mut command,
        "Python compatibility probe",
        Duration::from_secs(2),
    ) else {
        return false;
    };
    output.success && !output.stdout_truncated && output.stdout.trim_ascii() == PROBE_MARKER
}

fn plugin_known_issue(module: &str) -> Option<&'static str> {
    match module {
        "magnetdl" => Some("Category searches return 404 on the current public site."),
        _ => None,
    }
}

fn summarize_search_warning(message: &str) -> String {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("traceback") {
        if lower.contains("404") {
            return "One or more plugins failed with an HTTP 404. Try another plugin or search without a category filter.".to_string();
        }
        return "One or more plugins failed during search. Open Plugins to review providers or disable unstable ones.".to_string();
    }
    trimmed.to_string()
}

fn runtime() -> Result<&'static SearchRuntime, String> {
    SEARCH_RUNTIME
        .get()
        .ok_or_else(|| "search not initialized".to_string())
}

fn load_plugins(runtime: &SearchRuntime) -> Result<(Vec<SearchPlugin>, String), String> {
    let mut plugins = installed_plugins(&runtime.root)?;
    if runtime.python.is_none() {
        return Ok((plugins, PYTHON_MISSING.to_string()));
    }

    let output = run_python_script(
        runtime,
        "nova2.py",
        &["--capabilities".to_string()],
        CAPABILITIES_TIMEOUT,
        None,
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if output.stdout_truncated {
        return Ok((
            plugins,
            "search runtime capabilities output was too large".to_string(),
        ));
    }
    if output.stdout.is_empty() {
        return Ok((plugins, stderr));
    }

    let mut plugin_error = stderr;
    if let Some(root) = xml::parse(&output.stdout) {
        if root.tag == "capabilities" {
            for child in root.children {
                if let Some(plugin) = plugins.iter_mut().find(|plugin| plugin.module == child.tag) {
                    plugin.display_name = child
                        .child("name")
                        .map(|node| node.text.trim().to_string())
                        .filter(|text| !text.is_empty())
                        .unwrap_or_else(|| plugin.module.clone());
                    plugin.site_url = child
                        .child("url")
                        .map(|node| node.text.trim().to_string())
                        .unwrap_or_default();
                    plugin.categories = child
                        .child("categories")
                        .map(|node| {
                            node.text
                                .split_whitespace()
                                .map(|value| value.trim().to_string())
                                .filter(|value| !value.is_empty())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    if let Some(reason) = plugin_known_issue(&plugin.module) {
                        plugin.healthy = false;
                        plugin.broken_reason = reason.to_string();
                    } else {
                        plugin.healthy = true;
                        plugin.broken_reason.clear();
                    }
                }
            }
        } else if plugin_error.is_empty() {
            plugin_error = "search runtime returned invalid capabilities xml".to_string();
        }
    } else if plugin_error.is_empty() {
        plugin_error = "search runtime returned invalid capabilities xml".to_string();
    }

    Ok((plugins, plugin_error))
}

fn installed_plugins(root: &Path) -> Result<Vec<SearchPlugin>, String> {
    let engine_dir = root.join("engines");
    let entries = fs::read_dir(&engine_dir).map_err(|err| format!("read search plugins: {err}"))?;
    let mut plugins = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| format!("read search plugins: {err}"))?;
        let file_type = entry
            .file_type()
            .map_err(|err| format!("read search plugin type: {err}"))?;
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        if !file_type.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(module) = plugin_module_from_filename(file_name) else {
            continue;
        };
        if module == "__init__" {
            continue;
        }
        plugins.push(SearchPlugin {
            module: module.clone(),
            display_name: module,
            site_url: String::new(),
            version: plugin_version(&path).unwrap_or_default(),
            categories: Vec::new(),
            healthy: false,
            broken_reason: String::new(),
        });
    }
    crate::util::sort_by(&mut plugins, |left, right| left.module < right.module);
    Ok(plugins)
}

fn plugin_version(path: &Path) -> Option<String> {
    let bytes = read_regular_file_limited(path, MAX_PLUGIN_BYTES, "read search plugin").ok()?;
    let text = String::from_utf8(bytes).ok()?;
    for line in text.lines().take(8) {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("# VERSION:") {
            return Some(rest.trim().to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("#VERSION:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn filename_from_url(url: &str) -> Result<String, String> {
    let without_fragment = url.split('#').next().unwrap_or(url);
    let without_query = without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment);
    let file_name = without_query
        .rsplit('/')
        .next()
        .ok_or_else(|| "plugin url is missing a filename".to_string())?
        .trim();
    if file_name.is_empty() {
        return Err("plugin url is missing a filename".to_string());
    }
    Ok(file_name.to_string())
}

fn plugin_module_from_filename(filename: &str) -> Option<String> {
    let name = filename.trim();
    let stem = name.strip_suffix(".py")?;
    if stem.is_empty() {
        return None;
    }
    let mut chars = stem.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if chars.any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_')) {
        return None;
    }
    Some(stem.to_string())
}

fn sanitize_module_name(module: &str) -> Result<String, String> {
    let module = plugin_module_from_filename(&format!("{}.py", module.trim()))
        .ok_or_else(|| "invalid search plugin name".to_string())?;
    if module == "__init__" {
        return Err("search plugin name is reserved".to_string());
    }
    Ok(module)
}

fn install_plugin_bytes(filename: &str, bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty() {
        return Err("plugin file is empty".to_string());
    }
    if bytes.len() > MAX_PLUGIN_BYTES {
        return Err("plugin file is too large".to_string());
    }
    let module = plugin_module_from_filename(filename)
        .ok_or_else(|| "plugin filename must be a valid python module name".to_string())?;
    if module == "__init__" {
        return Err("plugin filename is reserved".to_string());
    }
    let source =
        std::str::from_utf8(bytes).map_err(|_| "plugin source must be valid UTF-8".to_string())?;
    if source.contains('\0') {
        return Err("plugin source contains a NUL byte".to_string());
    }
    write_plugin_file(runtime()?, filename, bytes)?;
    refresh_plugins()?;
    Ok(module)
}

fn write_plugin_file(runtime: &SearchRuntime, filename: &str, bytes: &[u8]) -> Result<(), String> {
    let module = plugin_module_from_filename(filename)
        .ok_or_else(|| "plugin filename must be a valid python module name".to_string())?;
    let path = runtime.root.join("engines").join(format!("{module}.py"));
    write_file_atomic(&path, bytes, "write plugin")
}

fn current_plugins() -> Vec<SearchPlugin> {
    SEARCH_STATE
        .get()
        .map(lock_state)
        .map(|state| state.plugins.clone())
        .unwrap_or_default()
}

fn resolve_selected_engines(
    plugins: &[SearchPlugin],
    requested: &[String],
) -> Result<Vec<String>, String> {
    let mut selected = Vec::new();
    if requested.is_empty() {
        selected.extend(
            plugins
                .iter()
                .filter(|plugin| plugin.healthy)
                .take(MAX_SELECTED_PLUGINS)
                .map(|plugin| plugin.module.clone()),
        );
        return Ok(selected);
    }

    if requested.len() > MAX_SELECTED_PLUGINS {
        return Err(format!(
            "too many search plugins selected (maximum {MAX_SELECTED_PLUGINS})"
        ));
    }

    for value in requested {
        let module = sanitize_module_name(value)?;
        let Some(plugin) = plugins.iter().find(|plugin| plugin.module == module) else {
            return Err(format!("unknown search plugin: {module}"));
        };
        if !plugin.healthy {
            return Err(format!("search plugin is not ready: {module}"));
        }
        if !selected.contains(&module) {
            selected.push(module);
        }
    }
    Ok(selected)
}

fn normalize_category(category: &str) -> Result<String, String> {
    let category = category.trim().to_ascii_lowercase();
    match category.as_str() {
        "all" | "anime" | "books" | "games" | "movies" | "music" | "pictures" | "software"
        | "tv" => Ok(category),
        _ => Err("invalid search category".to_string()),
    }
}

fn run_search_process(
    runtime: &SearchRuntime,
    query: &str,
    category: &str,
    plugins: &[String],
) -> Result<(Vec<SearchResult>, String), String> {
    ensure_real_directory(&runtime.root)?;
    ensure_real_directory(&runtime.root.join("engines"))?;
    let mut args = vec![plugins.join(","), category.to_string()];
    args.extend(
        query
            .split_whitespace()
            .map(|token| token.to_string())
            .filter(|token| !token.is_empty()),
    );
    let output = run_python_script(runtime, "nova2.py", &args, SEARCH_TIMEOUT, None)?;
    let plugins_by_url = current_plugins();
    let mut results = parse_search_results(&output.stdout, &plugins_by_url);
    sort_results(&mut results);

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stderr = if output.stderr_truncated {
        if stderr.is_empty() {
            "search plugin error output was truncated".to_string()
        } else {
            format!("{stderr} (error output truncated)")
        }
    } else {
        stderr
    };
    let stderr = if output.stdout_truncated {
        if stderr.is_empty() {
            "search results were truncated because a plugin returned too much data".to_string()
        } else {
            format!("{stderr}; search results were truncated")
        }
    } else {
        stderr
    };
    if output.success {
        return Ok((results, stderr));
    }
    if !results.is_empty() {
        let warning = if stderr.is_empty() {
            "one or more search plugins reported an error".to_string()
        } else {
            stderr
        };
        return Ok((results, warning));
    }
    if stderr.is_empty() {
        return Err("search failed".to_string());
    }
    Err(stderr)
}

fn parse_search_results(stdout: &[u8], plugins: &[SearchPlugin]) -> Vec<SearchResult> {
    let text = String::from_utf8_lossy(stdout);
    let mut results = Vec::new();
    for line in text.lines().take(MAX_RESULTS_PER_PLUGIN) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(8, '|').collect();
        if parts.len() < 6 {
            continue;
        }
        let link = parts[0].trim();
        if !is_supported_result_link(link) {
            continue;
        }
        let site_url = parts[5].trim().to_string();
        let plugin = plugin_name_by_site_url(&site_url, plugins).unwrap_or_default();
        let desc_link = parts
            .get(6)
            .map(|value| value.trim())
            .filter(|value| is_http_url(value))
            .unwrap_or_default()
            .to_string();
        results.push(SearchResult {
            result_id: 0,
            plugin,
            site_url,
            link: link.to_string(),
            name: parts[1].trim().to_string(),
            size_bytes: parse_i64(parts[2]),
            seeds: parse_i64(parts[3]),
            leech: parse_i64(parts[4]),
            desc_link,
            pub_date: parts.get(7).map(|value| parse_i64(value)).unwrap_or(-1),
        });
    }
    results
}

/// Most seeds first, then by name. The result id makes the order total, so
/// an unstable sort is deterministic across incremental merges.
fn sort_results(results: &mut [SearchResult]) {
    crate::util::sort_by(results, |left, right| {
        right
            .seeds
            .cmp(&left.seeds)
            .then_with(|| left.name.cmp(&right.name))
            .then(left.result_id.cmp(&right.result_id))
            .is_lt()
    });
}

fn is_http_url(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("http://") || value.starts_with("https://")
}

fn is_supported_result_link(value: &str) -> bool {
    value.trim().starts_with("magnet:?") || is_http_url(value)
}

fn plugin_name_by_site_url(site_url: &str, plugins: &[SearchPlugin]) -> Option<String> {
    fn normalize(url: &str) -> &str {
        url.trim().trim_end_matches('/')
    }
    let wanted = normalize(site_url);
    plugins
        .iter()
        .find(|plugin| {
            let url = normalize(&plugin.site_url);
            !url.is_empty() && url.eq_ignore_ascii_case(wanted)
        })
        .map(|plugin| plugin.module.clone())
}

fn parse_i64(value: &str) -> i64 {
    value.trim().parse::<i64>().unwrap_or(-1)
}

fn download_through_plugin(
    runtime: &SearchRuntime,
    plugin: &str,
    url: &str,
) -> Result<Vec<u8>, String> {
    let tmp_dir = create_plugin_temp_dir()?;
    let args = [plugin.to_string(), url.to_string()];
    let result = (|| -> Result<Vec<u8>, String> {
        // The private directory is both the working directory and the
        // interpreter's temporary directory, so `helpers.download_file`
        // (tempfile.mkstemp) writes where the containment check expects.
        let output = run_python_script(
            runtime,
            "nova2dl.py",
            &args,
            DOWNLOAD_TIMEOUT,
            Some(&tmp_dir),
        )?;
        if output.stdout_truncated || output.stderr_truncated {
            return Err("search plugin download output was too large".to_string());
        }
        if !output.success {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.is_empty() {
                return Err("plugin torrent download failed".to_string());
            }
            return Err(stderr);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let path_str = plugin_output_path(&stdout, url)
            .ok_or_else(|| "search plugin did not return a torrent file path".to_string())?;
        let path = Path::new(path_str);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            tmp_dir.join(path)
        };
        let output_metadata = fs::symlink_metadata(&path)
            .map_err(|err| format!("inspect plugin output path: {err}"))?;
        validate_regular_file_metadata(&output_metadata, "plugin output")?;
        let canonical_path = path
            .canonicalize()
            .map_err(|err| format!("canonicalize plugin output path: {err}"))?;
        let canonical_tmp = tmp_dir
            .canonicalize()
            .map_err(|err| format!("canonicalize temp dir: {err}"))?;
        if !canonical_path.starts_with(&canonical_tmp) {
            return Err("plugin returned a path outside its temp directory".to_string());
        }
        let bytes = read_regular_file_limited(
            &canonical_path,
            MAX_TORRENT_BYTES,
            "read downloaded torrent",
        )?;
        let _ = fs::remove_file(&canonical_path);
        Ok(bytes)
    })();
    let _ = fs::remove_dir_all(&tmp_dir);
    result
}

/// Plugins print `<path> <url>`. Strip the known URL so a temporary path
/// containing spaces (for example a Windows profile directory) survives;
/// otherwise fall back to the first whitespace-separated token.
fn plugin_output_path<'a>(stdout: &'a str, url: &str) -> Option<&'a str> {
    let stdout = stdout.trim();
    stdout
        .strip_suffix(url)
        .map(str::trim_end)
        .filter(|path| !path.is_empty() && !path.contains('\n'))
        .or_else(|| stdout.split_whitespace().next())
}

fn create_plugin_temp_dir() -> Result<PathBuf, String> {
    for attempt in 0..32u64 {
        let random = crate::system_entropy_u64();
        let dir = std::env::temp_dir().join(format!(
            "rustorrent-plugin-{}-{random:016x}-{attempt}",
            std::process::id()
        ));
        match create_private_temp_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(format!("create plugin temp dir: {err}")),
        }
    }
    Err("create plugin temp dir: could not allocate a unique directory".to_string())
}

#[cfg(unix)]
fn create_private_temp_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_temp_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

/// Run a runtime script. With `temp_dir`, that private directory becomes the
/// working directory and the interpreter's temporary directory; otherwise
/// the script runs in the runtime root.
fn run_python_script(
    runtime: &SearchRuntime,
    script_name: &str,
    args: &[String],
    timeout: Duration,
    temp_dir: Option<&Path>,
) -> Result<ProcessOutput, String> {
    let python = runtime
        .python
        .as_ref()
        .ok_or_else(|| "Python 3.9 or newer is not available".to_string())?;
    let script_path = runtime.root.join(script_name);
    let mut command = Command::new(python);
    command
        .arg("-I")
        .arg("-X")
        .arg("utf8")
        .arg(script_path)
        .args(args)
        .current_dir(temp_dir.unwrap_or(&runtime.root))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for name in [
        "PATH",
        "HOME",
        "TMPDIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "RUSTORRENT_SEARCH_INSECURE_SSL",
        "qbt_socks_proxy",
        "sock_proxy",
        // Windows: Winsock and the CRT need these; without SYSTEMROOT the
        // interpreter cannot open sockets.
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
    ] {
        if let Ok(value) = std::env::var(name) {
            command.env(name, value);
        }
    }
    if let Some(temp_dir) = temp_dir {
        for name in ["TMPDIR", "TEMP", "TMP"] {
            command.env(name, temp_dir);
        }
    }
    command.env("PYTHONIOENCODING", "utf-8");

    run_command_with_timeout(&mut command, script_name, timeout)
}

fn run_command_with_timeout(
    command: &mut Command,
    label: &str,
    timeout: Duration,
) -> Result<ProcessOutput, String> {
    let mut process =
        ProcessTree::spawn(command).map_err(|err| format!("launch {label}: {err}"))?;
    let stdout_reader = process
        .child
        .stdout
        .take()
        .map(|handle| ReaderTask::spawn(Box::new(handle), MAX_PROCESS_STDOUT_BYTES));
    let stderr_reader = process
        .child
        .stderr
        .take()
        .map(|handle| ReaderTask::spawn(Box::new(handle), MAX_PROCESS_STDERR_BYTES));
    let deadline = Instant::now() + timeout;
    let mut backoff = Duration::from_millis(1);
    let outcome = loop {
        match process.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => {}
            Ok(None) => break Err(format!("{label} timed out")),
            Err(err) => break Err(format!("wait {label}: {err}")),
        }
        thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_millis(50));
    };
    // Always kill the process group (descendants may hold the pipes) and
    // collect the bounded readers, whatever the outcome.
    let cleanup = process.terminate_and_reap();
    let ((stdout, stdout_truncated), (stderr, stderr_truncated)) =
        collect_reader_tasks(stdout_reader, stderr_reader);
    match (outcome, cleanup) {
        (Ok(status), Ok(())) => Ok(ProcessOutput {
            success: status.success(),
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        }),
        (Ok(_), Err(err)) => Err(format!("cleanup {label}: {err}")),
        (Err(message), Ok(())) => Err(message),
        (Err(message), Err(err)) => Err(format!("{message}; cleanup failed: {err}")),
    }
}

fn read_limited(reader: &mut dyn Read, limit: usize) -> (Vec<u8>, bool) {
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    let mut truncated = false;
    let mut chunk = [0u8; 8192];
    loop {
        let count = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        let remaining = limit.saturating_sub(output.len());
        let keep = remaining.min(count);
        output.extend_from_slice(&chunk[..keep]);
        truncated |= keep < count;
    }
    (output, truncated)
}

fn parse_unofficial_catalog(text: &str) -> Vec<SearchCatalogEntry> {
    let mut rows = Vec::new();
    let mut current_cells: Vec<String> = Vec::new();
    let mut current_cell = String::new();
    let mut in_row = false;
    let mut private_site = false;
    let mut row_private_site = false;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.starts_with("= Plugins for Private Sites =") {
            private_site = true;
            continue;
        }
        if line == "|-" {
            if let Some(entry) = build_catalog_entry(&current_cells, row_private_site) {
                rows.push(entry);
            }
            current_cells.clear();
            current_cell.clear();
            in_row = true;
            row_private_site = private_site;
            continue;
        }
        if !in_row {
            continue;
        }
        if line == "|}" {
            if let Some(entry) = build_catalog_entry(&current_cells, row_private_site) {
                rows.push(entry);
            }
            current_cells.clear();
            current_cell.clear();
            in_row = false;
            continue;
        }
        if line.starts_with('!') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('|') {
            if !current_cell.trim().is_empty() {
                current_cells.push(current_cell.trim().to_string());
            }
            current_cell.clear();
            current_cell.push_str(rest.trim());
        } else if !line.is_empty() {
            if !current_cell.is_empty() {
                current_cell.push(' ');
            }
            current_cell.push_str(line);
        }
    }
    if let Some(entry) = build_catalog_entry(&current_cells, row_private_site) {
        rows.push(entry);
    }
    rows
}

fn build_catalog_entry(cells: &[String], private_site: bool) -> Option<SearchCatalogEntry> {
    if cells.len() < 5 {
        return None;
    }
    let download_url = extract_download_url(&cells[4])?;
    let module = filename_from_url(&download_url)
        .ok()
        .and_then(|name| plugin_module_from_filename(&name))
        .unwrap_or_else(|| filename_from_link(&download_url));
    let comment = cells
        .get(5)
        .map(|value| clean_wiki_text(value))
        .unwrap_or_default();
    Some(SearchCatalogEntry {
        module,
        name: extract_display_name(&cells[0]).unwrap_or_else(|| filename_from_link(&download_url)),
        author: extract_display_name(&cells[1]).unwrap_or_else(|| clean_wiki_text(&cells[1])),
        version: clean_wiki_text(cells.get(2)?),
        updated: clean_wiki_text(cells.get(3)?),
        download_url,
        comment,
        private_site,
    })
}

fn extract_download_url(cell: &str) -> Option<String> {
    extract_external_links(cell)
        .into_iter()
        .map(|(url, _)| url)
        .find(|url| url.to_ascii_lowercase().contains(".py"))
}

fn extract_display_name(cell: &str) -> Option<String> {
    for (url, label) in extract_external_links(cell).into_iter().rev() {
        let lower = url.to_ascii_lowercase();
        if lower.ends_with(".png")
            || lower.ends_with(".gif")
            || lower.ends_with(".jpg")
            || lower.ends_with(".jpeg")
            || lower.contains("favicon")
        {
            continue;
        }
        let cleaned = clean_wiki_text(&label);
        if !cleaned.is_empty() {
            return Some(cleaned);
        }
    }
    let cleaned = clean_wiki_text(cell);
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn extract_external_links(text: &str) -> Vec<(String, String)> {
    let bytes = text.as_bytes();
    let mut links = Vec::new();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'[' && bytes.get(idx + 1) != Some(&b'[') {
            let start = idx + 1;
            if let Some(end_rel) = text[start..].find(']') {
                let chunk = text[start..start + end_rel].trim();
                if let Some((url, label)) = chunk.split_once(' ') {
                    links.push((url.trim().to_string(), label.trim().to_string()));
                } else if !chunk.is_empty() {
                    links.push((chunk.to_string(), String::new()));
                }
                idx = start + end_rel + 1;
                continue;
            }
        }
        idx += 1;
    }
    links
}

fn clean_wiki_text(text: &str) -> String {
    let mut out = text
        .replace("<br />", " / ")
        .replace("<br/>", " / ")
        .replace("<br>", " / ")
        .replace("'''", "")
        .replace("''", "")
        .replace("&nbsp;", " ");
    out = strip_links(&out, true);
    out = strip_links(&out, false);
    out = out.replace("&#124;", "|");
    collapse_whitespace(&out)
}

/// Replace wiki links by their labels: `[[target|label]]` when `double`,
/// otherwise `[url label]`. Links without a label are dropped. Text is
/// copied as string slices, so multi-byte characters stay intact.
fn strip_links(text: &str, double: bool) -> String {
    let close = if double { "]]" } else { "]" };
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let (mut idx, mut copied) = (0usize, 0usize);
    while idx < bytes.len() {
        if bytes[idx] == b'[' && (bytes.get(idx + 1) == Some(&b'[')) == double {
            let start = idx + 1 + usize::from(double);
            if let Some(end_rel) = text[start..].find(close) {
                out.push_str(&text[copied..idx]);
                let inner = &text[start..start + end_rel];
                let label = if double {
                    inner.rsplit_once('|')
                } else {
                    inner.trim().split_once(' ')
                };
                if let Some((_, label)) = label {
                    out.push_str(label.trim());
                }
                idx = start + end_rel + close.len();
                copied = idx;
                continue;
            }
        }
        idx += 1;
    }
    out.push_str(&text[copied..]);
    out
}

fn collapse_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
        } else {
            out.push(ch);
            last_space = false;
        }
    }
    out.trim().to_string()
}

fn filename_from_link(url: &str) -> String {
    filename_from_url(url)
        .ok()
        .and_then(|name| plugin_module_from_filename(&name))
        .unwrap_or_else(|| "plugin".to_string())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn set_last_error(message: &str) {
    if let Some(lock) = SEARCH_STATE.get() {
        let mut state = lock_state(lock);
        state.last_error = message.to_string();
    }
}

fn lock_state(lock: &Mutex<SearchState>) -> std::sync::MutexGuard<'_, SearchState> {
    match lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Append `text` as a quoted JSON string.
pub(crate) fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_module_from_filename_accepts_python_identifiers() {
        assert_eq!(
            plugin_module_from_filename("piratebay.py"),
            Some("piratebay".to_string())
        );
        assert_eq!(
            plugin_module_from_filename("_custom123.py"),
            Some("_custom123".to_string())
        );
    }

    #[test]
    fn plugin_module_from_filename_rejects_invalid_names() {
        assert_eq!(plugin_module_from_filename("1bad.py"), None);
        assert_eq!(plugin_module_from_filename("bad-name.py"), None);
        assert_eq!(plugin_module_from_filename("bad.txt"), None);
    }

    #[test]
    fn parse_search_results_maps_site_urls_back_to_plugins() {
        let plugins = vec![SearchPlugin {
            module: "piratebay".to_string(),
            display_name: "The Pirate Bay".to_string(),
            site_url: "https://thepiratebay.org".to_string(),
            version: "1.0".to_string(),
            categories: vec!["movies".to_string()],
            healthy: true,
            broken_reason: String::new(),
        }];
        let output = b"magnet:?xt=urn:btih:abc|Ubuntu ISO|1024|12|1|https://thepiratebay.org|https://thepiratebay.org/desc|1700000000\n";
        let results = parse_search_results(output, &plugins);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].plugin, "piratebay");
        assert_eq!(results[0].seeds, 12);
    }

    #[test]
    fn parse_unofficial_catalog_extracts_download_link() {
        let wiki = r#"
= Plugins for Public Sites =
{|class="sortable"
|-
| [[https://www.google.com/s2/favicons?domain=bitsearch.to#.png]] [https://bitsearch.to/ Bit Search]
| [https://github.com/BurningMop/qBittorrent-Search-Plugins BurningMop]
| 1.1
| 13/Apr/2024
| [https://raw.githubusercontent.com/BurningMop/qBittorrent-Search-Plugins/refs/heads/main/bitsearch.py [[https://raw.githubusercontent.com/Pireo/hello-world/master/Download.gif]] ]
| ✔ qbt 4.6.x / python 3.9.x
|}
"#;
        let entries = parse_unofficial_catalog(wiki);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Bit Search");
        assert_eq!(entries[0].module, "bitsearch");
        assert!(entries[0].download_url.ends_with("bitsearch.py"));
    }

    #[test]
    fn catalog_leaves_out_adult_sites_only() {
        let entry = |name: &str, url: &str| SearchCatalogEntry {
            name: name.to_string(),
            module: filename_from_link(url).trim_end_matches(".py").to_string(),
            download_url: url.to_string(),
            comment: "works for everything except XXX and software".to_string(),
            ..SearchCatalogEntry::default()
        };
        let base = "https://raw.githubusercontent.com/example/plugins/main/";
        for (name, file) in [
            ("My Porn Club", "mypornclub.py"),
            ("XXXClub", "xxxclubto.py"),
            ("Sukebei Nyaa", "sukebei/nyaa.py"),
        ] {
            assert!(
                is_adult_site(&entry(name, &format!("{base}{file}"))),
                "{name}"
            );
        }
        for (name, file) in [("Nyaa.si", "nyaasi.py"), ("EZTV", "eztvx.py")] {
            assert!(
                !is_adult_site(&entry(name, &format!("{base}{file}"))),
                "{name}"
            );
        }
    }

    #[test]
    fn recommended_plugins_are_valid_module_names() {
        for module in RECOMMENDED_PLUGINS {
            assert_eq!(
                plugin_module_from_filename(&format!("{module}.py")).as_deref(),
                Some(module)
            );
        }
    }

    #[test]
    fn installed_plugins_skips_package_init_files() {
        let root = std::env::temp_dir().join(format!("rustorrent-search-test-{}", now_secs()));
        let engines = root.join("engines");
        fs::create_dir_all(&engines).unwrap();
        fs::write(engines.join("__init__.py"), b"").unwrap();
        fs::write(engines.join("piratebay.py"), b"# VERSION: 1.0\n").unwrap();

        let plugins = installed_plugins(&root).unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].module, "piratebay");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn summarize_search_warning_hides_tracebacks() {
        let message = "Connection error: <none> Traceback (most recent call last): ...";
        let summary = summarize_search_warning(message);
        assert!(!summary.contains("Traceback"));
        assert!(summary.contains("plugins failed"));
    }

    #[test]
    fn plugin_known_issue_marks_magnetdl_broken() {
        assert!(plugin_known_issue("magnetdl").is_some());
        assert!(plugin_known_issue("piratebay").is_none());
    }

    #[test]
    fn catalog_json_omits_private_site_entries() {
        let entries = vec![
            SearchCatalogEntry {
                module: "publicmod".to_string(),
                name: "Public".to_string(),
                author: "Author".to_string(),
                version: "1.0".to_string(),
                updated: "today".to_string(),
                download_url: "https://example.com/public.py".to_string(),
                comment: String::new(),
                private_site: false,
            },
            SearchCatalogEntry {
                module: "privatemod".to_string(),
                name: "Private".to_string(),
                author: "Author".to_string(),
                version: "1.0".to_string(),
                updated: "today".to_string(),
                download_url: "https://example.com/private.py".to_string(),
                comment: String::new(),
                private_site: true,
            },
        ];
        let mut json = Json(String::from("["));
        append_catalog_entries_json(&mut json, &entries, &[]);
        let json = json.0;
        assert!(json.contains("\"module\":\"publicmod\""));
        assert!(!json.contains("\"module\":\"privatemod\""));
    }

    #[test]
    fn install_plugin_from_url_rejects_http() {
        let result = install_plugin_from_url("http://example.com/plugin.py");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("https://"));
    }

    #[test]
    fn install_plugin_from_url_rejects_non_url() {
        let result = install_plugin_from_url("ftp://example.com/plugin.py");
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn python_probe_requires_the_compatible_runtime_marker() {
        assert!(!command_available("/usr/bin/true"));
    }

    #[test]
    fn plugin_temp_dir_path_traversal_rejected() {
        let tmp = create_plugin_temp_dir().unwrap();
        let outside = std::env::temp_dir().join("rustorrent-outside-test");
        fs::create_dir_all(&outside).unwrap();
        let test_file = outside.join("secret.torrent");
        fs::write(&test_file, b"test data").unwrap();

        let canonical_tmp = tmp.canonicalize().unwrap();
        let canonical_outside = test_file.canonicalize().unwrap();
        assert!(!canonical_outside.starts_with(&canonical_tmp));

        let _ = fs::remove_dir_all(&tmp);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn create_plugin_temp_dir_creates_unique_dirs() {
        let a = create_plugin_temp_dir().unwrap();
        let b = create_plugin_temp_dir().unwrap();
        assert_ne!(a, b);
        assert!(a.exists());
        assert!(b.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(fs::metadata(&a).unwrap().permissions().mode() & 0o077, 0);
            assert_eq!(fs::metadata(&b).unwrap().permissions().mode() & 0o077, 0);
        }
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
    }

    #[cfg(unix)]
    #[test]
    fn runtime_creation_rejects_symlinked_parent_directories() {
        use std::os::unix::fs::symlink;

        let base = create_plugin_temp_dir().unwrap();
        let outside = create_plugin_temp_dir().unwrap();
        let linked = base.join("search");
        symlink(&outside, &linked).unwrap();

        assert!(ensure_runtime(&linked.join("nova3")).is_err());
        assert!(!outside.join("nova3").exists());

        let _ = fs::remove_dir_all(base);
        let _ = fs::remove_dir_all(outside);
    }

    #[cfg(unix)]
    #[test]
    fn process_timeout_kills_descendants_that_inherit_pipes() {
        let root = create_plugin_temp_dir().unwrap();
        let marker = root.join("descendant-survived");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("(sleep 1; printf survived > \"$MARKER\") & sleep 10")
            .env("MARKER", &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = Instant::now();
        let err = run_command_with_timeout(
            &mut command,
            "descendant-timeout-test",
            Duration::from_millis(100),
        )
        .unwrap_err();
        assert!(err.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(3));
        thread::sleep(Duration::from_millis(1_200));
        assert!(!marker.exists(), "timed-out descendant was not terminated");

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn successful_leader_exit_still_cleans_up_pipe_holding_descendants() {
        let root = create_plugin_temp_dir().unwrap();
        let marker = root.join("descendant-survived");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("(sleep 1; printf survived > \"$MARKER\") & exit 0")
            .env("MARKER", &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = Instant::now();
        let output = run_command_with_timeout(
            &mut command,
            "descendant-success-test",
            Duration::from_secs(3),
        )
        .unwrap();
        assert!(output.success);
        assert!(started.elapsed() < Duration::from_secs(3));
        thread::sleep(Duration::from_millis(1_200));
        assert!(!marker.exists(), "orphaned descendant was not terminated");

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn reader_collection_has_a_hard_deadline() {
        use std::os::unix::net::UnixStream;

        let (reader, writer) = UnixStream::pair().unwrap();
        let task = ReaderTask::spawn(Box::new(reader), 1024);
        let started = Instant::now();
        let (bytes, truncated) = task.collect(Instant::now() + Duration::from_millis(50));
        assert!(bytes.is_empty());
        assert!(truncated);
        assert!(started.elapsed() < Duration::from_secs(1));

        // Closing the writer lets the detached reader exit promptly after the
        // bounded collector has already returned.
        drop(writer);
    }

    #[test]
    fn bounded_file_reader_rejects_oversized_and_nonregular_inputs() {
        let root = create_plugin_temp_dir().unwrap();
        let oversized = root.join("oversized.bin");
        fs::write(&oversized, vec![0u8; 17]).unwrap();
        let err = read_regular_file_limited(&oversized, 16, "test read").unwrap_err();
        assert!(err.contains("too large"));

        let err = read_regular_file_limited(&root, 16, "test read").unwrap_err();
        assert!(err.contains("not a regular file"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let symlink_path = root.join("symlink.bin");
            symlink(&oversized, &symlink_path).unwrap();
            let err = read_regular_file_limited(&symlink_path, 32, "test read").unwrap_err();
            assert!(err.contains("not a regular file"));

            let hard_link_path = root.join("hard-link.bin");
            fs::hard_link(&oversized, &hard_link_path).unwrap();
            let err = read_regular_file_limited(&hard_link_path, 32, "test read").unwrap_err();
            assert!(err.contains("hard-linked"));
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_comparison_replaces_oversized_existing_file() {
        let root = create_plugin_temp_dir().unwrap();
        let path = root.join("runtime.py");
        fs::write(&path, vec![b'x'; MAX_RUNTIME_FILE_BYTES + 1]).unwrap();

        write_if_changed(&path, b"replacement").unwrap();
        let bytes =
            read_regular_file_limited(&path, MAX_RUNTIME_FILE_BYTES, "read replaced runtime")
                .unwrap();
        assert_eq!(bytes, b"replacement");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn json_writer_separates_members_and_escapes_strings() {
        let mut out = Json(String::new());
        out.open("", '{');
        out.raw("busy", &true);
        out.str("q", "a\"b\\c\n\u{1}é");
        out.open("list", '[');
        out.str("", "x");
        out.open("", '{');
        out.raw("n", &-1i64);
        out.0.push('}');
        out.0.push_str("],\"empty\":[]}");
        assert_eq!(
            out.0,
            r#"{"busy":true,"q":"a\"b\\c\n\u0001é","list":["x",{"n":-1}],"empty":[]}"#
        );
    }

    #[test]
    fn wiki_cleanup_keeps_multibyte_text_intact() {
        assert_eq!(
            clean_wiki_text("✔ qbt [[File:x.png|Ünïcode]] café [https://x.example/ label ü] ok"),
            "✔ qbt Ünïcode café label ü ok"
        );
        assert_eq!(strip_links("a [[b]] c", true), "a  c");
        assert_eq!(
            strip_links("日本 [unterminated", false),
            "日本 [unterminated"
        );
    }

    #[test]
    fn plugin_output_path_accepts_paths_with_spaces() {
        let url = "https://example.com/a.torrent";
        assert_eq!(
            plugin_output_path(
                "C:\\Users\\Jo Smith\\tmp\\x.torrent https://example.com/a.torrent\n",
                url
            ),
            Some("C:\\Users\\Jo Smith\\tmp\\x.torrent")
        );
        assert_eq!(
            plugin_output_path("/tmp/x.torrent https://other.example/b\n", url),
            Some("/tmp/x.torrent")
        );
        assert_eq!(plugin_output_path("  \n", url), None);
    }

    #[test]
    fn results_sort_is_total_and_deterministic() {
        let result = |id, seeds, name: &str| SearchResult {
            result_id: id,
            seeds,
            name: name.to_string(),
            ..SearchResult::default()
        };
        let mut results = vec![
            result(3, 5, "b"),
            result(2, 5, "a"),
            result(1, 5, "a"),
            result(0, 9, "z"),
        ];
        sort_results(&mut results);
        let ids = results.iter().map(|r| r.result_id).collect::<Vec<_>>();
        assert_eq!(ids, [0, 1, 2, 3]);
    }

    #[cfg(unix)]
    #[test]
    fn bundled_runtime_searches_mixed_case_engines_with_option_like_keywords() {
        let Some(python) = detect_python() else {
            return;
        };
        let base = create_plugin_temp_dir().unwrap();
        let root = base.join("nova3");
        ensure_runtime(&root).unwrap();
        fs::write(
            root.join("engines/MyEngine.py"),
            "from novaprinter import prettyPrinter\n\
             class MyEngine:\n\
             \x20   name = 'Mine'\n\
             \x20   url = 'https://mine.example'\n\
             \x20   supported_categories = {'all': '0', 'tv': '5'}\n\
             \x20   def search(self, what, cat='all'):\n\
             \x20       prettyPrinter({'link': 'magnet:?xt=urn:btih:' + what, 'name': 'N|x',\n\
             \x20           'size': '1 KB', 'seeds': 3, 'leech': 1, 'engine_url': self.url})\n",
        )
        .unwrap();
        let runtime = SearchRuntime {
            root: root.clone(),
            python: Some(python),
        };
        let output = run_python_script(
            &runtime,
            "nova2.py",
            &["--capabilities".to_string()],
            CAPABILITIES_TIMEOUT,
            None,
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&output.stdout).contains("<MyEngine>"));

        let (results, _) = run_search_process(
            &runtime,
            "hello --capabilities",
            "tv",
            &["MyEngine".to_string()],
        )
        .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "N x");
        assert_eq!(results[0].size_bytes, 1024);
        assert!(results[0].link.ends_with("hello%20--capabilities"));
        fs::remove_dir_all(base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn plugin_downloads_use_the_private_directory_for_temporary_files() {
        let Some(python) = detect_python() else {
            return;
        };
        let root = create_plugin_temp_dir().unwrap();
        fs::write(
            root.join("nova2dl.py"),
            "import os, sys, tempfile\n\
             fd, path = tempfile.mkstemp()\n\
             os.write(fd, b'd4:infoe')\n\
             os.close(fd)\n\
             print(path, sys.argv[2])\n",
        )
        .unwrap();
        let runtime = SearchRuntime {
            root: root.clone(),
            python: Some(python),
        };
        let bytes =
            download_through_plugin(&runtime, "engine", "https://example.com/x.torrent").unwrap();
        assert_eq!(bytes, b"d4:infoe");
        fs::remove_dir_all(root).unwrap();
    }
}

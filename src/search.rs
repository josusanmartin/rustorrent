use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{http, xml};

const SEARCH_TIMEOUT: Duration = Duration::from_secs(60);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);
const CAPABILITIES_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_PLUGIN_BYTES: usize = 512 * 1024;
const MAX_TORRENT_BYTES: usize = 10 * 1024 * 1024;
const MAX_CATALOG_BYTES: usize = 768 * 1024;
const CATALOG_CACHE_SECS: u64 = 6 * 60 * 60;
const CATALOG_URL: &str =
    "https://raw.githubusercontent.com/qbittorrent/search-plugins/master/wiki/Unofficial-search-plugins.mediawiki";

#[derive(Clone, Debug, Default)]
pub struct SearchPlugin {
    pub module: String,
    pub display_name: String,
    pub site_url: String,
    pub version: String,
    pub categories: Vec<String>,
    pub healthy: bool,
    pub broken_reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct SearchResult {
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

#[derive(Clone, Debug, Default)]
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

#[derive(Clone, Debug, Default)]
struct SearchState {
    plugins: Vec<SearchPlugin>,
    results: Vec<SearchResult>,
    catalog: Vec<SearchCatalogEntry>,
    busy: bool,
    python_available: bool,
    plugin_error: String,
    last_error: String,
    last_query: String,
    last_category: String,
    last_started_at: u64,
    last_finished_at: u64,
    catalog_error: String,
    catalog_fetched_at: u64,
}

#[derive(Clone, Debug)]
struct SearchRuntime {
    root: PathBuf,
    python: Option<String>,
}

#[derive(Debug)]
struct ProcessOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

pub enum SearchDownload {
    Magnet(String),
    TorrentBytes(Vec<u8>),
}

static SEARCH_RUNTIME: OnceLock<SearchRuntime> = OnceLock::new();
static SEARCH_STATE: OnceLock<Mutex<SearchState>> = OnceLock::new();

fn no_plugins_message() -> &'static str {
    "No search plugins are installed yet. Open Plugins or Community Catalog to add one."
}

pub fn prepare(download_dir: &Path) -> Result<(), String> {
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
        guard.plugin_error =
            "Python 3 was not found. Install python3 to use qBittorrent-style search plugins."
                .to_string();
    } else if guard.plugins.is_empty() {
        guard.plugin_error = no_plugins_message().to_string();
    }
    Ok(())
}

pub fn init(download_dir: &Path) -> Result<(), String> {
    prepare(download_dir)?;
    refresh_plugins()
}

pub fn refresh_plugins() -> Result<(), String> {
    let runtime = runtime()?;
    let state = SEARCH_STATE.get_or_init(|| Mutex::new(SearchState::default()));
    let mut guard = lock_state(state);
    let (plugins, plugin_error) = load_plugins(runtime)?;
    guard.plugins = plugins;
    guard.python_available = runtime.python.is_some();
    guard.plugin_error = plugin_error;
    if !guard.python_available && guard.plugin_error.is_empty() {
        guard.plugin_error =
            "Python 3 was not found. Install python3 to use qBittorrent-style search plugins."
                .to_string();
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
    let mut out = format!(
        "{{\"busy\":{},\"python_available\":{},\"plugin_error\":\"{}\",\"last_error\":\"{}\",\"query\":\"{}\",\"category\":\"{}\",\"last_started_at\":{},\"last_finished_at\":{},\"plugins\":[",
        if state.busy { "true" } else { "false" },
        if state.python_available { "true" } else { "false" },
        escape_json(&state.plugin_error),
        escape_json(&state.last_error),
        escape_json(&state.last_query),
        escape_json(&state.last_category),
        state.last_started_at,
        state.last_finished_at,
    );
    for (idx, plugin) in state.plugins.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"module\":\"{}\",\"display_name\":\"{}\",\"site_url\":\"{}\",\"version\":\"{}\",\"healthy\":{},\"broken_reason\":\"{}\",\"categories\":[",
            escape_json(&plugin.module),
            escape_json(&plugin.display_name),
            escape_json(&plugin.site_url),
            escape_json(&plugin.version),
            if plugin.healthy { "true" } else { "false" },
            escape_json(&plugin.broken_reason),
        ));
        for (cat_idx, category) in plugin.categories.iter().enumerate() {
            if cat_idx > 0 {
                out.push(',');
            }
            out.push_str(&format!("\"{}\"", escape_json(category)));
        }
        out.push_str("]}");
    }
    out.push_str("],\"results\":[");
    for (idx, result) in state.results.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"index\":{},\"plugin\":\"{}\",\"site_url\":\"{}\",\"link\":\"{}\",\"name\":\"{}\",\"size\":{},\"seeds\":{},\"leech\":{},\"desc_link\":\"{}\",\"pub_date\":{}}}",
            idx,
            escape_json(&result.plugin),
            escape_json(&result.site_url),
            escape_json(&result.link),
            escape_json(&result.name),
            result.size_bytes,
            result.seeds,
            result.leech,
            escape_json(&result.desc_link),
            result.pub_date,
        ));
    }
    out.push_str("]}");
    out
}

pub fn catalog_json(force_refresh: bool) -> String {
    let fetch_error = update_catalog(force_refresh).err();
    let Some(lock) = SEARCH_STATE.get() else {
        return "{\"entries\":[],\"error\":\"search not initialized\"}".to_string();
    };
    if let Some(err) = fetch_error {
        let mut state = lock_state(lock);
        state.catalog_error = err;
    }
    let state = lock_state(lock);
    let installed_plugins = state.plugins.clone();
    let mut out = format!(
        "{{\"error\":\"{}\",\"source_url\":\"{}\",\"fetched_at\":{},\"entries\":[",
        escape_json(&state.catalog_error),
        escape_json(CATALOG_URL),
        state.catalog_fetched_at
    );
    append_catalog_entries_json(&mut out, &state.catalog, &installed_plugins);
    out.push_str("]}");
    out
}

fn append_catalog_entries_json(
    out: &mut String,
    entries: &[SearchCatalogEntry],
    installed_plugins: &[SearchPlugin],
) {
    let mut first = true;
    for entry in entries.iter().filter(|entry| !entry.private_site) {
        if !first {
            out.push(',');
        }
        first = false;
        let installed = installed_plugins
            .iter()
            .find(|plugin| plugin.module == entry.module);
        out.push_str(&format!(
            "{{\"module\":\"{}\",\"name\":\"{}\",\"author\":\"{}\",\"version\":\"{}\",\"updated\":\"{}\",\"download_url\":\"{}\",\"comment\":\"{}\",\"private_site\":{},\"installed\":{},\"installed_version\":\"{}\",\"installed_name\":\"{}\",\"installed_healthy\":{}}}",
            escape_json(&entry.module),
            escape_json(&entry.name),
            escape_json(&entry.author),
            escape_json(&entry.version),
            escape_json(&entry.updated),
            escape_json(&entry.download_url),
            escape_json(&entry.comment),
            if entry.private_site { "true" } else { "false" },
            if installed.is_some() { "true" } else { "false" },
            escape_json(installed.map(|plugin| plugin.version.as_str()).unwrap_or("")),
            escape_json(
                installed
                    .map(|plugin| plugin.display_name.as_str())
                    .unwrap_or("")
            ),
            if installed.map(|plugin| plugin.healthy).unwrap_or(false) {
                "true"
            } else {
                "false"
            },
        ));
    }
}

pub fn install_plugin_from_url(url: &str) -> Result<String, String> {
    let trimmed = url.trim();
    if !trimmed.starts_with("https://") {
        return Err("plugin url must use https://".to_string());
    }
    let filename = filename_from_url(trimmed)?;
    let module = plugin_module_from_filename(&filename)
        .ok_or_else(|| "plugin filename must be a valid python module name".to_string())?;
    let bytes =
        http::get(trimmed, MAX_PLUGIN_BYTES).map_err(|err| format!("plugin download: {err}"))?;
    install_plugin_bytes(&filename, &bytes)?;
    Ok(module)
}

pub fn install_plugin_from_bytes(filename: &str, bytes: &[u8]) -> Result<String, String> {
    install_plugin_bytes(filename, bytes)
}

pub fn remove_plugin(module: &str) -> Result<(), String> {
    let module = sanitize_module_name(module)?;
    let runtime = runtime()?;
    let path = runtime.root.join("engines").join(format!("{module}.py"));
    if !path.exists() {
        return Err("unknown search plugin".to_string());
    }
    fs::remove_file(&path).map_err(|err| format!("remove plugin: {err}"))?;
    refresh_plugins()
}

pub fn start_search(query: &str, category: &str, engines: &[String]) -> Result<(), String> {
    let runtime = runtime()?.clone();
    if runtime.python.is_none() {
        set_last_error(
            "Python 3 was not found. Install python3 to use qBittorrent-style search plugins.",
        );
        return Err(
            "Python 3 was not found. Install python3 to use qBittorrent-style search plugins."
                .to_string(),
        );
    }

    let query = query.trim();
    if query.is_empty() {
        return Err("search query is empty".to_string());
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
        if guard.busy {
            return Err("search already running".to_string());
        }
        guard.busy = true;
        guard.last_error.clear();
        guard.results.clear();
        guard.last_query = query.to_string();
        guard.last_category = category.clone();
        guard.last_started_at = now_secs();
        guard.last_finished_at = 0;
    }

    let query_owned = query.to_string();
    thread::spawn(move || {
        let result = run_search_process(&runtime, &query_owned, &category, &selected);
        let state = SEARCH_STATE.get_or_init(|| Mutex::new(SearchState::default()));
        let mut guard = lock_state(state);
        guard.busy = false;
        guard.last_finished_at = now_secs();
        match result {
            Ok((results, warning)) => {
                guard.results = results;
                guard.last_error = summarize_search_warning(&warning);
            }
            Err(err) => {
                guard.last_error = summarize_search_warning(&err);
            }
        }
    });

    Ok(())
}

pub fn resolve_result(index: usize) -> Result<SearchDownload, String> {
    let runtime = runtime()?;
    let result = {
        let lock = SEARCH_STATE
            .get()
            .ok_or_else(|| "search not initialized".to_string())?;
        let state = lock_state(lock);
        state
            .results
            .get(index)
            .cloned()
            .ok_or_else(|| "unknown search result".to_string())?
    };

    if result.link.starts_with("magnet:?") {
        return Ok(SearchDownload::Magnet(result.link));
    }
    if !result.link.starts_with("http://") && !result.link.starts_with("https://") {
        return Err("unsupported search result link".to_string());
    }

    if !result.plugin.is_empty() && runtime.python.is_some() {
        if let Ok(bytes) = download_through_plugin(runtime, &result.plugin, &result.link) {
            return Ok(SearchDownload::TorrentBytes(bytes));
        }
    }

    let bytes = http::get(&result.link, MAX_TORRENT_BYTES)
        .map_err(|err| format!("torrent download: {err}"))?;
    Ok(SearchDownload::TorrentBytes(bytes))
}

fn update_catalog(force_refresh: bool) -> Result<(), String> {
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

    let bytes = http::get(CATALOG_URL, MAX_CATALOG_BYTES)
        .map_err(|err| format!("catalog download: {err}"))?;
    let text = String::from_utf8(bytes).map_err(|_| "catalog is not valid utf-8".to_string())?;
    let entries = parse_unofficial_catalog(&text);
    let mut guard = lock_state(state);
    guard.catalog = entries;
    guard.catalog_error.clear();
    guard.catalog_fetched_at = now_secs();
    Ok(())
}

fn ensure_runtime(root: &Path) -> Result<(), String> {
    fs::create_dir_all(root.join("engines")).map_err(|err| format!("search runtime dir: {err}"))?;
    write_if_changed(&root.join("__init__.py"), "")?;
    write_if_changed(&root.join("engines").join("__init__.py"), "")?;
    write_if_changed(
        &root.join("helpers.py"),
        include_str!("../assets/search_runtime/helpers.py"),
    )?;
    write_if_changed(
        &root.join("nova2.py"),
        include_str!("../assets/search_runtime/nova2.py"),
    )?;
    write_if_changed(
        &root.join("nova2dl.py"),
        include_str!("../assets/search_runtime/nova2dl.py"),
    )?;
    write_if_changed(
        &root.join("novaprinter.py"),
        include_str!("../assets/search_runtime/novaprinter.py"),
    )?;
    write_if_changed(
        &root.join("socks.py"),
        include_str!("../assets/search_runtime/socks.py"),
    )?;
    Ok(())
}

fn write_if_changed(path: &Path, content: &str) -> Result<(), String> {
    let bytes = content.as_bytes();
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return Ok(());
        }
    }
    fs::write(path, bytes).map_err(|err| format!("write {}: {err}", path.display()))
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
    Command::new(command)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
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
        return Ok((
            plugins,
            "Python 3 was not found. Install python3 to use qBittorrent-style search plugins."
                .to_string(),
        ));
    }

    let output = run_python_script(
        runtime,
        "nova2.py",
        &["--capabilities".to_string()],
        CAPABILITIES_TIMEOUT,
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
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
        let path = entry.path();
        if !path.is_file() {
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
    plugins.sort_by(|left, right| left.module.cmp(&right.module));
    Ok(plugins)
}

fn plugin_version(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
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
    plugin_module_from_filename(&format!("{}.py", module.trim()))
        .ok_or_else(|| "invalid search plugin name".to_string())
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
    let runtime = runtime()?;
    let path = runtime.root.join("engines").join(format!("{module}.py"));
    fs::write(&path, bytes).map_err(|err| format!("write plugin: {err}"))?;
    refresh_plugins()?;
    Ok(module)
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
                .map(|plugin| plugin.module.clone()),
        );
        return Ok(selected);
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
    let mut args = vec![plugins.join(","), category.to_string()];
    args.extend(
        query
            .split_whitespace()
            .map(|token| token.to_string())
            .filter(|token| !token.is_empty()),
    );
    let output = run_python_script(runtime, "nova2.py", &args, SEARCH_TIMEOUT)?;
    let plugins_by_url = current_plugins();
    let mut results = parse_search_results(&output.stdout, &plugins_by_url);
    results.sort_by(|left, right| {
        right
            .seeds
            .cmp(&left.seeds)
            .then_with(|| left.name.cmp(&right.name))
    });

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
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
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('|').collect();
        if parts.len() < 6 {
            continue;
        }
        let site_url = parts[5].trim().to_string();
        let plugin = plugin_name_by_site_url(&site_url, plugins).unwrap_or_default();
        results.push(SearchResult {
            plugin,
            site_url,
            link: parts[0].trim().to_string(),
            name: parts[1].trim().to_string(),
            size_bytes: parse_i64(parts[2]),
            seeds: parse_i64(parts[3]),
            leech: parse_i64(parts[4]),
            desc_link: parts
                .get(6)
                .map(|value| value.trim().to_string())
                .unwrap_or_default(),
            pub_date: parts.get(7).map(|value| parse_i64(value)).unwrap_or(-1),
        });
    }
    results
}

fn plugin_name_by_site_url(site_url: &str, plugins: &[SearchPlugin]) -> Option<String> {
    let normalized = site_url.trim().trim_end_matches('/');
    plugins.iter().find_map(|plugin| {
        let plugin_url = plugin.site_url.trim().trim_end_matches('/');
        if !plugin_url.is_empty() && plugin_url == normalized {
            Some(plugin.module.clone())
        } else {
            None
        }
    })
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
    let args = vec![plugin.to_string(), url.to_string()];
    let output =
        run_python_script_in_dir(runtime, "nova2dl.py", &args, DOWNLOAD_TIMEOUT, &tmp_dir)?;
    let result = (|| -> Result<Vec<u8>, String> {
        if !output.success {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.is_empty() {
                return Err("plugin torrent download failed".to_string());
            }
            return Err(stderr);
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let path_str = stdout
            .split_whitespace()
            .next()
            .ok_or_else(|| "search plugin did not return a torrent file path".to_string())?;
        let path = Path::new(path_str);
        let canonical_path = path
            .canonicalize()
            .map_err(|err| format!("canonicalize plugin output path: {err}"))?;
        let canonical_tmp = tmp_dir
            .canonicalize()
            .map_err(|err| format!("canonicalize temp dir: {err}"))?;
        if !canonical_path.starts_with(&canonical_tmp) {
            return Err("plugin returned a path outside its temp directory".to_string());
        }
        let bytes =
            fs::read(&canonical_path).map_err(|err| format!("read downloaded torrent: {err}"))?;
        let _ = fs::remove_file(&canonical_path);
        Ok(bytes)
    })();
    let _ = fs::remove_dir_all(&tmp_dir);
    result
}

fn create_plugin_temp_dir() -> Result<PathBuf, String> {
    let mut bytes = [0u8; 8];
    if let Ok(mut file) = File::open("/dev/urandom") {
        let _ = file.read_exact(&mut bytes);
    }
    let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("rustorrent-plugin-{suffix}"));
    fs::create_dir_all(&dir).map_err(|err| format!("create plugin temp dir: {err}"))?;
    Ok(dir)
}

fn run_python_script(
    runtime: &SearchRuntime,
    script_name: &str,
    args: &[String],
    timeout: Duration,
) -> Result<ProcessOutput, String> {
    run_python_script_in_dir(runtime, script_name, args, timeout, &runtime.root.clone())
}

fn run_python_script_in_dir(
    runtime: &SearchRuntime,
    script_name: &str,
    args: &[String],
    timeout: Duration,
    working_dir: &Path,
) -> Result<ProcessOutput, String> {
    let python = runtime
        .python
        .as_ref()
        .ok_or_else(|| "python3 not available".to_string())?;
    let script_path = runtime.root.join(script_name);
    let mut command = Command::new(python);
    command
        .arg("-I")
        .arg("-X")
        .arg("utf8")
        .arg(script_path)
        .args(args)
        .current_dir(working_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    if let Ok(path) = std::env::var("PATH") {
        command.env("PATH", path);
    }
    if let Ok(home) = std::env::var("HOME") {
        command.env("HOME", home);
    }
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        command.env("TMPDIR", tmpdir);
    }
    command.env("PYTHONIOENCODING", "utf-8");

    let mut child = command
        .spawn()
        .map_err(|err| format!("launch {script_name}: {err}"))?;
    let stdout_handle = child.stdout.take().map(|mut handle| {
        thread::spawn(move || {
            let mut stdout = Vec::new();
            let _ = handle.read_to_end(&mut stdout);
            stdout
        })
    });
    let stderr_handle = child.stderr.take().map(|mut handle| {
        thread::spawn(move || {
            let mut stderr = Vec::new();
            let _ = handle.read_to_end(&mut stderr);
            stderr
        })
    });
    let deadline = Instant::now() + timeout;
    let mut backoff = Duration::from_millis(1);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("wait {script_name}: {err}"))?
        {
            let stdout = join_reader(stdout_handle);
            let stderr = join_reader(stderr_handle);
            return Ok(ProcessOutput {
                success: status.success(),
                stdout,
                stderr,
            });
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = join_reader(stdout_handle);
            let _ = join_reader(stderr_handle);
            return Err(format!("{script_name} timed out"));
        }
        thread::sleep(backoff);
        backoff = (backoff * 2).min(Duration::from_millis(50));
    }
}

fn join_reader(handle: Option<thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default()
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
    out = strip_double_brackets(&out);
    out = strip_external_links_to_labels(&out);
    out = out.replace("&#124;", "|");
    collapse_whitespace(&out)
}

fn strip_double_brackets(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'[' && bytes.get(idx + 1) == Some(&b'[') {
            let start = idx + 2;
            if let Some(end_rel) = text[start..].find("]]") {
                let inner = &text[start..start + end_rel];
                if let Some((_, label)) = inner.rsplit_once('|') {
                    out.push_str(label.trim());
                }
                idx = start + end_rel + 2;
                continue;
            }
        }
        out.push(bytes[idx] as char);
        idx += 1;
    }
    out
}

fn strip_external_links_to_labels(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'[' && bytes.get(idx + 1) != Some(&b'[') {
            let start = idx + 1;
            if let Some(end_rel) = text[start..].find(']') {
                let inner = text[start..start + end_rel].trim();
                if let Some((_, label)) = inner.split_once(' ') {
                    out.push_str(label.trim());
                }
                idx = start + end_rel + 1;
                continue;
            }
        }
        out.push(bytes[idx] as char);
        idx += 1;
    }
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

fn escape_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
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
        let mut json = String::new();
        append_catalog_entries_json(&mut json, &entries, &[]);
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
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
    }
}

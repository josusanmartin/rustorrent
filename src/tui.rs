//! Interactive terminal interface. It drives the same local web API as the
//! browser UI (see `remote.rs`), so both interfaces offer the same actions:
//! add, pause/resume, stop, verify, remove (optionally with files), labels,
//! file priorities and renames, trackers, global limits, seed ratio, peer
//! profile, search and RSS.

use crate::remote::{
    clip, file_line, fmt_eta, fmt_rate, info_lines, is_done, priority_name, progress, search_line,
    session_lines, state_label, Client, Json,
};
use std::fmt::Write as _;
use std::io::Write;
use std::time::{Duration, Instant};

const REFRESH: Duration = Duration::from_millis(1000);
const FILTERS: [&str; 7] = [
    "all",
    "active",
    "downloading",
    "seeding",
    "paused",
    "done",
    "error",
];
const VIEWS: [&str; 4] = ["Transfers", "Search", "RSS", "Session"];
const TABS: [&str; 3] = ["Info", "Files", "Trackers"];
const PROFILES: [&str; 3] = ["conservative", "balanced", "aggressive"];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Key {
    Char(char),
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
    Esc,
    Backspace,
    Tab,
    Delete,
}

/// A pending text prompt and what to do with its answer.
#[derive(Clone, Copy, PartialEq)]
enum Ask {
    Add,
    Filter,
    Label,
    Limits,
    Ratio,
    Rename,
    AddTracker,
    Search,
    AddFeed,
    AddRule,
}

/// A pending single-key confirmation.
#[derive(Clone, Copy, PartialEq)]
enum Confirm {
    Remove(u64),
    RemoveTracker,
    RemoveFeed,
    RemoveRule,
}

struct Tui {
    client: Client,
    status: Json,
    search: Json,
    rss: Json,
    view: usize,
    filter: usize,
    text_filter: String,
    selected: usize,
    scroll: usize,
    detail: bool,
    tab: usize,
    sub: usize,
    ask: Option<(Ask, String)>,
    confirm: Option<Confirm>,
    message: String,
    message_at: Instant,
    help: bool,
}

pub fn run(client: Client) -> Result<(), String> {
    // Dropping the guard restores the terminal, so it must live for the whole loop.
    #[cfg_attr(not(windows), allow(unused_variables))]
    let terminal = Terminal::enter()?;
    #[cfg(windows)]
    let mut input = console::KeyReader::new(terminal.input);
    let mut tui = Tui {
        client,
        status: Json::Null,
        search: Json::Null,
        rss: Json::Null,
        view: 0,
        filter: 0,
        text_filter: String::new(),
        selected: 0,
        scroll: 0,
        detail: false,
        tab: 0,
        sub: 0,
        ask: None,
        confirm: None,
        message: String::new(),
        message_at: Instant::now(),
        help: false,
    };
    let mut last_refresh: Option<Instant> = None;
    let mut last_frame = String::new();
    loop {
        if crate::shutdown_requested() {
            return Ok(());
        }
        if last_refresh.is_none_or(|at| at.elapsed() >= REFRESH) {
            tui.refresh();
            last_refresh = Some(Instant::now());
        }
        let frame = tui.render();
        if frame != last_frame {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(frame.as_bytes());
            let _ = out.flush();
            last_frame = frame;
        }
        #[cfg(windows)]
        let key = input.read_key();
        #[cfg(not(windows))]
        let key = read_key();
        if let Some(key) = key {
            match tui.handle(key) {
                Some(true) => return Ok(()),
                Some(false) => last_refresh = None,
                None => {}
            }
        }
    }
}

impl Tui {
    fn refresh(&mut self) {
        let result = self
            .client
            .status()
            .map(|s| self.status = s)
            .and_then(|_| match self.view {
                1 => self.client.get("/search/status").map(|s| self.search = s),
                2 => self.client.get("/rss/status").map(|s| self.rss = s),
                _ => Ok(()),
            });
        if let Err(err) = result {
            self.say(format!("connection: {err}"));
        }
    }

    fn say(&mut self, message: String) {
        self.message = message;
        self.message_at = Instant::now();
    }

    fn visible(&self) -> Vec<&Json> {
        let needle = self.text_filter.to_lowercase();
        self.status
            .arr("torrents")
            .iter()
            .filter(|t| {
                let state = state_label(t);
                let keep = match FILTERS[self.filter] {
                    "all" => true,
                    "active" => t.n("download_rate_bps") >= 1.0 || t.n("upload_rate_bps") >= 1.0,
                    "downloading" => {
                        matches!(state, "downloading" | "waiting" | "metadata" | "queued")
                    }
                    "paused" => matches!(state, "paused" | "stopped" | "stopping"),
                    "done" => is_done(t),
                    other => state == other,
                };
                keep && (needle.is_empty()
                    || t.s("name").to_lowercase().contains(&needle)
                    || t.s("label").to_lowercase().contains(&needle))
            })
            .collect()
    }

    fn current(&self) -> Option<Json> {
        self.visible().get(self.selected).map(|t| (*t).clone())
    }

    /// Number of rows in the list that currently has the cursor.
    fn rows(&self) -> usize {
        match self.view {
            0 if self.detail && self.tab == 1 => self.current().map_or(0, |t| t.arr("files").len()),
            0 if self.detail && self.tab == 2 => {
                self.current().map_or(0, |t| t.arr("trackers").len())
            }
            0 => self.visible().len(),
            1 => self.search.arr("results").len(),
            2 => self.rss.arr("feeds").len() + self.rss.arr("rules").len(),
            _ => 0,
        }
    }

    fn cursor(&mut self) -> &mut usize {
        if self.view == 0 && !(self.detail && self.tab > 0) {
            &mut self.selected
        } else {
            &mut self.sub
        }
    }

    fn act(&mut self, result: Result<Json, String>, done: &str) {
        match result {
            Ok(_) => self.say(done.to_string()),
            Err(err) => self.say(format!("error: {err}")),
        }
    }

    /// Returns Some(true) to quit, Some(false) to force a refresh.
    fn handle(&mut self, key: Key) -> Option<bool> {
        if let Some((ask, mut text)) = self.ask.take() {
            match key {
                Key::Enter => return self.answer(ask, text.trim().to_string()),
                Key::Esc => {
                    if ask == Ask::Filter {
                        self.text_filter.clear();
                    }
                }
                Key::Backspace => {
                    text.pop();
                    self.ask = Some((ask, text));
                }
                Key::Char(c) => {
                    text.push(c);
                    self.ask = Some((ask, text));
                }
                _ => self.ask = Some((ask, text)),
            }
            if let Some((Ask::Filter, text)) = &self.ask {
                self.text_filter = text.clone();
                self.selected = 0;
            }
            return None;
        }
        if let Some(confirm) = self.confirm.take() {
            return self.confirmed(confirm, key);
        }
        if self.help {
            self.help = false;
            return None;
        }
        let rows = self.rows();
        let page = 10;
        match key {
            Key::Char('q') | Key::Char('\u{3}') => return Some(true),
            Key::Char('?') => self.help = true,
            Key::Char(c @ '1'..='4') => {
                self.view = c as usize - '1' as usize;
                self.sub = 0;
                return Some(false);
            }
            Key::Up | Key::Char('k') => {
                let cur = self.cursor();
                *cur = cur.saturating_sub(1);
            }
            Key::Down | Key::Char('j') => {
                let cur = self.cursor();
                *cur = (*cur + 1).min(rows.saturating_sub(1));
            }
            Key::PageUp => {
                let cur = self.cursor();
                *cur = cur.saturating_sub(page);
            }
            Key::PageDown => {
                let cur = self.cursor();
                *cur = (*cur + page).min(rows.saturating_sub(1));
            }
            Key::Home | Key::Char('g') => *self.cursor() = 0,
            Key::End | Key::Char('G') => *self.cursor() = rows.saturating_sub(1),
            Key::Char('/') if self.view != 1 => {
                self.view = 0;
                self.ask = Some((Ask::Filter, self.text_filter.clone()));
            }
            Key::Char('a') if self.view == 0 && !(self.detail && self.tab == 2) => {
                self.ask = Some((Ask::Add, String::new()))
            }
            Key::Char('L') => self.ask = Some((Ask::Limits, String::new())),
            Key::Char('R') if self.view == 3 => self.ask = Some((Ask::Ratio, String::new())),
            Key::Char('P') if self.view == 3 => {
                let current = self.status.s("peer_profile");
                let next = PROFILES
                    .iter()
                    .position(|p| *p == current)
                    .map_or(1, |i| (i + 1) % PROFILES.len());
                let result = self
                    .client
                    .post("/settings/peer-profile", &[("profile", PROFILES[next])]);
                self.act(result, &format!("peer profile: {}", PROFILES[next]));
                return Some(false);
            }
            _ => {
                return match self.view {
                    0 => self.handle_transfers(key),
                    1 => self.handle_search(key),
                    2 => self.handle_rss(key),
                    _ => None,
                }
            }
        }
        None
    }

    fn handle_transfers(&mut self, key: Key) -> Option<bool> {
        if key == Key::Tab {
            self.filter = (self.filter + 1) % FILTERS.len();
            self.selected = 0;
            return Some(false);
        }
        let torrent = self.current()?;
        let id = torrent.u("id");
        let action = |tui: &mut Tui, name: &str| {
            let result = crate::remote::torrent_action(&tui.client, name, id, false);
            tui.act(
                result.map(|_| Json::Null),
                &format!("{name}: {}", torrent.s("name")),
            );
        };
        match key {
            Key::Enter => {
                self.detail = !self.detail;
                self.sub = 0;
            }
            Key::Esc => self.detail = false,
            Key::Right | Key::Char('l') if self.detail => {
                self.tab = (self.tab + 1) % TABS.len();
                self.sub = 0;
            }
            Key::Left | Key::Char('h') if self.detail => {
                self.tab = (self.tab + TABS.len() - 1) % TABS.len();
                self.sub = 0;
            }
            Key::Char(' ') | Key::Char('+') | Key::Char('-') if self.detail && self.tab == 1 => {
                let file = torrent.arr("files").get(self.sub)?;
                let current = file.u("priority").min(3);
                let next = match key {
                    Key::Char('-') => current.saturating_sub(1),
                    Key::Char('+') => (current + 1).min(3),
                    _ if current == 0 => 2,
                    _ => 0,
                };
                let (id, index, level) = (id.to_string(), self.sub.to_string(), next.to_string());
                let result = self.client.post(
                    "/file-priority",
                    &[("id", &id), ("index", &index), ("priority", &level)],
                );
                self.act(result, &format!("priority: {}", priority_name(next)));
            }
            Key::Char('n') if self.detail && self.tab == 1 => {
                self.ask = Some((Ask::Rename, String::new()))
            }
            Key::Char('a') if self.detail && self.tab == 2 => {
                self.ask = Some((Ask::AddTracker, String::new()))
            }
            Key::Char('d') | Key::Delete if self.detail && self.tab == 2 => {
                if self.sub < torrent.arr("trackers").len() {
                    self.confirm = Some(Confirm::RemoveTracker);
                }
            }
            Key::Char(' ') | Key::Char('p') => {
                let resume = matches!(state_label(&torrent), "paused" | "stopped" | "error");
                action(self, if resume { "resume" } else { "pause" });
            }
            Key::Char('s') => action(self, "stop"),
            Key::Char('v') => action(self, "recheck"),
            Key::Char('A') => action(self, "archive"),
            Key::Char('d') | Key::Delete => self.confirm = Some(Confirm::Remove(id)),
            Key::Char('b') => self.ask = Some((Ask::Label, torrent.s("label").to_string())),
            _ => return None,
        }
        Some(false)
    }

    fn handle_search(&mut self, key: Key) -> Option<bool> {
        match key {
            Key::Char('/') | Key::Char('s') => {
                let last = self.search.s("query").to_string();
                self.ask = Some((Ask::Search, last));
                None
            }
            Key::Enter | Key::Char('a') => {
                let result = self.search.arr("results").get(self.sub)?.clone();
                let index = result.u("index").to_string();
                let reply = self.client.post("/search/add-result", &[("index", &index)]);
                self.act(reply, &format!("added: {}", result.s("name")));
                Some(false)
            }
            _ => None,
        }
    }

    fn handle_rss(&mut self, key: Key) -> Option<bool> {
        let feeds = self.rss.arr("feeds").len();
        match key {
            Key::Char('a') => self.ask = Some((Ask::AddFeed, String::new())),
            Key::Char('r') => self.ask = Some((Ask::AddRule, String::new())),
            Key::Char('d') | Key::Delete if self.sub < self.rows() => {
                self.confirm = Some(if self.sub < feeds {
                    Confirm::RemoveFeed
                } else {
                    Confirm::RemoveRule
                });
            }
            _ => return None,
        }
        None
    }

    fn confirmed(&mut self, confirm: Confirm, key: Key) -> Option<bool> {
        let yes = matches!(key, Key::Char('y') | Key::Char('Y') | Key::Enter);
        let result = match (confirm, key) {
            (Confirm::Remove(id), Key::Char('k') | Key::Char('y') | Key::Enter) => {
                crate::remote::torrent_action(&self.client, "remove", id, false)
                    .map(|_| "removed; files kept")
            }
            (Confirm::Remove(id), Key::Char('D')) => {
                crate::remote::torrent_action(&self.client, "remove", id, true)
                    .map(|_| "removed with files")
            }
            (Confirm::RemoveTracker, _) if yes => {
                let torrent = self.current()?;
                let url = match torrent.arr("trackers").get(self.sub)? {
                    Json::Str(url) => url.clone(),
                    _ => return None,
                };
                let id = torrent.u("id").to_string();
                self.client
                    .post("/torrent/remove-tracker", &[("id", &id), ("url", &url)])
                    .map(|_| "tracker removed")
            }
            (Confirm::RemoveFeed, _) if yes => {
                let url = self.rss.arr("feeds").get(self.sub)?.s("url").to_string();
                self.client
                    .post("/rss/remove-feed", &[("url", &url)])
                    .map(|_| "feed removed")
            }
            (Confirm::RemoveRule, _) if yes => {
                let index = self.sub.checked_sub(self.rss.arr("feeds").len())?;
                let name = self.rss.arr("rules").get(index)?.s("name").to_string();
                self.client
                    .post("/rss/remove-rule", &[("name", &name)])
                    .map(|_| "rule removed")
            }
            _ => Ok("cancelled"),
        };
        match result {
            Ok(done) => self.say(done.to_string()),
            Err(err) => self.say(format!("error: {err}")),
        }
        Some(false)
    }

    fn answer(&mut self, ask: Ask, text: String) -> Option<bool> {
        if text.is_empty() && !matches!(ask, Ask::Filter | Ask::Label) {
            return None;
        }
        let id = self
            .current()
            .map(|t| t.u("id").to_string())
            .unwrap_or_default();
        let result: Result<String, String> = match ask {
            Ask::Filter => {
                self.text_filter = text;
                return None;
            }
            Ask::Add => {
                let path = expand_home(&text);
                crate::remote::add(&self.client, &path, "", false, "", false)
                    .map(|new_id| format!("added (id {new_id})"))
            }
            Ask::Label => self
                .client
                .post("/torrent/set-label", &[("id", &id), ("label", &text)])
                .map(|_| "label updated".into()),
            Ask::Limits => {
                let mut parts = text.split_whitespace();
                let down = parts.next().unwrap_or("0");
                let up = parts.next().unwrap_or(down);
                crate::remote::set_limits(&self.client, down, up)
                    .map(|_| format!("limits: ↓ {down} ↑ {up}"))
            }
            Ask::Ratio => self
                .client
                .post("/settings/seed-ratio", &[("ratio", &text)])
                .map(|_| format!("seed ratio: {text}")),
            Ask::Rename => {
                let index = self.sub.to_string();
                self.client
                    .post(
                        "/rename-file",
                        &[("id", &id), ("index", &index), ("name", &text)],
                    )
                    .map(|_| "file renamed".into())
            }
            Ask::AddTracker => self
                .client
                .post("/torrent/add-tracker", &[("id", &id), ("url", &text)])
                .map(|_| "tracker added".into()),
            Ask::Search => {
                self.sub = 0;
                self.client
                    .post("/search/run", &[("query", &text), ("category", "all")])
                    .map(|_| format!("searching for {text}…"))
            }
            Ask::AddFeed => self
                .client
                .post("/rss/add-feed", &[("url", &text)])
                .map(|_| "feed added".into()),
            Ask::AddRule => {
                let mut parts = text.splitn(3, ' ');
                let name = parts.next().unwrap_or("");
                let pattern = parts.next().unwrap_or("");
                let feed = parts.next().unwrap_or("");
                self.client
                    .post(
                        "/rss/add-rule",
                        &[("name", name), ("pattern", pattern), ("feed_url", feed)],
                    )
                    .map(|_| "rule added".into())
            }
        };
        match result {
            Ok(done) => self.say(done),
            Err(err) => self.say(format!("error: {err}")),
        }
        Some(false)
    }

    fn render(&mut self) -> String {
        let (rows, cols) = terminal_size();
        let mut screen = Screen {
            out: String::with_capacity(rows * cols * 2),
            cols,
            row: 0,
        };
        screen.out.push_str("\x1b[?25l");
        if rows < 6 || cols < 40 {
            screen.out.push_str("\x1b[H\x1b[2J terminal too small");
            return screen.out;
        }

        // Header: app name, views, global rates.
        let mut header = String::from(" \x1b[1mrustorrent\x1b[0m  ");
        for (i, view) in VIEWS.iter().enumerate() {
            if i == self.view {
                let _ = write!(header, "\x1b[7m {} {view} \x1b[0m ", i + 1);
            } else {
                let _ = write!(header, "\x1b[2m {} {view} \x1b[0m ", i + 1);
            }
        }
        let rates = format!(
            "\x1b[34m↓ {}\x1b[0m  \x1b[32m↑ {}\x1b[0m ",
            fmt_rate(self.status.n("download_rate_bps")),
            fmt_rate(self.status.n("upload_rate_bps"))
        );
        screen.split_line(&header, &rates);

        let body_rows = rows - 3;
        match self.view {
            0 => self.render_transfers(&mut screen, body_rows),
            1 => self.render_search(&mut screen, body_rows),
            2 => self.render_rss(&mut screen, body_rows),
            _ => {
                screen.line("");
                for line in session_lines(&self.status) {
                    screen.line(&format!("  {line}"));
                }
                screen.line("");
                screen.line("  \x1b[2mL\x1b[0m set limits   \x1b[2mR\x1b[0m seed ratio   \x1b[2mP\x1b[0m next peer profile");
            }
        }
        if self.help {
            screen.row = 1;
            for line in HELP {
                screen.line(&format!(
                    "\x1b[7m {:<width$}\x1b[0m",
                    line,
                    width = cols.min(64) - 2
                ));
            }
        }
        while screen.row < rows - 1 {
            screen.line("");
        }

        // Footer: prompt, confirmation, message or key hints.
        let footer = if let Some((ask, text)) = &self.ask {
            format!(" {}: {text}█", ask_label(*ask))
        } else if let Some(confirm) = self.confirm {
            match confirm {
                Confirm::Remove(_) => {
                    " Remove transfer? [k] keep files  [D] delete files  [Esc] cancel".into()
                }
                _ => " Remove selected item? [y] yes  [Esc] cancel".into(),
            }
        } else if !self.message.is_empty() && self.message_at.elapsed() < Duration::from_secs(5) {
            format!(" {}", self.message)
        } else {
            match self.view {
                0 if self.detail && self.tab == 1 => " ↑↓ file  space skip/get  +/- priority  n rename  ←→ tab  Esc close",
                0 if self.detail && self.tab == 2 => " ↑↓ tracker  a add  d remove  ←→ tab  Esc close",
                0 => " a add  space pause  s stop  v verify  d remove  b label  Enter details  Tab filter  / find  ? help  q quit",
                1 => " s search  ↑↓ select  Enter add  1-4 views  q quit",
                2 => " a add feed  r add rule  d remove  1-4 views  q quit",
                _ => " L limits  R ratio  P profile  1-4 views  q quit",
            }
            .to_string()
        };
        let _ = write!(screen.out, "\x1b[{rows};1H\x1b[7m");
        screen.pad(&footer);
        screen.out.push_str("\x1b[0m");
        if self.ask.is_some() {
            screen.out.push_str("\x1b[?25h");
        }
        screen.out
    }

    fn render_transfers(&mut self, screen: &mut Screen, body_rows: usize) {
        let detail_rows = if self.detail {
            (body_rows / 2).max(6)
        } else {
            0
        };
        let list_rows = body_rows.saturating_sub(detail_rows + 1);
        let count = self.visible().len();
        self.selected = self.selected.min(count.saturating_sub(1));
        if self.selected < self.scroll {
            self.scroll = self.selected;
        }
        if list_rows > 0 && self.selected >= self.scroll + list_rows {
            self.scroll = self.selected + 1 - list_rows;
        }
        if self.detail && self.tab > 0 {
            let len = self.current().map_or(0, |t| {
                t.arr(if self.tab == 1 { "files" } else { "trackers" })
                    .len()
            });
            self.sub = self.sub.min(len.saturating_sub(1));
        }
        let torrents = self.visible();
        let mut filters = String::from(" ");
        for (i, name) in FILTERS.iter().enumerate() {
            if i == self.filter {
                let _ = write!(filters, "\x1b[1;4m{name}\x1b[0m  ");
            } else {
                let _ = write!(filters, "\x1b[2m{name}\x1b[0m  ");
            }
        }
        if !self.text_filter.is_empty() {
            let _ = write!(filters, "“{}”", self.text_filter);
        }
        let total = self.status.arr("torrents").len();
        screen.split_line(&filters, &format!("\x1b[2m{count}/{total}\x1b[0m "));

        if count == 0 {
            screen.line("");
            screen.line(if total == 0 {
                "  No transfers yet. Press a to add a .torrent file or magnet link."
            } else {
                "  No transfers match this filter. Press Tab or / to change it."
            });
        }
        let cols = screen.cols;
        for (i, t) in torrents
            .iter()
            .enumerate()
            .skip(self.scroll)
            .take(list_rows)
        {
            let state = state_label(t);
            let color = state_color(state);
            let bar_width = (cols / 8).clamp(6, 20);
            let done = progress(t);
            let filled = (done * bar_width as f64).round() as usize;
            let rate = match state {
                "downloading" => format!("↓ {}", fmt_rate(t.n("download_rate_bps"))),
                "seeding" => format!("↑ {}", fmt_rate(t.n("upload_rate_bps"))),
                _ => String::new(),
            };
            let eta = if state == "downloading" {
                fmt_eta(t.u("eta_secs"))
            } else {
                String::new()
            };
            let right = format!(
                "{color}{}\x1b[0m\x1b[2m{}\x1b[0m {:>6.1}% {rate:<12} {color}{state:<11}\x1b[0m {eta:>7} ",
                "━".repeat(filled.min(bar_width)),
                "─".repeat(bar_width - filled.min(bar_width)),
                done * 100.0,
            );
            let name_width = cols.saturating_sub(visible_len(&right) + 4);
            let mut name = clip(t.s("name"), name_width);
            if !t.s("label").is_empty()
                && name.chars().count() + t.s("label").chars().count() + 3 < name_width
            {
                let _ = write!(name, " \x1b[2m[{}]\x1b[0m", t.s("label"));
            }
            let marker = if i == self.selected {
                "\x1b[1m▌\x1b[0m"
            } else {
                " "
            };
            let left = format!("{marker} {name}");
            if i == self.selected {
                screen.split_line(&format!("\x1b[1m{left}"), &right);
            } else {
                screen.split_line(&left, &right);
            }
        }
        while screen.row < 2 + list_rows {
            screen.line("");
        }
        if !self.detail {
            return;
        }
        let Some(t) = torrents.get(self.selected) else {
            return;
        };
        let mut tabs = String::from(" ");
        for (i, tab) in TABS.iter().enumerate() {
            if i == self.tab {
                let _ = write!(tabs, "\x1b[7m {tab} \x1b[0m ");
            } else {
                let _ = write!(tabs, "\x1b[2m {tab} \x1b[0m ");
            }
        }
        screen.split_line(
            &tabs,
            &format!("\x1b[2m{}\x1b[0m ", clip(t.s("name"), cols / 2)),
        );
        let lines: Vec<String> = match self.tab {
            0 => info_lines(t)
                .into_iter()
                .map(|l| format!("  {l}"))
                .collect(),
            1 => t
                .arr("files")
                .iter()
                .enumerate()
                .map(|(i, f)| file_line(i, f))
                .collect(),
            _ => t
                .arr("trackers")
                .iter()
                .map(|u| match u {
                    Json::Str(url) => format!("  {url}"),
                    _ => String::new(),
                })
                .collect(),
        };
        let room = detail_rows.saturating_sub(1);
        let start = if self.tab > 0 {
            (self.sub + 1).saturating_sub(room)
        } else {
            0
        };
        for (i, line) in lines.iter().enumerate().skip(start).take(room) {
            if self.tab > 0 && i == self.sub {
                screen.line(&format!("\x1b[7m{}", clip(line, cols)));
            } else {
                screen.line(line);
            }
        }
        if lines.is_empty() {
            screen.line("  \x1b[2mNothing to show yet.\x1b[0m");
        }
    }

    fn render_search(&mut self, screen: &mut Screen, body_rows: usize) {
        let s = &self.search;
        let summary = if s.b("busy") {
            format!(" Searching for “{}”…", s.s("query"))
        } else if !s.s("last_error").is_empty() {
            format!(" \x1b[31m{}\x1b[0m", s.s("last_error"))
        } else if !s.s("query").is_empty() {
            format!(" {} results for “{}”", s.arr("results").len(), s.s("query"))
        } else if s.b("loading") {
            " Loading search plugins…".to_string()
        } else if !s.b("python_available") {
            " Search plugins need Python 3.9 or newer.".to_string()
        } else {
            format!(
                " {} plugins installed. Press s to search.",
                s.arr("plugins").len()
            )
        };
        screen.line(&summary);
        let results = s.arr("results").to_vec();
        list(
            screen,
            &results.iter().map(search_line).collect::<Vec<_>>(),
            self.sub,
            body_rows - 1,
        );
    }

    fn render_rss(&mut self, screen: &mut Screen, body_rows: usize) {
        let mut lines = Vec::new();
        for f in self.rss.arr("feeds") {
            lines.push(format!(
                "  feed  {}  ({} items)  {}",
                f.s("url"),
                f.u("items"),
                f.s("title")
            ));
        }
        for r in self.rss.arr("rules") {
            lines.push(format!(
                "  rule  {}: {}  {}",
                r.s("name"),
                r.s("pattern"),
                r.s("feed_url")
            ));
        }
        screen.line(" Feeds are polled automatically; matching items are added.");
        if lines.is_empty() {
            screen.line("  No feeds yet. Press a to add one.");
        }
        list(screen, &lines, self.sub, body_rows - 1);
    }
}

const HELP: [&str; 14] = [
    "Keys",
    "  1-4        Transfers, Search, RSS, Session",
    "  ↑↓ j k     Move    PgUp/PgDn/g/G  Jump",
    "  a          Add a .torrent path or magnet link",
    "  space p    Pause or resume",
    "  s v A      Stop, verify, archive",
    "  d          Remove (choose to keep or delete files)",
    "  b          Set label",
    "  Enter      Details; ←→ Info/Files/Trackers",
    "  Tab /      Cycle state filter, find by name",
    "  L          Global rate limits (e.g. 5m 1m)",
    "  R P        Seed ratio, peer profile (Session)",
    "  q          Quit",
    "  Press any key to close",
];

fn ask_label(ask: Ask) -> &'static str {
    match ask {
        Ask::Add => "Add .torrent path or magnet",
        Ask::Filter => "Find",
        Ask::Label => "Label",
        Ask::Limits => "Limits ↓ ↑ (e.g. 5m 1m, 0 = unlimited)",
        Ask::Ratio => "Seed ratio (0 = unlimited)",
        Ask::Rename => "New file name",
        Ask::AddTracker => "Tracker URL",
        Ask::Search => "Search",
        Ask::AddFeed => "Feed URL",
        Ask::AddRule => "Rule: name pattern [feed-url]",
    }
}

fn state_color(state: &str) -> &'static str {
    match state {
        "downloading" => "\x1b[34m",
        "seeding" => "\x1b[32m",
        "error" => "\x1b[31m",
        "paused" | "stopped" | "stopping" => "\x1b[2m",
        _ => "\x1b[33m",
    }
}

fn expand_home(path: &str) -> String {
    match (path.strip_prefix("~/"), std::env::var("HOME")) {
        (Some(rest), Ok(home)) => format!("{home}/{rest}"),
        _ => path.to_string(),
    }
}

fn list(screen: &mut Screen, lines: &[String], selected: usize, rows: usize) {
    let start = (selected + 1).saturating_sub(rows);
    for (i, line) in lines.iter().enumerate().skip(start).take(rows) {
        if i == selected {
            screen.line(&format!("\x1b[7m{}", clip(line, screen.cols)));
        } else {
            screen.line(line);
        }
    }
}

struct Screen {
    out: String,
    cols: usize,
    row: usize,
}

impl Screen {
    /// Writes one full-width line, clipping or padding to the terminal width.
    fn line(&mut self, text: &str) {
        self.row += 1;
        let _ = write!(self.out, "\x1b[{};1H", self.row);
        self.pad(text);
        self.out.push_str("\x1b[0m");
    }

    fn pad(&mut self, text: &str) {
        let mut width = 0;
        let mut escape = false;
        for ch in text.chars() {
            if escape {
                escape = !ch.is_ascii_alphabetic();
            } else if ch == '\x1b' {
                escape = true;
            } else if width >= self.cols {
                continue;
            } else {
                width += 1;
            }
            self.out.push(ch);
        }
        for _ in width..self.cols {
            self.out.push(' ');
        }
    }

    fn split_line(&mut self, left: &str, right: &str) {
        let gap = self
            .cols
            .saturating_sub(visible_len(left) + visible_len(right));
        if gap == 0 {
            self.line(left);
        } else {
            self.line(&format!("{left}\x1b[0m{}{right}", " ".repeat(gap)));
        }
    }
}

fn visible_len(text: &str) -> usize {
    let mut len = 0;
    let mut escape = false;
    for ch in text.chars() {
        if escape {
            escape = !ch.is_ascii_alphabetic();
        } else if ch == '\x1b' {
            escape = true;
        } else {
            len += 1;
        }
    }
    len
}

// ---------------------------------------------------------------- terminal

#[cfg(unix)]
struct Terminal {
    original: libc::termios,
}

#[cfg(unix)]
impl Terminal {
    fn enter() -> Result<Terminal, String> {
        // SAFETY: termios is plain data; tcgetattr fills it for a valid fd.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::isatty(0) } != 1 || unsafe { libc::tcgetattr(0, &mut original) } != 0 {
            return Err("the terminal UI needs an interactive terminal".into());
        }
        let mut raw = original;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
        raw.c_iflag &= !(libc::IXON | libc::ICRNL);
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 2;
        // SAFETY: `raw` is a valid termios derived from the current settings.
        if unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw) } != 0 {
            return Err("could not switch the terminal to raw mode".into());
        }
        crate::TUI_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J");
        let _ = out.flush();
        Ok(Terminal { original })
    }
}

#[cfg(unix)]
impl Drop for Terminal {
    fn drop(&mut self) {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(b"\x1b[0m\x1b[?25h\x1b[?1049l");
        let _ = out.flush();
        // SAFETY: restores the settings captured in `enter`.
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &self.original) };
        crate::TUI_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(windows)]
struct Terminal {
    input: *mut std::ffi::c_void,
    output: *mut std::ffi::c_void,
    input_mode: u32,
    output_mode: u32,
    input_code_page: u32,
    output_code_page: u32,
}

#[cfg(windows)]
impl Terminal {
    fn enter() -> Result<Terminal, String> {
        let input = console::std_handle(console::STD_INPUT_HANDLE)
            .ok_or("the terminal UI needs an interactive terminal")?;
        let output = console::std_handle(console::STD_OUTPUT_HANDLE)
            .ok_or("the terminal UI needs an interactive terminal")?;
        let input_mode =
            console::mode(input).ok_or("the terminal UI needs an interactive terminal")?;
        let output_mode =
            console::mode(output).ok_or("the terminal UI needs an interactive terminal")?;
        let raw_input = console::ENABLE_EXTENDED_FLAGS;
        let raw_output = output_mode
            | console::ENABLE_PROCESSED_OUTPUT
            | console::ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if !console::set_mode(input, raw_input) || !console::set_mode(output, raw_output) {
            let _ = console::set_mode(input, input_mode);
            let _ = console::set_mode(output, output_mode);
            return Err("could not switch the terminal to raw mode".into());
        }
        let input_code_page = console::input_code_page();
        let output_code_page = console::output_code_page();
        let _ = console::set_input_code_page(console::UTF8_CODE_PAGE);
        let _ = console::set_output_code_page(console::UTF8_CODE_PAGE);
        crate::TUI_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J");
        let _ = out.flush();
        Ok(Terminal {
            input,
            output,
            input_mode,
            output_mode,
            input_code_page,
            output_code_page,
        })
    }
}

#[cfg(windows)]
impl Drop for Terminal {
    fn drop(&mut self) {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(b"\x1b[0m\x1b[?25h\x1b[?1049l");
        let _ = out.flush();
        let _ = console::set_mode(self.input, self.input_mode);
        let _ = console::set_mode(self.output, self.output_mode);
        let _ = console::set_input_code_page(self.input_code_page);
        let _ = console::set_output_code_page(self.output_code_page);
        crate::TUI_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(not(any(unix, windows)))]
struct Terminal;

#[cfg(not(any(unix, windows)))]
impl Terminal {
    fn enter() -> Result<Terminal, String> {
        Err("the terminal UI needs an interactive terminal".into())
    }
}

#[cfg(unix)]
fn terminal_size() -> (usize, usize) {
    // SAFETY: winsize is plain data filled by TIOCGWINSZ on a valid fd.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        (ws.ws_row as usize, ws.ws_col as usize)
    } else {
        (24, 80)
    }
}

#[cfg(windows)]
fn terminal_size() -> (usize, usize) {
    let Some(output) = console::std_handle(console::STD_OUTPUT_HANDLE) else {
        return (24, 80);
    };
    console::window_size(output).unwrap_or((24, 80))
}

#[cfg(not(any(unix, windows)))]
fn terminal_size() -> (usize, usize) {
    (24, 80)
}

#[cfg(unix)]
fn read_byte() -> Option<u8> {
    let mut byte = 0u8;
    // SAFETY: reads at most one byte into a valid local buffer.
    let n = unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) };
    (n == 1).then_some(byte)
}

#[cfg(not(any(unix, windows)))]
fn read_byte() -> Option<u8> {
    None
}

#[cfg(windows)]
mod console {
    use std::ffi::c_void;

    pub(super) const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
    pub(super) const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
    pub(super) const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
    pub(super) const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;
    pub(super) const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    pub(super) const UTF8_CODE_PAGE: u32 = 65001;
    const WAIT_OBJECT_0: u32 = 0;
    const READ_TIMEOUT_MS: u32 = 200;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetStdHandle(kind: u32) -> *mut c_void;
        fn GetConsoleMode(handle: *mut c_void, mode: *mut u32) -> i32;
        fn SetConsoleMode(handle: *mut c_void, mode: u32) -> i32;
        fn GetConsoleScreenBufferInfo(handle: *mut c_void, info: *mut ScreenBufferInfo) -> i32;
        fn ReadConsoleInputW(
            handle: *mut c_void,
            buffer: *mut InputRecord,
            length: u32,
            read: *mut u32,
        ) -> i32;
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn GetConsoleCP() -> u32;
        fn GetConsoleOutputCP() -> u32;
        fn SetConsoleCP(code_page: u32) -> i32;
        fn SetConsoleOutputCP(code_page: u32) -> i32;
    }

    #[repr(C)]
    struct Coord {
        x: i16,
        y: i16,
    }

    #[repr(C)]
    struct SmallRect {
        left: i16,
        top: i16,
        right: i16,
        bottom: i16,
    }

    #[repr(C)]
    struct ScreenBufferInfo {
        _size: Coord,
        _cursor: Coord,
        _attributes: u16,
        window: SmallRect,
        _maximum: Coord,
    }

    pub(super) fn std_handle(kind: u32) -> Option<*mut c_void> {
        // SAFETY: the standard-handle identifiers are the documented constants.
        let handle = unsafe { GetStdHandle(kind) };
        if handle.is_null() || handle == usize::MAX as *mut c_void {
            None
        } else {
            Some(handle)
        }
    }

    pub(super) fn mode(handle: *mut c_void) -> Option<u32> {
        let mut mode = 0u32;
        // SAFETY: `handle` is a live console handle from `std_handle`.
        let ok = unsafe { GetConsoleMode(handle, &mut mode) };
        (ok != 0).then_some(mode)
    }

    pub(super) fn set_mode(handle: *mut c_void, mode: u32) -> bool {
        // SAFETY: `handle` is a live console handle and `mode` is a flag word.
        unsafe { SetConsoleMode(handle, mode) != 0 }
    }

    pub(super) fn input_code_page() -> u32 {
        // SAFETY: the call has no pointer arguments.
        unsafe { GetConsoleCP() }
    }

    pub(super) fn output_code_page() -> u32 {
        // SAFETY: the call has no pointer arguments.
        unsafe { GetConsoleOutputCP() }
    }

    pub(super) fn set_input_code_page(code_page: u32) -> bool {
        // SAFETY: a code page identifier is a plain integer.
        unsafe { SetConsoleCP(code_page) != 0 }
    }

    pub(super) fn set_output_code_page(code_page: u32) -> bool {
        // SAFETY: a code page identifier is a plain integer.
        unsafe { SetConsoleOutputCP(code_page) != 0 }
    }

    pub(super) fn window_size(handle: *mut c_void) -> Option<(usize, usize)> {
        let mut info = ScreenBufferInfo {
            _size: Coord { x: 0, y: 0 },
            _cursor: Coord { x: 0, y: 0 },
            _attributes: 0,
            window: SmallRect {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            },
            _maximum: Coord { x: 0, y: 0 },
        };
        // SAFETY: `info` matches the console screen-buffer structure.
        if unsafe { GetConsoleScreenBufferInfo(handle, &mut info) } == 0 {
            return None;
        }
        let rows = i32::from(info.window.bottom) - i32::from(info.window.top) + 1;
        let cols = i32::from(info.window.right) - i32::from(info.window.left) + 1;
        (rows > 0 && cols > 0).then_some((rows as usize, cols as usize))
    }

    /// Maps one console key event. `key_down` is the Windows BOOL, and
    /// `control` is `dwControlKeyState`.
    pub(super) fn key_from_event(
        key_down: i32,
        virtual_key: u16,
        unicode: u16,
        control: u32,
    ) -> Option<super::Key> {
        if key_down == 0 || matches!(virtual_key, 0x10..=0x12) {
            return None;
        }
        match virtual_key {
            0x26 => return Some(super::Key::Up),
            0x28 => return Some(super::Key::Down),
            0x25 => return Some(super::Key::Left),
            0x27 => return Some(super::Key::Right),
            0x21 => return Some(super::Key::PageUp),
            0x22 => return Some(super::Key::PageDown),
            0x24 => return Some(super::Key::Home),
            0x23 => return Some(super::Key::End),
            0x0D => return Some(super::Key::Enter),
            0x1B => return Some(super::Key::Esc),
            0x08 => return Some(super::Key::Backspace),
            0x09 => return Some(super::Key::Tab),
            0x2E => return Some(super::Key::Delete),
            _ => {}
        }
        // Ctrl+C arrives as C with a control modifier when processed input is off.
        const CTRL_PRESSED: u32 = 0x0004 | 0x0008;
        const ALT_PRESSED: u32 = 0x0001 | 0x0002;
        if virtual_key == u16::from(b'C')
            && (control & CTRL_PRESSED) != 0
            && (control & ALT_PRESSED) == 0
        {
            return Some(super::Key::Char('\u{3}'));
        }
        char::from_u32(u32::from(unicode))
            .filter(|ch| !ch.is_control() || *ch == '\u{3}')
            .map(super::Key::Char)
    }

    pub(super) struct KeyReader {
        input: *mut c_void,
        high_surrogate: Option<u16>,
        repeated: Option<(super::Key, u16)>,
    }

    impl KeyReader {
        /// `input` is the console input handle whose mode `Terminal` set.
        pub(super) fn new(input: *mut c_void) -> KeyReader {
            KeyReader {
                input,
                high_surrogate: None,
                repeated: None,
            }
        }

        fn take_repeated(&mut self) -> Option<super::Key> {
            let (key, remaining) = self.repeated.take()?;
            if remaining > 1 {
                self.repeated = Some((key, remaining - 1));
            }
            Some(key)
        }

        fn decode_event(&mut self, event: &KeyEvent) -> Option<super::Key> {
            if event.key_down == 0 || matches!(event.virtual_key, 0x10..=0x12) {
                return None;
            }
            let key = match event.unicode {
                0xD800..=0xDBFF => {
                    self.high_surrogate = Some(event.unicode);
                    return None;
                }
                0xDC00..=0xDFFF => {
                    let high = self.high_surrogate.take()?;
                    let scalar = 0x10000
                        + ((u32::from(high) - 0xD800) << 10)
                        + (u32::from(event.unicode) - 0xDC00);
                    char::from_u32(scalar).map(super::Key::Char)
                }
                _ => {
                    self.high_surrogate = None;
                    key_from_event(
                        event.key_down,
                        event.virtual_key,
                        event.unicode,
                        event.control,
                    )
                }
            }?;
            if event.repeat > 1 {
                self.repeated = Some((key, event.repeat - 1));
            }
            Some(key)
        }

        pub(super) fn read_key(&mut self) -> Option<super::Key> {
            if let Some(key) = self.take_repeated() {
                return Some(key);
            }
            let deadline = std::time::Instant::now()
                + std::time::Duration::from_millis(u64::from(READ_TIMEOUT_MS));
            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return None;
                }
                let wait_ms = u32::try_from(remaining.as_millis()).unwrap_or(READ_TIMEOUT_MS);
                // SAFETY: a console input handle can be waited on for the next event.
                let waited = unsafe { WaitForSingleObject(self.input, wait_ms) };
                if waited != WAIT_OBJECT_0 {
                    if waited == u32::MAX {
                        std::thread::sleep(std::time::Duration::from_millis(u64::from(
                            READ_TIMEOUT_MS,
                        )));
                    }
                    return None;
                }
                let mut record = InputRecord::default();
                let mut read = 0u32;
                // SAFETY: `record` is a complete input record and `read` receives the count.
                let ok = unsafe { ReadConsoleInputW(self.input, &mut record, 1, &mut read) };
                if ok == 0 || read == 0 {
                    return None;
                }
                if record.event_type == KEY_EVENT {
                    if let Some(key) = self.decode_event(&record.key) {
                        return Some(key);
                    }
                }
            }
        }
    }

    const KEY_EVENT: u16 = 0x0001;

    #[repr(C)]
    struct KeyEvent {
        key_down: i32,
        repeat: u16,
        virtual_key: u16,
        _scan: u16,
        unicode: u16,
        control: u32,
    }

    #[repr(C)]
    struct InputRecord {
        event_type: u16,
        _pad: u16,
        key: KeyEvent,
    }

    impl Default for InputRecord {
        fn default() -> Self {
            Self {
                event_type: 0,
                _pad: 0,
                key: KeyEvent {
                    key_down: 0,
                    repeat: 0,
                    virtual_key: 0,
                    _scan: 0,
                    unicode: 0,
                    control: 0,
                },
            }
        }
    }

    #[cfg(test)]
    #[test]
    fn input_record_matches_the_windows_layout() {
        assert_eq!(std::mem::size_of::<InputRecord>(), 20);
        assert_eq!(std::mem::align_of::<InputRecord>(), 4);
        assert_eq!(std::mem::offset_of!(InputRecord, key), 4);
        assert_eq!(std::mem::offset_of!(KeyEvent, unicode), 10);
        assert_eq!(std::mem::offset_of!(KeyEvent, control), 12);
    }

    #[cfg(test)]
    #[test]
    fn console_reader_preserves_repeats_and_surrogate_pairs() {
        let mut reader = KeyReader::new(std::ptr::null_mut());
        let mut event = InputRecord::default().key;
        event.key_down = 1;
        event.virtual_key = 0x26;
        event.repeat = 3;
        assert_eq!(reader.decode_event(&event), Some(super::Key::Up));
        assert_eq!(reader.take_repeated(), Some(super::Key::Up));
        assert_eq!(reader.take_repeated(), Some(super::Key::Up));
        assert_eq!(reader.take_repeated(), None);

        event.virtual_key = 0;
        event.repeat = 1;
        event.unicode = 0xD83D;
        assert_eq!(reader.decode_event(&event), None);
        event.key_down = 0;
        assert_eq!(reader.decode_event(&event), None);
        event.key_down = 1;
        event.unicode = 0xDE00;
        assert_eq!(
            reader.decode_event(&event),
            Some(super::Key::Char('\u{1F600}'))
        );
        assert_eq!(reader.decode_event(&event), None);

        event.unicode = 0xD83D;
        assert_eq!(reader.decode_event(&event), None);
        event.unicode = u16::from(b'a');
        assert_eq!(reader.decode_event(&event), Some(super::Key::Char('a')));
        event.unicode = 0xDE00;
        assert_eq!(reader.decode_event(&event), None);
    }
}

/// Reads one key press (waiting up to 200 ms), decoding escape sequences
/// and UTF-8 input.
#[cfg(not(windows))]
fn read_key() -> Option<Key> {
    let first = read_byte()?;
    Some(match first {
        b'\r' | b'\n' => Key::Enter,
        b'\t' => Key::Tab,
        0x7f | 0x08 => Key::Backspace,
        0x1b => {
            let Some(b'[' | b'O') = read_byte() else {
                return Some(Key::Esc);
            };
            let mut seq = Vec::new();
            while let Some(b) = read_byte() {
                seq.push(b);
                if b.is_ascii_alphabetic() || b == b'~' || seq.len() > 6 {
                    break;
                }
            }
            match seq.as_slice() {
                b"A" => Key::Up,
                b"B" => Key::Down,
                b"C" => Key::Right,
                b"D" => Key::Left,
                b"H" | b"1~" | b"7~" => Key::Home,
                b"F" | b"4~" | b"8~" => Key::End,
                b"5~" => Key::PageUp,
                b"6~" => Key::PageDown,
                b"3~" => Key::Delete,
                _ => return None,
            }
        }
        b if b < 0x80 => Key::Char(b as char),
        b => {
            let len = if b >= 0xF0 {
                4
            } else if b >= 0xE0 {
                3
            } else {
                2
            };
            let mut bytes = vec![b];
            for _ in 1..len {
                bytes.push(read_byte()?);
            }
            Key::Char(std::str::from_utf8(&bytes).ok()?.chars().next()?)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screen_pads_and_clips_ignoring_escapes() {
        let mut screen = Screen {
            out: String::new(),
            cols: 5,
            row: 0,
        };
        screen.pad("\x1b[1mabcdefg\x1b[0m");
        assert_eq!(screen.out, "\x1b[1mabcde\x1b[0m");
        assert_eq!(visible_len("\x1b[31m↓ 1\x1b[0m"), 3);
    }

    #[cfg(windows)]
    #[test]
    fn console_events_map_to_terminal_keys() {
        assert_eq!(console::key_from_event(1, 0x26, 0, 0), Some(Key::Up));
        assert_eq!(console::key_from_event(1, 0x0D, 13, 0), Some(Key::Enter));
        assert_eq!(console::key_from_event(1, 0x08, 8, 0), Some(Key::Backspace));
        assert_eq!(
            console::key_from_event(1, u16::from(b'C'), 3, 0x0008),
            Some(Key::Char('\u{3}'))
        );
        assert_eq!(
            console::key_from_event(1, u16::from(b'Q'), u16::from(b'q'), 0),
            Some(Key::Char('q'))
        );
        assert_eq!(console::key_from_event(0, 0x26, 0, 0), None);
        assert_eq!(console::key_from_event(1, 0x10, 0, 0), None);
        // AltGr is reported as Ctrl+Alt; typing a character must not exit the UI.
        assert_eq!(
            console::key_from_event(1, u16::from(b'C'), 0x0107, 0x0009),
            Some(Key::Char('\u{107}'))
        );
    }
}

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bencode::{self, Value};
use crate::xml;

#[derive(Debug, Clone)]
pub struct FeedItem {
    pub title: String,
    pub link: String,
    pub is_torrent: bool,
    pub guid: String,
}

#[derive(Debug, Clone)]
pub struct RssFeed {
    pub url: String,
    pub title: String,
    pub items: Vec<FeedItem>,
    pub last_poll: u64,
    pub poll_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct RssRule {
    pub name: String,
    pub feed_url: String,
    pub pattern: String,
}

pub struct RssState {
    pub feeds: Vec<RssFeed>,
    pub rules: Vec<RssRule>,
    pub seen_guids: Vec<String>,
}

impl RssState {
    pub fn new() -> Self {
        Self {
            feeds: Vec::new(),
            rules: Vec::new(),
            seen_guids: Vec::new(),
        }
    }
}

pub fn parse_feed(data: &[u8]) -> Result<(String, Vec<FeedItem>), String> {
    let root = xml::parse(data).ok_or_else(|| "invalid xml".to_string())?;
    match root.tag.as_str() {
        "rss" => parse_rss(&root),
        "feed" => parse_atom(&root),
        _ => Err(format!("unknown feed root tag: {}", root.tag)),
    }
}

fn parse_rss(root: &xml::XmlNode) -> Result<(String, Vec<FeedItem>), String> {
    let channel = root.child("channel").ok_or("missing <channel>")?;
    let title = channel
        .child("title")
        .map(|n| n.text.clone())
        .unwrap_or_default();
    let mut items = Vec::new();
    for item_node in channel.children_by_tag("item") {
        let item_title = item_node
            .child("title")
            .map(|n| n.text.clone())
            .unwrap_or_default();
        let link = item_node
            .child("link")
            .map(|n| n.text.clone())
            .unwrap_or_default();
        let guid = item_node
            .child("guid")
            .map(|n| n.text.clone())
            .unwrap_or_default();
        let enclosure_url = item_node
            .child("enclosure")
            .and_then(|n| n.attr("url"))
            .unwrap_or("");
        let enclosure_type = item_node
            .child("enclosure")
            .and_then(|n| n.attr("type"))
            .unwrap_or("");
        let (final_link, is_torrent) = if !enclosure_url.is_empty()
            && (enclosure_type.contains("torrent") || enclosure_url.ends_with(".torrent"))
        {
            (enclosure_url.to_string(), true)
        } else if link.ends_with(".torrent") {
            (link, true)
        } else {
            (link, false)
        };
        items.push(FeedItem {
            title: item_title,
            link: final_link.clone(),
            is_torrent,
            guid: if guid.is_empty() { final_link } else { guid },
        });
    }
    Ok((title, items))
}

fn parse_atom(root: &xml::XmlNode) -> Result<(String, Vec<FeedItem>), String> {
    let title = root
        .child("title")
        .map(|n| n.text.clone())
        .unwrap_or_default();
    let mut items = Vec::new();
    for entry in root.children_by_tag("entry") {
        let entry_title = entry
            .child("title")
            .map(|n| n.text.clone())
            .unwrap_or_default();
        let id = entry
            .child("id")
            .map(|n| n.text.clone())
            .unwrap_or_default();
        let link = entry
            .child("link")
            .and_then(|n| n.attr("href"))
            .unwrap_or("")
            .to_string();
        let is_torrent = link.ends_with(".torrent");
        items.push(FeedItem {
            title: entry_title,
            link: link.clone(),
            is_torrent,
            guid: if id.is_empty() { link } else { id },
        });
    }
    Ok((title, items))
}

pub fn match_rules<'a>(
    items: &'a [FeedItem],
    rules: &'a [RssRule],
    seen: &[String],
    feed_url: &str,
) -> Vec<(&'a FeedItem, &'a RssRule)> {
    let mut matches = Vec::new();
    for item in items {
        if seen.contains(&item.guid) {
            continue;
        }
        if !item.is_torrent {
            continue;
        }
        for rule in rules {
            if !rule.feed_url.is_empty() && rule.feed_url != feed_url {
                continue;
            }
            if glob_match(&rule.pattern, &item.title) {
                matches.push((item, rule));
                break;
            }
        }
    }
    matches
}

fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    let text_lower = text.to_ascii_lowercase();
    for alt in pattern.split('|') {
        let alt = alt.trim().to_ascii_lowercase();
        if alt.is_empty() {
            continue;
        }
        if glob_match_single(&alt, &text_lower) {
            return true;
        }
    }
    false
}

fn glob_match_single(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return text.contains(pattern);
    }
    let mut pos = 0;
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = text[pos..].find(part) {
            if idx == 0 && found != 0 {
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }
    if let Some(last) = parts.last() {
        if !last.is_empty() && !text.ends_with(last) {
            return false;
        }
    }
    true
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn save_rss_state(path: &Path, state: &RssState) -> Result<(), String> {
    let feeds_list: Vec<Value> = state
        .feeds
        .iter()
        .map(|feed| {
            Value::Dict(vec![
                (b"url".to_vec(), Value::Bytes(feed.url.as_bytes().to_vec())),
                (
                    b"title".to_vec(),
                    Value::Bytes(feed.title.as_bytes().to_vec()),
                ),
                (b"last_poll".to_vec(), Value::Int(feed.last_poll as i64)),
                (
                    b"poll_interval".to_vec(),
                    Value::Int(feed.poll_interval_secs as i64),
                ),
            ])
        })
        .collect();
    let rules_list: Vec<Value> = state
        .rules
        .iter()
        .map(|rule| {
            Value::Dict(vec![
                (
                    b"name".to_vec(),
                    Value::Bytes(rule.name.as_bytes().to_vec()),
                ),
                (
                    b"feed_url".to_vec(),
                    Value::Bytes(rule.feed_url.as_bytes().to_vec()),
                ),
                (
                    b"pattern".to_vec(),
                    Value::Bytes(rule.pattern.as_bytes().to_vec()),
                ),
            ])
        })
        .collect();
    let seen_list: Vec<Value> = state
        .seen_guids
        .iter()
        .map(|guid| Value::Bytes(guid.as_bytes().to_vec()))
        .collect();
    let dict = Value::Dict(vec![
        (b"feeds".to_vec(), Value::List(feeds_list)),
        (b"rules".to_vec(), Value::List(rules_list)),
        (b"seen".to_vec(), Value::List(seen_list)),
    ]);
    let data = bencode::encode(&dict);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| format!("rss save dir: {err}"))?;
    }
    std::fs::write(path, data).map_err(|err| format!("rss save: {err}"))
}

pub fn load_rss_state(path: &Path) -> Result<RssState, String> {
    let data = std::fs::read(path).map_err(|err| format!("rss load: {err}"))?;
    let value = bencode::parse(&data).map_err(|err| format!("rss parse: {err}"))?;
    let dict = match value {
        Value::Dict(items) => items,
        _ => return Err("rss state not a dict".to_string()),
    };
    let mut state = RssState::new();
    if let Some(Value::List(feeds)) = dict_get(&dict, b"feeds") {
        for item in feeds {
            if let Value::Dict(fd) = item {
                let url = dict_get_str(fd, b"url").unwrap_or_default();
                let title = dict_get_str(fd, b"title").unwrap_or_default();
                let last_poll = dict_get_int(fd, b"last_poll").unwrap_or(0) as u64;
                let poll_interval = dict_get_int(fd, b"poll_interval").unwrap_or(900) as u64;
                state.feeds.push(RssFeed {
                    url,
                    title,
                    items: Vec::new(),
                    last_poll,
                    poll_interval_secs: poll_interval,
                });
            }
        }
    }
    if let Some(Value::List(rules)) = dict_get(&dict, b"rules") {
        for item in rules {
            if let Value::Dict(rd) = item {
                let name = dict_get_str(rd, b"name").unwrap_or_default();
                let feed_url = dict_get_str(rd, b"feed_url").unwrap_or_default();
                let pattern = dict_get_str(rd, b"pattern").unwrap_or_default();
                state.rules.push(RssRule {
                    name,
                    feed_url,
                    pattern,
                });
            }
        }
    }
    if let Some(Value::List(seen)) = dict_get(&dict, b"seen") {
        for item in seen {
            if let Value::Bytes(bytes) = item {
                if let Ok(s) = String::from_utf8(bytes.clone()) {
                    state.seen_guids.push(s);
                }
            }
        }
    }
    Ok(state)
}

fn dict_get<'a>(dict: &'a [(Vec<u8>, Value)], key: &[u8]) -> Option<&'a Value> {
    dict.iter()
        .find(|(k, _)| k.as_slice() == key)
        .map(|(_, v)| v)
}

fn dict_get_str(dict: &[(Vec<u8>, Value)], key: &[u8]) -> Option<String> {
    match dict_get(dict, key) {
        Some(Value::Bytes(bytes)) => String::from_utf8(bytes.clone()).ok(),
        _ => None,
    }
}

fn dict_get_int(dict: &[(Vec<u8>, Value)], key: &[u8]) -> Option<i64> {
    match dict_get(dict, key) {
        Some(Value::Int(n)) => Some(*n),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_file(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rustorrent-rss-{name}-{nanos}.benc"))
    }

    #[test]
    fn parse_rss_feed() {
        let xml = br#"<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>Ubuntu ISO</title>
      <link>http://example.com/ubuntu.torrent</link>
      <guid>guid-001</guid>
    </item>
    <item>
      <title>Debian ISO</title>
      <enclosure url="http://example.com/debian.torrent" type="application/x-bittorrent"/>
      <guid>guid-002</guid>
    </item>
  </channel>
</rss>"#;
        let (title, items) = parse_feed(xml).unwrap();
        assert_eq!(title, "Test Feed");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Ubuntu ISO");
        assert!(items[0].is_torrent);
        assert_eq!(items[1].link, "http://example.com/debian.torrent");
        assert!(items[1].is_torrent);
    }

    #[test]
    fn parse_atom_feed() {
        let xml = br#"<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Feed</title>
  <entry>
    <title>Item One</title>
    <id>urn:uuid:001</id>
    <link href="http://example.com/1.torrent"/>
  </entry>
</feed>"#;
        let (title, items) = parse_feed(xml).unwrap();
        assert_eq!(title, "Atom Feed");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Item One");
        assert!(items[0].is_torrent);
        assert_eq!(items[0].guid, "urn:uuid:001");
    }

    #[test]
    fn glob_match_patterns() {
        assert!(glob_match("*ubuntu*", "Ubuntu 24.04 LTS"));
        assert!(glob_match("debian*", "debian-12.iso"));
        assert!(!glob_match("debian*", "Ubuntu 24.04"));
        assert!(glob_match("ubuntu|debian", "My Debian ISO"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("", "anything"));
    }

    #[test]
    fn match_rules_filters_seen_and_non_torrent() {
        let items = vec![
            FeedItem {
                title: "Ubuntu ISO".to_string(),
                link: "http://example.com/ubuntu.torrent".to_string(),
                is_torrent: true,
                guid: "guid-1".to_string(),
            },
            FeedItem {
                title: "Debian ISO".to_string(),
                link: "http://example.com/debian.torrent".to_string(),
                is_torrent: true,
                guid: "guid-2".to_string(),
            },
            FeedItem {
                title: "News article".to_string(),
                link: "http://example.com/news".to_string(),
                is_torrent: false,
                guid: "guid-3".to_string(),
            },
        ];
        let rules = vec![RssRule {
            name: "linux".to_string(),
            feed_url: String::new(),
            pattern: "*".to_string(),
        }];
        let seen = vec!["guid-1".to_string()];
        let matches = match_rules(&items, &rules, &seen, "http://feed");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0.title, "Debian ISO");
    }

    #[test]
    fn rss_state_save_load_roundtrip() {
        let path = temp_file("state");
        let mut state = RssState::new();
        state.feeds.push(RssFeed {
            url: "http://example.com/rss".to_string(),
            title: "Test".to_string(),
            items: Vec::new(),
            last_poll: 12345,
            poll_interval_secs: 900,
        });
        state.rules.push(RssRule {
            name: "linux".to_string(),
            feed_url: String::new(),
            pattern: "*ubuntu*".to_string(),
        });
        state.seen_guids.push("guid-001".to_string());

        save_rss_state(&path, &state).unwrap();
        let loaded = load_rss_state(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert_eq!(loaded.feeds.len(), 1);
        assert_eq!(loaded.feeds[0].url, "http://example.com/rss");
        assert_eq!(loaded.feeds[0].last_poll, 12345);
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules[0].pattern, "*ubuntu*");
        assert_eq!(loaded.seen_guids, vec!["guid-001"]);
    }

    #[test]
    fn rss_state_save_creates_parent_directory() {
        let path = temp_file("nested");
        let nested = path
            .parent()
            .unwrap()
            .join("rss-state-nested")
            .join("state.benc");
        let _ = fs::remove_dir_all(nested.parent().unwrap());
        let state = RssState::new();
        save_rss_state(&nested, &state).unwrap();
        assert!(nested.exists());
        let _ = fs::remove_file(&nested);
        let _ = fs::remove_dir_all(nested.parent().unwrap());
    }
}

pub struct XmlNode {
    pub tag: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    pub fn child(&self, tag: &str) -> Option<&XmlNode> {
        self.children.iter().find(|c| c.tag == tag)
    }

    pub fn children_by_tag(&self, tag: &str) -> Vec<&XmlNode> {
        self.children.iter().filter(|c| c.tag == tag).collect()
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub fn parse(data: &[u8]) -> Option<XmlNode> {
    let text = std::str::from_utf8(data).ok()?;
    let mut pos = 0;
    skip_prolog(text, &mut pos);
    parse_element(text, &mut pos)
}

fn skip_prolog(text: &str, pos: &mut usize) {
    loop {
        skip_whitespace(text, pos);
        if text[*pos..].starts_with("<?") {
            if let Some(end) = text[*pos..].find("?>") {
                *pos += end + 2;
                continue;
            }
        }
        if text[*pos..].starts_with("<!DOCTYPE") || text[*pos..].starts_with("<!doctype") {
            if let Some(end) = text[*pos..].find('>') {
                *pos += end + 1;
                continue;
            }
        }
        if text[*pos..].starts_with("<!--") {
            if let Some(end) = text[*pos..].find("-->") {
                *pos += end + 3;
                continue;
            }
        }
        break;
    }
}

fn skip_whitespace(text: &str, pos: &mut usize) {
    while *pos < text.len() && text.as_bytes()[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

fn skip_comment(text: &str, pos: &mut usize) -> bool {
    if text[*pos..].starts_with("<!--") {
        if let Some(end) = text[*pos..].find("-->") {
            *pos += end + 3;
            return true;
        }
    }
    false
}

fn parse_element(text: &str, pos: &mut usize) -> Option<XmlNode> {
    skip_whitespace(text, pos);
    while skip_comment(text, pos) {
        skip_whitespace(text, pos);
    }
    if *pos >= text.len() || text.as_bytes()[*pos] != b'<' {
        return None;
    }
    *pos += 1;
    if *pos < text.len() && (text.as_bytes()[*pos] == b'/' || text.as_bytes()[*pos] == b'!') {
        return None;
    }

    let tag_start = *pos;
    while *pos < text.len() {
        let ch = text.as_bytes()[*pos];
        if ch.is_ascii_whitespace() || ch == b'>' || ch == b'/' {
            break;
        }
        *pos += 1;
    }
    let tag = text[tag_start..*pos].to_string();
    if tag.is_empty() {
        return None;
    }

    let mut attrs = Vec::new();
    loop {
        skip_whitespace(text, pos);
        if *pos >= text.len() {
            return None;
        }
        if text.as_bytes()[*pos] == b'/' {
            *pos += 1;
            if *pos < text.len() && text.as_bytes()[*pos] == b'>' {
                *pos += 1;
            }
            return Some(XmlNode {
                tag,
                attrs,
                text: String::new(),
                children: Vec::new(),
            });
        }
        if text.as_bytes()[*pos] == b'>' {
            *pos += 1;
            break;
        }
        if let Some((key, value)) = parse_attribute(text, pos) {
            attrs.push((key, value));
        } else {
            *pos += 1;
        }
    }

    let mut children = Vec::new();
    let mut text_buf = String::new();

    loop {
        if *pos >= text.len() {
            break;
        }

        if text[*pos..].starts_with("<![CDATA[") {
            *pos += 9;
            if let Some(end) = text[*pos..].find("]]>") {
                text_buf.push_str(&text[*pos..*pos + end]);
                *pos += end + 3;
            }
            continue;
        }

        if skip_comment(text, pos) {
            continue;
        }

        if text[*pos..].starts_with("</") {
            if let Some(end) = text[*pos..].find('>') {
                *pos += end + 1;
            }
            break;
        }

        if text.as_bytes()[*pos] == b'<' {
            if let Some(child) = parse_element(text, pos) {
                children.push(child);
            } else {
                break;
            }
        } else {
            text_buf.push(text.as_bytes()[*pos] as char);
            *pos += 1;
        }
    }

    let decoded_text = decode_entities(&text_buf);

    Some(XmlNode {
        tag,
        attrs,
        text: decoded_text,
        children,
    })
}

fn parse_attribute(text: &str, pos: &mut usize) -> Option<(String, String)> {
    let key_start = *pos;
    while *pos < text.len() {
        let ch = text.as_bytes()[*pos];
        if ch == b'=' || ch.is_ascii_whitespace() || ch == b'>' || ch == b'/' {
            break;
        }
        *pos += 1;
    }
    let key = text[key_start..*pos].to_string();
    if key.is_empty() {
        return None;
    }
    skip_whitespace(text, pos);
    if *pos >= text.len() || text.as_bytes()[*pos] != b'=' {
        return Some((key, String::new()));
    }
    *pos += 1;
    skip_whitespace(text, pos);
    if *pos >= text.len() {
        return Some((key, String::new()));
    }
    let quote = text.as_bytes()[*pos];
    if quote == b'"' || quote == b'\'' {
        *pos += 1;
        let val_start = *pos;
        while *pos < text.len() && text.as_bytes()[*pos] != quote {
            *pos += 1;
        }
        let value = decode_entities(&text[val_start..*pos]);
        if *pos < text.len() {
            *pos += 1;
        }
        Some((key, value))
    } else {
        let val_start = *pos;
        while *pos < text.len()
            && !text.as_bytes()[*pos].is_ascii_whitespace()
            && text.as_bytes()[*pos] != b'>'
        {
            *pos += 1;
        }
        Some((key, text[val_start..*pos].to_string()))
    }
}

fn decode_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '&' {
            let mut entity = String::new();
            for ec in chars.by_ref() {
                if ec == ';' {
                    break;
                }
                entity.push(ec);
                if entity.len() > 10 {
                    out.push('&');
                    out.push_str(&entity);
                    entity.clear();
                    break;
                }
            }
            if entity.is_empty() {
                continue;
            }
            match entity.as_str() {
                "amp" => out.push('&'),
                "lt" => out.push('<'),
                "gt" => out.push('>'),
                "quot" => out.push('"'),
                "apos" => out.push('\''),
                _ if entity.starts_with('#') => {
                    let code = if entity.starts_with("#x") || entity.starts_with("#X") {
                        u32::from_str_radix(&entity[2..], 16).ok()
                    } else {
                        entity[1..].parse::<u32>().ok()
                    };
                    if let Some(c) = code.and_then(char::from_u32) {
                        out.push(c);
                    } else {
                        out.push('&');
                        out.push_str(&entity);
                        out.push(';');
                    }
                }
                _ => {
                    out.push('&');
                    out.push_str(&entity);
                    out.push(';');
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_element() {
        let xml = b"<root><child>hello</child></root>";
        let node = parse(xml).unwrap();
        assert_eq!(node.tag, "root");
        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children[0].tag, "child");
        assert_eq!(node.children[0].text, "hello");
    }

    #[test]
    fn parse_attributes() {
        let xml = b"<item url=\"https://example.com\" type='text/html'/>";
        let node = parse(xml).unwrap();
        assert_eq!(node.tag, "item");
        assert_eq!(node.attr("url"), Some("https://example.com"));
        assert_eq!(node.attr("type"), Some("text/html"));
        assert!(node.children.is_empty());
    }

    #[test]
    fn parse_cdata_section() {
        let xml = b"<data><![CDATA[<not>xml</not>]]></data>";
        let node = parse(xml).unwrap();
        assert_eq!(node.text, "<not>xml</not>");
    }

    #[test]
    fn decode_xml_entities() {
        assert_eq!(decode_entities("&amp;&lt;&gt;&quot;&apos;"), "&<>\"'");
        assert_eq!(decode_entities("&#65;&#x42;"), "AB");
    }

    #[test]
    fn parse_with_prolog_and_comments() {
        let xml = b"<?xml version=\"1.0\"?><!-- comment --><root>text</root>";
        let node = parse(xml).unwrap();
        assert_eq!(node.tag, "root");
        assert_eq!(node.text, "text");
    }

    #[test]
    fn child_and_children_by_tag() {
        let xml = b"<root><a>1</a><b>2</b><a>3</a></root>";
        let node = parse(xml).unwrap();
        assert_eq!(node.child("b").unwrap().text, "2");
        let a_nodes = node.children_by_tag("a");
        assert_eq!(a_nodes.len(), 2);
        assert_eq!(a_nodes[0].text, "1");
        assert_eq!(a_nodes[1].text, "3");
    }

    #[test]
    fn parse_rss_fragment() {
        let xml = br#"<?xml version="1.0"?>
<rss version="2.0">
  <channel>
    <title>Test Feed</title>
    <item>
      <title>Episode 1</title>
      <link>http://example.com/1</link>
      <guid>guid-001</guid>
      <enclosure url="http://example.com/1.torrent" type="application/x-bittorrent"/>
    </item>
  </channel>
</rss>"#;
        let root = parse(xml).unwrap();
        assert_eq!(root.tag, "rss");
        let channel = root.child("channel").unwrap();
        assert_eq!(channel.child("title").unwrap().text, "Test Feed");
        let item = channel.child("item").unwrap();
        assert_eq!(item.child("title").unwrap().text, "Episode 1");
        let enc = item.child("enclosure").unwrap();
        assert_eq!(enc.attr("url"), Some("http://example.com/1.torrent"));
    }
}

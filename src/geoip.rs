use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

pub struct GeoIpDb {
    entries: Vec<(u32, u32, [u8; 2])>,
}

impl GeoIpDb {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|err| format!("geoip load: {err}"))?;
        let mut entries = Vec::new();
        for (line_no, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.split_once('#').map(|(left, _)| left).unwrap_or(line);
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match parse_entry(line) {
                Some(entry) => entries.push(entry),
                None => {
                    return Err(format!("geoip line {}: invalid entry", line_no + 1));
                }
            }
        }
        entries.sort_by_key(|(start, _, _)| *start);
        Ok(GeoIpDb { entries })
    }

    pub fn lookup(&self, addr: IpAddr) -> Option<&str> {
        let ip_u32 = match addr {
            IpAddr::V4(ip) => u32::from(ip),
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                if segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
                    u32::from(Ipv4Addr::new(
                        (segments[6] >> 8) as u8,
                        segments[6] as u8,
                        (segments[7] >> 8) as u8,
                        segments[7] as u8,
                    ))
                } else {
                    return None;
                }
            }
        };
        let idx = self
            .entries
            .partition_point(|(start, _, _)| *start <= ip_u32);
        if idx == 0 {
            return None;
        }
        let (_, end, cc) = &self.entries[idx - 1];
        if ip_u32 <= *end {
            Some(std::str::from_utf8(cc).unwrap_or("??"))
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

fn parse_entry(line: &str) -> Option<(u32, u32, [u8; 2])> {
    let parts: Vec<&str> = line.splitn(3, ',').collect();
    if parts.len() < 3 {
        return None;
    }
    let cc_str = parts[2].trim();
    if cc_str.len() != 2 {
        return None;
    }
    let cc = [cc_str.as_bytes()[0], cc_str.as_bytes()[1]];

    let first = parts[0].trim();
    let second = parts[1].trim();

    if let Some(slash) = first.find('/') {
        let ip_str = &first[..slash];
        let prefix: u8 = first[slash + 1..].parse().ok()?;
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        let value = u32::from(ip);
        let mask = if prefix == 0 {
            0u32
        } else {
            (!0u32) << (32 - prefix)
        };
        let start = value & mask;
        let end = start | (!mask);
        Some((start, end, cc))
    } else {
        let start_ip: Ipv4Addr = first.parse().ok()?;
        let end_ip: Ipv4Addr = second.parse().ok()?;
        let start = u32::from(start_ip);
        let end = u32::from(end_ip);
        Some((start.min(end), start.max(end), cc))
    }
}

pub fn country_flag(cc: &str) -> String {
    if cc.len() != 2 {
        return String::new();
    }
    let bytes = cc.as_bytes();
    let a = bytes[0].to_ascii_uppercase();
    let b = bytes[1].to_ascii_uppercase();
    if !(b'A'..=b'Z').contains(&a) || !(b'A'..=b'Z').contains(&b) {
        return String::new();
    }
    let c1 = char::from_u32(0x1F1E6 + (a - b'A') as u32).unwrap_or('?');
    let c2 = char::from_u32(0x1F1E6 + (b - b'A') as u32).unwrap_or('?');
    format!("{c1}{c2}")
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
        std::env::temp_dir().join(format!("rustorrent-geoip-{name}-{nanos}.csv"))
    }

    #[test]
    fn lookup_returns_country_code() {
        let path = temp_file("basic");
        fs::write(
            &path,
            "# GeoIP test data\n\
             1.0.0.0,1.0.0.255,AU\n\
             8.8.8.0,8.8.8.255,US\n\
             192.168.0.0,192.168.255.255,XX\n",
        )
        .unwrap();
        let db = GeoIpDb::load(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert_eq!(db.lookup("1.0.0.1".parse().unwrap()), Some("AU"));
        assert_eq!(db.lookup("8.8.8.8".parse().unwrap()), Some("US"));
        assert_eq!(db.lookup("192.168.1.1".parse().unwrap()), Some("XX"));
        assert_eq!(db.lookup("10.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn lookup_supports_cidr_notation() {
        let path = temp_file("cidr");
        fs::write(&path, "10.0.0.0/8,,JP\n").unwrap();
        let db = GeoIpDb::load(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert_eq!(db.lookup("10.1.2.3".parse().unwrap()), Some("JP"));
        assert_eq!(db.lookup("11.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn lookup_handles_ipv6_mapped_ipv4() {
        let path = temp_file("v6mapped");
        fs::write(&path, "1.0.0.0,1.0.0.255,AU\n").unwrap();
        let db = GeoIpDb::load(&path).unwrap();
        let _ = fs::remove_file(&path);
        let v6: IpAddr = "::ffff:1.0.0.1".parse().unwrap();
        assert_eq!(db.lookup(v6), Some("AU"));
    }

    #[test]
    fn lookup_returns_none_for_pure_ipv6() {
        let path = temp_file("purev6");
        fs::write(&path, "1.0.0.0,1.0.0.255,AU\n").unwrap();
        let db = GeoIpDb::load(&path).unwrap();
        let _ = fs::remove_file(&path);
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(db.lookup(v6), None);
    }

    #[test]
    fn country_flag_generates_unicode_indicators() {
        assert_eq!(country_flag("US"), "\u{1F1FA}\u{1F1F8}");
        assert_eq!(country_flag("JP"), "\u{1F1EF}\u{1F1F5}");
        assert_eq!(country_flag("X"), "");
    }

    #[test]
    fn rejects_invalid_entries() {
        let path = temp_file("invalid");
        fs::write(&path, "not,valid\n").unwrap();
        assert!(GeoIpDb::load(&path).is_err());
        let _ = fs::remove_file(&path);
    }
}

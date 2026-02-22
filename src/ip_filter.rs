use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::{fs, str::FromStr};

#[derive(Default, Clone)]
pub struct IpFilter {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl IpFilter {
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let text =
            fs::read_to_string(path).map_err(|err| format!("failed to read blocklist: {err}"))?;
        let mut filter = Self::default();
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
            if let Err(err) = filter.add_rule(line) {
                return Err(format!("blocklist line {}: {}", line_no + 1, err));
            }
        }
        Ok(filter)
    }

    pub fn is_blocked(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(ip) => {
                let value = u32::from(ip);
                self.v4
                    .iter()
                    .any(|(start, end)| value >= *start && value <= *end)
            }
            IpAddr::V6(ip) => {
                let value = u128::from(ip);
                self.v6
                    .iter()
                    .any(|(start, end)| value >= *start && value <= *end)
            }
        }
    }

    fn add_rule(&mut self, rule: &str) -> Result<(), String> {
        if let Some((start, end)) = rule.split_once('-') {
            let start = start.trim();
            let end = end.trim();
            let start_ip = IpAddr::from_str(start).map_err(|_| "invalid start ip".to_string())?;
            let end_ip = IpAddr::from_str(end).map_err(|_| "invalid end ip".to_string())?;
            match (start_ip, end_ip) {
                (IpAddr::V4(start), IpAddr::V4(end)) => {
                    let (s, e) = normalize_v4_range(start, end);
                    self.v4.push((s, e));
                    Ok(())
                }
                (IpAddr::V6(start), IpAddr::V6(end)) => {
                    let (s, e) = normalize_v6_range(start, end);
                    self.v6.push((s, e));
                    Ok(())
                }
                _ => Err("mixed ip versions".to_string()),
            }
        } else if let Some((base, prefix)) = rule.split_once('/') {
            let base_ip =
                IpAddr::from_str(base.trim()).map_err(|_| "invalid cidr ip".to_string())?;
            let prefix = prefix
                .trim()
                .parse::<u8>()
                .map_err(|_| "invalid cidr prefix".to_string())?;
            match base_ip {
                IpAddr::V4(ip) => {
                    let (start, end) = cidr_v4(ip, prefix)?;
                    self.v4.push((start, end));
                    Ok(())
                }
                IpAddr::V6(ip) => {
                    let (start, end) = cidr_v6(ip, prefix)?;
                    self.v6.push((start, end));
                    Ok(())
                }
            }
        } else {
            let ip = IpAddr::from_str(rule.trim()).map_err(|_| "invalid ip".to_string())?;
            match ip {
                IpAddr::V4(ip) => {
                    let value = u32::from(ip);
                    self.v4.push((value, value));
                }
                IpAddr::V6(ip) => {
                    let value = u128::from(ip);
                    self.v6.push((value, value));
                }
            }
            Ok(())
        }
    }
}

fn normalize_v4_range(start: Ipv4Addr, end: Ipv4Addr) -> (u32, u32) {
    let mut s = u32::from(start);
    let mut e = u32::from(end);
    if s > e {
        std::mem::swap(&mut s, &mut e);
    }
    (s, e)
}

fn normalize_v6_range(start: Ipv6Addr, end: Ipv6Addr) -> (u128, u128) {
    let mut s = u128::from(start);
    let mut e = u128::from(end);
    if s > e {
        std::mem::swap(&mut s, &mut e);
    }
    (s, e)
}

fn cidr_v4(ip: Ipv4Addr, prefix: u8) -> Result<(u32, u32), String> {
    if prefix > 32 {
        return Err("cidr prefix out of range".to_string());
    }
    let value = u32::from(ip);
    let mask = if prefix == 0 {
        0u32
    } else {
        (!0u32) << (32 - prefix)
    };
    let start = value & mask;
    let end = start | (!mask);
    Ok((start, end))
}

fn cidr_v6(ip: Ipv6Addr, prefix: u8) -> Result<(u128, u128), String> {
    if prefix > 128 {
        return Err("cidr prefix out of range".to_string());
    }
    let value = u128::from(ip);
    let mask = if prefix == 0 {
        0u128
    } else {
        (!0u128) << (128 - prefix)
    };
    let start = value & mask;
    let end = start | (!mask);
    Ok((start, end))
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
        std::env::temp_dir().join(format!("rustorrent-ipfilter-{name}-{nanos}.txt"))
    }

    #[test]
    fn supports_single_range_and_cidr_rules() {
        let mut filter = IpFilter::default();
        filter.add_rule("10.0.0.1").unwrap();
        filter.add_rule("10.0.0.10 - 10.0.0.4").unwrap();
        filter.add_rule("192.168.1.0/24").unwrap();
        filter.add_rule("2001:db8::/32").unwrap();

        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))));
        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))));
        assert!(filter.is_blocked(IpAddr::V6("2001:db8::1".parse().unwrap())));
        assert!(!filter.is_blocked(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    }

    #[test]
    fn cidr_prefix_bounds_are_validated() {
        assert!(cidr_v4(Ipv4Addr::new(1, 2, 3, 4), 32).is_ok());
        assert!(cidr_v4(Ipv4Addr::new(1, 2, 3, 4), 33).is_err());
        assert!(cidr_v6("2001:db8::1".parse().unwrap(), 128).is_ok());
        assert!(cidr_v6("2001:db8::1".parse().unwrap(), 129).is_err());
    }

    #[test]
    fn from_file_ignores_comments_and_inline_comments() {
        let path = temp_file("comments");
        fs::write(
            &path,
            "\
# top comment
10.0.0.0/8
192.0.2.1 # inline comment

2001:db8::/32
",
        )
        .unwrap();

        let filter = IpFilter::from_file(&path).unwrap();
        let _ = fs::remove_file(&path);
        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10))));
        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(filter.is_blocked(IpAddr::V6("2001:db8::1234".parse().unwrap())));
    }

    #[test]
    fn from_file_reports_line_numbers_for_errors() {
        let path = temp_file("line-number");
        fs::write(&path, "10.0.0.1\nnot-an-ip\n").unwrap();
        let err = match IpFilter::from_file(&path) {
            Ok(_) => panic!("expected parse failure"),
            Err(err) => err,
        };
        let _ = fs::remove_file(&path);
        assert!(err.contains("line 2"));
    }
}

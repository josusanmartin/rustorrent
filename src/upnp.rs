use std::net::UdpSocket;
use std::time::Duration;

use crate::http;

const SSDP_ADDR: &str = "239.255.255.250:1900";
const SSDP_TIMEOUT: Duration = Duration::from_secs(2);

pub fn map_port(port: u16) -> Result<(), String> {
    let location = discover_gateway().ok_or_else(|| "upnp gateway not found".to_string())?;
    let description = http::get(&location, 512 * 1024)?;
    let control_url = parse_control_url(&description, &location)
        .ok_or_else(|| "upnp control url not found".to_string())?;

    let body = build_add_port_mapping(port);
    let headers = vec![
        ("Content-Type", "text/xml; charset=\"utf-8\"".to_string()),
        (
            "SOAPAction",
            "\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"".to_string(),
        ),
    ];
    let _ = http::post(&control_url, &headers, body.as_bytes(), 128 * 1024)?;
    Ok(())
}

fn discover_gateway() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = socket.set_read_timeout(Some(SSDP_TIMEOUT));
    let msg = "\
M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 2\r\n\
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
\r\n";
    let _ = socket.send_to(msg.as_bytes(), SSDP_ADDR);
    let mut buf = [0u8; 2048];
    if let Ok((n, _)) = socket.recv_from(&mut buf) {
        let text = String::from_utf8_lossy(&buf[..n]);
        for line in text.lines() {
            if let Some(value) = line.trim().strip_prefix("LOCATION:") {
                return Some(value.trim().to_string());
            }
            if let Some(value) = line.trim().strip_prefix("Location:") {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

fn parse_control_url(xml: &[u8], base: &str) -> Option<String> {
    let text = String::from_utf8_lossy(xml);
    let mut service_start = None;
    for (idx, line) in text.lines().enumerate() {
        if line.contains("WANIPConnection") || line.contains("WANPPPConnection") {
            service_start = Some(idx);
            break;
        }
    }
    let start = service_start?;
    let mut control = None;
    for line in text.lines().skip(start) {
        if let Some(url) = extract_tag(line, "controlURL") {
            control = Some(url.to_string());
            break;
        }
        if line.contains("</service>") {
            break;
        }
    }
    let control = control?;
    if control.starts_with("http://") || control.starts_with("https://") {
        return Some(control);
    }
    let base = base.trim_end_matches('/');
    Some(format!("{base}{control}"))
}

fn extract_tag<'a>(line: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = line.find(&open)? + open.len();
    let end = line[start..].find(&close)? + start;
    Some(line[start..end].trim())
}

fn build_add_port_mapping(port: u16) -> String {
    format!(
        "<?xml version=\"1.0\"?>\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body>\
<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
<NewRemoteHost></NewRemoteHost>\
<NewExternalPort>{port}</NewExternalPort>\
<NewProtocol>TCP</NewProtocol>\
<NewInternalPort>{port}</NewInternalPort>\
<NewInternalClient>{}</NewInternalClient>\
<NewEnabled>1</NewEnabled>\
<NewPortMappingDescription>rustorrent</NewPortMappingDescription>\
<NewLeaseDuration>0</NewLeaseDuration>\
</u:AddPortMapping>\
</s:Body>\
</s:Envelope>",
        local_ip().unwrap_or_else(|| "0.0.0.0".to_string())
    )
}

fn local_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    let _ = socket.connect("8.8.8.8:53");
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tag_reads_inner_text() {
        let line = "  <controlURL>/upnp/control/WANIPConn1</controlURL> ";
        assert_eq!(
            extract_tag(line, "controlURL"),
            Some("/upnp/control/WANIPConn1")
        );
        assert_eq!(extract_tag(line, "serviceType"), None);
    }

    #[test]
    fn parse_control_url_supports_relative_and_absolute_urls() {
        let relative = b"
<service>
  <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
  <controlURL>/upnp/control/WANIPConn1</controlURL>
</service>";
        assert_eq!(
            parse_control_url(relative, "http://router.local"),
            Some("http://router.local/upnp/control/WANIPConn1".to_string())
        );

        let absolute = b"
<service>
  <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
  <controlURL>http://router.local/control</controlURL>
</service>";
        assert_eq!(
            parse_control_url(absolute, "http://ignored"),
            Some("http://router.local/control".to_string())
        );
    }

    #[test]
    fn parse_control_url_returns_none_when_service_missing() {
        let xml = b"<root><serviceType>urn:schemas-upnp-org:service:Other:1</serviceType></root>";
        assert_eq!(parse_control_url(xml, "http://router.local"), None);
    }

    #[test]
    fn add_port_mapping_body_contains_requested_port() {
        let body = build_add_port_mapping(51413);
        assert!(body.contains("<NewExternalPort>51413</NewExternalPort>"));
        assert!(body.contains("<NewInternalPort>51413</NewInternalPort>"));
        assert!(body.contains("AddPortMapping"));
    }
}

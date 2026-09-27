use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use crate::http;

const SSDP_ADDR: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
const SSDP_ATTEMPTS: usize = 3;
const SSDP_TIMEOUT: Duration = Duration::from_secs(1);

pub fn map_port(port: u16) -> Result<crate::PortMapping, String> {
    let location = discover_gateway()
        .ok_or_else(|| "gateway did not answer UPnP discovery after 3 attempts".to_string())?;
    map_port_at(&location, port, None)
}

/// Maps the port on the router in front of ours: `client` is our router's
/// address on that outer network, where the outer router must forward to.
pub fn map_port_upstream(
    gateway: Ipv4Addr,
    client: Ipv4Addr,
    port: u16,
) -> Result<crate::PortMapping, String> {
    // Multicast discovery does not cross our router, so ask the gateway directly.
    let location = discover_gateway_at(SocketAddrV4::new(gateway, 1900), 2, SSDP_TIMEOUT)
        .ok_or_else(|| format!("{gateway} did not answer UPnP discovery"))?;
    map_port_at(&location, port, Some(client))
}

fn map_port_at(
    location: &str,
    port: u16,
    client: Option<Ipv4Addr>,
) -> Result<crate::PortMapping, String> {
    let location = location.to_string();
    let description = http::get_same_origin(&location, 512 * 1024)?;
    let control = parse_control_url(&description, &location)
        .ok_or_else(|| "upnp control url not found".to_string())?;
    let gateway =
        http::url_host_ip(&control.url).ok_or_else(|| "invalid gateway address".to_string())?;
    let client = match client {
        Some(client) => client.to_string(),
        None => local_ip(gateway).ok_or_else(|| "no local route to the gateway".to_string())?,
    };

    for protocol in ["TCP", "UDP"] {
        // A timed lease is renewed below; some routers only take permanent ones.
        let mut result = add_port_mapping(&control, port, protocol, &client, LEASE_SECS);
        if result.as_ref().is_err_and(|err| err == "upnp error 725") {
            result = add_port_mapping(&control, port, protocol, &client, 0);
        }
        result.map_err(|err| match err.as_str() {
            "upnp error 718" => format!(
                "the router already forwards port {port} to another device; \
                 choose a different incoming port"
            ),
            _ => err,
        })?;
    }
    Ok(crate::PortMapping {
        renew_after: Duration::from_secs(u64::from(LEASE_SECS) / 2),
        external_port: port,
        external_ip: external_ip(&control),
    })
}

const LEASE_SECS: u32 = 3600;

fn soap(control: &ControlEndpoint, action: &str, arguments: &str) -> Result<Vec<u8>, String> {
    let body = format!(
        "<?xml version=\"1.0\"?>\
<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
<s:Body><u:{action} xmlns:u=\"{}\">{arguments}</u:{action}></s:Body></s:Envelope>",
        control.service_type
    );
    let headers = vec![
        ("Content-Type", "text/xml; charset=\"utf-8\"".to_string()),
        (
            "SOAPAction",
            format!("\"{}#{action}\"", control.service_type),
        ),
    ];
    http::post(&control.url, &headers, body.as_bytes(), 128 * 1024)
}

fn add_port_mapping(
    control: &ControlEndpoint,
    port: u16,
    protocol: &str,
    client: &str,
    lease: u32,
) -> Result<(), String> {
    soap(
        control,
        "AddPortMapping",
        &add_port_mapping_arguments(port, protocol, client, lease),
    )
    .map(drop)
}

fn external_ip(control: &ControlEndpoint) -> Option<Ipv4Addr> {
    let body = soap(control, "GetExternalIPAddress", "").ok()?;
    let text = std::str::from_utf8(&body).ok()?;
    let (_, rest) = text.split_once("NewExternalIPAddress>")?;
    rest.split('<').next()?.trim().parse().ok()
}

fn discover_gateway() -> Option<String> {
    discover_gateway_at(SSDP_ADDR, SSDP_ATTEMPTS, SSDP_TIMEOUT)
}

fn discover_gateway_at(
    discovery_addr: SocketAddrV4,
    attempts: usize,
    timeout: Duration,
) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    for _ in 0..attempts {
        // Newer routers only answer searches for version 2 of the device.
        let mut sent = false;
        for version in [1, 2] {
            let msg = format!(
                "M-SEARCH * HTTP/1.1\r\n\
HOST: {discovery_addr}\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 1\r\n\
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:{version}\r\n\
\r\n"
            );
            sent |= socket.send_to(msg.as_bytes(), discovery_addr).is_ok();
        }
        if !sent {
            continue;
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if socket.set_read_timeout(Some(remaining)).is_err() {
                return None;
            }
            let mut buf = [0u8; 2048];
            match socket.recv_from(&mut buf) {
                Ok((n, source)) => {
                    if let Some(location) = ssdp_location(&buf[..n], source.ip()) {
                        return Some(location);
                    }
                }
                Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    break;
                }
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return None,
            }
        }
    }
    None
}

fn ssdp_location(response: &[u8], source_ip: IpAddr) -> Option<String> {
    let text = std::str::from_utf8(response).ok()?;
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("location") {
            let value = value.trim();
            if (value.starts_with("http://") || value.starts_with("https://"))
                && !value.bytes().any(|byte| byte.is_ascii_control())
                && http::url_host_ip(value) == Some(source_ip)
            {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
struct ControlEndpoint {
    url: String,
    service_type: String,
}

fn parse_control_url(xml: &[u8], base: &str) -> Option<ControlEndpoint> {
    fn local_name(tag: &str) -> &str {
        tag.rsplit(':').next().unwrap_or(tag)
    }

    fn find_service(node: &crate::xml::XmlNode) -> Option<(&str, &str)> {
        if local_name(&node.tag) == "service" {
            let service_type = node
                .children
                .iter()
                .find(|child| local_name(&child.tag) == "serviceType")?
                .text
                .trim();
            if matches!(
                service_type,
                "urn:schemas-upnp-org:service:WANIPConnection:1"
                    | "urn:schemas-upnp-org:service:WANIPConnection:2"
                    | "urn:schemas-upnp-org:service:WANPPPConnection:1"
            ) {
                let control = node
                    .children
                    .iter()
                    .find(|child| local_name(&child.tag) == "controlURL")?
                    .text
                    .trim();
                return Some((service_type, control));
            }
        }
        node.children.iter().find_map(find_service)
    }

    let root = crate::xml::parse(xml)?;
    let (service_type, control) = find_service(&root)?;
    let url = http::resolve_url(base, control).ok()?;
    if !http::same_origin(&url, base) {
        return None;
    }
    Some(ControlEndpoint {
        url,
        service_type: service_type.to_string(),
    })
}

fn add_port_mapping_arguments(port: u16, protocol: &str, client: &str, lease: u32) -> String {
    format!(
        "<NewRemoteHost></NewRemoteHost>\
<NewExternalPort>{port}</NewExternalPort>\
<NewProtocol>{protocol}</NewProtocol>\
<NewInternalPort>{port}</NewInternalPort>\
<NewInternalClient>{client}</NewInternalClient>\
<NewEnabled>1</NewEnabled>\
<NewPortMappingDescription>rustorrent</NewPortMappingDescription>\
<NewLeaseDuration>{lease}</NewLeaseDuration>"
    )
}

fn local_ip(gateway: IpAddr) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((gateway, 1900)).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn parse_control_url_supports_relative_and_absolute_urls() {
        let relative = b"
<service>
  <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
  <controlURL>/upnp/control/WANIPConn1</controlURL>
</service>";
        assert_eq!(
            parse_control_url(relative, "http://router.local/rootDesc.xml"),
            Some(ControlEndpoint {
                url: "http://router.local/upnp/control/WANIPConn1".to_string(),
                service_type: "urn:schemas-upnp-org:service:WANIPConnection:1".to_string(),
            })
        );

        let absolute = b"
<service>
  <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
  <controlURL>http://router.local/control</controlURL>
</service>";
        assert_eq!(
            parse_control_url(absolute, "http://router.local/rootDesc.xml"),
            Some(ControlEndpoint {
                url: "http://router.local/control".to_string(),
                service_type: "urn:schemas-upnp-org:service:WANPPPConnection:1".to_string(),
            })
        );
    }

    #[test]
    fn parse_control_url_returns_none_when_service_missing() {
        let xml = b"<root><serviceType>urn:schemas-upnp-org:service:Other:1</serviceType></root>";
        assert_eq!(parse_control_url(xml, "http://router.local"), None);
    }

    #[test]
    fn add_port_mapping_arguments_contain_port_and_lease() {
        let body = add_port_mapping_arguments(51413, "UDP", "192.0.2.2", 3600);
        assert!(body.contains("<NewExternalPort>51413</NewExternalPort>"));
        assert!(body.contains("<NewInternalPort>51413</NewInternalPort>"));
        assert!(body.contains("<NewProtocol>UDP</NewProtocol>"));
        assert!(body.contains("<NewInternalClient>192.0.2.2</NewInternalClient>"));
        assert!(body.contains("<NewLeaseDuration>3600</NewLeaseDuration>"));
    }

    #[test]
    fn ssdp_location_requires_the_response_source_host() {
        let response = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1:1900/igd.xml\r\n\r\n";
        assert_eq!(
            ssdp_location(response, "192.0.2.1".parse().unwrap()),
            Some("http://192.0.2.1:1900/igd.xml".to_string())
        );
        assert_eq!(ssdp_location(response, "192.0.2.2".parse().unwrap()), None);
    }

    #[test]
    fn discovery_retries_and_ignores_an_invalid_response() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let server_addr = match server.local_addr().unwrap() {
            std::net::SocketAddr::V4(addr) => addr,
            _ => unreachable!(),
        };
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let _ = server.recv_from(&mut buf).unwrap();
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            server
                .send_to(
                    b"HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1/igd.xml\r\n\r\n",
                    peer,
                )
                .unwrap();
            server
                .send_to(
                    b"HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:1900/igd.xml\r\n\r\n",
                    peer,
                )
                .unwrap();
        });

        assert_eq!(
            discover_gateway_at(server_addr, 2, Duration::from_millis(100)),
            Some("http://127.0.0.1:1900/igd.xml".to_string())
        );
        handle.join().unwrap();
    }

    /// A tiny router: serves the description, refuses a timed lease the way
    /// permanent-only routers do, then accepts the permanent one.
    fn fake_router(fault: &'static str) -> (String, thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let mut actions = Vec::new();
            let mut timed_refused = false;
            for stream in listener.incoming().take(7) {
                let mut stream = stream.unwrap();
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    request.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&request);
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .map_or(0, |v| v.trim().parse().unwrap());
                        if body.len() >= length {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&request).to_string();
                let (status, body) = if text.starts_with("GET") {
                    ("200 OK", "<root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl</controlURL></service></root>".to_string())
                } else if text.contains("GetExternalIPAddress") {
                    actions.push("ip".to_string());
                    (
                        "200 OK",
                        "<NewExternalIPAddress>100.64.0.9</NewExternalIPAddress>".to_string(),
                    )
                } else if text.contains("<NewLeaseDuration>3600") {
                    timed_refused = true;
                    actions.push("timed".to_string());
                    ("500 Internal Server Error", format!("<s:Fault><detail><UPnPError><errorCode>{fault}</errorCode></UPnPError></detail></s:Fault>"))
                } else {
                    actions.push("permanent".to_string());
                    ("200 OK", String::new())
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).unwrap();
                if actions.last().is_some_and(|a| a == "ip") || fault == "718" && timed_refused {
                    break;
                }
            }
            actions
        });
        (format!("{base}/desc.xml"), handle)
    }

    #[test]
    fn map_port_falls_back_to_a_permanent_lease_and_reads_the_public_address() {
        let (location, router) = fake_router("725");
        let mapping = map_port_at(&location, 51413, None).unwrap();
        assert_eq!(mapping.external_port, 51413);
        assert_eq!(mapping.external_ip, Some(Ipv4Addr::new(100, 64, 0, 9)));
        assert_eq!(
            router.join().unwrap(),
            ["timed", "permanent", "timed", "permanent", "ip"]
        );
    }

    #[test]
    fn map_port_explains_a_port_taken_by_another_device() {
        let (location, router) = fake_router("718");
        let err = map_port_at(&location, 51413, None).err().unwrap();
        assert!(err.contains("already forwards port 51413"), "{err}");
        assert_eq!(router.join().unwrap(), ["timed"]);
    }
}

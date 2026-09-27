use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

const NATPMP_PORT: u16 = 5351;
const NATPMP_RETRY_TIMEOUTS: [Duration; 4] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
];
#[cfg(target_os = "linux")]
const MAX_ROUTE_TABLE_BYTES: usize = 1024 * 1024;

pub fn map_port(port: u16, lifetime: u32) -> Result<crate::PortMapping, String> {
    let gateway = default_gateway().ok_or_else(|| "no gateway found".to_string())?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| err.to_string())?;
    let addr = SocketAddrV4::new(gateway, NATPMP_PORT);

    // The gateway may pick another external port; peers must be told that one.
    let (external_port, tcp_lifetime) = map_port_proto(&socket, addr, port, port, lifetime, 2)?;
    let (_, udp_lifetime) = map_port_proto(&socket, addr, port, external_port, lifetime, 1)?;
    Ok(crate::PortMapping {
        renew_after: Duration::from_secs(u64::from(tcp_lifetime.min(udp_lifetime))) / 2,
        external_port,
        external_ip: public_address(&socket, addr),
    })
}

/// Sends one request and returns the first well-formed answer from the gateway.
fn exchange<const N: usize>(
    socket: &UdpSocket,
    addr: SocketAddrV4,
    request: &[u8],
    op: u8,
) -> Result<[u8; N], String> {
    for timeout in NATPMP_RETRY_TIMEOUTS {
        socket
            .send_to(request, addr)
            .map_err(|err| err.to_string())?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            socket
                .set_read_timeout(Some(remaining))
                .map_err(|err| err.to_string())?;
            let mut resp = [0u8; N];
            match socket.recv_from(&mut resp) {
                Ok((n, source)) => {
                    if source != std::net::SocketAddr::V4(addr) {
                        continue;
                    }
                    if n != N || resp[0] != 0 || resp[1] != op + 128 {
                        return Err("natpmp invalid response".to_string());
                    }
                    let result_code = u16::from_be_bytes([resp[2], resp[3]]);
                    if result_code != 0 {
                        return Err(format!("natpmp error {result_code}"));
                    }
                    return Ok(resp);
                }
                Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    break;
                }
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(err.to_string()),
            }
        }
    }
    Err("gateway did not respond (NAT-PMP may be unsupported)".to_string())
}

fn map_port_proto(
    socket: &UdpSocket,
    addr: SocketAddrV4,
    port: u16,
    suggested_external: u16,
    lifetime: u32,
    op: u8,
) -> Result<(u16, u32), String> {
    let mut req = [0u8; 12];
    req[1] = op;
    req[4..6].copy_from_slice(&port.to_be_bytes());
    req[6..8].copy_from_slice(&suggested_external.to_be_bytes());
    req[8..12].copy_from_slice(&lifetime.to_be_bytes());
    let resp = exchange::<16>(socket, addr, &req, op)?;
    let internal_port = u16::from_be_bytes([resp[8], resp[9]]);
    let external_port = u16::from_be_bytes([resp[10], resp[11]]);
    if internal_port != port || external_port == 0 {
        return Err("natpmp gateway assigned an unexpected port".to_string());
    }
    let lease = u32::from_be_bytes([resp[12], resp[13], resp[14], resp[15]]);
    if lease == 0 {
        return Err("gateway returned an expired mapping".to_string());
    }
    Ok((external_port, lease))
}

/// The gateway's own internet address (opcode 0), used to spot double NAT.
fn public_address(socket: &UdpSocket, addr: SocketAddrV4) -> Option<Ipv4Addr> {
    let resp = exchange::<12>(socket, addr, &[0, 0], 0).ok()?;
    Some(Ipv4Addr::new(resp[8], resp[9], resp[10], resp[11]))
}

#[cfg(target_os = "linux")]
fn default_gateway() -> Option<Ipv4Addr> {
    let data = crate::read_file_limited(
        std::path::Path::new("/proc/net/route"),
        MAX_ROUTE_TABLE_BYTES,
        false,
    )
    .ok()?;
    let data = std::str::from_utf8(&data).ok()?;
    for line in data.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 2 && parts[1] == "00000000" {
            let gw = u32::from_str_radix(parts[2], 16).ok()?;
            let bytes = gw.to_le_bytes();
            return Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]));
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn default_gateway() -> Option<Ipv4Addr> {
    let output = std::process::Command::new("/sbin/route")
        .arg("-n")
        .arg("get")
        .arg("default")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("gateway:") {
            return rest.trim().parse::<Ipv4Addr>().ok();
        }
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn default_gateway() -> Option<Ipv4Addr> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn local_addr(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
    }

    #[test]
    fn map_port_proto_sends_expected_request_and_accepts_success() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            assert_eq!(n, 12);
            assert_eq!(buf[0], 0);
            assert_eq!(buf[1], 2);
            assert_eq!(u16::from_be_bytes([buf[4], buf[5]]), 51413);
            assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 51413);
            assert_eq!(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]), 1800);

            let mut resp = [0u8; 16];
            resp[12..16].copy_from_slice(&1800u32.to_be_bytes());
            resp[1] = 130; // op + 128 for TCP map
            resp[8..10].copy_from_slice(&51413u16.to_be_bytes());
            resp[10..12].copy_from_slice(&51413u16.to_be_bytes());
            server.send_to(&resp, peer).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        map_port_proto(
            &client,
            local_addr(server_addr.port()),
            51413,
            51413,
            1800,
            2,
        )
        .unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn map_port_proto_rejects_wrong_opcode() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            let mut resp = [0u8; 16];
            resp[12..16].copy_from_slice(&1800u32.to_be_bytes());
            resp[1] = 129; // wrong for op=2
            server.send_to(&resp, peer).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let err = map_port_proto(&client, local_addr(server_addr.port()), 1, 1, 60, 2).unwrap_err();
        assert!(err.contains("invalid response"));
        handle.join().unwrap();
    }

    #[test]
    fn map_port_proto_rejects_nonzero_result_code() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            let mut resp = [0u8; 16];
            resp[12..16].copy_from_slice(&1800u32.to_be_bytes());
            resp[1] = 129; // op=1 (udp) + 128
            resp[2..4].copy_from_slice(&2u16.to_be_bytes());
            server.send_to(&resp, peer).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let err = map_port_proto(&client, local_addr(server_addr.port()), 1, 1, 60, 1).unwrap_err();
        assert!(err.contains("natpmp error 2"));
        handle.join().unwrap();
    }

    #[test]
    fn map_port_proto_rejects_truncated_success_response() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            server.send_to(&[0, 130], peer).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let err = map_port_proto(&client, local_addr(server_addr.port()), 1, 1, 60, 2).unwrap_err();
        assert!(err.contains("invalid response"));
        handle.join().unwrap();
    }

    #[test]
    fn map_port_proto_retries_after_a_timeout() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let _ = server.recv_from(&mut buf).unwrap();
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            let mut resp = [0u8; 16];
            resp[12..16].copy_from_slice(&1800u32.to_be_bytes());
            resp[1] = 130;
            resp[8..10].copy_from_slice(&51413u16.to_be_bytes());
            resp[10..12].copy_from_slice(&51413u16.to_be_bytes());
            server.send_to(&resp, peer).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        map_port_proto(
            &client,
            local_addr(server_addr.port()),
            51413,
            51413,
            1800,
            2,
        )
        .unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn map_port_proto_accepts_a_different_external_port() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            let mut resp = [0u8; 16];
            resp[1] = 130;
            resp[8..10].copy_from_slice(&51413u16.to_be_bytes());
            resp[10..12].copy_from_slice(&40999u16.to_be_bytes());
            resp[12..16].copy_from_slice(&3600u32.to_be_bytes());
            server.send_to(&resp, peer).unwrap();
        });
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mapped = map_port_proto(
            &client,
            local_addr(server_addr.port()),
            51413,
            51413,
            3600,
            2,
        );
        assert_eq!(mapped, Ok((40999, 3600)));
        handle.join().unwrap();
    }

    #[test]
    fn public_address_reads_the_gateway_answer() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], &[0, 0]);
            let resp = [0, 128, 0, 0, 0, 0, 0, 9, 100, 64, 3, 7];
            server.send_to(&resp, peer).unwrap();
        });
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            public_address(&client, local_addr(server_addr.port())),
            Some(Ipv4Addr::new(100, 64, 3, 7))
        );
        handle.join().unwrap();
    }
}

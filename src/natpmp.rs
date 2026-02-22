use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

const NATPMP_PORT: u16 = 5351;
const NATPMP_TIMEOUT: Duration = Duration::from_secs(2);

pub fn map_port(port: u16, lifetime: u32) -> Result<(), String> {
    let gateway = default_gateway().ok_or_else(|| "no gateway found".to_string())?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| err.to_string())?;
    socket
        .set_read_timeout(Some(NATPMP_TIMEOUT))
        .map_err(|err| err.to_string())?;
    let addr = SocketAddrV4::new(gateway, NATPMP_PORT);

    map_port_proto(&socket, addr, port, lifetime, 2)?;
    map_port_proto(&socket, addr, port, lifetime, 1)?;
    Ok(())
}

fn map_port_proto(
    socket: &UdpSocket,
    addr: SocketAddrV4,
    port: u16,
    lifetime: u32,
    op: u8,
) -> Result<(), String> {
    let mut req = [0u8; 12];
    req[0] = 0;
    req[1] = op;
    req[4..6].copy_from_slice(&port.to_be_bytes());
    req[6..8].copy_from_slice(&port.to_be_bytes());
    req[8..12].copy_from_slice(&lifetime.to_be_bytes());
    socket.send_to(&req, addr).map_err(|err| err.to_string())?;
    let mut resp = [0u8; 16];
    let _ = socket.recv_from(&mut resp).map_err(|err| err.to_string())?;
    if resp[1] != op + 128 {
        return Err("natpmp invalid response".to_string());
    }
    let result_code = u16::from_be_bytes([resp[2], resp[3]]);
    if result_code != 0 {
        return Err(format!("natpmp error {result_code}"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn default_gateway() -> Option<Ipv4Addr> {
    let data = std::fs::read_to_string("/proc/net/route").ok()?;
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
    let output = std::process::Command::new("route")
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
            resp[1] = 130; // op + 128 for TCP map
            server.send_to(&resp, peer).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        map_port_proto(&client, local_addr(server_addr.port()), 51413, 1800, 2).unwrap();
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
            resp[1] = 129; // wrong for op=2
            server.send_to(&resp, peer).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let err = map_port_proto(&client, local_addr(server_addr.port()), 1, 60, 2).unwrap_err();
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
            resp[1] = 129; // op=1 (udp) + 128
            resp[2..4].copy_from_slice(&2u16.to_be_bytes());
            server.send_to(&resp, peer).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let err = map_port_proto(&client, local_addr(server_addr.port()), 1, 60, 1).unwrap_err();
        assert!(err.contains("natpmp error 2"));
        handle.join().unwrap();
    }
}

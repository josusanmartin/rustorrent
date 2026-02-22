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

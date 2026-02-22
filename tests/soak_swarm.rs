use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn system_entropy_u64() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    now.as_nanos() as u64
}

mod utp {
    include!("../src/utp.rs");
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn current_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
        return Some(pages.saturating_mul(4096));
    }
    #[cfg(target_os = "macos")]
    {
        let pid = std::process::id().to_string();
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &pid])
            .output()
            .ok()?;
        let kb = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .ok()?;
        return Some(kb.saturating_mul(1024));
    }
    #[allow(unreachable_code)]
    None
}

#[test]
#[ignore = "long-running release soak test"]
fn mixed_utp_tcp_swarm_has_low_error_rate_and_bounded_memory() {
    let soak_secs = std::env::var("RUSTORRENT_SOAK_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10);
    let deadline = Instant::now() + Duration::from_secs(soak_secs);
    let start_rss = current_rss_bytes();

    let tcp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    tcp_listener.set_nonblocking(true).unwrap();
    let tcp_addr = tcp_listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_server = Arc::clone(&stop);
    let tcp_server = thread::spawn(move || {
        while !stop_server.load(Ordering::SeqCst) {
            match tcp_listener.accept() {
                Ok((mut stream, _)) => {
                    thread::spawn(move || {
                        let mut buf = [0u8; 1024];
                        loop {
                            match stream.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let port_a = free_udp_port();
    let port_b = free_udp_port();
    let (connector_a, _listener_a) = utp::start(port_a);
    let (_connector_b, listener_b) = utp::start(port_b);
    thread::sleep(Duration::from_millis(100));
    let addr_b: SocketAddr = format!("127.0.0.1:{port_b}").parse().unwrap();
    let mut utp_a = connector_a.connect(addr_b).unwrap();
    let mut utp_b = {
        let accept_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(stream) = listener_b.try_accept() {
                break stream;
            }
            assert!(
                Instant::now() < accept_deadline,
                "timed out waiting for uTP accept"
            );
            thread::sleep(Duration::from_millis(10));
        }
    };
    utp_a.set_read_timeout(Some(Duration::from_secs(1)));
    utp_a.set_write_timeout(Some(Duration::from_secs(1)));
    utp_b.set_read_timeout(Some(Duration::from_secs(1)));
    utp_b.set_write_timeout(Some(Duration::from_secs(1)));

    let ops = AtomicU64::new(0);
    let errs = AtomicU64::new(0);
    let utp_ops = AtomicU64::new(0);
    let utp_errs = AtomicU64::new(0);
    let tcp_ops = AtomicU64::new(0);
    let tcp_errs = AtomicU64::new(0);

    let mut counter = 0u64;
    while Instant::now() < deadline {
        let byte = (counter % 251) as u8;
        let payload = vec![byte; 256];

        if utp_a.write_all(&payload).is_err() {
            errs.fetch_add(1, Ordering::SeqCst);
            utp_errs.fetch_add(1, Ordering::SeqCst);
        } else {
            let mut recv = vec![0u8; payload.len()];
            if utp_b.read_exact(&mut recv).is_err() || recv != payload {
                errs.fetch_add(1, Ordering::SeqCst);
                utp_errs.fetch_add(1, Ordering::SeqCst);
            } else {
                ops.fetch_add(1, Ordering::SeqCst);
                utp_ops.fetch_add(1, Ordering::SeqCst);
            }
        }

        let mut tcp_client = match TcpStream::connect(tcp_addr) {
            Ok(stream) => stream,
            Err(_) => {
                errs.fetch_add(1, Ordering::SeqCst);
                tcp_errs.fetch_add(1, Ordering::SeqCst);
                counter = counter.wrapping_add(1);
                continue;
            }
        };
        tcp_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        tcp_client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        if tcp_client.write_all(&payload).is_err() {
            errs.fetch_add(1, Ordering::SeqCst);
            tcp_errs.fetch_add(1, Ordering::SeqCst);
        } else {
            let mut recv = vec![0u8; payload.len()];
            if tcp_client.read_exact(&mut recv).is_err() || recv != payload {
                errs.fetch_add(1, Ordering::SeqCst);
                tcp_errs.fetch_add(1, Ordering::SeqCst);
            } else {
                ops.fetch_add(1, Ordering::SeqCst);
                tcp_ops.fetch_add(1, Ordering::SeqCst);
            }
        }

        counter = counter.wrapping_add(1);
    }

    stop.store(true, Ordering::SeqCst);
    let _ = tcp_server.join();

    let total_ops = ops.load(Ordering::SeqCst);
    let total_errs = errs.load(Ordering::SeqCst);
    assert!(total_ops >= 20, "too few operations in soak: {total_ops}");
    let error_rate = total_errs as f64 / (total_ops + total_errs).max(1) as f64;
    assert!(
        error_rate <= 0.01,
        "error rate too high: {:.2}% (ops={}, errs={}, utp_ops={}, utp_errs={}, tcp_ops={}, tcp_errs={})",
        error_rate * 100.0,
        total_ops,
        total_errs,
        utp_ops.load(Ordering::SeqCst),
        utp_errs.load(Ordering::SeqCst),
        tcp_ops.load(Ordering::SeqCst),
        tcp_errs.load(Ordering::SeqCst)
    );

    if let (Some(start), Some(end)) = (start_rss, current_rss_bytes()) {
        let delta = end.saturating_sub(start);
        assert!(
            delta <= 64 * 1024 * 1024,
            "rss delta too high: {} bytes",
            delta
        );
    }
}

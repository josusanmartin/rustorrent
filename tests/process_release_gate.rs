use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const INFO_HASH_HEX: &str = "2d59811606aa23e2fdb1f6d338b6c98a972004e9";
const INFO_HASH: [u8; 20] = [
    0x2d, 0x59, 0x81, 0x16, 0x06, 0xaa, 0x23, 0xe2, 0xfd, 0xb1, 0xf6, 0xd3, 0x38, 0xb6, 0xc9, 0x8a,
    0x97, 0x20, 0x04, 0xe9,
];

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("rustorrent-process-test-{label}-{nanos}"))
}

fn free_tcp_port() -> u16 {
    static USED: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    let mut used = USED
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap();
    loop {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() && used.insert(port) {
            return port;
        }
    }
}

fn wait_for_tcp(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

fn wait_for_process_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(_) => return None,
        }
    }
    None
}

fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

fn write_minimal_torrent(path: &Path) {
    let info = b"d6:lengthi1e4:name4:test12:piece lengthi1e6:pieces20:aaaaaaaaaaaaaaaaaaaae";
    let mut out = b"d8:announce27:http://127.0.0.1:1/announce4:info".to_vec();
    out.extend_from_slice(info);
    out.push(b'e');
    fs::write(path, out).unwrap();
}

fn build_handshake(info_hash: [u8; 20], peer_id: [u8; 20], extensions: bool) -> [u8; 68] {
    let mut out = [0u8; 68];
    out[0] = 19;
    out[1..20].copy_from_slice(b"BitTorrent protocol");
    if extensions {
        out[25] = 0x10;
    }
    out[28..48].copy_from_slice(&info_hash);
    out[48..68].copy_from_slice(&peer_id);
    out
}

struct TestProcess {
    child: Child,
    log: PathBuf,
}
impl Deref for TestProcess {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}
impl DerefMut for TestProcess {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}
impl Drop for TestProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_rustorrent(args: &[String], cwd: &Path) -> TestProcess {
    let log = cwd.join("process-output.log");
    let output = fs::File::create(&log).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_rustorrent"))
        .args(args)
        .arg("--no-port-mapping")
        .current_dir(cwd)
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output))
        .spawn()
        .unwrap();
    TestProcess { child, log }
}

#[cfg(windows)]
#[test]
fn desktop_launcher_event_saves_session_without_a_console() {
    use std::ffi::c_void;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::os::windows::process::CommandExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateEventW(
            attributes: *const c_void,
            manual: i32,
            initial: i32,
            name: *const u16,
        ) -> *mut c_void;
        fn SetEvent(event: *mut c_void) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
        fn DuplicateHandle(
            source_process: *mut c_void,
            source: *mut c_void,
            target_process: *mut c_void,
            target: *mut *mut c_void,
            access: u32,
            inherit: i32,
            options: u32,
        ) -> i32;
    }
    let root = temp_dir("desktop-shutdown");
    fs::create_dir_all(&root).unwrap();
    let torrent = root.join("input.torrent");
    write_minimal_torrent(&torrent);
    let secret = format!(
        "{:064x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let name: Vec<u16> = format!("Local\\Rustorrent.Shutdown.{secret}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    // SAFETY: a NUL-terminated name and default security create a new event.
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, name.as_ptr()) };
    assert!(!event.is_null());
    // SAFETY: CreateEventW returned an owned, valid handle.
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    // The launcher passes an inheritable handle to its own process.
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    let mut launcher = std::ptr::null_mut();
    // SAFETY: the pseudo-handle of this process is duplicated into an owned handle.
    let duplicated = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            GetCurrentProcess(),
            &mut launcher,
            SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
            1,
            0,
        )
    };
    assert_ne!(duplicated, 0);
    // SAFETY: DuplicateHandle returned an owned, valid handle.
    let launcher = unsafe { OwnedHandle::from_raw_handle(launcher) };
    let port = free_tcp_port();
    let log = root.join("process-output.log");
    let output = fs::File::create(&log).unwrap();
    let mut process = TestProcess {
        child: Command::new(env!("CARGO_BIN_EXE_rustorrent"))
            .args([
                "--ui",
                "--ui-addr",
                &format!("127.0.0.1:{port}"),
                "--no-port-mapping",
            ])
            .arg("--download-dir")
            .arg(&root)
            .arg(&torrent)
            .env("RUSTORRENT_UI_OWNER_SECRET", &secret)
            .env(
                "RUSTORRENT_LAUNCHER_HANDLE",
                (launcher.as_raw_handle() as usize).to_string(),
            )
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .current_dir(&root)
            .stdout(Stdio::from(output.try_clone().unwrap()))
            .stderr(Stdio::from(output))
            .spawn()
            .unwrap(),
        log,
    };
    assert!(wait_for_tcp(port, Duration::from_secs(10)));
    assert!(http_get(port, "/api-token").unwrap().contains(&secret));
    assert!(wait_for_file(
        &root.join(".rustorrent/session.benc"),
        Duration::from_secs(10)
    ));
    // SAFETY: the test owns this event until the child has exited.
    assert_ne!(unsafe { SetEvent(event.as_raw_handle()) }, 0);
    let status = wait_for_process_exit(&mut process, Duration::from_secs(20))
        .expect("desktop engine did not shut down after its launcher event");
    assert!(
        status.success(),
        "{}",
        fs::read_to_string(&process.log).unwrap()
    );
    assert!(root.join(".rustorrent/session.benc").is_file());
}

fn stop_child(mut child: TestProcess) -> String {
    let _ = child.kill();
    let _ = child.wait();
    fs::read_to_string(&child.log).unwrap_or_default()
}

fn http_get(port: u16, path: &str) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    Some(String::from_utf8_lossy(&response).into_owned())
}

fn bencode_value(data: &[u8], pos: &mut usize) -> bool {
    if *pos >= data.len() {
        return false;
    }
    match data[*pos] {
        b'i' => {
            *pos += 1;
            if *pos >= data.len() {
                return false;
            }
            if data[*pos] == b'-' {
                *pos += 1;
            }
            let start = *pos;
            while *pos < data.len() && data[*pos].is_ascii_digit() {
                *pos += 1;
            }
            if *pos == start || *pos >= data.len() || data[*pos] != b'e' {
                return false;
            }
            *pos += 1;
            true
        }
        b'l' => {
            *pos += 1;
            while *pos < data.len() && data[*pos] != b'e' {
                if !bencode_value(data, pos) {
                    return false;
                }
            }
            if *pos >= data.len() || data[*pos] != b'e' {
                return false;
            }
            *pos += 1;
            true
        }
        b'd' => {
            *pos += 1;
            while *pos < data.len() && data[*pos] != b'e' {
                if !bencode_bytes(data, pos) {
                    return false;
                }
                if !bencode_value(data, pos) {
                    return false;
                }
            }
            if *pos >= data.len() || data[*pos] != b'e' {
                return false;
            }
            *pos += 1;
            true
        }
        b'0'..=b'9' => bencode_bytes(data, pos),
        _ => false,
    }
}

fn bencode_bytes(data: &[u8], pos: &mut usize) -> bool {
    if *pos >= data.len() || !data[*pos].is_ascii_digit() {
        return false;
    }
    let mut len: usize = 0;
    while *pos < data.len() && data[*pos].is_ascii_digit() {
        len = len
            .saturating_mul(10)
            .saturating_add((data[*pos] - b'0') as usize);
        *pos += 1;
    }
    if *pos >= data.len() || data[*pos] != b':' {
        return false;
    }
    *pos += 1;
    if data.len().saturating_sub(*pos) < len {
        return false;
    }
    *pos += len;
    true
}

fn is_valid_bencode(data: &[u8]) -> bool {
    let mut pos = 0;
    bencode_value(data, &mut pos) && pos == data.len()
}

fn churn_peer_connection(peer_port: u16, token: usize) {
    if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", peer_port)) {
        let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
        match token % 4 {
            0 => {
                let handshake = build_handshake(INFO_HASH, [0x33u8; 20], true);
                let _ = stream.write_all(&handshake[..16]);
            }
            1 => {
                let _ = stream.write_all(&[0u8]);
                let oversized = vec![0xAA; 1536];
                let _ = stream.write_all(&oversized);
            }
            2 => {
                let handshake = build_handshake(INFO_HASH, [0x44u8; 20], true);
                let _ = stream.write_all(&handshake);
                let oversized = (2 * 1024 * 1024u32 + 1).to_be_bytes();
                let _ = stream.write_all(&oversized);
            }
            _ => {}
        }
    }
}

#[test]
fn ui_echoes_the_backend_owner_secret_for_launcher_verification() {
    let root = temp_dir("ui-owner-secret");
    fs::create_dir_all(&root).unwrap();
    let ui_port = free_tcp_port();
    let peer_port = free_tcp_port();
    let owner_secret = "0123456789abcdef".repeat(4);
    let args = vec![
        "--ui".to_string(),
        "--ui-addr".to_string(),
        format!("127.0.0.1:{ui_port}"),
        "--download-dir".to_string(),
        root.display().to_string(),
        "--port".to_string(),
        peer_port.to_string(),
    ];
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustorrent"))
        .args(&args)
        .env("RUSTORRENT_UI_OWNER_SECRET", &owner_secret)
        .current_dir(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    assert!(
        wait_for_tcp(ui_port, Duration::from_secs(6)),
        "ui port not ready"
    );
    let response = http_get(ui_port, "/api-token").unwrap_or_default();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains(&format!("\"owner_secret\":\"{owner_secret}\"")));
    assert!(
        child.try_wait().unwrap().is_none(),
        "backend exited after serving owner secret"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn explicit_ui_bind_failure_is_fatal() {
    let root = temp_dir("ui-bind-fatal");
    fs::create_dir_all(&root).unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let ui_port = occupied.local_addr().unwrap().port();
    let peer_port = free_tcp_port();
    let args = vec![
        "--ui".to_string(),
        "--ui-addr".to_string(),
        format!("127.0.0.1:{ui_port}"),
        "--download-dir".to_string(),
        root.display().to_string(),
        "--port".to_string(),
        peer_port.to_string(),
    ];
    let mut child = spawn_rustorrent(&args, &root);

    let status = wait_for_process_exit(&mut child, Duration::from_secs(6))
        .expect("backend kept running after explicit UI bind failure");
    assert!(!status.success(), "UI bind failure returned success");
    let output = stop_child(child);
    assert!(
        output.contains(&format!("UI bind 127.0.0.1:{ui_port} failed")),
        "missing fatal UI bind diagnostic: {output}"
    );

    drop(occupied);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn process_survives_truncated_and_oversized_frames() {
    let root = temp_dir("frames");
    fs::create_dir_all(&root).unwrap();
    let torrent_path = root.join("sample.torrent");
    write_minimal_torrent(&torrent_path);

    let ui_port = free_tcp_port();
    let peer_port = free_tcp_port();
    let args = vec![
        torrent_path.display().to_string(),
        "--download-dir".to_string(),
        root.display().to_string(),
        "--ui".to_string(),
        ui_port.to_string(),
        "--port".to_string(),
        peer_port.to_string(),
        "--retry-interval".to_string(),
        "1".to_string(),
    ];

    let mut child = spawn_rustorrent(&args, &root);
    assert!(
        wait_for_tcp(peer_port, Duration::from_secs(6)),
        "peer port not ready"
    );

    let full = build_handshake(INFO_HASH, [0x11u8; 20], true);
    {
        let mut s = TcpStream::connect(("127.0.0.1", peer_port)).unwrap();
        s.write_all(&full[..12]).unwrap();
    }

    thread::sleep(Duration::from_millis(150));
    assert!(child.try_wait().unwrap().is_none(), "process exited early");

    {
        let mut s = TcpStream::connect(("127.0.0.1", peer_port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        s.write_all(&full).unwrap();
        let mut resp = [0u8; 68];
        let _ = s.read_exact(&mut resp);
        let oversized = (2 * 1024 * 1024u32 + 1).to_be_bytes();
        s.write_all(&oversized).unwrap();
    }

    thread::sleep(Duration::from_millis(200));
    assert!(
        child.try_wait().unwrap().is_none(),
        "process crashed after oversized frame"
    );

    let _ = stop_child(child);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn proxy_mode_does_not_open_direct_peer_or_discovery_listeners() {
    let root = temp_dir("proxy-listeners");
    fs::create_dir_all(&root).unwrap();
    let ui_port = free_tcp_port();
    let peer_port = free_tcp_port();
    let args = vec![
        "--ui".to_string(),
        "--ui-addr".to_string(),
        format!("127.0.0.1:{ui_port}"),
        "--download-dir".to_string(),
        root.display().to_string(),
        "--port".to_string(),
        peer_port.to_string(),
        "--utp".to_string(),
        "--proxy".to_string(),
        "socks5://127.0.0.1:1".to_string(),
    ];
    let child = spawn_rustorrent(&args, &root);
    assert!(
        wait_for_tcp(ui_port, Duration::from_secs(6)),
        "ui port not ready"
    );

    let tcp = TcpListener::bind(("127.0.0.1", peer_port))
        .expect("proxy mode unexpectedly opened the direct TCP peer listener");
    let udp = UdpSocket::bind(("127.0.0.1", peer_port))
        .expect("proxy mode unexpectedly opened a DHT/uTP UDP listener");

    drop((tcp, udp));
    let _ = stop_child(child);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn process_survives_malformed_extension_payload() {
    let root = temp_dir("ext");
    fs::create_dir_all(&root).unwrap();
    let torrent_path = root.join("sample.torrent");
    write_minimal_torrent(&torrent_path);

    let ui_port = free_tcp_port();
    let peer_port = free_tcp_port();
    let args = vec![
        torrent_path.display().to_string(),
        "--download-dir".to_string(),
        root.display().to_string(),
        "--ui".to_string(),
        ui_port.to_string(),
        "--port".to_string(),
        peer_port.to_string(),
        "--retry-interval".to_string(),
        "1".to_string(),
    ];
    let mut child = spawn_rustorrent(&args, &root);
    assert!(
        wait_for_tcp(peer_port, Duration::from_secs(6)),
        "peer port not ready"
    );

    let handshake = build_handshake(INFO_HASH, [0x22u8; 20], true);
    let mut s = TcpStream::connect(("127.0.0.1", peer_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    s.write_all(&handshake).unwrap();
    let mut resp = [0u8; 68];
    let _ = s.read_exact(&mut resp);

    let malformed = [0, 0, 0, 3, 20, 0, b'x'];
    s.write_all(&malformed).unwrap();
    drop(s);

    thread::sleep(Duration::from_millis(250));
    assert!(
        child.try_wait().unwrap().is_none(),
        "process crashed on malformed extension"
    );

    let _ = stop_child(child);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn process_fails_closed_on_unrecoverable_session_state() {
    let root = temp_dir("corrupt-state");
    fs::create_dir_all(&root).unwrap();
    let torrent_path = root.join("sample.torrent");
    write_minimal_torrent(&torrent_path);
    let session_path = root.join(".rustorrent/session.benc");

    // Let the application create the protected Windows state directory and
    // state file. Replacing their contents afterward preserves the trusted
    // owner/ACL while still exercising unrecoverable parser corruption.
    let init_ui_port = free_tcp_port();
    let init_peer_port = free_tcp_port();
    let init_args = vec![
        torrent_path.display().to_string(),
        "--download-dir".to_string(),
        root.display().to_string(),
        "--ui".to_string(),
        init_ui_port.to_string(),
        "--port".to_string(),
        init_peer_port.to_string(),
        "--retry-interval".to_string(),
        "1".to_string(),
    ];
    let initializer = spawn_rustorrent(&init_args, &root);
    assert!(
        wait_for_file(&session_path, Duration::from_secs(10)),
        "initializer did not create session state"
    );
    let _ = stop_child(initializer);

    let _ = fs::remove_file(root.join(".rustorrent/session.benc.bak"));
    fs::write(&session_path, b"not-bencode").unwrap();

    let ui_port = free_tcp_port();
    let peer_port = free_tcp_port();
    let args = vec![
        torrent_path.display().to_string(),
        "--download-dir".to_string(),
        root.display().to_string(),
        "--ui".to_string(),
        ui_port.to_string(),
        "--port".to_string(),
        peer_port.to_string(),
        "--retry-interval".to_string(),
        "1".to_string(),
    ];

    let mut child = spawn_rustorrent(&args, &root);
    let status = wait_for_process_exit(&mut child, Duration::from_secs(6))
        .expect("process did not fail closed on corrupt session state");
    assert!(!status.success());
    let output = stop_child(child);
    assert!(
        output.contains("cannot load session state") && output.contains("session load failed"),
        "expected fatal session corruption error in logs: {output}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn process_survives_slowloris_ui_requests_and_stays_responsive() {
    let root = temp_dir("slowloris-ui");
    fs::create_dir_all(&root).unwrap();
    let torrent_path = root.join("sample.torrent");
    write_minimal_torrent(&torrent_path);

    let ui_port = free_tcp_port();
    let peer_port = free_tcp_port();
    let args = vec![
        torrent_path.display().to_string(),
        "--download-dir".to_string(),
        root.display().to_string(),
        "--ui".to_string(),
        ui_port.to_string(),
        "--port".to_string(),
        peer_port.to_string(),
        "--retry-interval".to_string(),
        "1".to_string(),
    ];
    let child = spawn_rustorrent(&args, &root);
    assert!(
        wait_for_tcp(ui_port, Duration::from_secs(6)),
        "ui port not ready"
    );

    let mut hold = Vec::new();
    for _ in 0..96 {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", ui_port)) {
            let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
            let _ = stream.write_all(b"GET /status HTTP/1.1\r\nHost: 127.0.0.1\r\n");
            hold.push(stream);
        }
    }

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut healthy = false;
    while Instant::now() < deadline {
        if let Some(response) = http_get(ui_port, "/status") {
            if response.starts_with("HTTP/1.1 200 OK") {
                healthy = true;
                break;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }

    assert!(healthy, "ui stayed unavailable under slowloris load");
    drop(hold);
    let _ = stop_child(child);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn process_survives_connection_churn_and_encrypted_handshake_storm() {
    let root = temp_dir("peer-storm");
    fs::create_dir_all(&root).unwrap();
    let torrent_path = root.join("sample.torrent");
    write_minimal_torrent(&torrent_path);

    let ui_port = free_tcp_port();
    let peer_port = free_tcp_port();
    let args = vec![
        torrent_path.display().to_string(),
        "--download-dir".to_string(),
        root.display().to_string(),
        "--ui".to_string(),
        ui_port.to_string(),
        "--port".to_string(),
        peer_port.to_string(),
        "--retry-interval".to_string(),
        "1".to_string(),
    ];
    let mut child = spawn_rustorrent(&args, &root);
    assert!(
        wait_for_tcp(peer_port, Duration::from_secs(6)),
        "peer port not ready"
    );

    let mut workers = Vec::new();
    for worker in 0..8usize {
        let port = peer_port;
        workers.push(thread::spawn(move || {
            for round in 0..80usize {
                churn_peer_connection(port, worker * 1000 + round);
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }

    thread::sleep(Duration::from_millis(400));
    assert!(
        child.try_wait().unwrap().is_none(),
        "process exited during peer churn storm"
    );

    let response = http_get(ui_port, "/status").unwrap_or_default();
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "ui status endpoint unavailable after peer storm"
    );

    let _ = stop_child(child);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn process_restart_recovery_loops_preserve_session_and_resume_files() {
    let root = temp_dir("restart-loops");
    fs::create_dir_all(&root).unwrap();
    let torrent_path = root.join("sample.torrent");
    write_minimal_torrent(&torrent_path);
    let state_dir = root.join(".rustorrent");
    let session_path = state_dir.join("session.benc");
    let resume_path = state_dir.join(format!("{INFO_HASH_HEX}.resume"));

    for round in 0..6 {
        let ui_port = free_tcp_port();
        let peer_port = free_tcp_port();
        let args = vec![
            torrent_path.display().to_string(),
            "--download-dir".to_string(),
            root.display().to_string(),
            "--ui".to_string(),
            ui_port.to_string(),
            "--port".to_string(),
            peer_port.to_string(),
            "--retry-interval".to_string(),
            "1".to_string(),
        ];
        let mut child = spawn_rustorrent(&args, &root);
        assert!(
            wait_for_tcp(ui_port, Duration::from_secs(6)),
            "ui not ready on round {round}"
        );
        assert!(
            wait_for_tcp(peer_port, Duration::from_secs(6)),
            "peer not ready on round {round}"
        );

        let churn_handle = thread::spawn(move || {
            for token in 0..150usize {
                churn_peer_connection(peer_port, token);
            }
        });
        let _ = churn_handle.join();
        assert!(
            wait_for_file(&session_path, Duration::from_secs(8)),
            "session file not created on round {round}"
        );
        assert!(
            wait_for_file(&resume_path, Duration::from_secs(20)),
            "resume file not created on round {round}"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "process exited unexpectedly on round {round}"
        );

        let _ = stop_child(child);
        let session_bytes = fs::read(&session_path).expect("missing session file");
        let resume_bytes = fs::read(&resume_path).expect("missing resume file");
        assert!(
            is_valid_bencode(&session_bytes),
            "session file invalid bencode on round {round}"
        );
        assert!(
            is_valid_bencode(&resume_bytes),
            "resume file invalid bencode on round {round}"
        );

        let session_backup = session_path.with_file_name("session.benc.bak");
        if let Ok(bytes) = fs::read(&session_backup) {
            assert!(
                is_valid_bencode(&bytes),
                "session backup invalid on round {round}"
            );
        }
        let resume_backup = resume_path.with_file_name(format!("{INFO_HASH_HEX}.resume.bak"));
        if let Ok(bytes) = fs::read(&resume_backup) {
            assert!(
                is_valid_bencode(&bytes),
                "resume backup invalid on round {round}"
            );
        }
    }

    let _ = fs::remove_dir_all(&root);
}

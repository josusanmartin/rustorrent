//! The desktop launcher requests a normal shutdown through a private event.
//! Watching its process also saves state if the launcher crashes or is killed.
use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> *mut c_void;
    fn GetProcessId(process: *mut c_void) -> u32;
    fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
    fn WaitForMultipleObjects(count: u32, handles: *const *mut c_void, all: i32, ms: u32) -> u32;
}

pub(crate) fn install_shutdown_watch() -> Result<(), String> {
    // An inherited handle, unlike a PID, cannot name a different process if
    // the launcher has already exited.
    let Ok(parent) = std::env::var("RUSTORRENT_LAUNCHER_HANDLE") else {
        return Ok(());
    };
    let parent = parent
        .parse::<usize>()
        .map_err(|_| "invalid launcher handle")? as *mut c_void;
    // SAFETY: GetProcessId only reads the handle and fails for anything that
    // is not a process handle with query access.
    if unsafe { GetProcessId(parent) } == 0 {
        return Err(format!(
            "open launcher process: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the launcher created this handle for this process to inherit,
    // and nothing else in the engine refers to it.
    let parent = unsafe { OwnedHandle::from_raw_handle(parent) };
    const HANDLE_FLAG_INHERIT: u32 = 1;
    // SAFETY: `parent` is a live handle; this keeps search plugins from inheriting it.
    let _ = unsafe { SetHandleInformation(parent.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) };
    let secret = std::env::var("RUSTORRENT_UI_OWNER_SECRET")
        .map_err(|_| "missing launcher ownership secret")?;
    if secret.len() != 64 || !secret.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid launcher ownership secret".into());
    }
    let name: Vec<u16> = format!("Local\\Rustorrent.Shutdown.{secret}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    const SYNCHRONIZE: u32 = 0x0010_0000;
    // SAFETY: the event name is NUL terminated and the handle is not inheritable.
    let event = unsafe { OpenEventW(SYNCHRONIZE, 0, name.as_ptr()) };
    if event.is_null() {
        return Err(format!(
            "open launcher event: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: OpenEventW returned a new owned handle.
    let event = unsafe { OwnedHandle::from_raw_handle(event) };
    std::thread::Builder::new()
        .name("launcher-shutdown".into())
        .spawn(move || {
            let handles = [event.as_raw_handle(), parent.as_raw_handle()];
            // SAFETY: both handles remain owned by this thread until the wait ends.
            let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, u32::MAX) };
            if result <= 1 {
                crate::request_shutdown();
            }
        })
        .map_err(|err| format!("watch launcher shutdown: {err}"))?;
    Ok(())
}

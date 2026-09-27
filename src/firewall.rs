// The macOS application firewall silently drops incoming peer connections for
// apps it has not been told to allow, which leaves a seed with nobody to serve.

/// "" when unknown or not macOS; otherwise off, allowed, blocked, unlisted
/// (never approved, so incoming connections are refused) or block-all.
pub(crate) fn status() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        let app = app_path();
        let app = app.to_string_lossy();
        match (
            socketfilterfw(&["--getglobalstate"]),
            socketfilterfw(&["--getblockall"]),
            socketfilterfw(&["--getappblocked", &app]),
        ) {
            (Some(global), Some(block_all), Some(listed)) => classify(&global, &block_all, &listed),
            _ => "",
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        ""
    }
}

/// Adds the app to the firewall's allowed list after the standard macOS
/// administrator prompt. Ok(false) means the person cancelled.
pub(crate) fn allow() -> Result<bool, String> {
    #[cfg(target_os = "macos")]
    {
        // The path travels as an argument and is quoted by AppleScript, so it
        // can never be read as shell syntax.
        let script = "on run argv\n\
            set fw to \"/usr/libexec/ApplicationFirewall/socketfilterfw\"\n\
            set app to quoted form of (item 1 of argv)\n\
            do shell script fw & \" --add \" & app & \" && \" & fw & \" --unblockapp \" & app \
            with prompt \"Rustorrent wants to accept incoming connections from peers.\" \
            with administrator privileges\n\
            end run";
        let output = std::process::Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(script)
            .arg(app_path())
            .output()
            .map_err(|err| format!("could not ask for permission: {err}"))?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("-128") || stderr.to_ascii_lowercase().contains("cancel") {
            return Ok(false);
        }
        Err(format!("the firewall was not changed: {}", stderr.trim()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("the application firewall is only managed on macOS".to_string())
    }
}

#[cfg(target_os = "macos")]
fn socketfilterfw(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
        .args(args)
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The .app bundle when running inside one, since that is what the firewall
/// lists and prompts for; otherwise the executable itself.
#[cfg(target_os = "macos")]
fn app_path() -> std::path::PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    exe.ancestors()
        .find(|path| path.extension().is_some_and(|ext| ext == "app"))
        .map_or_else(|| exe.clone(), std::path::Path::to_path_buf)
}

#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn classify(global: &str, block_all: &str, app: &str) -> &'static str {
    let lower = |text: &str| text.to_ascii_lowercase();
    let (global, block_all, app) = (lower(global), lower(block_all), lower(app));
    if global.contains("disabled") || global.contains("state = 0") {
        "off"
    } else if global.contains("state = 2")
        || (block_all.contains("enabled") && !block_all.contains("disabled"))
    {
        "block-all"
    } else if app.contains("not part of the firewall") {
        "unlisted"
    } else if app.contains("block") {
        "blocked"
    } else if app.contains("permit") || app.contains("allow") {
        "allowed"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::classify;

    #[test]
    fn classify_reads_socketfilterfw_output() {
        let on = "Firewall is enabled. (State = 1)";
        let open = "Firewall has block all state set to disabled.";
        assert_eq!(
            classify("Firewall is disabled. (State = 0)", open, ""),
            "off"
        );
        assert_eq!(
            classify(on, "Firewall has block all state set to enabled.", ""),
            "block-all"
        );
        assert_eq!(
            classify(
                on,
                open,
                "The application /A.app is not part of the firewall"
            ),
            "unlisted"
        );
        assert_eq!(
            classify(
                on,
                open,
                "The application /A.app is blocked from incoming connections"
            ),
            "blocked"
        );
        assert_eq!(
            classify(
                on,
                open,
                "Incoming connection to the application is permitted"
            ),
            "allowed"
        );
    }
}

# Rustorrent for Windows

Rustorrent is a desktop application with its own native window, taskbar icon,
menus and notification-area icon. Like the macOS app, it embeds the existing
interface in a system web view: WebView2 on Windows, WKWebView on macOS.
The download engine starts automatically without a console window.

## Run

1. Extract the entire ZIP.
2. Double-click **Rustorrent.exe**.

Use Windows 10 version 1703 or later, or Windows 11, with
[Microsoft Edge WebView2 Runtime](https://go.microsoft.com/fwlink/p/?LinkId=2124703).
The launcher reports when the runtime is missing. No .NET runtime, PowerShell
script, browser window or developer tools are needed to run the desktop app.

The **File** menu opens the Add dialog, Settings, the Downloads folder, and offers
**Hide to tray**. Double-click the tray icon to restore the window. Closing the
window or choosing **Exit** saves the session and stops the owned engine. Hiding
to the tray keeps transfers running. Starting the application again restores
its existing window.

The system Downloads folder is the default destination. Session state is stored
in its `.rustorrent` directory. Launcher logs and the WebView2 profile are under
`%LOCALAPPDATA%\Rustorrent`. A startup error includes the engine log path.

The launcher verifies that the local interface belongs to the engine it started.
Other sites open in the default browser; they cannot navigate the application
view. The engine also saves and exits if its launcher crashes or is terminated.

Search plugins additionally require Python 3.9+ available as `python3`, `python`,
or `py`, or an executable path in `RUSTORRENT_SEARCH_PYTHON`.

## CLI and terminal interface

The original engine is included as `rustorrent-bin.exe`:

```powershell
.\rustorrent-bin.exe --help
.\rustorrent-bin.exe --tui --download-dir 'D:\Downloads'
.\rustorrent-bin.exe --ui 8081 --download-dir 'D:\Downloads'
```

Use a different download directory if the desktop app is already running.

## Build

Install Rust 1.89+ with the MSVC toolchain and Visual Studio C++ Build Tools,
including the Windows SDK. From the repository root:

```powershell
.\windows\package_app.ps1
.\windows\package_app.ps1 -OutputDirectory 'C:\Builds\Rustorrent'
```

The script builds the Rust engine and the native C++ launcher. It downloads a
pinned WebView2 SDK from NuGet and verifies its SHA-256 before extraction.
The CRT and WebView2 loader are linked statically; the WebView2 Runtime itself
is installed separately. No Rust dependencies were added for the launcher.

Output: `target/windows-app/dist/`, containing a versioned x64 ZIP and checksum.
The ZIP includes both executables and all engine and WebView2 license notices.
The package is unsigned and does not install file associations or a service.

For ARM64, install the Rust target and MSVC ARM64 build tools, then pass
`-Target aarch64-pc-windows-msvc`. ARM64 has not been runtime-tested.

GitHub CI builds and uploads `windows-x86_64`. It runs native argument/origin
checks and a hidden WebView2 smoke test, including a graceful engine shutdown.
For local diagnostics, the packaged launcher accepts `--self-test`,
`--smoke-test <temporary-directory>`, and `--test-window <temporary-directory>`.
The last two isolate the download folder and browser profile from normal use.

`AppIcon.ico` is built from `macos/AppIcon.svg` by `create_icon.ps1` (needs
Google Chrome or Microsoft Edge). Run it after editing the SVG.

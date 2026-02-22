# rustorrent

A minimal BitTorrent client implemented in Rust. Single binary, ~840KB, three dependencies.

Works on **macOS** and **Linux**. Windows support is partial (builds, but NAT-PMP gateway detection is not implemented).

## Features

- **BitTorrent protocol** — full download and upload with SHA-1 piece verification
- **Magnet links** — metadata fetching via peers and DHT
- **Trackers** — HTTP and UDP (BEP 15)
- **DHT** — Distributed Hash Table (BEP 5) with K-bucket routing and node persistence
- **PEX** — Peer Exchange
- **LPD** — Local Peer Discovery (BEP 14)
- **uTP** — Micro Transport Protocol (BEP 29)
- **MSE/PE** — Message Stream Encryption for obfuscated connections
- **NAT-PMP & UPnP** — automatic port mapping
- **Web seeds** — HTTP/HTTPS seeding (BEP 19)
- **Web UI** — built-in browser interface
- **IP filtering** — blocklist support
- **Torrent creation** — create `.torrent` files from local paths
- **Selective download** — per-file priority
- **Rate limiting** — global and per-torrent bandwidth control
- **Sequential mode** — download pieces in order for streaming
- **Watch folder** — auto-load torrents from a directory
- **Move on complete** — relocate finished downloads
- **Session persistence** — resume state across restarts

## Dependencies

Only three crates:

- `native-tls` — HTTPS tracker support
- `num-bigint` — MSE Diffie-Hellman (optional, `mse` feature)
- `num-traits` — bigint helpers (optional, `mse` feature)

Everything else — bencode, SHA-1, HTTP client, peer protocol, DHT, uTP, UPnP, NAT-PMP, web UI — is implemented from scratch.

## Build

```
cargo build --release
```

The release profile is optimized for size (`opt-level = "z"`, LTO, single codegen unit, stripped symbols). The resulting binary is under 1MB.

To build without encryption support (removes the `num-bigint` dependency):

```
cargo build --release --no-default-features --features udp-tracker,dht,utp,lpd,natpmp,upnp,webseed
```

## Platform support

| Platform | Status |
|----------|--------|
| macOS (x86_64, aarch64) | Fully supported |
| Linux (x86_64, aarch64) | Fully supported |
| Windows | Builds, but NAT-PMP gateway detection unavailable |

All platform-specific code has proper `#[cfg]` gates with fallbacks. The entropy source uses `/dev/urandom` with a fallback to time/pid/stack address mixing on platforms without it.

## Usage

```
rustorrent [options] [file.torrent ...]
```

The client prints progress to stdout and runs until the download completes or you press `Ctrl+C`. Session state is saved to `.rustorrent/` in the working directory and automatically resumed on restart.

### Downloading a torrent file

```sh
rustorrent ubuntu.torrent
```

Output:

```
[ubuntu-25.10-desktop-amd64.iso]
  peers: 12/30  down: 4.2 MB/s  up: 128.0 KB/s  progress: 23.4%  eta: 18:32
```

### Downloading a magnet link

```sh
rustorrent --magnet "magnet:?xt=urn:btih:4b07d0071f9ceb21af6b8ba05b3a3c6f507e3fb2&dn=LibreOffice&tr=http://tracker.example.org:6969/announce"
```

The client will first fetch metadata from peers/DHT, then begin downloading.

### Downloading to a specific directory

```sh
rustorrent --download-dir ~/Downloads ubuntu.torrent
```

### Multiple torrents at once

```sh
rustorrent file1.torrent file2.torrent --magnet "magnet:?xt=urn:btih:..."
```

### Sequential download (for media streaming)

```sh
rustorrent --sequential movie.torrent
```

Pieces are downloaded in order so a media player can start playback before the download finishes.

### Rate limiting

```sh
# Limit download to 5 MB/s, upload to 1 MB/s
rustorrent --download-rate 5242880 --upload-rate 1048576 ubuntu.torrent

# Per-torrent limits (useful with multiple torrents)
rustorrent --torrent-download-rate 2621440 file1.torrent file2.torrent
```

Values are in bytes per second. `0` means unlimited (the default).

### Encryption

```sh
# Prefer encrypted connections (default)
rustorrent ubuntu.torrent

# Require encryption — refuse unencrypted peers
rustorrent --encryption require ubuntu.torrent

# Disable encryption
rustorrent --no-encryption ubuntu.torrent
```

### Move completed downloads

```sh
rustorrent --download-dir ~/incomplete --move-completed ~/complete ubuntu.torrent
```

When a torrent finishes, its files are moved from `~/incomplete` to `~/complete`.

### Watch a folder

```sh
rustorrent --watch ~/watch --download-dir ~/downloads
```

The client periodically scans `~/watch` for new `.torrent` files and adds them automatically. Processed files are moved to a `processed/` subdirectory.

### Preallocate disk space

```sh
rustorrent --preallocate ubuntu.torrent
```

Allocates the full file size on disk before downloading. Avoids fragmentation on HDDs.

### Custom listen port

```sh
rustorrent --port 51413 ubuntu.torrent
```

Default listen port is 6881. The client uses NAT-PMP and UPnP to automatically map the port on your router when possible.

### IP blocklist

```sh
rustorrent --blocklist blocklist.txt ubuntu.torrent
```

The blocklist file contains one IP range per line in the format `start-end` or a single IP per line.

### Disable uTP

```sh
rustorrent --no-utp ubuntu.torrent
```

Forces the client to use TCP only. Useful if uTP causes issues with your network.

### Tuning peer counts

```sh
# Allow more peers globally and per torrent
rustorrent --max-peers 500 --max-peers-torrent 80 ubuntu.torrent

# Limit concurrent active torrents
rustorrent --max-active 2 file1.torrent file2.torrent file3.torrent
```

### Write cache

```sh
# Buffer 16 MB of writes before flushing to disk
rustorrent --write-cache 16777216 ubuntu.torrent
```

Reduces disk I/O by batching writes. Useful for slow disks or when downloading many pieces simultaneously.

### Creating a torrent

```sh
rustorrent --create ./my-project \
  --tracker http://tracker.example.com:6969/announce \
  --output my-project.torrent

# Custom piece length (default is auto-calculated)
rustorrent --create ./my-project \
  --tracker http://tracker.example.com:6969/announce \
  --output my-project.torrent \
  --piece-length 262144
```

### Configuration file

```sh
rustorrent --config rustorrent.conf ubuntu.torrent
```

Or set the environment variable:

```sh
export RUSTORRENT_CONFIG=~/.config/rustorrent.conf
rustorrent ubuntu.torrent
```

### With the web UI

```sh
# Enable web UI on default port 8080
rustorrent --ui ubuntu.torrent

# Custom port
rustorrent --ui 9090 ubuntu.torrent

# Custom bind address
rustorrent --ui-addr 0.0.0.0:8080 ubuntu.torrent
```

Open `http://127.0.0.1:8080` in your browser. The UI lets you add/remove torrents, see progress, manage files, and configure settings. Use `--ui-addr 0.0.0.0:8080` to make it accessible from other machines on your network.

## All options

| Flag | Default | Description |
|------|---------|-------------|
| `[file.torrent ...]` | | One or more torrent files to download |
| `--magnet <link>` | | Add a magnet link |
| `--download-dir <dir>` | `.` | Download directory |
| `--port <port>` | `6881` | Listen port for incoming peers |
| `--ui [port]` | off | Enable web UI (default port: 8080) |
| `--ui-addr <addr>` | `127.0.0.1:8080` | Web UI bind address |
| `--sequential` | off | Download pieces in order |
| `--preallocate` | off | Preallocate disk space |
| `--encryption <mode>` | `prefer` | `disable`, `prefer`, or `require` |
| `--no-encryption` | | Shorthand for `--encryption disable` |
| `--utp` / `--no-utp` | on | Enable or disable uTP |
| `--max-peers <n>` | `200` | Global peer limit |
| `--max-peers-torrent <n>` | `30` | Per-torrent peer limit |
| `--max-active <n>` | `4` | Max concurrent active torrents |
| `--numwant <n>` | `200` | Peers to request from tracker |
| `--retry-interval <secs>` | `60` | Tracker re-announce interval |
| `--download-rate <bps>` | `0` | Global download limit (0 = unlimited) |
| `--upload-rate <bps>` | `0` | Global upload limit (0 = unlimited) |
| `--torrent-download-rate <bps>` | `0` | Per-torrent download limit |
| `--torrent-upload-rate <bps>` | `0` | Per-torrent upload limit |
| `--write-cache <bytes>` | `0` | Write cache size (0 = disabled) |
| `--move-completed <dir>` | | Move finished downloads to this directory |
| `--watch <dir>` | | Watch directory for new `.torrent` files |
| `--blocklist <path>` | | IP blocklist file |
| `--create <path>` | | Create a torrent from this file or directory |
| `--tracker <url>` | | Tracker URL (used with `--create`) |
| `--output <file>` | | Output torrent file (used with `--create`) |
| `--piece-length <bytes>` | auto | Piece length (used with `--create`) |
| `--config <path>` | | Config file path (env: `RUSTORRENT_CONFIG`) |

## License

MIT

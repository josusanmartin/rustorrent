# rustorrent

A minimal BitTorrent client implemented in Rust. Single binary, ~840KB, three dependencies.

## Features

- **BitTorrent protocol**: Full download and upload with piece verification
- **Magnet links**: Metadata fetching via peers and DHT
- **Trackers**: HTTP and UDP (BEP 15)
- **DHT**: Distributed Hash Table (BEP 5) with K-bucket routing and node persistence
- **PEX**: Peer Exchange
- **LPD**: Local Peer Discovery (BEP 14)
- **uTP**: Micro Transport Protocol (BEP 29)
- **MSE/PE**: Message Stream Encryption for obfuscated connections
- **NAT-PMP & UPnP**: Automatic port mapping
- **Web Seeds**: HTTP/HTTPS seeding (BEP 19)
- **Web UI**: Built-in interface at `http://127.0.0.1:8080`
- **IP filtering**: Blocklist support
- **Torrent creation**: Create `.torrent` files from local paths
- **Selective download**: Per-file priority
- **Rate limiting**: Global and per-torrent bandwidth control
- **Sequential mode**: Download pieces in order for streaming
- **Watch folder**: Auto-load torrents from a directory
- **Move on complete**: Relocate finished downloads
- **Session persistence**: Resume state across restarts

## Dependencies

Only three crates:

- `native-tls` — HTTPS tracker support
- `num-bigint` — MSE Diffie-Hellman (optional)
- `num-traits` — bigint helpers (optional)

Everything else — bencode, SHA-1, HTTP client, peer protocol, DHT, uTP, UPnP, NAT-PMP, web UI — is implemented from scratch.

## Build

```
cargo build --release
```

The release binary is optimized for size (`opt-level = "z"`, LTO, stripped).

## Usage

```
rustorrent [options] [file.torrent ...]
```

### Examples

```sh
# Download a torrent file
rustorrent ubuntu.torrent

# Magnet link with web UI
rustorrent --magnet "magnet:?xt=urn:btih:..." --ui

# Web UI on a custom port
rustorrent --ui 9090

# Create a torrent
rustorrent --create ./myfiles --tracker http://tracker.example.com:6969/announce --output my.torrent

# Watch a folder for new torrents
rustorrent --watch ~/torrents --download-dir ~/downloads --ui
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--ui [port]` | off (8080) | Enable web UI |
| `--port <port>` | 6881 | Listen port for incoming peers |
| `--download-dir <dir>` | `.` | Download directory |
| `--magnet <link>` | | Add a magnet link |
| `--watch <dir>` | | Watch directory for `.torrent` files |
| `--sequential` | off | Download pieces in order |
| `--encryption <mode>` | prefer | `disable`, `prefer`, or `require` |
| `--max-peers <n>` | 200 | Global peer limit |
| `--max-peers-torrent <n>` | 30 | Per-torrent peer limit |
| `--download-rate <bps>` | 0 | Global download limit (0 = unlimited) |
| `--upload-rate <bps>` | 0 | Global upload limit (0 = unlimited) |
| `--move-completed <dir>` | | Move finished downloads here |
| `--preallocate` | off | Preallocate disk space |
| `--blocklist <path>` | | IP blocklist file |
| `--config <path>` | | Config file (also `RUSTORRENT_CONFIG` env) |

## License

MIT

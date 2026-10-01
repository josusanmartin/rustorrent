# Handoff: state on 1 October 2026

All code is on `master`, released as 0.2.0-rc.5. No work is left unmerged, and nothing is scheduled to run.

## Releases

| Tag | Main changes |
|---|---|
| v0.2.0-rc.1 | Connectivity card, macOS firewall button, UPnP IGD v2, random default port, menu bar mode, new icon |
| v0.2.0-rc.2 | Same as rc.1 with an LZMA-compressed DMG (arm64: 709 KB) |
| v0.2.0-rc.3 | Double-NAT port mapping, BEP 55 hole punching, one UDP port for DHT and uTP, more outgoing connections when unreachable, "Outgoing only" wording, a uTP fix for libtorrent peers, recommended search plugins, adult sites hidden from the plugin catalog |
| v0.2.0-rc.4 | Connected-peer table in the Peers tab, and `GET /torrent/peers?id=` |
| v0.2.0-rc.5 | Working DHT (BEP 42 no longer drops replies, lookups start from bootstrap replies, fast retries), parallel magnet metadata, uTP-first connections, `p`/`v`/`yourip` in the BEP 10 handshake, separate incoming slots, 100 connections per transfer with a Settings field, Rust 1.99 compatibility |

All are GitHub pre-releases.

## Verified by tests, not yet in the wild

- **Double-NAT upstream mapping** (`start_upstream_mapping` in `main.rs`, `natpmp::map_port_via`, `upnp::map_port_upstream`). Unit tests cover it, but it has not run against real hardware. The user who reported the problem (router at 192.168.100.18 behind a provider modem) had not confirmed the result when they switched networks.
- **Hole punching.** It is tested over loopback with real sockets, with Rustorrent as relay and as target (`HolepunchTests`). It is not yet tested with two peers behind real NATs. The initiator role only runs when a peer learned over PEX cannot be reached.
- **Uploading.** Fixed in rc.5 and measured on the real Ubuntu 26.04.1 swarm, side by side with libtorrent 2.1 (Homebrew `libtorrent-rasterbar`, Python bindings): Rustorrent uploaded 162 MB in 11 minutes, libtorrent 17 MB. On the user's network (Google Wifi behind a modem that refuses port mapping) incoming peers arrive only over uTP, never TCP, which is why uTP-first mattered. A second-device test across networks is still worth doing.

## Known gaps and ideas

- **Peer table:** "Has" reads 0% for peers that do not send HAVE messages to a seed; libtorrent does not send them. An estimate from the bytes uploaded to that peer would help.
- **Peer ID:** still fixed at `-RT0001-`. Since rc.5 the BEP 10 `v` field names the client, so libtorrent shows "Rustorrent 0.2.0-rc.5"; the peer ID itself should carry the version too.
- **Incoming peers:** on the same swarm libtorrent held 50–60 incoming peers and Rustorrent 1–19. Rustorrent's outgoing PEX does not yet set the uTP flag (0x04) or report peers' listen ports, which would spread its address further.
- **Flaky test:** `test_required_encryption_upload_to_transmission` in `tests/e2e_transmission.py` fails about half the time on macOS, on rc.4 as well: Transmission hangs up during the inbound MSE handshake.
- **Torrent creation:** only from the CLI (`--create`), and only with one tracker. There is no UI for it.
- **Hole-punch status:** the UI doesn't show that hole punching is happening. A counter or a peer flag ("via hole punch") would make it visible.
- **Upload slots:** the upload slot count is a fixed 6 (`UPLOAD_SLOTS`). qBittorrent uses 4 per torrent and scales with the upload rate.
- **Signing:** the app is not Developer ID signed or notarized, so macOS asks on first launch.
- **CI warning:** actions pinned to Node 20 (`actions/checkout`, `actions/setup-node`) print a deprecation warning. They still pass; bump the pinned SHAs when convenient.

## Local setup

- **Rust:** stable, with a minimum of 1.89. For the license notice, `cargo install cargo-about`.
- **Node 22:** `npm ci`, then `npx playwright install chromium`.
- **Interop tests:** `transmission-daemon` for `tests/e2e_transmission.py`, and libtorrent's Python bindings for `tests/e2e_libtorrent.py` (`brew install libtorrent-rasterbar` on macOS; PyPI has no wheel for recent Pythons).
- **Toolchains:** CI uses the latest stable Rust and denies warnings, so run clippy with the newest release too (`rustup toolchain install <version> -c clippy -c rustfmt`, then `cargo +<version> clippy ...`) as well as `cargo +1.89.0 check`.
- **macOS app:** `./macos/package_app.sh --universal --dmg`.

See `CLAUDE.md` for the checks to run before pushing and for the release steps.

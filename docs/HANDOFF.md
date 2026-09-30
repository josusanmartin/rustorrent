# Handoff: state on 30 September 2026

All code is on `master` (9bb9bf1, "Release 0.2.0-rc.4"). No pull requests are open. No work is left unmerged, and nothing is scheduled to run.

## Releases

| Tag | Main changes |
|---|---|
| v0.2.0-rc.1 | Connectivity card, macOS firewall button, UPnP IGD v2, random default port, menu bar mode, new icon |
| v0.2.0-rc.2 | Same as rc.1 with an LZMA-compressed DMG (arm64: 709 KB) |
| v0.2.0-rc.3 | Double-NAT port mapping, BEP 55 hole punching, one UDP port for DHT and uTP, more outgoing connections when unreachable, "Outgoing only" wording, a uTP fix for libtorrent peers, recommended search plugins, adult sites hidden from the plugin catalog |
| v0.2.0-rc.4 | Connected-peer table in the Peers tab, and `GET /torrent/peers?id=` |

All are GitHub pre-releases. The arm64 DMG of rc.4 is 726,423 bytes.

## Verified by tests, not yet in the wild

- **Double-NAT upstream mapping** (`start_upstream_mapping` in `main.rs`, `natpmp::map_port_via`, `upnp::map_port_upstream`). Unit tests cover it, but it has not run against real hardware. The user who reported the problem (router at 192.168.100.18 behind a provider modem) had not confirmed the result when they switched networks.
- **Hole punching.** It is tested over loopback with real sockets, with Rustorrent as relay and as target (`HolepunchTests`). It is not yet tested with two peers behind real NATs. The initiator role only runs when a peer learned over PEX cannot be reached.
- **Uploading.** On a new network the user saw "Reachable" but 0 B uploaded. The Peers tab showed "Interested in us: 0": every peer was a seed, so the upload code was not at fault. The rc.4 peer table makes this visible. To force an upload, the user has a test torrent for `Rustorrent-0.2.0-rc.3-universal.dmg`, made with `rustorrent --create … --tracker udp://tracker.opentrackr.org:1337/announce --piece-length 65536`. It is to be seeded from the Mac and downloaded on a second device on another network.

## Known gaps and ideas

- **Peer table:** "Has" reads 0% for peers that do not send HAVE messages to a seed; libtorrent does not send them. An estimate from the bytes uploaded to that peer would help.
- **Peer ID:** ours is fixed at `-RT0001-`. It should carry the real version, and libtorrent reports the `RT` prefix as "Retriever".
- **Torrent creation:** only from the CLI (`--create`), and only with one tracker. There is no UI for it.
- **Hole-punch status:** the UI doesn't show that hole punching is happening. A counter or a peer flag ("via hole punch") would make it visible.
- **Upload slots:** the upload slot count is a fixed 6 (`UPLOAD_SLOTS`). qBittorrent scales its slots with the upload rate.
- **Signing:** the app is not Developer ID signed or notarized, so macOS asks on first launch.
- **CI warning:** actions pinned to Node 20 (`actions/checkout`, `actions/setup-node`) print a deprecation warning. They still pass; bump the pinned SHAs when convenient.

## Local setup

- **Rust:** stable, with a minimum of 1.89. For the license notice, `cargo install cargo-about`.
- **Node 22:** `npm ci`, then `npx playwright install chromium`.
- **Interop tests:** `transmission-daemon` for `tests/e2e_transmission.py`, and `pip install libtorrent` (or `python3-libtorrent`) for `tests/e2e_libtorrent.py`.
- **macOS app:** `./macos/package_app.sh --universal --dmg`.

See `CLAUDE.md` for the checks to run before pushing and for the release steps.

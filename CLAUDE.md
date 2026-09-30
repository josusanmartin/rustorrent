# Rustorrent

A BitTorrent client in Rust: one binary, a local web UI (`assets/ui`), a CLI and terminal UI, and a Swift launcher that wraps it as a macOS app. The Apple silicon DMG must stay under 1,000,000 bytes; CI and the release workflow both enforce this.

Read `PRODUCT.md` (who it is for, tone) and `DESIGN.md` (UI rules) before changing the interface. `docs/HANDOFF.md` has the current state and open work.

## Layout

- `src/main.rs`: the engine. Torrent workers, peer connections (`PeerConn`), choking (`UploadManager`), port mapping, the CLI flags, and stub modules for disabled features. It is large; search it rather than reading it whole.
- `src/ui.rs`: HTTP server and JSON API for the web UI and `rustorrent remote`. `src/remote.rs` is the CLI client and `src/tui.rs` the terminal UI.
- Protocols: `peer.rs` (wire messages), `peer_stream.rs` (TCP or uTP, optional MSE), `utp.rs` (BEP 29), `dht.rs`, `holepunch.rs` (BEP 55), `tracker.rs`, `udp_tracker.rs`, `lpd.rs`, `mse.rs`, `natpmp.rs`, `upnp.rs`.
- `src/search.rs`: runs qBittorrent nova3 search plugins. `src/firewall.rs`: the macOS application firewall.
- `macos/`: `package_app.sh` builds the app and DMG (ULMO compression), `Launcher.swift` is the native window and menu bar mode, and `create_icon.sh` builds the icon from `AppIcon.svg`.
- `docs/releases/`: one Markdown file per release; it becomes the GitHub release body.

## Features

Cargo features: `udp_tracker dht lpd utp mse natpmp upnp webseed` (all in `full`, the default) plus `verbose`, which turns on `log_debug!` output. Every feature can be disabled, and `main.rs` then uses a stub module with the same API. When you add a public function to a feature module, add it to the stub too, and check the feature combinations below.

## Checks to run before pushing

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features -- --test-threads=1
cargo test --locked --no-default-features -- --test-threads=1
for f in udp_tracker dht lpd utp mse natpmp upnp webseed verbose; do
  cargo check --locked --all-targets --no-default-features --features "$f"; done
```

On a Mac, also run `cargo clippy --all-targets -- -D warnings` natively. From Linux, add `--target aarch64-apple-darwin`.

Real-process tests, after `cargo build`:

```sh
python3 tests/e2e_transfer.py        # transfers, crash recovery, hole punching
python3 tests/e2e_transmission.py    # needs transmission-daemon; LAN tests need an RFC 1918 address
python3 tests/e2e_libtorrent.py      # needs libtorrent Python bindings (pip install libtorrent)
npx playwright test                  # browser flows with accessibility checks
```

A test script takes an optional binary path as its first argument, for example `python3 tests/e2e_transfer.py target/release/rustorrent HolepunchTests`. Set `RUSTORRENT_E2E_LOG=1` to print the app's log after each test. Set `PW_CHROMIUM_PATH` to use a Chromium you already have. `RUSTORRENT_SCREENSHOTS=1 npx playwright test tests/browser/screenshots.spec.mjs` regenerates `docs/screenshots` from `target/release`.

## Conventions

- **Tests:** never skip, disable or weaken a test to get green. A flaky e2e test is fixed by waiting for the state it depends on, as in `HolepunchTests`.
- **Peer addresses:** compare them in canonical form. Dual-stack listeners report IPv4 peers as `[::ffff:a.b.c.d]` (`normalize_peer_addr`, `holepunch::canon`). A Linux box without IPv6 hides this class of bug; CI does not.
- **UI copy:** follow `PRODUCT.md`. Use short, concrete labels, explain waiting states honestly, and don't use alarming wording when things still work (for example "Outgoing only", not "Not reachable").
- **Dependencies:** each one costs DMG bytes. Prefer the standard library.

## Releasing

1. Bump `version` in `Cargo.toml`, then run `cargo update -p rustorrent --offline`.
2. Regenerate the license notice: `cargo about generate --locked --all-features --fail about.hbs --output-file THIRD_PARTY_LICENSES.html`. CI fails if it is stale.
3. Write `docs/releases/v<version>.md`, following the previous one.
4. Merge to `master` once CI is green, then run the **Release** workflow (`.github/workflows/release.yml`) on `master` with input `tag` set to `v<version>`. It builds the arm64 and universal DMGs and ZIPs, the Linux tarball and `SHA256SUMS.txt`, and publishes a pre-release. It fails if the arm64 DMG reaches 1 MB.

The app is ad-hoc signed only; it is not Developer ID signed or notarized.
